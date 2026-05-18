use crate::listener::ListenerStopToken;
use crate::protocol::{ProxyTarget, target_name};
use crate::socks;
use anyhow::{Context, Result, bail, ensure};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy, Debug)]
pub struct HttpConnectInboundConfig {
    pub upstream_socks: SocketAddr,
}

pub async fn run_http_connect_listener(
    listener: TcpListener,
    config: HttpConnectInboundConfig,
) -> Result<()> {
    run_http_connect_listener_until(listener, config, ListenerStopToken::new()).await
}

pub async fn run_http_connect_listener_until(
    listener: TcpListener,
    config: HttpConnectInboundConfig,
    stop: ListenerStopToken,
) -> Result<()> {
    tracing::info!(
        "HTTP CONNECT inbound listening on http://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => accepted.context("accept HTTP CONNECT client")?,
            _ = stop.stopped() => return Ok(()),
        };
        tokio::spawn(async move {
            if let Err(error) = handle_http_connect(stream, config.upstream_socks).await {
                tracing::warn!("HTTP CONNECT client {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn handle_http_connect(mut local: TcpStream, upstream_socks: SocketAddr) -> Result<()> {
    let target = match read_connect_target(&mut local).await {
        Ok(target) => target,
        Err(error) => {
            let _ = write_http_response(&mut local, 400, "Bad Request").await;
            return Err(error);
        }
    };
    let mut upstream = match socks::connect_tcp(upstream_socks, &target).await {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = write_http_response(&mut local, 502, "Bad Gateway").await;
            return Err(error);
        }
    };
    write_http_response(&mut local, 200, "Connection Established").await?;
    tracing::info!(
        "HTTP CONNECT {} via SOCKS {}",
        target_name(&target),
        upstream_socks
    );
    copy_bidirectional(&mut local, &mut upstream)
        .await
        .context("relay HTTP CONNECT tunnel")?;
    Ok(())
}

async fn read_connect_target(stream: &mut TcpStream) -> Result<ProxyTarget> {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .context("read HTTP CONNECT request")?;
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let request = std::str::from_utf8(&request).context("decode HTTP CONNECT request")?;
    let first_line = request
        .lines()
        .next()
        .context("HTTP CONNECT request is empty")?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().context("HTTP CONNECT method is missing")?;
    let authority = parts.next().context("HTTP CONNECT authority is missing")?;
    let version = parts.next().context("HTTP CONNECT version is missing")?;
    ensure!(
        parts.next().is_none(),
        "HTTP CONNECT request line has trailing fields"
    );
    ensure!(
        method.eq_ignore_ascii_case("CONNECT"),
        "HTTP request method is not CONNECT"
    );
    ensure!(
        version.starts_with("HTTP/1."),
        "unsupported HTTP CONNECT version {version}"
    );
    parse_connect_authority(authority)
}

fn parse_connect_authority(authority: &str) -> Result<ProxyTarget> {
    let authority = authority.trim();
    ensure!(!authority.is_empty(), "HTTP CONNECT authority is empty");
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .with_context(|| format!("invalid bracketed CONNECT authority {authority}"))?;
        let port = tail
            .strip_prefix(':')
            .with_context(|| format!("CONNECT authority is missing port: {authority}"))?;
        (host, port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .with_context(|| format!("CONNECT authority must be host:port: {authority}"))?;
        if host.contains(':') {
            bail!("IPv6 CONNECT authority must use [addr]:port form: {authority}");
        }
        (host, port)
    };
    ensure!(!host.trim().is_empty(), "CONNECT authority host is empty");
    let port = port
        .parse::<u16>()
        .with_context(|| format!("parse CONNECT authority port: {authority}"))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ProxyTarget::Ip(SocketAddr::new(ip, port)));
    }
    Ok(ProxyTarget::Domain(host.to_string(), port))
}

async fn write_http_response(stream: &mut TcpStream, code: u16, reason: &str) -> Result<()> {
    stream
        .write_all(format!("HTTP/1.1 {code} {reason}\r\n\r\n").as_bytes())
        .await
        .context("write HTTP CONNECT response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_connect_authority() -> Result<()> {
        assert_eq!(
            parse_connect_authority("example.com:443")?,
            ProxyTarget::Domain("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_connect_authority("127.0.0.1:8080")?,
            ProxyTarget::Ip("127.0.0.1:8080".parse()?)
        );
        assert_eq!(
            parse_connect_authority("[::1]:8443")?,
            ProxyTarget::Ip("[::1]:8443".parse()?)
        );
        Ok(())
    }

    #[tokio::test]
    async fn listener_stops_on_token() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let stop = ListenerStopToken::new();
        let task_stop = stop.clone();
        let task = tokio::spawn(async move {
            run_http_connect_listener_until(
                listener,
                HttpConnectInboundConfig {
                    upstream_socks: "127.0.0.1:9".parse().expect("valid socket addr"),
                },
                task_stop,
            )
            .await
        });
        stop.stop();
        task.await.context("join HTTP CONNECT listener")??;
        Ok(())
    }
}
