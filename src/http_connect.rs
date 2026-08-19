use crate::listener::ListenerStopToken;
use crate::protocol::{ProxyTarget, target_name};
use crate::{socket_protect, socks, tls};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rustls::pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use crate::utls::UtlsFingerprint;

#[derive(Clone, Debug)]
pub struct HttpProxyClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    pub password: String,
    pub tls: bool,
    pub sni: String,
    pub insecure: bool,
    pub ca_cert_paths: Vec<PathBuf>,
    pub ca_certificates: Vec<String>,
    pub disable_system_roots: bool,
    pub pinned_cert_sha256: Vec<String>,
    pub client_fingerprint: Option<UtlsFingerprint>,
    pub extra_headers: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug)]
pub struct HttpConnectInboundConfig {
    pub upstream_socks: SocketAddr,
}

trait HttpProxyIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> HttpProxyIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type HttpProxyStream = Box<dyn HttpProxyIo>;

struct HttpProxyTunnel {
    stream: HttpProxyStream,
    pending: Vec<u8>,
}

pub async fn run_http_proxy_client(config: HttpProxyClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind HTTP proxy SOCKS listener on {}", config.listen))?;
    run_http_proxy_client_listener(listener, config).await
}

pub async fn run_http_proxy_client_listener(
    listener: TcpListener,
    config: HttpProxyClientConfig,
) -> Result<()> {
    tracing::info!("HTTP proxy client listening on socks5://{}", config.listen);
    loop {
        let (stream, peer) = crate::listener::accept_tcp(&listener)
            .await
            .context("accept SOCKS client")?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_http_proxy_socks(stream, config).await {
                tracing::warn!("HTTP proxy SOCKS client {peer} failed: {error:?}");
            }
        });
    }
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
            accepted = crate::listener::accept_tcp(&listener) => accepted.context("accept HTTP CONNECT client")?,
            _ = stop.stopped() => return Ok(()),
        };
        tokio::spawn(async move {
            if let Err(error) = handle_http_connect(stream, config.upstream_socks).await {
                tracing::warn!("HTTP CONNECT client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_http_proxy_socks(
    mut local: TcpStream,
    config: HttpProxyClientConfig,
) -> Result<()> {
    match socks::read_request(&mut local).await? {
        socks::SocksRequest::Connect(target) => {
            let mut tunnel = match open_http_proxy_tunnel(&config, &target).await {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x01).await;
                    return Err(error);
                }
            };
            socks::write_reply(&mut local, 0x00).await?;
            if !tunnel.pending.is_empty() {
                local
                    .write_all(&tunnel.pending)
                    .await
                    .context("write pending HTTP proxy tunnel bytes to SOCKS client")?;
            }
            tracing::info!("HTTP proxying {}", target_name(&target));
            copy_bidirectional(&mut local, &mut tunnel.stream)
                .await
                .context("relay HTTP proxy tunnel")?;
            Ok(())
        }
        socks::SocksRequest::UdpAssociate => {
            bail!("HTTP proxy outbound does not support SOCKS UDP ASSOCIATE")
        }
    }
}

async fn open_http_proxy_tunnel(
    config: &HttpProxyClientConfig,
    target: &ProxyTarget,
) -> Result<HttpProxyTunnel> {
    let tcp = socket_protect::connect_tcp_host_port(&config.server_host, config.server_port)
        .await
        .with_context(|| {
            format!(
                "connect HTTP proxy server {}:{}",
                config.server_host, config.server_port
            )
        })?;
    if config.tls {
        let mut client_config = Arc::unwrap_or_clone(
            tls::client_config_with_fingerprint_and_custom_root_material_options(
                config.insecure,
                config.client_fingerprint,
                &config.ca_cert_paths,
                &config.ca_certificates,
                config.disable_system_roots,
                &config.pinned_cert_sha256,
            )?,
        );
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(config.sni.clone())
            .with_context(|| format!("invalid HTTP proxy SNI: {}", config.sni))?;
        let stream = connector
            .connect(server_name, tcp)
            .await
            .context("TLS connect to HTTP proxy server")?;
        return http_proxy_connect(Box::new(stream), config, target).await;
    }
    http_proxy_connect(Box::new(tcp), config, target).await
}

async fn http_proxy_connect(
    mut stream: HttpProxyStream,
    config: &HttpProxyClientConfig,
    target: &ProxyTarget,
) -> Result<HttpProxyTunnel> {
    let authority = target_name(target);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Aerion\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n"
    );
    if !config.username.is_empty() || !config.password.is_empty() {
        let credential = format!("{}:{}", config.username, config.password);
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&BASE64_STANDARD.encode(credential.as_bytes()));
        request.push_str("\r\n");
    }
    for (key, value) in &config.extra_headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("write HTTP proxy CONNECT request")?;

    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .context("read HTTP proxy CONNECT response")?;
        ensure!(read > 0, "HTTP proxy closed before CONNECT response");
        response.extend_from_slice(&buffer[..read]);
        ensure!(
            response.len() <= 16 * 1024,
            "HTTP proxy CONNECT response header is too large"
        );
        if let Some(end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&response[..end]);
            let status = header
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default();
            ensure!(
                status == "200",
                "HTTP proxy CONNECT failed: {}",
                header.lines().next().unwrap_or("")
            );
            return Ok(HttpProxyTunnel {
                stream,
                pending: response[end + 4..].to_vec(),
            });
        }
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
