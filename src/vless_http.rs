use crate::vless_transport::VlessTransportConfig;
use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn client_upgrade<S>(
    stream: &mut S,
    transport: &VlessTransportConfig,
    default_host: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_upgrade_request(stream, transport, default_host, &[]).await?;
    let response = read_http_head(stream).await?;
    ensure!(
        response.starts_with("HTTP/1.1 101") || response.starts_with("HTTP/1.0 101"),
        "VLESS HTTPUpgrade server returned non-101 response: {}",
        response.lines().next().unwrap_or_default()
    );
    Ok(())
}

pub async fn server_upgrade<S>(stream: &mut S, transport: &VlessTransportConfig) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_head(stream).await?;
    ensure_request_path(&request, &transport.path)?;
    stream
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .await
        .context("write VLESS HTTPUpgrade response")?;
    stream.flush().await.context("flush VLESS HTTPUpgrade")
}

pub async fn write_upgrade_request<S>(
    stream: &mut S,
    transport: &VlessTransportConfig,
    default_host: &str,
    extra_headers: &[(&str, String)],
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let host = transport.request_host(default_host);
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        transport.path, host
    );
    for (key, value) in &transport.headers {
        if !key.eq_ignore_ascii_case("host") {
            request.push_str(key);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
    }
    for (key, value) in extra_headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("write VLESS HTTP upgrade request")?;
    stream.flush().await.context("flush VLESS HTTP upgrade")
}

pub async fn read_http_head<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .context("read HTTP upgrade header")?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return String::from_utf8(head).context("decode HTTP upgrade header");
        }
    }
}

pub fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

pub fn ensure_request_path(head: &str, expected_path: &str) -> Result<()> {
    let line = head
        .lines()
        .next()
        .context("HTTP upgrade request is empty")?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("GET") {
        bail!("unsupported HTTP upgrade method {method}");
    }
    ensure!(
        path == expected_path,
        "unexpected HTTP upgrade path {path}, expected {expected_path}"
    );
    Ok(())
}
