use crate::vless_transport::VlessTransportConfig;
use anyhow::{Context as _, Result, anyhow, ensure};
use bytes::{Buf as _, Bytes};
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};

const PIPE_CAPACITY: usize = 64 * 1024;
const COPY_BUFFER_LEN: usize = 16 * 1024;

pub struct H2TransportStream {
    reader: DuplexStream,
    writer: DuplexStream,
}

impl AsyncRead for H2TransportStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for H2TransportStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

pub async fn client<S>(
    stream: S,
    transport: &VlessTransportConfig,
    default_host: &str,
) -> Result<H2TransportStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, connection) = h2::client::handshake(stream)
        .await
        .context("start VLESS HTTP/2 client connection")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::warn!("VLESS HTTP/2 client connection failed: {error:?}");
        }
    });

    let host = transport.request_host(default_host);
    let request = build_client_request("POST", &host, transport, false)?;
    let (response, request_body) = client
        .send_request(request, false)
        .context("send VLESS HTTP/2 request")?;
    Ok(stream_from_client_parts(response, request_body, false))
}

pub async fn grpc_client<S>(
    stream: S,
    transport: &VlessTransportConfig,
    default_host: &str,
) -> Result<H2TransportStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client, connection) = h2::client::handshake(stream)
        .await
        .context("start VLESS gRPC client connection")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::warn!("VLESS gRPC client connection failed: {error:?}");
        }
    });

    let host = transport.request_host(default_host);
    let request = build_client_request("POST", &host, transport, true)?;
    let (response, request_body) = client
        .send_request(request, false)
        .context("send VLESS gRPC request")?;
    Ok(stream_from_client_parts(response, request_body, true))
}

pub async fn server<S>(stream: S, transport: &VlessTransportConfig) -> Result<H2TransportStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (request, mut respond) = accept_first_request(stream, "VLESS HTTP/2").await?;
    let (parts, body) = request.into_parts();
    ensure_http2_request(&parts, transport)?;
    let response = http::Response::builder()
        .status(200)
        .header("cache-control", "no-store")
        .body(())
        .context("build VLESS HTTP/2 response")?;
    let response_body = respond
        .send_response(response, false)
        .context("write VLESS HTTP/2 response headers")?;
    Ok(stream_from_h2_parts(body, response_body, false))
}

pub async fn grpc_server<S>(
    stream: S,
    transport: &VlessTransportConfig,
) -> Result<H2TransportStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (request, mut respond) = accept_first_request(stream, "VLESS gRPC").await?;
    let (parts, body) = request.into_parts();
    ensure_grpc_request(&parts, transport)?;
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("trailer", "grpc-status, grpc-message")
        .body(())
        .context("build VLESS gRPC response")?;
    let response_body = respond
        .send_response(response, false)
        .context("write VLESS gRPC response headers")?;
    Ok(stream_from_h2_parts(body, response_body, true))
}

async fn accept_first_request<S>(
    stream: S,
    name: &'static str,
) -> Result<(
    http::Request<h2::RecvStream>,
    h2::server::SendResponse<Bytes>,
)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream)
        .await
        .with_context(|| format!("accept {name} h2 connection"))?;
    let (request, respond) = connection
        .accept()
        .await
        .with_context(|| format!("{name} h2 connection closed before request"))?
        .with_context(|| format!("accept {name} request"))?;
    tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            match result {
                Ok((_, mut respond)) => {
                    let response = match http::Response::builder().status(404).body(()) {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::warn!("build extra {name} h2 404 response failed: {error:?}");
                            continue;
                        }
                    };
                    if let Err(error) = respond.send_response(response, true) {
                        tracing::warn!("reject extra {name} h2 request failed: {error:?}");
                    }
                }
                Err(error) => {
                    tracing::warn!("{name} h2 connection failed: {error:?}");
                    return;
                }
            }
        }
    });
    Ok((request, respond))
}

fn build_client_request(
    method: &str,
    host: &str,
    transport: &VlessTransportConfig,
    grpc: bool,
) -> Result<http::Request<()>> {
    let uri = format!("https://{}{}", host, transport.path)
        .parse::<http::Uri>()
        .with_context(|| format!("build VLESS HTTP/2 URI for host {host}"))?;
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::HOST, host);
    if grpc {
        builder = builder
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header("te", "trailers");
    }
    for (key, value) in &transport.headers {
        if !key.eq_ignore_ascii_case("host") {
            builder = builder.header(key.as_str(), value.as_str());
        }
    }
    builder.body(()).context("build VLESS HTTP/2 request")
}

fn ensure_http2_request(
    parts: &http::request::Parts,
    transport: &VlessTransportConfig,
) -> Result<()> {
    let path = parts.uri.path();
    ensure!(
        transport.path == "/" || path.starts_with(&transport.path),
        "unexpected VLESS HTTP/2 path {path}, expected prefix {}",
        transport.path
    );
    ensure_request_host(parts, transport, "VLESS HTTP/2")
}

fn ensure_grpc_request(
    parts: &http::request::Parts,
    transport: &VlessTransportConfig,
) -> Result<()> {
    ensure!(
        parts.method == http::Method::POST,
        "gRPC method must be POST"
    );
    let path = parts.uri.path();
    ensure!(
        path == transport.path,
        "unexpected gRPC path {path}, expected {}",
        transport.path
    );
    let content_type = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    ensure!(
        content_type.eq_ignore_ascii_case("application/grpc")
            || content_type
                .to_ascii_lowercase()
                .starts_with("application/grpc+"),
        "invalid gRPC content-type {content_type}"
    );
    ensure_request_host(parts, transport, "VLESS gRPC")
}

fn ensure_request_host(
    parts: &http::request::Parts,
    transport: &VlessTransportConfig,
    name: &str,
) -> Result<()> {
    let Some(expected) = transport
        .host
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
    else {
        return Ok(());
    };
    let host = parts
        .uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or_default();
    ensure!(
        normalize_host(host) == normalize_host(expected),
        "unexpected {name} host {host}, expected {expected}"
    );
    Ok(())
}

fn stream_from_h2_parts(
    body: h2::RecvStream,
    sender: h2::SendStream<Bytes>,
    grpc: bool,
) -> H2TransportStream {
    let (body_sink, reader) = duplex(PIPE_CAPACITY);
    let (writer, body_source) = duplex(PIPE_CAPACITY);

    tokio::spawn(async move {
        let result = if grpc {
            pump_grpc_body_to_pipe(H2BodyReader::new(body), body_sink).await
        } else {
            pump_h2_body_to_pipe(H2BodyReader::new(body), body_sink).await
        };
        if let Err(error) = result {
            tracing::warn!("VLESS h2 response body pump failed: {error:?}");
        }
    });
    tokio::spawn(async move {
        let result = if grpc {
            pump_pipe_to_grpc_body(body_source, sender).await
        } else {
            pump_pipe_to_h2_body(body_source, sender).await
        };
        if let Err(error) = result {
            tracing::warn!("VLESS h2 request body pump failed: {error:?}");
        }
    });

    H2TransportStream { reader, writer }
}

fn stream_from_client_parts(
    response: h2::client::ResponseFuture,
    sender: h2::SendStream<Bytes>,
    grpc: bool,
) -> H2TransportStream {
    let (body_sink, reader) = duplex(PIPE_CAPACITY);
    let (writer, body_source) = duplex(PIPE_CAPACITY);

    tokio::spawn(async move {
        let result = pump_client_response(response, body_sink, grpc).await;
        if let Err(error) = result {
            tracing::warn!("VLESS h2 client response pump failed: {error:?}");
        }
    });
    tokio::spawn(async move {
        let result = if grpc {
            pump_pipe_to_grpc_body(body_source, sender).await
        } else {
            pump_pipe_to_h2_body(body_source, sender).await
        };
        if let Err(error) = result {
            tracing::warn!("VLESS h2 client request body pump failed: {error:?}");
        }
    });

    H2TransportStream { reader, writer }
}

async fn pump_client_response(
    response: h2::client::ResponseFuture,
    sink: DuplexStream,
    grpc: bool,
) -> Result<()> {
    let response = response.await.context("read VLESS h2 response")?;
    ensure!(
        response.status().is_success(),
        "VLESS h2 server returned {}",
        response.status()
    );
    if grpc {
        let content_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        ensure!(
            content_type.eq_ignore_ascii_case("application/grpc")
                || content_type
                    .to_ascii_lowercase()
                    .starts_with("application/grpc+"),
            "VLESS gRPC response has invalid content-type {content_type}"
        );
        return pump_grpc_body_to_pipe(H2BodyReader::new(response.into_body()), sink).await;
    }
    pump_h2_body_to_pipe(H2BodyReader::new(response.into_body()), sink).await
}

async fn pump_h2_body_to_pipe<R>(mut reader: R, mut sink: DuplexStream) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    tokio::io::copy(&mut reader, &mut sink)
        .await
        .context("copy VLESS HTTP/2 body")?;
    sink.shutdown().await.ok();
    Ok(())
}

async fn pump_grpc_body_to_pipe<R>(mut reader: R, mut sink: DuplexStream) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(payload) = read_grpc_frame(&mut reader).await? else {
            sink.shutdown().await.ok();
            return Ok(());
        };
        sink.write_all(&payload)
            .await
            .context("write VLESS gRPC payload into pipe")?;
    }
}

async fn pump_pipe_to_h2_body(
    mut source: DuplexStream,
    mut sender: h2::SendStream<Bytes>,
) -> Result<()> {
    let mut buffer = [0u8; COPY_BUFFER_LEN];
    loop {
        let read = source
            .read(&mut buffer)
            .await
            .context("read VLESS HTTP/2 payload")?;
        if read == 0 {
            send_h2_data(&mut sender, Bytes::new(), true)
                .await
                .context("finish VLESS HTTP/2 body")?;
            return Ok(());
        }
        send_h2_data(&mut sender, Bytes::copy_from_slice(&buffer[..read]), false)
            .await
            .context("write VLESS HTTP/2 payload")?;
    }
}

async fn pump_pipe_to_grpc_body(
    mut source: DuplexStream,
    mut sender: h2::SendStream<Bytes>,
) -> Result<()> {
    let mut buffer = [0u8; COPY_BUFFER_LEN];
    loop {
        let read = source
            .read(&mut buffer)
            .await
            .context("read VLESS gRPC payload")?;
        if read == 0 {
            send_grpc_trailers(&mut sender, "0", None)
                .await
                .context("finish VLESS gRPC body")?;
            return Ok(());
        }
        send_h2_data(&mut sender, encode_grpc_frame(&buffer[..read]), false)
            .await
            .context("write VLESS gRPC payload")?;
    }
}

async fn send_h2_data(
    sender: &mut h2::SendStream<Bytes>,
    data: Bytes,
    end_of_stream: bool,
) -> Result<()> {
    if data.is_empty() {
        sender
            .send_data(data, end_of_stream)
            .context("write empty VLESS h2 data frame")?;
        return Ok(());
    }
    let mut offset = 0usize;
    while offset < data.len() {
        sender.reserve_capacity(data.len() - offset);
        let capacity = poll_fn(|cx| sender.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow!("VLESS h2 stream closed"))?
            .context("reserve VLESS h2 capacity")?;
        if capacity == 0 {
            tokio::task::yield_now().await;
            continue;
        }
        let take = capacity.min(data.len() - offset);
        let end = end_of_stream && offset + take == data.len();
        sender
            .send_data(data.slice(offset..offset + take), end)
            .context("write VLESS h2 data frame")?;
        offset += take;
    }
    Ok(())
}

async fn send_grpc_trailers(
    sender: &mut h2::SendStream<Bytes>,
    grpc_status: &str,
    grpc_message: Option<&str>,
) -> Result<()> {
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "grpc-status",
        http::HeaderValue::from_str(grpc_status).context("encode gRPC status trailer")?,
    );
    if let Some(message) = grpc_message.filter(|value| !value.is_empty()) {
        trailers.insert(
            "grpc-message",
            http::HeaderValue::from_str(message).context("encode gRPC message trailer")?,
        );
    }
    sender
        .send_trailers(trailers)
        .context("write gRPC trailers")?;
    Ok(())
}

async fn read_grpc_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("read gRPC frame header"),
    }
    ensure!(header[0] == 0, "compressed gRPC messages are not supported");
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut message = vec![0u8; length];
    reader
        .read_exact(&mut message)
        .await
        .context("read gRPC frame payload")?;
    let mut cursor = 0usize;
    let key = read_varint(&message, &mut cursor).context("read gRPC hunk field key")?;
    ensure!(key == 0x0a, "unsupported gRPC hunk field key {key:#x}");
    let data_len = read_varint(&message, &mut cursor).context("read gRPC hunk length")?;
    let data_len = usize::try_from(data_len).context("gRPC hunk length does not fit usize")?;
    ensure!(
        cursor + data_len == message.len(),
        "invalid gRPC hunk payload length"
    );
    Ok(Some(message[cursor..cursor + data_len].to_vec()))
}

fn encode_grpc_frame(payload: &[u8]) -> Bytes {
    let mut message = Vec::with_capacity(payload.len() + 8);
    message.push(0x0a);
    write_varint(payload.len() as u64, &mut message);
    message.extend_from_slice(payload);

    let mut frame = Vec::with_capacity(message.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    Bytes::from(frame)
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        ensure!(*cursor < bytes.len(), "truncated gRPC varint");
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        ensure!(shift < 64, "gRPC varint is too large");
    }
}

fn write_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

struct H2BodyReader {
    body: h2::RecvStream,
    current: Option<Bytes>,
}

impl Unpin for H2BodyReader {}

impl H2BodyReader {
    fn new(body: h2::RecvStream) -> Self {
        Self {
            body,
            current: None,
        }
    }
}

impl AsyncRead for H2BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(current) = self.current.as_mut() {
                let take = current.len().min(buf.remaining());
                buf.put_slice(&current[..take]);
                current.advance(take);
                if current.is_empty() {
                    self.current = None;
                }
                return Poll::Ready(Ok(()));
            }
            match self.body.poll_data(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    let _ = self.body.flow_control().release_capacity(bytes.len());
                    if bytes.is_empty() {
                        continue;
                    }
                    self.current = Some(bytes);
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(std::io::Error::other(error)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .split_once(':')
        .map(|(host, _)| host)
        .unwrap_or_else(|| host.trim().trim_end_matches('.'))
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn grpc_frame_roundtrip() -> Result<()> {
        let encoded = encode_grpc_frame(b"hello");
        let decoded = read_grpc_frame(&mut encoded.as_ref())
            .await?
            .context("frame")?;
        assert_eq!(decoded, b"hello");
        Ok(())
    }
}
