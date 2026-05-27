use crate::vless_http;
use crate::vless_transport::VlessTransportConfig;
use anyhow::{Context, Result, ensure};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, ready};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf, split,
};
use tokio::sync::mpsc;

const X_PADDING_LEN: usize = 100;

#[derive(Clone, Copy)]
enum XhttpRole {
    Client,
    Server,
}

pub struct XhttpStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    reader: mpsc::Receiver<Result<Vec<u8>, String>>,
    current: Vec<u8>,
    current_pos: usize,
    writer: WriteHalf<S>,
    role: XhttpRole,
    response_head_sent: bool,
    pending_write: Vec<u8>,
    pending_pos: usize,
    close_sent: bool,
}

pub async fn client<S>(
    mut stream: S,
    transport: &VlessTransportConfig,
    default_host: &str,
) -> Result<XhttpStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    write_request_head(&mut stream, transport, default_host).await?;
    Ok(XhttpStream::new(stream, XhttpRole::Client, true))
}

pub async fn server<S>(mut stream: S, transport: &VlessTransportConfig) -> Result<XhttpStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = vless_http::read_http_head(&mut stream).await?;
    ensure_request(&request, transport)?;
    Ok(XhttpStream::new(stream, XhttpRole::Server, false))
}

impl<S> XhttpStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn new(stream: S, role: XhttpRole, response_head_sent: bool) -> Self {
        let (reader, writer) = split(stream);
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            if let Err(error) = read_chunks(reader, tx.clone(), role).await {
                let _ = tx.send(Err(format!("{error:?}"))).await;
            }
        });
        Self {
            reader: rx,
            current: Vec::new(),
            current_pos: 0,
            writer,
            role,
            response_head_sent,
            pending_write: Vec::new(),
            pending_pos: 0,
            close_sent: false,
        }
    }

    fn queue_payload(&mut self, payload: &[u8]) -> Result<()> {
        if matches!(self.role, XhttpRole::Server) && !self.response_head_sent {
            self.response_head_sent = true;
            self.pending_write
                .extend_from_slice(response_head().as_bytes());
        }
        append_chunk(&mut self.pending_write, payload);
        Ok(())
    }

    fn queue_close(&mut self) {
        if matches!(self.role, XhttpRole::Server) && !self.response_head_sent {
            self.response_head_sent = true;
            self.pending_write
                .extend_from_slice(response_head().as_bytes());
        }
        self.pending_write.extend_from_slice(b"0\r\n\r\n");
    }

    fn poll_pending(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Self {
            writer,
            pending_write,
            pending_pos,
            ..
        } = &mut *self;
        while *pending_pos < pending_write.len() {
            let start = *pending_pos;
            let written = ready!(Pin::new(&mut *writer).poll_write(cx, &pending_write[start..]))?;
            if written == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "write xhttp chunk",
                )));
            }
            *pending_pos += written;
        }
        pending_write.clear();
        *pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for XhttpStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.current_pos < self.current.len() {
                let len = buf.remaining().min(self.current.len() - self.current_pos);
                let end = self.current_pos + len;
                buf.put_slice(&self.current[self.current_pos..end]);
                self.current_pos = end;
                if self.current_pos == self.current.len() {
                    self.current.clear();
                    self.current_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.reader).poll_recv(cx)) {
                Some(Ok(payload)) if payload.is_empty() => continue,
                Some(Ok(payload)) => {
                    self.current = payload;
                    self.current_pos = 0;
                }
                Some(Err(error)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        error,
                    )));
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S> AsyncWrite for XhttpStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.as_mut().poll_pending(cx))?;
        self.queue_payload(buf).map_err(std::io::Error::other)?;
        ready!(self.as_mut().poll_pending(cx))?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_pending(cx))?;
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_pending(cx))?;
        if !self.close_sent {
            self.close_sent = true;
            self.queue_close();
        }
        ready!(self.as_mut().poll_pending(cx))?;
        Pin::new(&mut self.writer).poll_flush(cx)
    }
}

async fn write_request_head<S>(
    stream: &mut S,
    transport: &VlessTransportConfig,
    default_host: &str,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let host = transport.request_host(default_host);
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\n",
        request_path_with_padding(&transport.path),
        host
    );
    for (key, value) in &transport.headers {
        ensure!(
            !key.eq_ignore_ascii_case("content-length")
                && !key.eq_ignore_ascii_case("transfer-encoding"),
            "VLESS XHTTP request header {key} conflicts with chunked stream-one body"
        );
        if !key.eq_ignore_ascii_case("host") {
            request.push_str(key);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("write VLESS XHTTP request head")?;
    stream.flush().await.context("flush VLESS XHTTP request")
}

async fn read_chunks<S>(
    mut reader: ReadHalf<S>,
    sender: mpsc::Sender<Result<Vec<u8>, String>>,
    role: XhttpRole,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if matches!(role, XhttpRole::Client) {
        let response = vless_http::read_http_head(&mut reader).await?;
        ensure_response(&response)?;
    }
    loop {
        let Some(payload) = read_chunk(&mut reader).await? else {
            return Ok(());
        };
        if sender.send(Ok(payload)).await.is_err() {
            return Ok(());
        }
    }
}

async fn read_chunk<R>(reader: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let Some(line) = read_crlf_line(reader).await? else {
        return Ok(None);
    };
    let size_text = line.split_once(';').map(|(size, _)| size).unwrap_or(&line);
    let size = usize::from_str_radix(size_text.trim(), 16)
        .with_context(|| format!("invalid XHTTP chunk size {line}"))?;
    if size == 0 {
        loop {
            let Some(trailer) = read_crlf_line(reader).await? else {
                return Ok(None);
            };
            if trailer.is_empty() {
                return Ok(None);
            }
        }
    }
    let mut payload = vec![0u8; size];
    reader
        .read_exact(&mut payload)
        .await
        .context("read VLESS XHTTP chunk payload")?;
    let mut crlf = [0u8; 2];
    reader
        .read_exact(&mut crlf)
        .await
        .context("read VLESS XHTTP chunk terminator")?;
    ensure!(crlf == *b"\r\n", "invalid VLESS XHTTP chunk terminator");
    Ok(Some(payload))
}

async fn read_crlf_line<R>(reader: &mut R) -> Result<Option<String>>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read_exact(&mut byte).await {
            Ok(_) => line.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && line.is_empty() => {
                return Ok(None);
            }
            Err(error) => return Err(error).context("read VLESS XHTTP chunk line"),
        }
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return String::from_utf8(line)
                .map(Some)
                .context("decode VLESS XHTTP chunk line");
        }
    }
}

fn ensure_request(head: &str, transport: &VlessTransportConfig) -> Result<()> {
    let line = head.lines().next().context("XHTTP request is empty")?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    ensure!(
        method.eq_ignore_ascii_case("POST"),
        "unsupported XHTTP stream-one method {method}"
    );
    ensure!(
        path_matches(path, &transport.path),
        "unexpected XHTTP path {path}, expected {}",
        transport.path
    );
    let transfer_encoding = vless_http::header_value(head, "Transfer-Encoding").unwrap_or_default();
    ensure!(
        transfer_encoding
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("chunked")),
        "VLESS XHTTP request must use chunked transfer encoding"
    );
    Ok(())
}

fn ensure_response(head: &str) -> Result<()> {
    ensure!(
        head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200"),
        "VLESS XHTTP server returned non-200 response: {}",
        head.lines().next().unwrap_or_default()
    );
    let transfer_encoding = vless_http::header_value(head, "Transfer-Encoding").unwrap_or_default();
    ensure!(
        transfer_encoding
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("chunked")),
        "VLESS XHTTP response must use chunked transfer encoding"
    );
    Ok(())
}

fn response_head() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nX-Padding: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
        "X".repeat(X_PADDING_LEN)
    )
}

fn append_chunk(output: &mut Vec<u8>, payload: &[u8]) {
    output.extend_from_slice(format!("{:X}\r\n", payload.len()).as_bytes());
    output.extend_from_slice(payload);
    output.extend_from_slice(b"\r\n");
}

fn request_path_with_padding(path: &str) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}x_padding={}", "X".repeat(X_PADDING_LEN))
}

fn path_matches(request_path: &str, expected_path: &str) -> bool {
    let path = request_path
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(request_path);
    path == expected_path
        || (expected_path != "/"
            && path
                .strip_prefix(expected_path)
                .is_some_and(|tail| tail.starts_with('/')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chunk_roundtrip() -> Result<()> {
        let mut encoded = Vec::new();
        append_chunk(&mut encoded, b"hello");
        encoded.extend_from_slice(b"0\r\n\r\n");
        let mut slice = encoded.as_slice();
        let decoded = read_chunk(&mut slice).await?.context("chunk")?;
        assert_eq!(decoded, b"hello");
        assert!(read_chunk(&mut slice).await?.is_none());
        Ok(())
    }

    #[test]
    fn request_path_preserves_existing_query() {
        assert_eq!(
            request_path_with_padding("/x?a=b"),
            format!("/x?a=b&x_padding={}", "X".repeat(X_PADDING_LEN))
        );
    }
}
