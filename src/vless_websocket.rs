use crate::vless_http;
use crate::vless_transport::VlessTransportConfig;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose};
use sha1::{Digest, Sha1};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, ready};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf, split,
};
use tokio::sync::mpsc;

const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xa;
const MAX_WEBSOCKET_FRAME: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
enum WebSocketRole {
    Client,
    Server,
}

pub struct WebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    reader: mpsc::Receiver<Result<Vec<u8>, String>>,
    current: Vec<u8>,
    current_pos: usize,
    writer: WriteHalf<S>,
    role: WebSocketRole,
    pending_write: Vec<u8>,
    pending_pos: usize,
    close_sent: bool,
}

struct WebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

pub async fn client<S>(
    mut stream: S,
    transport: &VlessTransportConfig,
    default_host: &str,
) -> Result<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let key = websocket_key()?;
    vless_http::write_upgrade_request(
        &mut stream,
        transport,
        default_host,
        &[
            ("Sec-WebSocket-Version", "13".to_string()),
            ("Sec-WebSocket-Key", key.clone()),
        ],
    )
    .await?;
    let response = vless_http::read_http_head(&mut stream).await?;
    ensure!(
        response.starts_with("HTTP/1.1 101") || response.starts_with("HTTP/1.0 101"),
        "VLESS WebSocket server returned non-101 response: {}",
        response.lines().next().unwrap_or_default()
    );
    vless_http::ensure_upgrade_headers(&response, "websocket")?;
    let accept = vless_http::header_value(&response, "Sec-WebSocket-Accept")
        .context("VLESS WebSocket response missing Sec-WebSocket-Accept")?;
    ensure!(
        accept == websocket_accept(&key),
        "VLESS WebSocket response has invalid Sec-WebSocket-Accept"
    );
    Ok(WebSocketStream::new(stream, WebSocketRole::Client))
}

pub async fn server<S>(
    mut stream: S,
    transport: &VlessTransportConfig,
) -> Result<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = vless_http::read_http_head(&mut stream).await?;
    vless_http::ensure_request_path(&request, &transport.path)?;
    vless_http::ensure_upgrade_headers(&request, "websocket")?;
    let key = vless_http::header_value(&request, "Sec-WebSocket-Key")
        .context("VLESS WebSocket request missing Sec-WebSocket-Key")?;
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        websocket_accept(key)
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write VLESS WebSocket handshake response")?;
    stream
        .flush()
        .await
        .context("flush VLESS WebSocket handshake")?;
    Ok(WebSocketStream::new(stream, WebSocketRole::Server))
}

impl<S> WebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn new(stream: S, role: WebSocketRole) -> Self {
        let (reader, writer) = split(stream);
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            if let Err(error) = read_frames(reader, tx.clone()).await {
                let _ = tx.send(Err(format!("{error:?}"))).await;
            }
        });
        Self {
            reader: rx,
            current: Vec::new(),
            current_pos: 0,
            writer,
            role,
            pending_write: Vec::new(),
            pending_pos: 0,
            close_sent: false,
        }
    }

    fn poll_pending(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        while self.pending_pos < self.pending_write.len() {
            let start = self.pending_pos;
            let chunk = self.pending_write[start..].to_vec();
            let written = ready!(Pin::new(&mut self.writer).poll_write(cx, &chunk))?;
            if written == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "write websocket frame",
                )));
            }
            self.pending_pos += written;
        }
        self.pending_write.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for WebSocketStream<S>
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

impl<S> AsyncWrite for WebSocketStream<S>
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
        self.pending_write = build_frame(
            OPCODE_BINARY,
            buf,
            matches!(self.role, WebSocketRole::Client),
        )
        .map_err(std::io::Error::other)?;
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
            self.pending_write = build_frame(
                OPCODE_CLOSE,
                &[],
                matches!(self.role, WebSocketRole::Client),
            )
            .map_err(std::io::Error::other)?;
        }
        ready!(self.as_mut().poll_pending(cx))?;
        Pin::new(&mut self.writer).poll_flush(cx)
    }
}

async fn read_frames<S>(
    mut reader: ReadHalf<S>,
    sender: mpsc::Sender<Result<Vec<u8>, String>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let Some(frame) = read_frame(&mut reader).await? else {
            return Ok(());
        };
        match frame.opcode {
            OPCODE_BINARY | OPCODE_TEXT | OPCODE_CONTINUATION => {
                if sender.send(Ok(frame.payload)).await.is_err() {
                    return Ok(());
                }
            }
            OPCODE_CLOSE => return Ok(()),
            OPCODE_PING | OPCODE_PONG => {}
            other => bail!("unsupported WebSocket opcode {other:#x}"),
        }
    }
}

async fn read_frame<R>(reader: &mut R) -> Result<Option<WebSocketFrame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("read WebSocket frame header"),
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut len = u64::from(header[1] & 0x7f);
    if len == 126 {
        let mut bytes = [0u8; 2];
        reader
            .read_exact(&mut bytes)
            .await
            .context("read WebSocket frame 16-bit length")?;
        len = u64::from(u16::from_be_bytes(bytes));
    } else if len == 127 {
        let mut bytes = [0u8; 8];
        reader
            .read_exact(&mut bytes)
            .await
            .context("read WebSocket frame 64-bit length")?;
        len = u64::from_be_bytes(bytes);
    }
    ensure!(
        len as usize <= MAX_WEBSOCKET_FRAME,
        "WebSocket frame length {len} exceeds {MAX_WEBSOCKET_FRAME}"
    );
    let mut mask = [0u8; 4];
    if masked {
        reader
            .read_exact(&mut mask)
            .await
            .context("read WebSocket frame mask")?;
    }
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("read WebSocket frame payload")?;
    }
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Some(WebSocketFrame { opcode, payload }))
}

fn build_frame(opcode: u8, payload: &[u8], masked: bool) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= MAX_WEBSOCKET_FRAME,
        "WebSocket payload length {} exceeds {MAX_WEBSOCKET_FRAME}",
        payload.len()
    );
    let mut frame = Vec::with_capacity(payload.len() + 16);
    frame.push(0x80 | opcode);
    let mask_bit = if masked { 0x80 } else { 0 };
    match payload.len() {
        0..=125 => frame.push(mask_bit | payload.len() as u8),
        126..=65535 => {
            frame.push(mask_bit | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(mask_bit | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    if masked {
        let mut mask = [0u8; 4];
        getrandom::fill(&mut mask).context("generate WebSocket mask")?;
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
    } else {
        frame.extend_from_slice(payload);
    }
    Ok(frame)
}

fn websocket_key() -> Result<String> {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).context("generate WebSocket key")?;
    Ok(general_purpose::STANDARD.encode(key))
}

fn websocket_accept(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    general_purpose::STANDARD.encode(sha1.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn websocket_frame_roundtrip() -> Result<()> {
        let frame = build_frame(OPCODE_BINARY, b"hello", true)?;
        let decoded = read_frame(&mut frame.as_slice()).await?.context("frame")?;
        assert_eq!(decoded.opcode, OPCODE_BINARY);
        assert_eq!(decoded.payload, b"hello");
        Ok(())
    }
}
