use super::VisionControl;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

// Keep rustls from reading beyond an outer TLS record. Otherwise it can ingest
// raw inner TLS records immediately following the final DIRECT padding block.
pub(crate) struct RecordIo {
    pub(crate) tcp: TcpStream,
    header: [u8; 5],
    header_len: usize,
    remaining: usize,
    limited: bool,
    completed: bool,
}

impl RecordIo {
    pub(crate) fn new(tcp: TcpStream) -> Self {
        Self {
            tcp,
            header: [0; 5],
            header_len: 0,
            remaining: 0,
            limited: false,
            completed: false,
        }
    }

    fn begin_read(&mut self) {
        self.limited = true;
        self.completed = false;
    }
}

impl AsyncRead for RecordIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.limited && self.completed {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let limit = if self.header_len < 5 {
            5 - self.header_len
        } else {
            self.remaining
        };
        let limit = limit.min(buf.remaining());
        let mut restricted = ReadBuf::new(&mut buf.initialize_unfilled()[..limit]);
        match Pin::new(&mut self.tcp).poll_read(cx, &mut restricted) {
            Poll::Ready(Ok(())) => {
                let bytes = restricted.filled();
                let n = bytes.len();
                if self.header_len < 5 {
                    let start = self.header_len;
                    self.header[start..start + n].copy_from_slice(bytes);
                    self.header_len += n;
                    if self.header_len == 5 {
                        self.remaining =
                            u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                    }
                } else {
                    self.remaining -= n;
                }
                if self.header_len == 5 && self.remaining == 0 {
                    self.header_len = 0;
                    self.completed = true;
                }
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for RecordIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

pub(crate) struct VisionTlsStream {
    inner: tokio_rustls::TlsStream<RecordIo>,
    control: Arc<VisionControl>,
}

impl VisionTlsStream {
    pub(crate) fn new(
        inner: impl Into<tokio_rustls::TlsStream<RecordIo>>,
        control: Arc<VisionControl>,
    ) -> Self {
        Self {
            inner: inner.into(),
            control,
        }
    }
}

impl AsyncRead for VisionTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.control.read_direct() {
            // Plaintext left in rustls belongs to the final outer record and
            // must precede bytes read directly from the socket.
            let target = buf.initialize_unfilled();
            let result = match &mut self.inner {
                tokio_rustls::TlsStream::Client(s) => s.get_mut().1.reader().read(target),
                tokio_rustls::TlsStream::Server(s) => s.get_mut().1.reader().read(target),
            };
            match result {
                Ok(n) if n > 0 => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() != io::ErrorKind::WouldBlock => return Poll::Ready(Err(e)),
                _ => {}
            }
            return Pin::new(&mut self.inner.get_mut().0.tcp).poll_read(cx, buf);
        }
        self.inner.get_mut().0.begin_read();
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VisionTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.control.write_direct() {
            Pin::new(&mut self.inner.get_mut().0.tcp).poll_write(cx, buf)
        } else {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.write_direct() {
            Pin::new(&mut self.inner.get_mut().0.tcp).poll_flush(cx)
        } else {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control.read_direct() || self.control.write_direct() {
            Pin::new(&mut self.inner.get_mut().0.tcp).poll_shutdown(cx)
        } else {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
}
