use super::*;
use std::io::IoSlice;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/performance/anytls.rs"
));

struct FragmentedWriter {
    bytes: Vec<u8>,
    limit: usize,
    pending: bool,
    vectored: bool,
    vectored_calls: usize,
}

impl tokio::io::AsyncWrite for FragmentedWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        input: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.pending = true;
        let len = input.len().min(self.limit);
        self.bytes.extend_from_slice(&input[..len]);
        std::task::Poll::Ready(Ok(len))
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        slices: &[IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.pending = true;
        self.vectored_calls += 1;
        let mut written = 0;
        for slice in slices {
            let len = slice.len().min(self.limit - written);
            self.bytes.extend_from_slice(&slice[..len]);
            written += len;
            if written == self.limit {
                break;
            }
        }
        std::task::Poll::Ready(Ok(written))
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn anytls_vectored_writes_preserve_frames_across_header_and_payload_boundaries() -> Result<()>
{
    for vectored in [false, true] {
        for limit in [1, 5, 7, 9, 32] {
            let inner = FragmentedWriter {
                bytes: Vec::new(),
                limit,
                pending: false,
                vectored,
                vectored_calls: 0,
            };
            let mut writer = PaddedFrameWriter::new(inner, PaddingScheme::from_text("stop=1")?);
            writer.write_frame(CMD_SYN, 42, &[]).await?;
            let payload = (0..66000).map(|i| i as u8).collect::<Vec<_>>();
            writer.write_payload_chunks(42, &payload).await?;
            writer.write_frame(CMD_FIN, 42, &[]).await?;
            write_frame(&mut writer.inner, CMD_SYN, 43, &[]).await?;
            let mut reader = writer.inner.bytes.as_slice();
            let frame = read_frame(&mut reader).await?;
            assert_eq!((frame.cmd, frame.stream_id), (CMD_SYN, 42));
            let mut received = Vec::new();
            for _ in 0..2 {
                let frame = read_frame(&mut reader).await?;
                assert_eq!((frame.cmd, frame.stream_id), (CMD_PSH, 42));
                received.extend(frame.payload);
            }
            assert_eq!(received, payload);
            let frame = read_frame(&mut reader).await?;
            assert_eq!((frame.cmd, frame.stream_id), (CMD_FIN, 42));
            let frame = read_frame(&mut reader).await?;
            assert_eq!((frame.cmd, frame.stream_id), (CMD_SYN, 43));
            assert!(reader.is_empty());
            assert_eq!(writer.inner.vectored_calls > 0, vectored);
        }
    }
    let mut writer = FragmentedWriter {
        bytes: Vec::new(),
        limit: 0,
        pending: false,
        vectored: true,
        vectored_calls: 0,
    };
    for size in [0, VECTORED_FRAME_MIN_PAYLOAD] {
        let error = write_frame(&mut writer, CMD_PSH, 1, &vec![0; size])
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::WriteZero,
        );
    }
    assert!(writer.vectored_calls > 0);
    Ok(())
}

#[test]
fn encodes_and_decodes_domain_target() {
    let target = ProxyTarget::Domain("example.com".to_string(), 443);
    let encoded = encode_target(&target).unwrap();
    let (decoded, tail) = decode_target(&encoded).unwrap();
    assert_eq!(decoded, target);
    assert!(tail.is_empty());
}

#[test]
fn encodes_and_decodes_ipv4_target() {
    let target = ProxyTarget::Ip("127.0.0.1:8080".parse().unwrap());
    let encoded = encode_target(&target).unwrap();
    let (decoded, tail) = decode_target(&encoded).unwrap();
    assert_eq!(decoded, target);
    assert!(tail.is_empty());
}

#[test]
fn encodes_ipv4_mapped_ipv6_as_ipv4() {
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
    let encoded = encode_target(&ProxyTarget::Ip(mapped)).unwrap();
    assert_eq!(encoded[0], 0x01);
    let (decoded, tail) = decode_target(&encoded).unwrap();
    assert_eq!(decoded, ProxyTarget::Ip("127.0.0.1:8080".parse().unwrap()));
    assert!(tail.is_empty());
}
