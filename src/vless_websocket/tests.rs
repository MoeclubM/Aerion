use super::*;

#[tokio::test]
async fn websocket_frame_roundtrip() -> Result<()> {
    let frame = build_frame(OPCODE_BINARY, b"hello", true)?;
    let decoded = read_frame(&mut frame.as_slice()).await?.context("frame")?;
    assert_eq!(decoded.opcode, OPCODE_BINARY);
    assert_eq!(decoded.payload, b"hello");
    Ok(())
}

#[tokio::test]
async fn websocket_backpressure_sends_each_frame_once() -> Result<()> {
    for role in [WebSocketRole::Client, WebSocketRole::Server] {
        let (stream, mut peer) = tokio::io::duplex(32);
        let mut stream = WebSocketStream::new(stream, role);
        let payload = (0..65536).map(|i| i as u8).collect::<Vec<_>>();
        let send = async {
            stream.write_all(&payload).await?;
            stream.write_all(b"next-frame").await?;
            stream.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        let receive = async {
            let first = read_frame(&mut peer).await?.context("first frame")?;
            assert_eq!(first.opcode, OPCODE_BINARY);
            assert_eq!(first.payload, payload);
            let second = read_frame(&mut peer).await?.context("second frame")?;
            assert_eq!(second.payload, b"next-frame");
            let close = read_frame(&mut peer).await?.context("close frame")?;
            assert_eq!(close.opcode, OPCODE_CLOSE);
            Ok::<(), anyhow::Error>(())
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::try_join!(send, receive)
        })
        .await??;
    }
    Ok(())
}
