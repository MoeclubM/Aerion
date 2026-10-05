mod transport_performance {
    use super::*;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    async fn transfer(
        stream: &mut WebSocketStream<tokio::io::DuplexStream>,
        peer: &mut tokio::io::DuplexStream,
        payload: &[u8],
        received: &mut [u8],
    ) -> Result<()> {
        tokio::try_join!(
            async {
                stream.write_all(payload).await?;
                Ok::<(), anyhow::Error>(())
            },
            async {
                let mut offset = 0;
                while offset < received.len() {
                    let frame = read_frame(peer).await?.context("frame")?;
                    assert!(!frame.payload.is_empty());
                    let end = offset + frame.payload.len();
                    received[offset..end].copy_from_slice(&frame.payload);
                    offset = end;
                }
                assert_eq!(black_box(received), payload);
                Ok::<(), anyhow::Error>(())
            },
        )?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "release benchmark run by transport-performance workflow"]
    async fn websocket_backpressure() -> Result<()> {
        for size in [16384, 32768, 65536] {
            for capacity in [512, 8192, 65536] {
                let (stream, mut peer) = tokio::io::duplex(capacity);
                let mut stream = WebSocketStream::new(stream, WebSocketRole::Server);
                let payload = vec![0x42; size];
                let mut received = vec![0; size];
                for _ in 0..8 {
                    transfer(&mut stream, &mut peer, &payload, &mut received).await?;
                }
                let start = Instant::now();
                let mut iterations = 0;
                while start.elapsed() < Duration::from_millis(350) {
                    transfer(&mut stream, &mut peer, &payload, &mut received).await?;
                    iterations += 1;
                }
                println!(
                    "PERF websocket-{size}-pipe-{capacity} {:.3}",
                    size as f64 * iterations as f64 / start.elapsed().as_secs_f64() / 1048576.0
                );
            }
        }
        Ok(())
    }
}
