mod transport_performance {
    use super::*;
    use std::hint::black_box;
    use std::time::Instant;

    async fn transfer(size: usize, buffered: bool, counted: bool, tcp: bool) -> Result<()> {
        let core = ProxyCore::new(vec![CoreUser::password("bench", "secret")])?;
        let session = if counted {
            core.authenticate("secret").await?
        } else {
            CoreSession::disabled()
        };
        let pair = async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let (client, accepted) = tokio::try_join!(
                tokio::net::TcpStream::connect(listener.local_addr()?),
                listener.accept(),
            )?;
            client.set_nodelay(true)?;
            accepted.0.set_nodelay(true)?;
            Ok::<_, anyhow::Error>((client, accepted.0))
        };
        type Stream = Box<dyn super::AsyncStream>;
        let (mut source, left, mut destination, right): (Stream, Stream, Stream, Stream) = if tcp {
            let (source, left) = pair.await?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let (destination, accepted) = tokio::try_join!(
                tokio::net::TcpStream::connect(listener.local_addr()?),
                listener.accept(),
            )?;
            destination.set_nodelay(true)?;
            accepted.0.set_nodelay(true)?;
            (
                Box::new(source),
                Box::new(left),
                Box::new(destination),
                Box::new(accepted.0),
            )
        } else {
            let (source, left) = duplex(128 * 1024);
            let (destination, right) = duplex(128 * 1024);
            (
                Box::new(source),
                Box::new(left),
                Box::new(destination),
                Box::new(right),
            )
        };
        let (lr, lw) = tokio::io::split(left);
        let (rr, rw) = tokio::io::split(right);
        let payload = vec![0x42; 512 * 1024];
        let mut received = vec![0; payload.len()];
        let traffic = async {
            tokio::try_join!(
                async {
                    for chunk in payload.chunks(size) {
                        source.write_all(chunk).await?;
                    }
                    Ok::<(), anyhow::Error>(())
                },
                async {
                    destination.read_exact(&mut received).await?;
                    Ok::<(), anyhow::Error>(())
                },
            )?;
            source.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        let relay = async {
            if buffered {
                relay_split_counted(
                    lr,
                    BufWriter::with_capacity(64 * 1024, lw),
                    rr,
                    BufWriter::with_capacity(64 * 1024, rw),
                    session,
                    "bench",
                )
                .await
            } else {
                relay_split_counted(lr, lw, rr, rw, session, "bench").await
            }
        };
        timeout(Duration::from_secs(5), async {
            tokio::try_join!(relay, traffic)
        })
        .await??;
        assert_eq!(black_box(received), payload);
        if counted {
            assert_eq!(core.snapshot().await[0].upload_bytes, payload.len() as u64);
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "release benchmark run by transport-performance workflow"]
    async fn relay_transfers() -> Result<()> {
        for tcp in [false, true] {
            for buffered in [false, true] {
                for counted in [false, true] {
                    for size in [1024, 32768] {
                        let label = format!(
                            "relay-{}-{}-{}-{size}",
                            if tcp { "tcp" } else { "pipe" },
                            if buffered { "buffered" } else { "raw" },
                            if counted { "counted" } else { "unlimited" }
                        );
                        for _ in 0..4 {
                            transfer(size, buffered, counted, tcp).await?;
                        }
                        let start = Instant::now();
                        let mut iterations = 0;
                        while start.elapsed() < Duration::from_millis(350) {
                            transfer(size, buffered, counted, tcp).await?;
                            iterations += 1;
                        }
                        println!(
                            "PERF {label} {:.3}",
                            0.5 * iterations as f64 / start.elapsed().as_secs_f64()
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
