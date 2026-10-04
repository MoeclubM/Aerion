mod protocol_performance {
    use super::*;
    use std::hint::black_box;
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/performance/support.rs"
        ));
    }

    struct CountingWriter(u64);

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0 += 1;
            black_box(buffer);
            std::task::Poll::Ready(Ok(buffer.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_write_vectored(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffers: &[std::io::IoSlice<'_>],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0 += 1;
            black_box(buffers);
            std::task::Poll::Ready(Ok(buffers.iter().map(|buffer| buffer.len()).sum()))
        }
        fn is_write_vectored(&self) -> bool {
            true
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    #[ignore = "release benchmark run by protocol-performance workflow"]
    fn vmess_body() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        for security in [
            SecurityType::None,
            SecurityType::Aes128Gcm,
            SecurityType::ChaCha20Poly1305,
        ] {
            let options = RequestOptions::new(
                REQUEST_OPTION_CHUNK_STREAM
                    | if security == SecurityType::None {
                        0
                    } else {
                        REQUEST_OPTION_AUTHENTICATED_LENGTH
                    },
            );
            let config = BodyConfig::new_request(security, options, [0x11; 16], [0x22; 16])?;
            for size in [64, 1024, 16384] {
                let plain = vec![0x42; size];
                let mut writer = BodyWriter::new(CountingWriter(0), config);
                let iterations =
                    support::measure(&format!("vmess-write-{security}-{size}"), size, || {
                        runtime
                            .block_on(writer.write_all_plain(black_box(&plain)))
                            .unwrap();
                    });
                println!(
                    "VMess {security} {size}: underlying writes/chunk {:.1}",
                    writer.inner.0 as f64 / iterations as f64
                );

                let mut writer = BodyWriter::new(Vec::new(), config);
                runtime.block_on(async {
                    for _ in 0..256 {
                        writer.write_all_plain(&plain).await.unwrap();
                    }
                });
                let wire = writer.inner;
                let mut reader = BodyReader::new(wire.as_slice(), config);
                let mut output = vec![0; size];
                let mut count = 0;
                support::measure(&format!("vmess-read-{security}-{size}"), size, || {
                    if count == 256 {
                        reader = BodyReader::new(wire.as_slice(), config);
                        count = 0;
                    }
                    assert_eq!(
                        runtime.block_on(reader.read_plain(&mut output)).unwrap(),
                        size
                    );
                    black_box(&output);
                    count += 1;
                });
            }
        }
        Ok(())
    }
}
