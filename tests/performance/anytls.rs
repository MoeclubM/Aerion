mod transport_performance {
    use super::*;
    use std::hint::black_box;
    use std::time::{Duration, Instant};
    use tokio::io::DuplexStream;

    async fn tls_pair(
        capacity: usize,
    ) -> Result<(
        tokio_rustls::client::TlsStream<DuplexStream>,
        tokio_rustls::server::TlsStream<DuplexStream>,
    )> {
        crate::tls::init_crypto();
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(identity.key_pair.serialize_der().into()),
            )?;
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let connector = tokio_rustls::TlsConnector::from(crate::tls::client_config(true));
        let (client, server) = tokio::io::duplex(capacity);
        let name = rustls::pki_types::ServerName::try_from("localhost")?;
        Ok(tokio::try_join!(
            connector.connect(name, client),
            acceptor.accept(server),
        )?)
    }

    async fn measure<W, R>(
        writer: W,
        mut reader: R,
        size: usize,
        capacity: usize,
        padded: bool,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
        R: AsyncRead + Unpin,
    {
        let mut writer = PaddedFrameWriter::new(writer, PaddingScheme::default());
        writer.send_padding = padded;
        let payload = vec![0x42; size];
        let mut iterations = 0;
        let mut start = Instant::now();
        loop {
            tokio::try_join!(
                async {
                    writer.write_payload_chunks(7, &payload).await?;
                    Ok::<(), anyhow::Error>(())
                },
                async {
                    loop {
                        let frame = read_frame(&mut reader).await?;
                        if frame.cmd == CMD_WASTE {
                            continue;
                        }
                        assert_eq!(frame.cmd, CMD_PSH);
                        assert_eq!(frame.stream_id, 7);
                        assert_eq!(black_box(frame.payload), payload);
                        break;
                    }
                    Ok::<(), anyhow::Error>(())
                },
            )?;
            iterations += 1;
            if iterations == 16 {
                start = Instant::now();
            }
            if iterations > 16 && start.elapsed() >= Duration::from_millis(350) {
                break;
            }
        }
        let role = if padded { "client" } else { "server" };
        println!(
            "PERF anytls-{role}-tls-{size}-pipe-{capacity} {:.3}",
            size as f64 * (iterations - 16) as f64 / start.elapsed().as_secs_f64() / 1048576.0
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "release benchmark run by transport-performance workflow"]
    async fn anytls_tls_frames() -> Result<()> {
        for size in [64, 1024, 4096, 16384, 32768] {
            for capacity in [8192, 65536] {
                let (client, server) = tls_pair(capacity).await?;
                measure(client, server, size, capacity, true).await?;
                let (client, server) = tls_pair(capacity).await?;
                measure(server, client, size, capacity, false).await?;
            }
        }
        Ok(())
    }
}
