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

#[tokio::test]
async fn serves_reused_and_concurrent_h2_streams() -> Result<()> {
    for grpc in [false, true] {
        let (client_io, server_io) = duplex(4096);
        let transport = if grpc {
            VlessTransportConfig::grpc(Some("Echo".into()), None, vec![])
        } else {
            VlessTransportConfig::http2(Some("/echo".into()), None, vec![])
        };
        let config = transport.clone();
        let server = tokio::spawn(async move {
            serve(server_io, &config, |mut stream| async move {
                let mut payload = [0; 5];
                stream.read_exact(&mut payload).await?;
                stream.write_all(&payload).await?;
                stream.shutdown().await?;
                Ok(())
            })
            .await
        });
        let (mut client, connection) = h2::client::handshake(client_io).await?;
        let driver = tokio::spawn(connection);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for _ in 0..2 {
                let mut tasks = tokio::task::JoinSet::new();
                for _ in 0..4 {
                    client = client.ready().await?;
                    let (response, body) = client.send_request(
                        build_client_request("POST", "example.com", &transport, grpc)?,
                        false,
                    )?;
                    let mut stream = stream_from_client_parts(response, body, grpc);
                    tasks.spawn(async move {
                        stream.write_all(b"hello").await?;
                        let mut payload = [0; 5];
                        stream.read_exact(&mut payload).await?;
                        assert_eq!(&payload, b"hello");
                        Ok::<_, anyhow::Error>(())
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result??;
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        server.abort();
        driver.abort();
    }
    Ok(())
}
