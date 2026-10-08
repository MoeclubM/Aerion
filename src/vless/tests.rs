use super::*;

const UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

#[tokio::test]
async fn revoked_idle_vision_closes_both_tcp_writers() -> Result<()> {
    let incoming = TcpListener::bind("127.0.0.1:0").await?;
    let local = TcpStream::connect(incoming.local_addr()?).await?;
    let (stream, _) = incoming.accept().await?;
    let outgoing = TcpListener::bind("127.0.0.1:0").await?;
    let remote = TcpStream::connect(outgoing.local_addr()?).await?;
    let (mut target, _) = outgoing.accept().await?;
    let core = ProxyCore::from_credentials("secret", &[]);
    let session = core.authenticate("secret").await?;
    let relay = tokio::spawn(relay_vision_server_counted(
        stream,
        remote,
        session,
        parse_uuid(UUID)?,
        Arc::new(VisionControl::default()),
    ));
    core.cancel_all_sessions();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        assert!(relay.await?.is_err());
        let mut local = local;
        assert_eq!(local.read(&mut [0u8; 1]).await?, 0);
        assert_eq!(target.read(&mut [0u8; 1]).await?, 0);
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn request_roundtrip() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 443);
    let mut bytes = Vec::new();
    write_vless_request(&mut bytes, &parse_uuid(UUID)?, CMD_TCP, &target, "").await?;
    let request = read_vless_request(&mut bytes.as_slice()).await?;
    assert_eq!(request.user, parse_uuid(UUID)?);
    assert_eq!(request.command, CMD_TCP);
    assert_eq!(request.target, target);
    Ok(())
}
