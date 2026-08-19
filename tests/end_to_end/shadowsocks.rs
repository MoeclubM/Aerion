use super::helpers::*;
use aerion::{
    ShadowsocksClientConfig, ShadowsocksServerConfig, run_shadowsocks_client_listener,
    run_shadowsocks_server_with_core,
};

#[tokio::test]
async fn shadowsocks_server_with_core_records_tcp_traffic() -> Result<()> {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), anyhow::Error>(())
    });

    let core = aerion::ProxyCore::from_credentials("test-password", &[]);
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_shadowsocks_server_with_core(
        ShadowsocksServerConfig {
            listen: server_addr,
            method: "aes-128-gcm".to_string(),
            password: "test-password".to_string(),
            users: Vec::new(),
            tcp: true,
            udp: false,
            udp_over_tcp: false,
        },
        core.clone(),
    ));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_shadowsocks_client_listener(
        client_listener,
        ShadowsocksClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            method: "aes-128-gcm".to_string(),
            password: "test-password".to_string(),
            udp: false,
            udp_over_tcp: false,
        },
    ));

    let payload = b"hello ss core";
    let result = timeout(Duration::from_secs(5), async {
        socks_echo(client_addr, echo_addr, payload).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let snapshots = core.snapshot().await;
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.user_id == "default")
            .context("missing Shadowsocks core default user snapshot")?;
        anyhow::ensure!(
            snapshot.upload_bytes >= payload.len() as u64,
            "Shadowsocks core upload was not recorded"
        );
        anyhow::ensure!(
            snapshot.download_bytes >= payload.len() as u64,
            "Shadowsocks core download was not recorded"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Shadowsocks core accounting test timed out")
    .and_then(|inner| inner);

    client_task.abort();
    server_task.abort();
    if result.is_ok() {
        echo_task.await??;
    } else {
        echo_task.abort();
    }
    result
}
