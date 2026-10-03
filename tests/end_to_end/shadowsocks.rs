use super::helpers::*;
use aerion::{ShadowsocksClientConfig, ShadowsocksServerConfig, run_shadowsocks_server_with_core};

#[tokio::test]
async fn malformed_udp_packets_do_not_stop_the_server() -> Result<()> {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let mut bytes = [0; 64];
        let (read, peer) = echo.recv_from(&mut bytes).await?;
        echo.send_to(&bytes[..read], peer).await
    });
    let addr = unused_udp_addr()?;
    let server = tokio::spawn(aerion::run_shadowsocks_server(ShadowsocksServerConfig {
        listen: addr,
        method: "aes-128-gcm".into(),
        password: "secret".into(),
        users: vec![],
        tcp: false,
        udp: true,
        udp_over_tcp: false,
    }));
    let result = timeout(Duration::from_secs(5), async {
        while std::net::UdpSocket::bind(addr).is_ok() {
            tokio::task::yield_now().await;
            anyhow::ensure!(!server.is_finished(), "UDP server failed to start");
        }
        let malformed = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        malformed.send_to(b"invalid", addr).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        anyhow::ensure!(
            !server.is_finished(),
            "malformed packet stopped the listener"
        );
        let config = shadowsocks::config::ServerConfig::new(
            addr,
            "secret",
            shadowsocks::crypto::CipherKind::AES_128_GCM,
        )?;
        let context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local);
        let proxy = shadowsocks::relay::udprelay::ProxySocket::connect(context, &config).await?;
        proxy
            .send(
                &shadowsocks::relay::socks5::Address::SocketAddress(echo_addr),
                b"valid",
            )
            .await?;
        let mut bytes = [0; 64];
        let (read, target, _) = proxy.recv(&mut bytes).await?;
        anyhow::ensure!(
            &bytes[..read] == b"valid"
                && target == shadowsocks::relay::socks5::Address::SocketAddress(echo_addr),
            "valid UDP relay failed"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("Shadowsocks UDP regression timed out")
    .and_then(|result| result);
    server.abort();
    echo_task.abort();
    result
}

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
    let client_core = aerion::ProxyCore::from_credentials("test-password", &[]);
    let client_task = tokio::spawn(
        aerion::shadowsocks::run_shadowsocks_client_listener_with_core(
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
            Some(client_core.clone()),
        ),
    );

    let payload = b"hello ss core";
    let result = timeout(Duration::from_secs(5), async {
        socks_echo(client_addr, echo_addr, payload).await?;
        let client_stats = client_core.snapshot().await;
        anyhow::ensure!(
            client_stats[0].upload_bytes == payload.len() as u64
                && client_stats[0].download_bytes == payload.len() as u64,
            "Shadowsocks client did not record payload bytes"
        );
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
