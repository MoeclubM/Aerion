use super::helpers::*;
use aerion::{
    ClientConfig, ServerConfig, ShadowsocksClientConfig, ShadowsocksServerConfig,
    run_client_listener, run_server_listener, run_shadowsocks_client_listener,
    run_shadowsocks_server_with_core,
};

#[tokio::test]
async fn socks_udp_associate_reaches_udp_target_through_uot() -> Result<()> {
    tls::init_crypto();

    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let server_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = server_listener.local_addr()?;
    let server_task = tokio::spawn(run_server_listener(
        server_listener,
        ServerConfig {
            listen: server_addr,
            password: "test-password".to_string(),
            users: Vec::new(),
            cert_path,
            key_path,
            certificates: Vec::new(),
            key: None,
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
            ech: None,
        },
    ));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_client_listener(
        client_listener,
        ClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            insecure: true,
            client_fingerprint: None,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
        },
        None,
    ));

    let result = timeout(Duration::from_secs(5), async {
        let mut control = TcpStream::connect(client_addr).await?;
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        control.read_exact(&mut greeting).await?;
        anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");

        write_socks_udp_associate(&mut control).await?;
        let udp_bind = read_socks_reply_addr(&mut control).await?;
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let packet = socks_udp_packet(udp_echo_addr, b"hello udp")?;
        udp.send_to(&packet, udp_bind).await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(payload == b"hello udp", "UDP echo payload mismatch");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("end-to-end UDP proxy test timed out")
    .and_then(|inner| inner);

    client_task.abort();
    server_task.abort();
    if result.is_ok() {
        udp_echo_task.await??;
    } else {
        udp_echo_task.abort();
    }
    result
}

#[tokio::test]
async fn socks_udp_associate_reaches_udp_target_through_shadowsocks_uot() -> Result<()> {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
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
            udp_over_tcp: true,
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
            udp: true,
            udp_over_tcp: true,
        },
    ));

    let result = timeout(Duration::from_secs(5), async {
        let mut control = TcpStream::connect(client_addr).await?;
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        control.read_exact(&mut greeting).await?;
        anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");

        write_socks_udp_associate(&mut control).await?;
        let udp_bind = read_socks_reply_addr(&mut control).await?;
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let payload = b"hello ss uot";
        udp.send_to(&socks_udp_packet(udp_echo_addr, payload)?, udp_bind)
            .await?;
        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let response_payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(
            response_payload == payload,
            "Shadowsocks UOT payload mismatch"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        let snapshots = core.snapshot().await;
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.user_id == "default")
            .context("missing Shadowsocks UOT core default user snapshot")?;
        anyhow::ensure!(
            snapshot.upload_bytes >= payload.len() as u64,
            "Shadowsocks UOT core upload was not recorded"
        );
        anyhow::ensure!(
            snapshot.download_bytes >= payload.len() as u64,
            "Shadowsocks UOT core download was not recorded"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Shadowsocks UOT end-to-end test timed out")
    .and_then(|inner| inner);

    client_task.abort();
    server_task.abort();
    if result.is_ok() {
        udp_echo_task.await??;
    } else {
        udp_echo_task.abort();
    }
    result
}
