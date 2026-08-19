use super::helpers::*;
use aerion::vless_transport::VlessTransportConfig;
use aerion::{
    TrojanClientConfig, TrojanServerConfig, run_trojan_client_listener, run_trojan_server,
};

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_trojan_server() -> Result<()> {
    tls::init_crypto();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_path = temp.path().join("trojan.crt");
    let key_path = temp.path().join("trojan.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_trojan_server(TrojanServerConfig {
        listen: server_addr,
        password: "unused-password".to_string(),
        users: vec!["test-password".to_string()],
        cert_path,
        key_path,
        certificates: Vec::new(),
        key: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
        fallback: TrojanServerConfig::default_fallback(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_trojan_client_listener(
        client_listener,
        TrojanClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            insecure: true,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            udp: true,
            client_fingerprint: None,
            transport: VlessTransportConfig::tcp(),
        },
        None,
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello trojan"),
    )
    .await
    .context("Trojan TCP end-to-end test timed out")
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

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_trojan_websocket_server() -> Result<()> {
    tls::init_crypto();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_path = temp.path().join("trojan-ws.crt");
    let key_path = temp.path().join("trojan-ws.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;
    let transport = VlessTransportConfig::websocket(Some("/trojan".to_string()), None, Vec::new());

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_trojan_server(TrojanServerConfig {
        listen: server_addr,
        password: "unused-password".to_string(),
        users: vec!["test-password".to_string()],
        cert_path,
        key_path,
        certificates: Vec::new(),
        key: None,
        transport: transport.clone(),
        ech: None,
        fallback: TrojanServerConfig::default_fallback(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_trojan_client_listener(
        client_listener,
        TrojanClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            insecure: true,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            udp: true,
            client_fingerprint: None,
            transport,
        },
        None,
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello trojan ws"),
    )
    .await
    .context("Trojan WebSocket TCP end-to-end test timed out")
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
