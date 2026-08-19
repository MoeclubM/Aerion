use super::helpers::*;
use aerion::{NaiveClientConfig, NaiveServerConfig, run_naive_client_listener, run_naive_server};

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_naive_custom_roots() -> Result<()> {
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
    let cert_path = temp.path().join("naive.crt");
    let key_path = temp.path().join("naive.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;
    let ca_cert_path = cert_path.clone();

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_naive_server(NaiveServerConfig {
        listen: server_addr,
        username: "user".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        cert_path,
        key_path,
        certificates: Vec::new(),
        key: None,
        udp_over_tcp: false,
        tcp: true,
        quic: false,
        quic_congestion_control: "bbr".to_string(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_naive_client_listener(
        client_listener,
        NaiveClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "user".to_string(),
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            insecure: false,
            ca_cert_paths: vec![ca_cert_path],
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            extra_headers: Vec::new(),
            udp_over_tcp: false,
            quic: false,
            quic_congestion_control: "bbr".to_string(),
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello naive custom roots"),
    )
    .await
    .context("Naive custom roots end-to-end test timed out")
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
