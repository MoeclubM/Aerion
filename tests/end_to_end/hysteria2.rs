use super::helpers::*;
use aerion::{
    Hysteria2ClientConfig, Hysteria2ServerConfig, run_hysteria2_client_listener,
    run_hysteria2_server,
};

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_hysteria2_server() -> Result<()> {
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
    let cert_path = temp.path().join("hy2.crt");
    let key_path = temp.path().join("hy2.key");
    let certificate_fingerprint = hex::encode(Sha256::digest(certified.cert.der().as_ref()));
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_hysteria2_server(Hysteria2ServerConfig {
        listen: server_addr,
        password: "unused-password".to_string(),
        users: vec!["test-password".to_string()],
        cert_path,
        key_path,
        certificates: Vec::new(),
        key: None,
        obfs: None,
        obfs_password: None,
        upload_bandwidth: None,
        udp: true,
        cc_rx: "0".to_string(),
        congestion_control: "bbr".to_string(),
        auth_timeout: std::time::Duration::from_secs(10),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_hysteria2_client_listener(
        client_listener,
        Hysteria2ClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            insecure: false,
            certificate_fingerprint: Some(certificate_fingerprint),
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            obfs: None,
            obfs_password: None,
            upload_bandwidth: None,
            download_bandwidth: None,
            udp: true,
            congestion_control: "bbr".to_string(),
        },
    ));

    let result = timeout(Duration::from_secs(5), async {
        let mut socks = TcpStream::connect(client_addr).await?;
        socks.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        socks.read_exact(&mut greeting).await?;
        anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");

        write_socks_connect(&mut socks, echo_addr).await?;
        let mut reply = [0u8; 10];
        socks.read_exact(&mut reply).await?;
        anyhow::ensure!(reply[1] == 0x00, "SOCKS connect failed: {:?}", reply);

        socks.write_all(b"hello hy2").await?;
        let mut echoed = vec![0u8; "hello hy2".len()];
        socks.read_exact(&mut echoed).await?;
        anyhow::ensure!(echoed == b"hello hy2", "Hysteria2 echo payload mismatch");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Hysteria2 TCP end-to-end test timed out")
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
async fn hysteria2_server_finishes_when_tcp_target_fins() -> Result<()> {
    tls::init_crypto();

    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        stream.shutdown().await?;
        Ok::<(), std::io::Error>(())
    });

    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_path = temp.path().join("hy2-fin.crt");
    let key_path = temp.path().join("hy2-fin.key");
    let certificate_fingerprint = hex::encode(Sha256::digest(certified.cert.der().as_ref()));
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_hysteria2_server(Hysteria2ServerConfig {
        listen: server_addr,
        password: "test-password".to_string(),
        users: Vec::new(),
        cert_path,
        key_path,
        certificates: Vec::new(),
        key: None,
        obfs: None,
        obfs_password: None,
        upload_bandwidth: None,
        udp: true,
        cc_rx: "0".to_string(),
        congestion_control: "bbr".to_string(),
        auth_timeout: std::time::Duration::from_secs(10),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_hysteria2_client_listener(
        client_listener,
        Hysteria2ClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            insecure: false,
            certificate_fingerprint: Some(certificate_fingerprint),
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            obfs: None,
            obfs_password: None,
            upload_bandwidth: None,
            download_bandwidth: None,
            udp: true,
            congestion_control: "bbr".to_string(),
        },
    ));

    let result = timeout(Duration::from_secs(8), async {
        let mut socks = TcpStream::connect(client_addr).await?;
        socks.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut greeting = [0u8; 2];
        socks.read_exact(&mut greeting).await?;
        anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");
        write_socks_connect(&mut socks, target_addr).await?;
        let mut reply = [0u8; 10];
        socks.read_exact(&mut reply).await?;
        anyhow::ensure!(reply[1] == 0x00, "SOCKS connect failed: {:?}", reply);
        socks.write_all(b"ping").await?;
        let mut echoed = [0u8; 4];
        socks.read_exact(&mut echoed).await?;
        anyhow::ensure!(&echoed == b"ping", "echo payload mismatch");
        let mut tail = [0u8; 1];
        let read = socks.read(&mut tail).await?;
        anyhow::ensure!(read == 0, "expected Hysteria2 stream EOF after target FIN");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Hysteria2 target-FIN test timed out")
    .and_then(|inner| inner);

    client_task.abort();
    server_task.abort();
    if result.is_ok() {
        target_task.await??;
    } else {
        target_task.abort();
    }
    result
}

#[tokio::test]
async fn socks_udp_associate_reaches_udp_target_through_hysteria2_datagrams() -> Result<()> {
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
    let cert_path = temp.path().join("hy2-udp.crt");
    let key_path = temp.path().join("hy2-udp.key");
    let ca_cert_path = cert_path.clone();
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_hysteria2_server(Hysteria2ServerConfig {
        listen: server_addr,
        password: "test-password".to_string(),
        users: Vec::new(),
        cert_path,
        key_path,
        certificates: Vec::new(),
        key: None,
        obfs: None,
        obfs_password: None,
        upload_bandwidth: None,
        udp: true,
        cc_rx: "0".to_string(),
        congestion_control: "bbr".to_string(),
        auth_timeout: std::time::Duration::from_secs(10),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_hysteria2_client_listener(
        client_listener,
        Hysteria2ClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            password: "test-password".to_string(),
            sni: "localhost".to_string(),
            insecure: false,
            certificate_fingerprint: None,
            ca_cert_paths: vec![ca_cert_path],
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            obfs: None,
            obfs_password: None,
            upload_bandwidth: None,
            download_bandwidth: None,
            udp: true,
            congestion_control: "bbr".to_string(),
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
        udp.send_to(
            &socks_udp_packet(udp_echo_addr, b"hello hy2 udp")?,
            udp_bind,
        )
        .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(
            payload == b"hello hy2 udp",
            "Hysteria2 UDP payload mismatch"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Hysteria2 UDP end-to-end test timed out")
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
