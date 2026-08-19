use super::helpers::*;
use aerion::vless_transport::VlessTransportConfig;
use aerion::{
    UtlsFingerprint, VmessClientConfig, VmessServerConfig, run_vmess_client_listener,
    run_vmess_server,
};

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_vmess_server() -> Result<()> {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vmess_server(VmessServerConfig {
        listen: server_addr,
        user_id: "00000000-0000-0000-0000-000000000000".to_string(),
        users: vec![user_id.clone()],
        tls: false,
        cert_path: None,
        key_path: None,
        certificates: Vec::new(),
        key: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vmess_client_listener(
        client_listener,
        VmessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            security: "aes-128-gcm".to_string(),
            packet_encoding: String::new(),
            udp: true,
            tls: false,
            sni: String::new(),
            insecure: false,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: None,
            transport: VlessTransportConfig::tcp(),
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vmess"),
    )
    .await
    .context("VMess TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vmess_websocket() -> Result<()> {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let transport = VlessTransportConfig::websocket(Some("/vmess".to_string()), None, Vec::new());
    let server_task = tokio::spawn(run_vmess_server(VmessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: false,
        cert_path: None,
        key_path: None,
        certificates: Vec::new(),
        key: None,
        transport: transport.clone(),
        ech: None,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vmess_client_listener(
        client_listener,
        VmessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            security: "aes-128-gcm".to_string(),
            packet_encoding: String::new(),
            udp: true,
            tls: false,
            sni: String::new(),
            insecure: false,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: None,
            transport,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vmess ws"),
    )
    .await
    .context("VMess WebSocket TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vmess_tls_server() -> Result<()> {
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
    let cert_path = temp.path().join("vmess-tls.crt");
    let key_path = temp.path().join("vmess-tls.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vmess_server(VmessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path: Some(cert_path),
        key_path: Some(key_path),
        certificates: Vec::new(),
        key: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vmess_client_listener(
        client_listener,
        VmessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            security: "aes-128-gcm".to_string(),
            packet_encoding: String::new(),
            udp: true,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: Some(UtlsFingerprint::Chrome),
            transport: VlessTransportConfig::tcp(),
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vmess tls"),
    )
    .await
    .context("VMess TLS TCP end-to-end test timed out")
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
async fn socks_udp_associate_reaches_udp_target_through_vmess_server() -> Result<()> {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vmess_server(VmessServerConfig {
        listen: server_addr,
        user_id: "00000000-0000-0000-0000-000000000000".to_string(),
        users: vec![user_id.clone()],
        tls: false,
        cert_path: None,
        key_path: None,
        certificates: Vec::new(),
        key: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vmess_client_listener(
        client_listener,
        VmessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            security: "chacha20-poly1305".to_string(),
            packet_encoding: String::new(),
            udp: true,
            tls: false,
            sni: String::new(),
            insecure: false,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: None,
            transport: VlessTransportConfig::tcp(),
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
            &socks_udp_packet(udp_echo_addr, b"hello vmess udp")?,
            udp_bind,
        )
        .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(payload == b"hello vmess udp", "VMess UDP payload mismatch");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("VMess UDP end-to-end test timed out")
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
async fn socks_udp_associate_reaches_udp_target_through_vmess_packetaddr() -> Result<()> {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vmess_server(VmessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: false,
        cert_path: None,
        key_path: None,
        certificates: Vec::new(),
        key: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vmess_client_listener(
        client_listener,
        VmessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            security: "aes-128-gcm".to_string(),
            packet_encoding: "packetaddr".to_string(),
            udp: true,
            tls: false,
            sni: String::new(),
            insecure: false,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: None,
            transport: VlessTransportConfig::tcp(),
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
            &socks_udp_packet(udp_echo_addr, b"hello vmess packetaddr")?,
            udp_bind,
        )
        .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(
            payload == b"hello vmess packetaddr",
            "VMess packetaddr payload mismatch"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("VMess packetaddr UDP end-to-end test timed out")
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
async fn socks_udp_associate_reaches_udp_target_through_vmess_xudp() -> Result<()> {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vmess_server(VmessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: false,
        cert_path: None,
        key_path: None,
        certificates: Vec::new(),
        key: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vmess_client_listener(
        client_listener,
        VmessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            security: "aes-128-gcm".to_string(),
            packet_encoding: "xudp".to_string(),
            udp: true,
            tls: false,
            sni: String::new(),
            insecure: false,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: None,
            transport: VlessTransportConfig::tcp(),
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
            &socks_udp_packet(udp_echo_addr, b"hello vmess xudp")?,
            udp_bind,
        )
        .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(
            payload == b"hello vmess xudp",
            "VMess XUDP payload mismatch"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("VMess XUDP UDP end-to-end test timed out")
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
