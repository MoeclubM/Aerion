use aerion::padding::PaddingScheme;
use aerion::protocol::{
    CMD_SERVER_SETTINGS, CMD_SETTINGS, parse_settings, password_hash, read_frame, write_frame,
};
use aerion::vless_transport::VlessTransportConfig;
use aerion::{
    ClientConfig, Hysteria2ClientConfig, Hysteria2ServerConfig, MieruClientConfig,
    MieruServerConfig, MieruTransport, RealityClientConfig, RealityServerConfig, ServerConfig,
    ShadowsocksClientConfig, ShadowsocksServerConfig, TrojanClientConfig, TrojanServerConfig,
    UtlsFingerprint, VlessClientConfig, VlessServerConfig, VmessClientConfig, VmessServerConfig,
    run_client_listener, run_hysteria2_client_listener, run_hysteria2_server,
    run_mieru_client_listener, run_mieru_server, run_server_listener,
    run_shadowsocks_client_listener, run_shadowsocks_server, run_trojan_client_listener,
    run_trojan_server, run_vless_client_listener, run_vless_server, run_vmess_client_listener,
    run_vmess_server, tls,
};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_aerion_server() -> Result<()> {
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
            password: "unused-password".to_string(),
            users: vec!["test-password".to_string()],
            cert_path,
            key_path,
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
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
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
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

        socks.write_all(b"hello aerion").await?;
        let mut echoed = vec![0u8; "hello aerion".len()];
        socks.read_exact(&mut echoed).await?;
        anyhow::ensure!(echoed == b"hello aerion", "echo payload mismatch");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("end-to-end proxy test timed out")
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
async fn anytls_server_accepts_auth_and_settings_in_tls_early_data() -> Result<()> {
    tls::init_crypto();

    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_path = temp.path().join("anytls-0rtt.crt");
    let key_path = temp.path().join("anytls-0rtt.key");
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
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
        },
    ));

    let tls_config = tls::client_config_early_data(true);
    let first = open_anytls_control_session(tls_config.clone(), server_addr, "test-password")
        .await
        .context("first AnyTLS TLS session")?;
    anyhow::ensure!(!first, "first connection must not have 0-RTT ticket yet");

    let second = open_anytls_control_session(tls_config, server_addr, "test-password")
        .await
        .context("second AnyTLS TLS session")?;
    anyhow::ensure!(second, "resumed AnyTLS session did not accept 0-RTT");

    server_task.abort();
    Ok(())
}

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
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
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
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
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

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_shadowsocks_server(ShadowsocksServerConfig {
        listen: server_addr,
        method: "aes-128-gcm".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        udp: false,
        udp_over_tcp: true,
    }));

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
        udp.send_to(&socks_udp_packet(udp_echo_addr, b"hello ss uot")?, udp_bind)
            .await?;
        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(
            payload == b"hello ss uot",
            "Shadowsocks UOT payload mismatch"
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
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_hysteria2_server(Hysteria2ServerConfig {
        listen: server_addr,
        password: "unused-password".to_string(),
        users: vec!["test-password".to_string()],
        cert_path,
        key_path,
        obfs: None,
        obfs_password: None,
        udp: true,
        cc_rx: "0".to_string(),
        congestion_control: "bbr".to_string(),
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
            insecure: true,
            obfs: None,
            obfs_password: None,
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
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_hysteria2_server(Hysteria2ServerConfig {
        listen: server_addr,
        password: "test-password".to_string(),
        users: Vec::new(),
        cert_path,
        key_path,
        obfs: None,
        obfs_password: None,
        udp: true,
        cc_rx: "0".to_string(),
        congestion_control: "bbr".to_string(),
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
            insecure: true,
            obfs: None,
            obfs_password: None,
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

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_mieru_server() -> Result<()> {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Tcp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Tcp,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello mieru"),
    )
    .await
    .context("Mieru TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_mieru_udp_packet_underlay() -> Result<()> {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Udp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Udp,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello mieru udp underlay"),
    )
    .await
    .context("Mieru UDP packet underlay TCP end-to-end test timed out")
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
async fn socks_udp_associate_reaches_udp_target_through_mieru_stream() -> Result<()> {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Tcp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Tcp,
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
            &socks_udp_packet(udp_echo_addr, b"hello mieru udp")?,
            udp_bind,
        )
        .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(payload == b"hello mieru udp", "Mieru UDP payload mismatch");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Mieru UDP-over-stream end-to-end test timed out")
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
async fn socks_udp_associate_reaches_udp_target_through_mieru_packet_underlay() -> Result<()> {
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let udp_echo_addr = udp_echo.local_addr()?;
    let udp_echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 256];
        let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
        udp_echo.send_to(&buffer[..read], peer).await?;
        Ok::<(), std::io::Error>(())
    });

    let server_addr = unused_udp_addr()?;
    let server_task = tokio::spawn(run_mieru_server(MieruServerConfig {
        listen: server_addr,
        username: "default".to_string(),
        password: "test-password".to_string(),
        users: Vec::new(),
        mtu: 1500,
        user_hint_mandatory: false,
        traffic_pattern: None,
        transport: MieruTransport::Udp,
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_mieru_client_listener(
        client_listener,
        MieruClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            username: "default".to_string(),
            password: "test-password".to_string(),
            hashed_password: None,
            mtu: 1500,
            traffic_pattern: None,
            transport: MieruTransport::Udp,
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
            &socks_udp_packet(udp_echo_addr, b"hello mieru packet udp")?,
            udp_bind,
        )
        .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(
            payload == b"hello mieru packet udp",
            "Mieru packet underlay UDP payload mismatch"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Mieru packet underlay UDP ASSOCIATE test timed out")
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
        transport: VlessTransportConfig::tcp(),
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
            udp: true,
            client_fingerprint: None,
            transport: VlessTransportConfig::tcp(),
        },
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
        transport: transport.clone(),
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
            udp: true,
            client_fingerprint: None,
            transport,
        },
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

#[tokio::test]
async fn socks_client_reaches_tcp_target_through_vless_server() -> Result<()> {
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
    let cert_path = temp.path().join("vless.crt");
    let key_path = temp.path().join("vless.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: "00000000-0000-0000-0000-000000000000".to_string(),
        users: vec![user_id.clone()],
        tls: true,
        cert_path,
        key_path,
        flow: String::new(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport: VlessTransportConfig::tcp(),
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vless"),
    )
    .await
    .context("VLESS TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vless_websocket() -> Result<()> {
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
    let cert_path = temp.path().join("vless-ws.crt");
    let key_path = temp.path().join("vless-ws.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let transport = VlessTransportConfig::websocket(Some("/vless".to_string()), None, Vec::new());
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path,
        key_path,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vless ws"),
    )
    .await
    .context("VLESS WebSocket TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vless_httpupgrade() -> Result<()> {
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
    let cert_path = temp.path().join("vless-httpupgrade.crt");
    let key_path = temp.path().join("vless-httpupgrade.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let transport =
        VlessTransportConfig::http_upgrade(Some("/upgrade".to_string()), None, Vec::new());
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path,
        key_path,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vless httpupgrade"),
    )
    .await
    .context("VLESS HTTPUpgrade TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vless_http2() -> Result<()> {
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
    let cert_path = temp.path().join("vless-h2.crt");
    let key_path = temp.path().join("vless-h2.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let transport = VlessTransportConfig::http2(Some("/h2".to_string()), None, Vec::new());
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path,
        key_path,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vless h2"),
    )
    .await
    .context("VLESS HTTP/2 TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vless_grpc() -> Result<()> {
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
    let cert_path = temp.path().join("vless-grpc.crt");
    let key_path = temp.path().join("vless-grpc.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let transport = VlessTransportConfig::grpc(Some("TunService".to_string()), None, Vec::new());
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path,
        key_path,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vless grpc"),
    )
    .await
    .context("VLESS gRPC TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vless_xhttp() -> Result<()> {
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
    let cert_path = temp.path().join("vless-xhttp.crt");
    let key_path = temp.path().join("vless-xhttp.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let transport = VlessTransportConfig::xhttp(
        Some("/xhttp".to_string()),
        None,
        Vec::new(),
        Some("stream-one".to_string()),
    )?;
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path,
        key_path,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vless xhttp"),
    )
    .await
    .context("VLESS XHTTP TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vless_reality() -> Result<()> {
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

    let mut server_private_bytes = [0u8; 32];
    getrandom::fill(&mut server_private_bytes)?;
    let server_private = StaticSecret::from(server_private_bytes);
    let server_public = PublicKey::from(&server_private).to_bytes();
    let short_id = [0xa1, 0xb2, 0, 0, 0, 0, 0, 0];

    let temp = tempfile::tempdir()?;
    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: false,
        cert_path: temp.path().join("unused.crt"),
        key_path: temp.path().join("unused.key"),
        flow: String::new(),
        reality: Some(RealityServerConfig {
            server_name: "localhost".to_string(),
            server_port: 443,
            server_names: vec!["localhost".to_string()],
            private_key: server_private.to_bytes(),
            short_ids: vec![short_id],
            alpn_protocols: Vec::new(),
        }),
        transport: VlessTransportConfig::tcp(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: false,
            sni: "localhost".to_string(),
            insecure: false,
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: Some(UtlsFingerprint::Chrome),
            reality: Some(RealityClientConfig {
                public_key: server_public,
                short_id,
            }),
            transport: VlessTransportConfig::tcp(),
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello reality"),
    )
    .await
    .context("VLESS REALITY TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vless_vision() -> Result<()> {
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
    let cert_path = temp.path().join("vless-vision.crt");
    let key_path = temp.path().join("vless-vision.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path,
        key_path,
        flow: "xtls-rprx-vision".to_string(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: "xtls-rprx-vision".to_string(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport: VlessTransportConfig::tcp(),
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello vision"),
    )
    .await
    .context("VLESS Vision TCP end-to-end test timed out")
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
async fn socks_client_reaches_tcp_target_through_vless_mux() -> Result<()> {
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
    let cert_path = temp.path().join("vless-mux.crt");
    let key_path = temp.path().join("vless-mux.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path,
        key_path,
        flow: String::new(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: true,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport: VlessTransportConfig::tcp(),
        },
    ));

    let result = timeout(
        Duration::from_secs(5),
        socks_echo(client_addr, echo_addr, b"hello mux"),
    )
    .await
    .context("VLESS mux TCP end-to-end test timed out")
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
async fn socks_udp_associate_reaches_udp_target_through_vless_xudp() -> Result<()> {
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
    let cert_path = temp.path().join("vless-xudp.crt");
    let key_path = temp.path().join("vless-xudp.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

    let user_id = "a3482e88-686a-4a58-8126-99c9df64b7bf".to_string();
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_vless_server(VlessServerConfig {
        listen: server_addr,
        user_id: user_id.clone(),
        users: Vec::new(),
        tls: true,
        cert_path,
        key_path,
        flow: String::new(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
    }));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_task = tokio::spawn(run_vless_client_listener(
        client_listener,
        VlessClientConfig {
            listen: client_addr,
            server_host: "127.0.0.1".to_string(),
            server_port: server_addr.port(),
            user_id,
            tls: true,
            sni: "localhost".to_string(),
            insecure: true,
            flow: String::new(),
            packet_encoding: "xudp".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
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
        udp.send_to(&socks_udp_packet(udp_echo_addr, b"hello xudp")?, udp_bind)
            .await?;

        let mut response = [0u8; 256];
        let (read, _) = udp.recv_from(&mut response).await?;
        let payload = socks_udp_payload(&response[..read])?;
        anyhow::ensure!(payload == b"hello xudp", "VLESS XUDP payload mismatch");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("VLESS XUDP end-to-end test timed out")
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
        transport: VlessTransportConfig::tcp(),
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
        transport: transport.clone(),
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
        transport: VlessTransportConfig::tcp(),
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
        transport: VlessTransportConfig::tcp(),
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
        transport: VlessTransportConfig::tcp(),
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
        transport: VlessTransportConfig::tcp(),
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

async fn write_socks_connect(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let SocketAddr::V4(target) = target else {
        anyhow::bail!("test target must be IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    Ok(())
}

async fn write_socks_udp_associate(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn read_socks_reply_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    anyhow::ensure!(
        head[0] == 0x05 && head[1] == 0x00,
        "SOCKS reply failed: {head:?}"
    );
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
            Ok(SocketAddr::from((
                [rest[0], rest[1], rest[2], rest[3]],
                u16::from_be_bytes([rest[4], rest[5]]),
            )))
        }
        other => anyhow::bail!("unsupported SOCKS reply address type: {other}"),
    }
}

fn socks_udp_packet(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let SocketAddr::V4(target) = target else {
        anyhow::bail!("test UDP target must be IPv4");
    };
    let mut packet = vec![0, 0, 0, 0x01];
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn socks_udp_payload(packet: &[u8]) -> Result<&[u8]> {
    anyhow::ensure!(packet.len() >= 10, "SOCKS UDP response is too short");
    anyhow::ensure!(
        &packet[..4] == [0, 0, 0, 0x01],
        "unexpected SOCKS UDP header"
    );
    Ok(&packet[10..])
}

fn unused_udp_addr() -> Result<SocketAddr> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?)
}

fn unused_tcp_addr() -> Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

async fn socks_echo(client_addr: SocketAddr, echo_addr: SocketAddr, payload: &[u8]) -> Result<()> {
    let mut socks = TcpStream::connect(client_addr).await?;
    socks.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    socks.read_exact(&mut greeting).await?;
    anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");
    write_socks_connect(&mut socks, echo_addr).await?;
    let mut reply = [0u8; 10];
    socks.read_exact(&mut reply).await?;
    anyhow::ensure!(reply[1] == 0x00, "SOCKS connect failed: {:?}", reply);
    socks.write_all(payload).await?;
    let mut echoed = vec![0u8; payload.len()];
    socks.read_exact(&mut echoed).await?;
    anyhow::ensure!(echoed == payload, "echo payload mismatch");
    Ok(())
}

async fn open_anytls_control_session(
    config: Arc<rustls::ClientConfig>,
    server_addr: SocketAddr,
    password: &str,
) -> Result<bool> {
    let tcp = TcpStream::connect(server_addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost")?;
    let mut stream = TlsConnector::from(config)
        .early_data(true)
        .connect(server_name, tcp)
        .await?;

    stream.write_all(&password_hash(password)).await?;
    stream.write_all(&0u16.to_be_bytes()).await?;
    let padding = PaddingScheme::from_lines(PaddingScheme::default_lines())?;
    let settings = format!("v=2\nclient=aerion-e2e\npadding-md5={}", padding.md5());
    write_frame(&mut stream, CMD_SETTINGS, 0, settings.as_bytes()).await?;

    let frame = read_frame(&mut stream).await?;
    anyhow::ensure!(
        frame.cmd == CMD_SERVER_SETTINGS,
        "unexpected AnyTLS server frame command: {}",
        frame.cmd
    );
    let settings = parse_settings(&frame.payload);
    anyhow::ensure!(
        settings.get("v").map(String::as_str) == Some("2"),
        "unexpected AnyTLS server settings: {:?}",
        settings
    );
    let accepted = stream.get_ref().1.is_early_data_accepted();
    stream.shutdown().await?;
    Ok(accepted)
}
