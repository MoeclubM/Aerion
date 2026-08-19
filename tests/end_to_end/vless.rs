use super::helpers::*;
use aerion::vless_transport::VlessTransportConfig;
use aerion::{
    RealityClientConfig, RealityServerConfig, UtlsFingerprint, VlessClientConfig,
    VlessServerConfig, run_vless_client_listener, run_vless_server,
};
use x25519_dalek::{PublicKey, StaticSecret};

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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport: VlessTransportConfig::tcp(),
        },
        None,
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
        None,
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
        None,
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
        None,
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
        None,
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: transport.clone(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport,
        },
        None,
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: Some(RealityServerConfig {
            server_name: "localhost".to_string(),
            server_port: 443,
            server_names: vec!["localhost".to_string()],
            private_key: server_private.to_bytes(),
            short_ids: vec![short_id],
            alpn_protocols: Vec::new(),
            max_time_diff_secs: 0,
            max_client_version: Some([0, 0, 0, 1]),
            fallback_limit: Default::default(),
        }),
        transport: VlessTransportConfig::tcp(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
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
        None,
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
        certificates: Vec::new(),
        key: None,
        flow: "xtls-rprx-vision".to_string(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: "xtls-rprx-vision".to_string(),
            packet_encoding: "packet".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport: VlessTransportConfig::tcp(),
        },
        None,
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: true,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport: VlessTransportConfig::tcp(),
        },
        None,
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
async fn vless_mux_server_finishes_when_tcp_target_fins() -> Result<()> {
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
    let cert_path = temp.path().join("vless-mux-fin.crt");
    let key_path = temp.path().join("vless-mux-fin.key");
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "packet".to_string(),
            mux: true,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport: VlessTransportConfig::tcp(),
        },
        None,
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
        anyhow::ensure!(read == 0, "expected VLESS mux EOF after target FIN");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("VLESS mux target-FIN test timed out")
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
        certificates: Vec::new(),
        key: None,
        flow: String::new(),
        reality: None,
        transport: VlessTransportConfig::tcp(),
        ech: None,
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: String::new(),
            packet_encoding: "xudp".to_string(),
            mux: false,
            udp: true,
            client_fingerprint: None,
            reality: None,
            transport: VlessTransportConfig::tcp(),
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
