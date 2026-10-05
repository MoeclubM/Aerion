use super::helpers::*;
use aerion::protocol::{
    CMD_SERVER_SETTINGS, CMD_SETTINGS, parse_settings, password_hash, read_frame, write_frame,
};
use aerion::{ClientConfig, ServerConfig, run_client_listener, run_server_listener};
use std::sync::Arc;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn heartbeat_preserves_partial_frames_and_revocation_closes_idle_sessions() -> Result<()> {
    tls::init_crypto();
    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let core = aerion::ProxyCore::from_credentials("secret", &[]);
    let server = tokio::spawn(aerion::run_server_listener_with_core(
        listener,
        ServerConfig {
            listen: addr,
            password: "secret".into(),
            users: Vec::new(),
            cert_path,
            key_path,
            certificates: Vec::new(),
            key: None,
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 1,
            ech: None,
        },
        core.clone(),
    ));
    let result = timeout(Duration::from_secs(5), async {
        let tcp = TcpStream::connect(addr).await?;
        let mut stream = TlsConnector::from(tls::client_config(true))
            .connect(rustls::pki_types::ServerName::try_from("localhost")?, tcp)
            .await?;
        stream.write_all(&password_hash("secret")).await?;
        stream.write_all(&[0, 0]).await?;
        let padding = PaddingScheme::from_lines(PaddingScheme::default_lines())?;
        write_frame(
            &mut stream,
            CMD_SETTINGS,
            0,
            format!("v=2\npadding-md5={}", padding.md5()).as_bytes(),
        )
        .await?;
        anyhow::ensure!(
            read_frame(&mut stream).await?.cmd == CMD_SERVER_SETTINGS,
            "missing settings"
        );
        let header = [aerion::protocol::CMD_HEART_REQUEST, 0, 0, 0, 17, 0, 0];
        stream.write_all(&header[..3]).await?;
        stream.flush().await?;
        anyhow::ensure!(
            read_frame(&mut stream).await?.cmd == aerion::protocol::CMD_HEART_REQUEST,
            "missing heartbeat"
        );
        stream.write_all(&header[3..]).await?;
        stream.flush().await?;
        let reply = read_frame(&mut stream).await?;
        anyhow::ensure!(
            reply.cmd == aerion::protocol::CMD_HEART_RESPONSE && reply.stream_id == 17,
            "partial frame was lost"
        );
        core.cancel_all_sessions();
        anyhow::ensure!(
            read_frame(&mut stream).await.is_err(),
            "revoked idle connection remained open"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("AnyTLS heartbeat/revocation test timed out")
    .and_then(|result| result);
    server.abort();
    result
}

#[tokio::test]
async fn fin_and_connection_close_interrupt_rate_limited_streams() -> Result<()> {
    tls::init_crypto();
    let temp = tempfile::tempdir()?;
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = temp.path().join("server.crt");
    let key_path = temp.path().join("server.key");
    std::fs::write(&cert_path, certified.cert.pem())?;
    std::fs::write(&key_path, certified.key_pair.serialize_pem())?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let mut user = aerion::CoreUser::password("user", "secret");
    user.upload_limit_bps = Some(1);
    user.download_limit_bps = Some(1);
    let core = aerion::ProxyCore::new(vec![user])?;
    let server = tokio::spawn(aerion::run_server_listener_with_core(
        listener,
        ServerConfig {
            listen: addr,
            password: "secret".into(),
            users: Vec::new(),
            cert_path,
            key_path,
            certificates: Vec::new(),
            key: None,
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
            ech: None,
        },
        core.clone(),
    ));
    let result = timeout(Duration::from_secs(10), async {
        for (download, close_connection) in [(false, false), (true, false), (false, true)] {
            let target_listener = TcpListener::bind("127.0.0.1:0").await?;
            let tcp = TcpStream::connect(addr).await?;
            let mut stream = TlsConnector::from(tls::client_config(true))
                .connect(rustls::pki_types::ServerName::try_from("localhost")?, tcp)
                .await?;
            stream.write_all(&password_hash("secret")).await?;
            stream.write_all(&[0, 0]).await?;
            let padding = PaddingScheme::from_lines(PaddingScheme::default_lines())?;
            write_frame(
                &mut stream,
                CMD_SETTINGS,
                0,
                format!("v=2\npadding-md5={}", padding.md5()).as_bytes(),
            )
            .await?;
            assert_eq!(read_frame(&mut stream).await?.cmd, CMD_SERVER_SETTINGS);
            write_frame(&mut stream, aerion::protocol::CMD_SYN, 1, &[]).await?;
            let target = aerion::protocol::ProxyTarget::Ip(target_listener.local_addr()?);
            write_frame(
                &mut stream,
                aerion::protocol::CMD_PSH,
                1,
                &aerion::protocol::encode_target(&target)?,
            )
            .await?;
            assert_eq!(
                read_frame(&mut stream).await?.cmd,
                aerion::protocol::CMD_SYNACK
            );
            let (mut target, _) = target_listener.accept().await?;
            if download {
                target.write_all(b"delayed payload").await?;
            } else {
                write_frame(
                    &mut stream,
                    aerion::protocol::CMD_PSH,
                    1,
                    b"delayed payload",
                )
                .await?;
                write_frame(&mut stream, aerion::protocol::CMD_HEART_REQUEST, 0, &[]).await?;
                assert_eq!(
                    read_frame(&mut stream).await?.cmd,
                    aerion::protocol::CMD_HEART_RESPONSE
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            if close_connection {
                stream.shutdown().await?;
            } else {
                write_frame(&mut stream, aerion::protocol::CMD_FIN, 1, &[]).await?;
            }
            assert_eq!(
                timeout(Duration::from_secs(2), target.read(&mut [0; 1])).await??,
                0,
                "cancelled stream retained its target writer while waiting for the limiter"
            );
            if !close_connection {
                write_frame(&mut stream, aerion::protocol::CMD_HEART_REQUEST, 0, &[]).await?;
                assert_eq!(
                    read_frame(&mut stream).await?.cmd,
                    aerion::protocol::CMD_HEART_RESPONSE
                );
                stream.shutdown().await?;
            }
            drop(stream);
            timeout(Duration::from_secs(2), async {
                while core.snapshot().await[0].online_sessions != 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("AnyTLS cancellation test timed out")
    .and_then(|result| result);
    server.abort();
    result
}

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
    let ca_cert_pem = certified.cert.pem();
    let ca_cert_sha256 = hex::encode(Sha256::digest(certified.cert.der().as_ref()));
    std::fs::write(&cert_path, &ca_cert_pem)?;
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
            insecure: false,
            client_fingerprint: None,
            ca_cert_paths: Vec::new(),
            ca_certificates: vec![ca_cert_pem],
            disable_system_roots: false,
            pinned_cert_sha256: vec![ca_cert_sha256],
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
        },
        None,
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
async fn anytls_server_rejects_tls_early_data() -> Result<()> {
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
            certificates: Vec::new(),
            key: None,
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
            ech: None,
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
    anyhow::ensure!(!second, "AnyTLS server must not accept TLS 1.3 0-RTT");

    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn anytls_server_finishes_when_tcp_target_fins() -> Result<()> {
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
    let cert_path = temp.path().join("anytls-fin.crt");
    let key_path = temp.path().join("anytls-fin.key");
    let ca_cert_pem = certified.cert.pem();
    std::fs::write(&cert_path, &ca_cert_pem)?;
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
            insecure: false,
            client_fingerprint: None,
            ca_cert_paths: Vec::new(),
            ca_certificates: vec![ca_cert_pem],
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
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
        anyhow::ensure!(read == 0, "expected AnyTLS stream EOF after target FIN");
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("AnyTLS target-FIN test timed out")
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
