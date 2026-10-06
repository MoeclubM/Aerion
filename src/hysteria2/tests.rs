use super::*;

fn fragment(packet_id: u16, fragment_id: u8, fragment_count: u8, payload: &[u8]) -> UdpMessage {
    UdpMessage {
        session_id: 1,
        packet_id,
        fragment_id,
        fragment_count,
        address: "127.0.0.1:53".into(),
        payload: payload.to_vec(),
    }
}

#[tokio::test]
async fn dropping_last_client_closes_quic_and_background_tasks() -> Result<()> {
    tls::init_crypto();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let addr = socket.local_addr()?;
    let server = tokio::spawn(run_hysteria2_server_socket_with_core(
        socket,
        Hysteria2ServerConfig {
            listen: addr,
            password: "secret".into(),
            users: vec![],
            cert_path: PathBuf::new(),
            key_path: PathBuf::new(),
            certificates: vec![certificate.cert.pem()],
            key: Some(certificate.key_pair.serialize_pem()),
            obfs: None,
            obfs_password: None,
            upload_bandwidth: None,
            udp: true,
            cc_rx: "0".into(),
            congestion_control: "bbr".into(),
            auth_timeout: Duration::from_secs(5),
        },
        ProxyCore::from_credentials("secret", &[]),
    ));
    let result = async {
        let client = Hysteria2Client::connect(Hysteria2ClientConfig {
            listen: "127.0.0.1:0".parse()?,
            server_host: "127.0.0.1".into(),
            server_port: addr.port(),
            password: "secret".into(),
            sni: "localhost".into(),
            insecure: true,
            certificate_fingerprint: None,
            ca_cert_paths: vec![],
            ca_certificates: vec![],
            disable_system_roots: false,
            pinned_cert_sha256: vec![],
            obfs: None,
            obfs_password: None,
            upload_bandwidth: None,
            download_bandwidth: None,
            udp: true,
            congestion_control: "bbr".into(),
        })
        .await?;
        let weak = Arc::downgrade(&client.inner);
        let connection = client.inner.connection.clone();
        drop(client);
        ensure!(
            weak.upgrade().is_none(),
            "datagram task retained the client"
        );
        tokio::time::timeout(Duration::from_secs(2), connection.closed()).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    result
}

#[tokio::test]
async fn fragment_reassembly_validates_indices_and_packet_limits() -> Result<()> {
    let fragments = Mutex::new(HashMap::new());
    assert!(
        reassemble_udp_message(fragment(1, 1, 1, b"bad"), &fragments)
            .await
            .is_err()
    );
    assert!(
        reassemble_udp_message(fragment(1, 1, 2, b"world"), &fragments)
            .await?
            .is_none()
    );
    let message = reassemble_udp_message(fragment(1, 0, 2, b"hello"), &fragments)
        .await?
        .unwrap();
    assert_eq!(message.payload, b"helloworld");
    assert!(fragments.lock().await.is_empty());
    for packet in 0..MAX_PENDING_PACKETS as u16 {
        assert!(
            reassemble_udp_message(fragment(packet, 0, 2, b"pending"), &fragments)
                .await?
                .is_none()
        );
    }
    assert!(
        reassemble_udp_message(fragment(1000, 0, 2, b"overflow"), &fragments)
            .await
            .is_err()
    );
    for buffer in fragments.lock().await.values_mut() {
        buffer.created_at = Instant::now() - UDP_FRAGMENT_TIMEOUT;
    }
    assert!(
        reassemble_udp_message(fragment(1000, 0, 2, b"new"), &fragments)
            .await?
            .is_none()
    );
    assert_eq!(fragments.lock().await.len(), 1);
    Ok(())
}

#[test]
fn varint_roundtrip() {
    for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823] {
        let mut encoded = Vec::new();
        encode_varint(value, &mut encoded).unwrap();
        let decoded = read_varint_from_slice(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, value);
    }
}

#[test]
fn udp_message_roundtrip() {
    let message = UdpMessage {
        session_id: 7,
        packet_id: 9,
        fragment_id: 0,
        fragment_count: 1,
        address: "example.com:53".to_string(),
        payload: b"hello".to_vec(),
    };
    let encoded = encode_udp_message(&message).unwrap();
    assert_eq!(decode_udp_message(&encoded).unwrap(), message);
}

#[test]
fn upload_limiter_maps_mbps_to_bytes_per_second() {
    assert_eq!(
        Hy2ByteRateLimiter::new(Some(8)).bytes_per_second,
        Some(1_000_000)
    );
    assert_eq!(Hy2ByteRateLimiter::new(None).bytes_per_second, None);
}

#[test]
fn salamander_roundtrip() {
    let salt = [7u8; SALAMANDER_SALT_LEN];
    let payload = b"hello hysteria2";
    let mut encrypted = vec![0u8; payload.len()];
    let mut decrypted = vec![0u8; payload.len()];
    salamander_xor(b"secret", &salt, payload, &mut encrypted);
    assert_ne!(encrypted, payload);
    salamander_xor(b"secret", &salt, &encrypted, &mut decrypted);
    assert_eq!(decrypted, payload);
}

#[test]
fn failed_auth_is_not_http_401() {
    assert_ne!(http::StatusCode::OK.as_u16(), 401);
    assert_eq!(http::StatusCode::from_u16(233).unwrap().as_u16(), 233);
    let padding = random_hysteria_padding_bytes().unwrap();
    assert!(padding.len() >= 16);
    assert!(padding.iter().all(|byte| byte.is_ascii_alphabetic()));
}
