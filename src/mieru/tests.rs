use super::*;
use crate::core::{CoreUser, ProxyCore};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[test]
fn metadata_roundtrip() -> Result<()> {
    let metadata = MieruMetadata::DataAck(MieruDataAckMetadata {
        protocol: DATA_CLIENT_TO_SERVER,
        session_id: 7,
        seq: 11,
        un_ack_seq: 3,
        window_size: 16,
        fragment: 0,
        prefix_len: 2,
        payload_len: 5,
        suffix_len: 4,
    });
    let parsed = MieruMetadata::parse(&metadata.marshal()?)?;
    match parsed {
        MieruMetadata::DataAck(parsed) => {
            assert_eq!(parsed.protocol, DATA_CLIENT_TO_SERVER);
            assert_eq!(parsed.session_id, 7);
            assert_eq!(parsed.seq, 11);
            assert_eq!(parsed.un_ack_seq, 3);
            assert_eq!(parsed.window_size, 16);
            assert_eq!(parsed.prefix_len, 2);
            assert_eq!(parsed.payload_len, 5);
            assert_eq!(parsed.suffix_len, 4);
        }
        _ => panic!("unexpected metadata type"),
    }
    Ok(())
}

#[test]
fn parses_traffic_pattern_base64_protobuf() -> Result<()> {
    let bytes = vec![
        0x08, 0x07, 0x10, 0x01, 0x1a, 0x04, 0x08, 0x01, 0x10, 0x0a, 0x22, 0x08, 0x08, 0x02, 0x10,
        0x01, 0x18, 0x05, 0x20, 0x0a,
    ];
    let encoded = BASE64_STANDARD.encode(bytes);
    let pattern =
        MieruTrafficPattern::parse_pair(Some(&encoded), None)?.context("traffic pattern parsed")?;
    let fragment = pattern.tcp_fragment.context("tcp fragment")?;
    assert!(fragment.enable);
    assert_eq!(fragment.max_sleep_ms, 10);
    let nonce = pattern.nonce.context("nonce pattern")?;
    assert_eq!(nonce.kind, MieruNonceType::PrintableSubset);
    assert!(nonce.apply_to_all_udp_packet);
    assert_eq!(nonce.min_len, 5);
    assert_eq!(nonce.max_len, 10);
    Ok(())
}

#[test]
fn heartbeat_jitter_stays_in_original_window() -> Result<()> {
    for _ in 0..32 {
        let ms = jittered_heartbeat_interval_ms()?;
        assert!(
            (4000..=6000).contains(&ms),
            "heartbeat interval {ms} ms is outside 5s ± 1s"
        );
    }
    Ok(())
}

#[tokio::test]
async fn idle_tcp_underlay_closes_after_last_session() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    let server_task = tokio::spawn(run_mieru_server_listener_with_core(
        listener,
        MieruServerConfig {
            listen: server_addr,
            username: "default".to_string(),
            password: "test-password".to_string(),
            users: Vec::new(),
            mtu: 1500,
            user_hint_mandatory: false,
            traffic_pattern: None,
            transport: MieruTransport::Tcp,
        },
        ProxyCore::new(vec![CoreUser::password("default", "test-password")])?,
    ));
    let underlay = connect_mieru_underlay(&MieruClientConfig {
        listen: "127.0.0.1:0".parse()?,
        server_host: "127.0.0.1".to_string(),
        server_port: server_addr.port(),
        username: "default".to_string(),
        password: "test-password".to_string(),
        hashed_password: None,
        mtu: 1500,
        traffic_pattern: None,
        transport: MieruTransport::Tcp,
    })
    .await?;
    let closed = TcpListener::bind("127.0.0.1:0").await?;
    let closed_addr = closed.local_addr()?;
    drop(closed);
    let port = closed_addr.port().to_be_bytes();
    let mut session = underlay.open_session(1500).await?;
    session
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port[0], port[1]])
        .await?;
    drop(session);
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        if !underlay.is_alive().await {
            server_task.abort();
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    server_task.abort();
    bail!("Mieru TCP underlay stayed alive after last session");
}
