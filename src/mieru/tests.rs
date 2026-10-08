use super::*;
use crate::core::{CoreUser, ProxyCore};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/performance/mieru_stream.rs"
));

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

#[test]
fn packet_sender_honors_peer_window_and_rejects_stale_or_future_acks() {
    let mut flow = PacketSendWindow::default();
    let mut unacked = BTreeMap::new();
    flow.ack(0, 2, 0, &mut unacked);
    assert!(flow.can_send(1, 1));
    assert!(!flow.can_send(2, 2));
    flow.ack(1, 0, 2, &mut unacked);
    assert!(!flow.can_send(2, 1));
    flow.ack(0, 100, 2, &mut unacked);
    assert_eq!(flow.peer_window, 0);
    flow.ack(3, 100, 2, &mut unacked);
    assert_eq!(flow.peer_ack, 1);
    flow.ack(1, 8, 2, &mut unacked);
    assert!(flow.can_send(2, 1));
}

#[test]
fn packet_loss_recovery_retransmits_partial_ack_without_repeated_window_cuts() {
    let mut flow = PacketSendWindow::default();
    let mut unacked = (0..5)
        .map(|seq| {
            (
                seq,
                OutstandingSegment {
                    segment: MieruSegment {
                        metadata: MieruMetadata::Session(MieruSessionMetadata {
                            protocol: OPEN_SESSION_REQUEST,
                            session_id: 1,
                            seq,
                            status_code: STATUS_OK,
                            payload_len: 0,
                            suffix_len: 0,
                        }),
                        payload: Vec::new(),
                    },
                    attempts: 1,
                    sent: Instant::now(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for _ in 0..3 {
        flow.ack(0, 32, 5, &mut unacked);
    }
    assert!(flow.fast_retransmit);
    flow.on_retransmit(5);
    let recovery_window = flow.congestion_window;
    unacked.get_mut(&0).unwrap().attempts += 1;
    for _ in 0..4 {
        flow.ack(0, 32, 5, &mut unacked);
    }
    assert!(
        !flow.fast_retransmit,
        "do not repeatedly retransmit the same hole"
    );
    flow.ack(2, 32, 5, &mut unacked);
    assert!(
        flow.fast_retransmit,
        "partial ACK exposes the next hole immediately"
    );
    flow.on_retransmit(5);
    assert_eq!(flow.congestion_window, recovery_window);
    flow.ack(5, 32, 5, &mut unacked);
    assert!(unacked.is_empty());
    assert!(flow.recovery_until.is_none());
}

#[test]
fn cumulative_packet_ack_removes_only_the_prefix_across_sequence_wraparound() {
    let mut flow = PacketSendWindow {
        peer_ack: u32::MAX - 1,
        ..Default::default()
    };
    let mut unacked = [u32::MAX - 1, u32::MAX, 0, 1]
        .into_iter()
        .map(|seq| {
            (
                seq,
                OutstandingSegment {
                    segment: MieruSegment {
                        metadata: MieruMetadata::Session(MieruSessionMetadata {
                            protocol: OPEN_SESSION_REQUEST,
                            session_id: 1,
                            seq,
                            status_code: STATUS_OK,
                            payload_len: 0,
                            suffix_len: 0,
                        }),
                        payload: Vec::new(),
                    },
                    attempts: 1,
                    sent: Instant::now(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    flow.ack(1, 32, 2, &mut unacked);
    assert_eq!(unacked.keys().copied().collect::<Vec<_>>(), vec![1]);
    assert_eq!(flow.peer_ack, 1);
}

#[tokio::test]
async fn cached_packet_cipher_preserves_authentication_hint_rotation_and_replay_checks()
-> Result<()> {
    let user = MieruUser::password("user", "secret").into_secret();
    let key = current_mieru_key(&user.hashed_password)?;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    configure_mieru_packet_socket(&socket)?;
    let cipher = MieruCipher::new(key, false, user.username.clone(), None);
    let mut peer = MieruPacketPeer {
        writer: Arc::new(Mutex::new(MieruAnyWriter::Packet(MieruPacketWriter::new(
            socket,
            Some("127.0.0.1:1234".parse()?),
            Vec::new(),
            cipher.clone(),
            1400,
            None,
        )))),
        cipher,
        user,
        key_epoch: 7,
        last_rx: Instant::now(),
    };
    let segment = MieruSegment {
        metadata: MieruMetadata::Session(MieruSessionMetadata {
            protocol: OPEN_SESSION_REQUEST,
            session_id: 1,
            seq: 0,
            status_code: STATUS_OK,
            payload_len: 4,
            suffix_len: 0,
        }),
        payload: b"ping".to_vec(),
    };
    let mut send = peer.cipher.clone();
    let packet = encode_mieru_packet_segment(&mut send, segment.clone(), 1400, None)?;
    let replay = MieruReplayCache::new();
    assert!(peer.decode(&packet, 8, true, &replay).is_err());
    let mut corrupted = packet.clone();
    corrupted[NONCE_LEN + 1] ^= 1;
    assert!(peer.decode(&corrupted, 7, true, &replay).is_err());
    let mut wrong_hint = MieruCipher::new(key, false, "another-user".to_string(), None);
    let wrong_hint_packet = encode_mieru_packet_segment(&mut wrong_hint, segment, 1400, None)?;
    assert!(peer.decode(&wrong_hint_packet, 7, true, &replay).is_err());
    assert_eq!(peer.decode(&packet, 7, true, &replay)?.payload, b"ping");
    assert!(
        peer.decode(&packet, 7, true, &replay).is_err(),
        "cached OPEN must still reject replay"
    );
    Ok(())
}

#[tokio::test]
async fn session_write_applies_backpressure_without_blocking_control() -> Result<()> {
    let (_, inbound) = mpsc::unbounded_channel();
    let (outbound, mut commands) = mpsc::unbounded_channel();
    let mut session = MieruSession::new(inbound, outbound.clone());
    for _ in 0..8 {
        session.write_all(&vec![0; MAX_PDU]).await?;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), session.write_all(b"blocked"))
            .await
            .is_err()
    );
    outbound.send(SessionCommand::SendAck {
        protocol: ACK_CLIENT_TO_SERVER,
        un_ack_seq: 1,
        window_size: 32,
    })?;
    drop(commands.recv().await);
    tokio::time::timeout(Duration::from_secs(1), session.write_all(b"released")).await??;
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
