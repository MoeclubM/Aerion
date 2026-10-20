use super::*;
use crate::core::{CoreUser, ProxyCore};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/performance/mieru_auth.rs"
));

#[test]
fn authentication_hint_is_prioritized_but_optional_fallback_still_checks_aead() -> Result<()> {
    let users = (0..3000)
        .map(|i| MieruUserSecret {
            username: format!("user-{i}"),
            password: String::new(),
            hashed_password: crypto::hash_mieru_password(b"secret", format!("user-{i}").as_bytes()),
        })
        .collect::<Vec<_>>();
    let selected = &users[2999];
    let key = crypto::current_mieru_key(&selected.hashed_password)?;
    let mut cipher = MieruCipher::new(key, false, selected.username.clone(), None);
    let nonce = cipher.encrypt(b"nonce hint")?;
    let candidates = wire::authentication_candidates(&users, &nonce[..NONCE_LEN], false);
    assert_eq!(candidates.len(), users.len());
    assert!(std::ptr::eq(candidates[0], selected));
    assert_eq!(
        wire::authentication_candidates(&users, &nonce[..NONCE_LEN], true).len(),
        1
    );
    let mut cipher = MieruCipher::new(key, false, "legacy-hint".into(), None);
    let packet = encode_mieru_packet_segment(
        &mut cipher,
        MieruSegment {
            metadata: MieruMetadata::DataAck(MieruDataAckMetadata {
                protocol: DATA_CLIENT_TO_SERVER,
                session_id: 1,
                seq: 1,
                un_ack_seq: 0,
                window_size: 32,
                fragment: 0,
                prefix_len: 0,
                payload_len: 0,
                suffix_len: 0,
            }),
            payload: b"payload".to_vec(),
        },
        1400,
        None,
    )?;
    let replay = MieruReplayCache::new();
    let (segment, user, _) =
        decode_mieru_packet_segment_for_server(&packet, &users, false, None, &replay)?;
    assert_eq!(user.username, selected.username);
    assert_eq!(segment.payload, b"payload");
    assert!(decode_mieru_packet_segment_for_server(&packet, &users, true, None, &replay).is_err());
    let mut corrupted = packet;
    corrupted[NONCE_LEN] ^= 1;
    assert!(
        decode_mieru_packet_segment_for_server(&corrupted, &users, false, None, &replay).is_err()
    );
    Ok(())
}

#[tokio::test]
async fn silent_tcp_peer_is_closed_before_authentication() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut peer = TcpStream::connect(listener.local_addr()?).await?;
    let (stream, addr) = listener.accept().await?;
    let task = tokio::spawn(handle_mieru_underlay_server(
        stream,
        Arc::from([]),
        ProxyCore::empty(),
        1400,
        false,
        None,
        addr,
        Arc::new(MieruReplayCache::new()),
    ));
    let error = tokio::time::timeout(
        crate::io_util::HANDSHAKE_TIMEOUT + Duration::from_secs(3),
        task,
    )
    .await??
    .unwrap_err();
    assert!(error.to_string().contains("Mieru authentication timed out"));
    let mut byte = [0];
    assert_eq!(peer.read(&mut byte).await?, 0);
    Ok(())
}

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
    flow.on_retransmit(5, false);
    let recovery_window = flow.congestion.window();
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
    flow.on_retransmit(5, false);
    assert_eq!(flow.congestion.window(), recovery_window);
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

#[test]
fn packet_rto_retains_a_margin_above_a_stable_rtt() {
    let mut flow = PacketSendWindow {
        srtt: Some(0.1),
        rtt_var: 0.0,
        ..Default::default()
    };
    let mut unacked = BTreeMap::new();
    unacked.insert(
        0,
        OutstandingSegment {
            segment: MieruSegment {
                metadata: MieruMetadata::Session(MieruSessionMetadata {
                    protocol: OPEN_SESSION_REQUEST,
                    session_id: 1,
                    seq: 0,
                    status_code: STATUS_OK,
                    payload_len: 0,
                    suffix_len: 0,
                }),
                payload: Vec::new(),
            },
            attempts: 1,
            sent: Instant::now() - Duration::from_millis(100),
        },
    );
    flow.ack(1, ACK_WINDOW_SIZE, 1, &mut unacked);
    assert!(flow.rto >= flow.rtt() + Duration::from_millis(10));
}

#[tokio::test]
async fn packet_output_flushes_the_latest_delayed_ack_before_closing() -> Result<()> {
    let receiver = UdpSocket::bind("127.0.0.1:0").await?;
    let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let key = [7; KEY_LEN];
    let writer = Arc::new(Mutex::new(MieruAnyWriter::Packet(MieruPacketWriter::new(
        sender,
        Some(receiver.local_addr()?),
        Vec::new(),
        MieruCipher::new(key, false, "ack-test".into(), None),
        1400,
        None,
    ))));
    let (commands, output) = mpsc::unbounded_channel();
    let receive_flow = ReceiveFlow::new(1400);
    for un_ack_seq in 1..=3 {
        receive_flow.un_ack_seq.store(un_ack_seq, Ordering::Relaxed);
        commands.send(SessionCommand::SendAck {
            protocol: ACK_SERVER_TO_CLIENT,
            immediate: false,
        })?;
    }
    commands.send(SessionCommand::Close)?;
    let task = tokio::spawn(run_mieru_session_output(
        1,
        false,
        false,
        writer,
        output,
        true,
        1400,
        receive_flow,
        Arc::new(Mutex::new(HashMap::new())),
        None,
    ));
    let mut cipher = MieruCipher::new(key, false, "ack-test".into(), None);
    let mut buffer = [0; 1500];
    let mut last_ack = None;
    loop {
        let (read, _) =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buffer)).await??;
        let segment = decode_mieru_packet_segment(&mut cipher, &buffer[..read])?;
        if segment.metadata.protocol() == CLOSE_SESSION_REQUEST {
            break;
        }
        assert_eq!(segment.metadata.protocol(), ACK_SERVER_TO_CLIENT);
        last_ack = segment.metadata.un_ack_seq();
    }
    assert_eq!(last_ack, Some(3));
    tokio::time::timeout(Duration::from_secs(1), task).await??;
    Ok(())
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
async fn packet_receive_window_drops_future_packets_and_recovers_without_closing() -> Result<()> {
    let (inbound, mut received) = mpsc::unbounded_channel();
    let (outbound, mut commands) = mpsc::unbounded_channel();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let entry = MieruSessionEntry {
        inbound,
        outbound,
        ordered: true,
        recv: Arc::new(Mutex::new(MieruReceiveState::default())),
        flow: ReceiveFlow::new(1400),
        writer: Arc::new(Mutex::new(MieruAnyWriter::Packet(MieruPacketWriter::new(
            socket,
            Some("127.0.0.1:1234".parse()?),
            Vec::new(),
            MieruCipher::new([0; KEY_LEN], false, "user".to_string(), None),
            1400,
            None,
        )))),
    };
    let initial_window = entry.flow.window.load(Ordering::Relaxed);
    let sessions = Arc::new(Mutex::new(HashMap::from([(1, entry.clone())])));
    let segment = |seq| MieruSegment {
        metadata: MieruMetadata::DataAck(MieruDataAckMetadata {
            protocol: DATA_CLIENT_TO_SERVER,
            session_id: 1,
            seq,
            un_ack_seq: 0,
            window_size: ACK_WINDOW_SIZE,
            fragment: 0,
            prefix_len: 0,
            payload_len: 4,
            suffix_len: 0,
        }),
        payload: seq.to_be_bytes().to_vec(),
    };
    for seq in 1..=(MAX_PENDING_SEGMENTS as u32 + 2) {
        route_session_segment(&sessions, segment(seq), Some(ACK_SERVER_TO_CLIENT)).await?;
    }
    assert_eq!(
        entry.recv.lock().await.pending.len(),
        MAX_PENDING_SEGMENTS - 1
    );
    assert_eq!(entry.flow.window.load(Ordering::Relaxed), 1);
    route_session_segment(&sessions, segment(0), Some(ACK_SERVER_TO_CLIENT)).await?;
    for seq in 0..MAX_PENDING_SEGMENTS as u32 {
        assert_eq!(
            received.recv().await.context("ordered payload")?.payload,
            seq.to_be_bytes()
        );
    }
    assert!(entry.recv.lock().await.pending.is_empty());
    assert_eq!(
        entry.flow.un_ack_seq.load(Ordering::Relaxed),
        MAX_PENDING_SEGMENTS as u32
    );
    assert_eq!(entry.flow.refresh().1, initial_window);
    // A packet dropped outside the earlier window can now be retransmitted.
    route_session_segment(
        &sessions,
        segment(MAX_PENDING_SEGMENTS as u32),
        Some(ACK_SERVER_TO_CLIENT),
    )
    .await?;
    assert_eq!(
        received.recv().await.context("retried payload")?.payload,
        (MAX_PENDING_SEGMENTS as u32).to_be_bytes()
    );
    let mut last_ack = None;
    while let Ok(command) = commands.try_recv() {
        last_ack = Some(command);
    }
    assert!(matches!(
        last_ack,
        Some(SessionCommand::SendAck {
            protocol: ACK_SERVER_TO_CLIENT,
            ..
        })
    ));
    let mut session = MieruSession::new(received, entry.outbound.clone())
        .with_receive_flow(&entry, ACK_SERVER_TO_CLIENT);
    let full = entry
        .flow
        .reserve_stream(vec![0x42; SESSION_RECEIVE_BYTES - RECEIVE_ITEM_OVERHEAD])
        .await
        .context("reserve receive budget")?;
    entry.inbound.send(full)?;
    let next = entry.flow.un_ack_seq.load(Ordering::Relaxed);
    route_session_segment(&sessions, segment(next), Some(ACK_SERVER_TO_CLIENT)).await?;
    assert_eq!(
        entry.flow.un_ack_seq.load(Ordering::Relaxed),
        next,
        "unretained payload must not be acknowledged"
    );
    assert_eq!(entry.flow.window.load(Ordering::Relaxed), 0);
    while commands.try_recv().is_ok() {}
    let mut payload = vec![0; SESSION_RECEIVE_BYTES - RECEIVE_ITEM_OVERHEAD];
    session.read_exact(&mut payload).await?;
    assert!(payload.iter().all(|b| *b == 0x42));
    assert!(matches!(
        commands.recv().await,
        Some(SessionCommand::SendAck {
            protocol: ACK_SERVER_TO_CLIENT,
            ..
        })
    ));
    assert!(entry.flow.window.load(Ordering::Relaxed) > 0);
    assert_eq!(entry.flow.un_ack_seq.load(Ordering::Relaxed), next);
    route_session_segment(&sessions, segment(next), Some(ACK_SERVER_TO_CLIENT)).await?;
    let mut retry = [0; 4];
    session.read_exact(&mut retry).await?;
    assert_eq!(retry, next.to_be_bytes());
    Ok(())
}

#[tokio::test]
async fn receive_budget_bounds_tcp_and_keeps_room_for_missing_udp_head() -> Result<()> {
    let flow = ReceiveFlow::new(1400);
    let full = flow
        .reserve_stream(vec![0; SESSION_RECEIVE_BYTES - RECEIVE_ITEM_OVERHEAD])
        .await
        .context("receive budget")?;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), flow.reserve_stream(vec![0]))
            .await
            .is_err()
    );
    assert!(flow.reserve_packet(vec![0], false).is_none());
    drop(full);
    let headroom = u16::MAX as usize + AEAD_OVERHEAD + RECEIVE_ITEM_OVERHEAD;
    let tail = flow
        .reserve_packet(
            vec![0; SESSION_RECEIVE_BYTES - headroom - RECEIVE_ITEM_OVERHEAD],
            true,
        )
        .context("reorder budget")?;
    assert!(flow.reserve_packet(vec![0], true).is_none());
    let head = flow
        .reserve_packet(vec![0; headroom - RECEIVE_ITEM_OVERHEAD], false)
        .context("missing head must fit")?;
    assert_eq!(flow.budget.available_permits(), 0);
    drop((head, tail));
    assert_eq!(flow.budget.available_permits(), SESSION_RECEIVE_BYTES);
    let tiny = flow
        .reserve_packet(vec![0], false)
        .context("small packet")?;
    assert_eq!(
        SESSION_RECEIVE_BYTES - flow.budget.available_permits(),
        1 + RECEIVE_ITEM_OVERHEAD
    );
    drop(tiny);
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
        immediate: false,
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
