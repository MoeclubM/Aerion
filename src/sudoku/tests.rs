use super::*;

#[tokio::test]
async fn legacy_httpmask_preserves_body_after_post_and_fake_websocket_headers() -> Result<()> {
    for header in [
        "POST /api/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1048576\r\n\r\n",
        "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        "", // raw clients remain accepted by a legacy listener
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (server, _) = listener.accept().await?;
        let mut packet = header.as_bytes().to_vec();
        packet.extend(b"raw-encrypted-body");
        client.write_all(&packet).await?;
        let options = SudokuOptions {
            http_mask: true,
            http_mask_mode: "legacy".into(),
            ..Default::default()
        };
        let mut server = transport::server(server, &options, &["test-user".into()]).await?;
        let mut body = [0; 18];
        tokio::time::timeout(Duration::from_secs(1), server.read_exact(&mut body)).await??;
        assert_eq!(&body, b"raw-encrypted-body");
    }
    Ok(())
}

include!("../../tests/performance/sudoku.rs");
include!("../../tests/performance/sudoku_transport.rs");

#[tokio::test]
async fn record_tunnel_half_close_drains_backpressured_write() -> Result<()> {
    let table = Table::new("half-close", "prefer_entropy", "")?;
    let (up, down) = bases("half-close", None, &[])?;
    // A tiny wire buffer forces every record through multiple Pending writes.
    let (wire, mut peer) = tokio::io::duplex(17);
    let mut stream = tunnel(
        wire,
        Receiver::new(table.clone(), false, false, up, "aes-128-gcm"),
        Sender::new(table.clone(), true, true, down, "aes-128-gcm", 0)?,
    );
    let mut decoder = Receiver::new(table, true, true, down, "aes-128-gcm");
    peer.shutdown().await?;
    let mut byte = [0];
    assert_eq!(stream.read(&mut byte).await?, 0);
    let payload = (0..131_073).map(|i| (i * 7) as u8).collect::<Vec<_>>();
    let received = tokio::time::timeout(Duration::from_secs(5), async {
        let send = async {
            stream.write_all(&payload).await?;
            stream.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        let receive = async {
            let mut received = Vec::new();
            loop {
                let plain = decoder.read(&mut peer).await?;
                if plain.is_empty() {
                    return Ok::<_, anyhow::Error>(received);
                }
                received.extend(plain);
            }
        };
        tokio::try_join!(send, receive).map(|(_, received)| received)
    })
    .await??;
    assert_eq!(received.len(), payload.len());
    assert!(received == payload, "backpressured record data changed");
    Ok(())
}

#[tokio::test]
async fn raw_and_mux_fin_preserve_delayed_response_and_accounting() -> Result<()> {
    for multiplex in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let options = SudokuOptions {
            aead: "aes-128-gcm".into(),
            padding_min: 1,
            padding_max: 5,
            ..Default::default()
        };
        let core = ProxyCore::from_credentials("half-close-user", &[]);
        let server = tokio::spawn(run_sudoku_server_listener_with_core(
            listener,
            SudokuServerConfig {
                listen: address,
                key: "half-close-user".into(),
                users: vec![],
                options: options.clone(),
            },
            core.clone(),
        ));
        let destination = TcpListener::bind("127.0.0.1:0").await?;
        let target = ProxyTarget::Ip(destination.local_addr()?);
        let expected = (0..131_073).map(|i| (i * 3) as u8).collect::<Vec<_>>();
        let response = expected.clone();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await?;
            assert_eq!(request, b"request before FIN");
            tokio::time::sleep(Duration::from_millis(30)).await;
            stream.write_all(&response).await?;
            stream.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        });
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut wire = TcpStream::connect(address).await?;
            let (mut receiver, mut sender) =
                client_handshake(&mut wire, "half-close-user", &options).await?;
            let mut address = Vec::new();
            uot::write_socks_address(&mut address, &target)?;
            if multiplex {
                sender.kip(&mut wire, 0x11, &[]).await?;
                let mut stream = tunnel(wire, receiver, sender);
                mux_frame(&mut stream, 1, 1, &address).await?;
                // Mihomo's idle keepalive must not reset stream zero.
                mux_frame(&mut stream, 2, 0, &[]).await?;
                mux_frame(&mut stream, 2, 1, b"request before FIN").await?;
                mux_frame(&mut stream, 3, 1, &[]).await?;
                let mut received = Vec::new();
                loop {
                    let kind = stream.read_u8().await?;
                    assert_eq!(stream.read_u32().await?, 1);
                    let length = stream.read_u32().await? as usize;
                    let mut data = vec![0; length];
                    stream.read_exact(&mut data).await?;
                    match kind {
                        2 => received.extend(data),
                        3 => break,
                        _ => bail!("unexpected mux response {kind}"),
                    }
                }
                assert_eq!(received.len(), expected.len());
                assert!(received == expected, "mux response data changed");
            } else {
                sender.kip(&mut wire, 0x10, &address).await?;
                sender.write(&mut wire, b"request before FIN").await?;
                wire.shutdown().await?;
                let mut received = Vec::new();
                loop {
                    let plain = receiver.read(&mut wire).await?;
                    if plain.is_empty() {
                        break;
                    }
                    received.extend(plain);
                }
                assert_eq!(received.len(), expected.len());
                assert!(received == expected, "raw response data changed");
            }
            responder.await??;
            Ok::<(), anyhow::Error>(())
        })
        .await;
        server.abort();
        result.with_context(|| format!("multiplex={multiplex}"))??;
        let snapshot = core.snapshot().await;
        assert_eq!(snapshot[0].upload_bytes, b"request before FIN".len() as u64);
        assert_eq!(snapshot[0].download_bytes, expected.len() as u64);
    }
    Ok(())
}

#[tokio::test]
async fn raw_and_mux_target_fin_keep_upload_open() -> Result<()> {
    for multiplex in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let options = SudokuOptions {
            aead: "aes-128-gcm".into(),
            padding_min: 1,
            padding_max: 5,
            ..Default::default()
        };
        let core = ProxyCore::from_credentials("target-fin-user", &[]);
        let server = tokio::spawn(run_sudoku_server_listener_with_core(
            listener,
            SudokuServerConfig {
                listen: address,
                key: "target-fin-user".into(),
                users: vec![],
                options: options.clone(),
            },
            core.clone(),
        ));
        let destination = TcpListener::bind("127.0.0.1:0").await?;
        let target = ProxyTarget::Ip(destination.local_addr()?);
        let upload = (0..131_073).map(|i| (i * 11) as u8).collect::<Vec<_>>();
        let expected = upload.clone();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await?;
            let mut request = [0; 7];
            stream.read_exact(&mut request).await?;
            assert_eq!(&request, b"request");
            stream.write_all(b"reply before FIN").await?;
            stream.shutdown().await?;
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await?;
            assert_eq!(received.len(), expected.len());
            assert!(received == expected, "upload after target FIN changed");
            Ok::<(), anyhow::Error>(())
        });
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut wire = TcpStream::connect(address).await?;
            let (receiver, mut sender) =
                client_handshake(&mut wire, "target-fin-user", &options).await?;
            let mut address = Vec::new();
            uot::write_socks_address(&mut address, &target)?;
            let mut stream = if multiplex {
                sender.kip(&mut wire, 0x11, &[]).await?;
                let mut stream = tunnel(wire, receiver, sender);
                mux_frame(&mut stream, 1, 1, &address).await?;
                mux_client(stream)
            } else {
                sender.kip(&mut wire, 0x10, &address).await?;
                tunnel(wire, receiver, sender)
            };
            stream.write_all(b"request").await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            assert_eq!(response, b"reply before FIN");
            stream.write_all(&upload).await?;
            stream.shutdown().await?;
            responder.await??;
            Ok::<(), anyhow::Error>(())
        })
        .await;
        server.abort();
        result.with_context(|| format!("multiplex={multiplex}"))??;
        let snapshot = core.snapshot().await;
        assert_eq!(snapshot[0].upload_bytes, 7 + upload.len() as u64);
        assert_eq!(snapshot[0].download_bytes, 16);
    }
    Ok(())
}

#[tokio::test]
async fn official_go_half_close_receives_delayed_response() -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let Ok(binary) = std::env::var("SUDOKU_INTEROP_BIN") else {
        return Ok(());
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(run_sudoku_server_listener_with_core(
        listener,
        SudokuServerConfig {
            listen: address,
            key: "interop-user-psk".into(),
            users: vec![],
            options: SudokuOptions {
                aead: "aes-128-gcm".into(),
                ..Default::default()
            },
        },
        ProxyCore::from_credentials("interop-user-psk", &[]),
    ));
    let destination = TcpListener::bind("127.0.0.1:0").await?;
    let target = destination.local_addr()?.to_string();
    let responder = tokio::spawn(async move {
        let (mut stream, _) = destination.accept().await?;
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await?;
        tokio::time::sleep(Duration::from_millis(30)).await;
        stream.write_all(&request).await?;
        stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });
    let expected = (0..131_073).map(|i| i as u8).collect::<Vec<_>>();
    let payload = expected.clone();
    let response = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut peer = Peer(
            Command::new(binary)
                .args([
                    "-mode",
                    "client",
                    "-addr",
                    &address.to_string(),
                    "-target",
                    &target,
                    "-aead",
                    "aes-128-gcm",
                    "-half-close",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        peer.0.stdin.take().unwrap().write_all(&payload)?;
        let mut response = Vec::new();
        std::io::Read::read_to_end(&mut peer.0.stdout.take().unwrap(), &mut response)?;
        ensure!(
            peer.0.wait()?.success(),
            "official half-close client failed"
        );
        Ok(response)
    })
    .await?;
    server.abort();
    responder.await??;
    let response = response?;
    assert_eq!(response.len(), expected.len());
    assert!(response == expected, "official peer response data changed");
    Ok(())
}

#[test]
fn appearance_preserves_fragmented_record_boundaries_without_padding() -> Result<()> {
    for mode in ["prefer_ascii", "prefer_entropy", "up_ascii_down_entropy"] {
        for packed in [false, true] {
            let table = Table::new("fragmented-records", mode, "xpxvvpvv")?;
            for down in [false, true] {
                let mut decoder = table::Decoder::new(table.clone(), down, packed);
                let mut output = Vec::new();
                let mut expected = Vec::new();
                for size in [0, 1, 2, 3, 4, 255, 8192] {
                    let plain = (0..size).map(|i| i as u8).collect::<Vec<_>>();
                    expected.extend_from_slice(&plain);
                    let wire = table::encode(&table, down, packed, &plain, 0)?;
                    for fragment in wire.chunks(7) {
                        output.extend(decoder.feed(fragment)?);
                    }
                }
                assert_eq!(output, expected);
            }
        }
    }
    Ok(())
}

struct Peer(std::process::Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn socks_tcp_udp_httpmask_mux_and_revocation_work_end_to_end() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    for mask in [None, Some("legacy"), Some("ws")] {
        for multiplex in ["off", "on"] {
            let result = async {
                let options = SudokuOptions {
                    http_mask: mask.is_some(),
                    http_mask_mode: mask.unwrap_or("legacy").into(),
                    path_root: "edge".into(),
                    multiplex: multiplex.into(),
                    custom_tables: vec!["xpxvvpvv".into(), "xxppvvvv".into()],
                    table_type: "up_ascii_down_entropy".into(),
                    ..Default::default()
                };
                let server_listener = TcpListener::bind("127.0.0.1:0").await?;
                let address = server_listener.local_addr()?;
                let core = ProxyCore::from_credentials("alice-key", &["bob-key".into()]);
                let server = tokio::spawn(run_sudoku_server_listener_with_core(
                    server_listener,
                    SudokuServerConfig {
                        listen: address,
                        key: "alice-key".into(),
                        users: vec!["bob-key".into()],
                        options: options.clone(),
                    },
                    core.clone(),
                ));
                let client_listener = TcpListener::bind("127.0.0.1:0").await?;
                let local = client_listener.local_addr()?;
                let client = tokio::spawn(run_sudoku_client_listener(
                    client_listener,
                    SudokuClientConfig {
                        listen: local,
                        server_host: address.ip().to_string(),
                        server_port: address.port(),
                        key: "bob-key".into(),
                        options,
                    },
                ));
                let echo = TcpListener::bind("127.0.0.1:0").await?;
                let target = ProxyTarget::Ip(echo.local_addr()?);
                let echo_task = tokio::spawn(async move {
                    let (stream, _) = echo.accept().await?;
                    let (mut r, mut w) = stream.into_split();
                    tokio::io::copy(&mut r, &mut w).await
                });
                let mut socks = TcpStream::connect(local).await?;
                socks.write_all(&[5, 1, 0]).await?;
                let mut greeting = [0; 2];
                socks
                    .read_exact(&mut greeting)
                    .await
                    .context("TCP SOCKS greeting")?;
                assert_eq!(greeting, [5, 0]);
                let mut command = vec![5, 1, 0];
                uot::write_socks_address(&mut command, &target)?;
                socks.write_all(&command).await?;
                let mut reply = [0; 10];
                tokio::time::timeout(Duration::from_secs(10), socks.read_exact(&mut reply))
                    .await
                    .context("TCP SOCKS reply timeout")?
                    .context("TCP SOCKS reply")?;
                assert_eq!(reply[1], 0);
                let data = (0..65536).map(|i| i as u8).collect::<Vec<_>>();
                socks.write_all(&data).await?;
                let mut response = vec![0; data.len()];
                tokio::time::timeout(Duration::from_secs(10), socks.read_exact(&mut response))
                    .await
                    .context("TCP echo timeout")?
                    .context("TCP echo")?;
                assert_eq!(response, data, "TCP mask={mask:?} mux={multiplex}");

                let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                let udp_target = ProxyTarget::Ip(udp_echo.local_addr()?);
                let udp_task = tokio::spawn(async move {
                    let mut buf = [0; 65535];
                    loop {
                        let (n, peer) = udp_echo.recv_from(&mut buf).await?;
                        udp_echo.send_to(&buf[..n], peer).await?;
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), std::io::Error>(())
                });
                let mut control = TcpStream::connect(local).await?;
                control.write_all(&[5, 1, 0]).await?;
                control
                    .read_exact(&mut greeting)
                    .await
                    .context("UDP SOCKS greeting")?;
                control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                tokio::time::timeout(Duration::from_secs(10), control.read_exact(&mut reply))
                    .await
                    .context("UDP SOCKS reply timeout")?
                    .context("UDP SOCKS reply")?;
                assert_eq!(reply[1], 0);
                let (bind, _) = uot::read_socks_address(&reply[3..])?;
                let ProxyTarget::Ip(bind) = bind else {
                    panic!("expected UDP address")
                };
                let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                for n in [1, 32, 4096] {
                    let packet = uot::encode_socks_udp_packet(&udp_target, &data[..n])?;
                    udp.send_to(&packet, bind).await?;
                    let mut buf = [0; 65535];
                    let (length, _) =
                        tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
                            .await??;
                    let (source, payload) = uot::parse_socks_udp_packet(&buf[..length])?;
                    assert_eq!(payload, &data[..n]);
                    assert_eq!(source, udp_target);
                }
                let snapshots = core.snapshot().await;
                let bob = snapshots
                    .iter()
                    .find(|user| user.user_id == "bob-key")
                    .unwrap();
                assert!(bob.upload_bytes >= data.len() as u64 + 4129);
                assert!(bob.download_bytes >= data.len() as u64 + 4129);
                let alice = snapshots
                    .iter()
                    .find(|user| user.user_id == "default")
                    .unwrap();
                assert_eq!(alice.upload_bytes, 0);
                core.replace_users(vec![crate::CoreUser::password("default", "alice-key")])?;
                let mut byte = [0];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(5), socks.read(&mut byte)).await??,
                    0
                );
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(5), control.read(&mut byte)).await??,
                    0
                );
                assert!(core.authenticate("bob-key").await.is_err());
                server.abort();
                client.abort();
                echo_task.abort();
                udp_task.abort();
                Ok::<(), anyhow::Error>(())
            }
            .await;
            result.with_context(|| format!("HTTPMask={mask:?} multiplex={multiplex}"))?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn official_go_peer_interoperates_in_both_directions() -> Result<()> {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    let Ok(binary) = std::env::var("SUDOKU_INTEROP_BIN") else {
        return Ok(());
    };
    let payload = (0..65536).map(|i| i as u8).collect::<Vec<_>>();
    for mode in [
        "prefer_entropy",
        "prefer_ascii",
        "up_ascii_down_entropy",
        "up_entropy_down_ascii",
    ] {
        for aead in ["chacha20-poly1305", "aes-128-gcm"] {
            for pure in [false, true] {
                for (custom, mask) in [("", "raw"), ("xpxvvpvv", "raw"), ("xpxvvpvv", "ws")] {
                    let options = SudokuOptions {
                        table_type: mode.into(),
                        aead: aead.into(),
                        enable_pure_downlink: pure,
                        custom_table: custom.into(),
                        http_mask: mask == "ws",
                        http_mask_mode: "ws".into(),
                        path_root: "edge".into(),
                        ..Default::default()
                    };
                    let args = [
                        "-ascii",
                        mode,
                        "-aead",
                        aead,
                        "-custom",
                        custom,
                        "-mask",
                        mask,
                        if pure { "-pure=true" } else { "-pure=false" },
                    ];
                    let mut peer = Peer(
                        Command::new(&binary)
                            .args(args)
                            .stdout(Stdio::piped())
                            .spawn()?,
                    );
                    let mut address = String::new();
                    std::io::BufReader::new(peer.0.stdout.take().unwrap())
                        .read_line(&mut address)?;
                    let address: SocketAddr = address.trim().parse()?;
                    let mut stream = transport::client(&SudokuClientConfig {
                        listen: address,
                        server_host: address.ip().to_string(),
                        server_port: address.port(),
                        key: "interop-user-psk".into(),
                        options: options.clone(),
                    })
                    .await?;
                    let (receiver, mut sender) = tokio::time::timeout(
                        Duration::from_secs(10),
                        client_handshake(&mut stream, "interop-user-psk", &options),
                    )
                    .await??;
                    sender
                        .kip(&mut stream, 0x10, &[1, 127, 0, 0, 1, 0, 80])
                        .await?;
                    let mut stream = tunnel(stream, receiver, sender);
                    stream.write_all(&payload).await?;
                    let mut response = vec![0; payload.len()];
                    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut response))
                        .await??;
                    assert_eq!(
                        response, payload,
                        "Rust client -> Go server {mode} {aead} pure={pure} custom={custom}"
                    );
                    drop(stream);
                    drop(peer);

                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let address = listener.local_addr()?;
                    let cfg = SudokuServerConfig {
                        listen: address,
                        key: "interop-user-psk".into(),
                        users: vec![],
                        options,
                    };
                    let server = tokio::spawn(run_sudoku_server_listener_with_core(
                        listener,
                        cfg,
                        ProxyCore::from_credentials("interop-user-psk", &[]),
                    ));
                    let echo = TcpListener::bind("127.0.0.1:0").await?;
                    let target = echo.local_addr()?.to_string();
                    let echo_task = tokio::spawn(async move {
                        let (stream, _) = echo.accept().await?;
                        let (mut r, mut w) = stream.into_split();
                        tokio::io::copy(&mut r, &mut w).await
                    });
                    let binary = binary.clone();
                    let args = args.map(String::from);
                    let expected = payload.clone();
                    let response = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                        let mut peer = Peer(
                            Command::new(binary)
                                .args(args)
                                .args([
                                    "-mode",
                                    "client",
                                    "-addr",
                                    &address.to_string(),
                                    "-target",
                                    &target,
                                ])
                                .stdin(Stdio::piped())
                                .stdout(Stdio::piped())
                                .spawn()?,
                        );
                        peer.0.stdin.take().unwrap().write_all(&expected)?;
                        let mut output = Vec::new();
                        std::io::Read::read_to_end(
                            &mut peer.0.stdout.take().unwrap(),
                            &mut output,
                        )?;
                        ensure!(peer.0.wait()?.success(), "official client failed");
                        Ok(output)
                    })
                    .await?;
                    server.abort();
                    echo_task.abort();
                    assert_eq!(
                        response?, payload,
                        "Go client -> Rust server {mode} {aead} pure={pure} custom={custom}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn appearance_roundtrips_all_bytes_and_fragmented_packed_records() -> Result<()> {
    for mode in [
        "prefer_ascii",
        "prefer_entropy",
        "up_ascii_down_entropy",
        "up_entropy_down_ascii",
    ] {
        for custom in ["", "xpxvvpvv"] {
            let table = Table::new("test-user-psk", mode, custom)?;
            let payload = (0..=255).collect::<Vec<u8>>();
            for down in [false, true] {
                for packed in [false, true] {
                    let wire = table::encode(&table, down, packed, &payload, 100)?;
                    let mut decoder = table::Decoder::new(table.clone(), down, packed);
                    let mut decoded = Vec::new();
                    for byte in wire {
                        decoded.extend(decoder.feed(&[byte])?);
                    }
                    assert_eq!(decoded, payload);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn appearance_encoder_stream_roundtrips_mixed_read_boundaries() -> Result<()> {
    let table = Table::new("appearance-stream", "up_ascii_down_entropy", "xpxvvpvv")?;
    for packed in [false, true] {
        for padding in [0, 5, 100] {
            let mut encoder = table::Encoder::new()?;
            let mut wire = Vec::new();
            let mut expected = Vec::new();
            for size in [1, 2, 3, 17, 64, 257, 4097] {
                let plain = (0..size).map(|i| (i * 7) as u8).collect::<Vec<_>>();
                wire.extend_from_slice(encoder.encode(&table, true, packed, &plain, padding));
                expected.extend(plain);
            }
            for fragment in [1, 4, 7, 31, 8192] {
                let mut decoder = table::Decoder::new(table.clone(), true, packed);
                let mut plain = Vec::new();
                for chunk in wire.chunks(fragment) {
                    decoder.feed_into(chunk, &mut plain)?;
                }
                assert_eq!(plain, expected);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn authenticated_handshake_and_revoked_users() -> Result<()> {
    let core = ProxyCore::from_credentials("alice-key", &["bob-key".into()]);
    for aead in ["chacha20-poly1305", "aes-128-gcm"] {
        for pure in [false, true] {
            let options = SudokuOptions {
                aead: aead.into(),
                enable_pure_downlink: pure,
                ..SudokuOptions::default()
            };
            let (mut client, mut server) = tokio::io::duplex(4096);
            let cache = Arc::new(Mutex::new(HashMap::new()));
            let (client_result, server_result) = tokio::join!(
                client_handshake(&mut client, "bob-key", &options),
                server_handshake(
                    &mut server,
                    &options,
                    &core,
                    "127.0.0.1:1234".parse()?,
                    &cache,
                    CredentialCache::default().snapshot(&core, &options)?
                )
            );
            let (mut client_recv, mut client_send) = client_result?;
            let (mut server_recv, mut server_send, session) = server_result?;
            assert_eq!(session.user_id(), "bob-key");
            client_send.write(&mut client, b"hello").await?;
            assert_eq!(server_recv.read(&mut server).await?, b"hello");
            server_send.write(&mut server, b"world").await?;
            assert_eq!(client_recv.read(&mut client).await?, b"world");
        }
    }
    core.replace_users(vec![crate::CoreUser::password("alice", "alice-key")])?;
    assert!(core.authenticate("bob-key").await.is_err());
    Ok(())
}

#[tokio::test]
async fn credential_cache_reuses_tables_and_enforces_live_revocation() -> Result<()> {
    let options = SudokuOptions {
        custom_tables: vec!["xpxvvpvv".into(), "xxppvvvv".into()],
        ..Default::default()
    };
    let core = ProxyCore::from_credentials("alice-key", &["bob-key".into()]);
    let mut cache = CredentialCache::default();
    let first = cache.snapshot(&core, &options)?;
    let bob = first.iter().find(|entry| entry.value == "bob-key").unwrap();
    let second = cache.snapshot(&core, &options)?;
    assert!(Arc::ptr_eq(
        bob,
        second
            .iter()
            .find(|entry| entry.value == "bob-key")
            .unwrap()
    ));
    core.replace_users(vec![
        crate::CoreUser::password("alice", "alice-key"),
        crate::CoreUser::password("carol", "carol-key"),
    ])?;
    let current = cache.snapshot(&core, &options)?;
    assert_eq!(cache.entries.len(), 2);
    assert!(!cache.entries.contains_key("bob-key"));
    assert!(current.iter().any(|entry| entry.value == "carol-key"));
    // A handshake already holding an old snapshot must fail after revocation.
    let (mut client, mut server) = tokio::io::duplex(4096);
    let replays = Arc::new(Mutex::new(HashMap::new()));
    let handshake = async {
        let result = server_handshake(
            &mut server,
            &options,
            &core,
            "127.0.0.1:1234".parse()?,
            &replays,
            first,
        )
        .await;
        drop(server);
        result
    };
    let (client_result, server_result) = tokio::join!(
        client_handshake(&mut client, "bob-key", &options),
        handshake
    );
    assert!(client_result.is_err());
    assert!(
        server_result
            .err()
            .unwrap()
            .to_string()
            .contains("core authentication failed")
    );
    Ok(())
}

#[test]
fn mihomo_import_preserves_sudoku_settings() -> Result<()> {
    let config: crate::MihomoConfig = serde_yaml::from_str(
        "proxies:\n  - name: Sudoku\n    type: sudoku\n    server: example.com\n    port: 443\n    key: user-psk\n    table-type: prefer_ascii\n    enable-pure-downlink: false\n    padding-min: 0\n    padding-max: 0\n    http-mask-multiplex: on\n    udp: true\n",
    )?;
    let proxy = config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?;
    let crate::MihomoClientConfig::Sudoku(proxy) = proxy else {
        panic!("wrong protocol")
    };
    assert_eq!(proxy.key, "user-psk");
    assert_eq!(proxy.options.table_type, "prefer_ascii");
    assert!(!proxy.options.enable_pure_downlink);
    assert_eq!(proxy.options.padding_max, 0);
    assert_eq!(proxy.options.multiplex, "on");
    let legacy: SudokuOptions = serde_json::from_str(r#"{"multiplex":"on"}"#)?;
    assert_eq!(legacy.multiplex, proxy.options.multiplex);
    Ok(())
}

#[tokio::test]
async fn replayed_hello_is_rejected_and_user_hash_cannot_choose_identity() -> Result<()> {
    let key = "bob-key";
    let options = SudokuOptions::default();
    let core = ProxyCore::from_credentials("alice-key", &[key.into()]);
    let replays = Arc::new(Mutex::new(HashMap::new()));
    let ephemeral = secret()?;
    let mut hello = timestamp()?.to_be_bytes().to_vec();
    hello.extend(&Sha256::digest(b"alice-key")[..8]); // Deliberately claim another user's hash.
    hello.extend([42; 16]);
    hello.extend(PublicKey::from(&ephemeral).as_bytes());
    hello.extend(7u32.to_be_bytes());
    let table = options.tables(key)?.remove(0);
    hello.extend(table.hint.to_be_bytes());
    for attempt in 0..2 {
        let (mut wire, mut server_wire) = tokio::io::duplex(4096);
        let options = options.clone();
        let core = core.clone();
        let replays = replays.clone();
        let server = tokio::spawn(async move {
            server_handshake(
                &mut server_wire,
                &options,
                &core,
                "127.0.0.1:1234".parse().unwrap(),
                &replays,
                CredentialCache::default().snapshot(&core, &options)?,
            )
            .await
            .map(|(_, _, session)| session.user_id().to_string())
        });
        let (up, down) = bases(key, None, &[])?;
        let mut sender = Sender::new(table.clone(), false, false, up, "chacha20-poly1305", 5)?;
        sender.kip(&mut wire, 1, &hello).await?;
        if attempt == 0 {
            let mut receiver = Receiver::new(table.clone(), true, true, down, "chacha20-poly1305");
            assert_eq!(receiver.kip(&mut wire).await?.0, 2);
            assert_eq!(server.await??, key);
        } else {
            let error = server.await?.expect_err("replayed nonce must fail");
            assert!(error.to_string().contains("replayed Sudoku handshake"));
        }
    }
    Ok(())
}
