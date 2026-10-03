use super::*;

struct Peer(std::process::Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn socks_tcp_udp_httpmask_mux_and_revocation_work_end_to_end() -> Result<()> {
    for mask in [None, Some("legacy"), Some("ws")] {
        for multiplex in ["off", "on"] {
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
            socks.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 0]);
            let mut command = vec![5, 1, 0];
            uot::write_socks_address(&mut command, &target)?;
            socks.write_all(&command).await?;
            let mut reply = [0; 10];
            tokio::time::timeout(Duration::from_secs(10), socks.read_exact(&mut reply)).await??;
            assert_eq!(reply[1], 0);
            let data = (0..65536).map(|i| i as u8).collect::<Vec<_>>();
            socks.write_all(&data).await?;
            let mut response = vec![0; data.len()];
            tokio::time::timeout(Duration::from_secs(10), socks.read_exact(&mut response))
                .await??;
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
            control.read_exact(&mut greeting).await?;
            control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            tokio::time::timeout(Duration::from_secs(10), control.read_exact(&mut reply)).await??;
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

#[tokio::test]
async fn authenticated_handshake_rejects_replay_and_revoked_users() -> Result<()> {
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
                    &cache
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

#[test]
fn mihomo_import_preserves_sudoku_settings() -> Result<()> {
    let config: crate::MihomoConfig = serde_yaml::from_str(
        "proxies:\n  - name: Sudoku\n    type: sudoku\n    server: example.com\n    port: 443\n    key: user-psk\n    table-type: prefer_ascii\n    enable-pure-downlink: false\n    padding-min: 0\n    padding-max: 0\n    udp: true\n",
    )?;
    let proxy = config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?;
    let crate::MihomoClientConfig::Sudoku(proxy) = proxy else {
        panic!("wrong protocol")
    };
    assert_eq!(proxy.key, "user-psk");
    assert_eq!(proxy.options.table_type, "prefer_ascii");
    assert!(!proxy.options.enable_pure_downlink);
    assert_eq!(proxy.options.padding_max, 0);
    Ok(())
}
