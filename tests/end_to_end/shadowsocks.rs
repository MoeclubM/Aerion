use super::helpers::*;
use aerion::{ShadowsocksClientConfig, ShadowsocksServerConfig, run_shadowsocks_server_with_core};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

#[tokio::test]
async fn malformed_udp_packets_do_not_stop_the_server() -> Result<()> {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let echo_addr = echo.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let mut bytes = [0; 64];
        let (read, peer) = echo.recv_from(&mut bytes).await?;
        echo.send_to(&bytes[..read], peer).await
    });
    let addr = unused_udp_addr()?;
    let server = tokio::spawn(aerion::run_shadowsocks_server(ShadowsocksServerConfig {
        listen: addr,
        method: "aes-128-gcm".into(),
        password: "secret".into(),
        users: vec![],
        tcp: false,
        udp: true,
        udp_over_tcp: false,
    }));
    let result = timeout(Duration::from_secs(5), async {
        while std::net::UdpSocket::bind(addr).is_ok() {
            tokio::task::yield_now().await;
            anyhow::ensure!(!server.is_finished(), "UDP server failed to start");
        }
        let malformed = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        malformed.send_to(b"invalid", addr).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        anyhow::ensure!(
            !server.is_finished(),
            "malformed packet stopped the listener"
        );
        let config = shadowsocks::config::ServerConfig::new(
            addr,
            "secret",
            shadowsocks::crypto::CipherKind::AES_128_GCM,
        )?;
        let context =
            shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Local);
        let proxy = shadowsocks::relay::udprelay::ProxySocket::connect(context, &config).await?;
        proxy
            .send(
                &shadowsocks::relay::socks5::Address::SocketAddress(echo_addr),
                b"valid",
            )
            .await?;
        let mut bytes = [0; 64];
        let (read, target, _) = proxy.recv(&mut bytes).await?;
        anyhow::ensure!(
            &bytes[..read] == b"valid"
                && target == shadowsocks::relay::socks5::Address::SocketAddress(echo_addr),
            "valid UDP relay failed"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("Shadowsocks UDP regression timed out")
    .and_then(|result| result);
    server.abort();
    echo_task.abort();
    result
}

#[tokio::test]
async fn shadowsocks_server_with_core_records_tcp_traffic() -> Result<()> {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await?;
        let mut buffer = [0u8; 64];
        let read = stream.read(&mut buffer).await?;
        stream.write_all(&buffer[..read]).await?;
        Ok::<(), anyhow::Error>(())
    });

    let core = aerion::ProxyCore::from_credentials("test-password", &[]);
    let server_addr = unused_tcp_addr()?;
    let server_task = tokio::spawn(run_shadowsocks_server_with_core(
        ShadowsocksServerConfig {
            listen: server_addr,
            method: "aes-128-gcm".to_string(),
            password: "test-password".to_string(),
            users: Vec::new(),
            tcp: true,
            udp: false,
            udp_over_tcp: false,
        },
        core.clone(),
    ));

    let client_listener = TcpListener::bind("127.0.0.1:0").await?;
    let client_addr = client_listener.local_addr()?;
    let client_core = aerion::ProxyCore::from_credentials("test-password", &[]);
    let client_task = tokio::spawn(
        aerion::shadowsocks::run_shadowsocks_client_listener_with_core(
            client_listener,
            ShadowsocksClientConfig {
                listen: client_addr,
                server_host: "127.0.0.1".to_string(),
                server_port: server_addr.port(),
                method: "aes-128-gcm".to_string(),
                password: "test-password".to_string(),
                udp: false,
                udp_over_tcp: false,
            },
            Some(client_core.clone()),
        ),
    );

    let payload = b"hello ss core";
    let result = timeout(Duration::from_secs(5), async {
        socks_echo(client_addr, echo_addr, payload).await?;
        let client_stats = client_core.snapshot().await;
        anyhow::ensure!(
            client_stats[0].upload_bytes == payload.len() as u64
                && client_stats[0].download_bytes == payload.len() as u64,
            "Shadowsocks client did not record payload bytes"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        let snapshots = core.snapshot().await;
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.user_id == "default")
            .context("missing Shadowsocks core default user snapshot")?;
        anyhow::ensure!(
            snapshot.upload_bytes >= payload.len() as u64,
            "Shadowsocks core upload was not recorded"
        );
        anyhow::ensure!(
            snapshot.download_bytes >= payload.len() as u64,
            "Shadowsocks core download was not recorded"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("Shadowsocks core accounting test timed out")
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
async fn ss2022_multi_user_tcp_udp_and_uot_accounting() -> Result<()> {
    use aerion::{CoreUser, ProxyCore};
    use bytes::BytesMut;
    use shadowsocks::config::{ServerConfig, ServerType};
    use shadowsocks::context::Context as SsContext;
    use shadowsocks::relay::socks5::Address;
    use shadowsocks::relay::tcprelay::ProxyClientStream;
    use shadowsocks::relay::udprelay::crypto_io::{decrypt_server_payload, encrypt_client_payload};
    use shadowsocks::relay::udprelay::options::UdpSocketControlData;

    timeout(Duration::from_secs(15), async {
        for (method, key_len, external_core) in [
            ("2022-blake3-aes-128-gcm", 16, true),
            ("2022-blake3-aes-256-gcm", 32, true),
            ("2022-blake3-aes-128-gcm", 16, false),
        ] {
            let mut tasks = tokio::task::JoinSet::new();
            let tcp_echo = TcpListener::bind("127.0.0.1:0").await?;
            let tcp_target = tcp_echo.local_addr()?;
            tasks.spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    let (mut stream, _) = tcp_echo.accept().await?;
                    connections.spawn(async move {
                        let (mut reader, mut writer) = stream.split();
                        tokio::io::copy(&mut reader, &mut writer).await
                    });
                }
                #[allow(unreachable_code)]
                Ok::<_, anyhow::Error>(())
            });
            let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let udp_target = udp_echo.local_addr()?;
            tasks.spawn(async move {
                let mut buffer = [0; 1024];
                loop {
                    let (read, peer) = udp_echo.recv_from(&mut buffer).await?;
                    udp_echo.send_to(&buffer[..read], peer).await?;
                }
                #[allow(unreachable_code)]
                Ok::<_, anyhow::Error>(())
            });

            let server_key = STANDARD.encode(vec![1; key_len]);
            let keys = [
                STANDARD.encode(vec![2; key_len]),
                STANDARD.encode(vec![3; key_len]),
            ];
            let users = vec![
                CoreUser::password("alice", &keys[0]),
                CoreUser::password("bob", &keys[1]),
            ];
            let core = ProxyCore::new(users.clone())?;
            let addr = unused_tcp_addr()?;
            let config = ShadowsocksServerConfig {
                listen: addr,
                method: method.into(),
                password: server_key.clone(),
                users: vec![format!("alice:{}", keys[0]), format!("bob:{}", keys[1])],
                tcp: true,
                udp: true,
                udp_over_tcp: true,
            };
            if external_core {
                tasks.spawn(run_shadowsocks_server_with_core(config, core.clone()));
            } else {
                tasks.spawn(aerion::run_shadowsocks_server(config));
            }
            while TcpStream::connect(addr).await.is_err() || std::net::UdpSocket::bind(addr).is_ok()
            {
                tokio::task::yield_now().await;
            }

            // Both users share the same client address and session ID.
            let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            udp_socket.connect(addr).await?;
            let mut session_id = [0; 8];
            getrandom::fill(&mut session_id)?;
            let mut control = UdpSocketControlData::default();
            control.client_session_id = u64::from_be_bytes(session_id);
            control.packet_id = 1;
            // The dependency's UDP cipher cache identifies keys by their address.
            // Keep every client config alive while sharing the session ID.
            let clients = keys
                .iter()
                .map(|key| {
                    ServerConfig::new(addr, format!("{server_key}:{key}"), method.parse().unwrap())
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut streams = Vec::new();
            let mut uot_streams = Vec::new();
            for (index, client) in clients.iter().enumerate() {
                eprintln!("SS2022 {method}, external core {external_core}, user {index}");
                let context = SsContext::new_shared(ServerType::Local);
                let payload = vec![index as u8 + 1; 7 + index];
                let mut stream =
                    ProxyClientStream::connect(context.clone(), client, tcp_target).await?;
                stream.write_all(&payload).await?;
                let mut echoed = vec![0; payload.len()];
                timeout(Duration::from_secs(3), stream.read_exact(&mut echoed))
                    .await
                    .context("SS2022 TCP echo timed out")??;
                anyhow::ensure!(echoed == payload, "SS2022 TCP payload mismatch");
                streams.push(stream);

                let mut encrypted = BytesMut::new();
                if index == 1 {
                    udp_socket.send(b"invalid").await?;
                }
                encrypt_client_payload(
                    &context,
                    client.method(),
                    client.key(),
                    &Address::SocketAddress(udp_target),
                    &control,
                    &client.clone_identity_keys(),
                    &payload,
                    &mut encrypted,
                );
                udp_socket.send(&encrypted).await?;
                let mut buffer = [0; 1024];
                let read = timeout(Duration::from_secs(3), udp_socket.recv(&mut buffer))
                    .await
                    .context("SS2022 UDP echo timed out")??;
                let (read, _, _) = decrypt_server_payload(
                    &context,
                    client.method(),
                    client.key(),
                    &mut buffer[..read],
                )?;
                anyhow::ensure!(&buffer[..read] == payload, "SS2022 UDP payload mismatch");

                let mut uot = ProxyClientStream::connect(
                    context,
                    client,
                    Address::DomainNameAddress(aerion::uot::MAGIC_ADDRESS.into(), 0),
                )
                .await?;
                let packet = aerion::uot::encode_associate_packet(
                    &aerion::protocol::ProxyTarget::Ip(udp_target),
                    &payload,
                )?;
                let mut request = aerion::uot::encode_v2_associate_request()?;
                request.extend_from_slice(&packet);
                uot.write_all(&request).await?;
                let mut response = vec![0; packet.len()];
                timeout(Duration::from_secs(3), uot.read_exact(&mut response))
                    .await
                    .context("SS2022 UoT echo timed out")??;
                let (_, echoed) = aerion::uot::decode_associate_packet(&response)?;
                anyhow::ensure!(echoed == payload, "SS2022 UoT payload mismatch");
                uot_streams.push(uot);

                if external_core {
                    let snapshots = core.snapshot().await;
                    let snapshot = snapshots
                        .iter()
                        .find(|s| s.user_id == users[index].id)
                        .unwrap();
                    anyhow::ensure!(
                        snapshot.upload_bytes == (payload.len() * 3) as u64
                            && snapshot.download_bytes == (payload.len() * 3) as u64,
                        "SS2022 traffic was not attributed to {}: {snapshot:?}",
                        users[index].id
                    );
                    anyhow::ensure!(snapshot.online_ip_list == ["127.0.0.1"], "missing user IP");
                    if index == 0 {
                        let bob = snapshots.iter().find(|s| s.user_id == "bob").unwrap();
                        anyhow::ensure!(
                            bob.upload_bytes == 0 && bob.download_bytes == 0,
                            "mixed user traffic"
                        );
                    }
                }
            }
            if external_core {
                core.replace_users(vec![users[1].clone()])?;
                let mut buffer = [0; 4];
                anyhow::ensure!(
                    matches!(
                        timeout(Duration::from_secs(3), streams[0].read(&mut buffer))
                            .await
                            .context("removed SS2022 user did not disconnect")?,
                        Ok(0) | Err(_)
                    ),
                    "removed SS2022 user kept an active TCP connection"
                );
                anyhow::ensure!(
                    matches!(
                        timeout(Duration::from_secs(3), uot_streams[0].read(&mut buffer))
                            .await
                            .context("removed SS2022 user kept an idle UoT connection")?,
                        Ok(0) | Err(_)
                    ),
                    "removed SS2022 user kept an active UoT connection"
                );
                streams[1].write_all(b"live").await?;
                streams[1].read_exact(&mut buffer).await?;
                anyhow::ensure!(&buffer == b"live", "removing alice disconnected bob");
                core.cancel_all_sessions();
                tasks.abort_all();
                timeout(Duration::from_secs(3), async {
                    while std::net::UdpSocket::bind(addr).is_err() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .context("cancelled SS2022 UDP sessions kept the listener bound")?;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("SS2022 multi-user relay timed out")?
}
