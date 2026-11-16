use super::*;
use crate::core::{CoreUser, ProxyCore};
use crate::listener::ListenerStopToken;
use crate::protocol::ProxyTarget;
use crate::tls::ServerTlsMaterial;
use crate::{MihomoClientConfig, MihomoConfig, socks, uot};
use anyhow::Result;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn make_test_tls_material() -> Result<(ServerTlsMaterial, String)> {
    crate::tls::init_crypto();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_pem = cert.cert.pem();
    let material = ServerTlsMaterial {
        cert_path: None,
        key_path: None,
        certificates: vec![cert_pem.clone()],
        key: Some(cert.signing_key.serialize_pem()),
        label: "flux test".into(),
        alpn_protocols: Vec::new(),
        early_data: false,
        ech: None,
    };
    Ok((material, cert_pem))
}

#[test]
fn flux_mihomo_yaml_parses_default_and_manual_channels() -> Result<()> {
    let (_, pub_tcp) = generate_flux_x25519_keypair()?;
    let (_, pub_quic) = generate_flux_x25519_keypair()?;
    let yaml = format!(
        r#"
proxies:
  - name: FluxAuto
    type: flux
    server: edge.example.com
    port: 443
    key: user-secret-token
    servername: edge.example.com
    resolved-v4:
      - 203.0.113.10
    resolved-v6:
      - 2001:db8::10
  - name: FluxManual
    type: flux
    server: edge.example.com
    port: 443
    password: user-secret-token
    ip-strategy: dual
    standby-channels: 3
    channel-max-mbps: 35
    rotation-interval-sec: 120
    rotation-bytes-mb: 64
    channels:
      - id: tcp-v4
        transport: tcp
        ports: "443"
        ip-version: ipv4
        security: obfs
        public-key: {pub_tcp}
        role: primary
        weight: 100
      - id: ws-cdn
        server: cdn.example.com
        ports: 8443
        transport: ws
        http-path: /flux-ws
        http-host: cdn.example.com
        security: tls
        skip-cert-verify: true
        role: primary
        weight: 80
      - id: quic-hop
        ports: "21000-21002"
        transport: udp
        security: obfs
        public-key: {pub_quic}
        role: backup
        weight: 60
"#
    );

    let cfg: MihomoConfig = serde_yaml::from_str(&yaml)?;
    let listen: SocketAddr = "127.0.0.1:1080".parse()?;

    let MihomoClientConfig::Flux(auto_cfg) = cfg.resolved_proxy_config("FluxAuto", listen)? else {
        panic!("expected Flux client config for FluxAuto");
    };
    assert_eq!(auto_cfg.options.ip_strategy, FluxIpStrategy::Latency);
    assert_eq!(auto_cfg.options.channel_max_mbps, DEFAULT_CHANNEL_MAX_MBPS);
    assert_eq!(auto_cfg.channels.len(), 2);
    assert_eq!(auto_cfg.channels[0].id, "tcp-v4");
    assert_eq!(auto_cfg.channels[0].transport, FluxTransportKind::Tcp);
    assert_eq!(auto_cfg.channels[0].ip_version, "ipv4");
    assert_eq!(auto_cfg.channels[0].security, FluxSecurityMode::Tls);
    assert_eq!(auto_cfg.channels[1].id, "tcp-v6");
    assert_eq!(auto_cfg.channels[1].transport, FluxTransportKind::Tcp);
    assert_eq!(auto_cfg.channels[1].ip_version, "ipv6");
    assert_eq!(auto_cfg.channels[1].security, FluxSecurityMode::Tls);
    assert_eq!(
        auto_cfg.channels[0].resolved_v4,
        vec![Ipv4Addr::new(203, 0, 113, 10)]
    );
    assert_eq!(
        auto_cfg.channels[1].resolved_v6,
        vec!["2001:db8::10".parse::<Ipv6Addr>()?]
    );
    assert_eq!(auto_cfg.all_static_ips().len(), 2);

    let MihomoClientConfig::Flux(manual_cfg) = cfg.resolved_proxy_config("FluxManual", listen)?
    else {
        panic!("expected Flux client config for FluxManual");
    };
    assert_eq!(manual_cfg.options.standby_channels, 3);
    assert_eq!(manual_cfg.options.channel_max_mbps, 35);
    assert_eq!(manual_cfg.channels.len(), 3);
    assert_eq!(manual_cfg.channels[0].security, FluxSecurityMode::Obfs);
    assert_eq!(manual_cfg.channels[1].transport, FluxTransportKind::Http);
    assert_eq!(manual_cfg.channels[1].http_mode, FluxHttpMode::Ws);
    assert_eq!(manual_cfg.channels[1].http_path, "/flux-ws");
    assert_eq!(manual_cfg.channels[2].ports, vec![21000, 21001, 21002]);
    assert_eq!(manual_cfg.channels[2].security, FluxSecurityMode::Obfs);
    assert_eq!(manual_cfg.channels[2].role, FluxChannelRole::Backup);

    let rejected_reality = serde_yaml::from_str::<MihomoConfig>(
        r#"
proxies:
  - name: FluxRealityRejected
    type: flux
    server: edge.example.com
    port: 443
    key: user-secret-token
    channels:
      - id: ch-1
        transport: tcp
        security: reality
"#,
    )
    .expect("mihomo top-level parses")
    .resolved_proxy_config("FluxRealityRejected", listen);
    assert!(rejected_reality.is_err());

    let oversized = parse_port_spec("10000-10100", MAX_FLUX_EXPANDED_PORTS);
    assert!(oversized.is_err());
    Ok(())
}

#[tokio::test]
async fn flux_multi_channel_shares_single_core_session_and_relays_tcp_udp() -> Result<()> {
    let (tls_material, cert_pem) = make_test_tls_material()?;
    let (ws_priv, ws_pub) = generate_flux_x25519_keypair()?;
    let (quic_priv, quic_pub) = generate_flux_x25519_keypair()?;

    // Target TCP echo server
    let tcp_echo = TcpListener::bind("127.0.0.1:0").await?;
    let tcp_target_addr = tcp_echo.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut s, _)) = tcp_echo.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    let Ok(n) = s.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        let _ = s.shutdown().await;
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // Target UDP echo server
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_target_addr = udp_echo.local_addr()?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = udp_echo.recv_from(&mut buf).await {
            let _ = udp_echo.send_to(&buf[..n], peer).await;
        }
    });

    let has_v6 = TcpListener::bind("[::1]:0").await.is_ok();
    let ws_listen_ip = if has_v6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };

    let mut user = CoreUser::password("u-flux", "flux-user-credential");
    user.max_online_sessions = Some(1);
    user.max_online_ips = Some(2);
    let core = ProxyCore::new(vec![user])?;

    let server_cfg = FluxServerConfig {
        key: String::new(),
        users: Vec::new(),
        udp: true,
        listeners: vec![
            FluxChannelServerConfig {
                id: "srv-tcp-tls".to_string(),
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ports: vec![0],
                transport: FluxTransportKind::Tcp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Tls,
                cert_mode: FluxCertMode::Inherit,
                tls_material: Some(tls_material),
                private_key: None,
            },
            FluxChannelServerConfig {
                id: "srv-ws-obfs".to_string(),
                listen_ip: ws_listen_ip,
                ports: vec![0],
                transport: FluxTransportKind::Http,
                http_mode: FluxHttpMode::Ws,
                http_host: Some("cdn.example.com".to_string()),
                http_path: "/ws-flux".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                cert_mode: FluxCertMode::OriginPlain,
                tls_material: None,
                private_key: Some(ws_priv),
            },
            FluxChannelServerConfig {
                id: "srv-quic-obfs".to_string(),
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ports: vec![0],
                transport: FluxTransportKind::Udp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                cert_mode: FluxCertMode::Inherit,
                tls_material: None,
                private_key: Some(quic_priv),
            },
        ],
    };

    let running_srv = start_flux_server_with_core(server_cfg, core.clone())?;
    let tcp_port = running_srv.tcp_addrs()[0].port();
    let ws_port = running_srv.tcp_addrs()[1].port();
    let quic_port = running_srv.udp_addrs()[0].port();

    let ws_host = if has_v6 { "::1" } else { "127.0.0.1" };

    let socks_listener = TcpListener::bind("127.0.0.1:0").await?;
    let socks_addr = socks_listener.local_addr()?;
    let client_cfg = FluxClientConfig {
        listen: socks_addr,
        server_host: "127.0.0.1".to_string(),
        server_port: tcp_port,
        key: "flux-user-credential".to_string(),
        udp: true,
        options: FluxOptions {
            ip_strategy: FluxIpStrategy::Dual,
            standby_channels: 2,
            channel_max_mbps: DEFAULT_CHANNEL_MAX_MBPS,
            rotation_interval_sec: 180,
            rotation_bytes_mb: 96,
        },
        channels: vec![
            FluxChannelClientConfig {
                id: "c-tcp-tls".to_string(),
                server_host: "127.0.0.1".to_string(),
                ports: vec![tcp_port],
                ip_version: "ipv4".to_string(),
                resolved_v4: Vec::new(),
                resolved_v6: Vec::new(),
                transport: FluxTransportKind::Tcp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Tls,
                sni: "localhost".to_string(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: vec![cert_pem],
                pinned_cert_sha256: Vec::new(),
                public_key: None,
                tls_binding: true,
                role: FluxChannelRole::Primary,
                weight: 100,
            },
            FluxChannelClientConfig {
                id: "c-ws-obfs".to_string(),
                server_host: ws_host.to_string(),
                ports: vec![ws_port],
                ip_version: "auto".to_string(),
                resolved_v4: Vec::new(),
                resolved_v6: Vec::new(),
                transport: FluxTransportKind::Http,
                http_mode: FluxHttpMode::Ws,
                http_host: Some("cdn.example.com".to_string()),
                http_path: "/ws-flux".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                sni: "cdn.example.com".to_string(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                public_key: Some(ws_pub),
                tls_binding: false,
                role: FluxChannelRole::Primary,
                weight: 90,
            },
            FluxChannelClientConfig {
                id: "c-quic-obfs".to_string(),
                server_host: "127.0.0.1".to_string(),
                ports: vec![quic_port],
                ip_version: "ipv4".to_string(),
                resolved_v4: Vec::new(),
                resolved_v6: Vec::new(),
                transport: FluxTransportKind::Udp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                sni: "localhost".to_string(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                public_key: Some(quic_pub),
                tls_binding: false,
                role: FluxChannelRole::Primary,
                weight: 95,
            },
        ],
    };

    let client_stop = ListenerStopToken::new();
    let client_stop_run = client_stop.clone();
    let client_task = tokio::spawn(async move {
        run_flux_client_listener_with_core_until(socks_listener, client_cfg, None, client_stop_run)
            .await
    });

    // Give background warmer a moment to bring up all 3 heterogeneous channels
    tokio::time::sleep(Duration::from_millis(250)).await;

    // 1. SOCKS5 TCP roundtrip
    let mut tcp_tunnel = socks::connect_tcp(socks_addr, &ProxyTarget::Ip(tcp_target_addr)).await?;
    let tcp_payload = vec![0x5Au8; 40 * 1024];
    tcp_tunnel.write_all(&tcp_payload).await?;
    let mut tcp_echoed = vec![0u8; tcp_payload.len()];
    tcp_tunnel.read_exact(&mut tcp_echoed).await?;
    assert_eq!(tcp_echoed, tcp_payload);
    tcp_tunnel.shutdown().await?;

    // 2. SOCKS5 UDP roundtrip (including > 2500B payload exercising fragmentation + reassembly)
    let assoc = socks::udp_associate(socks_addr).await?;
    let udp_payload = (0..3000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let pkt = uot::encode_socks_udp_packet(&ProxyTarget::Ip(udp_target_addr), &udp_payload)?;
    assoc.udp.send_to(&pkt, assoc.bind).await?;
    let mut udp_resp = vec![0u8; 4096];
    let (n, _) =
        tokio::time::timeout(Duration::from_secs(5), assoc.udp.recv_from(&mut udp_resp)).await??;
    let (_, decoded_udp) = uot::parse_socks_udp_packet(&udp_resp[..n])?;
    assert_eq!(decoded_udp, udp_payload.as_slice());
    drop(assoc);

    // 3. Verify all 3 warm channels shared a SINGLE CoreSession (max_online_sessions == 1!)
    let snap = core.snapshot().await;
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].online_sessions, 1);
    assert!(snap[0].upload_bytes >= (tcp_payload.len() + udp_payload.len()) as u64);
    assert!(snap[0].download_bytes >= (tcp_payload.len() + udp_payload.len()) as u64);

    client_stop.stop();
    let _ = client_task.await;
    running_srv.stop();
    let _ = running_srv.wait().await;
    Ok(())
}

#[tokio::test]
async fn flux_hot_stream_migration_survives_mid_transfer_channel_cut() -> Result<()> {
    let (tcp_priv, tcp_pub) = generate_flux_x25519_keypair()?;
    let (quic_priv, quic_pub) = generate_flux_x25519_keypair()?;
    // Target TCP echo server that keeps connection open across multiple bursts
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let target_conn_counter = target_connections.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            target_conn_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        let _ = stream.shutdown().await;
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let core = ProxyCore::new(vec![CoreUser::password("u1", "secret-migrate")])?;

    let server_cfg = FluxServerConfig {
        key: String::new(),
        users: Vec::new(),
        udp: true,
        listeners: vec![
            FluxChannelServerConfig {
                id: "primary-tcp".to_string(),
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ports: vec![0],
                transport: FluxTransportKind::Tcp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                cert_mode: FluxCertMode::Inherit,
                tls_material: None,
                private_key: Some(tcp_priv),
            },
            FluxChannelServerConfig {
                id: "backup-quic".to_string(),
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ports: vec![0],
                transport: FluxTransportKind::Udp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                cert_mode: FluxCertMode::Inherit,
                tls_material: None,
                private_key: Some(quic_priv),
            },
        ],
    };

    let running_srv = start_flux_server_with_core(server_cfg, core)?;
    let real_tcp_addr = running_srv.tcp_addrs()[0];
    let quic_port = running_srv.udp_addrs()[0].port();

    // Controllable TCP middlebox in front of primary-tcp so we can cut it mid-stream!
    let middlebox = TcpListener::bind("127.0.0.1:0").await?;
    let middlebox_port = middlebox.local_addr()?.port();
    let kill_handles: Arc<StdMutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let kill_handles_bg = kill_handles.clone();
    let middlebox_accept = tokio::spawn(async move {
        while let Ok((mut down, _)) = middlebox.accept().await {
            if let Ok(mut up) = TcpStream::connect(real_tcp_addr).await {
                let h = tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                });
                kill_handles_bg.lock().unwrap().push(h);
            }
        }
    });

    let socks_listener = TcpListener::bind("127.0.0.1:0").await?;
    let socks_addr = socks_listener.local_addr()?;

    let client_cfg = FluxClientConfig {
        listen: socks_addr,
        server_host: "127.0.0.1".to_string(),
        server_port: middlebox_port,
        key: "secret-migrate".to_string(),
        udp: true,
        options: FluxOptions {
            ip_strategy: FluxIpStrategy::Dual,
            standby_channels: 1,
            channel_max_mbps: DEFAULT_CHANNEL_MAX_MBPS,
            rotation_interval_sec: 300,
            rotation_bytes_mb: 128,
        },
        channels: vec![
            FluxChannelClientConfig {
                id: "primary-tcp".to_string(),
                server_host: "127.0.0.1".to_string(),
                ports: vec![middlebox_port],
                ip_version: "ipv4".to_string(),
                resolved_v4: Vec::new(),
                resolved_v6: Vec::new(),
                transport: FluxTransportKind::Tcp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                sni: "localhost".to_string(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                public_key: Some(tcp_pub),
                tls_binding: false,
                role: FluxChannelRole::Primary,
                weight: 100,
            },
            FluxChannelClientConfig {
                id: "backup-quic".to_string(),
                server_host: "127.0.0.1".to_string(),
                ports: vec![quic_port],
                ip_version: "ipv4".to_string(),
                resolved_v4: Vec::new(),
                resolved_v6: Vec::new(),
                transport: FluxTransportKind::Udp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                sni: "localhost".to_string(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                public_key: Some(quic_pub),
                tls_binding: false,
                role: FluxChannelRole::Backup,
                weight: 80,
            },
        ],
    };

    let client_stop = ListenerStopToken::new();
    let client_stop_run = client_stop.clone();
    let client_task = tokio::spawn(async move {
        run_flux_client_listener_with_core_until(socks_listener, client_cfg, None, client_stop_run)
            .await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Open a single long-lived SOCKS5 TCP connection
    let mut inner_conn = socks::connect_tcp(socks_addr, &ProxyTarget::Ip(target_addr)).await?;

    // Phase 1: 64 KiB over primary TCP channel
    let phase1 = (0..65536)
        .map(|i| ((i * 7 + 3) % 256) as u8)
        .collect::<Vec<_>>();
    inner_conn.write_all(&phase1).await?;
    let mut recv1 = vec![0u8; phase1.len()];
    inner_conn.read_exact(&mut recv1).await?;
    assert_eq!(recv1, phase1);

    // Cut the primary TCP channel completely while inner_conn remains open!
    middlebox_accept.abort();
    for h in kill_handles.lock().unwrap().drain(..) {
        h.abort();
    }

    // Phase 2: Immediately stream 128 KiB on the SAME inner_conn; must hot-migrate to backup QUIC!
    let phase2 = (0..131072)
        .map(|i| ((i * 13 + 19) % 256) as u8)
        .collect::<Vec<_>>();
    inner_conn.write_all(&phase2).await?;
    let mut recv2 = vec![0u8; phase2.len()];
    tokio::time::timeout(Duration::from_secs(6), inner_conn.read_exact(&mut recv2)).await??;
    assert_eq!(recv2, phase2);

    // Target server must have seen ONLY ONE TCP connection (never reconnected!)
    assert_eq!(
        target_connections.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    inner_conn.shutdown().await?;
    client_stop.stop();
    let _ = client_task.await;
    running_srv.stop();
    let _ = running_srv.wait().await;
    Ok(())
}

#[tokio::test]
async fn flux_latency_strategy_and_udp_relay_role_route_cleanly() -> Result<()> {
    let (tcp_priv, tcp_pub) = generate_flux_x25519_keypair()?;
    let (udp_priv, udp_pub) = generate_flux_x25519_keypair()?;
    let (_, udp_eq_pub) = generate_flux_x25519_keypair()?;
    let yaml = format!(
        r#"
proxies:
  - name: FluxPerChannel
    type: flux
    server: edge.example.com
    port: 443
    key: user-secret-token
    ip-strategy: latency
    standby-channels: 0
    channels:
      - id: tcp-v4
        transport: tcp
        ip-version: ipv4
        public-key: {tcp_pub}
        role: primary
      - id: tcp-v6
        transport: tcp
        ip-version: ipv6
        security: tls
        sni: edge.example.com
        role: primary
      - id: udp-dedicated
        transport: udp
        ports: 21000
        public-key: {udp_pub}
        role: udp_relay
      - id: udp-equal
        transport: udp
        ports: 21001
        public-key: {udp_eq_pub}
        role: equal
"#
    );
    let cfg: MihomoConfig = serde_yaml::from_str(&yaml)?;
    let listen: SocketAddr = "127.0.0.1:1080".parse()?;
    let MihomoClientConfig::Flux(parsed) = cfg.resolved_proxy_config("FluxPerChannel", listen)?
    else {
        panic!("expected Flux client config");
    };
    assert_eq!(parsed.options.ip_strategy, FluxIpStrategy::Latency);
    assert_eq!(parsed.channels[0].security, FluxSecurityMode::Obfs);
    assert_eq!(parsed.channels[1].security, FluxSecurityMode::Tls);
    assert_eq!(parsed.channels[2].security, FluxSecurityMode::Obfs);
    assert_eq!(parsed.channels[2].role, FluxChannelRole::UdpRelay);
    assert_eq!(parsed.channels[3].role, FluxChannelRole::Primary);

    // Live runtime check: primary TCP + dedicated udp_relay UDP channel
    let core = ProxyCore::new(vec![CoreUser::password("u1", "user-secret-token")])?;
    let running = start_flux_server_with_core(
        FluxServerConfig {
            key: String::new(),
            users: Vec::new(),
            udp: true,
            listeners: vec![
                FluxChannelServerConfig {
                    id: "tcp-main".to_string(),
                    listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ports: vec![0],
                    transport: FluxTransportKind::Tcp,
                    http_mode: FluxHttpMode::Ws,
                    http_host: None,
                    http_path: "/".to_string(),
                    http_headers: BTreeMap::new(),
                    security: FluxSecurityMode::Obfs,
                    cert_mode: FluxCertMode::Inherit,
                    tls_material: None,
                    private_key: Some(tcp_priv),
                },
                FluxChannelServerConfig {
                    id: "udp-relay".to_string(),
                    listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ports: vec![0],
                    transport: FluxTransportKind::Udp,
                    http_mode: FluxHttpMode::Ws,
                    http_host: None,
                    http_path: "/".to_string(),
                    http_headers: BTreeMap::new(),
                    security: FluxSecurityMode::Obfs,
                    cert_mode: FluxCertMode::Inherit,
                    tls_material: None,
                    private_key: Some(udp_priv),
                },
            ],
        },
        core,
    )?;
    let tcp_port = running.tcp_addrs()[0].port();
    let udp_port = running.udp_addrs()[0].port();

    let client_proxy: crate::config_compat::mihomo::MihomoFluxProxy =
        serde_json::from_value(serde_json::json!({
            "name": "FluxLive",
            "server": "127.0.0.1",
            "port": tcp_port,
            "key": "user-secret-token",
            "ip-strategy": "latency",
            "standby-channels": 0,
            "channels": [
                {
                    "id": "tcp-main",
                    "transport": "tcp",
                    "ports": tcp_port,
                    "public-key": tcp_pub,
                    "role": "primary"
                },
                {
                    "id": "udp-relay",
                    "transport": "udp",
                    "ports": udp_port,
                    "public-key": udp_pub,
                    "role": "udp_relay"
                }
            ]
        }))?;
    let pool = FluxClientPool::new(client_proxy.to_client_config("127.0.0.1:0".parse()?)?)?;

    // UDP picker dials udp_relay on demand and selects it
    let udp_ch = pool.pick_channel_for_udp().await?;
    assert_eq!(udp_ch.role, FluxChannelRole::UdpRelay);
    assert_eq!(udp_ch.transport, FluxTransportKind::Udp);

    // Even though udp_relay is already warm, TCP stream picker warms and picks primary TCP
    let tcp_slot = pool.pick_channel_for_new_stream().await?;
    assert_eq!(tcp_slot.ch.role, FluxChannelRole::Primary);
    assert_eq!(tcp_slot.ch.transport, FluxTransportKind::Tcp);
    drop(tcp_slot);

    pool.shutdown_all();
    running.stop();
    let _ = running.wait().await;
    Ok(())
}

#[tokio::test]
async fn flux_obfs_rejects_wrong_server_key_and_udp_tamper() -> Result<()> {
    let (srv_priv, srv_pub) = generate_flux_x25519_keypair()?;
    let (_, wrong_pub) = generate_flux_x25519_keypair()?;
    let core = ProxyCore::new(vec![CoreUser::password("u1", "secret-user")])?;
    let srv = start_flux_server_with_core(
        FluxServerConfig {
            key: String::new(),
            users: Vec::new(),
            udp: true,
            listeners: vec![
                FluxChannelServerConfig {
                    id: "tcp-obfs".into(),
                    listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ports: vec![0],
                    transport: FluxTransportKind::Tcp,
                    http_mode: FluxHttpMode::Ws,
                    http_host: None,
                    http_path: "/".into(),
                    http_headers: BTreeMap::new(),
                    security: FluxSecurityMode::Obfs,
                    cert_mode: FluxCertMode::Inherit,
                    tls_material: None,
                    private_key: Some(srv_priv.clone()),
                },
                FluxChannelServerConfig {
                    id: "udp-obfs".into(),
                    listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ports: vec![0],
                    transport: FluxTransportKind::Udp,
                    http_mode: FluxHttpMode::Ws,
                    http_host: None,
                    http_path: "/".into(),
                    http_headers: BTreeMap::new(),
                    security: FluxSecurityMode::Obfs,
                    cert_mode: FluxCertMode::Inherit,
                    tls_material: None,
                    private_key: Some(srv_priv),
                },
            ],
        },
        core,
    )?;
    let tcp_addr = srv.tcp_addrs()[0];
    let udp_addr = srv.udp_addrs()[0];

    let bad_tcp = transport::connect_client_channel(
        &FluxChannelClientConfig {
            id: "tcp-bad".into(),
            server_host: "127.0.0.1".into(),
            ports: vec![tcp_addr.port()],
            ip_version: "ipv4".into(),
            resolved_v4: Vec::new(),
            resolved_v6: Vec::new(),
            transport: FluxTransportKind::Tcp,
            http_mode: FluxHttpMode::Ws,
            http_host: None,
            http_path: "/".into(),
            http_headers: BTreeMap::new(),
            security: FluxSecurityMode::Obfs,
            sni: "localhost".into(),
            alpn: Vec::new(),
            fingerprint: None,
            insecure: false,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            pinned_cert_sha256: Vec::new(),
            public_key: Some(wrong_pub.clone()),
            tls_binding: false,
            role: FluxChannelRole::Primary,
            weight: 100,
        },
        tcp_addr,
    )
    .await;
    assert!(
        bad_tcp.is_err(),
        "wrong X25519 public key must fail TCP obfs handshake"
    );

    // Valid public key on UDP succeeds, wrong key is dropped silently until timeout
    let good_udp = tokio::time::timeout(
        Duration::from_secs(3),
        transport::connect_client_channel(
            &FluxChannelClientConfig {
                id: "udp-good".into(),
                server_host: "127.0.0.1".into(),
                ports: vec![udp_addr.port()],
                ip_version: "ipv4".into(),
                resolved_v4: Vec::new(),
                resolved_v6: Vec::new(),
                transport: FluxTransportKind::Udp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".into(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                sni: "localhost".into(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                public_key: Some(srv_pub),
                tls_binding: false,
                role: FluxChannelRole::Primary,
                weight: 100,
            },
            udp_addr,
        ),
    )
    .await?;
    assert!(good_udp.is_ok());

    let bad_udp = tokio::time::timeout(
        Duration::from_millis(600),
        transport::connect_client_channel(
            &FluxChannelClientConfig {
                id: "udp-bad".into(),
                server_host: "127.0.0.1".into(),
                ports: vec![udp_addr.port()],
                ip_version: "ipv4".into(),
                resolved_v4: Vec::new(),
                resolved_v6: Vec::new(),
                transport: FluxTransportKind::Udp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".into(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                sni: "localhost".into(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                public_key: Some(wrong_pub),
                tls_binding: false,
                role: FluxChannelRole::Primary,
                weight: 100,
            },
            udp_addr,
        ),
    )
    .await;
    assert!(
        bad_udp.is_err(),
        "wrong X25519 public key must be silently dropped on UDP"
    );

    srv.stop();
    let _ = srv.wait().await;
    Ok(())
}

#[tokio::test]
async fn flux_muxes_under_speed_budget_and_scales_out_parallel_channels_on_overflow() -> Result<()>
{
    let (tcp_priv, tcp_pub) = generate_flux_x25519_keypair()?;

    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    let Ok(n) = s.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        let _ = s.shutdown().await;
                        break;
                    }
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let core = ProxyCore::new(vec![
        CoreUser::password("u-mux", "mux-secret"),
        CoreUser::password("u-scale", "scale-secret"),
    ])?;
    let srv = start_flux_server_with_core(
        FluxServerConfig {
            key: String::new(),
            users: Vec::new(),
            udp: false,
            listeners: vec![FluxChannelServerConfig {
                id: "tcp-obfs".into(),
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ports: vec![0],
                transport: FluxTransportKind::Tcp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".into(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Obfs,
                cert_mode: FluxCertMode::Inherit,
                tls_material: None,
                private_key: Some(tcp_priv),
            }],
        },
        core.clone(),
    )?;
    let srv_port = srv.tcp_addrs()[0].port();

    let make_channel = || FluxChannelClientConfig {
        id: "tcp-obfs".into(),
        server_host: "127.0.0.1".into(),
        ports: vec![srv_port],
        ip_version: "ipv4".into(),
        resolved_v4: Vec::new(),
        resolved_v6: Vec::new(),
        transport: FluxTransportKind::Tcp,
        http_mode: FluxHttpMode::Ws,
        http_host: None,
        http_path: "/".into(),
        http_headers: BTreeMap::new(),
        security: FluxSecurityMode::Obfs,
        sni: "localhost".into(),
        alpn: Vec::new(),
        fingerprint: None,
        insecure: false,
        ca_cert_paths: Vec::new(),
        ca_certificates: Vec::new(),
        pinned_cert_sha256: Vec::new(),
        public_key: Some(tcp_pub.clone()),
        tls_binding: false,
        role: FluxChannelRole::Primary,
        weight: 100,
    };

    // 1. Under-budget mux packing: 4 concurrent low-speed streams stay muxed on 1 outer channel
    let mux_socks = TcpListener::bind("127.0.0.1:0").await?;
    let mux_socks_addr = mux_socks.local_addr()?;
    let mux_pool = FluxClientPool::new(FluxClientConfig {
        listen: mux_socks_addr,
        server_host: "127.0.0.1".into(),
        server_port: srv_port,
        key: "mux-secret".into(),
        udp: false,
        options: FluxOptions {
            ip_strategy: FluxIpStrategy::Dual,
            standby_channels: 2,
            channel_max_mbps: 50,
            rotation_interval_sec: 300,
            rotation_bytes_mb: 128,
        },
        channels: vec![make_channel()],
    })?;
    let mux_stop = ListenerStopToken::new();
    let mux_stop_bg = mux_stop.clone();
    let mux_pool_bg = mux_pool.clone();
    let mux_task = tokio::spawn(async move {
        client::run_flux_client_listener_with_pool_until(mux_socks, mux_pool_bg, None, mux_stop_bg)
            .await
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(mux_pool.usable_channels().len(), 3);

    let mut open_streams = Vec::new();
    for idx in 0..4u8 {
        let mut s = socks::connect_tcp(mux_socks_addr, &ProxyTarget::Ip(echo_addr)).await?;
        let payload = vec![0x20 + idx; 4096];
        s.write_all(&payload).await?;
        let mut echoed = vec![0u8; payload.len()];
        s.read_exact(&mut echoed).await?;
        assert_eq!(echoed, payload);
        open_streams.push(s);
    }

    let mux_channels = mux_pool.usable_channels();
    let active_carriers = mux_channels
        .iter()
        .filter(|ch| ch.active_stream_count() > 0)
        .collect::<Vec<_>>();
    assert_eq!(
        active_carriers.len(),
        1,
        "expected all 4 low-speed streams muxed on 1 outer channel"
    );
    assert_eq!(active_carriers[0].active_stream_count(), 4);
    assert_eq!(
        mux_channels
            .iter()
            .filter(|ch| ch.total_bytes_transferred() > 0)
            .count(),
        1
    );

    for mut s in open_streams {
        let _ = s.shutdown().await;
    }
    mux_stop.stop();
    let _ = mux_task.await;

    // 2. Overflow & simultaneous burst rebalance: 3 streams exceeding 1 Mbps scale out & split
    let scale_socks = TcpListener::bind("127.0.0.1:0").await?;
    let scale_socks_addr = scale_socks.local_addr()?;
    let scale_pool = FluxClientPool::new(FluxClientConfig {
        listen: scale_socks_addr,
        server_host: "127.0.0.1".into(),
        server_port: srv_port,
        key: "scale-secret".into(),
        udp: false,
        options: FluxOptions {
            ip_strategy: FluxIpStrategy::Dual,
            standby_channels: 0,
            channel_max_mbps: 1,
            rotation_interval_sec: 300,
            rotation_bytes_mb: 128,
        },
        channels: vec![make_channel()],
    })?;
    let scale_stop = ListenerStopToken::new();
    let scale_stop_bg = scale_stop.clone();
    let scale_pool_bg = scale_pool.clone();
    let scale_task = tokio::spawn(async move {
        client::run_flux_client_listener_with_pool_until(
            scale_socks,
            scale_pool_bg,
            None,
            scale_stop_bg,
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(scale_pool.usable_channels().len(), 1);

    let mut workers = tokio::task::JoinSet::new();
    for stream_idx in 0..3u8 {
        workers.spawn(async move {
            let mut s = socks::connect_tcp(scale_socks_addr, &ProxyTarget::Ip(echo_addr)).await?;
            let chunk = vec![0xA0 + stream_idx; 16 * 1024];
            let mut recv_buf = vec![0u8; chunk.len()];
            for _ in 0..14 {
                s.write_all(&chunk).await?;
                s.read_exact(&mut recv_buf).await?;
                assert_eq!(recv_buf, chunk);
                tokio::time::sleep(Duration::from_millis(75)).await;
            }
            s.shutdown().await?;
            Result::<()>::Ok(())
        });
    }
    while let Some(joined) = workers.join_next().await {
        joined??;
    }

    let scaled_channels = scale_pool.usable_channels();
    assert!(
        scaled_channels.len() >= 2,
        "expected pool to auto-scale beyond 1 channel under >1 Mbps load, got {}",
        scaled_channels.len()
    );
    let carrying_channels = scaled_channels
        .iter()
        .filter(|ch| ch.total_bytes_transferred() > 0)
        .count();
    assert!(
        carrying_channels >= 2,
        "expected simultaneous streams exceeding 1 Mbps to rebalance across >=2 outer channels, got {carrying_channels}"
    );

    scale_stop.stop();
    let _ = scale_task.await;
    srv.stop();
    let _ = srv.wait().await;
    Ok(())
}

#[tokio::test]
async fn flux_origin_plain_http_works_with_tls_binding_disabled() -> Result<()> {
    let core = ProxyCore::new(vec![CoreUser::password("u1", "origin-secret")])?;
    let srv = start_flux_server_with_core(
        FluxServerConfig {
            key: String::new(),
            users: Vec::new(),
            udp: false,
            listeners: vec![FluxChannelServerConfig {
                id: "ws-origin-plain".into(),
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ports: vec![0],
                transport: FluxTransportKind::Http,
                http_mode: FluxHttpMode::Ws,
                http_host: Some("cdn.example.com".into()),
                http_path: "/ws".into(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Tls,
                cert_mode: FluxCertMode::OriginPlain,
                tls_material: None,
                private_key: None,
            }],
        },
        core,
    )?;
    let port = srv.tcp_addrs()[0].port();
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    tokio::spawn(async move {
        if let Ok((mut s, _)) = target.accept().await {
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });

    // Direct HTTP connection against OriginPlain (simulating CDN -> Origin) with tls_binding=false
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let boxed = crate::vless_transport::apply_client_transport(
        tcp,
        &crate::vless_transport::VlessTransportConfig::websocket(
            Some("/ws".into()),
            Some("cdn.example.com".into()),
            Vec::new(),
        ),
        "127.0.0.1",
    )
    .await?;
    let (mut reader, mut writer, _) = transport::split_boxed_stream_with_binding(boxed, None);
    let cred_hash = crate::protocol::password_hash("origin-secret");
    let session_id = [4u8; 16];
    let ephemeral = [5u8; 32];
    let blind_key = auth::derive_blind_key(&[0; 32], &session_id, &ephemeral)?;
    let auth_key = auth::handshake_key(&blind_key, &cred_hash, &[0; 32])?;
    let mut hello = frame::FluxFrame::SessionHello {
        session_id,
        client_ephemeral_pub: ephemeral,
        timestamp_secs: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        channel_id: "ws-origin-plain".into(),
        blinded_credential: auth::xor_32(&cred_hash, &blind_key),
        client_proof: [0; 32],
    };
    let proof = auth::client_proof(&auth_key, &hello)?;
    if let frame::FluxFrame::SessionHello { client_proof, .. } = &mut hello {
        *client_proof = proof;
    }
    writer.write_frame(&hello, true).await?;
    let ok = reader.read_frame().await?;
    assert!(matches!(
        ok,
        Some(frame::FluxFrame::SessionOk { status: 0, .. })
    ));
    let _ = target_addr;

    srv.stop();
    let _ = srv.wait().await;
    Ok(())
}
