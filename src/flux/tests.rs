use super::*;
use crate::core::{CoreUser, ProxyCore};
use crate::listener::ListenerStopToken;
use crate::protocol::ProxyTarget;
use crate::reality::{RealityClientConfig, RealityServerConfig};
use crate::{MihomoClientConfig, MihomoConfig, socks, uot};
use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use x25519_dalek::{PublicKey, StaticSecret};

fn make_reality_keypair() -> ([u8; 32], String, String) {
    let priv_bytes = [0x42u8; 32];
    let secret = StaticSecret::from(priv_bytes);
    let pub_bytes = PublicKey::from(&secret).to_bytes();
    (
        priv_bytes,
        URL_SAFE_NO_PAD.encode(priv_bytes),
        URL_SAFE_NO_PAD.encode(pub_bytes),
    )
}

#[test]
fn flux_mihomo_yaml_parses_default_and_manual_channels() -> Result<()> {
    let (_, _, pub_b64) = make_reality_keypair();
    let yaml = format!(
        r#"
proxies:
  - name: FluxAuto
    type: flux
    server: edge.example.com
    port: 443
    key: user-secret-token
    servername: www.microsoft.com
    reality-opts:
      public-key: {pub_b64}
      short-id: 01020304
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
    rotation-interval-sec: 120
    rotation-bytes-mb: 64
    reality-opts:
      public-key: {pub_b64}
      short-id: aabbccdd
    channels:
      - id: reality-v4
        transport: tcp
        ports: "443"
        ip-version: ipv4
        sni: www.microsoft.com
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
        obfs-key: obfs-channel-secret
        role: backup
        weight: 60
"#
    );

    let cfg: MihomoConfig = serde_yaml::from_str(&yaml)?;
    let listen: SocketAddr = "127.0.0.1:1080".parse()?;

    let MihomoClientConfig::Flux(auto_cfg) = cfg.resolved_proxy_config("FluxAuto", listen)? else {
        panic!("expected Flux client config for FluxAuto");
    };
    assert_eq!(auto_cfg.channels.len(), 2);
    assert_eq!(auto_cfg.channels[0].transport, FluxTransportKind::Tcp);
    assert_eq!(auto_cfg.channels[1].transport, FluxTransportKind::Udp);
    assert_eq!(
        auto_cfg.channels[0].resolved_v4,
        vec![Ipv4Addr::new(203, 0, 113, 10)]
    );
    assert_eq!(auto_cfg.all_static_ips().len(), 2);

    let MihomoClientConfig::Flux(manual_cfg) = cfg.resolved_proxy_config("FluxManual", listen)?
    else {
        panic!("expected Flux client config for FluxManual");
    };
    assert_eq!(manual_cfg.options.standby_channels, 3);
    assert_eq!(manual_cfg.channels.len(), 3);
    assert_eq!(manual_cfg.channels[1].transport, FluxTransportKind::Http);
    assert_eq!(manual_cfg.channels[1].http_mode, FluxHttpMode::Ws);
    assert_eq!(manual_cfg.channels[1].http_path, "/flux-ws");
    assert_eq!(manual_cfg.channels[2].ports, vec![21000, 21001, 21002]);
    assert_eq!(manual_cfg.channels[2].security, FluxSecurityMode::Obfs);
    assert_eq!(manual_cfg.channels[2].role, FluxChannelRole::Backup);

    let oversized = parse_port_spec("10000-10100", MAX_FLUX_EXPANDED_PORTS);
    assert!(oversized.is_err());
    Ok(())
}

#[tokio::test]
async fn flux_multi_channel_shares_single_core_session_and_relays_tcp_udp() -> Result<()> {
    let (_, priv_b64, pub_b64) = make_reality_keypair();
    let short_id = "0102030405060708";

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

    let reality_srv = RealityServerConfig::from_strings(
        "www.example.com",
        443,
        vec!["www.example.com".to_string()],
        &priv_b64,
        &[short_id.to_string()],
        Vec::new(),
    )?;

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
                id: "srv-tcp-reality".to_string(),
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ports: vec![0],
                transport: FluxTransportKind::Tcp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Reality,
                cert_mode: FluxCertMode::Inherit,
                tls_material: None,
                reality: Some(reality_srv.clone()),
                reality_fallback: Some(false),
                obfs_key: None,
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
                reality: None,
                reality_fallback: None,
                obfs_key: Some("flux-obfs-shared-secret".to_string()),
            },
            FluxChannelServerConfig {
                id: "srv-quic-reality".to_string(),
                listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ports: vec![0],
                transport: FluxTransportKind::Udp,
                http_mode: FluxHttpMode::Ws,
                http_host: None,
                http_path: "/".to_string(),
                http_headers: BTreeMap::new(),
                security: FluxSecurityMode::Reality,
                cert_mode: FluxCertMode::Inherit,
                tls_material: None,
                reality: Some(reality_srv),
                reality_fallback: Some(false),
                obfs_key: None,
            },
        ],
    };

    let running_srv = start_flux_server_with_core(server_cfg, core.clone())?;
    let tcp_port = running_srv.tcp_addrs()[0].port();
    let ws_port = running_srv.tcp_addrs()[1].port();
    let quic_port = running_srv.udp_addrs()[0].port();

    let reality_cli = RealityClientConfig::from_strings(&pub_b64, short_id)?;
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
            rotation_interval_sec: 180,
            rotation_bytes_mb: 96,
        },
        channels: vec![
            FluxChannelClientConfig {
                id: "c-tcp-reality".to_string(),
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
                security: FluxSecurityMode::Reality,
                sni: "www.example.com".to_string(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                reality: Some(reality_cli.clone()),
                obfs_key: None,
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
                reality: None,
                obfs_key: Some("flux-obfs-shared-secret".to_string()),
                role: FluxChannelRole::Primary,
                weight: 90,
            },
            FluxChannelClientConfig {
                id: "c-quic-reality".to_string(),
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
                security: FluxSecurityMode::Reality,
                sni: "www.example.com".to_string(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                reality: Some(reality_cli),
                obfs_key: None,
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
    let (_, priv_b64, pub_b64) = make_reality_keypair();
    let short_id = "a1b2c3d4";

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

    let reality_srv = RealityServerConfig::from_strings(
        "www.example.com",
        443,
        vec!["www.example.com".to_string()],
        &priv_b64,
        &[short_id.to_string()],
        Vec::new(),
    )?;
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
                security: FluxSecurityMode::Reality,
                cert_mode: FluxCertMode::Inherit,
                tls_material: None,
                reality: Some(reality_srv),
                reality_fallback: Some(false),
                obfs_key: None,
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
                reality: None,
                reality_fallback: None,
                obfs_key: Some("backup-quic-obfs-key".to_string()),
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

    let reality_cli = RealityClientConfig::from_strings(&pub_b64, short_id)?;
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
                security: FluxSecurityMode::Reality,
                sni: "www.example.com".to_string(),
                alpn: Vec::new(),
                fingerprint: None,
                insecure: false,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                pinned_cert_sha256: Vec::new(),
                reality: Some(reality_cli),
                obfs_key: None,
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
                reality: None,
                obfs_key: Some("backup-quic-obfs-key".to_string()),
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
async fn flux_reality_tcp_and_udp_fallback_forwards_unauthenticated_probes() -> Result<()> {
    let (_, priv_b64, _) = make_reality_keypair();

    // Mock borrowed TCP origin server
    let origin_tcp = TcpListener::bind("127.0.0.1:0").await?;
    let origin_tcp_port = origin_tcp.local_addr()?.port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = origin_tcp.accept().await {
            let mut req = [0u8; 64];
            let _ = s.read(&mut req).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nBORROWED-ORIGIN")
                .await;
            let _ = s.shutdown().await;
        }
    });

    // Mock borrowed UDP/H3 origin server
    let origin_udp = UdpSocket::bind("127.0.0.1:0").await?;
    let origin_udp_port = origin_udp.local_addr()?.port();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        if let Ok((_, peer)) = origin_udp.recv_from(&mut buf).await {
            let _ = origin_udp.send_to(b"BORROWED-H3-UDP", peer).await;
        }
    });

    let tcp_reality = RealityServerConfig::from_strings(
        "127.0.0.1",
        origin_tcp_port,
        vec!["127.0.0.1".to_string()],
        &priv_b64,
        &["01020304".to_string()],
        Vec::new(),
    )?;
    let udp_reality = RealityServerConfig::from_strings(
        "127.0.0.1",
        origin_udp_port,
        vec!["127.0.0.1".to_string()],
        &priv_b64,
        &["01020304".to_string()],
        Vec::new(),
    )?;

    let core = ProxyCore::new(vec![CoreUser::password("u1", "secret")])?;
    let running = start_flux_server_with_core(
        FluxServerConfig {
            key: String::new(),
            users: Vec::new(),
            udp: true,
            listeners: vec![
                FluxChannelServerConfig {
                    id: "tcp-fb".to_string(),
                    listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ports: vec![0],
                    transport: FluxTransportKind::Tcp,
                    http_mode: FluxHttpMode::Ws,
                    http_host: None,
                    http_path: "/".to_string(),
                    http_headers: BTreeMap::new(),
                    security: FluxSecurityMode::Reality,
                    cert_mode: FluxCertMode::Inherit,
                    tls_material: None,
                    reality: Some(tcp_reality),
                    reality_fallback: Some(true),
                    obfs_key: None,
                },
                FluxChannelServerConfig {
                    id: "udp-fb".to_string(),
                    listen_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ports: vec![0],
                    transport: FluxTransportKind::Udp,
                    http_mode: FluxHttpMode::Ws,
                    http_host: None,
                    http_path: "/".to_string(),
                    http_headers: BTreeMap::new(),
                    security: FluxSecurityMode::Reality,
                    cert_mode: FluxCertMode::Inherit,
                    tls_material: None,
                    reality: Some(udp_reality),
                    reality_fallback: Some(true),
                    obfs_key: None,
                },
            ],
        },
        core,
    )?;

    // 1. Unauthenticated TCP HTTP probe -> forwarded to origin_tcp
    let mut probe_tcp = TcpStream::connect(running.tcp_addrs()[0]).await?;
    probe_tcp
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await?;
    let mut resp = Vec::new();
    probe_tcp.read_to_end(&mut resp).await?;
    assert!(
        String::from_utf8_lossy(&resp).contains("BORROWED-ORIGIN"),
        "unexpected TCP fallback response: {:?}",
        String::from_utf8_lossy(&resp)
    );

    // 2. Unauthenticated UDP probe -> forwarded to origin_udp
    let probe_udp = UdpSocket::bind("127.0.0.1:0").await?;
    probe_udp
        .send_to(b"unauthenticated-quic-probe-bytes", running.udp_addrs()[0])
        .await?;
    let mut udp_resp = [0u8; 256];
    let (n, _) =
        tokio::time::timeout(Duration::from_secs(5), probe_udp.recv_from(&mut udp_resp)).await??;
    assert_eq!(&udp_resp[..n], b"BORROWED-H3-UDP");

    running.stop();
    let _ = running.wait().await;
    Ok(())
}
