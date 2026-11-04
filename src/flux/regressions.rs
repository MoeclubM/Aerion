use super::*;
use crate::core::{CoreUser, ProxyCore};
use crate::listener::ListenerStopToken;
use crate::protocol::ProxyTarget;
use anyhow::Result;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinSet;

fn server_config() -> FluxServerConfig {
    FluxServerConfig {
        key: "user-token".into(),
        users: vec![],
        udp: true,
        listeners: vec![FluxChannelServerConfig {
            id: "test".into(),
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
            reality: None,
            reality_fallback: None,
            obfs_key: Some("channel-shared-key".into()),
        }],
    }
}

fn client_config(ports: Vec<u16>) -> Result<FluxClientConfig> {
    let proxy: crate::config_compat::mihomo::MihomoFluxProxy = serde_json::from_value(
        serde_json::json!({
            "name": "Flux", "server": "127.0.0.1", "port": ports[0],
            "key": "user-token", "security": "obfs", "obfs-key": "channel-shared-key",
            "standby-channels": ports.len() - 1, "rotation-interval-sec": 0, "rotation-bytes-mb": 0,
            "channels": ports.into_iter().enumerate().map(|(i, port)| serde_json::json!({
                "id": format!("channel-{i}"), "ports": port, "transport": "tcp",
                "weight": if i == 0 { 100 } else { 1 }, "role": if i == 0 { "primary" } else { "backup" },
            })).collect::<Vec<_>>()
        }),
    )?;
    proxy.to_client_config("127.0.0.1:0".parse()?)
}

async fn middlebox(
    listener: TcpListener,
    upstream: std::net::SocketAddr,
    blackhole: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((client, _)) = accepted else { return; };
                let blackhole = blackhole.clone();
                let active = active.clone();
                tasks.spawn(async move {
                    struct Count(Arc<AtomicUsize>);
                    impl Drop for Count { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); } }
                    let Ok(server) = TcpStream::connect(upstream).await else { return; };
                    active.fetch_add(1, Ordering::SeqCst);
                    let _count = Count(active);
                    let (cr, cw) = client.into_split();
                    let (sr, sw) = server.into_split();
                    async fn copy(mut r: tokio::net::tcp::OwnedReadHalf, mut w: tokio::net::tcp::OwnedWriteHalf, drop: Arc<AtomicBool>) {
                        let mut buf = [0u8; 16384];
                        loop {
                            let Ok(n) = r.read(&mut buf).await else { return; };
                            if n == 0 { return; }
                            if !drop.load(Ordering::Acquire) && w.write_all(&buf[..n]).await.is_err() { return; }
                        }
                    }
                    tokio::select! {
                        _ = copy(cr, sw, blackhole.clone()) => {},
                        _ = copy(sr, cw, blackhole) => {},
                    }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
}

#[tokio::test]
async fn download_only_blackhole_migrates_and_listener_abort_closes_channels() -> Result<()> {
    let config = server_config();
    let core = ProxyCore::new(vec![CoreUser::password("u", "user-token")])?;
    let server = start_flux_server_with_core(config, core)?;
    let server_addr = server.tcp_addrs()[0];
    let relay = TcpListener::bind("127.0.0.1:0").await?;
    let relay_port = relay.local_addr()?.port();
    let blackhole = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));
    let relay_task = tokio::spawn(middlebox(
        relay,
        server_addr,
        blackhole.clone(),
        active.clone(),
    ));
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target.local_addr()?;
    let begin = Arc::new(Notify::new());
    let writer_begin = begin.clone();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await?;
        socket.write_all(b"ready").await?;
        writer_begin.notified().await;
        socket.write_all(&vec![0x5a; 1024 * 1024]).await?;
        anyhow::Ok(())
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let config = client_config(vec![relay_port, server_addr.port()])?;
    let client_task = tokio::spawn(run_flux_client_listener(listener, config));
    let mut stream = crate::socks::connect_tcp(addr, &ProxyTarget::Ip(target_addr)).await?;
    let mut banner = [0; 5];
    stream.read_exact(&mut banner).await?;
    assert_eq!(&banner, b"ready");
    tokio::time::sleep(Duration::from_millis(200)).await;
    blackhole.store(true, Ordering::Release);
    begin.notify_one();
    let mut payload = vec![0; 1024 * 1024];
    tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut payload)).await??;
    assert!(payload.iter().all(|byte| *byte == 0x5a));
    client_task.abort();
    let _ = client_task.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while active.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    relay_task.abort();
    target_task.await??;
    server.stop();
    server.wait().await?;
    Ok(())
}

#[tokio::test]
async fn replacing_listeners_preserves_the_target_connection() -> Result<()> {
    for transport in [FluxTransportKind::Tcp, FluxTransportKind::Udp] {
        let core = ProxyCore::new(vec![CoreUser::password("u", "user-token")])?;
        let state = FluxServerState::new(core, true);
        let stop = ListenerStopToken::new();
        let mut config = server_config();
        config.listeners[0].transport = transport;
        let server = start_flux_server_with_state(config.clone(), &state, stop.clone())?;
        let port = if transport == FluxTransportKind::Udp {
            server.udp_addrs()[0].port()
        } else {
            server.tcp_addrs()[0].port()
        };
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let target_addr = target.local_addr()?;
        let target_task = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await?;
            let (mut r, mut w) = socket.split();
            tokio::io::copy(&mut r, &mut w).await
        });
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let mut client_config = client_config(vec![port])?;
        client_config.channels[0].transport = transport;
        let client = tokio::spawn(run_flux_client_listener(listener, client_config));
        let mut stream = crate::socks::connect_tcp(addr, &ProxyTarget::Ip(target_addr)).await?;
        stream.write_all(b"before").await?;
        let mut response = [0; 6];
        stream.read_exact(&mut response).await?;
        stop.stop();
        server.wait().await?;
        config.listeners[0].ports = vec![port];
        let replacement = start_flux_server_with_state(config, &state, ListenerStopToken::new())?;
        stream.write_all(b"after!").await?;
        tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut response)).await??;
        assert_eq!(&response, b"after!");
        client.abort();
        let _ = client.await;
        target_task.abort();
        replacement.stop();
        replacement.wait().await?;
    }
    Ok(())
}

#[test]
fn handshake_proofs_require_secret_and_channel_binding() -> Result<()> {
    let credential = [7; 32];
    let blind = [9; 32];
    let binding = [11; 32];
    let key = auth::handshake_key(&blind, &credential, &binding)?;
    let mut hello = frame::FluxFrame::SessionHello {
        session_id: [1; 16],
        client_ephemeral_pub: [2; 32],
        timestamp_secs: 10,
        channel_id: "quic".into(),
        blinded_credential: auth::xor_32(&blind, &credential),
        client_proof: [0; 32],
    };
    let proof = auth::client_proof(&key, &hello)?;
    if let frame::FluxFrame::SessionHello { client_proof, .. } = &mut hello {
        *client_proof = proof;
    }
    let server = auth::server_proof(&key, &hello, true)?;
    assert_ne!(
        server,
        auth::server_proof(&auth::xor_32(&blind, &credential), &hello, true)?
    );
    let other = auth::handshake_key(&blind, &credential, &[12; 32])?;
    assert_ne!(server, auth::server_proof(&other, &hello, true)?);
    assert_ne!(server, auth::server_proof(&key, &hello, false)?);
    if let frame::FluxFrame::SessionHello { timestamp_secs, .. } = &mut hello {
        *timestamp_secs += 1;
    }
    assert_ne!(proof, auth::client_proof(&key, &hello)?);
    Ok(())
}
