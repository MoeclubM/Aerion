use crate::protocol::{ProxyTarget, target_name};
use crate::routing::{RouteDecision, RouteNetwork, RouteTable};
use crate::socket_protect;
use crate::socks::{self, SocksRequest};
use crate::uot;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct RouteProxyConfig {
    pub routes: RouteTable,
    pub upstreams: BTreeMap<String, SocketAddr>,
}

struct UdpCommand {
    target: ProxyTarget,
    payload: Vec<u8>,
    peer: SocketAddr,
}

pub async fn run_route_proxy(listener: TcpListener, config: RouteProxyConfig) -> Result<()> {
    let routes = Arc::new(config.routes);
    let upstreams = Arc::new(config.upstreams);
    tracing::info!(
        "route proxy listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = listener.accept().await.context("accept route client")?;
        let routes = routes.clone();
        let upstreams = upstreams.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_route_client(stream, routes, upstreams).await {
                tracing::warn!("route client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_route_client(
    mut local: TcpStream,
    routes: Arc<RouteTable>,
    upstreams: Arc<BTreeMap<String, SocketAddr>>,
) -> Result<()> {
    match socks::read_request(&mut local).await? {
        SocksRequest::Connect(target) => {
            let decision = routes.decide(&target, RouteNetwork::Tcp);
            match decision {
                RouteDecision::Direct => {
                    let mut remote = match connect_direct(&target).await {
                        Ok(remote) => remote,
                        Err(error) => {
                            let _ = socks::write_reply(&mut local, 0x01).await;
                            return Err(error);
                        }
                    };
                    socks::write_reply(&mut local, 0x00).await?;
                    tracing::info!("routing {} direct", target_name(&target));
                    copy_bidirectional(&mut local, &mut remote)
                        .await
                        .context("relay direct route")?;
                    Ok(())
                }
                RouteDecision::Block => {
                    socks::write_reply(&mut local, 0x02).await?;
                    bail!("route blocked {}", target_name(&target))
                }
                RouteDecision::Proxy(tag) => {
                    let upstream = *upstreams
                        .get(&tag)
                        .with_context(|| format!("route outbound {tag} was not started"))?;
                    let mut remote = match socks::connect_tcp(upstream, &target).await {
                        Ok(remote) => remote,
                        Err(error) => {
                            let _ = socks::write_reply(&mut local, 0x05).await;
                            return Err(error);
                        }
                    };
                    socks::write_reply(&mut local, 0x00).await?;
                    tracing::info!("routing {} via {tag}", target_name(&target));
                    copy_bidirectional(&mut local, &mut remote)
                        .await
                        .with_context(|| format!("relay route via {tag}"))?;
                    Ok(())
                }
            }
        }
        SocksRequest::UdpAssociate => handle_udp_associate(local, routes, upstreams).await,
    }
}

async fn connect_direct(target: &ProxyTarget) -> Result<TcpStream> {
    match target {
        ProxyTarget::Ip(addr) => socket_protect::connect_tcp_addr(*addr).await,
        ProxyTarget::Domain(host, port) => socket_protect::connect_tcp_host_port(host, *port).await,
    }
}

async fn handle_udp_associate(
    mut control: TcpStream,
    routes: Arc<RouteTable>,
    upstreams: Arc<BTreeMap<String, SocketAddr>>,
) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("bind route UDP associate socket on {bind_ip}:0"))?,
    );
    socks::write_reply_with_bind(&mut control, 0x00, udp.local_addr()?).await?;
    tracing::info!("route UDP associate listening on {}", udp.local_addr()?);

    let mut sessions = BTreeMap::<String, mpsc::Sender<UdpCommand>>::new();
    let mut packet = vec![0u8; u16::MAX as usize + 512];
    let mut control_probe = [0u8; 1];
    loop {
        tokio::select! {
            received = udp.recv_from(&mut packet) => {
                let (read, peer) = received.context("receive route UDP packet")?;
                let (target, payload) = uot::parse_socks_udp_packet(&packet[..read])?;
                match routes.decide(&target, RouteNetwork::Udp) {
                    RouteDecision::Direct => {
                        let key = format!("direct:{}", target_name(&target));
                        let tx = sessions.entry(key).or_insert_with(|| {
                            spawn_direct_udp_session(target.clone(), udp.clone())
                        }).clone();
                        tx.send(UdpCommand {
                            target,
                            payload: payload.to_vec(),
                            peer,
                        }).await.context("send direct UDP route command")?;
                    }
                    RouteDecision::Block => {
                        tracing::info!("blocking UDP {}", target_name(&target));
                    }
                    RouteDecision::Proxy(tag) => {
                        let upstream = *upstreams
                            .get(&tag)
                            .with_context(|| format!("route UDP outbound {tag} was not started"))?;
                        let tx = sessions.entry(format!("proxy:{tag}")).or_insert_with(|| {
                            spawn_proxy_udp_session(tag.clone(), upstream, udp.clone())
                        }).clone();
                        tx.send(UdpCommand {
                            target,
                            payload: payload.to_vec(),
                            peer,
                        }).await.with_context(|| format!("send UDP route command to {tag}"))?;
                    }
                }
            }
            read = control.read(&mut control_probe) => {
                if read.context("read route UDP control connection")? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

fn spawn_direct_udp_session(
    target: ProxyTarget,
    client_udp: Arc<UdpSocket>,
) -> mpsc::Sender<UdpCommand> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(error) = run_direct_udp_session(target, rx, client_udp).await {
            tracing::warn!("direct UDP route session failed: {error:?}");
        }
    });
    tx
}

fn spawn_proxy_udp_session(
    tag: String,
    upstream: SocketAddr,
    client_udp: Arc<UdpSocket>,
) -> mpsc::Sender<UdpCommand> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(error) = run_proxy_udp_session(&tag, upstream, rx, client_udp).await {
            tracing::warn!("proxy UDP route session {tag} failed: {error:?}");
        }
    });
    tx
}

async fn run_direct_udp_session(
    target: ProxyTarget,
    mut rx: mpsc::Receiver<UdpCommand>,
    client_udp: Arc<UdpSocket>,
) -> Result<()> {
    let remote = resolve_udp_target(&target).await?;
    let bind = if remote.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = socket_protect::bind_udp(bind).await?;
    let mut peer = None;
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        tokio::select! {
            command = rx.recv() => {
                let Some(command) = command else {
                    return Ok(());
                };
                peer = Some(command.peer);
                socket.send_to(&command.payload, remote)
                    .await
                    .with_context(|| format!("send direct UDP {}", target_name(&command.target)))?;
            }
            received = socket.recv_from(&mut buffer) => {
                let (read, source) = received.context("receive direct UDP response")?;
                let response = uot::encode_socks_udp_packet(
                    &ProxyTarget::Ip(source),
                    &buffer[..read],
                )?;
                let peer = peer.context("route UDP client peer is not known yet")?;
                client_udp.send_to(&response, peer)
                    .await
                    .with_context(|| format!("send direct UDP response to {peer}"))?;
            }
        }
    }
}

async fn run_proxy_udp_session(
    tag: &str,
    upstream: SocketAddr,
    mut rx: mpsc::Receiver<UdpCommand>,
    client_udp: Arc<UdpSocket>,
) -> Result<()> {
    let association = socks::udp_associate(upstream).await?;
    let _control = association.control;
    let socket = association.udp;
    let bind = association.bind;
    let mut peer = None;
    let mut buffer = vec![0u8; u16::MAX as usize + 512];
    loop {
        tokio::select! {
            command = rx.recv() => {
                let Some(command) = command else {
                    return Ok(());
                };
                peer = Some(command.peer);
                let packet = uot::encode_socks_udp_packet(&command.target, &command.payload)?;
                socket.send_to(&packet, bind)
                    .await
                    .with_context(|| format!("send UDP route via {tag}"))?;
            }
            received = socket.recv_from(&mut buffer) => {
                let (read, _) = received.with_context(|| format!("receive UDP route via {tag}"))?;
                let (source, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let response = uot::encode_socks_udp_packet(&source, payload)?;
                let peer = peer.context("route UDP client peer is not known yet")?;
                client_udp.send_to(&response, peer)
                    .await
                    .with_context(|| format!("send UDP route response to {peer}"))?;
            }
        }
    }
}

async fn resolve_udp_target(target: &ProxyTarget) -> Result<SocketAddr> {
    match target {
        ProxyTarget::Ip(addr) => Ok(*addr),
        ProxyTarget::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .with_context(|| format!("resolve UDP target {host}:{port}"))?
            .next()
            .with_context(|| format!("UDP target resolved to no addresses: {host}:{port}")),
    }
}
