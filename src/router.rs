use crate::core::ProxyCore;
use crate::listener::ListenerStopToken;
use crate::protocol::{ProxyTarget, target_name};
use crate::routing::{RouteDecision, RouteNetwork, RouteTable, SharedRouteTable};
use crate::socket_protect;
use crate::socks::{self, SocksRequest};
use crate::uot;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct RouteProxyConfig {
    pub routes: RouteTable,
    pub upstreams: BTreeMap<String, SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct RouteProxyState {
    routes: SharedRouteTable,
    upstreams: Arc<RwLock<BTreeMap<String, SocketAddr>>>,
    core: Option<ProxyCore>,
}

struct UdpCommand {
    target: ProxyTarget,
    payload: Vec<u8>,
    peer: SocketAddr,
}

pub async fn run_route_proxy(listener: TcpListener, config: RouteProxyConfig) -> Result<()> {
    run_route_proxy_with_state(listener, RouteProxyState::from_config(config)).await
}

pub async fn run_route_proxy_until(
    listener: TcpListener,
    config: RouteProxyConfig,
    stop: ListenerStopToken,
) -> Result<()> {
    run_route_proxy_with_state_until(listener, RouteProxyState::from_config(config), stop).await
}

pub async fn run_route_proxy_with_state(
    listener: TcpListener,
    state: RouteProxyState,
) -> Result<()> {
    run_route_proxy_with_state_until(listener, state, ListenerStopToken::new()).await
}

pub async fn run_route_proxy_with_state_until(
    listener: TcpListener,
    state: RouteProxyState,
    stop: ListenerStopToken,
) -> Result<()> {
    tracing::info!(
        "route proxy listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = tokio::select! {
            _ = stop.stopped() => return Ok(()),
            accepted = listener.accept() => accepted.context("accept route client")?,
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_route_client(stream, state).await {
                tracing::warn!("route client {peer} failed: {error:?}");
            }
        });
    }
}

impl RouteProxyState {
    pub fn new(
        routes: RouteTable,
        upstreams: BTreeMap<String, SocketAddr>,
        core: Option<ProxyCore>,
    ) -> Self {
        Self {
            routes: SharedRouteTable::new(routes),
            upstreams: Arc::new(RwLock::new(upstreams)),
            core,
        }
    }

    pub fn from_config(config: RouteProxyConfig) -> Self {
        Self::new(config.routes, config.upstreams, None)
    }

    pub fn with_core(mut self, core: ProxyCore) -> Self {
        self.core = Some(core);
        self
    }

    pub fn route_table(&self) -> SharedRouteTable {
        self.routes.clone()
    }

    pub fn replace_routes(&self, routes: RouteTable) {
        self.routes.replace(routes);
    }

    pub fn replace_upstreams(&self, upstreams: BTreeMap<String, SocketAddr>) {
        *self
            .upstreams
            .write()
            .expect("route upstreams lock poisoned") = upstreams;
    }

    pub fn set_upstream(&self, tag: impl Into<String>, upstream: SocketAddr) {
        self.upstreams
            .write()
            .expect("route upstreams lock poisoned")
            .insert(tag.into(), upstream);
    }

    pub fn remove_upstream(&self, tag: &str) -> Option<SocketAddr> {
        self.upstreams
            .write()
            .expect("route upstreams lock poisoned")
            .remove(tag)
    }

    pub fn upstream(&self, tag: &str) -> Option<SocketAddr> {
        self.upstreams
            .read()
            .expect("route upstreams lock poisoned")
            .get(tag)
            .copied()
    }

    pub fn upstreams_snapshot(&self) -> BTreeMap<String, SocketAddr> {
        self.upstreams
            .read()
            .expect("route upstreams lock poisoned")
            .clone()
    }

    pub fn decide(&self, target: &ProxyTarget, network: RouteNetwork) -> RouteDecision {
        self.routes.decide(target, network)
    }

    pub fn try_decide(&self, target: &ProxyTarget, network: RouteNetwork) -> Result<RouteDecision> {
        self.routes.try_decide(target, network)
    }

    pub fn core(&self) -> Option<&ProxyCore> {
        self.core.as_ref()
    }
}

async fn handle_route_client(mut local: TcpStream, state: RouteProxyState) -> Result<()> {
    let peer = local.peer_addr()?;
    let session = if let Some(core) = state.core() {
        Some(core.open_session_from("default", peer).await?)
    } else {
        None
    };
    match socks::read_request(&mut local).await? {
        SocksRequest::Connect(target) => {
            let decision = state.try_decide(&target, RouteNetwork::Tcp)?;
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
                    if let Some(session) = session {
                        copy_bidirectional_recorded(&mut local, &mut remote, session)
                            .await
                            .context("relay direct recorded route")?;
                    } else {
                        copy_bidirectional(&mut local, &mut remote)
                            .await
                            .context("relay direct route")?;
                    }
                    Ok(())
                }
                RouteDecision::Block => {
                    socks::write_reply(&mut local, 0x02).await?;
                    bail!("route blocked {}", target_name(&target))
                }
                RouteDecision::Proxy(tag) => {
                    let upstream = state
                        .upstream(&tag)
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
                    if let Some(session) = session {
                        copy_bidirectional_recorded(&mut local, &mut remote, session)
                            .await
                            .with_context(|| format!("relay recorded route via {tag}"))?;
                    } else {
                        copy_bidirectional(&mut local, &mut remote)
                            .await
                            .with_context(|| format!("relay route via {tag}"))?;
                    }
                    Ok(())
                }
            }
        }
        SocksRequest::UdpAssociate => handle_udp_associate(local, state).await,
    }
}

async fn copy_bidirectional_recorded(
    local: &mut TcpStream,
    remote: &mut TcpStream,
    session: crate::core::CoreSession,
) -> Result<()> {
    let (mut local_read, mut local_write) = local.split();
    let (mut remote_read, mut remote_write) = remote.split();

    let upload = async {
        let mut buffer = vec![0u8; 16384];
        loop {
            let read = local_read.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            session.record_upload(read).await?;
            remote_write.write_all(&buffer[..read]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let download = async {
        let mut buffer = vec![0u8; 16384];
        loop {
            let read = remote_read.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            session.record_download(read).await?;
            local_write.write_all(&buffer[..read]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = upload => result?,
        result = download => result?,
    }
    Ok(())
}

async fn connect_direct(target: &ProxyTarget) -> Result<TcpStream> {
    match target {
        ProxyTarget::Ip(addr) => socket_protect::connect_tcp_addr(*addr).await,
        ProxyTarget::Domain(host, port) => socket_protect::connect_tcp_host_port(host, *port).await,
    }
}

async fn handle_udp_associate(mut control: TcpStream, state: RouteProxyState) -> Result<()> {
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

    let peer = control.peer_addr()?;
    let session = if let Some(core) = state.core() {
        Some(core.open_session_from("default", peer).await?)
    } else {
        None
    };

    loop {
        tokio::select! {
            received = udp.recv_from(&mut packet) => {
                let (read, peer) = received.context("receive route UDP packet")?;
                let (target, payload) = uot::parse_socks_udp_packet(&packet[..read])?;
                match state.try_decide(&target, RouteNetwork::Udp)? {
                    RouteDecision::Direct => {
                        let key = format!("direct:{}", target_name(&target));
                        let tx = sessions.entry(key).or_insert_with(|| {
                            spawn_direct_udp_session(target.clone(), udp.clone(), session.clone())
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
                        let upstream = state
                            .upstream(&tag)
                            .with_context(|| format!("route UDP outbound {tag} was not started"))?;
                        let tx = sessions
                            .entry(format!("proxy:{tag}@{upstream}"))
                            .or_insert_with(|| {
                                spawn_proxy_udp_session(tag.clone(), upstream, udp.clone(), session.clone())
                            })
                            .clone();
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
    session: Option<crate::core::CoreSession>,
) -> mpsc::Sender<UdpCommand> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(error) = run_direct_udp_session(target, rx, client_udp, session).await {
            tracing::warn!("direct UDP route session failed: {error:?}");
        }
    });
    tx
}

fn spawn_proxy_udp_session(
    tag: String,
    upstream: SocketAddr,
    client_udp: Arc<UdpSocket>,
    session: Option<crate::core::CoreSession>,
) -> mpsc::Sender<UdpCommand> {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(error) = run_proxy_udp_session(&tag, upstream, rx, client_udp, session).await {
            tracing::warn!("proxy UDP route session {tag} failed: {error:?}");
        }
    });
    tx
}

async fn run_direct_udp_session(
    target: ProxyTarget,
    mut rx: mpsc::Receiver<UdpCommand>,
    client_udp: Arc<UdpSocket>,
    session: Option<crate::core::CoreSession>,
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
                if let Some(session) = &session {
                    session.record_upload(command.payload.len()).await?;
                }
                socket.send_to(&command.payload, remote)
                    .await
                    .with_context(|| format!("send direct UDP {}", target_name(&command.target)))?;
            }
            received = socket.recv_from(&mut buffer) => {
                let (read, source) = received.context("receive direct UDP response")?;
                if let Some(session) = &session {
                    session.record_download(read).await?;
                }
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
    session: Option<crate::core::CoreSession>,
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
                if let Some(session) = &session {
                    session.record_upload(command.payload.len()).await?;
                }
                let packet = uot::encode_socks_udp_packet(&command.target, &command.payload)?;
                socket.send_to(&packet, bind)
                    .await
                    .with_context(|| format!("send UDP route via {tag}"))?;
            }
            received = socket.recv_from(&mut buffer) => {
                let (read, _) = received.with_context(|| format!("receive UDP route via {tag}"))?;
                if let Some(session) = &session {
                    session.record_download(read).await?;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RouteRule;

    #[test]
    fn route_proxy_state_hot_updates_routes_and_upstreams() {
        let target = ProxyTarget::Domain("example.com".to_string(), 443);
        let state = RouteProxyState::new(RouteTable::default(), BTreeMap::new(), None);
        assert_eq!(
            state.decide(&target, RouteNetwork::Tcp),
            RouteDecision::Direct
        );

        state.replace_routes(RouteTable {
            rules: vec![RouteRule::new(RouteDecision::Proxy("node-a".to_string()))],
            default: RouteDecision::Block,
            ..RouteTable::default()
        });
        assert_eq!(
            state.decide(&target, RouteNetwork::Tcp),
            RouteDecision::Proxy("node-a".to_string())
        );

        let first = "127.0.0.1:10001".parse().expect("valid socket addr");
        let second = "127.0.0.1:10002".parse().expect("valid socket addr");
        state.set_upstream("node-a", first);
        assert_eq!(state.upstream("node-a"), Some(first));
        state.set_upstream("node-a", second);
        assert_eq!(state.upstream("node-a"), Some(second));
        assert_eq!(state.remove_upstream("node-a"), Some(second));
        assert_eq!(state.upstream("node-a"), None);
    }
}
