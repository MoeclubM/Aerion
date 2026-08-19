use crate::core::{CoreSession, ProxyCore, relay_bidirectional_counted};
use crate::protocol::{ProxyTarget, resolve_target_addr, target_name};
use crate::{socket_protect, socks, uot};
use anyhow::{Context, Result, bail, ensure};
use shadowsocks::config::{
    ServerAddr as ShadowsocksServerAddr, ServerConfig as ShadowsocksInnerConfig, ServerType,
    ServerUser, ServerUserManager,
};
use shadowsocks::context::{
    Context as ShadowsocksContext, SharedContext as ShadowsocksSharedContext,
};
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::UdpSocket as ShadowsocksUdpSocket;
use shadowsocks::relay::socks5::Address as ShadowsocksAddress;
use shadowsocks::relay::tcprelay::ProxyClientStream;
use shadowsocks::relay::tcprelay::ProxyListener;
use shadowsocks::relay::tcprelay::ProxyServerStream;
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::relay::udprelay::{MAXIMUM_UDP_PAYLOAD_SIZE, ProxySocket};
use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;

const SHADOWSOCKS_UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct ShadowsocksClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub method: String,
    pub password: String,
    pub udp: bool,
    pub udp_over_tcp: bool,
}

#[derive(Clone, Debug)]
pub struct ShadowsocksServerConfig {
    pub listen: SocketAddr,
    pub method: String,
    pub password: String,
    pub users: Vec<String>,
    pub tcp: bool,
    pub udp: bool,
    pub udp_over_tcp: bool,
}

#[derive(Clone)]
struct ShadowsocksRuntime {
    server_host: String,
    server_port: u16,
    server: ShadowsocksInnerConfig,
    context: ShadowsocksSharedContext,
    udp: bool,
    udp_over_tcp: bool,
    password: String,
}

#[derive(Clone)]
struct ShadowsocksServerRuntime {
    server: ShadowsocksInnerConfig,
    context: ShadowsocksSharedContext,
    core: ProxyCore,
    password: String,
    tcp_multi_user: bool,
    tcp: bool,
    udp: bool,
    udp_over_tcp: bool,
    udp_nat: Arc<Mutex<HashMap<(SocketAddr, u64), Arc<SsUdpNat>>>>,
}

struct SsUdpNat {
    socket: Arc<UdpSocket>,
    server_session_id: u64,
    packet_id: AtomicU64,
}

const MAX_SS_UDP_NAT: usize = 1024;

pub async fn run_shadowsocks_client(config: ShadowsocksClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Shadowsocks SOCKS listener on {}", config.listen))?;
    run_shadowsocks_client_listener(listener, config).await
}

pub async fn run_shadowsocks_client_listener(
    listener: TcpListener,
    config: ShadowsocksClientConfig,
) -> Result<()> {
    run_shadowsocks_client_listener_with_core(listener, config, None).await
}

pub async fn run_shadowsocks_client_listener_with_core(
    listener: TcpListener,
    config: ShadowsocksClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    let runtime = ShadowsocksRuntime::from_config(config)?;
    tracing::info!(
        "Shadowsocks client listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = crate::listener::accept_tcp(&listener)
            .await
            .context("accept SOCKS client")?;
        let runtime = runtime.clone();
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_shadowsocks_socks(stream, runtime, core, peer).await {
                tracing::warn!("Shadowsocks SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

impl ShadowsocksRuntime {
    fn from_config(config: ShadowsocksClientConfig) -> Result<Self> {
        let method = config
            .method
            .parse::<CipherKind>()
            .map_err(|_| anyhow::anyhow!("unsupported Shadowsocks cipher {}", config.method))?;
        let server_addr = config
            .server_host
            .parse::<IpAddr>()
            .map(|ip| ShadowsocksServerAddr::SocketAddr(SocketAddr::new(ip, config.server_port)))
            .unwrap_or_else(|_| {
                ShadowsocksServerAddr::DomainName(config.server_host.clone(), config.server_port)
            });
        Ok(Self {
            server_host: config.server_host,
            server_port: config.server_port,
            server: ShadowsocksInnerConfig::new(server_addr, config.password.clone(), method)
                .context("build Shadowsocks server config")?,
            context: ShadowsocksContext::new_shared(ServerType::Local),
            udp: config.udp,
            udp_over_tcp: config.udp_over_tcp,
            password: config.password,
        })
    }
}

impl ShadowsocksServerRuntime {
    fn from_config(config: ShadowsocksServerConfig, core: ProxyCore) -> Result<Self> {
        let method = config
            .method
            .parse::<CipherKind>()
            .map_err(|_| anyhow::anyhow!("unsupported Shadowsocks cipher {}", config.method))?;
        let password = config.password.clone();
        let tcp_multi_user = config.tcp && !config.users.is_empty();
        let mut server = ShadowsocksInnerConfig::new(
            ShadowsocksServerAddr::SocketAddr(config.listen),
            config.password,
            method,
        )
        .context("build Shadowsocks server config")?;
        if !config.users.is_empty() {
            let mut users = ServerUserManager::new();
            for user in config.users {
                let (name, key) = user
                    .split_once(':')
                    .unwrap_or((user.as_str(), user.as_str()));
                users.add_user(
                    ServerUser::with_encoded_key(name, key)
                        .with_context(|| format!("decode Shadowsocks server user {name}"))?,
                );
            }
            server.set_user_manager(users);
        }
        Ok(Self {
            server,
            context: ShadowsocksContext::new_shared(ServerType::Server),
            core,
            password,
            tcp_multi_user,
            tcp: config.tcp,
            udp: config.udp,
            udp_over_tcp: config.udp_over_tcp,
            udp_nat: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

pub async fn run_shadowsocks_server(config: ShadowsocksServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.password, &config.users);
    run_shadowsocks_server_with_core(config, core).await
}

pub async fn run_shadowsocks_server_with_core(
    config: ShadowsocksServerConfig,
    core: ProxyCore,
) -> Result<()> {
    let runtime = ShadowsocksServerRuntime::from_config(config, core)?;
    ensure!(
        runtime.tcp || runtime.udp,
        "Shadowsocks server must enable TCP or UDP"
    );
    ensure!(
        !runtime.tcp_multi_user,
        "Aerion Shadowsocks TCP multi-user accounting requires authenticated user exposure from the shadowsocks crate"
    );
    if runtime.udp && !runtime.tcp {
        return run_shadowsocks_udp_server(runtime).await;
    }
    let listener = ProxyListener::bind(runtime.context.clone(), &runtime.server)
        .await
        .context("bind Shadowsocks server TCP listener")?;
    tracing::info!("Shadowsocks server listening on {}", listener.local_addr()?);
    if runtime.udp {
        let udp_runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = run_shadowsocks_udp_server(udp_runtime).await {
                tracing::warn!("Shadowsocks UDP server exited: {error:?}");
            }
        });
    }
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("accept Shadowsocks client")?;
        let udp_over_tcp = runtime.udp_over_tcp;
        let core = runtime.core.clone();
        let password = runtime.password.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_shadowsocks_tcp_client(stream, udp_over_tcp, core, password, peer).await
            {
                tracing::warn!("Shadowsocks TCP client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_shadowsocks_tcp_client<S>(
    mut inbound: ProxyServerStream<S>,
    udp_over_tcp: bool,
    core: ProxyCore,
    password: String,
    peer: SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = inbound
        .handshake()
        .await
        .context("read Shadowsocks TCP target")?;
    let target = proxy_target(&target);
    if uot::is_magic_target(&target) {
        ensure!(
            udp_over_tcp,
            "Shadowsocks UDP-over-TCP is disabled by server config"
        );
        let session = core.authenticate_from(&password, peer).await?;
        return relay_shadowsocks_uot_stream(inbound, target, session).await;
    }
    let session = core.authenticate_from(&password, peer).await?;
    let mut outbound = socket_protect::connect_proxy_target(&target).await?;
    tracing::info!("Shadowsocks serving TCP {}", target_name(&target));
    relay_bidirectional_counted(&mut inbound, &mut outbound, session, "Shadowsocks").await
}

async fn run_shadowsocks_udp_server(runtime: ShadowsocksServerRuntime) -> Result<()> {
    let proxy = Arc::new(
        ProxySocket::bind(runtime.context.clone(), &runtime.server)
            .await
            .context("bind Shadowsocks server UDP socket")?,
    );
    tracing::info!(
        "Shadowsocks UDP server listening on {}",
        proxy.local_addr()?
    );
    let buffer_len = MAXIMUM_UDP_PAYLOAD_SIZE + ShadowsocksAddress::max_serialized_len();
    loop {
        let mut buffer = vec![0u8; buffer_len];
        let (read, peer, target, _, control) = proxy
            .recv_from_with_ctrl(&mut buffer)
            .await
            .context("receive Shadowsocks UDP packet")?;
        let proxy = proxy.clone();
        let session = shadowsocks_udp_core_session(&runtime, peer, control.as_ref()).await?;
        let payload = buffer[..read].to_vec();
        let nat = runtime.udp_nat.clone();
        tokio::spawn(async move {
            if let Err(error) =
                relay_shadowsocks_udp_packet(proxy, peer, target, control, payload, session, nat)
                    .await
            {
                tracing::warn!("Shadowsocks UDP packet from {peer} failed: {error:?}");
            }
        });
    }
}

async fn relay_shadowsocks_udp_packet(
    proxy: Arc<ProxySocket<ShadowsocksUdpSocket>>,
    peer: SocketAddr,
    target: ShadowsocksAddress,
    control: Option<UdpSocketControlData>,
    payload: Vec<u8>,
    session: CoreSession,
    nat: Arc<Mutex<HashMap<(SocketAddr, u64), Arc<SsUdpNat>>>>,
) -> Result<()> {
    let target_addr = resolve_shadowsocks_address(&target).await?;
    let client_session_id = control
        .as_ref()
        .map(|control| control.client_session_id)
        .unwrap_or(0);
    let entry = get_or_create_ss_udp_nat(
        nat,
        proxy.clone(),
        peer,
        client_session_id,
        control.clone(),
        session.clone(),
    )
    .await?;
    session.record_upload(payload.len()).await?;
    socket_protect::send_to_dual_stack(&entry.socket, &payload, target_addr)
        .await
        .with_context(|| format!("send Shadowsocks UDP payload to {target_addr}"))?;
    Ok(())
}

async fn get_or_create_ss_udp_nat(
    nat: Arc<Mutex<HashMap<(SocketAddr, u64), Arc<SsUdpNat>>>>,
    proxy: Arc<ProxySocket<ShadowsocksUdpSocket>>,
    peer: SocketAddr,
    client_session_id: u64,
    control: Option<UdpSocketControlData>,
    session: CoreSession,
) -> Result<Arc<SsUdpNat>> {
    let key = (peer, client_session_id);
    {
        let table = nat.lock().await;
        if let Some(entry) = table.get(&key) {
            return Ok(entry.clone());
        }
        ensure!(
            table.len() < MAX_SS_UDP_NAT,
            "Shadowsocks UDP NAT table exceeds {MAX_SS_UDP_NAT} sessions"
        );
    }
    let outbound = socket_protect::bind_dual_stack_udp()
        .await
        .context("bind Shadowsocks UDP NAT socket")?;
    let mut server_session_id_buf = [0u8; 8];
    getrandom::fill(&mut server_session_id_buf)
        .context("generate Shadowsocks UDP server_session_id")?;
    let entry = Arc::new(SsUdpNat {
        socket: Arc::new(outbound),
        server_session_id: u64::from_be_bytes(server_session_id_buf),
        packet_id: AtomicU64::new(0),
    });
    {
        let mut table = nat.lock().await;
        if let Some(existing) = table.get(&key) {
            return Ok(existing.clone());
        }
        table.insert(key, entry.clone());
    }
    let recv_entry = entry.clone();
    tokio::spawn(async move {
        if let Err(error) =
            relay_shadowsocks_udp_responses(proxy, peer, control, session, recv_entry).await
        {
            tracing::debug!("Shadowsocks UDP NAT {peer} closed: {error:?}");
        }
        nat.lock().await.remove(&key);
    });
    Ok(entry)
}

async fn relay_shadowsocks_udp_responses(
    proxy: Arc<ProxySocket<ShadowsocksUdpSocket>>,
    peer: SocketAddr,
    control: Option<UdpSocketControlData>,
    session: CoreSession,
    entry: Arc<SsUdpNat>,
) -> Result<()> {
    let mut buffer = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    while let Ok(read) = timeout(
        SHADOWSOCKS_UDP_SESSION_TIMEOUT,
        entry.socket.recv_from(&mut buffer),
    )
    .await
    {
        let (read, source) = read.context("receive Shadowsocks UDP response")?;
        let source = ShadowsocksAddress::SocketAddress(source);
        session.record_download(read).await?;
        if let Some(inbound_control) = control.as_ref() {
            let mut response_control = inbound_control.clone();
            response_control.server_session_id = entry.server_session_id;
            response_control.packet_id = entry.packet_id.fetch_add(1, Ordering::Relaxed) + 1;
            proxy
                .send_to_with_ctrl(peer, &source, &response_control, &buffer[..read])
                .await
                .with_context(|| format!("send Shadowsocks UDP response to {peer}"))?;
        } else {
            proxy
                .send_to(peer, &source, &buffer[..read])
                .await
                .with_context(|| format!("send Shadowsocks UDP response to {peer}"))?;
        }
    }
    Ok(())
}

async fn shadowsocks_udp_core_session(
    runtime: &ShadowsocksServerRuntime,
    peer: SocketAddr,
    control: Option<&UdpSocketControlData>,
) -> Result<CoreSession> {
    if let Some(user) = control.and_then(|control| control.user.as_ref()) {
        return runtime.core.open_session_from(user.name(), peer).await;
    }
    runtime
        .core
        .authenticate_from(&runtime.password, peer)
        .await
}

async fn handle_shadowsocks_socks(
    mut local: TcpStream,
    runtime: ShadowsocksRuntime,
    core: Option<ProxyCore>,
    peer: SocketAddr,
) -> Result<()> {
    let _session = if let Some(core) = core.as_ref() {
        Some(core.authenticate_from(&runtime.password, peer).await?)
    } else {
        None
    };
    match socks::read_request(&mut local).await? {
        socks::SocksRequest::Connect(target) => {
            let tcp = socket_protect::connect_tcp_host_port(
                runtime.server_host.as_str(),
                runtime.server_port,
            )
            .await
            .with_context(|| {
                format!(
                    "connect Shadowsocks server {}:{}",
                    runtime.server_host, runtime.server_port
                )
            })?;
            let mut remote = ProxyClientStream::from_stream(
                runtime.context.clone(),
                tcp,
                &runtime.server,
                shadowsocks_address(&target),
            );
            poll_fn(|cx| Pin::new(&mut remote).poll_write(cx, &[]))
                .await
                .context("write Shadowsocks TCP request header")?;
            socks::write_reply(&mut local, 0x00).await?;
            tracing::info!("Shadowsocks proxying {}", target_name(&target));
            tokio::io::copy_bidirectional(&mut local, &mut remote)
                .await
                .context("relay Shadowsocks TCP")?;
            Ok(())
        }
        socks::SocksRequest::UdpAssociate => {
            ensure!(runtime.udp, "Shadowsocks UDP is disabled by client config");
            if runtime.udp_over_tcp {
                return handle_shadowsocks_uot_associate(local, runtime).await;
            }
            handle_shadowsocks_udp_associate(local, runtime).await
        }
    }
}

async fn handle_shadowsocks_udp_associate(
    mut control: TcpStream,
    runtime: ShadowsocksRuntime,
) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .with_context(|| format!("bind Shadowsocks SOCKS UDP associate socket on {bind_ip}:0"))?;
    socks::write_reply_with_bind(&mut control, 0x00, udp.local_addr()?).await?;

    let proxy = connect_shadowsocks_udp_server(&runtime).await?;
    let mut peers = HashMap::<ShadowsocksAddress, SocketAddr>::new();
    let udp_buffer_len = MAXIMUM_UDP_PAYLOAD_SIZE + ShadowsocksAddress::max_serialized_len() + 3;
    let mut local_buffer = vec![0u8; udp_buffer_len];
    let mut remote_buffer = vec![0u8; udp_buffer_len];
    let mut control_buffer = [0u8; 1];

    loop {
        tokio::select! {
            read = udp.recv_from(&mut local_buffer) => {
                let (read, peer) = read.context("receive SOCKS UDP packet")?;
                let (target, payload) = uot::parse_socks_udp_packet(&local_buffer[..read])?;
                let target = shadowsocks_address(&target);
                proxy.send(&target, payload).await.context("send Shadowsocks UDP packet")?;
                peers.insert(canonicalize_ss_address(target), peer);
            }
            read = proxy.recv(&mut remote_buffer) => {
                let (read, target, _) = read.context("receive Shadowsocks UDP packet")?;
                let target = canonicalize_ss_address(target);
                let peer = peers
                    .get(&target)
                    .with_context(|| format!("SOCKS UDP peer for {target} is not known"))?;
                let packet = uot::encode_socks_udp_packet(
                    &proxy_target(&target),
                    &remote_buffer[..read],
                )?;
                udp.send_to(&packet, peer)
                    .await
                    .with_context(|| format!("send SOCKS UDP response to {peer}"))?;
            }
            read = control.read(&mut control_buffer) => {
                if read.context("read SOCKS UDP control connection")? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

async fn handle_shadowsocks_uot_associate(
    mut control: TcpStream,
    runtime: ShadowsocksRuntime,
) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("bind Shadowsocks UOT SOCKS UDP socket on {bind_ip}:0"))?,
    );
    socks::write_reply_with_bind(&mut control, 0x00, udp.local_addr()?).await?;

    let tcp =
        socket_protect::connect_tcp_host_port(runtime.server_host.as_str(), runtime.server_port)
            .await
            .with_context(|| {
                format!(
                    "connect Shadowsocks UOT server {}:{}",
                    runtime.server_host, runtime.server_port
                )
            })?;
    let mut remote = ProxyClientStream::from_stream(
        runtime.context.clone(),
        tcp,
        &runtime.server,
        shadowsocks_address(&uot::magic_target()),
    );
    poll_fn(|cx| Pin::new(&mut remote).poll_write(cx, &[]))
        .await
        .context("write Shadowsocks UOT TCP request header")?;
    remote
        .write_all(&uot::encode_v2_associate_request()?)
        .await
        .context("write Shadowsocks UOT associate request")?;
    let (mut remote_reader, mut remote_writer) = tokio::io::split(remote);
    let peer = Arc::new(Mutex::new(None::<SocketAddr>));

    let udp_to_stream = {
        let udp = udp.clone();
        let peer = peer.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, next_peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive Shadowsocks UOT SOCKS UDP packet")?;
                *peer.lock().await = Some(next_peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let packet = uot::encode_associate_packet(&target, payload)?;
                remote_writer
                    .write_all(&packet)
                    .await
                    .context("write Shadowsocks UOT packet")?;
            }
        }
    };
    let stream_to_udp = {
        let udp = udp.clone();
        async move {
            let request = uot::legacy_associate_request();
            let mut pending = Vec::new();
            let mut buffer = vec![0u8; 32 * 1024];
            loop {
                while let Some((source, payload, _)) =
                    uot::take_stream_packet(&request, &mut pending)?
                {
                    let peer = (*peer.lock().await).context("SOCKS UDP peer is not known yet")?;
                    let response = uot::encode_socks_udp_packet(&source, &payload)?;
                    udp.send_to(&response, peer)
                        .await
                        .with_context(|| format!("send Shadowsocks UOT response to {peer}"))?;
                }
                let read = remote_reader
                    .read(&mut buffer)
                    .await
                    .context("read Shadowsocks UOT stream")?;
                if read == 0 {
                    return Ok::<(), anyhow::Error>(());
                }
                pending.extend_from_slice(&buffer[..read]);
            }
        }
    };
    let control_closed = async {
        let mut buffer = [0u8; 1];
        loop {
            if control
                .read(&mut buffer)
                .await
                .context("read Shadowsocks UOT control connection")?
                == 0
            {
                return Ok::<(), anyhow::Error>(());
            }
        }
    };

    tokio::select! {
        result = udp_to_stream => result,
        result = stream_to_udp => result,
        result = control_closed => result,
    }
}

async fn relay_shadowsocks_uot_stream<S>(
    mut inbound: ProxyServerStream<S>,
    target: ProxyTarget,
    session: CoreSession,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending = Vec::new();
    let request = if uot::is_legacy_magic_target(&target) {
        uot::legacy_associate_request()
    } else {
        let mut buffer = [0u8; 1024];
        loop {
            let read = inbound
                .read(&mut buffer)
                .await
                .context("read Shadowsocks UOT request")?;
            ensure!(read > 0, "Shadowsocks UOT stream closed before request");
            pending.extend_from_slice(&buffer[..read]);
            if let Some(request) = uot::take_v2_request(&mut pending)? {
                break request;
            }
        }
    };
    let udp = Arc::new(
        UdpSocket::bind(match &request.destination {
            ProxyTarget::Ip(addr) if addr.is_ipv6() => "[::]:0",
            _ => "0.0.0.0:0",
        })
        .await
        .context("bind Shadowsocks UOT UDP socket")?,
    );
    if request.is_connect {
        let target = resolve_target_addr(&request.destination).await?;
        udp.connect(target)
            .await
            .with_context(|| format!("connect Shadowsocks UOT UDP target {target}"))?;
    }
    tracing::info!("Shadowsocks serving UDP-over-TCP");
    let (mut reader, mut writer) = tokio::io::split(inbound);
    let downlink_is_connect = request.is_connect;

    let uplink = {
        let udp = udp.clone();
        let request = request;
        let uplink_session = session.clone();
        async move {
            let mut buffer = vec![0u8; 32 * 1024];
            loop {
                while let Some((destination, payload, connected)) =
                    uot::take_stream_packet(&request, &mut pending)?
                {
                    uplink_session.record_upload(payload.len()).await?;
                    if connected {
                        let sent = udp
                            .send(&payload)
                            .await
                            .context("send connected Shadowsocks UOT payload")?;
                        if sent != payload.len() {
                            bail!(
                                "short Shadowsocks UOT send: expected {}, wrote {}",
                                payload.len(),
                                sent
                            );
                        }
                    } else {
                        let target = resolve_target_addr(&destination).await?;
                        let sent = udp
                            .send_to(&payload, target)
                            .await
                            .with_context(|| format!("send Shadowsocks UOT payload to {target}"))?;
                        if sent != payload.len() {
                            bail!(
                                "short Shadowsocks UOT send: expected {}, wrote {}",
                                payload.len(),
                                sent
                            );
                        }
                    }
                }
                let read = reader
                    .read(&mut buffer)
                    .await
                    .context("read Shadowsocks UOT packet stream")?;
                if read == 0 {
                    return Ok::<(), anyhow::Error>(());
                }
                pending.extend_from_slice(&buffer[..read]);
            }
        }
    };
    let downlink = async move {
        let mut buffer = vec![0u8; u16::MAX as usize];
        loop {
            let packet = if downlink_is_connect {
                let read = udp
                    .recv(&mut buffer)
                    .await
                    .context("receive connected Shadowsocks UOT payload")?;
                session.record_download(read).await?;
                uot::encode_connect_packet(&buffer[..read])?
            } else {
                let (read, source) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive Shadowsocks UOT payload")?;
                session.record_download(read).await?;
                uot::encode_associate_packet(&ProxyTarget::Ip(source), &buffer[..read])?
            };
            writer
                .write_all(&packet)
                .await
                .context("write Shadowsocks UOT response packet")?;
        }
    };

    tokio::select! {
        result = uplink => result,
        result = downlink => result,
    }
}

async fn connect_shadowsocks_udp_server(
    runtime: &ShadowsocksRuntime,
) -> Result<ProxySocket<ShadowsocksUdpSocket>> {
    let server_addr = tokio::net::lookup_host((runtime.server_host.as_str(), runtime.server_port))
        .await
        .with_context(|| {
            format!(
                "resolve Shadowsocks UDP server {}:{}",
                runtime.server_host, runtime.server_port
            )
        })?
        .next()
        .with_context(|| {
            format!(
                "Shadowsocks UDP server resolved to no addresses: {}:{}",
                runtime.server_host, runtime.server_port
            )
        })?;
    let bind_addr = if server_addr.is_ipv6() {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let udp = socket_protect::bind_udp_std(bind_addr)
        .with_context(|| format!("bind protected Shadowsocks UDP socket on {bind_addr}"))?;
    let udp = UdpSocket::from_std(udp).context("create tokio Shadowsocks UDP socket")?;
    udp.connect(server_addr)
        .await
        .with_context(|| format!("connect Shadowsocks UDP server {server_addr}"))?;
    Ok(ProxySocket::from_socket(
        UdpSocketType::Client,
        runtime.context.clone(),
        &runtime.server,
        ShadowsocksUdpSocket::from(udp),
    ))
}

async fn resolve_shadowsocks_address(target: &ShadowsocksAddress) -> Result<SocketAddr> {
    match target {
        ShadowsocksAddress::SocketAddress(addr) => Ok(*addr),
        ShadowsocksAddress::DomainNameAddress(host, port) => {
            tokio::net::lookup_host((host.as_str(), *port))
                .await
                .with_context(|| format!("resolve Shadowsocks UDP target {host}:{port}"))?
                .next()
                .with_context(|| {
                    format!("Shadowsocks UDP target resolved to no addresses: {host}:{port}")
                })
        }
    }
}

fn shadowsocks_address(target: &ProxyTarget) -> ShadowsocksAddress {
    match target {
        ProxyTarget::Ip(addr) => {
            ShadowsocksAddress::SocketAddress(crate::protocol::canonicalize_socket_addr(*addr))
        }
        ProxyTarget::Domain(host, port) => {
            ShadowsocksAddress::DomainNameAddress(host.clone(), *port)
        }
    }
}

fn canonicalize_ss_address(addr: ShadowsocksAddress) -> ShadowsocksAddress {
    match addr {
        ShadowsocksAddress::SocketAddress(socket) => {
            ShadowsocksAddress::SocketAddress(crate::protocol::canonicalize_socket_addr(socket))
        }
        other => other,
    }
}

fn proxy_target(target: &ShadowsocksAddress) -> ProxyTarget {
    match target {
        ShadowsocksAddress::SocketAddress(addr) => ProxyTarget::Ip(*addr),
        ShadowsocksAddress::DomainNameAddress(host, port) => {
            ProxyTarget::Domain(host.clone(), *port)
        }
    }
}
