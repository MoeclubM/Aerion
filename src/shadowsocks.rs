use crate::protocol::{ProxyTarget, target_name};
use crate::{socket_protect, socks, uot};
use anyhow::{Context, Result, ensure};
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
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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
}

#[derive(Clone, Debug)]
pub struct ShadowsocksServerConfig {
    pub listen: SocketAddr,
    pub method: String,
    pub password: String,
    pub users: Vec<String>,
    pub udp: bool,
}

#[derive(Clone)]
struct ShadowsocksRuntime {
    server_host: String,
    server_port: u16,
    server: ShadowsocksInnerConfig,
    context: ShadowsocksSharedContext,
    udp: bool,
}

#[derive(Clone)]
struct ShadowsocksServerRuntime {
    server: ShadowsocksInnerConfig,
    context: ShadowsocksSharedContext,
    udp: bool,
}

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
    let runtime = ShadowsocksRuntime::from_config(config)?;
    tracing::info!(
        "Shadowsocks client listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = listener.accept().await.context("accept SOCKS client")?;
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_shadowsocks_socks(stream, runtime).await {
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
            server: ShadowsocksInnerConfig::new(server_addr, config.password, method)
                .context("build Shadowsocks server config")?,
            context: ShadowsocksContext::new_shared(ServerType::Local),
            udp: config.udp,
        })
    }
}

impl ShadowsocksServerRuntime {
    fn from_config(config: ShadowsocksServerConfig) -> Result<Self> {
        let method = config
            .method
            .parse::<CipherKind>()
            .map_err(|_| anyhow::anyhow!("unsupported Shadowsocks cipher {}", config.method))?;
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
            udp: config.udp,
        })
    }
}

pub async fn run_shadowsocks_server(config: ShadowsocksServerConfig) -> Result<()> {
    let runtime = ShadowsocksServerRuntime::from_config(config)?;
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
        tokio::spawn(async move {
            if let Err(error) = handle_shadowsocks_tcp_client(stream).await {
                tracing::warn!("Shadowsocks TCP client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_shadowsocks_tcp_client<S>(mut inbound: ProxyServerStream<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = inbound
        .handshake()
        .await
        .context("read Shadowsocks TCP target")?;
    let target = proxy_target(&target);
    let mut outbound = connect_proxy_target(&target).await?;
    tracing::info!("Shadowsocks serving TCP {}", target_name(&target));
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .context("relay Shadowsocks TCP")?;
    Ok(())
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
        let payload = buffer[..read].to_vec();
        tokio::spawn(async move {
            if let Err(error) =
                relay_shadowsocks_udp_packet(proxy, peer, target, control, payload).await
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
) -> Result<()> {
    let target_addr = resolve_shadowsocks_address(&target).await?;
    let bind_addr = if target_addr.is_ipv6() {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let outbound = socket_protect::bind_udp(bind_addr).await?;
    outbound
        .send_to(&payload, target_addr)
        .await
        .with_context(|| format!("send Shadowsocks UDP payload to {target_addr}"))?;

    let mut buffer = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    while let Ok(read) = timeout(
        SHADOWSOCKS_UDP_SESSION_TIMEOUT,
        outbound.recv_from(&mut buffer),
    )
    .await
    {
        let (read, _) = read.context("receive Shadowsocks UDP response")?;
        if let Some(control) = control.as_ref() {
            proxy
                .send_to_with_ctrl(peer, &target, control, &buffer[..read])
                .await
                .with_context(|| format!("send Shadowsocks UDP response to {peer}"))?;
        } else {
            proxy
                .send_to(peer, &target, &buffer[..read])
                .await
                .with_context(|| format!("send Shadowsocks UDP response to {peer}"))?;
        }
    }
    Ok(())
}

async fn handle_shadowsocks_socks(mut local: TcpStream, runtime: ShadowsocksRuntime) -> Result<()> {
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
                peers.insert(target, peer);
            }
            read = proxy.recv(&mut remote_buffer) => {
                let (read, target, _) = read.context("receive Shadowsocks UDP packet")?;
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

async fn connect_proxy_target(target: &ProxyTarget) -> Result<TcpStream> {
    match target {
        ProxyTarget::Ip(addr) => socket_protect::connect_tcp_addr(*addr).await,
        ProxyTarget::Domain(host, port) => socket_protect::connect_tcp_host_port(host, *port).await,
    }
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
        ProxyTarget::Ip(addr) => ShadowsocksAddress::SocketAddress(*addr),
        ProxyTarget::Domain(host, port) => {
            ShadowsocksAddress::DomainNameAddress(host.clone(), *port)
        }
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
