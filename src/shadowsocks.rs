use crate::protocol::{ProxyTarget, target_name};
use crate::{socket_protect, socks, uot};
use anyhow::{Context, Result, ensure};
use shadowsocks::config::{ServerAddr as ShadowsocksServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{
    Context as ShadowsocksContext, SharedContext as ShadowsocksSharedContext,
};
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::UdpSocket as ShadowsocksUdpSocket;
use shadowsocks::relay::socks5::Address as ShadowsocksAddress;
use shadowsocks::relay::tcprelay::ProxyClientStream;
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::relay::udprelay::{MAXIMUM_UDP_PAYLOAD_SIZE, ProxySocket};
use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Clone, Debug)]
pub struct ShadowsocksClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub method: String,
    pub password: String,
    pub udp: bool,
}

#[derive(Clone)]
struct ShadowsocksRuntime {
    server_host: String,
    server_port: u16,
    server: ServerConfig,
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
            server: ServerConfig::new(server_addr, config.password, method)
                .context("build Shadowsocks server config")?,
            context: ShadowsocksContext::new_shared(ServerType::Local),
            udp: config.udp,
        })
    }
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
