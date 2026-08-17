use crate::protocol::ProxyTarget;
use anyhow::{Context, Result, bail};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use tokio::net::TcpSocket;

type SocketProtector = Arc<dyn Fn(i32) -> Result<()> + Send + Sync + 'static>;

static SOCKET_PROTECTOR: RwLock<Option<SocketProtector>> = RwLock::new(None);

pub fn set_socket_protector<F>(protector: F)
where
    F: Fn(i32) -> Result<()> + Send + Sync + 'static,
{
    *SOCKET_PROTECTOR
        .write()
        .expect("socket protector lock poisoned") = Some(Arc::new(protector));
}

pub fn clear_socket_protector() {
    *SOCKET_PROTECTOR
        .write()
        .expect("socket protector lock poisoned") = None;
}

pub fn protect_socket_fd(fd: i32) -> Result<()> {
    let protector = SOCKET_PROTECTOR
        .read()
        .expect("socket protector lock poisoned")
        .clone();
    if let Some(protector) = protector {
        protector(fd)?;
    }
    Ok(())
}

pub async fn connect_proxy_target(target: &ProxyTarget) -> Result<TcpStream> {
    match target {
        ProxyTarget::Ip(addr) => connect_tcp_addr(*addr)
            .await
            .with_context(|| format!("connect target {addr}")),
        ProxyTarget::Domain(host, port) => connect_tcp_host_port(host, *port)
            .await
            .with_context(|| format!("connect target {host}:{port}")),
    }
}

pub async fn connect_tcp_host_port(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve TCP peer {host}:{port}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        bail!("TCP peer resolved to no addresses: {host}:{port}");
    }
    if addrs.len() == 1 {
        return connect_tcp_addr(addrs[0])
            .await
            .with_context(|| format!("connect target {}", addrs[0]));
    }
    let mut racers = JoinSet::new();
    for addr in addrs {
        racers.spawn(async move { connect_tcp_addr(addr).await.map_err(|error| (addr, error)) });
    }
    let mut last_error = None;
    while let Some(result) = racers.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                racers.abort_all();
                return Ok(stream);
            }
            Ok(Err((addr, error))) => {
                last_error = Some(anyhow::anyhow!("connect TCP peer {addr}: {error:#}"));
            }
            Err(join_error) => {
                last_error = Some(anyhow::anyhow!("TCP dial task failed: {join_error}"));
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("TCP peer resolved to no addresses: {host}:{port}")))
}

pub async fn connect_tcp_addr(addr: SocketAddr) -> Result<TcpStream> {
    let stream = connect_tcp_addr_inner(addr).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn connect_tcp_addr_inner(addr: SocketAddr) -> Result<TcpStream> {
    #[cfg(unix)]
    {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4().context("create protected IPv4 TCP socket")?
        } else {
            TcpSocket::new_v6().context("create protected IPv6 TCP socket")?
        };
        protect_socket_fd(socket.as_raw_fd())?;
        return socket
            .connect(addr)
            .await
            .with_context(|| format!("connect protected TCP peer {addr}"));
    }
    #[cfg(not(unix))]
    {
        TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect TCP peer {addr}"))
    }
}

pub async fn bind_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = bind_udp_std(addr)?;
    UdpSocket::from_std(socket).context("create tokio UDP socket from protected socket")
}

pub async fn bind_dual_stack_udp() -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("create dual-stack UDP socket")?;
    socket.set_only_v6(false).context("enable dual-stack UDP")?;
    socket
        .set_nonblocking(true)
        .context("set dual-stack UDP socket nonblocking")?;
    socket
        .bind(&std::net::SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
        .context("bind dual-stack UDP socket")?;
    #[cfg(unix)]
    protect_socket_fd(std::os::fd::AsRawFd::as_raw_fd(&socket))?;
    UdpSocket::from_std(socket.into()).context("create tokio dual-stack UDP socket")
}

pub fn bind_udp_std(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)
        .with_context(|| format!("bind protected UDP socket on {addr}"))?;
    #[cfg(unix)]
    protect_socket_fd(socket.as_raw_fd())?;
    socket
        .set_nonblocking(true)
        .context("set protected UDP socket nonblocking")?;
    Ok(socket)
}
