use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpStream, UdpSocket};

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

pub async fn connect_tcp_host_port(host: &str, port: u16) -> Result<TcpStream> {
    let mut last_error = None;
    for addr in tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve TCP peer {host}:{port}"))?
    {
        match connect_tcp_addr(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("TCP peer resolved to no addresses: {host}:{port}")))
}

pub async fn connect_tcp_addr(addr: SocketAddr) -> Result<TcpStream> {
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
