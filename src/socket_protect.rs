use crate::protocol::ProxyTarget;
use anyhow::{Context, Result, bail};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::task::JoinSet;

#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd};

const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(15);
const UDP_BUF_SIZES: [usize; 3] = [8 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024];

type SocketProtector = Arc<dyn Fn(i32) -> Result<()> + Send + Sync + 'static>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutboundInterface {
    pub name: Option<String>,
    pub ipv4_index: Option<u32>,
    pub ipv6_index: Option<u32>,
}

static SOCKET_PROTECTOR: RwLock<Option<SocketProtector>> = RwLock::new(None);
static OUTBOUND_INTERFACE: RwLock<Option<OutboundInterface>> = RwLock::new(None);

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

pub fn set_outbound_interface(interface: OutboundInterface) {
    *OUTBOUND_INTERFACE
        .write()
        .expect("outbound interface lock poisoned") = Some(interface);
}

pub fn clear_outbound_interface() {
    *OUTBOUND_INTERFACE
        .write()
        .expect("outbound interface lock poisoned") = None;
}

pub fn detect_default_outbound_interface() -> Option<OutboundInterface> {
    #[cfg(windows)]
    {
        return windows_udp::detect_default_interface();
    }
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in table.lines().skip(1) {
            let mut cols = line.split_whitespace();
            let Some(iface) = cols.next() else {
                continue;
            };
            let Some(dest) = cols.next() else {
                continue;
            };
            if dest == "00000000"
                && !iface.starts_with("tun")
                && !iface.starts_with("utun")
                && !iface.starts_with("wg")
            {
                return Some(OutboundInterface {
                    name: Some(iface.to_string()),
                    ipv4_index: None,
                    ipv6_index: None,
                });
            }
        }
        return None;
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

pub fn configure_udp_socket_buffers(socket: &Socket) {
    for size in UDP_BUF_SIZES {
        if socket.set_recv_buffer_size(size).is_ok() {
            break;
        }
    }
    for size in UDP_BUF_SIZES {
        if socket.set_send_buffer_size(size).is_ok() {
            break;
        }
    }
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
    tokio::time::timeout(Duration::from_secs(15), async {
        match target {
            ProxyTarget::Ip(addr) => connect_tcp_addr(*addr)
                .await
                .with_context(|| format!("connect target {addr}")),
            ProxyTarget::Domain(host, port) => connect_tcp_host_port(host, *port)
                .await
                .with_context(|| format!("connect target {host}:{port}")),
        }
    })
    .await
    .context("connect target timed out")?
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
    configure_tcp_socket(&stream);
    Ok(stream)
}

pub fn configure_tcp_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    enable_tcp_keepalive(stream);
}

pub fn enable_tcp_keepalive(stream: &TcpStream) {
    let socket = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_TIME);
    let _ = socket.set_tcp_keepalive(&keepalive);
}

async fn connect_tcp_addr_inner(addr: SocketAddr) -> Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4().context("create outbound IPv4 TCP socket")?
    } else {
        TcpSocket::new_v6().context("create outbound IPv6 TCP socket")?
    };
    let is_loopback = addr.ip().is_loopback();
    #[cfg(unix)]
    {
        protect_socket_fd(socket.as_raw_fd())?;
        apply_unix_outbound_interface(&socket, is_loopback);
    }
    #[cfg(windows)]
    {
        apply_windows_outbound_interface(&socket, addr.is_ipv6(), false, is_loopback);
    }
    socket
        .connect(addr)
        .await
        .with_context(|| format!("connect TCP peer {addr}"))
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
    configure_udp_socket_buffers(&socket);
    socket
        .bind(&std::net::SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
        .context("bind dual-stack UDP socket")?;
    disable_windows_udp_connreset(&socket)?;
    #[cfg(windows)]
    apply_windows_outbound_interface(&socket, true, true, false);
    #[cfg(unix)]
    {
        protect_socket_fd(socket.as_raw_fd())?;
        apply_unix_outbound_interface(&socket, false);
    }
    UdpSocket::from_std(socket.into()).context("create tokio dual-stack UDP socket")
}

pub fn dual_stack_dest(local: SocketAddr, dest: SocketAddr) -> SocketAddr {
    match (local.ip(), dest) {
        (IpAddr::V6(_), SocketAddr::V4(v4)) => {
            SocketAddr::from((v4.ip().to_ipv6_mapped(), v4.port()))
        }
        _ => dest,
    }
}

pub async fn send_to_dual_stack(
    socket: &UdpSocket,
    buf: &[u8],
    dest: SocketAddr,
) -> std::io::Result<usize> {
    socket
        .send_to(buf, dual_stack_dest(socket.local_addr()?, dest))
        .await
}

pub async fn connect_dual_stack(socket: &UdpSocket, dest: SocketAddr) -> std::io::Result<()> {
    socket
        .connect(dual_stack_dest(socket.local_addr()?, dest))
        .await
}

pub fn bind_udp_std(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)
        .with_context(|| format!("bind protected UDP socket on {addr}"))?;
    configure_udp_socket_buffers(&socket2::SockRef::from(&socket));
    disable_windows_udp_connreset(&socket)?;
    let is_loopback = addr.ip().is_loopback();
    #[cfg(windows)]
    apply_windows_outbound_interface(&socket, addr.is_ipv6(), false, is_loopback);
    #[cfg(unix)]
    {
        protect_socket_fd(socket.as_raw_fd())?;
        apply_unix_outbound_interface(&socket, is_loopback);
    }
    socket
        .set_nonblocking(true)
        .context("set protected UDP socket nonblocking")?;
    Ok(socket)
}

#[cfg(unix)]
fn apply_unix_outbound_interface<S: AsFd>(socket: &S, is_loopback: bool) {
    #[cfg(target_os = "linux")]
    if !is_loopback {
        let iface = OUTBOUND_INTERFACE
            .read()
            .expect("outbound interface lock poisoned")
            .as_ref()
            .and_then(|item| item.name.clone());
        if let Some(name) = iface {
            let _ = socket2::SockRef::from(socket).bind_device(Some(name.as_bytes()));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (socket, is_loopback);
}

#[cfg(windows)]
fn apply_windows_outbound_interface<S: std::os::windows::io::AsRawSocket>(
    socket: &S,
    ipv6: bool,
    dual_stack: bool,
    is_loopback: bool,
) {
    if is_loopback {
        return;
    }
    let iface = OUTBOUND_INTERFACE
        .read()
        .expect("outbound interface lock poisoned")
        .clone();
    if let Some(iface) = iface {
        windows_udp::bind_unicast_if(socket, &iface, ipv6, dual_stack);
    }
}

#[cfg(windows)]
mod windows_udp {
    use super::*;
    use std::os::windows::io::AsRawSocket;

    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 23;
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    #[repr(C)]
    struct SockAddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: [u8; 4],
        sin_zero: [u8; 8],
    }

    #[repr(C)]
    struct SockAddrIn6 {
        sin6_family: u16,
        sin6_port: u16,
        sin6_flowinfo: u32,
        sin6_addr: [u8; 16],
        sin6_scope_id: u32,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *const core::ffi::c_void,
            optlen: i32,
        ) -> i32;

        fn WSAIoctl(
            s: usize,
            dw_io_control_code: u32,
            lpv_in_buffer: *mut core::ffi::c_void,
            cb_in_buffer: u32,
            lpv_out_buffer: *mut core::ffi::c_void,
            cb_out_buffer: u32,
            lpcb_bytes_returned: *mut u32,
            lp_overlapped: *mut core::ffi::c_void,
            lp_completion_routine: *mut core::ffi::c_void,
        ) -> i32;
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetBestInterfaceEx(dest_addr: *const core::ffi::c_void, best_if_index: *mut u32) -> u32;
    }

    pub(super) fn detect_default_interface() -> Option<OutboundInterface> {
        let probe_v4 = SockAddrIn {
            sin_family: AF_INET,
            sin_port: 53u16.to_be(),
            sin_addr: [8, 8, 8, 8],
            sin_zero: [0; 8],
        };
        let mut idx_v4 = 0u32;
        let ipv4_index = (unsafe {
            GetBestInterfaceEx((&probe_v4 as *const SockAddrIn).cast(), &mut idx_v4)
        } == 0
            && idx_v4 != 0)
            .then_some(idx_v4);

        let probe_v6 = SockAddrIn6 {
            sin6_family: AF_INET6,
            sin6_port: 53u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: [
                0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
            ],
            sin6_scope_id: 0,
        };
        let mut idx_v6 = 0u32;
        let ipv6_index = (unsafe {
            GetBestInterfaceEx((&probe_v6 as *const SockAddrIn6).cast(), &mut idx_v6)
        } == 0
            && idx_v6 != 0)
            .then_some(idx_v6);

        if ipv4_index.is_none() && ipv6_index.is_none() {
            return None;
        }
        Some(OutboundInterface {
            name: None,
            ipv4_index,
            ipv6_index,
        })
    }

    pub(super) fn bind_unicast_if<S: AsRawSocket>(
        socket: &S,
        iface: &OutboundInterface,
        ipv6: bool,
        dual_stack: bool,
    ) {
        let raw = socket.as_raw_socket() as usize;
        if (!ipv6 || dual_stack)
            && let Some(idx4) = iface.ipv4_index
        {
            let net_idx = idx4.to_be();
            let _ = unsafe {
                setsockopt(
                    raw,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    (&net_idx as *const u32).cast(),
                    4,
                )
            };
        }
        if ipv6 && let Some(idx6) = iface.ipv6_index {
            let _ = unsafe {
                setsockopt(
                    raw,
                    IPPROTO_IPV6,
                    IPV6_UNICAST_IF,
                    (&idx6 as *const u32).cast(),
                    4,
                )
            };
        }
    }

    pub(super) fn disable_connreset<S: AsRawSocket>(socket: &S) -> Result<()> {
        let mut enable: i32 = 0;
        let mut bytes_returned = 0u32;
        let result = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as usize,
                SIO_UDP_CONNRESET,
                (&mut enable as *mut i32).cast(),
                4,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            bail!(
                "disable Windows UDP connreset failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn disable_windows_udp_connreset<S: std::os::windows::io::AsRawSocket>(
    socket: &S,
) -> Result<()> {
    windows_udp::disable_connreset(socket)
}

#[cfg(not(windows))]
pub(crate) fn disable_windows_udp_connreset<T>(_: &T) -> Result<()> {
    Ok(())
}
