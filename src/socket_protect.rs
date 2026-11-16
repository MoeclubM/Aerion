use crate::protocol::{ProxyTarget, target_name};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::task::JoinSet;

#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd};

const TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(15);
const UDP_BUF_SIZES: [usize; 3] = [8 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024];
const FALLBACK_DNS_SERVERS: [SocketAddr; 6] = [
    SocketAddr::V4(std::net::SocketAddrV4::new(
        Ipv4Addr::new(114, 114, 114, 114),
        53,
    )),
    SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::new(223, 5, 5, 5), 53)),
    SocketAddr::V4(std::net::SocketAddrV4::new(
        Ipv4Addr::new(119, 29, 29, 29),
        53,
    )),
    SocketAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53)),
    SocketAddr::V6(std::net::SocketAddrV6::new(
        Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 1),
        53,
        0,
        0,
    )),
    SocketAddr::V6(std::net::SocketAddrV6::new(
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        53,
        0,
        0,
    )),
];

/// Returns true when `ip` belongs to the RFC 2544 benchmark range (`198.18.0.0/15`)
/// or tun2proxy's IPv6 VirtualDNS range (`fdfe:dcba:9877::/64`).
pub fn is_fake_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            oct[0] == 198 && (oct[1] == 18 || oct[1] == 19)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_fake_ip(IpAddr::V4(v4));
            }
            let segs = v6.segments();
            segs[0] == 0xfdfe && segs[1] == 0xdcba && segs[2] == 0x9877 && segs[3] == 0
        }
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn is_usable_dns_ip(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || is_fake_ip(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_usable_dns_ip(IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            !v6.is_unicast_link_local() && (seg0 & 0xffc0) != 0xfec0
        }
    }
}

pub(crate) fn is_tunnel_or_vpn_adapter(if_type: u32, name: &str, description: &str) -> bool {
    // 24 = IF_TYPE_SOFTWARE_LOOPBACK, 53 = IF_TYPE_PROP_VIRTUAL (Wintun/Tailscale/WireGuard),
    // 131 = IF_TYPE_TUNNEL.
    if matches!(if_type, 24 | 53 | 131) {
        return true;
    }
    let name_lower = name.to_ascii_lowercase();
    let desc_lower = description.to_ascii_lowercase();
    const KEYWORDS: [&str; 15] = [
        "wintun",
        "wireguard",
        "tailscale",
        "zerotier",
        "tap-windows",
        "tap adapter",
        "openvpn",
        "sing-tun",
        "clash",
        "mihomo",
        "neto",
        "secovpn",
        "xbclient",
        "utun",
        "npcap",
    ];
    KEYWORDS
        .iter()
        .any(|kw| name_lower.contains(kw) || desc_lower.contains(kw))
}

pub(crate) fn is_hypervisor_bridge_adapter(name: &str, description: &str) -> bool {
    let name_lower = name.to_ascii_lowercase();
    let desc_lower = description.to_ascii_lowercase();
    const BRIDGE_KEYWORDS: [&str; 5] = ["vethernet", "wsl", "vmware", "virtualbox", "docker"];
    BRIDGE_KEYWORDS
        .iter()
        .any(|kw| name_lower.contains(kw) || desc_lower.contains(kw))
}

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
    let mut guard = OUTBOUND_INTERFACE
        .write()
        .expect("outbound interface lock poisoned");
    let changed = guard.as_ref() != Some(&interface);
    if changed {
        tracing::info!(
            name = ?interface.name,
            ipv4_index = ?interface.ipv4_index,
            ipv6_index = ?interface.ipv6_index,
            "Aerion outbound interface updated"
        );
    }
    *guard = Some(interface);
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
                && !iface.starts_with("tailscale")
                && !iface.starts_with("zt")
                && !iface.starts_with("clash")
                && !iface.starts_with("sing")
                && !iface.starts_with("Meta")
                && !iface.starts_with("neto")
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
    match tokio::time::timeout(Duration::from_secs(15), async {
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
    {
        Ok(result) => result,
        Err(_) => {
            let err = std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect target {} timed out", target_name(target)),
            );
            Err(err).context("connect target timed out")
        }
    }
}

pub async fn resolve_host_non_fakeip(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let trimmed_host = host.trim().trim_matches(['[', ']']).trim_end_matches('.');
    if trimmed_host.is_empty()
        || trimmed_host.eq_ignore_ascii_case("invalid")
        || trimmed_host
            .get(trimmed_host.len().saturating_sub(8)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".invalid"))
    {
        let err = std::io::Error::new(
            std::io::ErrorKind::HostUnreachable,
            format!("RFC 6761 invalid domain: {host}:{port}"),
        );
        return Err(err).with_context(|| format!("resolve peer {host}:{port}"));
    }
    if let Ok(ip) = trimmed_host.parse::<IpAddr>() {
        if is_fake_ip(ip) {
            let err = std::io::Error::new(
                std::io::ErrorKind::HostUnreachable,
                format!("refusing direct resolution of synthetic FakeIP {ip}:{port}"),
            );
            return Err(err).with_context(|| format!("resolve peer {host}:{port}"));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let has_tunnel_protection = SOCKET_PROTECTOR
        .read()
        .expect("socket protector lock poisoned")
        .is_some()
        || OUTBOUND_INTERFACE
            .read()
            .expect("outbound interface lock poisoned")
            .is_some();
    let mut saw_fake_ip = false;
    let mut lookup_err = None;
    let mut addrs = Vec::new();
    match tokio::net::lookup_host((trimmed_host, port)).await {
        Ok(iter) => {
            for addr in iter {
                if is_fake_ip(addr.ip()) {
                    saw_fake_ip = true;
                } else if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
            }
        }
        Err(error) => {
            lookup_err = Some(error);
        }
    }

    if addrs.is_empty() && (saw_fake_ip || has_tunnel_protection) {
        tracing::warn!(
            host = %trimmed_host,
            saw_fake_ip,
            has_lookup_error = lookup_err.is_some(),
            "OS DNS produced no routable addresses; falling back to protected UDP DNS"
        );
        match resolve_via_protected_udp_dns(trimmed_host, port).await {
            Ok(resolved) if !resolved.is_empty() => addrs = resolved,
            Ok(_) => {}
            Err(udp_err) => {
                if let Some(error) = lookup_err {
                    let err = std::io::Error::new(
                        std::io::ErrorKind::HostUnreachable,
                        format!("{host}:{port}: {error}; protected UDP DNS failed: {udp_err:#}"),
                    );
                    return Err(err).with_context(|| format!("resolve peer {host}:{port}"));
                }
                return Err(udp_err);
            }
        }
    } else if let Some(error) = lookup_err {
        let err = std::io::Error::new(
            std::io::ErrorKind::HostUnreachable,
            format!("{host}:{port}: {error}"),
        );
        return Err(err).with_context(|| format!("resolve peer {host}:{port}"));
    }
    if addrs.is_empty() {
        let err = std::io::Error::new(
            std::io::ErrorKind::HostUnreachable,
            format!("peer resolved to no routable addresses: {host}:{port}"),
        );
        return Err(err.into());
    }
    Ok(addrs)
}

fn collect_protected_dns_servers() -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    #[cfg(windows)]
    {
        for addr in windows_udp::detect_physical_dns_servers() {
            if !servers.contains(&addr) {
                servers.push(addr);
            }
        }
    }
    #[cfg(target_os = "linux")]
    if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in resolv.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if let Some(rest) = line.strip_prefix("nameserver")
                && let Ok(ip) = rest.trim().parse::<IpAddr>()
                && is_usable_dns_ip(ip)
            {
                let sa = SocketAddr::new(ip, 53);
                if !servers.contains(&sa) {
                    servers.push(sa);
                }
            }
        }
    }
    for server in FALLBACK_DNS_SERVERS {
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    servers.truncate(8);
    servers
}

async fn resolve_via_protected_udp_dns(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let q_a = build_dns_query(host, 1, 0x4101)?;
    let q_aaaa = build_dns_query(host, 28, 0x4102)?;
    let (sock, dual_stack) = match bind_dual_stack_udp().await {
        Ok(sock) => (sock, true),
        Err(_) => (
            bind_udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?,
            false,
        ),
    };
    for server in collect_protected_dns_servers() {
        if dual_stack {
            let _ = send_to_dual_stack(&sock, &q_a, server).await;
            let _ = send_to_dual_stack(&sock, &q_aaaa, server).await;
        } else if server.is_ipv4() {
            let _ = sock.send_to(&q_a, server).await;
            let _ = sock.send_to(&q_aaaa, server).await;
        }
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 1500];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut got_a = false;
    let mut got_aaaa = false;
    while (!got_a || !got_aaaa) && tokio::time::Instant::now() < deadline {
        let recv_timeout = if out.is_empty() {
            deadline
        } else {
            (tokio::time::Instant::now() + Duration::from_millis(80)).min(deadline)
        };
        match tokio::time::timeout_at(recv_timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n >= 12 => {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                if id != 0x4101 && id != 0x4102 {
                    continue;
                }
                let mut parsed_any = false;
                for ip in parse_dns_answers(&buf[..n]) {
                    if !is_fake_ip(ip) {
                        parsed_any = true;
                        let sa = SocketAddr::new(ip, port);
                        if !out.contains(&sa) {
                            out.push(sa);
                        }
                    }
                }
                if parsed_any {
                    if id == 0x4101 {
                        got_a = true;
                    } else {
                        got_aaaa = true;
                    }
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
    Ok(out)
}

fn build_dns_query(host: &str, qtype: u16, tx_id: u16) -> Result<Vec<u8>> {
    let mut pkt = Vec::with_capacity(64 + host.len());
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&[0; 6]); // AN/NS/AR = 0
    for label in host.trim_end_matches('.').split('.') {
        anyhow::ensure!(
            !label.is_empty() && label.len() <= 63,
            "invalid DNS label in {host}"
        );
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(pkt)
}

fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0usize;
    loop {
        let len = *pkt.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            let _ = pkt.get(pos + 1)?;
            return Some(pos + 2);
        }
        if (len & 0xC0) != 0 {
            return None;
        }
        pos = pos.checked_add(1 + usize::from(len))?;
        jumps += 1;
        if jumps > 128 || pos > pkt.len() {
            return None;
        }
    }
}

fn parse_dns_answers(pkt: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if pkt.len() < 12 || (pkt[2] & 0x80) == 0 || (pkt[3] & 0x0F) != 0 {
        return out;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        let Some(next) = skip_dns_name(pkt, pos) else {
            return out;
        };
        if next + 4 > pkt.len() {
            return out;
        }
        pos = next + 4;
    }
    for _ in 0..ancount {
        let Some(next) = skip_dns_name(pkt, pos) else {
            break;
        };
        if next + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[next], pkt[next + 1]]);
        let rclass = u16::from_be_bytes([pkt[next + 2], pkt[next + 3]]);
        let rdlen = u16::from_be_bytes([pkt[next + 8], pkt[next + 9]]) as usize;
        let rdata = next + 10;
        if rdata + rdlen > pkt.len() {
            break;
        }
        if rclass == 1 {
            if rtype == 1 && rdlen == 4 {
                out.push(IpAddr::V4(Ipv4Addr::new(
                    pkt[rdata],
                    pkt[rdata + 1],
                    pkt[rdata + 2],
                    pkt[rdata + 3],
                )));
            } else if rtype == 28 && rdlen == 16 {
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&pkt[rdata..rdata + 16]);
                out.push(IpAddr::V6(Ipv6Addr::from(oct)));
            }
        }
        pos = rdata + rdlen;
    }
    out
}

pub async fn connect_tcp_host_port(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = resolve_host_non_fakeip(host, port)
        .await
        .with_context(|| format!("resolve TCP peer {host}:{port}"))?;
    if addrs.len() == 1 {
        return connect_tcp_addr(addrs[0])
            .await
            .with_context(|| format!("connect target {}", addrs[0]));
    }
    let mut racers = JoinSet::new();
    for addr in addrs {
        racers.spawn(async move { connect_tcp_addr(addr).await.map_err(|error| (addr, error)) });
    }
    let mut best_error: Option<anyhow::Error> = None;
    while let Some(result) = racers.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                racers.abort_all();
                return Ok(stream);
            }
            Ok(Err((addr, error))) => {
                let candidate = error.context(format!("connect target {addr}"));
                best_error = Some(match best_error {
                    Some(prev) => prefer_dial_error(prev, candidate),
                    None => candidate,
                });
            }
            Err(join_error) => {
                if best_error.is_none() {
                    best_error = Some(anyhow::anyhow!("TCP dial task failed: {join_error}"));
                }
            }
        }
    }
    if let Some(error) = best_error {
        return Err(error);
    }
    let err = std::io::Error::new(
        std::io::ErrorKind::HostUnreachable,
        format!("TCP peer resolved to no addresses: {host}:{port}"),
    );
    Err(err.into())
}

fn dial_error_rank(error: &anyhow::Error) -> u8 {
    for cause in error.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            return match io_err.kind() {
                std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::PermissionDenied => 3,
                std::io::ErrorKind::HostUnreachable => 2,
                std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::NetworkDown
                | std::io::ErrorKind::AddrNotAvailable => 1,
                _ => 2,
            };
        }
    }
    0
}

fn prefer_dial_error(prev: anyhow::Error, next: anyhow::Error) -> anyhow::Error {
    if dial_error_rank(&next) >= dial_error_rank(&prev) {
        next
    } else {
        prev
    }
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

pub fn reset_tcp_stream(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

pub fn is_connection_reset_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| {
                matches!(
                    io_err.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                )
            })
    })
}

pub fn enable_tcp_keepalive(stream: &TcpStream) {
    let socket = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_TIME)
        .with_interval(TCP_KEEPALIVE_TIME);
    let _ = socket.set_tcp_keepalive(&keepalive);
}

async fn connect_tcp_addr_inner(addr: SocketAddr) -> Result<TcpStream> {
    if is_fake_ip(addr.ip()) {
        tracing::warn!(
            target = %addr,
            "refusing direct TCP dial to synthetic FakeIP"
        );
        let err = std::io::Error::new(
            std::io::ErrorKind::HostUnreachable,
            format!("refusing direct TCP dial to synthetic FakeIP {addr}"),
        );
        return Err(err).with_context(|| format!("connect TCP peer {addr}"));
    }
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
    let socket = bind_udp_std_inner(addr, false)?;
    UdpSocket::from_std(socket).context("create tokio UDP socket from protected socket")
}

pub async fn bind_tunnel_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = bind_udp_std_inner(addr, true)?;
    UdpSocket::from_std(socket).context("create tokio UDP socket from protected socket")
}

pub async fn bind_dual_stack_udp() -> Result<UdpSocket> {
    bind_dual_stack_udp_inner(false).await
}

pub async fn bind_dual_stack_tunnel_udp() -> Result<UdpSocket> {
    bind_dual_stack_udp_inner(true).await
}

async fn bind_dual_stack_udp_inner(large_buffers: bool) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("create dual-stack UDP socket")?;
    socket.set_only_v6(false).context("enable dual-stack UDP")?;
    socket
        .set_nonblocking(true)
        .context("set dual-stack UDP socket nonblocking")?;
    if large_buffers {
        configure_udp_socket_buffers(&socket);
    }
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
    bind_udp_std_inner(addr, false)
}

pub fn bind_tunnel_udp_std(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    bind_udp_std_inner(addr, true)
}

fn bind_udp_std_inner(addr: SocketAddr, large_buffers: bool) -> Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)
        .with_context(|| format!("bind protected UDP socket on {addr}"))?;
    if large_buffers {
        configure_udp_socket_buffers(&socket2::SockRef::from(&socket));
    }
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
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GetAdaptersAddresses, GetBestInterfaceEx,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET as WS_AF_INET, AF_INET6 as WS_AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN,
        SOCKADDR_IN6,
    };

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

    unsafe fn pwstr_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
    }

    unsafe fn sockaddr_to_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        let fam = unsafe { (*sa).sa_family };
        if fam == WS_AF_INET {
            let sin = unsafe { &*(sa.cast::<SOCKADDR_IN>()) };
            let ip = Ipv4Addr::from(unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes());
            Some(IpAddr::V4(ip))
        } else if fam == WS_AF_INET6 {
            let sin6 = unsafe { &*(sa.cast::<SOCKADDR_IN6>()) };
            let ip = Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte });
            Some(IpAddr::V6(ip))
        } else {
            None
        }
    }

    struct PhysicalCandidate {
        name: String,
        if_index_v4: u32,
        if_index_v6: u32,
        metric_v4: u32,
        metric_v6: u32,
        has_v4_gw: bool,
        has_v6_gw: bool,
        is_bridge: bool,
        dns_servers: Vec<IpAddr>,
    }

    fn enumerate_physical_candidates() -> Vec<PhysicalCandidate> {
        let mut size: u32 = 32 * 1024;
        let mut buf: Vec<u8> = vec![0u8; size as usize];
        for _ in 0..3 {
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_INCLUDE_GATEWAYS,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                    &mut size,
                )
            };
            if rc == NO_ERROR {
                break;
            }
            if rc == ERROR_BUFFER_OVERFLOW {
                buf.resize(size as usize, 0);
                continue;
            }
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut cur = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !cur.is_null() {
            let adapter = unsafe { &*cur };
            cur = adapter.Next;
            if adapter.OperStatus != IfOperStatusUp {
                continue;
            }
            let name = unsafe { pwstr_to_string(adapter.FriendlyName) };
            let desc = unsafe { pwstr_to_string(adapter.Description) };
            if is_tunnel_or_vpn_adapter(adapter.IfType, &name, &desc) {
                continue;
            }

            let mut has_v4_gw = false;
            let mut has_v6_gw = false;
            let mut gw = adapter.FirstGatewayAddress;
            while !gw.is_null() {
                let gw_ref = unsafe { &*gw };
                if let Some(ip) = unsafe { sockaddr_to_ip(gw_ref.Address.lpSockaddr) } {
                    match ip {
                        IpAddr::V4(ip)
                            if !ip.is_unspecified()
                                && !ip.is_loopback()
                                && !is_fake_ip(IpAddr::V4(ip)) =>
                        {
                            has_v4_gw = true;
                        }
                        IpAddr::V6(ip)
                            if !ip.is_unspecified()
                                && !ip.is_loopback()
                                && !is_fake_ip(IpAddr::V6(ip)) =>
                        {
                            has_v6_gw = true;
                        }
                        _ => {}
                    }
                }
                gw = gw_ref.Next;
            }

            if !has_v4_gw && !has_v6_gw {
                continue;
            }
            let mut dns_servers = Vec::new();
            let mut dns = adapter.FirstDnsServerAddress;
            while !dns.is_null() {
                let dns_ref = unsafe { &*dns };
                if let Some(ip) = unsafe { sockaddr_to_ip(dns_ref.Address.lpSockaddr) }
                    && is_usable_dns_ip(ip)
                    && !dns_servers.contains(&ip)
                {
                    dns_servers.push(ip);
                }
                dns = dns_ref.Next;
            }
            let if_index_v4 = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            out.push(PhysicalCandidate {
                is_bridge: is_hypervisor_bridge_adapter(&name, &desc),
                name,
                if_index_v4,
                if_index_v6: adapter.Ipv6IfIndex,
                metric_v4: adapter.Ipv4Metric,
                metric_v6: adapter.Ipv6Metric,
                has_v4_gw,
                has_v6_gw,
                dns_servers,
            });
        }
        out
    }

    pub(super) fn detect_physical_dns_servers() -> Vec<SocketAddr> {
        let outbound = OUTBOUND_INTERFACE
            .read()
            .expect("outbound interface lock poisoned")
            .clone();
        let mut candidates = enumerate_physical_candidates();
        candidates.sort_by_key(|c| {
            let matches_outbound = outbound.as_ref().is_some_and(|iface| {
                (iface.ipv4_index.is_some() && iface.ipv4_index == Some(c.if_index_v4))
                    || (iface.ipv6_index.is_some() && iface.ipv6_index == Some(c.if_index_v6))
            });
            (!matches_outbound, c.is_bridge, c.metric_v4.min(c.metric_v6))
        });
        let mut out = Vec::new();
        for c in candidates {
            for ip in c.dns_servers {
                let sa = SocketAddr::new(ip, 53);
                if !out.contains(&sa) {
                    out.push(sa);
                }
            }
        }
        out
    }

    pub(super) fn detect_default_interface() -> Option<OutboundInterface> {
        let probe_v4 = SockAddrIn {
            sin_family: AF_INET,
            sin_port: 53u16.to_be(),
            sin_addr: [8, 8, 8, 8],
            sin_zero: [0; 8],
        };
        let mut idx_v4 = 0u32;
        let best_v4 =
            (unsafe { GetBestInterfaceEx((&probe_v4 as *const SockAddrIn).cast(), &mut idx_v4) }
                == 0
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
        let best_v6 =
            (unsafe { GetBestInterfaceEx((&probe_v6 as *const SockAddrIn6).cast(), &mut idx_v6) }
                == 0
                && idx_v6 != 0)
                .then_some(idx_v6);

        let candidates = enumerate_physical_candidates();
        if !candidates.is_empty() {
            let chosen_v4 = best_v4
                .and_then(|idx| {
                    candidates
                        .iter()
                        .find(|c| c.has_v4_gw && c.if_index_v4 == idx && !c.is_bridge)
                })
                .or_else(|| {
                    candidates
                        .iter()
                        .filter(|c| c.has_v4_gw && c.if_index_v4 != 0)
                        .min_by_key(|c| (c.is_bridge, c.metric_v4, c.if_index_v4))
                });

            let chosen_v6 = best_v6
                .and_then(|idx| {
                    candidates
                        .iter()
                        .find(|c| c.has_v6_gw && c.if_index_v6 == idx && !c.is_bridge)
                })
                .or_else(|| {
                    candidates
                        .iter()
                        .filter(|c| c.has_v6_gw && c.if_index_v6 != 0)
                        .min_by_key(|c| (c.is_bridge, c.metric_v6, c.if_index_v6))
                })
                .or_else(|| chosen_v4.filter(|c| c.if_index_v6 != 0));

            let ipv4_index = chosen_v4.map(|c| c.if_index_v4);
            let ipv6_index = chosen_v6.map(|c| c.if_index_v6);
            let name = chosen_v4
                .or(chosen_v6)
                .map(|c| c.name.clone())
                .filter(|s| !s.is_empty());
            if ipv4_index.is_some() || ipv6_index.is_some() {
                return Some(OutboundInterface {
                    name,
                    ipv4_index,
                    ipv6_index,
                });
            }
        }

        tracing::warn!(
            best_v4 = ?best_v4,
            best_v6 = ?best_v6,
            "no physical outbound adapter with gateway found on Windows"
        );
        None
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
            anyhow::bail!(
                "disable Windows UDP connreset failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }
}

#[cfg(windows)]
pub fn disable_windows_udp_connreset<S: std::os::windows::io::AsRawSocket>(
    socket: &S,
) -> Result<()> {
    windows_udp::disable_connreset(socket)
}

#[cfg(not(windows))]
pub fn disable_windows_udp_connreset<T>(_: &T) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_tunnel_and_fake_ip_ranges() {
        assert!(is_fake_ip("198.18.0.1".parse().unwrap()));
        assert!(is_fake_ip("198.19.255.254".parse().unwrap()));
        assert!(!is_fake_ip("198.20.0.1".parse().unwrap()));
        assert!(!is_fake_ip("8.8.8.8".parse().unwrap()));
        assert!(is_fake_ip("fdfe:dcba:9877::1".parse().unwrap()));
        assert!(!is_fake_ip("fdfe:dcba:9878::1".parse().unwrap()));
        assert!(!is_fake_ip("2001:4860:4860::8888".parse().unwrap()));

        assert!(is_tunnel_or_vpn_adapter(53, "wintun", "wintun Tunnel"));
        assert!(is_tunnel_or_vpn_adapter(
            53,
            "Tailscale",
            "Tailscale Tunnel"
        ));
        assert!(is_tunnel_or_vpn_adapter(
            6,
            "以太网 5",
            "TAP-Windows Adapter V9 #2"
        ));
        assert!(!is_tunnel_or_vpn_adapter(
            71,
            "WLAN 2",
            "Intel(R) Wi-Fi 6E AX211 160MHz #2"
        ));
        assert!(is_hypervisor_bridge_adapter(
            "vEthernet (WSL)",
            "Hyper-V Virtual Ethernet Adapter"
        ));
    }

    #[tokio::test]
    async fn rejects_direct_dial_to_fake_ip() {
        let err = connect_tcp_addr("198.18.0.214:443".parse().unwrap())
            .await
            .unwrap_err();
        let has_unreachable = err.chain().any(|c| {
            c.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::HostUnreachable)
        });
        assert!(has_unreachable, "unexpected error: {err:#}");
    }

    #[test]
    fn dns_wire_codec_round_trips_answers() {
        let q = build_dns_query("example.com", 1, 0x4101).unwrap();
        let mut resp = q.clone();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[6] = 0x00;
        resp[7] = 0x01; // 1 answer
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to example.com
        resp.extend_from_slice(&1u16.to_be_bytes()); // A
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&[93, 184, 216, 34]);
        assert_eq!(
            parse_dns_answers(&resp),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    #[test]
    fn default_outbound_interface_never_selects_tunnel_adapter() {
        if let Some(iface) = detect_default_outbound_interface()
            && let Some(name) = iface.name.as_deref()
        {
            assert!(
                !is_tunnel_or_vpn_adapter(0, name, ""),
                "selected tunnel interface: {iface:?}"
            );
        }
    }
}
