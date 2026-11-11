use crate::protocol::{ProxyTarget, target_name};
use crate::{socket_protect, uot};
use anyhow::{Context, Result, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpStream, UdpSocket};

pub const REPLY_SUCCEEDED: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_NOT_ALLOWED: u8 = 0x02;
pub const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub const REPLY_TTL_EXPIRED: u8 = 0x06;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocksConnectError {
    pub code: u8,
    pub upstream: SocketAddr,
}

impl std::fmt::Display for SocksConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SOCKS upstream {} connect failed with code {:#04x} ({})",
            self.upstream,
            self.code,
            reply_code_description(self.code),
        )
    }
}

impl std::error::Error for SocksConnectError {}

pub fn reply_code_description(code: u8) -> &'static str {
    match code {
        REPLY_SUCCEEDED => "succeeded",
        REPLY_GENERAL_FAILURE => "general SOCKS server failure",
        REPLY_NOT_ALLOWED => "connection not allowed by ruleset",
        REPLY_NETWORK_UNREACHABLE => "network unreachable",
        REPLY_HOST_UNREACHABLE => "host unreachable",
        REPLY_CONNECTION_REFUSED => "connection refused",
        REPLY_TTL_EXPIRED => "TTL expired",
        REPLY_COMMAND_NOT_SUPPORTED => "command not supported",
        REPLY_ADDRESS_TYPE_NOT_SUPPORTED => "address type not supported",
        _ => "unassigned SOCKS error",
    }
}

pub fn http_status_for_reply_code(code: u8) -> (u16, &'static str, &'static str) {
    match code {
        REPLY_NOT_ALLOWED => (403, "Forbidden", "connection_refused"),
        REPLY_TTL_EXPIRED => (504, "Gateway Timeout", "connection_timeout"),
        REPLY_COMMAND_NOT_SUPPORTED | REPLY_ADDRESS_TYPE_NOT_SUPPORTED => {
            (501, "Not Implemented", "http_request_error")
        }
        REPLY_NETWORK_UNREACHABLE => (502, "Bad Gateway", "destination_ip_unroutable"),
        REPLY_HOST_UNREACHABLE => (502, "Bad Gateway", "dns_error"),
        REPLY_CONNECTION_REFUSED => (502, "Bad Gateway", "connection_refused"),
        _ => (502, "Bad Gateway", "proxy_internal_error"),
    }
}

pub fn reply_code_for_http_connect_failure(status: u16, proxy_status: Option<&str>) -> u8 {
    if status == 403 || status == 407 {
        return REPLY_NOT_ALLOWED;
    }
    if status == 504 {
        return REPLY_TTL_EXPIRED;
    }
    if status == 501 {
        return REPLY_COMMAND_NOT_SUPPORTED;
    }
    if let Some(raw) = proxy_status {
        let lower = raw.to_ascii_lowercase();
        if lower.contains("error=connection_timeout") {
            return REPLY_TTL_EXPIRED;
        }
        if lower.contains("error=destination_ip_unroutable") {
            return REPLY_NETWORK_UNREACHABLE;
        }
        if lower.contains("error=dns_error") || lower.contains("error=destination_unavailable") {
            return REPLY_HOST_UNREACHABLE;
        }
        if lower.contains("error=connection_refused") {
            return REPLY_CONNECTION_REFUSED;
        }
    }
    REPLY_GENERAL_FAILURE
}

pub fn reply_code_for_error(error: &anyhow::Error) -> u8 {
    for cause in error.chain() {
        if let Some(socks_err) = cause.downcast_ref::<SocksConnectError>()
            && socks_err.code != REPLY_SUCCEEDED
        {
            return socks_err.code;
        }
    }
    for cause in error.chain() {
        if cause.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
            return REPLY_TTL_EXPIRED;
        }
    }
    let mut io_code = None;
    for cause in error.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>()
            && let Some(mapped) = reply_code_from_io_error(io_err)
        {
            io_code = Some(mapped);
        }
    }
    if let Some(code) = io_code {
        return code;
    }
    reply_code_from_message(&format!("{error:#}"))
}

pub fn reply_code_for_proxy_error(error: &anyhow::Error) -> u8 {
    for cause in error.chain() {
        if let Some(socks_err) = cause.downcast_ref::<SocksConnectError>()
            && socks_err.code != REPLY_SUCCEEDED
        {
            return socks_err.code;
        }
    }
    for cause in error.chain() {
        if cause.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
            return REPLY_TTL_EXPIRED;
        }
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            match io_err.kind() {
                std::io::ErrorKind::TimedOut => return REPLY_TTL_EXPIRED,
                std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::NetworkDown => {
                    return REPLY_NETWORK_UNREACHABLE;
                }
                _ => {}
            }
        }
    }
    REPLY_GENERAL_FAILURE
}

fn reply_code_from_io_error(io_err: &std::io::Error) -> Option<u8> {
    match io_err.kind() {
        std::io::ErrorKind::PermissionDenied => return Some(REPLY_NOT_ALLOWED),
        std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::NetworkDown => {
            return Some(REPLY_NETWORK_UNREACHABLE);
        }
        std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::AddrNotAvailable => {
            return Some(REPLY_HOST_UNREACHABLE);
        }
        std::io::ErrorKind::ConnectionRefused => return Some(REPLY_CONNECTION_REFUSED),
        std::io::ErrorKind::TimedOut => return Some(REPLY_TTL_EXPIRED),
        std::io::ErrorKind::Unsupported => return Some(REPLY_COMMAND_NOT_SUPPORTED),
        std::io::ErrorKind::InvalidInput => return Some(REPLY_ADDRESS_TYPE_NOT_SUPPORTED),
        _ => {}
    }
    #[cfg(windows)]
    if let Some(raw) = io_err.raw_os_error() {
        return match raw {
            10013 => Some(REPLY_NOT_ALLOWED),
            10050 | 10051 => Some(REPLY_NETWORK_UNREACHABLE),
            10064 | 10065 | 11001 | 11002 | 11004 => Some(REPLY_HOST_UNREACHABLE),
            10061 => Some(REPLY_CONNECTION_REFUSED),
            10060 => Some(REPLY_TTL_EXPIRED),
            _ => None,
        };
    }
    None
}

fn reply_code_from_message(raw: &str) -> u8 {
    let text = raw.to_ascii_lowercase();
    if text.contains("error=connection_refused")
        || text.contains("connection refused")
        || text.contains("actively refused")
        || text.contains("econnrefused")
    {
        return REPLY_CONNECTION_REFUSED;
    }
    if text.contains("error=connection_timeout")
        || text.contains(" 504 ")
        || text.ends_with(" 504")
        || text.contains("timed out")
        || text.contains("i/o timeout")
        || text.contains("deadline exceeded")
        || text.contains("ttl expired")
    {
        return REPLY_TTL_EXPIRED;
    }
    if text.contains("error=destination_ip_unroutable")
        || text.contains("network is unreachable")
        || text.contains("network unreachable")
        || text.contains("network is down")
        || text.contains("enetunreach")
    {
        return REPLY_NETWORK_UNREACHABLE;
    }
    if text.contains("error=dns_error")
        || text.contains("error=destination_unavailable")
        || text.contains("no route to host")
        || text.contains("host is unreachable")
        || text.contains("host unreachable")
        || text.contains("host is down")
        || text.contains("ehostunreach")
        || text.contains("no such host")
        || text.contains("name or service not known")
        || text.contains("nodename nor servname")
        || text.contains("temporary failure in name resolution")
        || text.contains("resolved to no addresses")
        || text.contains("resolve tcp peer")
        || text.contains("lookup ")
    {
        return REPLY_HOST_UNREACHABLE;
    }
    if text.contains(" 403 ")
        || text.ends_with(" 403")
        || text.contains(" 407 ")
        || text.ends_with(" 407")
        || text.contains("permission denied")
        || text.contains("not allowed")
        || text.contains("administratively prohibited")
    {
        return REPLY_NOT_ALLOWED;
    }
    REPLY_GENERAL_FAILURE
}

#[derive(Clone, Debug)]
pub struct SocksProxyClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    pub password: String,
    pub udp: bool,
}

pub enum SocksRequest {
    Connect(ProxyTarget),
    UdpAssociate,
}

pub async fn handle_socks_greeting(mut stream: TcpStream) -> Result<(SocksRequest, TcpStream)> {
    let request = read_request(&mut stream).await?;
    Ok((request, stream))
}

pub struct SocksUdpAssociation {
    pub control: TcpStream,
    pub udp: UdpSocket,
    pub bind: SocketAddr,
}

pub async fn run_socks_proxy_client(config: SocksProxyClientConfig) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind SOCKS proxy listener on {}", config.listen))?;
    run_socks_proxy_client_listener(listener, config).await
}

pub async fn run_socks_proxy_client_listener(
    listener: tokio::net::TcpListener,
    config: SocksProxyClientConfig,
) -> Result<()> {
    tracing::info!("SOCKS proxy client listening on socks5://{}", config.listen);
    loop {
        let (stream, peer) = crate::listener::accept_tcp(&listener)
            .await
            .context("accept SOCKS client")?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_socks_proxy_client(stream, config).await {
                tracing::warn!("SOCKS proxy client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_socks_proxy_client(
    mut local: TcpStream,
    config: SocksProxyClientConfig,
) -> Result<()> {
    match read_request(&mut local).await? {
        SocksRequest::Connect(target) => {
            let mut remote = match connect_proxy_tcp(&config, &target).await {
                Ok(remote) => remote,
                Err(error) => {
                    let _ = write_reply(&mut local, reply_code_for_proxy_error(&error)).await;
                    return Err(error);
                }
            };
            write_reply(&mut local, REPLY_SUCCEEDED).await?;
            tracing::info!("SOCKS proxying {}", target_name(&target));
            if let Err(error) = copy_bidirectional(&mut local, &mut remote)
                .await
                .context("relay SOCKS proxy TCP tunnel")
            {
                if socket_protect::is_connection_reset_error(&error) {
                    socket_protect::reset_tcp_stream(&local);
                    socket_protect::reset_tcp_stream(&remote);
                }
                return Err(error);
            }
            Ok(())
        }
        SocksRequest::UdpAssociate => {
            if !config.udp {
                let _ = write_reply(&mut local, REPLY_COMMAND_NOT_SUPPORTED).await;
                bail!("SOCKS proxy outbound UDP is disabled")
            }
            handle_socks_proxy_udp_associate(local, &config).await
        }
    }
}

pub async fn read_request(stream: &mut TcpStream) -> Result<SocksRequest> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .context("read SOCKS greeting")?;
    ensure!(header[0] == 0x05, "only SOCKS5 is supported");
    let mut methods = vec![0u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .context("read SOCKS methods")?;
    stream
        .write_all(&[0x05, if methods.contains(&0x00) { 0x00 } else { 0xff }])
        .await
        .context("write SOCKS method response")?;
    ensure!(
        methods.contains(&0x00),
        "SOCKS client did not offer no-authentication method"
    );

    let mut request = [0u8; 4];
    stream
        .read_exact(&mut request)
        .await
        .context("read SOCKS request")?;
    ensure!(request[0] == 0x05, "invalid SOCKS version");
    ensure!(request[2] == 0x00, "invalid SOCKS reserved byte");
    let target = match request[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream
                .read_exact(&mut ip)
                .await
                .context("read SOCKS IPv4 target")?;
            let port = read_port(stream).await?;
            ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .context("read SOCKS domain length")?;
            let mut host = vec![0u8; length[0] as usize];
            stream
                .read_exact(&mut host)
                .await
                .context("read SOCKS domain target")?;
            let port = read_port(stream).await?;
            ProxyTarget::Domain(
                String::from_utf8(host).context("decode SOCKS domain target")?,
                port,
            )
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream
                .read_exact(&mut ip)
                .await
                .context("read SOCKS IPv6 target")?;
            let port = read_port(stream).await?;
            ProxyTarget::Ip(SocketAddr::new(IpAddr::V6(ip.into()), port))
        }
        other => bail!("unsupported SOCKS address type: {other}"),
    };
    match request[1] {
        0x01 => Ok(SocksRequest::Connect(target)),
        0x03 => Ok(SocksRequest::UdpAssociate),
        other => bail!("unsupported SOCKS command: {other}"),
    }
}

pub async fn write_reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    write_reply_with_bind(
        stream,
        code,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    )
    .await
}

pub async fn connect_tcp(upstream: SocketAddr, target: &ProxyTarget) -> Result<TcpStream> {
    let mut stream = connect_no_auth(upstream).await?;
    write_proxy_request(&mut stream, 0x01, target).await?;
    read_proxy_reply(&mut stream, upstream).await?;
    Ok(stream)
}

async fn connect_proxy_tcp(
    config: &SocksProxyClientConfig,
    target: &ProxyTarget,
) -> Result<TcpStream> {
    let mut stream = connect_proxy_server(config).await?;
    let upstream = stream
        .peer_addr()
        .context("read SOCKS proxy peer address")?;
    write_proxy_request(&mut stream, 0x01, target).await?;
    read_proxy_reply(&mut stream, upstream).await?;
    Ok(stream)
}

pub async fn udp_associate(upstream: SocketAddr) -> Result<SocksUdpAssociation> {
    let mut control = connect_no_auth(upstream).await?;
    let local_ip = control.local_addr()?.ip();
    let bind_request = if upstream.is_ipv4() {
        ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    } else {
        ProxyTarget::Ip(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            0,
        ))
    };
    write_proxy_request(&mut control, 0x03, &bind_request).await?;
    let bind = normalize_udp_bind(read_proxy_reply(&mut control, upstream).await?, upstream);
    let udp = UdpSocket::bind(SocketAddr::new(local_ip, 0))
        .await
        .with_context(|| format!("bind SOCKS UDP client socket for {upstream}"))?;
    Ok(SocksUdpAssociation { control, udp, bind })
}

async fn connect_proxy_udp_associate(
    config: &SocksProxyClientConfig,
) -> Result<SocksUdpAssociation> {
    let mut control = connect_proxy_server(config).await?;
    let upstream = control
        .peer_addr()
        .context("read SOCKS proxy peer address")?;
    let local_ip = control.local_addr()?.ip();
    let bind_request = if upstream.is_ipv4() {
        ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    } else {
        ProxyTarget::Ip(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            0,
        ))
    };
    write_proxy_request(&mut control, 0x03, &bind_request).await?;
    let bind = normalize_udp_bind(read_proxy_reply(&mut control, upstream).await?, upstream);
    let udp = socket_protect::bind_udp(SocketAddr::new(local_ip, 0))
        .await
        .with_context(|| format!("bind SOCKS proxy UDP socket for {upstream}"))?;
    Ok(SocksUdpAssociation { control, udp, bind })
}

async fn connect_proxy_server(config: &SocksProxyClientConfig) -> Result<TcpStream> {
    let mut stream = socket_protect::connect_tcp_host_port(&config.server_host, config.server_port)
        .await
        .with_context(|| {
            format!(
                "connect SOCKS proxy server {}:{}",
                config.server_host, config.server_port
            )
        })?;
    negotiate_proxy_auth(&mut stream, &config.username, &config.password).await?;
    Ok(stream)
}

async fn negotiate_proxy_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<()> {
    if username.is_empty() && password.is_empty() {
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .context("write SOCKS proxy greeting")?;
        let mut method = [0u8; 2];
        stream
            .read_exact(&mut method)
            .await
            .context("read SOCKS proxy method response")?;
        ensure!(
            method == [0x05, 0x00],
            "SOCKS proxy rejected no-auth method"
        );
        return Ok(());
    }

    ensure!(
        username.len() <= u8::MAX as usize,
        "SOCKS username is too long"
    );
    ensure!(
        password.len() <= u8::MAX as usize,
        "SOCKS password is too long"
    );
    stream
        .write_all(&[0x05, 0x01, 0x02])
        .await
        .context("write SOCKS proxy username/password greeting")?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .context("read SOCKS proxy method response")?;
    ensure!(
        method == [0x05, 0x02],
        "SOCKS proxy rejected username/password method"
    );

    let mut auth = Vec::with_capacity(3 + username.len() + password.len());
    auth.push(0x01);
    auth.push(username.len() as u8);
    auth.extend_from_slice(username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    stream
        .write_all(&auth)
        .await
        .context("write SOCKS proxy username/password auth")?;
    let mut response = [0u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .context("read SOCKS proxy auth response")?;
    ensure!(
        response == [0x01, 0x00],
        "SOCKS proxy authentication failed"
    );
    Ok(())
}

async fn handle_socks_proxy_udp_associate(
    mut control: TcpStream,
    config: &SocksProxyClientConfig,
) -> Result<()> {
    let association = match connect_proxy_udp_associate(config).await {
        Ok(association) => association,
        Err(error) => {
            let _ = write_reply(&mut control, reply_code_for_proxy_error(&error)).await;
            return Err(error);
        }
    };
    let _upstream_control = association.control;
    let upstream_udp = association.udp;
    let upstream_bind = association.bind;
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let client_udp = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| {
                format!("bind local SOCKS proxy UDP associate socket on {bind_ip}:0")
            })?,
    );
    write_reply_with_bind(&mut control, 0x00, client_udp.local_addr()?).await?;
    tracing::info!(
        "SOCKS proxy UDP associate listening on {}",
        client_udp.local_addr()?
    );

    let mut peer = None;
    let mut local_packet = vec![0u8; u16::MAX as usize + 512];
    let mut upstream_packet = vec![0u8; u16::MAX as usize + 512];
    let mut control_probe = [0u8; 1];
    loop {
        tokio::select! {
            received = client_udp.recv_from(&mut local_packet) => {
                let (read, client_peer) = received.context("receive SOCKS proxy UDP packet")?;
                let (target, payload) = uot::parse_socks_udp_packet(&local_packet[..read])?;
                peer = Some(client_peer);
                let packet = uot::encode_socks_udp_packet(&target, payload)?;
                upstream_udp.send_to(&packet, upstream_bind)
                    .await
                    .with_context(|| format!("send SOCKS proxy UDP {}", target_name(&target)))?;
            }
            received = upstream_udp.recv_from(&mut upstream_packet) => {
                let (read, _) = received.context("receive SOCKS proxy UDP response")?;
                let (source, payload) = uot::parse_socks_udp_packet(&upstream_packet[..read])?;
                let response = uot::encode_socks_udp_packet(&source, payload)?;
                let peer = peer.context("SOCKS proxy UDP client peer is not known yet")?;
                client_udp.send_to(&response, peer)
                    .await
                    .with_context(|| format!("send SOCKS proxy UDP response to {peer}"))?;
            }
            read = control.read(&mut control_probe) => {
                if read.context("read SOCKS proxy UDP control connection")? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

async fn connect_no_auth(upstream: SocketAddr) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("connect SOCKS upstream {upstream}"))?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .context("write SOCKS greeting")?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .context("read SOCKS method response")?;
    ensure!(
        method == [0x05, 0x00],
        "SOCKS upstream {upstream} rejected no-auth method"
    );
    Ok(stream)
}

async fn write_proxy_request(
    stream: &mut TcpStream,
    command: u8,
    target: &ProxyTarget,
) -> Result<()> {
    let mut request = vec![0x05, command, 0x00];
    match target {
        ProxyTarget::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        },
        ProxyTarget::Domain(host, _) => {
            ensure!(
                host.len() <= u8::MAX as usize,
                "SOCKS domain target is too long: {host}"
            );
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&target_port(target).to_be_bytes());
    stream
        .write_all(&request)
        .await
        .context("write SOCKS request")
}

async fn read_proxy_reply(stream: &mut TcpStream, upstream: SocketAddr) -> Result<SocketAddr> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("read SOCKS reply")?;
    ensure!(header[0] == 0x05, "invalid SOCKS reply version");
    let code = header[1];
    let bound_addr = read_reply_bind_addr(stream, header[3], upstream).await;
    if code != REPLY_SUCCEEDED {
        return Err(anyhow::Error::new(SocksConnectError { code, upstream }));
    }
    bound_addr
}

async fn read_reply_bind_addr(
    stream: &mut TcpStream,
    atyp: u8,
    upstream: SocketAddr,
) -> Result<SocketAddr> {
    let ip = match atyp {
        0x01 => {
            let mut bound = [0u8; 4];
            stream
                .read_exact(&mut bound)
                .await
                .context("read SOCKS IPv4 bind address")?;
            IpAddr::V4(Ipv4Addr::from(bound))
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .context("read SOCKS domain bind length")?;
            let mut bound = vec![0u8; length[0] as usize];
            stream
                .read_exact(&mut bound)
                .await
                .context("read SOCKS domain bind address")?;
            bail!("SOCKS upstream {upstream} returned domain bind address")
        }
        0x04 => {
            let mut bound = [0u8; 16];
            stream
                .read_exact(&mut bound)
                .await
                .context("read SOCKS IPv6 bind address")?;
            IpAddr::V6(bound.into())
        }
        other => bail!("unsupported SOCKS bind address type: {other}"),
    };
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .context("read SOCKS bind port")?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

pub async fn write_reply_with_bind(
    stream: &mut TcpStream,
    code: u8,
    bind: SocketAddr,
) -> Result<()> {
    let mut response = vec![0x05, code, 0x00];
    match bind {
        SocketAddr::V4(addr) => {
            response.push(0x01);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            response.push(0x04);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    stream
        .write_all(&response)
        .await
        .context("write SOCKS reply")
}

async fn read_port(stream: &mut TcpStream) -> Result<u16> {
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .context("read SOCKS target port")?;
    Ok(u16::from_be_bytes(port))
}

fn target_port(target: &ProxyTarget) -> u16 {
    match target {
        ProxyTarget::Ip(addr) => addr.port(),
        ProxyTarget::Domain(_, port) => *port,
    }
}

fn normalize_udp_bind(bind: SocketAddr, upstream: SocketAddr) -> SocketAddr {
    if bind.ip().is_unspecified() {
        SocketAddr::new(upstream.ip(), bind.port())
    } else {
        bind
    }
}

#[cfg(test)]
mod tests;
