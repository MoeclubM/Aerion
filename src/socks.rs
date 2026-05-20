use crate::protocol::ProxyTarget;
use anyhow::{Context, Result, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub enum SocksRequest {
    Connect(ProxyTarget),
    UdpAssociate,
}

pub async fn handle_socks_greeting(stream: &mut TcpStream) -> Result<(SocksRequest, TcpStream)> {
    let request = read_request(stream).await?;
    Ok((request, stream.try_clone()?))
}

pub struct SocksUdpAssociation {
    pub control: TcpStream,
    pub udp: UdpSocket,
    pub bind: SocketAddr,
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
        .write_all(&[0x05, 0x00])
        .await
        .context("write SOCKS method response")?;

    let mut request = [0u8; 4];
    stream
        .read_exact(&mut request)
        .await
        .context("read SOCKS request")?;
    ensure!(request[0] == 0x05, "invalid SOCKS version");
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
    ensure!(
        header[1] == 0x00,
        "SOCKS upstream {upstream} connect failed with code {}",
        header[1]
    );
    let ip = match header[3] {
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
mod tests {
    use super::*;

    #[test]
    fn udp_associate_uses_upstream_ip_for_unspecified_bind() -> Result<()> {
        assert_eq!(
            normalize_udp_bind("0.0.0.0:5300".parse()?, "192.0.2.10:1080".parse()?),
            "192.0.2.10:5300".parse::<SocketAddr>()?
        );
        assert_eq!(
            normalize_udp_bind("[::]:5300".parse()?, "[2001:db8::1]:1080".parse()?),
            "[2001:db8::1]:5300".parse::<SocketAddr>()?
        );
        assert_eq!(
            normalize_udp_bind("198.51.100.5:5300".parse()?, "192.0.2.10:1080".parse()?),
            "198.51.100.5:5300".parse::<SocketAddr>()?
        );
        Ok(())
    }
}
