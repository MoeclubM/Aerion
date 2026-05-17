use crate::protocol::ProxyTarget;
use anyhow::{Context, Result, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum SocksRequest {
    Connect(ProxyTarget),
    UdpAssociate,
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
    write_connect_request(&mut stream, target).await?;
    read_connect_reply(&mut stream, upstream).await?;
    Ok(stream)
}

async fn write_connect_request(stream: &mut TcpStream, target: &ProxyTarget) -> Result<()> {
    let mut request = vec![0x05, 0x01, 0x00];
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
        .context("write SOCKS connect request")
}

async fn read_connect_reply(stream: &mut TcpStream, upstream: SocketAddr) -> Result<()> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("read SOCKS connect reply")?;
    ensure!(header[0] == 0x05, "invalid SOCKS reply version");
    ensure!(
        header[1] == 0x00,
        "SOCKS upstream {upstream} connect failed with code {}",
        header[1]
    );
    match header[3] {
        0x01 => {
            let mut bound = [0u8; 4];
            stream
                .read_exact(&mut bound)
                .await
                .context("read SOCKS IPv4 bind address")?;
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
        }
        0x04 => {
            let mut bound = [0u8; 16];
            stream
                .read_exact(&mut bound)
                .await
                .context("read SOCKS IPv6 bind address")?;
        }
        other => bail!("unsupported SOCKS bind address type: {other}"),
    }
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .context("read SOCKS bind port")?;
    Ok(())
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
