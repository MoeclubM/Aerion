pub(crate) use aerion::padding::PaddingScheme;
pub(crate) use aerion::tls;
pub(crate) use anyhow::{Context, Result};
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use std::net::SocketAddr;
pub(crate) use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(crate) use tokio::net::{TcpListener, TcpStream};
pub(crate) use tokio::time::{Duration, timeout};

pub(crate) async fn write_socks_connect(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let SocketAddr::V4(target) = target else {
        anyhow::bail!("test target must be IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    Ok(())
}

pub(crate) async fn write_socks_udp_associate(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

pub(crate) async fn read_socks_reply_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    anyhow::ensure!(
        head[0] == 0x05 && head[1] == 0x00,
        "SOCKS reply failed: {head:?}"
    );
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
            Ok(SocketAddr::from((
                [rest[0], rest[1], rest[2], rest[3]],
                u16::from_be_bytes([rest[4], rest[5]]),
            )))
        }
        other => anyhow::bail!("unsupported SOCKS reply address type: {other}"),
    }
}

pub(crate) fn socks_udp_packet(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let SocketAddr::V4(target) = target else {
        anyhow::bail!("test UDP target must be IPv4");
    };
    let mut packet = vec![0, 0, 0, 0x01];
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub(crate) fn socks_udp_payload(packet: &[u8]) -> Result<&[u8]> {
    anyhow::ensure!(packet.len() >= 10, "SOCKS UDP response is too short");
    anyhow::ensure!(
        &packet[..4] == [0, 0, 0, 0x01],
        "unexpected SOCKS UDP header"
    );
    Ok(&packet[10..])
}

pub(crate) fn unused_udp_addr() -> Result<SocketAddr> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?)
}

pub(crate) fn unused_tcp_addr() -> Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

pub(crate) async fn socks_echo(
    client_addr: SocketAddr,
    echo_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let mut socks = TcpStream::connect(client_addr).await?;
    socks.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    socks.read_exact(&mut greeting).await?;
    anyhow::ensure!(greeting == [0x05, 0x00], "unexpected SOCKS greeting reply");
    write_socks_connect(&mut socks, echo_addr).await?;
    let mut reply = [0u8; 10];
    socks.read_exact(&mut reply).await?;
    anyhow::ensure!(reply[1] == 0x00, "SOCKS connect failed: {:?}", reply);
    socks.write_all(payload).await?;
    let mut echoed = vec![0u8; payload.len()];
    socks.read_exact(&mut echoed).await?;
    anyhow::ensure!(echoed == payload, "echo payload mismatch");
    Ok(())
}
