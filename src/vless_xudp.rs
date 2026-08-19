use crate::core::CoreSession;
use crate::protocol::{ProxyTarget, resolve_target_addr};
use crate::socket_protect;
use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::UdpSocket;

pub const MUX_DESTINATION: &str = "v1.mux.cool";
pub const MUX_PORT: u16 = 666;

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEPALIVE: u8 = 0x04;
const NETWORK_UDP: u8 = 0x02;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

struct ClientPacket {
    destination: ProxyTarget,
    payload: Vec<u8>,
}

pub fn mux_target() -> ProxyTarget {
    ProxyTarget::Domain(MUX_DESTINATION.to_string(), MUX_PORT)
}

pub fn is_mux_target(target: &ProxyTarget) -> bool {
    matches!(target, ProxyTarget::Domain(host, port) if host.eq_ignore_ascii_case(MUX_DESTINATION) && *port == MUX_PORT)
}

pub async fn relay_server<S>(stream: S, session: CoreSession) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let socket = Arc::new(
        socket_protect::bind_dual_stack_udp()
            .await
            .context("bind XUDP UDP")?,
    );
    let (mut reader, mut writer) = split(stream);
    let mut current_destination = None;
    let mut destination_cache = HashMap::new();
    let udp_to_client = {
        let socket = socket.clone();
        let session = session.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                let (read, source) = socket
                    .recv_from(&mut buffer)
                    .await
                    .context("receive XUDP UDP response")?;
                session.record_download(read).await?;
                let encoded = encode_packet(&ProxyTarget::Ip(source), &buffer[..read])?;
                writer
                    .write_all(&encoded)
                    .await
                    .context("write XUDP response")?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };
    let client_to_udp = async {
        while let Some(packet) = read_packet(&mut reader, &mut current_destination).await? {
            let target =
                target_socket_addr_cached(&packet.destination, &mut destination_cache).await?;
            session.record_upload(packet.payload.len()).await?;
            socket_protect::send_to_dual_stack(&socket, &packet.payload, target)
                .await
                .with_context(|| format!("send XUDP payload to {target}"))?;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = client_to_udp => result,
        result = udp_to_client => result,
    }
}

pub async fn write_client_packet<W>(
    writer: &mut W,
    destination: &ProxyTarget,
    payload: &[u8],
    is_new: bool,
    global_id: &[u8; 8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_client_packet(destination, payload, is_new, global_id)?;
    writer
        .write_all(&encoded)
        .await
        .context("write XUDP packet")
}

pub fn encode_client_packet(
    destination: &ProxyTarget,
    payload: &[u8],
    is_new: bool,
    global_id: &[u8; 8],
) -> Result<Vec<u8>> {
    let mut metadata = vec![
        0u8,
        0u8,
        if is_new { STATUS_NEW } else { STATUS_KEEP },
        0x01,
        NETWORK_UDP,
    ];
    write_destination_xudp(&mut metadata, destination)?;
    if is_new {
        metadata.extend_from_slice(global_id);
    }
    encode_packet_parts(&metadata, payload)
}

pub fn encode_response_packet(source: &ProxyTarget, payload: &[u8]) -> Result<Vec<u8>> {
    encode_packet(source, payload)
}

pub async fn read_response_packet<R>(reader: &mut R) -> Result<Option<(ProxyTarget, Vec<u8>)>>
where
    R: AsyncRead + Unpin,
{
    let mut current_destination = None;
    Ok(read_packet(reader, &mut current_destination)
        .await?
        .map(|packet| (packet.destination, packet.payload)))
}

async fn read_packet<R>(
    reader: &mut R,
    current_destination: &mut Option<ProxyTarget>,
) -> Result<Option<ClientPacket>>
where
    R: AsyncRead + Unpin,
{
    let Some(metadata_len) = read_length_or_eof(reader, "read XUDP metadata length").await? else {
        return Ok(None);
    };
    ensure!(
        metadata_len >= 4,
        "short XUDP metadata length {metadata_len}"
    );
    let mut metadata = vec![0u8; metadata_len as usize];
    reader
        .read_exact(&mut metadata)
        .await
        .context("read XUDP metadata")?;
    let payload_len = read_u16(reader, "read XUDP payload length").await? as usize;
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .await
        .context("read XUDP payload")?;
    decode_packet_parts(&metadata, payload, current_destination)
}

pub fn decode_packet_chunk(
    chunk: &[u8],
    current_destination: &mut Option<ProxyTarget>,
) -> Result<Option<(ProxyTarget, Vec<u8>)>> {
    ensure!(chunk.len() >= 4, "short XUDP packet chunk");
    let metadata_len = u16::from_be_bytes([chunk[0], chunk[1]]) as usize;
    ensure!(
        metadata_len >= 4,
        "short XUDP metadata length {metadata_len}"
    );
    let payload_len_offset = 2 + metadata_len;
    ensure!(
        chunk.len() >= payload_len_offset + 2,
        "truncated XUDP packet chunk"
    );
    let payload_len =
        u16::from_be_bytes([chunk[payload_len_offset], chunk[payload_len_offset + 1]]) as usize;
    let payload_offset = payload_len_offset + 2;
    ensure!(
        chunk.len() == payload_offset + payload_len,
        "XUDP packet chunk has trailing bytes"
    );
    let metadata = &chunk[2..payload_len_offset];
    let payload = chunk[payload_offset..].to_vec();
    decode_packet_parts(metadata, payload, current_destination)
        .map(|packet| packet.map(|packet| (packet.destination, packet.payload)))
}

fn decode_packet_parts(
    metadata: &[u8],
    payload: Vec<u8>,
    current_destination: &mut Option<ProxyTarget>,
) -> Result<Option<ClientPacket>> {
    let status = metadata[2];
    if status == STATUS_END {
        return Ok(None);
    }
    ensure!(
        status == STATUS_NEW || status == STATUS_KEEP,
        "unsupported XUDP status {status:#x}"
    );

    let destination = if metadata.len() > 4 {
        ensure!(
            metadata[4] == NETWORK_UDP,
            "unsupported XUDP network type {}",
            metadata[4]
        );
        let (destination, consumed) = parse_destination_xudp(&metadata[5..])?;
        let trailing = metadata.len() - 5 - consumed;
        if status == STATUS_NEW {
            ensure!(
                trailing == 8,
                "XUDP NEW metadata must include 8-byte GlobalID, got {trailing}"
            );
        } else {
            ensure!(
                trailing == 0,
                "unsupported XUDP metadata tail length {trailing}"
            );
        }
        *current_destination = Some(destination.clone());
        destination
    } else {
        current_destination
            .clone()
            .context("XUDP packet is missing destination metadata")?
    };

    Ok(Some(ClientPacket {
        destination,
        payload,
    }))
}

fn encode_packet(source: &ProxyTarget, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(payload.len() <= u16::MAX as usize, "XUDP payload too large");
    let mut metadata = vec![0u8, 0u8, STATUS_KEEP, 0x01, NETWORK_UDP];
    write_destination_xudp(&mut metadata, source)?;
    encode_packet_parts(&metadata, payload)
}

fn encode_packet_parts(metadata: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        metadata.len() <= u16::MAX as usize,
        "XUDP metadata too large"
    );
    ensure!(payload.len() <= u16::MAX as usize, "XUDP payload too large");
    let mut encoded = Vec::with_capacity(2 + metadata.len() + 2 + payload.len());
    encoded.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    encoded.extend_from_slice(metadata);
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn parse_destination_xudp(bytes: &[u8]) -> Result<(ProxyTarget, usize)> {
    ensure!(bytes.len() >= 3, "missing XUDP destination");
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    match bytes[2] {
        ATYP_IPV4 => {
            ensure!(bytes.len() >= 7, "short XUDP IPv4 destination");
            Ok((
                ProxyTarget::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(bytes[3], bytes[4], bytes[5], bytes[6])),
                    port,
                )),
                7,
            ))
        }
        ATYP_IPV6 => {
            ensure!(bytes.len() >= 19, "short XUDP IPv6 destination");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[3..19]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                19,
            ))
        }
        ATYP_DOMAIN => {
            ensure!(bytes.len() >= 4, "short XUDP domain destination");
            let len = bytes[3] as usize;
            ensure!(bytes.len() >= 4 + len, "short XUDP domain destination");
            Ok((
                ProxyTarget::Domain(
                    String::from_utf8(bytes[4..4 + len].to_vec()).context("decode XUDP domain")?,
                    port,
                ),
                4 + len,
            ))
        }
        other => bail!("unsupported XUDP address type {other:#x}"),
    }
}

fn write_destination_xudp(buffer: &mut Vec<u8>, destination: &ProxyTarget) -> Result<()> {
    let port = match destination {
        ProxyTarget::Ip(addr) => addr.port(),
        ProxyTarget::Domain(_, port) => *port,
    };
    buffer.extend_from_slice(&port.to_be_bytes());
    match destination {
        ProxyTarget::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buffer.push(ATYP_IPV4);
                buffer.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buffer.push(ATYP_IPV6);
                buffer.extend_from_slice(&ip.octets());
            }
        },
        ProxyTarget::Domain(host, _) => {
            ensure!(host.len() <= u8::MAX as usize, "XUDP domain too long");
            buffer.push(ATYP_DOMAIN);
            buffer.push(host.len() as u8);
            buffer.extend_from_slice(host.as_bytes());
        }
    }
    Ok(())
}

async fn target_socket_addr_cached(
    target: &ProxyTarget,
    cache: &mut HashMap<String, SocketAddr>,
) -> Result<SocketAddr> {
    let key = match target {
        ProxyTarget::Ip(addr) => return Ok(*addr),
        ProxyTarget::Domain(host, port) => format!("{host}:{port}"),
    };
    if let Some(addr) = cache.get(&key).copied() {
        return Ok(addr);
    }
    let ProxyTarget::Domain(_host, _port) = target else {
        unreachable!("IP target returned above")
    };
    let addr = resolve_target_addr(target).await?;
    cache.insert(key, addr);
    Ok(addr)
}

async fn read_length_or_eof<R>(reader: &mut R, context: &str) -> Result<Option<u16>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    match reader.read_exact(&mut bytes).await {
        Ok(_) => Ok(Some(u16::from_be_bytes(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error).context(context.to_string()),
    }
}

async fn read_u16<R>(reader: &mut R, context: &str) -> Result<u16>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    reader
        .read_exact(&mut bytes)
        .await
        .with_context(|| context.to_string())?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_xudp_new_packet() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 53);
        let mut bytes = Vec::new();
        write_client_packet(&mut bytes, &target, b"abc", true, &[0u8; 8]).await?;
        let packet = read_packet(&mut bytes.as_slice(), &mut None)
            .await?
            .context("packet")?;
        assert_eq!(packet.destination, target);
        assert_eq!(packet.payload, b"abc");
        Ok(())
    }

    #[test]
    fn decodes_in_memory_xudp_packet_chunk() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 53);
        let bytes = encode_client_packet(&target, b"abc", true, &[0u8; 8])?;
        let metadata_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        assert_eq!(metadata_len, 28);
        assert_eq!(&bytes[2..4], &[0, 0]);
        assert_eq!(bytes[4], STATUS_NEW);
        assert_eq!(bytes[5], 0x01);
        assert_eq!(bytes[6], NETWORK_UDP);
        let (destination, payload) = decode_packet_chunk(&bytes, &mut None)?.context("packet")?;
        assert_eq!(destination, target);
        assert_eq!(payload, b"abc");
        Ok(())
    }

    #[test]
    fn xudp_end_status_is_0x03() {
        assert_eq!(STATUS_END, 0x03);
        assert_eq!(STATUS_KEEPALIVE, 0x04);
    }

    #[test]
    fn keep_frame_includes_address_without_global_id() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 53);
        let bytes = encode_client_packet(&target, b"abc", false, &[1u8; 8])?;
        let metadata_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        assert_eq!(bytes[4], STATUS_KEEP);
        assert_eq!(metadata_len, 20);
        let (destination, payload) = decode_packet_chunk(&bytes, &mut None)?.context("packet")?;
        assert_eq!(destination, target);
        assert_eq!(payload, b"abc");
        Ok(())
    }
}
