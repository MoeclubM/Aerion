use crate::protocol::{ProxyTarget, decode_target, encode_target};
use anyhow::{Context, Result, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

const AF_IPV4: u8 = 0x00;
const AF_IPV6: u8 = 0x01;
const AF_FQDN: u8 = 0x02;

#[derive(Debug)]
pub struct UotRequest {
    pub is_connect: bool,
    pub destination: ProxyTarget,
}

pub fn is_magic_target(target: &ProxyTarget) -> bool {
    match target {
        ProxyTarget::Domain(host, _) => {
            host.eq_ignore_ascii_case(MAGIC_ADDRESS)
                || host.eq_ignore_ascii_case(LEGACY_MAGIC_ADDRESS)
        }
        ProxyTarget::Ip(_) => false,
    }
}

pub fn is_legacy_magic_target(target: &ProxyTarget) -> bool {
    matches!(target, ProxyTarget::Domain(host, _) if host.eq_ignore_ascii_case(LEGACY_MAGIC_ADDRESS))
}

pub fn magic_target() -> ProxyTarget {
    ProxyTarget::Domain(MAGIC_ADDRESS.to_string(), 0)
}

pub fn encode_v2_associate_request() -> Result<Vec<u8>> {
    let mut bytes = vec![0];
    write_socks_address(
        &mut bytes,
        &ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
    )?;
    Ok(bytes)
}

pub fn decode_v2_request(payload: &[u8]) -> Result<UotRequest> {
    ensure!(!payload.is_empty(), "UOT request is empty");
    let is_connect = payload[0] != 0;
    let (destination, tail) = read_socks_address(&payload[1..])?;
    ensure!(tail.is_empty(), "UOT request has trailing bytes");
    Ok(UotRequest {
        is_connect,
        destination,
    })
}

pub fn decode_request_for_target<'a>(
    target: &ProxyTarget,
    payload: &'a [u8],
) -> Result<(UotRequest, &'a [u8])> {
    if is_legacy_magic_target(target) {
        return Ok((legacy_associate_request(), payload));
    }
    let length = v2_request_len(payload)?.context("incomplete UOT request")?;
    ensure!(payload.len() >= length, "incomplete UOT request");
    Ok((decode_v2_request(&payload[..length])?, &payload[length..]))
}

pub fn v2_request_complete(payload: &[u8]) -> Result<bool> {
    Ok(v2_request_len(payload)?.is_some_and(|length| payload.len() >= length))
}

pub fn legacy_associate_request() -> UotRequest {
    UotRequest {
        is_connect: false,
        destination: ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
    }
}

pub fn take_v2_request(pending: &mut Vec<u8>) -> Result<Option<UotRequest>> {
    let Some(length) = v2_request_len(pending)? else {
        return Ok(None);
    };
    if pending.len() < length {
        return Ok(None);
    }
    let request = decode_v2_request(&pending[..length])?;
    pending.drain(..length);
    Ok(Some(request))
}

pub fn take_stream_packet(
    request: &UotRequest,
    pending: &mut Vec<u8>,
) -> Result<Option<(ProxyTarget, Vec<u8>, bool)>> {
    if request.is_connect {
        let Some(length) = connect_packet_len(pending)? else {
            return Ok(None);
        };
        if pending.len() < length {
            return Ok(None);
        }
        let payload = decode_connect_packet(&pending[..length])?.to_vec();
        pending.drain(..length);
        return Ok(Some((request.destination.clone(), payload, true)));
    }
    let Some(length) = associate_packet_len(pending)? else {
        return Ok(None);
    };
    if pending.len() < length {
        return Ok(None);
    }
    let packet = pending[..length].to_vec();
    pending.drain(..length);
    let (destination, payload) = decode_associate_packet(&packet)?;
    Ok(Some((destination, payload.to_vec(), false)))
}

pub fn encode_associate_packet(destination: &ProxyTarget, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "UDP payload too large: {}",
        payload.len()
    );
    let mut bytes = Vec::new();
    write_uot_address(&mut bytes, destination)?;
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn decode_associate_packet(packet: &[u8]) -> Result<(ProxyTarget, &[u8])> {
    let (destination, tail) = read_uot_address(packet)?;
    ensure!(tail.len() >= 2, "UOT packet missing payload length");
    let length = u16::from_be_bytes([tail[0], tail[1]]) as usize;
    ensure!(
        tail.len() >= 2 + length,
        "UOT packet payload is shorter than declared length"
    );
    ensure!(
        tail.len() == 2 + length,
        "UOT packet has trailing bytes after payload"
    );
    Ok((destination, &tail[2..]))
}

pub fn encode_connect_packet(payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "UDP payload too large: {}",
        payload.len()
    );
    let mut bytes = Vec::with_capacity(2 + payload.len());
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn decode_connect_packet(packet: &[u8]) -> Result<&[u8]> {
    ensure!(
        packet.len() >= 2,
        "UOT connected packet missing payload length"
    );
    let length = u16::from_be_bytes([packet[0], packet[1]]) as usize;
    ensure!(
        packet.len() >= 2 + length,
        "UOT connected packet payload is shorter than declared length"
    );
    ensure!(
        packet.len() == 2 + length,
        "UOT connected packet has trailing bytes after payload"
    );
    Ok(&packet[2..])
}

pub fn parse_socks_udp_packet(packet: &[u8]) -> Result<(ProxyTarget, &[u8])> {
    ensure!(packet.len() >= 4, "SOCKS UDP packet is too short");
    ensure!(
        packet[0] == 0 && packet[1] == 0,
        "invalid SOCKS UDP reserved bytes"
    );
    ensure!(
        packet[2] == 0,
        "fragmented SOCKS UDP packets are not supported"
    );
    read_socks_address(&packet[3..])
}

pub fn encode_socks_udp_packet(source: &ProxyTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = vec![0, 0, 0];
    write_socks_address(&mut bytes, source)?;
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn v2_request_len(packet: &[u8]) -> Result<Option<usize>> {
    if packet.len() < 2 {
        return Ok(None);
    }
    let address_offset = 1;
    match packet[address_offset] {
        0x01 => Ok(Some(address_offset + 7)),
        0x04 => Ok(Some(address_offset + 19)),
        0x03 => {
            if packet.len() < address_offset + 2 {
                return Ok(None);
            }
            Ok(Some(
                address_offset + 2 + packet[address_offset + 1] as usize + 2,
            ))
        }
        other => bail!("unsupported UOT request address type: {other}"),
    }
}

fn connect_packet_len(packet: &[u8]) -> Result<Option<usize>> {
    if packet.len() < 2 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([packet[0], packet[1]]) as usize;
    Ok(Some(2 + payload_len))
}

fn associate_packet_len(packet: &[u8]) -> Result<Option<usize>> {
    if packet.is_empty() {
        return Ok(None);
    }
    let payload_len_offset = match packet[0] {
        AF_IPV4 => {
            if packet.len() < 7 {
                return Ok(None);
            }
            7
        }
        AF_IPV6 => {
            if packet.len() < 19 {
                return Ok(None);
            }
            19
        }
        AF_FQDN => {
            if packet.len() < 2 {
                return Ok(None);
            }
            let address_len = packet[1] as usize;
            if packet.len() < 2 + address_len + 2 {
                return Ok(None);
            }
            2 + address_len + 2
        }
        other => bail!("unsupported UOT address family: {other}"),
    };
    if packet.len() < payload_len_offset + 2 {
        return Ok(None);
    }
    let payload_len =
        u16::from_be_bytes([packet[payload_len_offset], packet[payload_len_offset + 1]]) as usize;
    Ok(Some(payload_len_offset + 2 + payload_len))
}

fn write_socks_address(bytes: &mut Vec<u8>, target: &ProxyTarget) -> Result<()> {
    bytes.extend_from_slice(&encode_target(target)?);
    Ok(())
}

fn read_socks_address(packet: &[u8]) -> Result<(ProxyTarget, &[u8])> {
    decode_target(packet)
}

fn write_uot_address(bytes: &mut Vec<u8>, target: &ProxyTarget) -> Result<()> {
    match target {
        ProxyTarget::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                bytes.push(AF_IPV4);
                bytes.extend_from_slice(&ip.octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                bytes.push(AF_IPV6);
                bytes.extend_from_slice(&ip.octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
        ProxyTarget::Domain(host, port) => {
            ensure!(host.len() <= u8::MAX as usize, "UOT domain too long");
            bytes.push(AF_FQDN);
            bytes.push(host.len() as u8);
            bytes.extend_from_slice(host.as_bytes());
            bytes.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn read_uot_address(packet: &[u8]) -> Result<(ProxyTarget, &[u8])> {
    ensure!(!packet.is_empty(), "UOT address is empty");
    match packet[0] {
        AF_IPV4 => {
            ensure!(packet.len() >= 7, "UOT IPv4 address is too short");
            let ip = Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4]);
            let port = u16::from_be_bytes([packet[5], packet[6]]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(ip), port)),
                &packet[7..],
            ))
        }
        AF_IPV6 => {
            ensure!(packet.len() >= 19, "UOT IPv6 address is too short");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[1..17]);
            let port = u16::from_be_bytes([packet[17], packet[18]]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::from(octets), port)),
                &packet[19..],
            ))
        }
        AF_FQDN => {
            ensure!(packet.len() >= 2, "UOT domain address is too short");
            let length = packet[1] as usize;
            let port_offset = 2 + length;
            ensure!(
                packet.len() >= port_offset + 2,
                "UOT domain address missing port"
            );
            let host = String::from_utf8(packet[2..port_offset].to_vec())
                .context("decode UOT domain address")?;
            let port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
            Ok((ProxyTarget::Domain(host, port), &packet[port_offset + 2..]))
        }
        other => bail!("unsupported UOT address family: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_associate_packet() {
        let target = ProxyTarget::Domain("example.com".to_string(), 53);
        let packet = encode_associate_packet(&target, b"abc").unwrap();
        let (decoded, payload) = decode_associate_packet(&packet).unwrap();
        assert_eq!(decoded, target);
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn parses_socks_udp_packet() {
        let target = ProxyTarget::Ip("1.2.3.4:53".parse().unwrap());
        let packet = encode_socks_udp_packet(&target, b"abc").unwrap();
        let (decoded, payload) = parse_socks_udp_packet(&packet).unwrap();
        assert_eq!(decoded, target);
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn legacy_request_preserves_initial_packet() {
        let target = ProxyTarget::Domain(LEGACY_MAGIC_ADDRESS.to_string(), 0);
        let (request, packet) = decode_request_for_target(&target, b"abc").unwrap();
        assert!(!request.is_connect);
        assert_eq!(packet, b"abc");
    }

    #[test]
    fn v2_request_can_be_split_and_preserves_initial_packet() {
        let target = magic_target();
        let request = encode_v2_associate_request().unwrap();
        assert!(!v2_request_complete(&request[..3]).unwrap());
        assert!(v2_request_complete(&request).unwrap());

        let packet =
            encode_associate_packet(&ProxyTarget::Ip("1.2.3.4:53".parse().unwrap()), b"abc")
                .unwrap();
        let mut payload = request;
        payload.extend_from_slice(&packet);
        let (decoded, initial_packet) = decode_request_for_target(&target, &payload).unwrap();
        assert!(!decoded.is_connect);
        assert_eq!(initial_packet, packet);
    }

    #[test]
    fn reassembles_stream_packets_from_pending_buffer() {
        let target = ProxyTarget::Ip("1.2.3.4:53".parse().unwrap());
        let request = UotRequest {
            is_connect: false,
            destination: target.clone(),
        };
        let packet = encode_associate_packet(&target, b"hello").unwrap();
        let mut pending = packet[..3].to_vec();
        assert!(
            take_stream_packet(&request, &mut pending)
                .unwrap()
                .is_none()
        );
        pending.extend_from_slice(&packet[3..]);
        let (decoded, payload, _) = take_stream_packet(&request, &mut pending)
            .unwrap()
            .expect("complete packet");
        assert_eq!(decoded, target);
        assert_eq!(payload, b"hello");
        assert!(pending.is_empty());
    }
}
