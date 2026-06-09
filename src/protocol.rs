use crate::padding::{PADDING_CHECKPOINT, PaddingScheme};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;
pub const MAX_FRAME_PAYLOAD_LEN: usize = u16::MAX as usize;

pub(crate) const FRAME_HEADER_LEN: usize = 7;
const CLIENT_NAME: &str = "aerion/0.1.0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Debug)]
pub struct Frame {
    pub cmd: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

pub fn password_hash(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

pub struct PaddedFrameWriter<W> {
    inner: W,
    padding: PaddingScheme,
    packet_counter: u32,
    send_padding: bool,
}

impl<W> PaddedFrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(inner: W, padding: PaddingScheme) -> Self {
        Self {
            inner,
            padding,
            packet_counter: 0,
            send_padding: true,
        }
    }

    pub async fn write_auth_preface(&mut self, password: &str) -> Result<()> {
        let hash = password_hash(password);
        let padding_len = self.padding.preface_padding_len()?;
        self.inner
            .write_all(&hash)
            .await
            .context("write authentication hash")?;
        self.inner
            .write_all(&(padding_len as u16).to_be_bytes())
            .await
            .context("write authentication padding length")?;
        if padding_len > 0 {
            self.inner
                .write_all(&vec![0u8; padding_len])
                .await
                .context("write authentication padding")?;
        }
        self.inner
            .flush()
            .await
            .context("flush authentication preface")
    }

    pub async fn write_client_settings(&mut self) -> Result<()> {
        let settings = format!(
            "v=2\nclient={CLIENT_NAME}\npadding-md5={}",
            self.padding.md5()
        );
        self.write_frame(CMD_SETTINGS, 0, settings.as_bytes()).await
    }

    pub async fn write_frame(&mut self, cmd: u8, stream_id: u32, payload: &[u8]) -> Result<()> {
        self.write_frame_with_flush(cmd, stream_id, payload, true)
            .await
    }

    pub async fn write_frame_with_flush(
        &mut self,
        cmd: u8,
        stream_id: u32,
        payload: &[u8],
        flush: bool,
    ) -> Result<()> {
        ensure!(
            payload.len() <= MAX_FRAME_PAYLOAD_LEN,
            "Aerion frame payload too large"
        );
        let frame = encode_frame(cmd, stream_id, payload);
        self.write_packet(&frame, flush)
            .await
            .context("write Aerion frame")
    }

    pub async fn write_payload_chunks(&mut self, stream_id: u32, payload: &[u8]) -> Result<()> {
        let chunks = payload.chunks(MAX_FRAME_PAYLOAD_LEN).collect::<Vec<_>>();
        for (index, chunk) in chunks.iter().enumerate() {
            let flush = index + 1 == chunks.len();
            self.write_frame_with_flush(CMD_PSH, stream_id, chunk, flush)
                .await?;
        }
        Ok(())
    }

    pub fn update_padding_scheme(&mut self, raw: &str) -> Result<()> {
        self.padding = PaddingScheme::from_text(raw).context("parse padding scheme update")?;
        self.packet_counter = 0;
        self.send_padding = true;
        Ok(())
    }

    async fn write_packet(&mut self, mut payload: &[u8], flush: bool) -> Result<()> {
        if self.send_padding {
            self.packet_counter = self.packet_counter.saturating_add(1);
            let packet = self.packet_counter;
            if packet < self.padding.stop() {
                for size in self.padding.record_payload_sizes(packet)? {
                    if size == PADDING_CHECKPOINT {
                        if payload.is_empty() {
                            break;
                        }
                        continue;
                    }
                    let size = size as usize;
                    if payload.len() > size {
                        self.inner
                            .write_all(&payload[..size])
                            .await
                            .context("write padded payload chunk")?;
                        payload = &payload[size..];
                    } else if !payload.is_empty() {
                        if size > payload.len() + FRAME_HEADER_LEN {
                            let padding_len = size - payload.len() - FRAME_HEADER_LEN;
                            let padding_frame = encode_frame(CMD_WASTE, 0, &vec![0u8; padding_len]);
                            let mut packet =
                                Vec::with_capacity(payload.len() + padding_frame.len());
                            packet.extend_from_slice(payload);
                            packet.extend_from_slice(&padding_frame);
                            self.inner
                                .write_all(&packet)
                                .await
                                .context("write padded payload")?;
                        } else {
                            self.inner
                                .write_all(payload)
                                .await
                                .context("write payload")?;
                        }
                        payload = &[];
                    } else {
                        let padding_frame = encode_frame(CMD_WASTE, 0, &vec![0u8; size]);
                        self.inner
                            .write_all(&padding_frame)
                            .await
                            .context("write padding frame")?;
                    }
                }
                if payload.is_empty() {
                    if flush {
                        self.inner.flush().await.context("flush padded packet")?;
                    }
                    return Ok(());
                }
            } else {
                self.send_padding = false;
            }
        }
        self.inner
            .write_all(payload)
            .await
            .context("write payload")?;
        if flush {
            self.inner.flush().await.context("flush packet")?;
        }
        Ok(())
    }
}

pub async fn read_auth_preface<R>(reader: &mut R, expected_password: &str) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    read_auth_preface_any(reader, std::slice::from_ref(&expected_password)).await
}

pub async fn read_auth_preface_any<R>(reader: &mut R, expected_passwords: &[&str]) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    read_auth_preface_user(reader, expected_passwords).await?;
    Ok(())
}

pub async fn read_auth_preface_user<R>(
    reader: &mut R,
    expected_passwords: &[&str],
) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut hash = [0u8; 32];
    reader
        .read_exact(&mut hash)
        .await
        .context("read authentication hash")?;
    let mut padding_len = [0u8; 2];
    reader
        .read_exact(&mut padding_len)
        .await
        .context("read authentication padding length")?;
    let padding_len = u16::from_be_bytes(padding_len) as usize;
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        reader
            .read_exact(&mut padding)
            .await
            .context("read authentication padding")?;
    }
    for password in expected_passwords {
        let password = password.trim();
        if hash == password_hash(password) {
            return Ok(password.to_string());
        }
    }
    bail!("authentication failed")
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .context("read Aerion frame header")?;
    let length = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut payload = vec![0u8; length];
    if length > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("read Aerion frame payload")?;
    }
    Ok(Frame {
        cmd: header[0],
        stream_id: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        payload,
    })
}

pub async fn write_frame<W>(writer: &mut W, cmd: u8, stream_id: u32, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    ensure!(
        payload.len() <= MAX_FRAME_PAYLOAD_LEN,
        "Aerion frame payload too large"
    );
    let frame = encode_frame(cmd, stream_id, payload);
    writer
        .write_all(&frame)
        .await
        .context("write Aerion frame")?;
    writer.flush().await.context("flush Aerion frame")
}

pub async fn write_payload_chunks<W>(writer: &mut W, stream_id: u32, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    for chunk in payload.chunks(MAX_FRAME_PAYLOAD_LEN) {
        write_frame(writer, CMD_PSH, stream_id, chunk).await?;
    }
    Ok(())
}

pub async fn write_client_settings<W>(writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let settings = format!("v=2\nclient={CLIENT_NAME}");
    write_frame(writer, CMD_SETTINGS, 0, settings.as_bytes()).await
}

pub fn parse_settings(bytes: &[u8]) -> std::collections::HashMap<String, String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

pub(crate) fn encode_frame(cmd: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.push(cmd);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn encode_target(target: &ProxyTarget) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    match target {
        ProxyTarget::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                encoded.push(0x01);
                encoded.extend_from_slice(&ip.octets());
                encoded.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                encoded.push(0x04);
                encoded.extend_from_slice(&ip.octets());
                encoded.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
        ProxyTarget::Domain(host, port) => {
            ensure!(host.len() <= u8::MAX as usize, "domain too long");
            encoded.push(0x03);
            encoded.push(host.len() as u8);
            encoded.extend_from_slice(host.as_bytes());
            encoded.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(encoded)
}

pub fn decode_target(payload: &[u8]) -> Result<(ProxyTarget, &[u8])> {
    ensure!(!payload.is_empty(), "target payload is empty");
    match payload[0] {
        0x01 => {
            ensure!(payload.len() >= 7, "IPv4 target payload is too short");
            let ip = Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]);
            let port = u16::from_be_bytes([payload[5], payload[6]]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(ip), port)),
                &payload[7..],
            ))
        }
        0x03 => {
            ensure!(payload.len() >= 2, "domain target payload is too short");
            let length = payload[1] as usize;
            let port_offset = 2 + length;
            ensure!(
                payload.len() >= port_offset + 2,
                "domain target payload missing port"
            );
            let host = String::from_utf8(payload[2..port_offset].to_vec())
                .context("decode domain target")?;
            let port = u16::from_be_bytes([payload[port_offset], payload[port_offset + 1]]);
            Ok((ProxyTarget::Domain(host, port), &payload[port_offset + 2..]))
        }
        0x04 => {
            ensure!(payload.len() >= 19, "IPv6 target payload is too short");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[1..17]);
            let port = u16::from_be_bytes([payload[17], payload[18]]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                &payload[19..],
            ))
        }
        other => bail!("unsupported target address type: {other}"),
    }
}

pub fn target_name(target: &ProxyTarget) -> String {
    match target {
        ProxyTarget::Ip(addr) => addr.to_string(),
        ProxyTarget::Domain(host, port) => format!("{host}:{port}"),
    }
}

pub async fn resolve_target_addr(target: &ProxyTarget) -> Result<SocketAddr> {
    match target {
        ProxyTarget::Ip(addr) => Ok(*addr),
        ProxyTarget::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .with_context(|| format!("resolve UDP target {host}:{port}"))?
            .next()
            .with_context(|| format!("UDP target resolved to no addresses: {host}:{port}")),
    }
}

pub fn parse_uuid(value: &str) -> Result<[u8; 16]> {
    let normalized = value.chars().filter(|ch| *ch != '-').collect::<String>();
    ensure!(normalized.len() == 32, "invalid UUID length");
    let mut uuid = [0u8; 16];
    hex::decode_to_slice(normalized, &mut uuid).context("decode UUID")?;
    Ok(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_domain_target() {
        let target = ProxyTarget::Domain("example.com".to_string(), 443);
        let encoded = encode_target(&target).unwrap();
        let (decoded, tail) = decode_target(&encoded).unwrap();
        assert_eq!(decoded, target);
        assert!(tail.is_empty());
    }

    #[test]
    fn encodes_and_decodes_ipv4_target() {
        let target = ProxyTarget::Ip("127.0.0.1:8080".parse().unwrap());
        let encoded = encode_target(&target).unwrap();
        let (decoded, tail) = decode_target(&encoded).unwrap();
        assert_eq!(decoded, target);
        assert!(tail.is_empty());
    }
}
