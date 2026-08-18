use crate::protocol::{ProxyTarget, decode_target};
use anyhow::{Result, bail, ensure};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) const SOCKS_VERSION: u8 = 0x05;
pub(super) const SOCKS_NO_AUTH: u8 = 0x00;
pub(super) const SOCKS_NO_ACCEPTABLE: u8 = 0xff;
pub(super) const SOCKS_CMD_CONNECT: u8 = 0x01;
pub(super) const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

pub(super) enum SocksRequest {
    Connect(ProxyTarget),
    UdpAssociate,
}

pub(super) async fn read_socks_greeting<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    ensure!(header[0] == SOCKS_VERSION, "unsupported SOCKS version");
    let mut methods = vec![0u8; header[1] as usize];
    reader.read_exact(&mut methods).await?;
    let mut out = header.to_vec();
    out.extend_from_slice(&methods);
    Ok(out)
}

pub(super) async fn read_socks_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + Unpin,
{
    let request = read_socks_request_raw(stream).await?;
    parse_socks_request(request)
}

pub(super) async fn read_socks_request_raw<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    ensure!(header[0] == SOCKS_VERSION, "invalid SOCKS request version");
    let mut out = header.to_vec();
    read_socks_address_raw(reader, header[3], &mut out).await?;
    Ok(out)
}

pub(super) async fn read_socks_response_raw<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    ensure!(header[0] == SOCKS_VERSION, "invalid SOCKS response version");
    let mut out = header.to_vec();
    read_socks_address_raw(reader, header[3], &mut out).await?;
    Ok(out)
}

pub(super) async fn write_socks_reply_with_bind<W>(
    writer: &mut W,
    code: u8,
    bind: SocketAddr,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut response = vec![SOCKS_VERSION, code, 0];
    match bind {
        SocketAddr::V4(addr) => {
            response.push(SOCKS_ATYP_IPV4);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            response.push(SOCKS_ATYP_IPV6);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    writer.write_all(&response).await?;
    Ok(())
}

pub(super) async fn read_packet_over_stream<R>(reader: &mut R, payload: &mut [u8]) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 1];
    reader.read_exact(&mut prefix).await?;
    ensure!(prefix[0] == 0x00, "invalid packet-over-stream prefix");
    let mut length = [0u8; 2];
    reader.read_exact(&mut length).await?;
    let length = u16::from_be_bytes(length) as usize;
    ensure!(
        payload.len() >= length,
        "packet-over-stream output buffer is too small"
    );
    reader.read_exact(&mut payload[..length]).await?;
    let mut suffix = [0u8; 1];
    reader.read_exact(&mut suffix).await?;
    ensure!(suffix[0] == 0xff, "invalid packet-over-stream suffix");
    Ok(length)
}

pub(super) async fn write_packet_over_stream<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    ensure!(
        payload.len() <= u16::MAX as usize,
        "packet-over-stream payload is too large"
    );
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.push(0x00);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    packet.push(0xff);
    writer.write_all(&packet).await?;
    writer.flush().await?;
    Ok(())
}

fn parse_socks_request(request: Vec<u8>) -> Result<SocksRequest> {
    let target = parse_socks_target_from_request(&request)?;
    match request[1] {
        SOCKS_CMD_CONNECT => Ok(SocksRequest::Connect(target)),
        SOCKS_CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate),
        other => bail!("unsupported SOCKS command {other:#x}"),
    }
}

fn parse_socks_target_from_request(request: &[u8]) -> Result<ProxyTarget> {
    ensure!(request.len() >= 4, "SOCKS request is too short");
    decode_target(&request[3..]).map(|(target, _)| target)
}

async fn read_socks_address_raw<R>(reader: &mut R, atyp: u8, out: &mut Vec<u8>) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut rest = [0u8; 6];
            reader.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            out.push(len[0]);
            let mut rest = vec![0u8; len[0] as usize + 2];
            reader.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        SOCKS_ATYP_IPV6 => {
            let mut rest = [0u8; 18];
            reader.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        other => bail!("unsupported SOCKS address type {other:#x}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_request_with_shared_target_decoder() -> Result<()> {
        let request = vec![
            SOCKS_VERSION,
            SOCKS_CMD_CONNECT,
            0,
            SOCKS_ATYP_DOMAIN,
            11,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            b'.',
            b'c',
            b'o',
            b'm',
            0x01,
            0xbb,
        ];
        match parse_socks_request(request)? {
            SocksRequest::Connect(ProxyTarget::Domain(host, port)) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("unexpected SOCKS request"),
        }
        Ok(())
    }
}
