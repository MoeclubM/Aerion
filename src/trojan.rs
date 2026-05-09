use crate::core::{CoreSession, ProxyCore};
use crate::protocol::{ProxyTarget, target_name};
use crate::socket_protect;
use crate::{socks, tls, uot, utls};
use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha224};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const TROJAN_AUTH_LEN: usize = 56;

#[derive(Clone, Debug)]
pub struct TrojanClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub password: String,
    pub sni: String,
    pub insecure: bool,
    pub udp: bool,
    pub client_fingerprint: Option<utls::UtlsFingerprint>,
}

#[derive(Clone, Debug)]
pub struct TrojanServerConfig {
    pub listen: SocketAddr,
    pub password: String,
    pub users: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

enum TrojanRequest {
    Connect(ProxyTarget),
    UdpAssociate,
}

struct TrojanUdpPacket {
    target: ProxyTarget,
    payload: Vec<u8>,
}

pub async fn run_trojan_client(config: TrojanClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Trojan SOCKS listener on {}", config.listen))?;
    run_trojan_client_listener(listener, config).await
}

pub async fn run_trojan_client_listener(
    listener: TcpListener,
    config: TrojanClientConfig,
) -> Result<()> {
    tracing::info!(
        "Trojan client listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = listener.accept().await.context("accept SOCKS client")?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_trojan_socks(stream, config).await {
                tracing::warn!("Trojan SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn run_trojan_server(config: TrojanServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.password, &config.users);
    run_trojan_server_with_core(config, core).await
}

pub async fn run_trojan_server_with_core(
    config: TrojanServerConfig,
    core: ProxyCore,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Trojan server on {}", config.listen))?;
    let acceptor = TlsAcceptor::from(tls::server_config(&config.cert_path, &config.key_path)?);
    let auth = trojan_auth_map(&config.password, &config.users);
    tracing::info!("Trojan server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await.context("accept Trojan client")?;
        let acceptor = acceptor.clone();
        let auth = auth.clone();
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_trojan_client(stream, acceptor, auth, core).await {
                tracing::warn!("Trojan client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_trojan_socks(mut local: TcpStream, config: TrojanClientConfig) -> Result<()> {
    match socks::read_request(&mut local).await? {
        socks::SocksRequest::Connect(target) => {
            let mut server = connect_trojan_server(&config).await?;
            write_trojan_request(&mut server, &config.password, CMD_CONNECT, &target).await?;
            socks::write_reply(&mut local, 0x00).await?;
            tracing::info!("Trojan proxying {}", target_name(&target));
            tokio::io::copy_bidirectional(&mut local, &mut server)
                .await
                .context("relay Trojan TCP")?;
            Ok(())
        }
        socks::SocksRequest::UdpAssociate => {
            ensure!(config.udp, "Trojan UDP is disabled by client config");
            handle_trojan_udp_associate(local, config).await
        }
    }
}

async fn handle_trojan_udp_associate(
    mut control: TcpStream,
    config: TrojanClientConfig,
) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .with_context(|| format!("bind Trojan SOCKS UDP associate socket on {bind_ip}:0"))?;
    socks::write_reply_with_bind(&mut control, 0x00, udp.local_addr()?).await?;

    let mut server = connect_trojan_server(&config).await?;
    write_trojan_request(
        &mut server,
        &config.password,
        CMD_UDP_ASSOCIATE,
        &ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
    )
    .await?;
    let (mut reader, writer) = tokio::io::split(server);
    let writer = Arc::new(Mutex::new(writer));
    let udp = Arc::new(udp);
    let (client_tx, mut client_rx) = mpsc::channel::<SocketAddr>(8);

    let udp_to_trojan = {
        let udp = udp.clone();
        let writer = writer.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive SOCKS UDP packet")?;
                let _ = client_tx.try_send(peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let packet = encode_trojan_udp_packet(&target, payload)?;
                writer
                    .lock()
                    .await
                    .write_all(&packet)
                    .await
                    .context("write Trojan UDP packet")?;
            }
        }
    };

    let trojan_to_udp = {
        let udp = udp.clone();
        async move {
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => if let Some(next_peer) = next_peer { peer = Some(next_peer); },
                    packet = read_trojan_udp_packet(&mut reader) => {
                        let Some(packet) = packet? else { return Ok::<(), anyhow::Error>(()); };
                        let response = uot::encode_socks_udp_packet(&packet.target, &packet.payload)?;
                        let peer = peer.context("SOCKS UDP peer is not known yet")?;
                        udp.send_to(&response, peer)
                            .await
                            .with_context(|| format!("send SOCKS UDP response to {peer}"))?;
                    }
                }
            }
        }
    };

    let control_closed = async {
        let mut buffer = [0u8; 1];
        loop {
            if control
                .read(&mut buffer)
                .await
                .context("read SOCKS UDP control connection")?
                == 0
            {
                return Ok::<(), anyhow::Error>(());
            }
        }
    };

    tokio::select! {
        result = udp_to_trojan => result,
        result = trojan_to_udp => result,
        result = control_closed => result,
    }
}

async fn connect_trojan_server(
    config: &TrojanClientConfig,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp =
        socket_protect::connect_tcp_host_port(config.server_host.as_str(), config.server_port)
            .await
            .with_context(|| {
                format!(
                    "connect Trojan server {}:{}",
                    config.server_host, config.server_port
                )
            })?;
    let connector = TlsConnector::from(tls::client_config_with_fingerprint(
        config.insecure,
        config.client_fingerprint,
    ));
    let server_name = ServerName::try_from(config.sni.clone())
        .with_context(|| format!("invalid Trojan SNI: {}", config.sni))?;
    connector
        .connect(server_name, tcp)
        .await
        .context("TLS connect to Trojan server")
}

async fn handle_trojan_client(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    auth: HashMap<[u8; TROJAN_AUTH_LEN], String>,
    core: ProxyCore,
) -> Result<()> {
    let mut stream = acceptor.accept(stream).await.context("accept Trojan TLS")?;
    let credential = read_trojan_auth(&mut stream, &auth).await?;
    let session = core.authenticate(&credential).await?;
    match read_trojan_request(&mut stream).await? {
        TrojanRequest::Connect(target) => {
            let mut remote = connect_target(&target).await?;
            tracing::info!("Trojan opened {}", target_name(&target));
            relay_counted(&mut stream, &mut remote, session).await
        }
        TrojanRequest::UdpAssociate => relay_trojan_udp(stream, session).await,
    }
}

async fn relay_counted<A, B>(left: &mut A, right: &mut B, session: CoreSession) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut lr, mut lw) = tokio::io::split(left);
    let (mut rr, mut rw) = tokio::io::split(right);
    let uplink_session = session.clone();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = lr.read(&mut buffer).await.context("read Trojan uplink")?;
            if read == 0 {
                let _ = rw.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            uplink_session.record_upload(read).await?;
            rw.write_all(&buffer[..read])
                .await
                .context("write Trojan uplink")?;
        }
    };
    let downlink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = rr.read(&mut buffer).await.context("read Trojan downlink")?;
            if read == 0 {
                let _ = lw.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            session.record_download(read).await?;
            lw.write_all(&buffer[..read])
                .await
                .context("write Trojan downlink")?;
        }
    };
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

async fn relay_trojan_udp(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    session: CoreSession,
) -> Result<()> {
    let udp = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind Trojan UDP")?,
    );
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(Mutex::new(writer));
    let udp_to_remote = {
        let udp = udp.clone();
        let session = session.clone();
        async move {
            while let Some(packet) = read_trojan_udp_packet(&mut reader).await? {
                let target = target_socket_addr(&packet.target).await?;
                session.record_upload(packet.payload.len()).await?;
                udp.send_to(&packet.payload, target)
                    .await
                    .with_context(|| format!("send Trojan UDP payload to {target}"))?;
            }
            Ok::<(), anyhow::Error>(())
        }
    };
    let remote_to_udp = {
        let udp = udp.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                let (read, source) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive Trojan UDP response")?;
                session.record_download(read).await?;
                let packet = encode_trojan_udp_packet(&ProxyTarget::Ip(source), &buffer[..read])?;
                writer
                    .lock()
                    .await
                    .write_all(&packet)
                    .await
                    .context("write Trojan UDP response")?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };
    tokio::try_join!(udp_to_remote, remote_to_udp)?;
    Ok(())
}

async fn write_trojan_request<W>(
    writer: &mut W,
    password: &str,
    command: u8,
    target: &ProxyTarget,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(trojan_auth(password).as_bytes())
        .await
        .context("write Trojan auth")?;
    writer.write_all(b"\r\n").await?;
    writer.write_all(&[command]).await?;
    write_trojan_address(writer, target).await?;
    writer.write_all(b"\r\n").await?;
    writer.flush().await.context("flush Trojan request")
}

async fn read_trojan_auth<R>(
    reader: &mut R,
    auth: &HashMap<[u8; TROJAN_AUTH_LEN], String>,
) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut auth_hex = [0u8; TROJAN_AUTH_LEN];
    reader
        .read_exact(&mut auth_hex)
        .await
        .context("read Trojan auth")?;
    read_crlf(reader).await?;
    auth.get(&auth_hex)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Trojan authentication failed"))
}

async fn read_trojan_request<R>(reader: &mut R) -> Result<TrojanRequest>
where
    R: AsyncRead + Unpin,
{
    let command = read_u8(reader).await?;
    let target = read_trojan_address(reader).await?;
    read_crlf(reader).await?;
    match command {
        CMD_CONNECT => Ok(TrojanRequest::Connect(target)),
        CMD_UDP_ASSOCIATE => Ok(TrojanRequest::UdpAssociate),
        other => bail!("unsupported Trojan command {other:#x}"),
    }
}

async fn read_trojan_udp_packet<R>(reader: &mut R) -> Result<Option<TrojanUdpPacket>>
where
    R: AsyncRead + Unpin,
{
    let target = match read_trojan_address_or_eof(reader).await? {
        Some(target) => target,
        None => return Ok(None),
    };
    let mut length = [0u8; 2];
    reader
        .read_exact(&mut length)
        .await
        .context("read Trojan UDP packet length")?;
    read_crlf(reader).await?;
    let mut payload = vec![0u8; u16::from_be_bytes(length) as usize];
    reader
        .read_exact(&mut payload)
        .await
        .context("read Trojan UDP payload")?;
    Ok(Some(TrojanUdpPacket { target, payload }))
}

fn encode_trojan_udp_packet(target: &ProxyTarget, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "Trojan UDP payload too large"
    );
    let mut packet = Vec::new();
    write_trojan_address_sync(&mut packet, target)?;
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn write_trojan_address<W>(writer: &mut W, target: &ProxyTarget) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut encoded = Vec::new();
    write_trojan_address_sync(&mut encoded, target)?;
    writer
        .write_all(&encoded)
        .await
        .context("write Trojan address")
}

fn write_trojan_address_sync(out: &mut Vec<u8>, target: &ProxyTarget) -> Result<()> {
    match target {
        ProxyTarget::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
        ProxyTarget::Domain(host, port) => {
            ensure!(host.len() <= u8::MAX as usize, "Trojan domain too long");
            out.push(ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

async fn read_trojan_address<R>(reader: &mut R) -> Result<ProxyTarget>
where
    R: AsyncRead + Unpin,
{
    read_trojan_address_or_eof(reader)
        .await?
        .context("Trojan address reached EOF")
}

async fn read_trojan_address_or_eof<R>(reader: &mut R) -> Result<Option<ProxyTarget>>
where
    R: AsyncRead + Unpin,
{
    let mut atyp = [0u8; 1];
    match reader.read_exact(&mut atyp).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("read Trojan address type"),
    }
    Ok(Some(match atyp[0] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader
                .read_exact(&mut octets)
                .await
                .context("read Trojan IPv4 address")?;
            ProxyTarget::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                read_port(reader).await?,
            ))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader
                .read_exact(&mut octets)
                .await
                .context("read Trojan IPv6 address")?;
            ProxyTarget::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                read_port(reader).await?,
            ))
        }
        ATYP_DOMAIN => {
            let length = read_u8(reader).await? as usize;
            let mut host = vec![0u8; length];
            reader
                .read_exact(&mut host)
                .await
                .context("read Trojan domain")?;
            ProxyTarget::Domain(
                String::from_utf8(host).context("decode Trojan domain")?,
                read_port(reader).await?,
            )
        }
        other => bail!("unsupported Trojan address type {other:#x}"),
    }))
}

async fn read_crlf<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await.context("read CRLF")?;
    ensure!(crlf == *b"\r\n", "invalid CRLF");
    Ok(())
}

async fn read_u8<R>(reader: &mut R) -> Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte).await.context("read byte")?;
    Ok(byte[0])
}

async fn read_port<R>(reader: &mut R) -> Result<u16>
where
    R: AsyncRead + Unpin,
{
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await.context("read port")?;
    Ok(u16::from_be_bytes(port))
}

fn trojan_auth(password: &str) -> String {
    hex::encode(Sha224::digest(password.trim().as_bytes()))
}

fn trojan_auth_map(password: &str, users: &[String]) -> HashMap<[u8; TROJAN_AUTH_LEN], String> {
    let mut map = HashMap::new();
    for credential in std::iter::once(password).chain(users.iter().map(String::as_str)) {
        let credential = credential.trim();
        if credential.is_empty() {
            continue;
        }
        let mut auth = [0u8; TROJAN_AUTH_LEN];
        auth.copy_from_slice(trojan_auth(credential).as_bytes());
        map.insert(auth, credential.to_string());
    }
    map
}

async fn connect_target(target: &ProxyTarget) -> Result<TcpStream> {
    match target {
        ProxyTarget::Ip(addr) => TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect target {addr}")),
        ProxyTarget::Domain(host, port) => TcpStream::connect((host.as_str(), *port))
            .await
            .with_context(|| format!("connect target {host}:{port}")),
    }
}

async fn target_socket_addr(target: &ProxyTarget) -> Result<SocketAddr> {
    match target {
        ProxyTarget::Ip(addr) => Ok(*addr),
        ProxyTarget::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .with_context(|| format!("resolve UDP target {host}:{port}"))?
            .next()
            .with_context(|| format!("UDP target resolved to no addresses: {host}:{port}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_packet_roundtrip() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 443);
        let encoded = encode_trojan_udp_packet(&target, b"abc")?;
        let decoded = read_trojan_udp_packet(&mut encoded.as_slice())
            .await?
            .expect("packet");
        assert_eq!(decoded.target, target);
        assert_eq!(decoded.payload, b"abc");
        Ok(())
    }
}
