use crate::core::{CoreSession, ProxyCore, relay_bidirectional_counted};
use crate::protocol::{ProxyTarget, constant_time_eq, resolve_target_addr, target_name};
use crate::socket_protect;
use crate::tls::{ServerTlsAcceptor, ServerTlsMaterial, TlsEchServerKeys};
use crate::vless_transport::VlessTransportConfig;
use crate::{socks, tls, uot, utls, vless_transport};
use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha224};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::TlsConnector;

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
    pub ca_cert_paths: Vec<PathBuf>,
    pub ca_certificates: Vec<String>,
    pub disable_system_roots: bool,
    pub pinned_cert_sha256: Vec<String>,
    pub udp: bool,
    pub client_fingerprint: Option<utls::UtlsFingerprint>,
    pub transport: VlessTransportConfig,
}

#[derive(Clone, Debug)]
pub struct TrojanServerConfig {
    pub listen: SocketAddr,
    pub password: String,
    pub users: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub certificates: Vec<String>,
    pub key: Option<String>,
    pub transport: VlessTransportConfig,
    pub ech: Option<TlsEchServerKeys>,
    pub fallback: SocketAddr,
}

impl TrojanServerConfig {
    pub fn default_fallback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)
    }
}

type TrojanTransport = vless_transport::BoxedTransportStream;

enum TrojanRequest {
    Connect(ProxyTarget),
    UdpAssociate,
}

struct TrojanUdpPacket {
    target: ProxyTarget,
    payload: Vec<u8>,
}

pub async fn run_trojan_client(config: TrojanClientConfig) -> Result<()> {
    run_trojan_client_with_core(config, None).await
}

pub async fn run_trojan_client_with_core(
    config: TrojanClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Trojan SOCKS listener on {}", config.listen))?;
    run_trojan_client_listener(listener, config, core).await
}

pub async fn run_trojan_client_listener(
    listener: TcpListener,
    config: TrojanClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    tracing::info!(
        "Trojan client listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = listener.accept().await.context("accept SOCKS client")?;
        let config = config.clone();
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_trojan_socks_with_core(stream, config, core, peer).await {
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
    let acceptor = tls::build_server_tls_acceptor(&ServerTlsMaterial {
        cert_path: tls::present_path(&config.cert_path).map(PathBuf::from),
        key_path: tls::present_path(&config.key_path).map(PathBuf::from),
        certificates: config.certificates.clone(),
        key: config.key.clone(),
        label: "Trojan server TLS".to_string(),
        alpn_protocols: config.transport.alpn_protocols(),
        early_data: false,
        ech: config.ech.clone(),
    })?;
    let transport = config.transport.clone();
    let fallback = config.fallback;
    tracing::info!("Trojan server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await.context("accept Trojan client")?;
        let acceptor = acceptor.clone();
        let core = core.clone();
        let transport = transport.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_trojan_client(stream, acceptor, core, peer, transport, fallback).await
            {
                tracing::warn!("Trojan client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_trojan_socks_with_core(
    stream: TcpStream,
    config: TrojanClientConfig,
    core: Option<ProxyCore>,
    peer: SocketAddr,
) -> Result<()> {
    let (target, mut stream) = socks::handle_socks_greeting(stream).await?;
    let session = if let Some(core) = core.as_ref() {
        core.authenticate_from(&config.password, peer).await?
    } else {
        CoreSession::disabled()
    };
    match target {
        socks::SocksRequest::Connect(target) => {
            let mut server = connect_trojan_server(&config).await?;
            write_trojan_request(&mut server, &config.password, CMD_CONNECT, &target).await?;
            socks::write_reply(&mut stream, 0x00).await?;
            tracing::info!("Trojan proxying {}", target_name(&target));
            relay_bidirectional_counted(&mut stream, &mut server, session, "Trojan").await
        }
        socks::SocksRequest::UdpAssociate => {
            let _bind_ip = match stream.local_addr()?.ip() {
                IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
                ip => ip,
            };
            ensure!(config.udp, "Trojan UDP is disabled by client config");
            handle_trojan_udp_associate_counted(stream, config, session).await
        }
    }
}

async fn handle_trojan_udp_associate_counted(
    mut control: TcpStream,
    config: TrojanClientConfig,
    session: CoreSession,
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
        let session = session.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive SOCKS UDP packet")?;
                let _ = client_tx.try_send(peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                session.record_upload(payload.len()).await?;
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
        let session = session.clone();
        async move {
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => if let Some(next_peer) = next_peer { peer = Some(next_peer); },
                    packet = read_trojan_udp_packet(&mut reader) => {
                        let Some(packet) = packet? else { return Ok::<(), anyhow::Error>(()); };
                        session.record_download(packet.payload.len()).await?;
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

async fn connect_trojan_server(config: &TrojanClientConfig) -> Result<TrojanTransport> {
    let tcp =
        socket_protect::connect_tcp_host_port(config.server_host.as_str(), config.server_port)
            .await
            .with_context(|| {
                format!(
                    "connect Trojan server {}:{}",
                    config.server_host, config.server_port
                )
            })?;
    let mut client_config = Arc::unwrap_or_clone(
        tls::client_config_with_fingerprint_and_custom_root_material_options(
            config.insecure,
            config.client_fingerprint,
            &config.ca_cert_paths,
            &config.ca_certificates,
            config.disable_system_roots,
            &config.pinned_cert_sha256,
        )?,
    );
    let alpn = config.transport.alpn_protocols();
    if !alpn.is_empty() {
        client_config.alpn_protocols = alpn;
    }
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(config.sni.clone())
        .with_context(|| format!("invalid Trojan SNI: {}", config.sni))?;
    let stream = connector
        .connect(server_name, tcp)
        .await
        .context("TLS connect to Trojan server")?;
    vless_transport::apply_client_transport(stream, &config.transport, &config.server_host).await
}

async fn handle_trojan_client(
    stream: TcpStream,
    acceptor: ServerTlsAcceptor,
    core: ProxyCore,
    peer: SocketAddr,
    transport: VlessTransportConfig,
    fallback: SocketAddr,
) -> Result<()> {
    let stream = acceptor.accept(stream).await.context("accept Trojan TLS")?;
    let stream = vless_transport::apply_server_transport(stream, &transport).await?;
    let mut stream = CapturingStream::new(stream);
    match read_authenticated_trojan_request(&mut stream, &core).await {
        Ok((credential, request)) => {
            let session = core.authenticate_from(&credential, peer).await?;
            match request {
                TrojanRequest::Connect(target) => {
                    let mut remote = socket_protect::connect_proxy_target(&target).await?;
                    tracing::info!("Trojan opened {}", target_name(&target));
                    relay_bidirectional_counted(&mut stream, &mut remote, session, "Trojan").await
                }
                TrojanRequest::UdpAssociate => relay_trojan_udp(stream, session).await,
            }
        }
        Err(error) => {
            tracing::debug!("Trojan falling back after handshake failure: {error:?}");
            relay_trojan_fallback(stream, fallback).await
        }
    }
}

async fn read_authenticated_trojan_request<S>(
    stream: &mut S,
    core: &ProxyCore,
) -> Result<(String, TrojanRequest)>
where
    S: AsyncRead + Unpin,
{
    let mut auth_hex = [0u8; TROJAN_AUTH_LEN];
    stream
        .read_exact(&mut auth_hex)
        .await
        .context("read Trojan auth")?;
    let credential = lookup_trojan_credential(core, &auth_hex)
        .ok_or_else(|| anyhow::anyhow!("Trojan authentication failed"))?;
    read_crlf(stream).await?;
    Ok((credential, read_trojan_request(stream).await?))
}

async fn relay_trojan_fallback<S>(
    mut stream: CapturingStream<S>,
    fallback: SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut remote = TcpStream::connect(fallback)
        .await
        .with_context(|| format!("connect Trojan fallback {fallback}"))?;
    remote
        .write_all(&stream.take_captured())
        .await
        .context("write Trojan fallback prefix")?;
    let (mut client_reader, mut client_writer) = tokio::io::split(stream);
    let (mut fallback_reader, mut fallback_writer) = remote.into_split();
    tokio::try_join!(
        tokio::io::copy(&mut client_reader, &mut fallback_writer),
        tokio::io::copy(&mut fallback_reader, &mut client_writer),
    )?;
    Ok(())
}

struct CapturingStream<S> {
    inner: S,
    captured: Vec<u8>,
}

impl<S> CapturingStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            captured: Vec::new(),
        }
    }

    fn take_captured(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.captured)
    }
}

impl<S> AsyncRead for CapturingStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        self.captured.extend_from_slice(&buf.filled()[filled..]);
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for CapturingStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn relay_trojan_udp<S>(stream: S, session: CoreSession) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let udp = Arc::new(
        socket_protect::bind_dual_stack_udp()
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
                let target = resolve_target_addr(&packet.target).await?;
                session.record_upload(packet.payload.len()).await?;
                socket_protect::send_to_dual_stack(&udp, &packet.payload, target)
                    .await
                    .with_context(|| format!("send Trojan UDP payload to {target}"))?;
            }
            Ok::<(), anyhow::Error>(())
        }
    };
    let remote_to_udp = {
        let udp = udp.clone();
        let session = session.clone();
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
        }
    };
    tokio::select! {
        result = udp_to_remote => result,
        result = remote_to_udp => result,
    }
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
                String::from_utf8(host)
                    .map_err(|_| anyhow::anyhow!("Trojan domain address is not valid UTF-8"))?,
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
    hex::encode(Sha224::digest(password.as_bytes()))
}

fn trojan_auth_hex(password: &str) -> [u8; TROJAN_AUTH_LEN] {
    let encoded = trojan_auth(password);
    let mut auth = [0u8; TROJAN_AUTH_LEN];
    auth.copy_from_slice(encoded.as_bytes());
    auth
}

fn ascii_lower_copy(bytes: &[u8; TROJAN_AUTH_LEN]) -> [u8; TROJAN_AUTH_LEN] {
    let mut lowered = *bytes;
    for byte in &mut lowered {
        *byte = byte.to_ascii_lowercase();
    }
    lowered
}

fn lookup_trojan_credential(core: &ProxyCore, wire: &[u8; TROJAN_AUTH_LEN]) -> Option<String> {
    let wire = ascii_lower_copy(wire);
    let mut found = None;
    for credential in core.known_credentials() {
        let expected = ascii_lower_copy(&trojan_auth_hex(&credential));
        if constant_time_eq(&wire, &expected) {
            found = Some(credential);
        }
    }
    found
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

    #[test]
    fn password_hash_uses_raw_bytes_and_accepts_hex_case() {
        let core = ProxyCore::from_credentials(" secret", &[]);
        let lower = trojan_auth_hex(" secret");
        let mut upper = lower;
        for byte in &mut upper {
            *byte = byte.to_ascii_uppercase();
        }
        assert_eq!(
            lookup_trojan_credential(&core, &lower).as_deref(),
            Some(" secret")
        );
        assert_eq!(
            lookup_trojan_credential(&core, &upper).as_deref(),
            Some(" secret")
        );
        assert!(lookup_trojan_credential(&core, &trojan_auth_hex("secret")).is_none());
    }

    #[test]
    fn default_fallback_is_localhost_http() {
        assert_eq!(
            TrojanServerConfig::default_fallback(),
            "127.0.0.1:80".parse().unwrap()
        );
    }
}
