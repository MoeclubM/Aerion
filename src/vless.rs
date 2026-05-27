use crate::core::{CoreSession, ProxyCore, relay_bidirectional_counted};
use crate::protocol::{ProxyTarget, parse_uuid, resolve_target_addr, target_name};
use crate::tls::{ServerTlsAcceptor, ServerTlsMaterial, TlsEchServerKeys};
use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::ServerName;
use crate::{
    reality, reality_tls_client, socket_protect, socks, tls, uot, utls, vless_mux,
    vless_transport, vless_vision, vless_xudp,
};
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use vless_transport::VlessTransportConfig;

const VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
const CMD_MUX: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const FLOW_XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

#[derive(Clone, Debug)]
pub struct VlessClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub user_id: String,
    pub tls: bool,
    pub sni: String,
    pub insecure: bool,
    pub ca_cert_paths: Vec<PathBuf>,
    pub ca_certificates: Vec<String>,
    pub disable_system_roots: bool,
    pub pinned_cert_sha256: Vec<String>,
    pub flow: String,
    pub packet_encoding: String,
    pub mux: bool,
    pub udp: bool,
    pub client_fingerprint: Option<utls::UtlsFingerprint>,
    pub reality: Option<reality::RealityClientConfig>,
    pub transport: VlessTransportConfig,
}

#[derive(Clone, Debug)]
pub struct VlessServerConfig {
    pub listen: SocketAddr,
    pub user_id: String,
    pub users: Vec<String>,
    pub tls: bool,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub certificates: Vec<String>,
    pub key: Option<String>,
    pub flow: String,
    pub reality: Option<reality::RealityServerConfig>,
    pub transport: VlessTransportConfig,
    pub ech: Option<TlsEchServerKeys>,
}

struct VlessRequest {
    user: [u8; 16],
    command: u8,
    target: ProxyTarget,
    flow: String,
}

type BoxedVlessStream = vless_transport::BoxedTransportStream;

#[derive(Clone)]
struct RealityServerState {
    config: reality::RealityServerConfig,
    cert_state: Arc<reality::RealityCertificateState>,
}

pub async fn run_vless_client(config: VlessClientConfig) -> Result<()> {
    run_vless_client_with_core(config, None).await
}

pub async fn run_vless_client_with_core(
    config: VlessClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind VLESS SOCKS listener on {}", config.listen))?;
    run_vless_client_listener(listener, config, core).await
}

pub async fn run_vless_client_listener(
    listener: TcpListener,
    config: VlessClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    tracing::info!(
        "VLESS client listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = listener.accept().await.context("accept SOCKS client")?;
        let config = config.clone();
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_vless_socks_with_core(stream, config, core, peer).await {
                tracing::warn!("VLESS SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn run_vless_server(config: VlessServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.user_id, &config.users);
    run_vless_server_with_core(config, core).await
}

pub async fn run_vless_server_with_core(config: VlessServerConfig, core: ProxyCore) -> Result<()> {
    ensure!(
        !(config.reality.is_some()
            && config.ech.as_ref().is_some_and(TlsEchServerKeys::is_configured)),
        "VLESS REALITY and TLS ECH are mutually exclusive server modes"
    );
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind VLESS server on {}", config.listen))?;
    let acceptor = if config.reality.is_none() && config.tls {
        Some(tls::build_server_tls_acceptor(&ServerTlsMaterial {
            cert_path: tls::present_path(&config.cert_path).map(PathBuf::from),
            key_path: tls::present_path(&config.key_path).map(PathBuf::from),
            certificates: config.certificates.clone(),
            key: config.key.clone(),
            label: "VLESS server TLS".to_string(),
            alpn_protocols: config.transport.alpn_protocols(),
            early_data: false,
            ech: config.ech.clone(),
        })?)
    } else {
        None
    };
    let transport_alpn = config.transport.alpn_protocols();
    let reality = config
        .reality
        .clone()
        .map(|mut config| {
            if config.alpn_protocols.is_empty() {
                config.alpn_protocols = transport_alpn.clone();
            }
            Ok::<_, anyhow::Error>(RealityServerState {
                config,
                cert_state: Arc::new(reality::RealityCertificateState::build()?),
            })
        })
        .transpose()?;
    let users = vless_users(&config.user_id, &config.users)?;
    let flow = config.flow.clone();
    let transport = config.transport.clone();
    tracing::info!("VLESS server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await.context("accept VLESS client")?;
        let acceptor = acceptor.clone();
        let reality = reality.clone();
        let users = users.clone();
        let core = core.clone();
        let flow = flow.clone();
        let transport = transport.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_vless_client(
                stream, acceptor, reality, users, core, flow, transport, peer,
            )
            .await
            {
                tracing::warn!("VLESS client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_vless_socks_with_core(
    mut stream: TcpStream,
    config: VlessClientConfig,
    core: Option<ProxyCore>,
    peer: SocketAddr,
) -> Result<()> {
    let (request, mut stream) = socks::handle_socks_greeting(stream).await?;
    let session = if let Some(core) = core.as_ref() {
        core.authenticate_from(&config.user_id, peer).await?
    } else {
        CoreSession::disabled()
    };
    match request {
        socks::SocksRequest::Connect(target) => {
            let mut server = connect_vless_server(&config).await?;
            let user = parse_uuid(&config.user_id)?;
            if config.mux {
                write_vless_request(&mut server, &user, CMD_MUX, &vless_xudp::mux_target(), "")
                    .await?;
                read_vless_response_header(&mut server).await?;
                socks::write_reply(&mut stream, 0x00).await?;
                return vless_mux::relay_single_tcp_client_counted(server, stream, target, session)
                    .await;
            }
            write_vless_request(&mut server, &user, CMD_TCP, &target, &config.flow).await?;
            read_vless_response_header(&mut server).await?;
            socks::write_reply(&mut stream, 0x00).await?;
            tracing::info!("VLESS proxying {}", target_name(&target));
            if is_vision_flow(&config.flow) {
                relay_vision_client_counted(stream, server, user, session).await
            } else {
                relay_bidirectional_counted(&mut stream, &mut server, session, "VLESS").await
            }
        }
        socks::SocksRequest::UdpAssociate => {
            ensure!(config.udp, "VLESS UDP is disabled by client config");
            handle_vless_udp_associate_counted(stream, config, session).await
        }
    }
}

async fn handle_vless_udp_associate_counted(
    mut control: TcpStream,
    config: VlessClientConfig,
    session: CoreSession,
) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("bind VLESS SOCKS UDP associate socket on {bind_ip}:0"))?,
    );
    socks::write_reply_with_bind(&mut control, 0x00, udp.local_addr()?).await?;
    let user = parse_uuid(&config.user_id)?;
    if config.packet_encoding.eq_ignore_ascii_case("xudp") {
        return handle_vless_xudp_associate_counted(control, config, udp, user, session).await;
    }

    let pool = Arc::new(VlessUdpSessionPool::new(config.clone(), user).await?);
    let udp_loop = {
        let udp = udp.clone();
        let session = session.clone();
        let pool = pool.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive SOCKS UDP packet")?;
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                session.record_upload(payload.len()).await?;
                let response = pool.roundtrip(&target, payload).await?;
                session.record_download(response.len()).await?;
                let packet = uot::encode_socks_udp_packet(&target, &response)?;
                udp.send_to(&packet, peer)
                    .await
                    .with_context(|| format!("send SOCKS UDP response to {peer}"))?;
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
        result = udp_loop => result,
        result = control_closed => result,
    }
}

async fn vless_udp_roundtrip_on_stream<S>(server: &mut S, payload: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_vless_udp_frame(server, payload).await?;
    server.flush().await.context("flush VLESS UDP request")?;
    read_vless_udp_frame(server)
        .await?
        .context("VLESS UDP response missing")
}

struct VlessUdpSessionPool {
    config: VlessClientConfig,
    user: [u8; 16],
    sessions: Mutex<HashMap<String, BoxedVlessStream>>,
}

impl VlessUdpSessionPool {
    async fn new(config: VlessClientConfig, user: [u8; 16]) -> Result<Self> {
        Ok(Self {
            config,
            user,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    async fn roundtrip(&self, target: &ProxyTarget, payload: &[u8]) -> Result<Vec<u8>> {
        let key = target_name(target);
        let mut sessions = self.sessions.lock().await;
        if !sessions.contains_key(&key) {
            let mut server = connect_vless_server(&self.config).await?;
            write_vless_request(&mut server, &self.user, CMD_UDP, target, "").await?;
            read_vless_response_header(&mut server).await?;
            sessions.insert(key.clone(), server);
        }
        let server = sessions
            .get_mut(&key)
            .expect("VLESS UDP session pool entry exists");
        vless_udp_roundtrip_on_stream(server, payload).await
    }
}

async fn handle_vless_xudp_associate_counted(
    mut control: TcpStream,
    config: VlessClientConfig,
    udp: Arc<UdpSocket>,
    user: [u8; 16],
    session: CoreSession,
) -> Result<()> {
    let mut server = connect_vless_server(&config).await?;
    write_vless_request(&mut server, &user, CMD_UDP, &vless_xudp::mux_target(), "").await?;
    read_vless_response_header(&mut server).await?;
    let (mut reader, mut writer) = tokio::io::split(server);
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<SocketAddr>(8);

    let udp_to_xudp = {
        let udp = udp.clone();
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
                vless_xudp::write_client_packet(&mut writer, &target, payload, true).await?;
            }
        }
    };

    let xudp_to_udp = {
        let udp = udp.clone();
        let session = session.clone();
        async move {
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => if let Some(next_peer) = next_peer { peer = Some(next_peer); },
                    packet = vless_xudp::read_response_packet(&mut reader) => {
                        let Some((source, payload)) = packet? else { return Ok::<(), anyhow::Error>(()); };
                        session.record_download(payload.len()).await?;
                        let response = uot::encode_socks_udp_packet(&source, &payload)?;
                        let peer = peer.context("SOCKS UDP peer is not known yet")?;
                        udp.send_to(&response, peer)
                            .await
                            .with_context(|| format!("send SOCKS XUDP response to {peer}"))?;
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
        result = udp_to_xudp => result,
        result = xudp_to_udp => result,
        result = control_closed => result,
    }
}

async fn connect_vless_server(config: &VlessClientConfig) -> Result<BoxedVlessStream> {
    let tcp =
        socket_protect::connect_tcp_host_port(config.server_host.as_str(), config.server_port)
            .await
            .with_context(|| {
                format!(
                    "connect VLESS server {}:{}",
                    config.server_host, config.server_port
                )
            })?;
    if let Some(reality) = config.reality.as_ref() {
        let fingerprint = config
            .client_fingerprint
            .unwrap_or(utls::UtlsFingerprint::Chrome);
        let alpn = config.transport.alpn_protocols();
        let alpn = if alpn.is_empty() { None } else { Some(alpn) };
        let stream = reality_tls_client::connect(tcp, reality, &config.sni, fingerprint, alpn)
            .await
            .context("REALITY connect to VLESS server")?;
        return vless_transport::apply_client_transport(stream, &config.transport, &config.server_host).await;
    }
    if !config.tls {
        return vless_transport::apply_client_transport(tcp, &config.transport, &config.server_host).await;
    }
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
        .with_context(|| format!("invalid VLESS SNI: {}", config.sni))?;
    let stream = connector
        .connect(server_name, tcp)
        .await
        .context("TLS connect to VLESS server")?;
    vless_transport::apply_client_transport(stream, &config.transport, &config.server_host).await
}

async fn accept_reality_tls(
    stream: TcpStream,
    reality: &RealityServerState,
) -> Result<Option<tokio_rustls::server::TlsStream<TcpStream>>> {
    let client_hello = reality::peek_client_hello(&stream)
        .await
        .context("peek VLESS REALITY ClientHello")?;
    let authenticated = match reality::authenticate_client_hello(&client_hello, &reality.config) {
        Ok(authenticated) => authenticated,
        Err(error) => {
            tracing::warn!("VLESS REALITY ClientHello rejected: {error:?}");
            reality::proxy_fallback(stream, &reality.config).await?;
            return Ok(None);
        }
    };
    let server_config = reality
        .cert_state
        .server_config(&authenticated.auth_key, &reality.config.alpn_protocols)?;
    let stream = TlsAcceptor::from(server_config)
        .accept(stream)
        .await
        .context("accept VLESS REALITY TLS")?;
    Ok(Some(stream))
}

async fn handle_vless_client(
    stream: TcpStream,
    acceptor: Option<ServerTlsAcceptor>,
    reality: Option<RealityServerState>,
    users: HashMap<[u8; 16], String>,
    core: ProxyCore,
    allowed_flow: String,
    transport: VlessTransportConfig,
    peer: SocketAddr,
) -> Result<()> {
    let mut stream = if let Some(reality) = reality {
        let Some(stream) = accept_reality_tls(stream, &reality).await? else {
            return Ok(());
        };
        vless_transport::apply_server_transport(stream, &transport).await?
    } else if let Some(acceptor) = acceptor {
        let stream = acceptor.accept(stream).await.context("accept VLESS TLS")?;
        vless_transport::apply_server_transport(stream, &transport).await?
    } else {
        vless_transport::apply_server_transport(stream, &transport).await?
    };
    let request = read_vless_request(&mut stream).await?;
    let credential = users
        .get(&request.user)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("VLESS authentication failed"))?;
    validate_flow(&request, &allowed_flow)?;
    let session = core.authenticate_from(&credential, peer).await?;
    match request.command {
        CMD_TCP => {
            let mut remote = socket_protect::connect_proxy_target(&request.target).await?;
            write_vless_response_header(&mut stream).await?;
            tracing::info!("VLESS opened {}", target_name(&request.target));
            if is_vision_flow(&request.flow) {
                relay_vision_server_counted(stream, remote, session, request.user).await
            } else {
                relay_bidirectional_counted(&mut stream, &mut remote, session, "VLESS").await
            }
        }
        CMD_UDP => {
            write_vless_response_header(&mut stream).await?;
            if vless_xudp::is_mux_target(&request.target) {
                vless_xudp::relay_server(stream, session).await
            } else {
                relay_vless_udp(stream, request.target, session).await
            }
        }
        CMD_MUX => {
            write_vless_response_header(&mut stream).await?;
            vless_mux::relay_server(stream, session).await
        }
        other => bail!("unsupported VLESS command {other:#x}"),
    }
}


async fn relay_vision_server_counted<S>(
    stream: S,
    mut remote: TcpStream,
    session: CoreSession,
    user: [u8; 16],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (client_reader, mut client_writer) = tokio::io::split(stream);
    let mut client_reader = vless_vision::VisionReader::new(client_reader, user);
    let (mut remote_reader, mut remote_writer) = remote.split();
    let uplink_session = session.clone();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = client_reader
                .read(&mut buffer)
                .await
                .context("read VLESS Vision uplink")?;
            if read == 0 {
                let _ = remote_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            uplink_session.record_upload(read).await?;
            remote_writer
                .write_all(&buffer[..read])
                .await
                .context("write VLESS Vision uplink")?;
        }
    };
    let downlink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        let mut first = true;
        loop {
            let read = remote_reader
                .read(&mut buffer)
                .await
                .context("read VLESS Vision downlink")?;
            if read == 0 {
                let _ = client_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            session.record_download(read).await?;
            if first {
                first = false;
                let encoded = vless_vision::encode_end_frame(&user, &buffer[..read])?;
                client_writer
                    .write_all(&encoded)
                    .await
                    .context("write VLESS Vision first downlink")?;
            } else {
                client_writer
                    .write_all(&buffer[..read])
                    .await
                    .context("write VLESS Vision downlink")?;
            }
        }
    };
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

async fn relay_vision_client_counted(
    local: TcpStream,
    server: BoxedVlessStream,
    user: [u8; 16],
    session: CoreSession,
) -> Result<()> {
    let (mut local_reader, mut local_writer) = local.into_split();
    let (mut server_reader, mut server_writer) = tokio::io::split(server);
    let mut server_reader = vless_vision::VisionReader::new(&mut server_reader, user);
    let uplink_session = session.clone();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        let mut first = true;
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read local Vision payload")?;
            if read == 0 {
                let _ = server_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            uplink_session.record_upload(read).await?;
            if first {
                first = false;
                let encoded = vless_vision::encode_end_frame(&user, &buffer[..read])?;
                server_writer
                    .write_all(&encoded)
                    .await
                    .context("write first VLESS Vision payload")?;
            } else {
                server_writer
                    .write_all(&buffer[..read])
                    .await
                    .context("write VLESS Vision payload")?;
            }
        }
    };
    let downlink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = server_reader
                .read(&mut buffer)
                .await
                .context("read VLESS Vision response")?;
            if read == 0 {
                let _ = local_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            session.record_download(read).await?;
            local_writer
                .write_all(&buffer[..read])
                .await
                .context("write local Vision response")?;
        }
    };
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

async fn relay_vless_udp<S>(mut stream: S, target: ProxyTarget, session: CoreSession) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target_addr = resolve_target_addr(&target).await?;
    let udp = UdpSocket::bind(if target_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await
    .context("bind VLESS UDP socket")?;
    udp.connect(target_addr)
        .await
        .with_context(|| format!("connect VLESS UDP target {target_addr}"))?;
    while let Some(payload) = read_vless_udp_frame(&mut stream).await? {
        session.record_upload(payload.len()).await?;
        udp.send(&payload)
            .await
            .with_context(|| format!("send VLESS UDP payload to {target_addr}"))?;
        let mut buffer = vec![0u8; u16::MAX as usize];
        let read = udp
            .recv(&mut buffer)
            .await
            .context("receive VLESS UDP response")?;
        session.record_download(read).await?;
        write_vless_udp_frame(&mut stream, &buffer[..read]).await?;
    }
    Ok(())
}

async fn write_vless_request<W>(
    writer: &mut W,
    user: &[u8; 16],
    command: u8,
    target: &ProxyTarget,
    flow: &str,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[VERSION]).await?;
    writer.write_all(user).await?;
    let addons = encode_addons(flow)?;
    writer.write_all(&[addons.len() as u8]).await?;
    writer.write_all(&addons).await?;
    writer.write_all(&[command]).await?;
    if command != CMD_TCP && command != CMD_UDP && command != CMD_MUX {
        bail!("unsupported VLESS command {command:#x}");
    }
    if command != CMD_MUX {
        write_vless_address(writer, target).await?;
    }
    writer.flush().await.context("flush VLESS request")
}

async fn read_vless_request<R>(reader: &mut R) -> Result<VlessRequest>
where
    R: AsyncRead + Unpin,
{
    let version = read_u8(reader).await?;
    ensure!(version == VERSION, "unsupported VLESS version {version:#x}");
    let mut user = [0u8; 16];
    reader
        .read_exact(&mut user)
        .await
        .context("read VLESS user id")?;
    let addons_len = read_u8(reader).await? as usize;
    let flow = if addons_len > 0 {
        let mut addons = vec![0u8; addons_len];
        reader
            .read_exact(&mut addons)
            .await
            .context("read VLESS addons")?;
        decode_flow_addon(&addons)?
    } else {
        String::new()
    };
    let command = read_u8(reader).await?;
    let target = if command == CMD_MUX {
        vless_xudp::mux_target()
    } else {
        read_vless_address(reader).await?
    };
    Ok(VlessRequest {
        user,
        command,
        target,
        flow,
    })
}

async fn write_vless_response_header<W>(writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[VERSION, 0])
        .await
        .context("write VLESS response header")
}

async fn read_vless_response_header<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let version = read_u8(reader).await?;
    ensure!(
        version == VERSION,
        "unsupported VLESS response version {version:#x}"
    );
    let addons_len = read_u8(reader).await? as usize;
    if addons_len > 0 {
        let mut addons = vec![0u8; addons_len];
        reader
            .read_exact(&mut addons)
            .await
            .context("read VLESS response addons")?;
    }
    Ok(())
}

async fn write_vless_udp_frame<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    ensure!(
        payload.len() <= u16::MAX as usize,
        "VLESS UDP payload too large"
    );
    writer
        .write_all(&(payload.len() as u16).to_be_bytes())
        .await?;
    writer
        .write_all(payload)
        .await
        .context("write VLESS UDP frame")
}

async fn read_vless_udp_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    match reader.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("read VLESS UDP frame length"),
    }
    let mut payload = vec![0u8; u16::from_be_bytes(length) as usize];
    reader
        .read_exact(&mut payload)
        .await
        .context("read VLESS UDP frame payload")?;
    Ok(Some(payload))
}

async fn write_vless_address<W>(writer: &mut W, target: &ProxyTarget) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match target {
        ProxyTarget::Ip(addr) => {
            writer.write_all(&addr.port().to_be_bytes()).await?;
            match addr.ip() {
                IpAddr::V4(ip) => {
                    writer.write_all(&[ATYP_IPV4]).await?;
                    writer.write_all(&ip.octets()).await?;
                }
                IpAddr::V6(ip) => {
                    writer.write_all(&[ATYP_IPV6]).await?;
                    writer.write_all(&ip.octets()).await?;
                }
            }
        }
        ProxyTarget::Domain(host, port) => {
            ensure!(host.len() <= u8::MAX as usize, "VLESS domain too long");
            writer.write_all(&port.to_be_bytes()).await?;
            writer.write_all(&[ATYP_DOMAIN, host.len() as u8]).await?;
            writer.write_all(host.as_bytes()).await?;
        }
    }
    Ok(())
}

async fn read_vless_address<R>(reader: &mut R) -> Result<ProxyTarget>
where
    R: AsyncRead + Unpin,
{
    let port = read_port(reader).await?;
    match read_u8(reader).await? {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader
                .read_exact(&mut octets)
                .await
                .context("read VLESS IPv4 address")?;
            Ok(ProxyTarget::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader
                .read_exact(&mut octets)
                .await
                .context("read VLESS IPv6 address")?;
            Ok(ProxyTarget::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let length = read_u8(reader).await? as usize;
            let mut host = vec![0u8; length];
            reader
                .read_exact(&mut host)
                .await
                .context("read VLESS domain")?;
            Ok(ProxyTarget::Domain(
                String::from_utf8(host).context("decode VLESS domain")?,
                port,
            ))
        }
        other => bail!("unsupported VLESS address type {other:#x}"),
    }
}

fn is_vision_flow(flow: &str) -> bool {
    flow.trim().eq_ignore_ascii_case(FLOW_XTLS_RPRX_VISION)
}

fn validate_flow(request: &VlessRequest, allowed_flow: &str) -> Result<()> {
    if request.flow.trim().is_empty() {
        return Ok(());
    }
    ensure!(
        is_vision_flow(&request.flow),
        "unsupported VLESS flow {}",
        request.flow
    );
    ensure!(
        is_vision_flow(allowed_flow),
        "VLESS client requested flow {} but server flow is {}",
        request.flow,
        allowed_flow
    );
    ensure!(
        request.command == CMD_TCP,
        "VLESS xtls-rprx-vision flow only supports TCP"
    );
    Ok(())
}

fn encode_addons(flow: &str) -> Result<Vec<u8>> {
    if flow.trim().is_empty() {
        return Ok(Vec::new());
    }
    ensure!(is_vision_flow(flow), "unsupported VLESS flow {flow}");
    let flow = flow.trim().as_bytes();
    ensure!(flow.len() <= u8::MAX as usize, "VLESS flow addon too long");
    let mut addons = Vec::with_capacity(2 + flow.len());
    addons.push(0x0a);
    addons.push(flow.len() as u8);
    addons.extend_from_slice(flow);
    ensure!(addons.len() <= u8::MAX as usize, "VLESS addons too long");
    Ok(addons)
}

fn decode_flow_addon(addons: &[u8]) -> Result<String> {
    let mut cursor = 0usize;
    let mut flow = String::new();
    while cursor < addons.len() {
        let key = read_varint(addons, &mut cursor)?;
        let field_number = key >> 3;
        let wire_type = key & 0x07;
        match (field_number, wire_type) {
            (1, 2) => {
                let value = read_length_delimited(addons, &mut cursor)?;
                flow = String::from_utf8(value.to_vec()).context("decode VLESS flow addon")?;
            }
            (_, 0) => {
                let _ = read_varint(addons, &mut cursor)?;
            }
            (_, 2) => {
                let _ = read_length_delimited(addons, &mut cursor)?;
            }
            _ => bail!("unsupported VLESS addons wire type {wire_type}"),
        }
    }
    Ok(flow)
}

fn read_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        ensure!(*cursor < bytes.len(), "truncated VLESS addons varint");
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        ensure!(shift < 64, "VLESS addons varint is too large");
    }
}

fn read_length_delimited<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let len = read_varint(bytes, cursor)? as usize;
    ensure!(
        *cursor + len <= bytes.len(),
        "truncated VLESS addons payload"
    );
    let start = *cursor;
    *cursor += len;
    Ok(&bytes[start..start + len])
}

fn vless_users(user_id: &str, users: &[String]) -> Result<HashMap<[u8; 16], String>> {
    let mut map = HashMap::new();
    for credential in std::iter::once(user_id).chain(users.iter().map(String::as_str)) {
        let credential = credential.trim();
        if credential.is_empty() {
            continue;
        }
        map.insert(parse_uuid(credential)?, credential.to_string());
    }
    Ok(map)
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

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

    #[tokio::test]
    async fn request_roundtrip() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 443);
        let mut bytes = Vec::new();
        write_vless_request(&mut bytes, &parse_uuid(UUID)?, CMD_TCP, &target, "").await?;
        let request = read_vless_request(&mut bytes.as_slice()).await?;
        assert_eq!(request.user, parse_uuid(UUID)?);
        assert_eq!(request.command, CMD_TCP);
        assert_eq!(request.target, target);
        Ok(())
    }
}
