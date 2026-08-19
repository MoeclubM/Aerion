use crate::core::{CoreSession, ProxyCore};
use crate::protocol::{ProxyTarget, parse_uuid, resolve_target_addr, target_name};
use crate::tls::{ServerTlsAcceptor, ServerTlsMaterial, TlsEchServerKeys};
use crate::vless_transport::VlessTransportConfig;
use crate::vmess_body::{BodyConfig, BodyReader, BodyWriter, RequestOptions, SecurityType};
use crate::{socket_protect, socks, tls, uot, utls, vless_transport, vless_xudp};
use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, generic_array::GenericArray};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use anyhow::{Context, Result, bail, ensure};
use md5::Md5;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::WriteHalf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

const AUTH_ID_REPLAY_TTL: Duration = Duration::from_secs(120);
const SESSION_HISTORY_TTL: Duration = Duration::from_secs(180);
const VERSION: u8 = 0x01;

struct VmessReplayFilter {
    auth_ids: std::sync::Mutex<HashMap<[u8; 16], Instant>>,
    sessions: std::sync::Mutex<HashMap<([u8; 16], [u8; 16], [u8; 16]), Instant>>,
}

impl VmessReplayFilter {
    fn new() -> Self {
        Self {
            auth_ids: std::sync::Mutex::new(HashMap::new()),
            sessions: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn check_auth_id(&self, auth_id: [u8; 16]) -> Result<()> {
        let now = Instant::now();
        let mut guard = self
            .auth_ids
            .lock()
            .expect("VMess auth id replay lock poisoned");
        guard.retain(|_, seen| now.duration_since(*seen) <= AUTH_ID_REPLAY_TTL);
        ensure!(
            guard.insert(auth_id, now).is_none(),
            "VMess AuthID replay detected"
        );
        Ok(())
    }

    fn check_session(&self, user: [u8; 16], body_key: [u8; 16], body_iv: [u8; 16]) -> Result<()> {
        let now = Instant::now();
        let mut guard = self
            .sessions
            .lock()
            .expect("VMess session history lock poisoned");
        guard.retain(|_, seen| now.duration_since(*seen) <= SESSION_HISTORY_TTL);
        ensure!(
            guard.insert((user, body_key, body_iv), now).is_none(),
            "VMess session replay detected"
        );
        Ok(())
    }
}
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
const CMD_MUX: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const AEAD_TAG_LEN: usize = 16;
const HMAC_BLOCK_SIZE: usize = 64;
const AUTH_ID_ENCRYPTION_KEY_SALT: &str = "AES Auth ID Encryption";
const VMESS_AEAD_KDF_SALT: &[u8] = b"VMess AEAD KDF";
const VMESS_HEADER_PAYLOAD_KEY_SALT: &str = "VMess Header AEAD Key";
const VMESS_HEADER_PAYLOAD_IV_SALT: &str = "VMess Header AEAD Nonce";
const VMESS_HEADER_LENGTH_KEY_SALT: &str = "VMess Header AEAD Key_Length";
const VMESS_HEADER_LENGTH_IV_SALT: &str = "VMess Header AEAD Nonce_Length";
const AEAD_RESPONSE_HEADER_LENGTH_KEY_SALT: &str = "AEAD Resp Header Len Key";
const AEAD_RESPONSE_HEADER_LENGTH_IV_SALT: &str = "AEAD Resp Header Len IV";
const AEAD_RESPONSE_HEADER_PAYLOAD_KEY_SALT: &str = "AEAD Resp Header Key";
const AEAD_RESPONSE_HEADER_PAYLOAD_IV_SALT: &str = "AEAD Resp Header IV";

#[derive(Clone, Debug)]
pub struct VmessClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub user_id: String,
    pub security: String,
    pub packet_encoding: String,
    pub udp: bool,
    pub tls: bool,
    pub sni: String,
    pub insecure: bool,
    pub ca_cert_paths: Vec<PathBuf>,
    pub ca_certificates: Vec<String>,
    pub disable_system_roots: bool,
    pub pinned_cert_sha256: Vec<String>,
    pub client_fingerprint: Option<utls::UtlsFingerprint>,
    pub transport: VlessTransportConfig,
}

#[derive(Clone, Debug)]
pub struct VmessServerConfig {
    pub listen: SocketAddr,
    pub user_id: String,
    pub users: Vec<String>,
    pub tls: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub certificates: Vec<String>,
    pub key: Option<String>,
    pub transport: VlessTransportConfig,
    pub ech: Option<TlsEchServerKeys>,
}

type VmessTransport = vless_transport::BoxedTransportStream;

struct VmessRequest {
    command: u8,
    target: ProxyTarget,
    response_header: u8,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    options: RequestOptions,
    security: SecurityType,
}

struct VmessClientKeys {
    response_header: u8,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    options: RequestOptions,
    security: SecurityType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmessPacketEncoding {
    PerTarget,
    PacketAddr,
    Xudp,
}

pub fn ensure_vmess_packet_encoding(value: &str) -> Result<()> {
    vmess_packet_encoding(value).map(|_| ())
}

fn vmess_packet_encoding(value: &str) -> Result<VmessPacketEncoding> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "none" => Ok(VmessPacketEncoding::PerTarget),
        "packetaddr" | "packet-addr" => Ok(VmessPacketEncoding::PacketAddr),
        "xudp" => Ok(VmessPacketEncoding::Xudp),
        other => bail!("unsupported VMess packet_encoding {other}"),
    }
}

impl VmessRequest {
    fn request_body_config(&self) -> Result<BodyConfig> {
        BodyConfig::new_request(
            self.security,
            self.options,
            self.request_body_key,
            self.request_body_iv,
        )
    }

    fn response_body_config(&self) -> Result<BodyConfig> {
        BodyConfig::new_response(
            self.security,
            self.options,
            self.request_body_key,
            self.request_body_iv,
        )
    }
}

pub async fn run_vmess_client(config: VmessClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind VMess SOCKS listener on {}", config.listen))?;
    run_vmess_client_listener(listener, config).await
}

pub async fn run_vmess_client_listener(
    listener: TcpListener,
    config: VmessClientConfig,
) -> Result<()> {
    run_vmess_client_listener_with_core(listener, config, None).await
}

pub async fn run_vmess_client_listener_with_core(
    listener: TcpListener,
    config: VmessClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    tracing::info!(
        "VMess client listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = crate::listener::accept_tcp(&listener)
            .await
            .context("accept SOCKS client")?;
        let config = config.clone();
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_vmess_socks(stream, config, core, peer).await {
                tracing::warn!("VMess SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn run_vmess_server(config: VmessServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.user_id, &config.users);
    run_vmess_server_with_core(config, core).await
}

pub async fn run_vmess_server_with_core(config: VmessServerConfig, core: ProxyCore) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind VMess server on {}", config.listen))?;
    let users = vmess_users(&config.user_id, &config.users)?;
    let acceptor = if config.tls {
        Some(tls::build_server_tls_acceptor(&ServerTlsMaterial {
            cert_path: config.cert_path.clone(),
            key_path: config.key_path.clone(),
            certificates: config.certificates.clone(),
            key: config.key.clone(),
            label: "VMess server TLS".to_string(),
            alpn_protocols: config.transport.alpn_protocols(),
            early_data: false,
            ech: config.ech.clone(),
        })?)
    } else {
        None
    };
    let transport = config.transport.clone();
    let replay = Arc::new(VmessReplayFilter::new());
    tracing::info!("VMess server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = crate::listener::accept_tcp(&listener)
            .await
            .context("accept VMess client")?;
        let acceptor = acceptor.clone();
        let users = users.clone();
        let core = core.clone();
        let transport = transport.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            let result = async {
                let stream = accept_vmess_transport(stream, acceptor).await?;
                let stream = vless_transport::apply_server_transport(stream, &transport).await?;
                handle_vmess_client(stream, users, core, peer, replay).await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!("VMess client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_vmess_socks(
    mut local: TcpStream,
    config: VmessClientConfig,
    core: Option<ProxyCore>,
    peer: SocketAddr,
) -> Result<()> {
    let _session = if let Some(core) = core.as_ref() {
        Some(core.authenticate_from(&config.user_id, peer).await?)
    } else {
        None
    };
    match socks::read_request(&mut local).await? {
        socks::SocksRequest::Connect(target) => {
            let mut server = connect_vmess_transport(&config).await?;
            let security = SecurityType::from_name(&config.security)?;
            let options = vmess_request_options(CMD_TCP, security);
            let keys = write_vmess_request(
                &mut server,
                &parse_uuid(&config.user_id)?,
                CMD_TCP,
                &target,
                security,
                options,
            )
            .await?;
            read_vmess_response_header(&mut server, &keys).await?;
            socks::write_reply(&mut local, 0x00).await?;
            tracing::info!("VMess proxying {}", target_name(&target));
            relay_vmess_client_tcp(local, server, keys).await
        }
        socks::SocksRequest::UdpAssociate => {
            ensure!(config.udp, "VMess UDP is disabled by client config");
            handle_vmess_udp_associate(local, config).await
        }
    }
}

async fn connect_vmess_transport(config: &VmessClientConfig) -> Result<VmessTransport> {
    let tcp =
        socket_protect::connect_tcp_host_port(config.server_host.as_str(), config.server_port)
            .await
            .with_context(|| {
                format!(
                    "connect VMess server {}:{}",
                    config.server_host, config.server_port
                )
            })?;
    if !config.tls {
        return vless_transport::apply_client_transport(
            tcp,
            &config.transport,
            &config.server_host,
        )
        .await;
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
    let sni = if config.sni.trim().is_empty() {
        config.server_host.clone()
    } else {
        config.sni.clone()
    };
    let server_name =
        ServerName::try_from(sni.clone()).with_context(|| format!("invalid VMess SNI: {sni}"))?;
    let stream = connector
        .connect(server_name, tcp)
        .await
        .context("TLS connect to VMess server")?;
    vless_transport::apply_client_transport(stream, &config.transport, &config.server_host).await
}

async fn accept_vmess_transport(
    stream: TcpStream,
    acceptor: Option<ServerTlsAcceptor>,
) -> Result<VmessTransport> {
    match acceptor {
        Some(acceptor) => Ok(Box::new(
            acceptor.accept(stream).await.context("accept VMess TLS")?,
        )),
        None => Ok(Box::new(stream)),
    }
}

async fn handle_vmess_client(
    mut stream: VmessTransport,
    users: HashMap<[u8; 16], String>,
    core: ProxyCore,
    peer: SocketAddr,
    replay: Arc<VmessReplayFilter>,
) -> Result<()> {
    let (request, credential) =
        read_vmess_request(&mut stream, &users, Some(replay.as_ref())).await?;
    let session = core.authenticate_from(&credential, peer).await?;
    match request.command {
        CMD_TCP => {
            let remote = socket_protect::connect_proxy_target(&request.target).await?;
            write_vmess_response_header(&mut stream, &request).await?;
            tracing::info!("VMess opened {}", target_name(&request.target));
            relay_vmess_tcp(stream, remote, request, session).await
        }
        CMD_UDP => {
            write_vmess_response_header(&mut stream, &request).await?;
            relay_vmess_udp(stream, request, session).await
        }
        CMD_MUX if vless_xudp::is_mux_target(&request.target) => {
            write_vmess_response_header(&mut stream, &request).await?;
            relay_vmess_udp(stream, request, session).await
        }
        CMD_MUX => bail!(
            "unsupported VMess mux target {}",
            target_name(&request.target)
        ),
        other => bail!("unsupported VMess command {other:#x}"),
    }
}

async fn relay_vmess_client_tcp(
    local: TcpStream,
    server: VmessTransport,
    keys: VmessClientKeys,
) -> Result<()> {
    let request_config = BodyConfig::new_request(
        keys.security,
        keys.options,
        keys.request_body_key,
        keys.request_body_iv,
    )?;
    let response_config = BodyConfig::new_response(
        keys.security,
        keys.options,
        keys.request_body_key,
        keys.request_body_iv,
    )?;
    let (mut local_reader, mut local_writer) = local.into_split();
    let (server_reader, server_writer) = tokio::io::split(server);
    let mut server_reader = BodyReader::new(server_reader, response_config);
    let mut server_writer = BodyWriter::new(server_writer, request_config);

    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read VMess local uplink")?;
            if read == 0 {
                return server_writer.finish().await;
            }
            server_writer
                .write_all_plain(&buffer[..read])
                .await
                .context("write VMess client uplink")?;
        }
    };
    let downlink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = server_reader
                .read_plain(&mut buffer)
                .await
                .context("read VMess client downlink")?;
            if read == 0 {
                return local_writer
                    .shutdown()
                    .await
                    .context("shutdown VMess local downlink");
            }
            local_writer
                .write_all(&buffer[..read])
                .await
                .context("write VMess local downlink")?;
        }
    };
    let result = tokio::select! {
        result = uplink => result,
        result = downlink => result,
    };
    let _ = server_writer.finish().await;
    let _ = local_writer.shutdown().await;
    result
}

async fn relay_vmess_tcp(
    stream: VmessTransport,
    remote: TcpStream,
    request: VmessRequest,
    session: CoreSession,
) -> Result<()> {
    let request_config = request.request_body_config()?;
    let response_config = request.response_body_config()?;
    let (client_reader, client_writer) = tokio::io::split(stream);
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let mut client_reader = BodyReader::new(client_reader, request_config);
    let mut client_writer = BodyWriter::new(client_writer, response_config);

    let uplink_session = session.clone();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = client_reader
                .read_plain(&mut buffer)
                .await
                .context("read VMess TCP uplink body")?;
            if read == 0 {
                let _ = remote_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            uplink_session.record_upload(read).await?;
            remote_writer
                .write_all(&buffer[..read])
                .await
                .context("write VMess TCP uplink")?;
        }
    };
    let downlink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = remote_reader
                .read(&mut buffer)
                .await
                .context("read VMess TCP downlink")?;
            if read == 0 {
                return client_writer.finish().await;
            }
            session.record_download(read).await?;
            client_writer
                .write_all_plain(&buffer[..read])
                .await
                .context("write VMess TCP downlink body")?;
        }
    };
    let result = tokio::select! {
        result = uplink => result,
        result = downlink => result,
    };
    let _ = remote_writer.shutdown().await;
    let _ = client_writer.finish().await;
    result
}

async fn handle_vmess_udp_associate(
    mut control: TcpStream,
    config: VmessClientConfig,
) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("bind VMess SOCKS UDP associate socket on {bind_ip}:0"))?,
    );
    socks::write_reply_with_bind(&mut control, 0x00, udp.local_addr()?).await?;

    let peer = Arc::new(Mutex::new(None::<SocketAddr>));
    let tunnels = Arc::new(Mutex::new(HashMap::<
        String,
        Arc<Mutex<BodyWriter<WriteHalf<VmessTransport>>>>,
    >::new()));
    let user = parse_uuid(&config.user_id)?;
    match vmess_packet_encoding(&config.packet_encoding)? {
        VmessPacketEncoding::PacketAddr => {
            return handle_vmess_packetaddr_associate(control, config, udp, user).await;
        }
        VmessPacketEncoding::Xudp => {
            return handle_vmess_xudp_associate(control, config, udp, user).await;
        }
        VmessPacketEncoding::PerTarget => {}
    }

    let udp_loop = {
        let udp = udp.clone();
        let peer = peer.clone();
        let tunnels = tunnels.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, next_peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive SOCKS UDP packet")?;
                *peer.lock().await = Some(next_peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let key = target_name(&target);
                let writer = if let Some(writer) = tunnels.lock().await.get(&key).cloned() {
                    writer
                } else {
                    let writer = open_vmess_udp_tunnel(
                        &config,
                        user,
                        target.clone(),
                        udp.clone(),
                        peer.clone(),
                    )
                    .await?;
                    tunnels.lock().await.insert(key, writer.clone());
                    writer
                };
                writer
                    .lock()
                    .await
                    .write_packet_plain(payload)
                    .await
                    .context("write VMess UDP packet")?;
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
        result = control_closed => result,
        result = udp_loop => result,
    }
}

async fn handle_vmess_packetaddr_associate(
    mut control: TcpStream,
    config: VmessClientConfig,
    udp: Arc<UdpSocket>,
    user: [u8; 16],
) -> Result<()> {
    let mut server = connect_vmess_transport(&config).await?;
    let security = SecurityType::from_name(&config.security)?;
    let options = vmess_request_options(CMD_UDP, security);
    let keys = write_vmess_request(
        &mut server,
        &user,
        CMD_UDP,
        &vmess_packetaddr_target(),
        security,
        options,
    )
    .await?;
    read_vmess_response_header(&mut server, &keys).await?;
    let request_config = BodyConfig::new_request(
        keys.security,
        keys.options,
        keys.request_body_key,
        keys.request_body_iv,
    )?;
    let response_config = BodyConfig::new_response(
        keys.security,
        keys.options,
        keys.request_body_key,
        keys.request_body_iv,
    )?;
    let (reader, writer) = tokio::io::split(server);
    let mut reader = BodyReader::new(reader, response_config);
    let writer = Arc::new(Mutex::new(BodyWriter::new(writer, request_config)));
    let peer = Arc::new(Mutex::new(None::<SocketAddr>));

    let udp_to_vmess = {
        let udp = udp.clone();
        let peer = peer.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, next_peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive SOCKS UDP packet")?;
                *peer.lock().await = Some(next_peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let packet = encode_vmess_packetaddr_packet(&target, payload)?;
                writer
                    .lock()
                    .await
                    .write_packet_plain(&packet)
                    .await
                    .context("write VMess packetaddr packet")?;
            }
        }
    };
    let vmess_to_udp = {
        let udp = udp.clone();
        async move {
            loop {
                let Some(packet) = reader.read_packet().await? else {
                    return Ok::<(), anyhow::Error>(());
                };
                let (source, payload) = decode_vmess_packetaddr_packet(&packet)?;
                let response = uot::encode_socks_udp_packet(&source, payload)?;
                let peer = (*peer.lock().await).context("SOCKS UDP peer is not known yet")?;
                udp.send_to(&response, peer)
                    .await
                    .with_context(|| format!("send VMess packetaddr response to {peer}"))?;
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
        result = control_closed => result,
        result = udp_to_vmess => result,
        result = vmess_to_udp => result,
    }
}

async fn handle_vmess_xudp_associate(
    mut control: TcpStream,
    config: VmessClientConfig,
    udp: Arc<UdpSocket>,
    user: [u8; 16],
) -> Result<()> {
    let mut server = connect_vmess_transport(&config).await?;
    let security = SecurityType::from_name(&config.security)?;
    let options = vmess_request_options(CMD_MUX, security);
    let keys = write_vmess_request(
        &mut server,
        &user,
        CMD_MUX,
        &vless_xudp::mux_target(),
        security,
        options,
    )
    .await?;
    read_vmess_response_header(&mut server, &keys).await?;
    let request_config = BodyConfig::new_request(
        keys.security,
        keys.options,
        keys.request_body_key,
        keys.request_body_iv,
    )?;
    let response_config = BodyConfig::new_response(
        keys.security,
        keys.options,
        keys.request_body_key,
        keys.request_body_iv,
    )?;
    let (reader, writer) = tokio::io::split(server);
    let mut reader = BodyReader::new(reader, response_config);
    let mut writer = BodyWriter::new(writer, request_config);
    let peer = Arc::new(Mutex::new(None::<SocketAddr>));

    let udp_to_vmess = {
        let udp = udp.clone();
        let peer = peer.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            let mut is_new = true;
            let mut global_id = [0u8; 8];
            getrandom::fill(&mut global_id).context("generate VMess XUDP GlobalID")?;
            loop {
                let (read, next_peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive SOCKS UDP packet")?;
                *peer.lock().await = Some(next_peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let packet =
                    vless_xudp::encode_client_packet(&target, payload, is_new, &global_id)?;
                is_new = false;
                writer
                    .write_packet_plain(&packet)
                    .await
                    .context("write VMess XUDP packet")?;
            }
        }
    };
    let vmess_to_udp = {
        let udp = udp.clone();
        async move {
            let mut current_source = None;
            loop {
                let Some(packet) = reader.read_packet().await? else {
                    return Ok::<(), anyhow::Error>(());
                };
                let Some((source, payload)) =
                    vless_xudp::decode_packet_chunk(&packet, &mut current_source)?
                else {
                    return Ok::<(), anyhow::Error>(());
                };
                let response = uot::encode_socks_udp_packet(&source, &payload)?;
                let peer = (*peer.lock().await).context("SOCKS UDP peer is not known yet")?;
                udp.send_to(&response, peer)
                    .await
                    .with_context(|| format!("send VMess XUDP response to {peer}"))?;
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
        result = control_closed => result,
        result = udp_to_vmess => result,
        result = vmess_to_udp => result,
    }
}

async fn open_vmess_udp_tunnel(
    config: &VmessClientConfig,
    user: [u8; 16],
    target: ProxyTarget,
    udp: Arc<UdpSocket>,
    peer: Arc<Mutex<Option<SocketAddr>>>,
) -> Result<Arc<Mutex<BodyWriter<WriteHalf<VmessTransport>>>>> {
    let mut server = connect_vmess_transport(config).await?;
    let security = SecurityType::from_name(&config.security)?;
    let options = vmess_request_options(CMD_UDP, security);
    let keys = write_vmess_request(&mut server, &user, CMD_UDP, &target, security, options).await?;
    read_vmess_response_header(&mut server, &keys).await?;
    let request_config = BodyConfig::new_request(
        keys.security,
        keys.options,
        keys.request_body_key,
        keys.request_body_iv,
    )?;
    let response_config = BodyConfig::new_response(
        keys.security,
        keys.options,
        keys.request_body_key,
        keys.request_body_iv,
    )?;
    let (reader, writer) = tokio::io::split(server);
    let writer = Arc::new(Mutex::new(BodyWriter::new(writer, request_config)));
    let source = target.clone();
    tokio::spawn(async move {
        let mut reader = BodyReader::new(reader, response_config);
        loop {
            let result = async {
                let Some(payload) = reader.read_packet().await? else {
                    return Ok::<(), anyhow::Error>(());
                };
                let peer = (*peer.lock().await).context("SOCKS UDP peer is not known yet")?;
                let response = uot::encode_socks_udp_packet(&source, &payload)?;
                udp.send_to(&response, peer)
                    .await
                    .with_context(|| format!("send VMess UDP response to {peer}"))?;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(
                    "VMess UDP tunnel {} failed: {error:?}",
                    target_name(&source)
                );
                return;
            }
        }
    });
    Ok(writer)
}

async fn relay_vmess_udp(
    stream: VmessTransport,
    request: VmessRequest,
    session: CoreSession,
) -> Result<()> {
    ensure!(
        request.options.chunk_stream(),
        "VMess UDP command requires chunk stream option"
    );
    let request_config = request.request_body_config()?;
    let response_config = request.response_body_config()?;
    let (client_reader, client_writer) = tokio::io::split(stream);
    let mut client_reader = BodyReader::new(client_reader, request_config);
    let mut client_writer = BodyWriter::new(client_writer, response_config);
    if vless_xudp::is_mux_target(&request.target) {
        return relay_vmess_xudp_udp(client_reader, client_writer, session).await;
    }
    if is_vmess_packetaddr_target(&request.target) {
        return relay_vmess_packetaddr_udp(client_reader, client_writer, session).await;
    }

    let target = resolve_target_addr(&request.target).await?;
    let socket = Arc::new(
        UdpSocket::bind(if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await
        .context("bind VMess UDP socket")?,
    );
    socket
        .connect(target)
        .await
        .with_context(|| format!("connect VMess UDP target {target}"))?;

    let uplink_socket = socket.clone();
    let uplink_session = session.clone();
    let uplink = async move {
        while let Some(packet) = client_reader.read_packet().await? {
            uplink_session.record_upload(packet.len()).await?;
            let sent = uplink_socket
                .send(&packet)
                .await
                .context("send VMess UDP payload")?;
            ensure!(
                sent == packet.len(),
                "short VMess UDP send: expected {}, wrote {}",
                packet.len(),
                sent
            );
        }
        Ok::<(), anyhow::Error>(())
    };
    let downlink = async move {
        let mut buffer = vec![0u8; u16::MAX as usize];
        loop {
            let read = socket
                .recv(&mut buffer)
                .await
                .context("receive VMess UDP payload")?;
            session.record_download(read).await?;
            client_writer
                .write_packet_plain(&buffer[..read])
                .await
                .context("write VMess UDP response packet")?;
        }
    };
    tokio::select! {
        result = uplink => result,
        result = downlink => result,
    }
}

async fn relay_vmess_xudp_udp<R, W>(
    mut client_reader: BodyReader<R>,
    mut client_writer: BodyWriter<W>,
    session: CoreSession,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind VMess XUDP UDP socket")?,
    );
    let uplink_socket = socket.clone();
    let uplink_session = session.clone();
    let uplink = async move {
        let mut current_destination = None;
        while let Some(packet) = client_reader.read_packet().await? {
            let Some((target, payload)) =
                vless_xudp::decode_packet_chunk(&packet, &mut current_destination)?
            else {
                return Ok::<(), anyhow::Error>(());
            };
            uplink_session.record_upload(payload.len()).await?;
            let target = resolve_target_addr(&target).await?;
            let sent = uplink_socket
                .send_to(&payload, target)
                .await
                .with_context(|| format!("send VMess XUDP payload to {target}"))?;
            ensure!(
                sent == payload.len(),
                "short VMess XUDP send: expected {}, wrote {}",
                payload.len(),
                sent
            );
        }
        Ok::<(), anyhow::Error>(())
    };
    let downlink = async move {
        let mut buffer = vec![0u8; u16::MAX as usize];
        loop {
            let (read, source) = socket
                .recv_from(&mut buffer)
                .await
                .context("receive VMess XUDP UDP response")?;
            session.record_download(read).await?;
            let packet =
                vless_xudp::encode_response_packet(&ProxyTarget::Ip(source), &buffer[..read])?;
            client_writer
                .write_packet_plain(&packet)
                .await
                .context("write VMess XUDP response packet")?;
        }
    };
    tokio::select! {
        result = uplink => result,
        result = downlink => result,
    }
}

async fn relay_vmess_packetaddr_udp<R, W>(
    mut client_reader: BodyReader<R>,
    mut client_writer: BodyWriter<W>,
    session: CoreSession,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind VMess packetaddr UDP socket")?,
    );
    let uplink_socket = socket.clone();
    let uplink_session = session.clone();
    let uplink = async move {
        while let Some(packet) = client_reader.read_packet().await? {
            let (target, payload) = decode_vmess_packetaddr_packet(&packet)?;
            uplink_session.record_upload(payload.len()).await?;
            let target = resolve_target_addr(&target).await?;
            let sent = uplink_socket
                .send_to(payload, target)
                .await
                .with_context(|| format!("send VMess packetaddr payload to {target}"))?;
            ensure!(
                sent == payload.len(),
                "short VMess packetaddr send: expected {}, wrote {}",
                payload.len(),
                sent
            );
        }
        Ok::<(), anyhow::Error>(())
    };
    let downlink = async move {
        let mut buffer = vec![0u8; u16::MAX as usize];
        loop {
            let (read, source) = socket
                .recv_from(&mut buffer)
                .await
                .context("receive VMess packetaddr UDP response")?;
            session.record_download(read).await?;
            let packet = encode_vmess_packetaddr_packet(&ProxyTarget::Ip(source), &buffer[..read])?;
            client_writer
                .write_packet_plain(&packet)
                .await
                .context("write VMess packetaddr response packet")?;
        }
    };
    tokio::select! {
        result = uplink => result,
        result = downlink => result,
    }
}

async fn write_vmess_request<W>(
    writer: &mut W,
    user: &[u8; 16],
    command: u8,
    target: &ProxyTarget,
    security: SecurityType,
    options: RequestOptions,
) -> Result<VmessClientKeys>
where
    W: AsyncWrite + Unpin,
{
    let cmd_key = vmess_cmd_key(user);
    let auth_id = create_auth_id(&cmd_key, unix_time())?;
    let mut connection_nonce = [0u8; 8];
    let mut request_body_iv = [0u8; 16];
    let mut request_body_key = [0u8; 16];
    let mut response_header = [0u8; 1];
    getrandom::fill(&mut connection_nonce).context("generate VMess nonce")?;
    getrandom::fill(&mut request_body_iv).context("generate VMess body iv")?;
    getrandom::fill(&mut request_body_key).context("generate VMess body key")?;
    getrandom::fill(&mut response_header).context("generate VMess response header")?;

    let mut header = Vec::new();
    header.push(VERSION);
    header.extend_from_slice(&request_body_iv);
    header.extend_from_slice(&request_body_key);
    header.push(response_header[0]);
    header.push(options.bits());
    header.push(security.raw_byte());
    header.push(0);
    header.push(command);
    if command != CMD_MUX {
        write_vmess_address_sync(&mut header, target)?;
    }
    let checksum = fnv1a32(&header).to_be_bytes();
    header.extend_from_slice(&checksum);

    let length_key = kdf16(
        &cmd_key,
        VMESS_HEADER_LENGTH_KEY_SALT,
        &[auth_id.as_slice(), connection_nonce.as_slice()],
    );
    let length_nonce = kdf(
        &cmd_key,
        VMESS_HEADER_LENGTH_IV_SALT,
        &[auth_id.as_slice(), connection_nonce.as_slice()],
    );
    let payload_key = kdf16(
        &cmd_key,
        VMESS_HEADER_PAYLOAD_KEY_SALT,
        &[auth_id.as_slice(), connection_nonce.as_slice()],
    );
    let payload_nonce = kdf(
        &cmd_key,
        VMESS_HEADER_PAYLOAD_IV_SALT,
        &[auth_id.as_slice(), connection_nonce.as_slice()],
    );

    writer.write_all(&auth_id).await?;
    writer
        .write_all(&encrypt_aes_gcm(
            &length_key,
            &length_nonce[..12],
            &(header.len() as u16).to_be_bytes(),
            &auth_id,
        )?)
        .await?;
    writer.write_all(&connection_nonce).await?;
    writer
        .write_all(&encrypt_aes_gcm(
            &payload_key,
            &payload_nonce[..12],
            &header,
            &auth_id,
        )?)
        .await?;
    writer.flush().await.context("flush VMess request")?;

    Ok(VmessClientKeys {
        response_header: response_header[0],
        request_body_key,
        request_body_iv,
        options,
        security: security.normalized(),
    })
}

async fn read_vmess_request<R>(
    reader: &mut R,
    users: &HashMap<[u8; 16], String>,
    replay: Option<&VmessReplayFilter>,
) -> Result<(VmessRequest, String)>
where
    R: AsyncRead + Unpin,
{
    let mut auth_id = [0u8; 16];
    reader
        .read_exact(&mut auth_id)
        .await
        .context("read VMess auth id")?;
    let now = unix_time();
    for (user, credential) in users {
        let cmd_key = vmess_cmd_key(user);
        if decode_auth_id(&cmd_key, &auth_id)
            .map(|timestamp| (timestamp - now).abs() <= 120)
            .unwrap_or(false)
        {
            if let Some(replay) = replay {
                replay.check_auth_id(auth_id)?;
            }
            let header = open_vmess_aead_header(reader, &cmd_key, &auth_id).await?;
            let request = parse_vmess_header(&header)?;
            if let Some(replay) = replay {
                replay.check_session(*user, request.request_body_key, request.request_body_iv)?;
            }
            return Ok((request, credential.clone()));
        }
    }
    bail!("VMess authentication failed")
}

async fn open_vmess_aead_header<R>(
    reader: &mut R,
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut encrypted_length = [0u8; 2 + AEAD_TAG_LEN];
    reader
        .read_exact(&mut encrypted_length)
        .await
        .context("read VMess AEAD header length")?;
    let mut connection_nonce = [0u8; 8];
    reader
        .read_exact(&mut connection_nonce)
        .await
        .context("read VMess AEAD header nonce")?;
    let length_key = kdf16(
        cmd_key,
        VMESS_HEADER_LENGTH_KEY_SALT,
        &[auth_id, connection_nonce.as_slice()],
    );
    let length_nonce = kdf(
        cmd_key,
        VMESS_HEADER_LENGTH_IV_SALT,
        &[auth_id, connection_nonce.as_slice()],
    );
    let length_plain =
        decrypt_aes_gcm(&length_key, &length_nonce[..12], &encrypted_length, auth_id)?;
    ensure!(
        length_plain.len() == 2,
        "invalid VMess header length payload"
    );
    let header_length = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
    let mut encrypted_payload = vec![0u8; header_length + AEAD_TAG_LEN];
    reader
        .read_exact(&mut encrypted_payload)
        .await
        .context("read VMess AEAD header payload")?;
    let payload_key = kdf16(
        cmd_key,
        VMESS_HEADER_PAYLOAD_KEY_SALT,
        &[auth_id, connection_nonce.as_slice()],
    );
    let payload_nonce = kdf(
        cmd_key,
        VMESS_HEADER_PAYLOAD_IV_SALT,
        &[auth_id, connection_nonce.as_slice()],
    );
    decrypt_aes_gcm(
        &payload_key,
        &payload_nonce[..12],
        &encrypted_payload,
        auth_id,
    )
}

fn parse_vmess_header(header: &[u8]) -> Result<VmessRequest> {
    ensure!(header.len() >= 42, "VMess request header too short");
    ensure!(
        header[0] == VERSION,
        "unsupported VMess version {}",
        header[0]
    );
    let actual_checksum = fnv1a32(&header[..header.len() - 4]);
    let expected_checksum = u32::from_be_bytes([
        header[header.len() - 4],
        header[header.len() - 3],
        header[header.len() - 2],
        header[header.len() - 1],
    ]);
    ensure!(
        actual_checksum == expected_checksum,
        "invalid VMess request checksum"
    );
    let mut request_body_iv = [0u8; 16];
    request_body_iv.copy_from_slice(&header[1..17]);
    let mut request_body_key = [0u8; 16];
    request_body_key.copy_from_slice(&header[17..33]);
    let response_header = header[33];
    let mut options = RequestOptions::new(header[34]);
    ensure!(
        !options.has_unknown_bits(),
        "unsupported VMess request option bits: 0x{:02x}",
        options.bits() & !RequestOptions::supported_mask()
    );
    let padding_len = (header[35] >> 4) as usize;
    let raw_security = SecurityType::from_raw(header[35] & 0x0f)?;
    if raw_security == SecurityType::Zero {
        options.clear_chunk_stream();
        options.clear_chunk_masking();
        options.clear_authenticated_length();
    }
    let security = raw_security.normalized();
    ensure!(
        header[36] == 0,
        "unsupported VMess reserved byte {}",
        header[36]
    );
    let command = header[37];
    ensure!(
        !(raw_security == SecurityType::Zero && (command == CMD_UDP || command == CMD_MUX)),
        "VMess security=zero does not support UDP"
    );
    let (target, target_len) = if command == CMD_MUX {
        (vless_xudp::mux_target(), 0)
    } else {
        read_vmess_address_sync(&header[38..])?
    };
    ensure!(
        header.len() == 38 + target_len + padding_len + 4,
        "invalid VMess padding length"
    );
    Ok(VmessRequest {
        command,
        target,
        response_header,
        request_body_key,
        request_body_iv,
        options,
        security,
    })
}

async fn write_vmess_response_header<W>(writer: &mut W, request: &VmessRequest) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let keys = VmessClientKeys {
        response_header: request.response_header,
        request_body_key: request.request_body_key,
        request_body_iv: request.request_body_iv,
        options: request.options,
        security: request.security,
    };
    writer
        .write_all(&encode_vmess_response_header(&keys)?)
        .await
        .context("write VMess response header")
}

async fn read_vmess_response_header<R>(reader: &mut R, keys: &VmessClientKeys) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let response_key = response_body_key(&keys.request_body_key);
    let response_iv = response_body_iv(&keys.request_body_iv);
    let length_key = kdf16(&response_key, AEAD_RESPONSE_HEADER_LENGTH_KEY_SALT, &[]);
    let length_nonce = kdf(&response_iv, AEAD_RESPONSE_HEADER_LENGTH_IV_SALT, &[]);
    let payload_key = kdf16(&response_key, AEAD_RESPONSE_HEADER_PAYLOAD_KEY_SALT, &[]);
    let payload_nonce = kdf(&response_iv, AEAD_RESPONSE_HEADER_PAYLOAD_IV_SALT, &[]);
    let mut encrypted_length = [0u8; 2 + AEAD_TAG_LEN];
    reader
        .read_exact(&mut encrypted_length)
        .await
        .context("read VMess response header length")?;
    let length_plain = decrypt_aes_gcm(&length_key, &length_nonce[..12], &encrypted_length, &[])?;
    ensure!(
        length_plain.len() == 2,
        "invalid VMess response header length"
    );
    let length = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
    let mut encrypted_payload = vec![0u8; length + AEAD_TAG_LEN];
    reader
        .read_exact(&mut encrypted_payload)
        .await
        .context("read VMess response header payload")?;
    let payload = decrypt_aes_gcm(&payload_key, &payload_nonce[..12], &encrypted_payload, &[])?;
    ensure!(payload.len() >= 4, "VMess response header too short");
    ensure!(
        payload[0] == keys.response_header,
        "VMess response header verification failed"
    );
    Ok(())
}

fn encode_vmess_response_header(keys: &VmessClientKeys) -> Result<Vec<u8>> {
    let response_key = response_body_key(&keys.request_body_key);
    let response_iv = response_body_iv(&keys.request_body_iv);
    let header_plain = [keys.response_header, 0, 0, 0];
    let length_key = kdf16(&response_key, AEAD_RESPONSE_HEADER_LENGTH_KEY_SALT, &[]);
    let length_nonce = kdf(&response_iv, AEAD_RESPONSE_HEADER_LENGTH_IV_SALT, &[]);
    let payload_key = kdf16(&response_key, AEAD_RESPONSE_HEADER_PAYLOAD_KEY_SALT, &[]);
    let payload_nonce = kdf(&response_iv, AEAD_RESPONSE_HEADER_PAYLOAD_IV_SALT, &[]);
    let mut out = encrypt_aes_gcm(
        &length_key,
        &length_nonce[..12],
        &(header_plain.len() as u16).to_be_bytes(),
        &[],
    )?;
    out.extend_from_slice(&encrypt_aes_gcm(
        &payload_key,
        &payload_nonce[..12],
        &header_plain,
        &[],
    )?);
    Ok(out)
}

fn write_vmess_address_sync(out: &mut Vec<u8>, target: &ProxyTarget) -> Result<()> {
    match target {
        ProxyTarget::Ip(addr) => {
            out.extend_from_slice(&addr.port().to_be_bytes());
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(ATYP_IPV4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(ATYP_IPV6);
                    out.extend_from_slice(&ip.octets());
                }
            }
        }
        ProxyTarget::Domain(host, port) => {
            ensure!(host.len() <= u8::MAX as usize, "VMess domain too long");
            out.extend_from_slice(&port.to_be_bytes());
            out.push(ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    Ok(())
}

fn read_vmess_address_sync(data: &[u8]) -> Result<(ProxyTarget, usize)> {
    ensure!(data.len() >= 3, "short VMess address");
    let port = u16::from_be_bytes([data[0], data[1]]);
    match data[2] {
        ATYP_IPV4 => {
            ensure!(data.len() >= 7, "short VMess IPv4 address");
            Ok((
                ProxyTarget::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(data[3], data[4], data[5], data[6])),
                    port,
                )),
                7,
            ))
        }
        ATYP_IPV6 => {
            ensure!(data.len() >= 19, "short VMess IPv6 address");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[3..19]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                19,
            ))
        }
        ATYP_DOMAIN => {
            ensure!(data.len() >= 4, "short VMess domain address");
            let length = data[3] as usize;
            ensure!(data.len() >= 4 + length, "short VMess domain address");
            Ok((
                ProxyTarget::Domain(
                    String::from_utf8(data[4..4 + length].to_vec())
                        .context("decode VMess domain")?,
                    port,
                ),
                4 + length,
            ))
        }
        other => bail!("unsupported VMess address type {other:#x}"),
    }
}

fn vmess_packetaddr_target() -> ProxyTarget {
    ProxyTarget::Domain("sp.packet-addr.v2fly.arpa".to_string(), 0)
}

fn is_vmess_packetaddr_target(target: &ProxyTarget) -> bool {
    matches!(target, ProxyTarget::Domain(host, _) if host.eq_ignore_ascii_case("sp.packet-addr.v2fly.arpa"))
}

fn encode_vmess_packetaddr_packet(target: &ProxyTarget, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(19 + payload.len());
    match target {
        ProxyTarget::Ip(addr) => {
            out.extend_from_slice(&addr.port().to_be_bytes());
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(ATYP_IPV4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(0x02);
                    out.extend_from_slice(&ip.octets());
                }
            }
        }
        ProxyTarget::Domain(host, _) => {
            bail!("VMess packetaddr does not support FQDN target {host}")
        }
    }
    out.extend_from_slice(payload);
    Ok(out)
}

fn decode_vmess_packetaddr_packet(data: &[u8]) -> Result<(ProxyTarget, &[u8])> {
    ensure!(data.len() >= 3, "short VMess packetaddr packet");
    let port = u16::from_be_bytes([data[0], data[1]]);
    match data[2] {
        ATYP_IPV4 => {
            ensure!(data.len() >= 7, "short VMess packetaddr IPv4 packet");
            Ok((
                ProxyTarget::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(data[3], data[4], data[5], data[6])),
                    port,
                )),
                &data[7..],
            ))
        }
        0x02 => {
            ensure!(data.len() >= 19, "short VMess packetaddr IPv6 packet");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[3..19]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                &data[19..],
            ))
        }
        other => bail!("unsupported VMess packetaddr address type {other:#x}"),
    }
}

fn vmess_users(user_id: &str, users: &[String]) -> Result<HashMap<[u8; 16], String>> {
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

fn vmess_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn create_auth_id(cmd_key: &[u8; 16], timestamp: i64) -> Result<[u8; 16]> {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&timestamp.to_be_bytes());
    getrandom::fill(&mut plain[8..12]).context("generate VMess auth id random")?;
    let checksum = crc32_ieee(&plain[..12]);
    plain[12..16].copy_from_slice(&checksum.to_be_bytes());
    let key = kdf16(cmd_key, AUTH_ID_ENCRYPTION_KEY_SALT, &[]);
    Ok(aes_128_ecb_encrypt(&key, &plain))
}

fn decode_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> Result<i64> {
    let key = kdf16(cmd_key, AUTH_ID_ENCRYPTION_KEY_SALT, &[]);
    let plain = aes_128_ecb_decrypt(&key, auth_id);
    let mut timestamp = [0u8; 8];
    timestamp.copy_from_slice(&plain[..8]);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&plain[12..16]);
    ensure!(
        u32::from_be_bytes(checksum) == crc32_ieee(&plain[..12]),
        "invalid VMess auth id checksum"
    );
    Ok(i64::from_be_bytes(timestamp))
}

fn response_body_key(request_body_key: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(request_body_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn response_body_iv(request_body_iv: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(request_body_iv);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 32] {
    let mut levels = Vec::with_capacity(2 + path.len());
    levels.push(VMESS_AEAD_KDF_SALT);
    levels.push(salt.as_bytes());
    levels.extend_from_slice(path);
    nested_hmac_hash(&levels, key)
}

fn kdf16(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, salt, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

fn nested_hmac_hash(levels: &[&[u8]], data: &[u8]) -> [u8; 32] {
    if let Some((last, rest)) = levels.split_last() {
        hmac_with_custom_hash(last, data, |input| {
            if rest.is_empty() {
                sha256_hash(input)
            } else {
                nested_hmac_hash(rest, input)
            }
        })
    } else {
        sha256_hash(data)
    }
}

fn hmac_with_custom_hash<F>(key: &[u8], data: &[u8], hash_fn: F) -> [u8; 32]
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut key_block = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        key_block[..32].copy_from_slice(&hash_fn(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];
    for index in 0..HMAC_BLOCK_SIZE {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Vec::with_capacity(HMAC_BLOCK_SIZE + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = hash_fn(&inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK_SIZE + inner_hash.len());
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    hash_fn(&outer)
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encrypt_aes_gcm(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .context("init AES-128-GCM")?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt AES-128-GCM"))
}

fn decrypt_aes_gcm(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        ciphertext.len() >= AEAD_TAG_LEN,
        "AES-GCM ciphertext too short"
    );
    Aes128Gcm::new_from_slice(key)
        .context("init AES-128-GCM")?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("decrypt AES-128-GCM"))
}

fn aes_128_ecb_encrypt(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn aes_128_ecb_decrypt(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut block);
    block.into()
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH")
        .as_secs() as i64
}

fn vmess_request_options(command: u8, security: SecurityType) -> RequestOptions {
    let mut options = RequestOptions::new(0);
    if command == CMD_UDP || command == CMD_MUX || security.normalized() != SecurityType::None {
        options.enable_chunk_stream();
    }
    options
}

#[cfg(test)]
mod tests;
