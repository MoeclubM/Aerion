use crate::core::{CoreSession, CoreUser, ProxyCore};
use crate::protocol::{ProxyTarget, target_name};
use crate::{socket_protect, socks, tls};
use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, IdleTimeout, VarInt};
use rustls::RootCertStore;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, tcp::OwnedWriteHalf};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::JoinHandle;

const TUIC_VERSION: u8 = 0x05;
const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;

const ADDR_DOMAIN: u8 = 0x00;
const ADDR_IPV4: u8 = 0x01;
const ADDR_IPV6: u8 = 0x02;
const ADDR_NONE: u8 = 0xff;

const TUIC_H3_ALPN: &[u8] = b"h3";
const DEFAULT_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const TUIC_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const TUIC_CONN_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
const TUIC_MAX_INCOMING_STREAMS: u32 = 1024;
const TUIC_DATAGRAM_BUFFER_SIZE: usize = 8 * 1024 * 1024;
const TUIC_MAX_UNI_COMMAND: usize = u16::MAX as usize + 512;
const UDP_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);
const PACKET_COMMAND_FIXED_LEN: usize = 10;

#[derive(Clone, Debug)]
pub struct TuicClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub uuid: String,
    pub password: String,
    pub sni: String,
    pub insecure: bool,
    pub udp: bool,
    pub udp_relay_mode: String,
    pub congestion_control: String,
    pub alpn_protocols: Vec<String>,
    pub heartbeat_interval_secs: u64,
}

#[derive(Clone, Debug)]
pub struct TuicServerConfig {
    pub listen: SocketAddr,
    pub uuid: String,
    pub password: String,
    pub users: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub udp: bool,
    pub congestion_control: String,
    pub alpn_protocols: Vec<String>,
    pub heartbeat_interval_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuicUser {
    pub uuid: String,
    pub password: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuicUdpRelayMode {
    Native,
    Quic,
}

#[derive(Clone)]
struct TuicClient {
    inner: Arc<TuicClientInner>,
}

struct TuicClientInner {
    endpoint: Endpoint,
    connection: quinn::Connection,
    udp_mode: TuicUdpRelayMode,
    udp_sessions: Mutex<HashMap<u16, mpsc::Sender<TuicPacket>>>,
    udp_fragments: Mutex<HashMap<(u16, u16), TuicFragmentBuffer>>,
    next_assoc_id: AtomicU16,
    next_packet_id: AtomicU16,
    datagram_handle: JoinHandle<()>,
    uni_handle: JoinHandle<()>,
    heartbeat_handle: JoinHandle<()>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TuicPacket {
    assoc_id: u16,
    target: ProxyTarget,
    payload: Vec<u8>,
}

struct TuicFragmentBuffer {
    target: Option<ProxyTarget>,
    created_at: Instant,
    fragments: Vec<Option<Vec<u8>>>,
}

#[derive(Clone, Debug)]
struct TuicPacketCommand {
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    target: Option<ProxyTarget>,
    payload: Vec<u8>,
}

type ServerUdpSessions = Arc<Mutex<HashMap<u16, Arc<ServerUdpSession>>>>;
type SharedFragments = Arc<Mutex<HashMap<(u16, u16), TuicFragmentBuffer>>>;

struct ServerUdpSession {
    socket: Arc<UdpSocket>,
    response_handle: StdMutex<JoinHandle<()>>,
}

struct TuicAuthState {
    session: Mutex<Option<CoreSession>>,
    error: Mutex<Option<String>>,
    notify: Notify,
}

impl Drop for TuicClientInner {
    fn drop(&mut self) {
        let _ = &self.endpoint;
        self.connection.close(VarInt::from_u32(0), b"client closed");
        self.datagram_handle.abort();
        self.uni_handle.abort();
        self.heartbeat_handle.abort();
    }
}

impl Drop for ServerUdpSession {
    fn drop(&mut self) {
        match self.response_handle.lock() {
            Ok(handle) => handle.abort(),
            Err(poisoned) => poisoned.into_inner().abort(),
        }
    }
}

impl TuicUdpRelayMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "native" => Ok(Self::Native),
            "quic" => Ok(Self::Quic),
            other => bail!("unsupported TUIC udp_relay_mode {other}"),
        }
    }
}

impl TuicAuthState {
    fn new() -> Self {
        Self {
            session: Mutex::new(None),
            error: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    async fn set_session(&self, session: CoreSession) {
        *self.session.lock().await = Some(session);
        self.notify.notify_waiters();
    }

    async fn set_error(&self, error: String) {
        *self.error.lock().await = Some(error);
        self.notify.notify_waiters();
    }

    async fn wait_session(&self) -> Result<CoreSession> {
        loop {
            if let Some(session) = self.session.lock().await.clone() {
                return Ok(session);
            }
            if let Some(error) = self.error.lock().await.clone() {
                bail!("{error}");
            }
            self.notify.notified().await;
        }
    }
}

pub fn parse_tuic_user(value: &str) -> Result<TuicUser> {
    let value = value.trim();
    let (uuid, password) = value
        .split_once(':')
        .or_else(|| value.split_once('='))
        .unwrap_or((value, value));
    let uuid = uuid.trim();
    let password = password.trim();
    ensure!(!uuid.is_empty(), "TUIC user UUID is empty");
    ensure!(!password.is_empty(), "TUIC user password is empty");
    parse_uuid(uuid).with_context(|| format!("parse TUIC user UUID {uuid}"))?;
    Ok(TuicUser {
        uuid: uuid.to_string(),
        password: password.to_string(),
    })
}

pub async fn run_tuic_client(config: TuicClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind TUIC local SOCKS listener on {}", config.listen))?;
    run_tuic_client_listener(listener, config).await
}

pub async fn run_tuic_client_listener(
    listener: TcpListener,
    config: TuicClientConfig,
) -> Result<()> {
    let client = TuicClient::connect(&config).await?;
    tracing::info!(
        "TUIC client listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("accept TUIC SOCKS client")?;
        let client = client.clone();
        let udp_enabled = config.udp;
        tokio::spawn(async move {
            if let Err(error) = handle_tuic_socks_client(stream, client, udp_enabled).await {
                tracing::warn!("TUIC SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn run_tuic_server(config: TuicServerConfig) -> Result<()> {
    let users = tuic_users(&config)?;
    let core = ProxyCore::new(
        users
            .iter()
            .map(|user| CoreUser::password(user.uuid.clone(), user.uuid.clone()))
            .collect(),
    )?;
    run_tuic_server_with_core(config, core).await
}

pub async fn run_tuic_server_with_core(config: TuicServerConfig, core: ProxyCore) -> Result<()> {
    let endpoint = build_server_endpoint(&config)?;
    tracing::info!("TUIC server listening on {}", endpoint.local_addr()?);
    while let Some(incoming) = endpoint.accept().await {
        let users = tuic_user_map(&config)?;
        let core = core.clone();
        let udp_enabled = config.udp;
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(error) =
                        handle_tuic_connection(connection, users, udp_enabled, core).await
                    {
                        tracing::warn!("TUIC connection failed: {error:?}");
                    }
                }
                Err(error) => tracing::warn!("TUIC QUIC handshake failed: {error:?}"),
            }
        });
    }
    Ok(())
}

impl TuicClient {
    async fn connect(config: &TuicClientConfig) -> Result<Self> {
        let remote_addr = resolve_host_addr(&config.server_host, config.server_port).await?;
        let endpoint = build_client_endpoint(config, remote_addr.is_ipv6())?;
        let connection = endpoint
            .connect(remote_addr, &config.sni)
            .with_context(|| format!("connect TUIC server {remote_addr}"))?
            .await
            .context("complete TUIC QUIC handshake")?;
        let uuid = parse_uuid(&config.uuid)?;
        let token = tuic_token(&connection, &uuid, &config.password)?;
        let mut auth = Vec::with_capacity(48);
        auth.extend_from_slice(&uuid);
        auth.extend_from_slice(&token);
        let mut stream = connection
            .open_uni()
            .await
            .context("open TUIC auth stream")?;
        write_command(&mut stream, CMD_AUTHENTICATE, &auth)
            .await
            .context("write TUIC auth command")?;
        stream.finish().context("finish TUIC auth stream")?;

        let udp_mode = TuicUdpRelayMode::parse(&config.udp_relay_mode)?;
        let udp_sessions = Mutex::new(HashMap::new());
        let udp_fragments = Mutex::new(HashMap::new());
        let datagram_connection = connection.clone();
        let uni_connection = connection.clone();
        let heartbeat_connection = connection.clone();
        let heartbeat_interval = heartbeat_interval(config.heartbeat_interval_secs);

        let inner = Arc::new_cyclic(move |weak: &std::sync::Weak<TuicClientInner>| {
            let datagram_weak = weak.clone();
            let uni_weak = weak.clone();
            TuicClientInner {
                endpoint,
                connection,
                udp_mode,
                udp_sessions,
                udp_fragments,
                next_assoc_id: AtomicU16::new(1),
                next_packet_id: AtomicU16::new(1),
                datagram_handle: tokio::spawn(async move {
                    run_client_datagram_dispatch(datagram_connection, datagram_weak).await
                }),
                uni_handle: tokio::spawn(async move {
                    run_client_uni_dispatch(uni_connection, uni_weak).await
                }),
                heartbeat_handle: tokio::spawn(async move {
                    run_tuic_heartbeat(heartbeat_connection, heartbeat_interval).await
                }),
            }
        });

        Ok(Self { inner })
    }

    async fn open_tcp(
        &self,
        target: &ProxyTarget,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = self
            .inner
            .connection
            .open_bi()
            .await
            .context("open TUIC TCP relay stream")?;
        write_command(&mut send, CMD_CONNECT, &encode_tuic_address(Some(target))?)
            .await
            .context("write TUIC connect command")?;
        Ok((send, recv))
    }

    async fn send_udp_packet(
        &self,
        assoc_id: u16,
        target: &ProxyTarget,
        payload: &[u8],
    ) -> Result<()> {
        let packet_id = self.inner.next_packet_id.fetch_add(1, Ordering::SeqCst);
        send_packet_commands(
            &self.inner.connection,
            self.inner.udp_mode,
            assoc_id,
            packet_id,
            target,
            payload,
        )
        .await
    }

    async fn dissociate_udp(&self, assoc_id: u16) -> Result<()> {
        self.inner.udp_sessions.lock().await.remove(&assoc_id);
        let mut stream = self
            .inner
            .connection
            .open_uni()
            .await
            .context("open TUIC dissociate stream")?;
        write_command(&mut stream, CMD_DISSOCIATE, &assoc_id.to_be_bytes()).await?;
        stream.finish().context("finish TUIC dissociate stream")?;
        Ok(())
    }

    fn next_assoc_id(&self) -> u16 {
        self.inner.next_assoc_id.fetch_add(1, Ordering::SeqCst)
    }
}

async fn handle_tuic_socks_client(
    mut local: TcpStream,
    client: TuicClient,
    udp_enabled: bool,
) -> Result<()> {
    match socks::read_request(&mut local).await? {
        socks::SocksRequest::Connect(target) => {
            let stream = match client.open_tcp(&target).await {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(error);
                }
            };
            socks::write_reply(&mut local, 0x00).await?;
            tracing::info!("TUIC proxying {}", target_name(&target));
            relay_tuic_tcp(local, stream).await
        }
        socks::SocksRequest::UdpAssociate => {
            ensure!(udp_enabled, "TUIC UDP is disabled by config");
            handle_tuic_udp_associate(local, client).await
        }
    }
}

async fn relay_tuic_tcp(
    local: TcpStream,
    stream: (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let (mut send, mut recv) = stream;
    let (mut local_reader, local_writer) = local.into_split();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read TUIC local payload")?;
            if read == 0 {
                send.finish().context("finish TUIC send stream")?;
                return Ok::<(), anyhow::Error>(());
            }
            send.write_all(&buffer[..read])
                .await
                .context("write TUIC stream payload")?;
        }
    };
    let downlink = write_tuic_recv_to_local(&mut recv, local_writer);
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

async fn write_tuic_recv_to_local(
    recv: &mut quinn::RecvStream,
    mut local_writer: OwnedWriteHalf,
) -> Result<()> {
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        let read = recv
            .read(&mut buffer)
            .await
            .context("read TUIC stream payload")?;
        let Some(read) = read else {
            local_writer
                .shutdown()
                .await
                .context("shutdown TUIC local writer")?;
            return Ok(());
        };
        local_writer
            .write_all(&buffer[..read])
            .await
            .context("write TUIC local payload")?;
    }
}

async fn handle_tuic_udp_associate(mut control: TcpStream, client: TuicClient) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .with_context(|| format!("bind TUIC SOCKS UDP associate socket on {bind_ip}:0"))?;
    let udp_addr = udp.local_addr()?;
    socks::write_reply_with_bind(&mut control, 0x00, udp_addr).await?;

    let assoc_id = client.next_assoc_id();
    let (sender, mut receiver) = mpsc::channel::<TuicPacket>(32);
    client
        .inner
        .udp_sessions
        .lock()
        .await
        .insert(assoc_id, sender);
    let udp = Arc::new(udp);
    let (client_tx, mut client_rx) = mpsc::channel::<SocketAddr>(8);

    let udp_to_tuic = {
        let udp = udp.clone();
        let client = client.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive TUIC SOCKS UDP packet")?;
                let _ = client_tx.try_send(peer);
                let (target, payload) = crate::uot::parse_socks_udp_packet(&buffer[..read])?;
                client.send_udp_packet(assoc_id, &target, payload).await?;
            }
        }
    };

    let tuic_to_udp = {
        let udp = udp.clone();
        async move {
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => {
                        if let Some(next_peer) = next_peer {
                            peer = Some(next_peer);
                        }
                    }
                    packet = receiver.recv() => {
                        let Some(packet) = packet else {
                            return Ok::<(), anyhow::Error>(());
                        };
                        let response = crate::uot::encode_socks_udp_packet(&packet.target, &packet.payload)?;
                        let peer = peer.context("TUIC SOCKS UDP peer is not known yet")?;
                        udp.send_to(&response, peer)
                            .await
                            .with_context(|| format!("send TUIC SOCKS UDP response to {peer}"))?;
                    }
                }
            }
        }
    };

    let control_closed = async {
        let mut buffer = [0u8; 1];
        loop {
            let read = control
                .read(&mut buffer)
                .await
                .context("read TUIC SOCKS UDP control connection")?;
            if read == 0 {
                return Ok::<(), anyhow::Error>(());
            }
        }
    };

    let result = tokio::select! {
        result = udp_to_tuic => result,
        result = tuic_to_udp => result,
        result = control_closed => result,
    };
    client.dissociate_udp(assoc_id).await?;
    result
}

async fn run_client_datagram_dispatch(
    connection: quinn::Connection,
    inner: std::sync::Weak<TuicClientInner>,
) {
    loop {
        let datagram = match connection.read_datagram().await {
            Ok(datagram) => datagram,
            Err(error) => {
                tracing::debug!("TUIC client datagram receiver stopped: {error:?}");
                return;
            }
        };
        let Some(inner) = inner.upgrade() else {
            return;
        };
        if let Err(error) = handle_client_packet_bytes(&inner, &datagram).await {
            tracing::warn!("invalid TUIC client datagram: {error:?}");
        }
    }
}

async fn run_client_uni_dispatch(
    connection: quinn::Connection,
    inner: std::sync::Weak<TuicClientInner>,
) {
    loop {
        let mut stream = match connection.accept_uni().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!("TUIC client unidirectional receiver stopped: {error:?}");
                return;
            }
        };
        let Some(inner) = inner.upgrade() else {
            return;
        };
        tokio::spawn(async move {
            let result = async {
                let bytes = stream
                    .read_to_end(TUIC_MAX_UNI_COMMAND)
                    .await
                    .context("read TUIC unidirectional command")?;
                handle_client_packet_bytes(&inner, &bytes).await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!("invalid TUIC client unidirectional command: {error:?}");
            }
        });
    }
}

async fn handle_client_packet_bytes(inner: &TuicClientInner, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() >= 2, "TUIC command is too short");
    ensure!(
        bytes[0] == TUIC_VERSION,
        "unsupported TUIC version {}",
        bytes[0]
    );
    match bytes[1] {
        CMD_PACKET => {
            let packet = parse_packet_command(bytes)?;
            let mut fragments = inner.udp_fragments.lock().await;
            let packet = push_fragment(&mut fragments, packet)?;
            if let Some(packet) = packet {
                let sender = inner
                    .udp_sessions
                    .lock()
                    .await
                    .get(&packet.assoc_id)
                    .cloned();
                if let Some(sender) = sender {
                    let _ = sender.send(packet).await;
                }
            }
            Ok(())
        }
        CMD_HEARTBEAT => Ok(()),
        other => bail!("unexpected TUIC client command type {other}"),
    }
}

async fn handle_tuic_connection(
    connection: quinn::Connection,
    users: HashMap<[u8; 16], TuicUser>,
    udp_enabled: bool,
    core: ProxyCore,
) -> Result<()> {
    let peer = connection.remote_address();
    let auth = Arc::new(TuicAuthState::new());
    let udp_sessions: ServerUdpSessions = Arc::new(Mutex::new(HashMap::new()));
    let udp_fragments: SharedFragments = Arc::new(Mutex::new(HashMap::new()));

    let uni_handle = {
        let connection = connection.clone();
        let auth = auth.clone();
        let udp_sessions = udp_sessions.clone();
        let udp_fragments = udp_fragments.clone();
        let core = core.clone();
        tokio::spawn(async move {
            run_server_uni_loop(
                connection,
                users,
                auth,
                udp_sessions,
                udp_fragments,
                udp_enabled,
                core,
                peer,
            )
            .await
        })
    };

    let datagram_handle = {
        let connection = connection.clone();
        let auth = auth.clone();
        let udp_sessions = udp_sessions.clone();
        let udp_fragments = udp_fragments.clone();
        tokio::spawn(async move {
            run_server_datagram_loop(connection, auth, udp_sessions, udp_fragments, udp_enabled)
                .await
        })
    };

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let auth = auth.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_server_bi_stream(send, recv, auth).await {
                        tracing::warn!("TUIC TCP relay failed: {error:?}");
                    }
                });
            }
            Err(error) => {
                uni_handle.abort();
                datagram_handle.abort();
                return Err(error).context("accept TUIC bidirectional stream");
            }
        }
    }
}

async fn run_server_uni_loop(
    connection: quinn::Connection,
    users: HashMap<[u8; 16], TuicUser>,
    auth: Arc<TuicAuthState>,
    udp_sessions: ServerUdpSessions,
    udp_fragments: SharedFragments,
    udp_enabled: bool,
    core: ProxyCore,
    peer: SocketAddr,
) {
    loop {
        let mut stream = match connection.accept_uni().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!("TUIC server unidirectional receiver stopped: {error:?}");
                return;
            }
        };
        let connection = connection.clone();
        let users = users.clone();
        let auth = auth.clone();
        let udp_sessions = udp_sessions.clone();
        let udp_fragments = udp_fragments.clone();
        let core = core.clone();
        tokio::spawn(async move {
            let result = async {
                let bytes = stream
                    .read_to_end(TUIC_MAX_UNI_COMMAND)
                    .await
                    .context("read TUIC server unidirectional command")?;
                handle_server_command_bytes(
                    &connection,
                    &bytes,
                    &users,
                    &auth,
                    &udp_sessions,
                    &udp_fragments,
                    udp_enabled,
                    &core,
                    peer,
                    TuicUdpRelayMode::Quic,
                )
                .await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!("TUIC server unidirectional command failed: {error:?}");
            }
        });
    }
}

async fn run_server_datagram_loop(
    connection: quinn::Connection,
    auth: Arc<TuicAuthState>,
    udp_sessions: ServerUdpSessions,
    udp_fragments: SharedFragments,
    udp_enabled: bool,
) {
    loop {
        let datagram = match connection.read_datagram().await {
            Ok(datagram) => datagram,
            Err(error) => {
                tracing::debug!("TUIC server datagram receiver stopped: {error:?}");
                return;
            }
        };
        if let Err(error) = handle_server_datagram_bytes(
            &connection,
            &datagram,
            &auth,
            &udp_sessions,
            &udp_fragments,
            udp_enabled,
            TuicUdpRelayMode::Native,
        )
        .await
        {
            tracing::warn!("TUIC server datagram command failed: {error:?}");
        }
    }
}

async fn handle_server_datagram_bytes(
    connection: &quinn::Connection,
    bytes: &[u8],
    auth: &Arc<TuicAuthState>,
    udp_sessions: &ServerUdpSessions,
    udp_fragments: &SharedFragments,
    udp_enabled: bool,
    mode: TuicUdpRelayMode,
) -> Result<()> {
    ensure!(bytes.len() >= 2, "TUIC datagram command is too short");
    ensure!(
        bytes[0] == TUIC_VERSION,
        "unsupported TUIC version {}",
        bytes[0]
    );
    match bytes[1] {
        CMD_PACKET => {
            handle_server_packet_bytes(
                connection,
                bytes,
                auth,
                udp_sessions,
                udp_fragments,
                udp_enabled,
                mode,
            )
            .await
        }
        CMD_HEARTBEAT => Ok(()),
        other => bail!("unexpected TUIC datagram command type {other}"),
    }
}

async fn handle_server_command_bytes(
    connection: &quinn::Connection,
    bytes: &[u8],
    users: &HashMap<[u8; 16], TuicUser>,
    auth: &Arc<TuicAuthState>,
    udp_sessions: &ServerUdpSessions,
    udp_fragments: &SharedFragments,
    udp_enabled: bool,
    core: &ProxyCore,
    peer: SocketAddr,
    mode: TuicUdpRelayMode,
) -> Result<()> {
    ensure!(bytes.len() >= 2, "TUIC command is too short");
    ensure!(
        bytes[0] == TUIC_VERSION,
        "unsupported TUIC version {}",
        bytes[0]
    );
    match bytes[1] {
        CMD_AUTHENTICATE => {
            if let Err(error) =
                authenticate_tuic_connection(connection, &bytes[2..], users, auth, core, peer).await
            {
                auth.set_error(format!("{error:?}")).await;
                connection.close(VarInt::from_u32(0), b"auth failed");
                return Err(error);
            }
            Ok(())
        }
        CMD_PACKET => {
            handle_server_packet_bytes(
                connection,
                bytes,
                auth,
                udp_sessions,
                udp_fragments,
                udp_enabled,
                mode,
            )
            .await
        }
        CMD_DISSOCIATE => {
            ensure!(
                bytes.len() == 4,
                "TUIC dissociate command length is invalid"
            );
            let assoc_id = u16::from_be_bytes([bytes[2], bytes[3]]);
            udp_sessions.lock().await.remove(&assoc_id);
            Ok(())
        }
        CMD_HEARTBEAT => Ok(()),
        other => bail!("unsupported TUIC command type {other}"),
    }
}

async fn handle_server_packet_bytes(
    connection: &quinn::Connection,
    bytes: &[u8],
    auth: &Arc<TuicAuthState>,
    udp_sessions: &ServerUdpSessions,
    udp_fragments: &SharedFragments,
    udp_enabled: bool,
    mode: TuicUdpRelayMode,
) -> Result<()> {
    ensure!(udp_enabled, "TUIC UDP is disabled by server config");
    let packet = parse_packet_command(bytes)?;
    let mut fragments = udp_fragments.lock().await;
    let packet = push_fragment(&mut fragments, packet)?;
    let Some(packet) = packet else {
        return Ok(());
    };
    let session = auth.wait_session().await?;
    let target = target_socket_addr(&packet.target).await?;
    let udp_session = get_server_udp_session(
        connection,
        udp_sessions,
        packet.assoc_id,
        mode,
        target.is_ipv6(),
        session.clone(),
    )
    .await?;
    session.record_upload(packet.payload.len()).await?;
    udp_session
        .socket
        .send_to(&packet.payload, target)
        .await
        .with_context(|| format!("send TUIC UDP payload to {target}"))?;
    Ok(())
}

async fn authenticate_tuic_connection(
    connection: &quinn::Connection,
    payload: &[u8],
    users: &HashMap<[u8; 16], TuicUser>,
    auth: &Arc<TuicAuthState>,
    core: &ProxyCore,
    peer: SocketAddr,
) -> Result<()> {
    ensure!(
        payload.len() == 48,
        "TUIC authenticate payload length is invalid"
    );
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&payload[..16]);
    let token = &payload[16..48];
    let user = users
        .get(&uuid)
        .with_context(|| format!("TUIC user {} is not configured", format_uuid(&uuid)))?;
    let expected = tuic_token(connection, &uuid, &user.password)?;
    ensure!(
        constant_time_eq(token, &expected),
        "TUIC authentication failed"
    );
    let session = core.open_session_from(&user.uuid, peer).await?;
    auth.set_session(session).await;
    Ok(())
}

async fn handle_server_bi_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    auth: Arc<TuicAuthState>,
) -> Result<()> {
    let mut header = [0u8; 2];
    recv.read_exact(&mut header)
        .await
        .context("read TUIC bidirectional command header")?;
    ensure!(
        header[0] == TUIC_VERSION,
        "unsupported TUIC version {}",
        header[0]
    );
    ensure!(
        header[1] == CMD_CONNECT,
        "unexpected TUIC bidirectional command type {}",
        header[1]
    );
    let target = read_tuic_address(&mut recv)
        .await?
        .context("TUIC connect target address is none")?;
    let session = auth.wait_session().await?;
    let remote = match connect_target(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = send.finish();
            return Err(error)
                .with_context(|| format!("connect TUIC target {}", target_name(&target)));
        }
    };
    let _ = remote.set_nodelay(true);
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let uplink_session = session.clone();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = recv
                .read(&mut buffer)
                .await
                .context("read TUIC uplink stream")?;
            let Some(read) = read else {
                remote_writer
                    .shutdown()
                    .await
                    .context("shutdown TUIC target writer")?;
                return Ok::<(), anyhow::Error>(());
            };
            uplink_session.record_upload(read).await?;
            remote_writer
                .write_all(&buffer[..read])
                .await
                .context("write TUIC target payload")?;
        }
    };
    let downlink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = remote_reader
                .read(&mut buffer)
                .await
                .context("read TUIC target payload")?;
            if read == 0 {
                send.finish().context("finish TUIC response stream")?;
                return Ok::<(), anyhow::Error>(());
            }
            session.record_download(read).await?;
            send.write_all(&buffer[..read])
                .await
                .context("write TUIC downlink stream")?;
        }
    };
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

async fn get_server_udp_session(
    connection: &quinn::Connection,
    sessions: &ServerUdpSessions,
    assoc_id: u16,
    mode: TuicUdpRelayMode,
    bind_ipv6: bool,
    core: CoreSession,
) -> Result<Arc<ServerUdpSession>> {
    if let Some(session) = sessions.lock().await.get(&assoc_id).cloned() {
        return Ok(session);
    }
    let socket = Arc::new(match mode {
        TuicUdpRelayMode::Native | TuicUdpRelayMode::Quic => {
            let ip = if bind_ipv6 {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            };
            socket_protect::bind_udp(SocketAddr::new(ip, 0)).await?
        }
    });
    let response_socket = socket.clone();
    let response_connection = connection.clone();
    let response_core = core.clone();
    let response_handle = tokio::spawn(async move {
        if let Err(error) = run_server_udp_responses(
            response_connection,
            assoc_id,
            response_socket,
            mode,
            response_core,
        )
        .await
        {
            tracing::warn!("TUIC UDP response loop failed: {error:?}");
        }
    });
    let session = Arc::new(ServerUdpSession {
        socket,
        response_handle: StdMutex::new(response_handle),
    });
    sessions.lock().await.insert(assoc_id, session.clone());
    Ok(session)
}

async fn run_server_udp_responses(
    connection: quinn::Connection,
    assoc_id: u16,
    socket: Arc<UdpSocket>,
    mode: TuicUdpRelayMode,
    core: CoreSession,
) -> Result<()> {
    let mut buffer = vec![0u8; u16::MAX as usize];
    let mut packet_id = 1u16;
    loop {
        let (read, source) = socket
            .recv_from(&mut buffer)
            .await
            .context("receive TUIC UDP response")?;
        core.record_download(read).await?;
        send_packet_commands(
            &connection,
            mode,
            assoc_id,
            packet_id,
            &ProxyTarget::Ip(source),
            &buffer[..read],
        )
        .await?;
        packet_id = packet_id.wrapping_add(1);
    }
}

async fn send_packet_commands(
    connection: &quinn::Connection,
    mode: TuicUdpRelayMode,
    assoc_id: u16,
    packet_id: u16,
    target: &ProxyTarget,
    payload: &[u8],
) -> Result<()> {
    let max_frame_len = match mode {
        TuicUdpRelayMode::Native => connection
            .max_datagram_size()
            .context("TUIC native UDP datagram size is not available")?,
        TuicUdpRelayMode::Quic => usize::MAX,
    };
    for frame in encode_packet_fragments(assoc_id, packet_id, target, payload, max_frame_len)? {
        match mode {
            TuicUdpRelayMode::Native => {
                connection
                    .send_datagram_wait(Bytes::from(frame))
                    .await
                    .context("send TUIC native UDP datagram")?;
            }
            TuicUdpRelayMode::Quic => {
                let mut stream = connection
                    .open_uni()
                    .await
                    .context("open TUIC UDP unidirectional stream")?;
                stream
                    .write_all(&frame)
                    .await
                    .context("write TUIC UDP stream command")?;
                stream.finish().context("finish TUIC UDP stream command")?;
            }
        }
    }
    Ok(())
}

fn encode_packet_fragments(
    assoc_id: u16,
    packet_id: u16,
    target: &ProxyTarget,
    payload: &[u8],
    max_frame_len: usize,
) -> Result<Vec<Vec<u8>>> {
    let address = encode_tuic_address(Some(target))?;
    let none_address = encode_tuic_address(None)?;
    let first_capacity = max_packet_payload_len(max_frame_len, address.len())?;
    if payload.len() <= first_capacity {
        return Ok(vec![encode_packet_command(
            assoc_id,
            packet_id,
            1,
            0,
            Some(target),
            payload,
        )?]);
    }
    let next_capacity = max_packet_payload_len(max_frame_len, none_address.len())?;
    let rest = payload.len() - first_capacity;
    let total = 1 + rest.div_ceil(next_capacity);
    ensure!(
        total <= u8::MAX as usize,
        "TUIC UDP packet needs too many fragments"
    );
    let mut frames = Vec::with_capacity(total);
    let mut offset = 0usize;
    let first = &payload[..first_capacity];
    frames.push(encode_packet_command(
        assoc_id,
        packet_id,
        total as u8,
        0,
        Some(target),
        first,
    )?);
    offset += first.len();
    for frag_id in 1..total {
        let take = next_capacity.min(payload.len() - offset);
        frames.push(encode_packet_command(
            assoc_id,
            packet_id,
            total as u8,
            frag_id as u8,
            None,
            &payload[offset..offset + take],
        )?);
        offset += take;
    }
    Ok(frames)
}

fn max_packet_payload_len(max_frame_len: usize, address_len: usize) -> Result<usize> {
    let header_len = PACKET_COMMAND_FIXED_LEN + address_len;
    ensure!(
        header_len < max_frame_len,
        "TUIC packet command header exceeds peer datagram limit"
    );
    Ok((max_frame_len - header_len).min(u16::MAX as usize))
}

fn encode_packet_command(
    assoc_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    target: Option<&ProxyTarget>,
    payload: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "TUIC packet fragment payload too large"
    );
    let address = encode_tuic_address(target)?;
    let mut bytes = Vec::with_capacity(PACKET_COMMAND_FIXED_LEN + address.len() + payload.len());
    bytes.push(TUIC_VERSION);
    bytes.push(CMD_PACKET);
    bytes.extend_from_slice(&assoc_id.to_be_bytes());
    bytes.extend_from_slice(&packet_id.to_be_bytes());
    bytes.push(frag_total);
    bytes.push(frag_id);
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&address);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn parse_packet_command(bytes: &[u8]) -> Result<TuicPacketCommand> {
    ensure!(
        bytes.len() >= PACKET_COMMAND_FIXED_LEN,
        "TUIC packet command is too short"
    );
    ensure!(
        bytes[0] == TUIC_VERSION,
        "unsupported TUIC version {}",
        bytes[0]
    );
    ensure!(bytes[1] == CMD_PACKET, "TUIC command is not Packet");
    let assoc_id = u16::from_be_bytes([bytes[2], bytes[3]]);
    let packet_id = u16::from_be_bytes([bytes[4], bytes[5]]);
    let frag_total = bytes[6];
    let frag_id = bytes[7];
    let size = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
    ensure!(frag_total > 0, "TUIC packet frag_total is zero");
    ensure!(
        frag_id < frag_total,
        "TUIC packet frag_id {} >= frag_total {}",
        frag_id,
        frag_total
    );
    let (target, address_len) = parse_tuic_address(&bytes[10..])?;
    let payload_offset = 10 + address_len;
    ensure!(
        bytes.len() >= payload_offset + size,
        "TUIC packet payload is shorter than SIZE"
    );
    ensure!(
        bytes.len() == payload_offset + size,
        "TUIC packet has trailing bytes after payload"
    );
    if frag_total == 1 || frag_id == 0 {
        ensure!(
            target.is_some(),
            "TUIC first packet fragment address is none"
        );
    } else {
        ensure!(
            target.is_none(),
            "TUIC non-first packet fragment address is not none"
        );
    }
    Ok(TuicPacketCommand {
        assoc_id,
        packet_id,
        frag_total,
        frag_id,
        target,
        payload: bytes[payload_offset..payload_offset + size].to_vec(),
    })
}

fn push_fragment(
    fragments: &mut HashMap<(u16, u16), TuicFragmentBuffer>,
    packet: TuicPacketCommand,
) -> Result<Option<TuicPacket>> {
    if packet.frag_total == 1 {
        return Ok(Some(TuicPacket {
            assoc_id: packet.assoc_id,
            target: packet.target.context("TUIC single packet has no address")?,
            payload: packet.payload,
        }));
    }
    let now = Instant::now();
    fragments.retain(|_, buffer| now.duration_since(buffer.created_at) <= UDP_FRAGMENT_TIMEOUT);
    let key = (packet.assoc_id, packet.packet_id);
    let buffer = fragments.entry(key).or_insert_with(|| TuicFragmentBuffer {
        target: None,
        created_at: now,
        fragments: vec![None; packet.frag_total as usize],
    });
    ensure!(
        buffer.fragments.len() == packet.frag_total as usize,
        "TUIC packet fragment count changed"
    );
    if packet.frag_id == 0 {
        buffer.target = packet.target;
    }
    ensure!(
        buffer.fragments[packet.frag_id as usize].is_none(),
        "TUIC duplicate packet fragment"
    );
    buffer.fragments[packet.frag_id as usize] = Some(packet.payload);
    let Some(target) = buffer.target.clone() else {
        return Ok(None);
    };
    if buffer.fragments.iter().any(Option::is_none) {
        return Ok(None);
    }
    let mut payload = Vec::new();
    for fragment in &mut buffer.fragments {
        payload.extend(
            fragment
                .take()
                .context("TUIC fragment disappeared after completeness check")?,
        );
    }
    fragments.remove(&key);
    Ok(Some(TuicPacket {
        assoc_id: key.0,
        target,
        payload,
    }))
}

async fn write_command<W>(writer: &mut W, command: u8, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[TUIC_VERSION, command]).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

fn encode_tuic_address(target: Option<&ProxyTarget>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    match target {
        None => bytes.push(ADDR_NONE),
        Some(ProxyTarget::Ip(addr)) => match addr.ip() {
            IpAddr::V4(ip) => {
                bytes.push(ADDR_IPV4);
                bytes.extend_from_slice(&ip.octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                bytes.push(ADDR_IPV6);
                bytes.extend_from_slice(&ip.octets());
                bytes.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
        Some(ProxyTarget::Domain(host, port)) => {
            ensure!(
                host.len() <= u8::MAX as usize,
                "TUIC domain address too long"
            );
            bytes.push(ADDR_DOMAIN);
            bytes.push(host.len() as u8);
            bytes.extend_from_slice(host.as_bytes());
            bytes.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(bytes)
}

async fn read_tuic_address<R>(reader: &mut R) -> Result<Option<ProxyTarget>>
where
    R: AsyncRead + Unpin,
{
    let mut kind = [0u8; 1];
    reader
        .read_exact(&mut kind)
        .await
        .context("read TUIC address type")?;
    match kind[0] {
        ADDR_NONE => Ok(None),
        ADDR_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            reader.read_exact(&mut host).await?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await?;
            Ok(Some(ProxyTarget::Domain(
                String::from_utf8(host).context("decode TUIC domain address")?,
                u16::from_be_bytes(port),
            )))
        }
        ADDR_IPV4 => {
            let mut addr = [0u8; 6];
            reader.read_exact(&mut addr).await?;
            Ok(Some(ProxyTarget::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
                u16::from_be_bytes([addr[4], addr[5]]),
            ))))
        }
        ADDR_IPV6 => {
            let mut addr = [0u8; 18];
            reader.read_exact(&mut addr).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr[..16]);
            Ok(Some(ProxyTarget::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([addr[16], addr[17]]),
            ))))
        }
        other => bail!("unsupported TUIC address type {other}"),
    }
}

fn parse_tuic_address(bytes: &[u8]) -> Result<(Option<ProxyTarget>, usize)> {
    ensure!(!bytes.is_empty(), "TUIC address is empty");
    match bytes[0] {
        ADDR_NONE => Ok((None, 1)),
        ADDR_DOMAIN => {
            ensure!(bytes.len() >= 2, "TUIC domain address missing length");
            let len = bytes[1] as usize;
            let port_offset = 2 + len;
            ensure!(
                bytes.len() >= port_offset + 2,
                "TUIC domain address missing port"
            );
            Ok((
                Some(ProxyTarget::Domain(
                    String::from_utf8(bytes[2..port_offset].to_vec())
                        .context("decode TUIC domain address")?,
                    u16::from_be_bytes([bytes[port_offset], bytes[port_offset + 1]]),
                )),
                port_offset + 2,
            ))
        }
        ADDR_IPV4 => {
            ensure!(bytes.len() >= 7, "TUIC IPv4 address is too short");
            Ok((
                Some(ProxyTarget::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4])),
                    u16::from_be_bytes([bytes[5], bytes[6]]),
                ))),
                7,
            ))
        }
        ADDR_IPV6 => {
            ensure!(bytes.len() >= 19, "TUIC IPv6 address is too short");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            Ok((
                Some(ProxyTarget::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    u16::from_be_bytes([bytes[17], bytes[18]]),
                ))),
                19,
            ))
        }
        other => bail!("unsupported TUIC address type {other}"),
    }
}

fn tuic_token(connection: &quinn::Connection, uuid: &[u8; 16], password: &str) -> Result<[u8; 32]> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|_| anyhow!("export TUIC token keying material"))?;
    Ok(token)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

fn parse_uuid(value: &str) -> Result<[u8; 16]> {
    let text = value.trim();
    let mut hex = String::with_capacity(32);
    for ch in text.chars() {
        if ch != '-' {
            hex.push(ch);
        }
    }
    ensure!(hex.len() == 32, "UUID must contain 16 bytes");
    let mut output = [0u8; 16];
    for index in 0..16 {
        output[index] =
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).context("parse UUID hex")?;
    }
    Ok(output)
}

fn format_uuid(uuid: &[u8; 16]) -> String {
    let hex = hex::encode(uuid);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn tuic_users(config: &TuicServerConfig) -> Result<Vec<TuicUser>> {
    let mut users = Vec::new();
    if !config.uuid.trim().is_empty() || !config.password.trim().is_empty() {
        let uuid = config.uuid.trim();
        let password = config.password.trim();
        ensure!(
            !uuid.is_empty(),
            "TUIC server uuid is required when password is set"
        );
        ensure!(
            !password.is_empty(),
            "TUIC server password is required when uuid is set"
        );
        parse_uuid(uuid)?;
        users.push(TuicUser {
            uuid: uuid.to_string(),
            password: password.to_string(),
        });
    }
    for user in &config.users {
        users.push(parse_tuic_user(user)?);
    }
    ensure!(!users.is_empty(), "TUIC server needs at least one user");
    Ok(users)
}

fn tuic_user_map(config: &TuicServerConfig) -> Result<HashMap<[u8; 16], TuicUser>> {
    let mut map = HashMap::new();
    for user in tuic_users(config)? {
        let uuid = parse_uuid(&user.uuid)?;
        ensure!(
            map.insert(uuid, user).is_none(),
            "duplicate TUIC user UUID {}",
            format_uuid(&uuid)
        );
    }
    Ok(map)
}

async fn connect_target(target: &ProxyTarget) -> Result<TcpStream> {
    match target {
        ProxyTarget::Ip(addr) => socket_protect::connect_tcp_addr(*addr)
            .await
            .with_context(|| format!("connect TUIC target {addr}")),
        ProxyTarget::Domain(host, port) => socket_protect::connect_tcp_host_port(host, *port)
            .await
            .with_context(|| format!("connect TUIC target {host}:{port}")),
    }
}

async fn target_socket_addr(target: &ProxyTarget) -> Result<SocketAddr> {
    match target {
        ProxyTarget::Ip(addr) => Ok(*addr),
        ProxyTarget::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .with_context(|| format!("resolve TUIC UDP target {host}:{port}"))?
            .next()
            .with_context(|| format!("TUIC UDP target resolved to no addresses: {host}:{port}")),
    }
}

async fn resolve_host_addr(host: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve TUIC peer {host}:{port}"))?
        .next()
        .with_context(|| format!("TUIC peer resolved to no addresses: {host}:{port}"))
}

fn build_client_endpoint(config: &TuicClientConfig, bind_ipv6: bool) -> Result<Endpoint> {
    let mut tls = if config.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(tls::InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = alpn_protocols(&config.alpn_protocols);
    let quic_tls =
        QuicClientConfig::try_from(Arc::new(tls)).context("build TUIC QUIC TLS client config")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    client_config.transport_config(Arc::new(tuic_transport_config(&config.congestion_control)?));
    let bind_addr = if bind_ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let socket = socket_protect::bind_udp_std(bind_addr)?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("bind TUIC UDP endpoint")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn build_server_endpoint(config: &TuicServerConfig) -> Result<Endpoint> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            tls::load_certs(&config.cert_path)?,
            tls::load_key(&config.key_path)?,
        )
        .with_context(|| {
            format!(
                "build TUIC TLS server config with cert {} and key {}",
                config.cert_path.display(),
                config.key_path.display()
            )
        })?;
    tls_config.alpn_protocols = alpn_protocols(&config.alpn_protocols);
    let crypto =
        QuicServerConfig::try_from(tls_config).context("build TUIC QUIC TLS server config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(tuic_transport_config(&config.congestion_control)?));
    let socket = socket_protect::bind_udp_std(config.listen)?;
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("bind TUIC server endpoint")
}

fn tuic_transport_config(congestion_control: &str) -> Result<quinn::TransportConfig> {
    let mut transport_config = quinn::TransportConfig::default();
    let idle_timeout =
        IdleTimeout::try_from(DEFAULT_QUIC_IDLE_TIMEOUT).context("build TUIC idle timeout")?;
    transport_config
        .stream_receive_window(VarInt::from_u32(TUIC_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(TUIC_CONN_RECEIVE_WINDOW))
        .send_window(u64::from(TUIC_CONN_RECEIVE_WINDOW))
        .max_concurrent_bidi_streams(VarInt::from_u32(TUIC_MAX_INCOMING_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(TUIC_MAX_INCOMING_STREAMS))
        .max_idle_timeout(Some(idle_timeout))
        .datagram_receive_buffer_size(Some(TUIC_DATAGRAM_BUFFER_SIZE))
        .datagram_send_buffer_size(TUIC_DATAGRAM_BUFFER_SIZE)
        .congestion_controller_factory(
            match congestion_control.trim().to_ascii_lowercase().as_str() {
                "" | "cubic" => Arc::new(quinn::congestion::CubicConfig::default()),
                "bbr" => Arc::new(quinn::congestion::BbrConfig::default()),
                "reno" | "newreno" | "new_reno" => {
                    Arc::new(quinn::congestion::NewRenoConfig::default())
                }
                other => bail!("unsupported TUIC congestion_control {other}"),
            },
        );
    Ok(transport_config)
}

fn alpn_protocols(values: &[String]) -> Vec<Vec<u8>> {
    let values = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.as_bytes().to_vec())
        .collect::<Vec<_>>();
    if values.is_empty() {
        vec![TUIC_H3_ALPN.to_vec()]
    } else {
        values
    }
}

fn heartbeat_interval(seconds: u64) -> Duration {
    if seconds == 0 {
        DEFAULT_HEARTBEAT_INTERVAL
    } else {
        Duration::from_secs(seconds)
    }
}

async fn run_tuic_heartbeat(connection: quinn::Connection, heartbeat_interval: Duration) {
    let mut ticker = tokio::time::interval(heartbeat_interval);
    loop {
        ticker.tick().await;
        if let Err(error) = connection
            .send_datagram_wait(Bytes::from_static(&[TUIC_VERSION, CMD_HEARTBEAT]))
            .await
        {
            tracing::debug!("TUIC heartbeat stopped: {error:?}");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_fragments_roundtrip() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 53);
        let payload = (0u8..90).collect::<Vec<_>>();
        let frames = encode_packet_fragments(7, 42, &target, &payload, 48)?;
        assert!(frames.len() > 1);

        let mut fragments = HashMap::new();
        let mut complete = None;
        for frame in frames {
            let packet = parse_packet_command(&frame)?;
            if packet.frag_id > 0 {
                assert!(packet.target.is_none());
            }
            complete = push_fragment(&mut fragments, packet)?;
        }

        let packet = complete.context("fragmented packet did not complete")?;
        assert_eq!(packet.assoc_id, 7);
        assert_eq!(packet.target, target);
        assert_eq!(packet.payload, payload);
        assert!(fragments.is_empty());
        Ok(())
    }

    #[test]
    fn packet_parser_rejects_non_first_fragment_address() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 53);
        let frame = encode_packet_command(7, 42, 2, 1, Some(&target), b"payload")?;
        let error =
            parse_packet_command(&frame).expect_err("non-first fragment must use none addr");
        assert!(error.to_string().contains("non-first packet fragment"));
        Ok(())
    }

    #[test]
    fn fragment_buffer_rejects_duplicate_fragment() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 53);
        let frame = encode_packet_command(7, 42, 2, 0, Some(&target), b"payload")?;
        let packet = parse_packet_command(&frame)?;
        let mut fragments = HashMap::new();
        assert!(push_fragment(&mut fragments, packet.clone())?.is_none());
        let error =
            push_fragment(&mut fragments, packet).expect_err("duplicate fragment must fail");
        assert!(error.to_string().contains("duplicate packet fragment"));
        Ok(())
    }
}
