use crate::core::{CoreSession, ProxyCore};
use crate::listener;
use crate::padding::{PADDING_CHECKPOINT, PaddingScheme};
use crate::protocol::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, FRAME_HEADER_LEN,
    Frame, ProxyTarget, decode_target, encode_frame, encode_target, parse_settings,
    resolve_target_addr, target_name,
};
use crate::socket_protect;
use crate::socks::{self, SocksRequest};
use crate::uot;
use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket, tcp::OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Instant, sleep};
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

const HANDSHAKE_NONCE_LEN: usize = 32;
const HANDSHAKE_TIMESTAMP_LEN: usize = 8;
const HANDSHAKE_X25519_PUBLIC_KEY_LEN: usize = 32;
const HANDSHAKE_PADDING_LEN_FIELD_LEN: usize = 2;
const HANDSHAKE_MIN_PADDING_LEN: usize = 16;
const HANDSHAKE_MAX_PADDING_LEN: usize = 512;
const HANDSHAKE_TAG_LEN: usize = 32;
const HANDSHAKE_REPLAY_WINDOW_SECS: u64 = 300;
const RECORD_NONCE_LEN: usize = 24;
const RECORD_TAG_LEN: usize = 16;
const MAX_RECORD_LEN: usize = u16::MAX as usize;
const MAX_RECORD_PLAINTEXT_LEN: usize = MAX_RECORD_LEN - RECORD_TAG_LEN;
const MAX_FRAME_PAYLOAD_LEN: usize = MAX_RECORD_PLAINTEXT_LEN - FRAME_HEADER_LEN;
const RECORD_NONCE_PREFIX: &[u8; 16] = b"NodeExpandAEADv4";
const RECORD_AAD_PREFIX: &[u8] = b"nodeexpand-record-v4";
const RECORD_LENGTH_MASK_PREFIX: &[u8] = b"nodeexpand-record-length-v4";
const HEARTBEAT_JITTER_MIN_PERCENT: u64 = 70;
const HEARTBEAT_JITTER_SPAN_PERCENT: u64 = 61;

type HandshakeReplayCache = Arc<Mutex<HashMap<[u8; HANDSHAKE_NONCE_LEN], u64>>>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct NodeExpandEndpoint {
    pub server_host: String,
    pub server_port: u16,
}

#[derive(Clone, Debug)]
pub struct NodeExpandClientConfig {
    pub listen: SocketAddr,
    pub endpoints: Vec<NodeExpandEndpoint>,
    pub password: String,
    pub padding_scheme: Vec<String>,
    pub heartbeat_interval_secs: u64,
}

#[derive(Clone, Debug)]
pub struct NodeExpandServerConfig {
    pub listen: SocketAddr,
    pub password: String,
    pub users: Vec<String>,
    pub padding_scheme: Vec<String>,
    pub heartbeat_interval_secs: u64,
}

pub async fn run_nodeexpand_client(config: NodeExpandClientConfig) -> Result<()> {
    run_nodeexpand_client_with_core(config, None).await
}

pub async fn run_nodeexpand_client_with_core(
    config: NodeExpandClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind NodeExpand local SOCKS listener on {}", config.listen))?;
    run_nodeexpand_client_listener(listener, config, core).await
}

pub async fn run_nodeexpand_client_listener(
    listener: TcpListener,
    config: NodeExpandClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    ensure!(
        !config.endpoints.is_empty(),
        "NodeExpand client requires at least one endpoint"
    );
    ensure!(
        config.heartbeat_interval_secs > 0,
        "NodeExpand heartbeat interval must be greater than 0"
    );
    let shared = Arc::new(SharedNodeExpandClient::new(config));
    tracing::info!(
        "NodeExpand client listening on socks5://{}",
        listener.local_addr()?
    );
    loop {
        let (stream, peer) = match listener::accept_client(&listener).await {
            Ok(v) => v,
            Err(listener::AcceptError::Cancelled) => return Ok(()),
            Err(listener::AcceptError::Io(error)) => {
                return Err(error).context("accept SOCKS client");
            }
        };
        let shared = shared.clone();
        let config = shared.config.clone();
        let core = core.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_socks_client(stream, shared, config, core, peer).await {
                tracing::warn!("NodeExpand SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn run_nodeexpand_server(config: NodeExpandServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.password, &config.users);
    run_nodeexpand_server_with_core(config, core).await
}

pub async fn run_nodeexpand_server_with_core(
    config: NodeExpandServerConfig,
    core: ProxyCore,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind NodeExpand server on {}", config.listen))?;
    run_nodeexpand_server_listener_with_core(listener, config, core).await
}

pub async fn run_nodeexpand_server_listener_with_core(
    listener: TcpListener,
    config: NodeExpandServerConfig,
    core: ProxyCore,
) -> Result<()> {
    ensure!(
        config.heartbeat_interval_secs > 0,
        "NodeExpand heartbeat interval must be greater than 0"
    );
    let padding = PaddingScheme::from_lines(config.padding_scheme.clone())?;
    let replay_cache = Arc::new(Mutex::new(HashMap::new()));
    tracing::info!("NodeExpand server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("accept NodeExpand client")?;
        let passwords = auth_passwords(&config.password, &config.users);
        let replay_cache = replay_cache.clone();
        let padding = padding.clone();
        let core = core.clone();
        let heartbeat_interval_secs = config.heartbeat_interval_secs;
        tokio::spawn(async move {
            if let Err(error) = handle_nodeexpand_client(
                stream,
                passwords,
                replay_cache,
                padding,
                core,
                heartbeat_interval_secs,
                peer,
            )
            .await
            {
                tracing::warn!("NodeExpand client {peer} failed: {error:?}");
            }
        });
    }
}

#[derive(Clone)]
struct SharedNodeExpandClient {
    config: NodeExpandClientConfig,
    sessions: Arc<Mutex<Vec<NodeExpandEndpointState>>>,
}

#[derive(Clone)]
struct NodeExpandEndpointState {
    endpoint: NodeExpandEndpoint,
    session: Option<NodeExpandClientSession>,
}

impl SharedNodeExpandClient {
    fn new(config: NodeExpandClientConfig) -> Self {
        let sessions = config
            .endpoints
            .iter()
            .cloned()
            .map(|endpoint| NodeExpandEndpointState {
                endpoint,
                session: None,
            })
            .collect();
        Self {
            config,
            sessions: Arc::new(Mutex::new(sessions)),
        }
    }

    async fn get_or_connect(&self) -> Result<NodeExpandClientSession> {
        let mut states = self.sessions.lock().await;
        let mut errors = Vec::new();
        for state in states.iter_mut() {
            let reconnect = match state.session.as_ref() {
                Some(session) => !session.is_alive().await,
                None => true,
            };
            if reconnect {
                match NodeExpandClientSession::connect(&state.endpoint, &self.config).await {
                    Ok(session) => {
                        state.session = Some(session);
                    }
                    Err(error) => {
                        let endpoint = format!(
                            "{}:{}",
                            state.endpoint.server_host, state.endpoint.server_port
                        );
                        tracing::warn!(
                            endpoint = %endpoint,
                            %error,
                            "NodeExpand endpoint connect failed"
                        );
                        state.session = None;
                        errors.push(format!("{endpoint}: {error}"));
                    }
                }
            }
        }
        if let Some(session) = states
            .iter()
            .filter_map(|state| state.session.as_ref())
            .min_by_key(|session| session.load())
            .cloned()
        {
            return Ok(session);
        }
        if errors.is_empty() {
            bail!("NodeExpand client has no connected endpoint");
        }
        bail!(
            "NodeExpand client has no connected endpoint: {}",
            errors.join("; ")
        )
    }
}

#[derive(Clone)]
struct NodeExpandClientSession {
    writer: Arc<Mutex<NodeExpandFrameWriter<WriteHalf<TcpStream>>>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    next_stream_id: Arc<AtomicU32>,
    closed: Arc<Mutex<Option<String>>>,
    active_streams: Arc<AtomicU32>,
}

enum StreamEvent {
    SynAck(Vec<u8>),
    Payload(Vec<u8>),
    Fin,
    Error(String),
}

struct NodeExpandClientStream {
    stream_id: u32,
    writer: Arc<Mutex<NodeExpandFrameWriter<WriteHalf<TcpStream>>>>,
    events: mpsc::Receiver<StreamEvent>,
    active_streams: Arc<AtomicU32>,
}

impl Drop for NodeExpandClientStream {
    fn drop(&mut self) {
        self.active_streams.fetch_sub(1, Ordering::SeqCst);
    }
}

impl NodeExpandClientSession {
    async fn is_alive(&self) -> bool {
        self.closed.lock().await.is_none()
    }

    fn load(&self) -> u32 {
        self.active_streams.load(Ordering::SeqCst)
    }

    async fn connect(
        endpoint: &NodeExpandEndpoint,
        config: &NodeExpandClientConfig,
    ) -> Result<Self> {
        let mut tcp = socket_protect::connect_tcp_host_port(
            endpoint.server_host.as_str(),
            endpoint.server_port,
        )
        .await
        .with_context(|| {
            format!(
                "connect NodeExpand server {}:{}",
                endpoint.server_host, endpoint.server_port
            )
        })?;
        let _ = tcp.set_nodelay(true);
        let keys = client_handshake(&mut tcp, &config.password).await?;
        let (reader, writer) = split(tcp);
        let padding = PaddingScheme::from_lines(config.padding_scheme.clone())?;
        let mut writer =
            NodeExpandFrameWriter::new(writer, keys.send_key, keys.send_length_key, padding)?;
        writer.write_client_settings().await?;

        let session = Self {
            writer: Arc::new(Mutex::new(writer)),
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: Arc::new(AtomicU32::new(1)),
            closed: Arc::new(Mutex::new(None)),
            active_streams: Arc::new(AtomicU32::new(0)),
        };
        let reader = NodeExpandFrameReader::new(reader, keys.recv_key, keys.recv_length_key)?;
        tokio::spawn(read_client_session_frames(
            reader,
            session.writer.clone(),
            session.streams.clone(),
            session.closed.clone(),
        ));
        tokio::spawn(run_heartbeat(
            session.writer.clone(),
            session.closed.clone(),
            config.heartbeat_interval_secs,
        ));
        Ok(session)
    }

    async fn open_stream(
        &self,
        target: ProxyTarget,
        initial_payload: Vec<u8>,
    ) -> Result<NodeExpandClientStream> {
        if let Some(error) = self.closed.lock().await.clone() {
            bail!("NodeExpand client session is closed: {error}");
        }
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);
        if stream_id == 0 {
            bail!("NodeExpand stream id exhausted");
        }
        let (events_tx, mut events_rx) = mpsc::channel(32);
        self.streams.lock().await.insert(stream_id, events_tx);

        let mut first_payload = encode_target(&target)?;
        first_payload.extend_from_slice(&initial_payload);
        {
            let mut writer = self.writer.lock().await;
            if let Err(error) = writer.write_frame(CMD_SYN, stream_id, &[]).await {
                self.streams.lock().await.remove(&stream_id);
                *self.closed.lock().await = Some(format!("write NodeExpand stream SYN: {error:?}"));
                return Err(error).context("write NodeExpand stream SYN");
            }
            if let Err(error) = writer.write_payload_chunks(stream_id, &first_payload).await {
                self.streams.lock().await.remove(&stream_id);
                *self.closed.lock().await = Some(format!(
                    "write NodeExpand stream initial payload: {error:?}"
                ));
                return Err(error).context("write NodeExpand stream initial payload");
            }
        }

        loop {
            let event = events_rx
                .recv()
                .await
                .context("NodeExpand stream closed before SYNACK")?;
            match event {
                StreamEvent::SynAck(payload) if payload.is_empty() => {
                    self.active_streams.fetch_add(1, Ordering::SeqCst);
                    return Ok(NodeExpandClientStream {
                        stream_id,
                        writer: self.writer.clone(),
                        events: events_rx,
                        active_streams: self.active_streams.clone(),
                    });
                }
                StreamEvent::SynAck(payload) => {
                    self.streams.lock().await.remove(&stream_id);
                    bail!(
                        "NodeExpand stream open failed: {}",
                        String::from_utf8_lossy(&payload)
                    );
                }
                StreamEvent::Error(error) => {
                    self.streams.lock().await.remove(&stream_id);
                    bail!("{error}");
                }
                StreamEvent::Fin => {
                    self.streams.lock().await.remove(&stream_id);
                    bail!("NodeExpand stream closed before SYNACK");
                }
                StreamEvent::Payload(_) => {}
            }
        }
    }
}

impl NodeExpandClientStream {
    async fn read_payload(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let Some(event) = self.events.recv().await else {
                return Ok(None);
            };
            match event {
                StreamEvent::Payload(payload) => return Ok(Some(payload)),
                StreamEvent::Fin => return Ok(None),
                StreamEvent::Error(error) => bail!("{error}"),
                StreamEvent::SynAck(payload) if !payload.is_empty() => {
                    bail!(
                        "NodeExpand stream error: {}",
                        String::from_utf8_lossy(&payload)
                    );
                }
                StreamEvent::SynAck(_) => {}
            }
        }
    }
}

async fn handle_socks_client(
    mut local: TcpStream,
    shared: Arc<SharedNodeExpandClient>,
    config: NodeExpandClientConfig,
    core: Option<ProxyCore>,
    peer: SocketAddr,
) -> Result<()> {
    match socks::read_request(&mut local).await? {
        SocksRequest::Connect(target) => {
            let session = match shared.get_or_connect().await {
                Ok(session) => session,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(error);
                }
            };
            let stream = match session.open_stream(target.clone(), Vec::new()).await {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(error);
                }
            };
            let core_session = if let Some(core) = core.as_ref() {
                core.authenticate_from(&config.password, peer).await?
            } else {
                CoreSession::disabled()
            };
            socks::write_reply(&mut local, 0x00).await?;
            tracing::info!("NodeExpand proxying {}", target_name(&target));
            relay_tcp_counted(local, stream, core_session).await
        }
        SocksRequest::UdpAssociate => {
            let session = match shared.get_or_connect().await {
                Ok(session) => session,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(error);
                }
            };
            handle_udp_associate_counted(local, session, config, core, peer).await
        }
    }
}

async fn relay_tcp_counted(
    local: TcpStream,
    mut stream: NodeExpandClientStream,
    session: CoreSession,
) -> Result<()> {
    let stream_id = stream.stream_id;
    let writer = stream.writer.clone();
    let (mut local_reader, local_writer) = local.into_split();
    let uplink_session = session.clone();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read local payload")?;
            if read == 0 {
                writer
                    .lock()
                    .await
                    .write_frame(CMD_FIN, stream_id, &[])
                    .await?;
                return Ok::<(), anyhow::Error>(());
            }
            uplink_session.record_upload(read).await?;
            writer
                .lock()
                .await
                .write_payload_chunks(stream_id, &buffer[..read])
                .await?;
        }
    };
    let downlink = write_stream_payloads_counted(&mut stream, local_writer, session);
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

async fn write_stream_payloads_counted(
    stream: &mut NodeExpandClientStream,
    mut local_writer: OwnedWriteHalf,
    session: CoreSession,
) -> Result<()> {
    while let Some(payload) = stream.read_payload().await? {
        session.record_download(payload.len()).await?;
        local_writer
            .write_all(&payload)
            .await
            .context("write local payload")?;
    }
    local_writer
        .shutdown()
        .await
        .context("shutdown local writer")
}

async fn handle_udp_associate_counted(
    mut control: TcpStream,
    session: NodeExpandClientSession,
    config: NodeExpandClientConfig,
    core: Option<ProxyCore>,
    peer: SocketAddr,
) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .with_context(|| format!("bind SOCKS UDP associate socket on {bind_ip}:0"))?;
    let udp_addr = udp.local_addr()?;
    socks::write_reply_with_bind(&mut control, 0x00, udp_addr).await?;

    let core_session = if let Some(core) = core.as_ref() {
        core.authenticate_from(&config.password, peer).await?
    } else {
        CoreSession::disabled()
    };
    let stream = session
        .open_stream(uot::magic_target(), uot::encode_v2_associate_request()?)
        .await?;
    let udp = Arc::new(udp);
    let (client_tx, mut client_rx) = mpsc::channel::<SocketAddr>(8);

    let udp_to_stream = {
        let udp = udp.clone();
        let stream_id = stream.stream_id;
        let writer = stream.writer.clone();
        let core_session = core_session.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive SOCKS UDP packet")?;
                let _ = client_tx.try_send(peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                core_session.record_upload(payload.len()).await?;
                let packet = uot::encode_associate_packet(&target, payload)?;
                writer
                    .lock()
                    .await
                    .write_payload_chunks(stream_id, &packet)
                    .await?;
            }
        }
    };

    let stream_to_udp = {
        let udp = udp.clone();
        let mut stream = stream;
        let core_session = core_session.clone();
        async move {
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => {
                        if let Some(next_peer) = next_peer {
                            peer = Some(next_peer);
                        }
                    }
                    payload = stream.read_payload() => {
                        let Some(payload) = payload? else {
                            return Ok::<(), anyhow::Error>(());
                        };
                        let (source, packet) = uot::decode_associate_packet(&payload)?;
                        core_session.record_download(packet.len()).await?;
                        let response = uot::encode_socks_udp_packet(&source, packet)?;
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
            let read = control
                .read(&mut buffer)
                .await
                .context("read SOCKS UDP control connection")?;
            if read == 0 {
                return Ok::<(), anyhow::Error>(());
            }
        }
    };

    tokio::select! {
        result = udp_to_stream => result,
        result = stream_to_udp => result,
        result = control_closed => result,
    }
}

async fn read_client_session_frames(
    mut reader: NodeExpandFrameReader<ReadHalf<TcpStream>>,
    writer: Arc<Mutex<NodeExpandFrameWriter<WriteHalf<TcpStream>>>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    closed: Arc<Mutex<Option<String>>>,
) {
    let result: Result<()> = async {
        loop {
            let frame = reader.read_frame().await?;
            handle_client_session_frame(frame, &writer, &streams).await?;
        }
    }
    .await;
    if let Err(error) = result {
        let message = format!("{error:?}");
        *closed.lock().await = Some(message.clone());
        let senders = {
            let mut streams = streams.lock().await;
            streams
                .drain()
                .map(|(_, sender)| sender)
                .collect::<Vec<_>>()
        };
        for sender in senders {
            let _ = sender.send(StreamEvent::Error(message.clone())).await;
        }
    }
}

async fn handle_client_session_frame(
    frame: Frame,
    writer: &Arc<Mutex<NodeExpandFrameWriter<WriteHalf<TcpStream>>>>,
    streams: &Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
) -> Result<()> {
    match frame.cmd {
        CMD_PSH => {
            send_stream_event(
                streams,
                frame.stream_id,
                StreamEvent::Payload(frame.payload),
            )
            .await
        }
        CMD_FIN => {
            let sender = streams.lock().await.remove(&frame.stream_id);
            if let Some(sender) = sender {
                let _ = sender.send(StreamEvent::Fin).await;
            }
        }
        CMD_SYNACK => {
            send_stream_event(streams, frame.stream_id, StreamEvent::SynAck(frame.payload)).await
        }
        CMD_ALERT => bail!(
            "NodeExpand server alert: {}",
            String::from_utf8_lossy(&frame.payload)
        ),
        CMD_HEART_REQUEST => {
            writer
                .lock()
                .await
                .write_frame(CMD_HEART_RESPONSE, frame.stream_id, &[])
                .await?;
        }
        CMD_UPDATE_PADDING_SCHEME => {
            let raw =
                std::str::from_utf8(&frame.payload).context("decode padding scheme update")?;
            writer.lock().await.update_padding_scheme(raw)?;
        }
        CMD_WASTE | CMD_SETTINGS | CMD_SERVER_SETTINGS | CMD_HEART_RESPONSE => {}
        _ => {}
    }
    Ok(())
}

async fn send_stream_event(
    streams: &Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    stream_id: u32,
    event: StreamEvent,
) {
    let sender = streams.lock().await.get(&stream_id).cloned();
    if let Some(sender) = sender {
        let _ = sender.send(event).await;
    }
}

async fn run_heartbeat(
    writer: Arc<Mutex<NodeExpandFrameWriter<WriteHalf<TcpStream>>>>,
    closed: Arc<Mutex<Option<String>>>,
    heartbeat_interval_secs: u64,
) {
    loop {
        let delay = match jittered_heartbeat_interval(heartbeat_interval_secs) {
            Ok(value) => value,
            Err(error) => {
                *closed.lock().await = Some(format!("schedule NodeExpand heartbeat: {error:?}"));
                return;
            }
        };
        sleep(delay).await;
        if closed.lock().await.is_some() {
            return;
        }
        if let Err(error) = writer
            .lock()
            .await
            .write_frame(CMD_HEART_REQUEST, 0, &[])
            .await
        {
            *closed.lock().await = Some(format!("write NodeExpand heartbeat: {error:?}"));
            return;
        }
    }
}

async fn handle_nodeexpand_client(
    mut stream: TcpStream,
    passwords: Vec<String>,
    replay_cache: HandshakeReplayCache,
    padding: PaddingScheme,
    core: ProxyCore,
    heartbeat_interval_secs: u64,
    peer: SocketAddr,
) -> Result<()> {
    let password_refs = passwords.iter().map(String::as_str).collect::<Vec<_>>();
    let (credential, keys) = server_handshake(&mut stream, &password_refs, &replay_cache).await?;
    let session = core.authenticate_from(&credential, peer).await?;
    let (reader, writer) = split(stream);
    let mut reader = NodeExpandFrameReader::new(reader, keys.recv_key, keys.recv_length_key)?;
    let writer = Arc::new(Mutex::new(NodeExpandFrameWriter::new(
        writer,
        keys.send_key,
        keys.send_length_key,
        padding.clone(),
    )?));
    let mut received_settings = false;
    let mut pending = HashSet::new();
    let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let heartbeat = sleep(jittered_heartbeat_interval(heartbeat_interval_secs)?);
    tokio::pin!(heartbeat);

    loop {
        let frame = tokio::select! {
            frame = reader.read_frame() => frame?,
            _ = &mut heartbeat => {
                if received_settings {
                    let mut writer = writer.lock().await;
                    writer.write_frame(CMD_HEART_REQUEST, 0, &[]).await?;
                }
                heartbeat.as_mut().reset(Instant::now() + jittered_heartbeat_interval(heartbeat_interval_secs)?);
                continue;
            }
        };
        match frame.cmd {
            CMD_SYN => {
                if !received_settings {
                    let mut writer = writer.lock().await;
                    writer
                        .write_frame(CMD_ALERT, 0, b"client did not send settings")
                        .await?;
                    bail!("NodeExpand client did not send settings before SYN");
                }
                pending.insert(frame.stream_id);
            }
            CMD_PSH if streams.contains_key(&frame.stream_id) => {
                let sender = streams.get(&frame.stream_id).expect("stream key exists");
                if sender.send(frame.payload).await.is_err() {
                    streams.remove(&frame.stream_id);
                }
            }
            CMD_PSH if pending.remove(&frame.stream_id) => {
                match open_stream(frame, writer.clone(), session.clone()).await {
                    Ok((stream_id, sender)) => {
                        streams.insert(stream_id, sender);
                    }
                    Err(error) => {
                        tracing::warn!("NodeExpand open stream failed: {error:?}");
                    }
                }
            }
            CMD_FIN => {
                pending.remove(&frame.stream_id);
                streams.remove(&frame.stream_id);
            }
            CMD_HEART_REQUEST => {
                let mut writer = writer.lock().await;
                writer
                    .write_frame(CMD_HEART_RESPONSE, frame.stream_id, &[])
                    .await?;
            }
            CMD_SETTINGS => {
                let settings = parse_settings(&frame.payload);
                received_settings = true;
                if settings.get("padding-md5").map(String::as_str) != Some(padding.md5()) {
                    let mut writer = writer.lock().await;
                    writer
                        .write_frame(CMD_UPDATE_PADDING_SCHEME, 0, padding.raw_text().as_bytes())
                        .await?;
                }
                let mut writer = writer.lock().await;
                writer.write_frame(CMD_SERVER_SETTINGS, 0, b"v=4").await?;
            }
            CMD_WASTE | CMD_SERVER_SETTINGS | CMD_UPDATE_PADDING_SCHEME => {}
            CMD_ALERT => {
                bail!(
                    "NodeExpand client alert: {}",
                    String::from_utf8_lossy(&frame.payload)
                );
            }
            _ => {}
        }
    }
}

fn auth_passwords(password: &str, users: &[String]) -> Vec<String> {
    std::iter::once(password)
        .chain(users.iter().map(String::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

async fn open_stream(
    frame: Frame,
    writer: Arc<Mutex<NodeExpandFrameWriter<WriteHalf<TcpStream>>>>,
    session: CoreSession,
) -> Result<(u32, mpsc::Sender<Vec<u8>>)> {
    let stream_id = frame.stream_id;
    let (target, initial_payload) = match decode_target(&frame.payload) {
        Ok(value) => value,
        Err(error) => {
            let mut writer = writer.lock().await;
            writer
                .write_frame(CMD_SYNACK, stream_id, error.to_string().as_bytes())
                .await?;
            return Err(error);
        }
    };
    if uot::is_magic_target(&target) {
        return match open_uot_stream(stream_id, &target, initial_payload, writer.clone(), session)
            .await
        {
            Ok(value) => Ok(value),
            Err(error) => {
                let mut writer = writer.lock().await;
                writer
                    .write_frame(CMD_SYNACK, stream_id, error.to_string().as_bytes())
                    .await?;
                Err(error)
            }
        };
    }
    let remote = match socket_protect::connect_proxy_target(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            let mut writer = writer.lock().await;
            writer
                .write_frame(CMD_SYNACK, stream_id, error.to_string().as_bytes())
                .await?;
            return Err(error);
        }
    };
    let _ = remote.set_nodelay(true);
    {
        let mut writer = writer.lock().await;
        writer.write_frame(CMD_SYNACK, stream_id, &[]).await?;
    }
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(32);
    tracing::info!(
        "NodeExpand opened stream {stream_id} to {}",
        target_name(&target)
    );

    if !initial_payload.is_empty() {
        sender
            .send(initial_payload.to_vec())
            .await
            .context("queue initial stream payload")?;
    }

    let downlink_writer = writer.clone();
    let downlink_session = session.clone();
    tokio::spawn(async move {
        let result = async {
            let mut buffer = vec![0u8; 32 * 1024];
            loop {
                let read = remote_reader
                    .read(&mut buffer)
                    .await
                    .context("read target payload")?;
                if read == 0 {
                    let mut writer = downlink_writer.lock().await;
                    writer.write_frame(CMD_FIN, stream_id, &[]).await?;
                    return Ok::<(), anyhow::Error>(());
                }
                downlink_session.record_download(read).await?;
                {
                    let mut writer = downlink_writer.lock().await;
                    writer
                        .write_payload_chunks(stream_id, &buffer[..read])
                        .await?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("NodeExpand stream {stream_id} downlink failed: {error:?}");
        }
    });

    let uplink_session = session;
    tokio::spawn(async move {
        let result = async {
            while let Some(payload) = receiver.recv().await {
                uplink_session.record_upload(payload.len()).await?;
                remote_writer
                    .write_all(&payload)
                    .await
                    .context("write target payload")?;
            }
            remote_writer
                .shutdown()
                .await
                .context("shutdown target writer")
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("NodeExpand stream {stream_id} uplink failed: {error:?}");
        }
    });

    Ok((stream_id, sender))
}

async fn open_uot_stream(
    stream_id: u32,
    target: &ProxyTarget,
    initial_payload: &[u8],
    writer: Arc<Mutex<NodeExpandFrameWriter<WriteHalf<TcpStream>>>>,
    session: CoreSession,
) -> Result<(u32, mpsc::Sender<Vec<u8>>)> {
    let (request, initial_packet) = uot::decode_request_for_target(target, initial_payload)?;
    let udp = match &request.destination {
        ProxyTarget::Ip(addr) if addr.is_ipv6() => UdpSocket::bind("[::]:0").await?,
        _ => UdpSocket::bind("0.0.0.0:0").await?,
    };
    if request.is_connect {
        let target = resolve_target_addr(&request.destination).await?;
        udp.connect(target)
            .await
            .with_context(|| format!("connect UDP socket to {target}"))?;
    }
    let udp = Arc::new(udp);
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(32);
    tracing::info!("NodeExpand opened UOT stream {stream_id}");

    if !initial_packet.is_empty() {
        sender
            .send(initial_packet.to_vec())
            .await
            .context("queue initial legacy UOT packet")?;
    }
    {
        let mut writer = writer.lock().await;
        writer.write_frame(CMD_SYNACK, stream_id, &[]).await?;
    }

    let uplink_udp = udp.clone();
    let is_connect = request.is_connect;
    let uplink_session = session.clone();
    tokio::spawn(async move {
        let result = async {
            while let Some(packet) = receiver.recv().await {
                if is_connect {
                    let payload = uot::decode_connect_packet(&packet)?;
                    uplink_session.record_upload(payload.len()).await?;
                    let sent = uplink_udp
                        .send(payload)
                        .await
                        .context("send connected UDP payload")?;
                    if sent != payload.len() {
                        bail!("short UDP send: expected {}, wrote {}", payload.len(), sent);
                    }
                } else {
                    let (target, payload) = uot::decode_associate_packet(&packet)?;
                    let target = resolve_target_addr(&target).await?;
                    uplink_session.record_upload(payload.len()).await?;
                    let sent = uplink_udp
                        .send_to(payload, target)
                        .await
                        .with_context(|| format!("send UDP payload to {target}"))?;
                    if sent != payload.len() {
                        bail!("short UDP send: expected {}, wrote {}", payload.len(), sent);
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("NodeExpand UOT stream {stream_id} uplink failed: {error:?}");
        }
    });

    let downlink_udp = udp.clone();
    let downlink_writer = writer.clone();
    let downlink_session = session;
    tokio::spawn(async move {
        let result: Result<()> = async {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                let (read, source) = if is_connect {
                    let read = downlink_udp
                        .recv(&mut buffer)
                        .await
                        .context("receive connected UDP payload")?;
                    let source = downlink_udp.peer_addr().context("read UDP peer address")?;
                    (read, source)
                } else {
                    downlink_udp
                        .recv_from(&mut buffer)
                        .await
                        .context("receive UDP payload")?
                };
                let packet = if is_connect {
                    uot::encode_connect_packet(&buffer[..read])?
                } else {
                    uot::encode_associate_packet(&ProxyTarget::Ip(source), &buffer[..read])?
                };
                downlink_session.record_download(read).await?;
                {
                    let mut writer = downlink_writer.lock().await;
                    writer.write_payload_chunks(stream_id, &packet).await?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("NodeExpand UOT stream {stream_id} downlink failed: {error:?}");
        }
    });

    Ok((stream_id, sender))
}

struct NodeExpandFrameWriter<W> {
    inner: W,
    cipher: XChaCha20Poly1305,
    length_key: [u8; 32],
    padding: PaddingScheme,
    packet_counter: u32,
    sequence: u64,
    send_padding: bool,
}

impl<W> NodeExpandFrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(inner: W, key: [u8; 32], length_key: [u8; 32], padding: PaddingScheme) -> Result<Self> {
        Ok(Self {
            inner,
            cipher: XChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| anyhow::anyhow!("create NodeExpand record cipher"))?,
            length_key,
            padding,
            packet_counter: 0,
            sequence: 0,
            send_padding: true,
        })
    }

    async fn write_client_settings(&mut self) -> Result<()> {
        let settings = format!(
            "v=4\nclient=aerion/0.1.0\npadding-md5={}",
            self.padding.md5()
        );
        self.write_frame(CMD_SETTINGS, 0, settings.as_bytes()).await
    }

    async fn write_frame(&mut self, cmd: u8, stream_id: u32, payload: &[u8]) -> Result<()> {
        self.write_frame_with_flush(cmd, stream_id, payload, true)
            .await
    }

    async fn write_frame_with_flush(
        &mut self,
        cmd: u8,
        stream_id: u32,
        payload: &[u8],
        flush: bool,
    ) -> Result<()> {
        ensure!(
            payload.len() <= MAX_FRAME_PAYLOAD_LEN,
            "NodeExpand frame payload too large"
        );
        let frame = encode_frame(cmd, stream_id, payload);
        self.write_packet(&frame, flush)
            .await
            .context("write NodeExpand frame")
    }

    async fn write_payload_chunks(&mut self, stream_id: u32, payload: &[u8]) -> Result<()> {
        let chunks = payload.chunks(MAX_FRAME_PAYLOAD_LEN).collect::<Vec<_>>();
        for (index, chunk) in chunks.iter().enumerate() {
            let flush = index + 1 == chunks.len();
            self.write_frame_with_flush(CMD_PSH, stream_id, chunk, flush)
                .await?;
        }
        Ok(())
    }

    fn update_padding_scheme(&mut self, raw: &str) -> Result<()> {
        self.padding = PaddingScheme::from_text(raw).context("parse NodeExpand padding update")?;
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
                    ensure!(
                        size <= MAX_RECORD_PLAINTEXT_LEN,
                        "NodeExpand padding record too large"
                    );
                    if payload.len() > size {
                        self.write_record(&payload[..size], false).await?;
                        payload = &payload[size..];
                    } else if !payload.is_empty() {
                        if size > payload.len() + FRAME_HEADER_LEN {
                            let padding_len = size - payload.len() - FRAME_HEADER_LEN;
                            let padding_frame = encode_frame(CMD_WASTE, 0, &vec![0u8; padding_len]);
                            let mut packet =
                                Vec::with_capacity(payload.len() + padding_frame.len());
                            packet.extend_from_slice(payload);
                            packet.extend_from_slice(&padding_frame);
                            self.write_record(&packet, false).await?;
                        } else {
                            self.write_record(payload, false).await?;
                        }
                        payload = &[];
                    } else {
                        ensure!(
                            size + FRAME_HEADER_LEN <= MAX_RECORD_PLAINTEXT_LEN,
                            "NodeExpand padding frame too large"
                        );
                        let padding_frame = encode_frame(CMD_WASTE, 0, &vec![0u8; size]);
                        self.write_record(&padding_frame, false).await?;
                    }
                }
                if payload.is_empty() {
                    if flush {
                        self.inner
                            .flush()
                            .await
                            .context("flush NodeExpand record")?;
                    }
                    return Ok(());
                }
            } else {
                self.send_padding = false;
            }
        }
        self.write_record(payload, flush).await
    }

    async fn write_record(&mut self, plaintext: &[u8], flush: bool) -> Result<()> {
        ensure!(
            plaintext.len() <= MAX_RECORD_PLAINTEXT_LEN,
            "NodeExpand record plaintext too large"
        );
        let sequence = self.sequence;
        let record_len = plaintext.len() + RECORD_TAG_LEN;
        ensure!(record_len <= MAX_RECORD_LEN, "NodeExpand record too large");
        let record_len = record_len as u16;
        let nonce = record_nonce(sequence);
        let aad = record_aad(sequence, record_len);
        let encrypted = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt NodeExpand record"))?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("NodeExpand send record sequence exhausted")?;
        let masked_len = mask_record_length(&self.length_key, sequence, record_len)?;
        self.inner
            .write_all(&masked_len.to_be_bytes())
            .await
            .context("write NodeExpand record length")?;
        self.inner
            .write_all(&encrypted)
            .await
            .context("write NodeExpand record payload")?;
        if flush {
            self.inner
                .flush()
                .await
                .context("flush NodeExpand record")?;
        }
        Ok(())
    }
}

struct NodeExpandFrameReader<R> {
    inner: R,
    cipher: XChaCha20Poly1305,
    length_key: [u8; 32],
    pending: Vec<u8>,
    sequence: u64,
}

impl<R> NodeExpandFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(inner: R, key: [u8; 32], length_key: [u8; 32]) -> Result<Self> {
        Ok(Self {
            inner,
            cipher: XChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| anyhow::anyhow!("create NodeExpand record cipher"))?,
            length_key,
            pending: Vec::new(),
            sequence: 0,
        })
    }

    async fn read_frame(&mut self) -> Result<Frame> {
        loop {
            if self.pending.len() >= FRAME_HEADER_LEN {
                let payload_len = u16::from_be_bytes([self.pending[5], self.pending[6]]) as usize;
                let frame_len = FRAME_HEADER_LEN + payload_len;
                if self.pending.len() >= frame_len {
                    let header = &self.pending[..FRAME_HEADER_LEN];
                    let payload = self.pending[FRAME_HEADER_LEN..frame_len].to_vec();
                    let frame = Frame {
                        cmd: header[0],
                        stream_id: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
                        payload,
                    };
                    self.pending.drain(..frame_len);
                    return Ok(frame);
                }
            }
            let record = self.read_record().await?;
            self.pending.extend_from_slice(&record);
        }
    }

    async fn read_record(&mut self) -> Result<Vec<u8>> {
        let mut length = [0u8; 2];
        self.inner
            .read_exact(&mut length)
            .await
            .context("read NodeExpand record length")?;
        let sequence = self.sequence;
        let length =
            unmask_record_length(&self.length_key, sequence, u16::from_be_bytes(length))? as usize;
        ensure!(length >= RECORD_TAG_LEN, "NodeExpand record is too short");
        let mut encrypted = vec![0u8; length];
        self.inner
            .read_exact(&mut encrypted)
            .await
            .context("read NodeExpand record")?;
        let nonce = record_nonce(sequence);
        let aad = record_aad(sequence, length as u16);
        let plaintext = self
            .cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &encrypted,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("decrypt NodeExpand record"))?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("NodeExpand receive record sequence exhausted")?;
        Ok(plaintext)
    }
}

struct NodeExpandKeys {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_length_key: [u8; 32],
    recv_length_key: [u8; 32],
}

async fn client_handshake(stream: &mut TcpStream, password: &str) -> Result<NodeExpandKeys> {
    let mut client_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    getrandom::fill(&mut client_nonce).context("generate NodeExpand client nonce")?;
    let client_timestamp = current_unix_secs()?.to_be_bytes();
    let client_secret = generate_x25519_secret()?;
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let client_padding = random_handshake_padding()?;
    let client_padding_len = encode_handshake_padding_len(
        b"client-handshake-len-v4",
        &[&client_nonce, &client_timestamp, &client_public],
        client_padding.len(),
    )?;
    let client_tag = handshake_tag(
        password,
        &[
            b"client-v4",
            &client_nonce,
            &client_timestamp,
            &client_public,
            &client_padding_len,
            &client_padding,
        ],
    )?;
    stream
        .write_all(&client_nonce)
        .await
        .context("write NodeExpand client nonce")?;
    stream
        .write_all(&client_timestamp)
        .await
        .context("write NodeExpand client timestamp")?;
    stream
        .write_all(&client_public)
        .await
        .context("write NodeExpand client X25519 public key")?;
    stream
        .write_all(&client_padding_len)
        .await
        .context("write NodeExpand client padding length")?;
    stream
        .write_all(&client_padding)
        .await
        .context("write NodeExpand client padding")?;
    stream
        .write_all(&client_tag)
        .await
        .context("write NodeExpand client tag")?;
    stream
        .flush()
        .await
        .context("flush NodeExpand client handshake")?;

    let mut server_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    let mut server_public = [0u8; HANDSHAKE_X25519_PUBLIC_KEY_LEN];
    let mut server_padding_len = [0u8; HANDSHAKE_PADDING_LEN_FIELD_LEN];
    let mut server_tag = [0u8; HANDSHAKE_TAG_LEN];
    stream
        .read_exact(&mut server_nonce)
        .await
        .context("read NodeExpand server nonce")?;
    stream
        .read_exact(&mut server_public)
        .await
        .context("read NodeExpand server X25519 public key")?;
    stream
        .read_exact(&mut server_padding_len)
        .await
        .context("read NodeExpand server padding length")?;
    let server_padding_len = decode_handshake_padding_len(
        b"server-handshake-len-v4",
        &[
            &client_nonce,
            &client_timestamp,
            &client_public,
            &server_nonce,
            &server_public,
        ],
        server_padding_len,
    )?;
    let mut server_padding = vec![0u8; server_padding_len];
    stream
        .read_exact(&mut server_padding)
        .await
        .context("read NodeExpand server padding")?;
    stream
        .read_exact(&mut server_tag)
        .await
        .context("read NodeExpand server tag")?;
    let expected = handshake_tag(
        password,
        &[
            b"server-v4",
            &client_nonce,
            &client_timestamp,
            &client_public,
            &server_nonce,
            &server_public,
            &encode_handshake_padding_len(
                b"server-handshake-len-v4",
                &[
                    &client_nonce,
                    &client_timestamp,
                    &client_public,
                    &server_nonce,
                    &server_public,
                ],
                server_padding.len(),
            )?,
            &server_padding,
        ],
    )?;
    ensure!(
        server_tag == expected,
        "NodeExpand server authentication failed"
    );
    derive_keys(
        password,
        &client_nonce,
        &client_timestamp,
        &server_nonce,
        &client_public,
        &server_public,
        &client_secret
            .diffie_hellman(&PublicKey::from(server_public))
            .to_bytes(),
        true,
    )
}

async fn server_handshake(
    stream: &mut TcpStream,
    passwords: &[&str],
    replay_cache: &HandshakeReplayCache,
) -> Result<(String, NodeExpandKeys)> {
    let mut client_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    let mut client_timestamp = [0u8; HANDSHAKE_TIMESTAMP_LEN];
    let mut client_public = [0u8; HANDSHAKE_X25519_PUBLIC_KEY_LEN];
    let mut client_padding_len = [0u8; HANDSHAKE_PADDING_LEN_FIELD_LEN];
    let mut client_tag = [0u8; HANDSHAKE_TAG_LEN];
    stream
        .read_exact(&mut client_nonce)
        .await
        .context("read NodeExpand client nonce")?;
    stream
        .read_exact(&mut client_timestamp)
        .await
        .context("read NodeExpand client timestamp")?;
    stream
        .read_exact(&mut client_public)
        .await
        .context("read NodeExpand client X25519 public key")?;
    stream
        .read_exact(&mut client_padding_len)
        .await
        .context("read NodeExpand client padding length")?;
    let client_padding_len = decode_handshake_padding_len(
        b"client-handshake-len-v4",
        &[&client_nonce, &client_timestamp, &client_public],
        client_padding_len,
    )?;
    let mut client_padding = vec![0u8; client_padding_len];
    stream
        .read_exact(&mut client_padding)
        .await
        .context("read NodeExpand client padding")?;
    stream
        .read_exact(&mut client_tag)
        .await
        .context("read NodeExpand client tag")?;
    let now = current_unix_secs()?;
    let timestamp = u64::from_be_bytes(client_timestamp);
    ensure!(
        now.abs_diff(timestamp) <= HANDSHAKE_REPLAY_WINDOW_SECS,
        "NodeExpand client handshake timestamp is outside replay window"
    );

    let mut credential = None;
    for password in passwords {
        let password = password.trim();
        if password.is_empty() {
            continue;
        }
        let expected = handshake_tag(
            password,
            &[
                b"client-v4",
                &client_nonce,
                &client_timestamp,
                &client_public,
                &encode_handshake_padding_len(
                    b"client-handshake-len-v4",
                    &[&client_nonce, &client_timestamp, &client_public],
                    client_padding.len(),
                )?,
                &client_padding,
            ],
        )?;
        if expected == client_tag {
            credential = Some(password.to_string());
            break;
        }
    }
    let credential = credential.context("NodeExpand authentication failed")?;
    reject_replayed_client_nonce(replay_cache, client_nonce, now).await?;

    let mut server_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    getrandom::fill(&mut server_nonce).context("generate NodeExpand server nonce")?;
    let server_secret = generate_x25519_secret()?;
    let server_public = PublicKey::from(&server_secret).to_bytes();
    let server_padding = random_handshake_padding()?;
    let server_padding_len = encode_handshake_padding_len(
        b"server-handshake-len-v4",
        &[
            &client_nonce,
            &client_timestamp,
            &client_public,
            &server_nonce,
            &server_public,
        ],
        server_padding.len(),
    )?;
    let server_tag = handshake_tag(
        &credential,
        &[
            b"server-v4",
            &client_nonce,
            &client_timestamp,
            &client_public,
            &server_nonce,
            &server_public,
            &server_padding_len,
            &server_padding,
        ],
    )?;
    stream
        .write_all(&server_nonce)
        .await
        .context("write NodeExpand server nonce")?;
    stream
        .write_all(&server_public)
        .await
        .context("write NodeExpand server X25519 public key")?;
    stream
        .write_all(&server_padding_len)
        .await
        .context("write NodeExpand server padding length")?;
    stream
        .write_all(&server_padding)
        .await
        .context("write NodeExpand server padding")?;
    stream
        .write_all(&server_tag)
        .await
        .context("write NodeExpand server tag")?;
    stream
        .flush()
        .await
        .context("flush NodeExpand server handshake")?;

    let keys = derive_keys(
        &credential,
        &client_nonce,
        &client_timestamp,
        &server_nonce,
        &client_public,
        &server_public,
        &server_secret
            .diffie_hellman(&PublicKey::from(client_public))
            .to_bytes(),
        false,
    )?;
    Ok((credential, keys))
}

fn handshake_tag(password: &str, parts: &[&[u8]]) -> Result<[u8; HANDSHAKE_TAG_LEN]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(password.trim().as_bytes())
        .map_err(|_| anyhow::anyhow!("initialize NodeExpand handshake HMAC"))?;
    for part in parts {
        mac.update(part);
    }
    let bytes = mac.finalize().into_bytes();
    let mut tag = [0u8; HANDSHAKE_TAG_LEN];
    tag.copy_from_slice(&bytes);
    Ok(tag)
}

fn derive_keys(
    password: &str,
    client_nonce: &[u8; HANDSHAKE_NONCE_LEN],
    client_timestamp: &[u8; HANDSHAKE_TIMESTAMP_LEN],
    server_nonce: &[u8; HANDSHAKE_NONCE_LEN],
    client_public: &[u8; HANDSHAKE_X25519_PUBLIC_KEY_LEN],
    server_public: &[u8; HANDSHAKE_X25519_PUBLIC_KEY_LEN],
    shared_secret: &[u8; HANDSHAKE_X25519_PUBLIC_KEY_LEN],
    client: bool,
) -> Result<NodeExpandKeys> {
    ensure!(
        shared_secret.iter().any(|value| *value != 0),
        "NodeExpand X25519 shared secret is invalid"
    );
    let mut salt = Vec::with_capacity(
        client_nonce.len()
            + client_timestamp.len()
            + server_nonce.len()
            + client_public.len()
            + server_public.len(),
    );
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(client_timestamp);
    salt.extend_from_slice(server_nonce);
    salt.extend_from_slice(client_public);
    salt.extend_from_slice(server_public);
    let password = password.trim();
    let mut input_key_material = Vec::with_capacity(password.len() + shared_secret.len());
    input_key_material.extend_from_slice(password.as_bytes());
    input_key_material.extend_from_slice(shared_secret);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &input_key_material);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    let mut c2s_len = [0u8; 32];
    let mut s2c_len = [0u8; 32];
    hkdf.expand(b"nodeexpand v4 c2s", &mut c2s)
        .map_err(|_| anyhow::anyhow!("derive NodeExpand client-to-server key"))?;
    hkdf.expand(b"nodeexpand v4 s2c", &mut s2c)
        .map_err(|_| anyhow::anyhow!("derive NodeExpand server-to-client key"))?;
    hkdf.expand(b"nodeexpand v4 c2s length", &mut c2s_len)
        .map_err(|_| anyhow::anyhow!("derive NodeExpand client-to-server length key"))?;
    hkdf.expand(b"nodeexpand v4 s2c length", &mut s2c_len)
        .map_err(|_| anyhow::anyhow!("derive NodeExpand server-to-client length key"))?;
    if client {
        Ok(NodeExpandKeys {
            send_key: c2s,
            recv_key: s2c,
            send_length_key: c2s_len,
            recv_length_key: s2c_len,
        })
    } else {
        Ok(NodeExpandKeys {
            send_key: s2c,
            recv_key: c2s,
            send_length_key: s2c_len,
            recv_length_key: c2s_len,
        })
    }
}

async fn reject_replayed_client_nonce(
    replay_cache: &HandshakeReplayCache,
    client_nonce: [u8; HANDSHAKE_NONCE_LEN],
    now: u64,
) -> Result<()> {
    let oldest = now.saturating_sub(HANDSHAKE_REPLAY_WINDOW_SECS);
    let mut replay_cache = replay_cache.lock().await;
    replay_cache.retain(|_, seen_at| *seen_at >= oldest);
    ensure!(
        !replay_cache.contains_key(&client_nonce),
        "NodeExpand client handshake nonce was replayed"
    );
    replay_cache.insert(client_nonce, now);
    Ok(())
}

fn record_nonce(sequence: u64) -> [u8; RECORD_NONCE_LEN] {
    let mut nonce = [0u8; RECORD_NONCE_LEN];
    nonce[..RECORD_NONCE_PREFIX.len()].copy_from_slice(RECORD_NONCE_PREFIX);
    nonce[RECORD_NONCE_PREFIX.len()..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn record_aad(sequence: u64, record_len: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_AAD_PREFIX.len() + 10);
    aad.extend_from_slice(RECORD_AAD_PREFIX);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&record_len.to_be_bytes());
    aad
}

fn mask_record_length(length_key: &[u8; 32], sequence: u64, record_len: u16) -> Result<u16> {
    Ok(record_len ^ record_length_mask(length_key, sequence)?)
}

fn unmask_record_length(length_key: &[u8; 32], sequence: u64, masked_len: u16) -> Result<u16> {
    Ok(masked_len ^ record_length_mask(length_key, sequence)?)
}

fn record_length_mask(length_key: &[u8; 32], sequence: u64) -> Result<u16> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(length_key)
        .map_err(|_| anyhow::anyhow!("initialize NodeExpand record length HMAC"))?;
    mac.update(RECORD_LENGTH_MASK_PREFIX);
    mac.update(&sequence.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn generate_x25519_secret() -> Result<StaticSecret> {
    let mut private_key = [0u8; 32];
    getrandom::fill(&mut private_key).context("generate NodeExpand X25519 private key")?;
    Ok(StaticSecret::from(private_key))
}

fn random_handshake_padding() -> Result<Vec<u8>> {
    let padding_len = random_usize(HANDSHAKE_MIN_PADDING_LEN, HANDSHAKE_MAX_PADDING_LEN)?;
    let mut padding = vec![0u8; padding_len];
    getrandom::fill(&mut padding).context("generate NodeExpand handshake padding")?;
    Ok(padding)
}

fn encode_handshake_padding_len(
    label: &[u8],
    parts: &[&[u8]],
    padding_len: usize,
) -> Result<[u8; HANDSHAKE_PADDING_LEN_FIELD_LEN]> {
    ensure!(
        (HANDSHAKE_MIN_PADDING_LEN..=HANDSHAKE_MAX_PADDING_LEN).contains(&padding_len),
        "NodeExpand handshake padding length is out of range"
    );
    let mask = handshake_padding_len_mask(label, parts);
    Ok(((padding_len as u16) ^ mask).to_be_bytes())
}

fn decode_handshake_padding_len(
    label: &[u8],
    parts: &[&[u8]],
    encoded: [u8; HANDSHAKE_PADDING_LEN_FIELD_LEN],
) -> Result<usize> {
    let mask = handshake_padding_len_mask(label, parts);
    let padding_len = (u16::from_be_bytes(encoded) ^ mask) as usize;
    ensure!(
        (HANDSHAKE_MIN_PADDING_LEN..=HANDSHAKE_MAX_PADDING_LEN).contains(&padding_len),
        "NodeExpand handshake padding length is out of range"
    );
    Ok(padding_len)
}

fn handshake_padding_len_mask(label: &[u8], parts: &[&[u8]]) -> u16 {
    let mut hasher = Sha256::new();
    hasher.update(b"nodeexpand-handshake-length-v4");
    hasher.update(label);
    for part in parts {
        hasher.update(part);
    }
    let bytes = hasher.finalize();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn jittered_heartbeat_interval(heartbeat_interval_secs: u64) -> Result<Duration> {
    let base_ms = heartbeat_interval_secs
        .checked_mul(1000)
        .context("NodeExpand heartbeat interval is too large")?;
    let percent = HEARTBEAT_JITTER_MIN_PERCENT + random_u64()? % HEARTBEAT_JITTER_SPAN_PERCENT;
    let millis = base_ms
        .checked_mul(percent)
        .context("NodeExpand heartbeat jitter interval is too large")?
        / 100;
    Ok(Duration::from_millis(millis.max(1)))
}

fn random_usize(min: usize, max: usize) -> Result<usize> {
    ensure!(min <= max, "NodeExpand random range is invalid");
    let span = (max - min + 1) as u64;
    Ok(min + (random_u64()? % span) as usize)
}

fn random_u64() -> Result<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).context("generate NodeExpand randomness")?;
    Ok(u64::from_be_bytes(bytes))
}

fn current_unix_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read system time for NodeExpand handshake")?
        .as_secs())
}
