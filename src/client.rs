use crate::core::{CoreSession, ProxyCore};
use crate::listener;
use crate::padding::PaddingScheme;
use crate::protocol::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, Frame,
    PaddedFrameWriter, ProxyTarget, encode_target, read_frame, target_name,
};
use crate::socket_protect;
use crate::socks::{self, SocksRequest};
use crate::task_abort::TaskAbort;
use crate::tls;
use crate::uot;
use crate::utls::UtlsFingerprint;
use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::ServerName;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, interval};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub password: String,
    pub sni: String,
    pub insecure: bool,
    pub client_fingerprint: Option<UtlsFingerprint>,
    pub ca_cert_paths: Vec<PathBuf>,
    pub ca_certificates: Vec<String>,
    pub disable_system_roots: bool,
    pub pinned_cert_sha256: Vec<String>,
    pub padding_scheme: Vec<String>,
    pub heartbeat_interval_secs: u64,
}

pub async fn run_client(config: ClientConfig) -> Result<()> {
    run_client_with_core(config, None).await
}

pub async fn run_client_with_core(config: ClientConfig, core: Option<ProxyCore>) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind local SOCKS listener on {}", config.listen))?;
    run_client_listener(listener, config, core).await
}

pub async fn run_client_listener(
    listener: TcpListener,
    config: ClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    ensure!(
        config.heartbeat_interval_secs > 0,
        "AnyTLS heartbeat interval must be positive"
    );
    let padding = PaddingScheme::from_lines(config.padding_scheme.clone())?;
    let tls_config = tls::client_config_with_fingerprint_and_custom_root_material_options(
        config.insecure,
        config.client_fingerprint,
        &config.ca_cert_paths,
        &config.ca_certificates,
        config.disable_system_roots,
        &config.pinned_cert_sha256,
    )?;
    let shared = Arc::new(SharedClientSession::new(config, tls_config, padding));
    tokio::spawn(sweep_idle_client_sessions(shared.clone()));
    tracing::info!("client listening on socks5://{}", listener.local_addr()?);
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
                tracing::warn!("SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

const MAX_IDLE_SESSIONS: usize = 16;
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

struct SharedClientSession {
    config: ClientConfig,
    tls_config: Arc<rustls::ClientConfig>,
    padding: Arc<Mutex<PaddingScheme>>,
    idle: Mutex<VecDeque<(ClientSession, Instant)>>,
}

impl SharedClientSession {
    fn new(
        config: ClientConfig,
        tls_config: Arc<rustls::ClientConfig>,
        padding: PaddingScheme,
    ) -> Self {
        Self {
            config,
            tls_config,
            padding: Arc::new(Mutex::new(padding)),
            idle: Mutex::new(VecDeque::new()),
        }
    }

    async fn acquire(&self) -> Result<ClientSession> {
        let mut to_close = Vec::new();
        let reused = {
            let mut idle = self.idle.lock().await;
            to_close.extend(take_expired_idle_sessions(&mut idle));
            let mut found = None;
            while let Some((session, _)) = idle.pop_front() {
                if session.is_alive() {
                    found = Some(session);
                    break;
                }
                to_close.push(session);
            }
            found
        };
        close_idle_sessions(to_close, "idle timeout").await;
        if let Some(session) = reused {
            return Ok(session);
        }
        let padding = self.padding.lock().await.clone();
        ClientSession::connect(
            &self.config,
            self.tls_config.clone(),
            padding,
            self.padding.clone(),
        )
        .await
    }

    async fn release(&self, session: ClientSession) {
        if !session.is_alive() {
            return;
        }
        let overflow;
        let expired;
        {
            let mut idle = self.idle.lock().await;
            expired = take_expired_idle_sessions(&mut idle);
            if idle.len() < MAX_IDLE_SESSIONS {
                idle.push_back((session, Instant::now()));
                overflow = None;
            } else {
                overflow = Some(session);
            }
        }
        close_idle_sessions(expired, "idle timeout").await;
        if let Some(session) = overflow {
            session.close("idle pool full").await;
        }
    }
}

fn take_expired_idle_sessions(idle: &mut VecDeque<(ClientSession, Instant)>) -> Vec<ClientSession> {
    let now = Instant::now();
    let mut keep = VecDeque::new();
    let mut expired = Vec::new();
    while let Some((session, since)) = idle.pop_front() {
        if now.duration_since(since) < IDLE_SESSION_TIMEOUT {
            keep.push_back((session, since));
        } else {
            expired.push(session);
        }
    }
    *idle = keep;
    expired
}

async fn close_idle_sessions(sessions: Vec<ClientSession>, reason: &str) {
    for session in sessions {
        session.close(reason).await;
    }
}

async fn sweep_idle_client_sessions(shared: Arc<SharedClientSession>) {
    let mut ticker = interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        let expired = {
            let mut idle = shared.idle.lock().await;
            take_expired_idle_sessions(&mut idle)
        };
        close_idle_sessions(expired, "idle timeout").await;
    }
}

#[derive(Clone)]
struct ClientSession {
    writer: Arc<Mutex<PaddedFrameWriter<WriteHalf<TlsStream<TcpStream>>>>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    next_stream_id: Arc<AtomicU32>,
    closed: Arc<Mutex<Option<String>>>,
    abort: Arc<TaskAbort>,
    first_packet: Arc<AtomicBool>,
    server_v2: Arc<AtomicBool>,
}

enum StreamEvent {
    SynAck(Vec<u8>),
    Payload(Vec<u8>),
    Fin,
    Error(String),
}

struct ClientStream {
    stream_id: u32,
    writer: Arc<Mutex<PaddedFrameWriter<WriteHalf<TlsStream<TcpStream>>>>>,
    events: mpsc::Receiver<StreamEvent>,
    pending: Option<Vec<u8>>,
}

impl ClientSession {
    fn is_alive(&self) -> bool {
        !self.abort.is_triggered()
    }

    async fn close(&self, reason: &str) {
        let already = {
            let mut closed = self.closed.lock().await;
            if closed.is_some() {
                true
            } else {
                *closed = Some(reason.to_string());
                false
            }
        };
        self.abort.trigger();
        if already {
            return;
        }
        let _ = self.writer.lock().await.shutdown().await;
        self.fail_open_streams(reason).await;
    }

    async fn fail_open_streams(&self, reason: &str) {
        let senders = {
            let mut streams = self.streams.lock().await;
            streams
                .drain()
                .map(|(_, sender)| sender)
                .collect::<Vec<_>>()
        };
        for sender in senders {
            let _ = sender.send(StreamEvent::Error(reason.to_string())).await;
        }
    }

    async fn connect(
        config: &ClientConfig,
        tls_config: Arc<rustls::ClientConfig>,
        padding: PaddingScheme,
        shared_padding: Arc<Mutex<PaddingScheme>>,
    ) -> Result<Self> {
        let tcp =
            socket_protect::connect_tcp_host_port(config.server_host.as_str(), config.server_port)
                .await
                .with_context(|| {
                    format!(
                        "connect Aerion server {}:{}",
                        config.server_host, config.server_port
                    )
                })?;
        let connector = TlsConnector::from(tls_config);
        let server_name = ServerName::try_from(config.sni.clone())
            .with_context(|| format!("invalid SNI: {}", config.sni))?;
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .context("TLS connect to Aerion server")?;
        let (reader, writer) = split(tls_stream);
        let mut writer = PaddedFrameWriter::new(writer, padding);
        writer.write_auth_preface(&config.password).await?;
        writer.write_client_settings().await?;

        let session = Self {
            writer: Arc::new(Mutex::new(writer)),
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: Arc::new(AtomicU32::new(1)),
            closed: Arc::new(Mutex::new(None)),
            abort: Arc::new(TaskAbort::new()),
            first_packet: Arc::new(AtomicBool::new(true)),
            server_v2: Arc::new(AtomicBool::new(false)),
        };
        tokio::spawn(read_session_frames(reader, session.clone(), shared_padding));
        tokio::spawn(run_heartbeat(
            session.clone(),
            config.heartbeat_interval_secs,
        ));
        Ok(session)
    }

    async fn open_stream(
        &self,
        target: ProxyTarget,
        initial_payload: Vec<u8>,
    ) -> Result<ClientStream> {
        if let Some(error) = self.closed.lock().await.clone() {
            bail!("Aerion client session is closed: {error}");
        }
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);
        if stream_id == 0 {
            bail!("Aerion stream id exhausted");
        }
        let (events_tx, mut events_rx) = mpsc::channel(32);
        self.streams.lock().await.insert(stream_id, events_tx);

        let mut first_payload = encode_target(&target)?;
        first_payload.extend_from_slice(&initial_payload);
        let first = self.first_packet.swap(false, Ordering::SeqCst);
        {
            let mut writer = self.writer.lock().await;
            writer
                .write_frame_with_flush(CMD_SYN, stream_id, &[], !first)
                .await?;
            writer
                .write_payload_chunks(stream_id, &first_payload)
                .await?;
        }

        let mut pending_payload = None;
        loop {
            let event = events_rx
                .recv()
                .await
                .context("Aerion stream closed before SYNACK")?;
            match event {
                StreamEvent::SynAck(payload) if payload.is_empty() => {
                    return Ok(ClientStream {
                        stream_id,
                        writer: self.writer.clone(),
                        events: events_rx,
                        pending: pending_payload,
                    });
                }
                StreamEvent::SynAck(payload) => {
                    self.streams.lock().await.remove(&stream_id);
                    bail!("stream open failed: {}", String::from_utf8_lossy(&payload));
                }
                StreamEvent::Error(error) => {
                    self.streams.lock().await.remove(&stream_id);
                    bail!("{error}");
                }
                StreamEvent::Fin => {
                    self.streams.lock().await.remove(&stream_id);
                    bail!("stream closed before SYNACK");
                }
                StreamEvent::Payload(payload) => {
                    if self.server_v2.load(Ordering::SeqCst) {
                        pending_payload = Some(payload);
                        continue;
                    }
                    return Ok(ClientStream {
                        stream_id,
                        writer: self.writer.clone(),
                        events: events_rx,
                        pending: Some(payload),
                    });
                }
            }
        }
    }
}

impl ClientStream {
    async fn read_payload(&mut self) -> Result<Option<Vec<u8>>> {
        if let Some(payload) = self.pending.take() {
            return Ok(Some(payload));
        }
        loop {
            let Some(event) = self.events.recv().await else {
                return Ok(None);
            };
            match event {
                StreamEvent::Payload(payload) => return Ok(Some(payload)),
                StreamEvent::Fin => return Ok(None),
                StreamEvent::Error(error) => bail!("{error}"),
                StreamEvent::SynAck(payload) if !payload.is_empty() => {
                    bail!("stream error: {}", String::from_utf8_lossy(&payload));
                }
                StreamEvent::SynAck(_) => {}
            }
        }
    }
}

async fn handle_socks_client(
    mut local: TcpStream,
    shared: Arc<SharedClientSession>,
    config: ClientConfig,
    core: Option<ProxyCore>,
    peer: SocketAddr,
) -> Result<()> {
    match socks::read_request(&mut local).await? {
        SocksRequest::Connect(target) => {
            let session = match shared.acquire().await {
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
                    shared.release(session).await;
                    return Err(error);
                }
            };
            let core_session = if let Some(core) = core.as_ref() {
                core.authenticate_from(&config.password, peer).await?
            } else {
                CoreSession::disabled()
            };
            socks::write_reply(&mut local, 0x00).await?;
            tracing::info!("proxying {}", target_name(&target));
            let result = relay_tcp_counted(local, stream, core_session).await;
            shared.release(session).await;
            result
        }
        SocksRequest::UdpAssociate => {
            let session = match shared.acquire().await {
                Ok(session) => session,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(error);
                }
            };
            let result =
                handle_udp_associate_counted(local, session.clone(), config, core, peer).await;
            shared.release(session).await;
            result
        }
    }
}

async fn relay_tcp_counted(
    local: TcpStream,
    mut stream: ClientStream,
    session: crate::core::CoreSession,
) -> Result<()> {
    let stream_id = stream.stream_id;
    let writer = stream.writer.clone();
    let (mut local_reader, mut local_writer) = local.into_split();
    let uplink_session = session.clone();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read local payload")?;
            if read == 0 {
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
    let downlink = async {
        while let Some(payload) = stream.read_payload().await? {
            session.record_download(payload.len()).await?;
            local_writer
                .write_all(&payload)
                .await
                .context("write local payload")?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::select! {
        result = uplink => result,
        result = downlink => result,
    };
    {
        let mut writer = writer.lock().await;
        let _ = writer.write_frame(CMD_FIN, stream_id, &[]).await;
    }
    let _ = local_writer.shutdown().await;
    result
}

async fn handle_udp_associate_counted(
    mut control: TcpStream,
    session: ClientSession,
    config: ClientConfig,
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
    let stream_id = stream.stream_id;
    let writer = stream.writer.clone();
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

    let result = tokio::select! {
        result = udp_to_stream => result,
        result = stream_to_udp => result,
        result = control_closed => result,
    };
    {
        let mut writer = writer.lock().await;
        let _ = writer.write_frame(CMD_FIN, stream_id, &[]).await;
    }
    result
}

async fn read_session_frames(
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    session: ClientSession,
    shared_padding: Arc<Mutex<PaddingScheme>>,
) {
    let result: Result<()> = async {
        loop {
            tokio::select! {
                _ = session.abort.cancelled() => return Ok(()),
                frame = read_frame(&mut reader) => {
                    handle_session_frame(
                        frame?,
                        &session.writer,
                        &session.streams,
                        &shared_padding,
                        &session.server_v2,
                    )
                    .await?;
                }
            }
        }
    }
    .await;
    if let Err(error) = result {
        session.close(&format!("{error:?}")).await;
    }
}

async fn handle_session_frame(
    frame: Frame,
    writer: &Arc<Mutex<PaddedFrameWriter<WriteHalf<TlsStream<TcpStream>>>>>,
    streams: &Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    shared_padding: &Arc<Mutex<PaddingScheme>>,
    server_v2: &Arc<AtomicBool>,
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
        CMD_ALERT => bail!("server alert: {}", String::from_utf8_lossy(&frame.payload)),
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
            let padding =
                PaddingScheme::from_text(raw).context("parse server padding scheme update")?;
            writer.lock().await.update_padding_scheme(raw)?;
            *shared_padding.lock().await = padding;
        }
        CMD_SERVER_SETTINGS => {
            server_v2.store(true, Ordering::SeqCst);
        }
        CMD_WASTE | CMD_SETTINGS | CMD_HEART_RESPONSE => {}
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

async fn run_heartbeat(session: ClientSession, heartbeat_interval_secs: u64) {
    let mut ticker = interval(Duration::from_secs(heartbeat_interval_secs));
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = session.abort.cancelled() => return,
            _ = ticker.tick() => {}
        }
        if let Err(error) = session
            .writer
            .lock()
            .await
            .write_frame(CMD_HEART_REQUEST, 0, &[])
            .await
        {
            session.close(&format!("write heartbeat: {error:?}")).await;
            return;
        }
    }
}
