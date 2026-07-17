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
use crate::tls;
use crate::uot;
use crate::utls::UtlsFingerprint;
use anyhow::{Context, Result, bail, ensure};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket, tcp::OwnedWriteHalf};
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
    let tls_config =
        tls::client_config_with_fingerprint_and_custom_root_material_early_data_options(
            config.insecure,
            config.client_fingerprint,
            &config.ca_cert_paths,
            &config.ca_certificates,
            config.disable_system_roots,
            &config.pinned_cert_sha256,
        )?;
    let shared = Arc::new(SharedClientSession::new(config, tls_config, padding));
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

struct SharedClientSession {
    config: ClientConfig,
    tls_config: Arc<rustls::ClientConfig>,
    session: Mutex<Option<ClientSession>>,
    padding: Arc<Mutex<PaddingScheme>>,
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
            session: Mutex::new(None),
            padding: Arc::new(Mutex::new(padding)),
        }
    }

    async fn get_or_connect(&self) -> Result<ClientSession> {
        loop {
            {
                let guard = self.session.lock().await;
                if let Some(session) = guard.as_ref() {
                    if session.is_alive().await {
                        return Ok(session.clone());
                    }
                }
            }
            let mut guard = self.session.lock().await;
            if let Some(session) = guard.as_ref() {
                if session.is_alive().await {
                    return Ok(session.clone());
                }
                guard.take();
            }
            let padding = self.padding.lock().await.clone();
            let session = ClientSession::connect(
                &self.config,
                self.tls_config.clone(),
                padding,
                self.padding.clone(),
            )
            .await?;
            guard.replace(session.clone());
            return Ok(session);
        }
    }
}

#[derive(Clone)]
struct ClientSession {
    writer: Arc<Mutex<PaddedFrameWriter<WriteHalf<TlsStream<TcpStream>>>>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    next_stream_id: Arc<AtomicU32>,
    closed: Arc<Mutex<Option<String>>>,
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
}

impl ClientSession {
    async fn is_alive(&self) -> bool {
        self.closed.lock().await.is_none()
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
        let _ = tcp.set_nodelay(true);
        let connector = TlsConnector::from(tls_config).early_data(true);
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
        };
        tokio::spawn(read_session_frames(
            reader,
            session.writer.clone(),
            session.streams.clone(),
            session.closed.clone(),
            shared_padding,
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
        {
            let mut writer = self.writer.lock().await;
            writer.write_frame(CMD_SYN, stream_id, &[]).await?;
            writer
                .write_payload_chunks(stream_id, &first_payload)
                .await?;
        }

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
                StreamEvent::Payload(_) => {}
            }
        }
    }
}

impl ClientStream {
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
            tracing::info!("proxying {}", target_name(&target));
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
    mut stream: ClientStream,
    session: crate::core::CoreSession,
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
    stream: &mut ClientStream,
    mut local_writer: OwnedWriteHalf,
    session: crate::core::CoreSession,
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

async fn read_session_frames(
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    writer: Arc<Mutex<PaddedFrameWriter<WriteHalf<TlsStream<TcpStream>>>>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    closed: Arc<Mutex<Option<String>>>,
    shared_padding: Arc<Mutex<PaddingScheme>>,
) {
    let result: Result<()> = async {
        loop {
            let frame = read_frame(&mut reader).await?;
            handle_session_frame(frame, &writer, &streams, &shared_padding).await?;
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

async fn handle_session_frame(
    frame: Frame,
    writer: &Arc<Mutex<PaddedFrameWriter<WriteHalf<TlsStream<TcpStream>>>>>,
    streams: &Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    shared_padding: &Arc<Mutex<PaddingScheme>>,
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
    writer: Arc<Mutex<PaddedFrameWriter<WriteHalf<TlsStream<TcpStream>>>>>,
    closed: Arc<Mutex<Option<String>>>,
    heartbeat_interval_secs: u64,
) {
    let mut ticker = interval(Duration::from_secs(heartbeat_interval_secs));
    loop {
        ticker.tick().await;
        if closed.lock().await.is_some() {
            return;
        }
        if let Err(error) = writer
            .lock()
            .await
            .write_frame(CMD_HEART_REQUEST, 0, &[])
            .await
        {
            *closed.lock().await = Some(format!("write heartbeat: {error:?}"));
            return;
        }
    }
}
