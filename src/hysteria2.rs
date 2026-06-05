use crate::core::{CoreSession, CoreUserLimits, ProxyCore};
use crate::listener;
use crate::protocol::{ProxyTarget, resolve_target_addr, target_name};
use crate::{socket_protect, socks, tls, uot};
use anyhow::{Context, Result, bail, ensure};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, IdleTimeout, UdpPoller, VarInt};
use rustls::RootCertStore;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll, ready};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, tcp::OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

const H3_ALPN: &[u8] = b"h3";
const AUTH_URI: &str = "https://hysteria/auth";
const AUTH_PATH: &str = "/auth";
const AUTH_HOST: &str = "hysteria";
const HY2_TCP_REQUEST_ID: u64 = 0x401;
const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HY2_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const HY2_CONN_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
const HY2_MAX_INCOMING_STREAMS: u32 = 1024;
const HY2_DATAGRAM_BUFFER_SIZE: usize = 8 * 1024 * 1024;
const MAX_ADDRESS_LEN: u64 = 2048;
const MAX_PADDING_LEN: u64 = 4096;
const UDP_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(30);
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SALAMANDER_SALT_LEN: usize = 8;
const SALAMANDER_KEY_LEN: usize = 32;
const SALAMANDER_MIN_PASSWORD_LEN: usize = 4;

#[derive(Clone, Debug)]
pub struct Hysteria2ClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub password: String,
    pub sni: String,
    pub insecure: bool,
    pub certificate_fingerprint: Option<String>,
    pub ca_cert_paths: Vec<PathBuf>,
    pub ca_certificates: Vec<String>,
    pub disable_system_roots: bool,
    pub pinned_cert_sha256: Vec<String>,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub upload_bandwidth: Option<u64>,
    pub download_bandwidth: Option<u64>,
    pub udp: bool,
    pub congestion_control: String,
}

#[derive(Clone, Debug)]
pub struct Hysteria2ServerConfig {
    pub listen: SocketAddr,
    pub password: String,
    pub users: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub certificates: Vec<String>,
    pub key: Option<String>,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub upload_bandwidth: Option<u64>,
    pub udp: bool,
    pub cc_rx: String,
    pub congestion_control: String,
}

#[derive(Clone)]
pub struct Hysteria2Client {
    inner: Arc<Hysteria2ClientInner>,
}

struct Hysteria2ClientInner {
    endpoint: Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    h3_sender: Mutex<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    udp_enabled: bool,
    upload_limiter: Hy2ByteRateLimiter,
    udp_sessions: Mutex<HashMap<u32, mpsc::Sender<UdpMessage>>>,
    udp_fragments: Mutex<HashMap<(u32, u16), UdpFragmentBuffer>>,
    next_udp_session_id: AtomicU32,
    next_udp_packet_id: AtomicU16,
}

pub struct Hysteria2TcpStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    client: Hysteria2Client,
}

pub struct Hysteria2UdpSession {
    client: Hysteria2Client,
    session_id: u32,
    incoming: mpsc::Receiver<UdpMessage>,
}

#[derive(Debug)]
struct Hy2ByteRateLimiter {
    bytes_per_second: Option<u64>,
    next: StdMutex<Instant>,
}

impl Hy2ByteRateLimiter {
    fn new(mbps: Option<u64>) -> Self {
        Self {
            bytes_per_second: mbps.map(|mbps| mbps.saturating_mul(125_000)),
            next: StdMutex::new(Instant::now()),
        }
    }

    async fn wait(&self, bytes: usize) {
        let Some(bytes_per_second) = self.bytes_per_second.filter(|rate| *rate > 0) else {
            return;
        };
        let delay = {
            let mut next = self.next.lock().expect("HY2 upload limiter poisoned");
            let now = Instant::now();
            let start = if *next > now { *next } else { now };
            let duration = Duration::from_secs_f64(bytes as f64 / bytes_per_second as f64);
            *next = start + duration;
            start.saturating_duration_since(now)
        };
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UdpMessage {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: String,
    payload: Vec<u8>,
}

struct UdpFragmentBuffer {
    address: String,
    created_at: Instant,
    fragments: Vec<Option<Vec<u8>>>,
}

type ServerUdpSessions = Arc<Mutex<HashMap<u32, Arc<ServerUdpSession>>>>;
type ServerUdpFragments = Arc<Mutex<HashMap<(u32, u16), UdpFragmentBuffer>>>;

struct ServerUdpSession {
    socket: Arc<UdpSocket>,
    core: CoreSession,
    last_seen: StdMutex<Instant>,
    response_handle: StdMutex<JoinHandle<()>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SalamanderConfig {
    password: Vec<u8>,
}

#[derive(Debug)]
struct SalamanderUdpSocket {
    io: UdpSocket,
    password: Vec<u8>,
    recv_buffer: StdMutex<Vec<u8>>,
}

type IoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

struct SalamanderUdpPoller {
    socket: Arc<SalamanderUdpSocket>,
    future: Option<IoFuture>,
}

impl Drop for Hysteria2ClientInner {
    fn drop(&mut self) {
        let _ = &self.endpoint;
        let _ = &self.h3_sender;
        self.connection.close(VarInt::from_u32(0), b"client closed");
        self.h3_driver.abort();
    }
}

impl Drop for ServerUdpSession {
    fn drop(&mut self) {
        self.response_handle
            .lock()
            .expect("HY2 UDP response handle poisoned")
            .abort();
    }
}

impl SalamanderConfig {
    fn new(password: &str) -> Result<Self> {
        ensure!(
            password.len() >= SALAMANDER_MIN_PASSWORD_LEN,
            "Hysteria2 salamander obfs password must be at least {SALAMANDER_MIN_PASSWORD_LEN} bytes"
        );
        Ok(Self {
            password: password.as_bytes().to_vec(),
        })
    }
}

impl SalamanderUdpSocket {
    fn new(socket: std::net::UdpSocket, config: SalamanderConfig) -> io::Result<Self> {
        Ok(Self {
            io: UdpSocket::from_std(socket)?,
            password: config.password,
            recv_buffer: StdMutex::new(Vec::new()),
        })
    }
}

impl AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SalamanderUdpPoller {
            socket: self,
            future: None,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut salt = [0u8; SALAMANDER_SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|error| io::Error::other(format!("generate HY2 salamander salt: {error}")))?;
        let mut packet = vec![0u8; SALAMANDER_SALT_LEN + transmit.contents.len()];
        packet[..SALAMANDER_SALT_LEN].copy_from_slice(&salt);
        salamander_xor(
            &self.password,
            &salt,
            transmit.contents,
            &mut packet[SALAMANDER_SALT_LEN..],
        );
        let written = self.io.try_send_to(&packet, transmit.destination)?;
        if written == packet.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write full HY2 salamander packet",
            ))
        }
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let mut buffer = self
                .recv_buffer
                .lock()
                .expect("HY2 salamander recv buffer poisoned");
            buffer.resize(bufs[0].len() + SALAMANDER_SALT_LEN, 0);
            match self.io.try_recv_from(&mut buffer) {
                Ok((read, addr)) => {
                    if read <= SALAMANDER_SALT_LEN {
                        continue;
                    }
                    let mut salt = [0u8; SALAMANDER_SALT_LEN];
                    salt.copy_from_slice(&buffer[..SALAMANDER_SALT_LEN]);
                    let output_len = read - SALAMANDER_SALT_LEN;
                    salamander_xor(
                        &self.password,
                        &salt,
                        &buffer[SALAMANDER_SALT_LEN..read],
                        &mut bufs[0][..output_len],
                    );
                    meta[0] = RecvMeta {
                        addr,
                        len: output_len,
                        stride: output_len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

impl fmt::Debug for SalamanderUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderUdpPoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for SalamanderUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.future.is_none() {
            let socket = this.socket.clone();
            this.future = Some(Box::pin(async move { socket.io.writable().await }));
        }
        let result = this
            .future
            .as_mut()
            .expect("HY2 writable future set")
            .as_mut()
            .poll(cx);
        if result.is_ready() {
            this.future = None;
        }
        result
    }
}

impl Hysteria2Client {
    pub async fn connect(config: Hysteria2ClientConfig) -> Result<Self> {
        let remote_addr = resolve_host_addr(&config.server_host, config.server_port).await?;
        let endpoint = build_client_endpoint(&config, remote_addr.is_ipv6())?;
        let connection = endpoint
            .connect(remote_addr, &config.sni)
            .with_context(|| format!("connect Hysteria2 server {remote_addr}"))?
            .await
            .context("complete Hysteria2 QUIC handshake")?;
        let (mut h3_driver, mut h3_sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .context("initialize Hysteria2 HTTP/3 client")?;
        let h3_driver = tokio::spawn(async move {
            let error = h3_driver.wait_idle().await;
            tracing::debug!(?error, "Hysteria2 HTTP/3 client driver exited");
        });
        let udp_enabled = authenticate_client(&mut h3_sender, &config).await?;
        let client = Self {
            inner: Arc::new(Hysteria2ClientInner {
                endpoint,
                connection,
                h3_driver,
                h3_sender: Mutex::new(h3_sender),
                udp_enabled: udp_enabled && config.udp,
                upload_limiter: Hy2ByteRateLimiter::new(config.upload_bandwidth),
                udp_sessions: Mutex::new(HashMap::new()),
                udp_fragments: Mutex::new(HashMap::new()),
                next_udp_session_id: AtomicU32::new(1),
                next_udp_packet_id: AtomicU16::new(1),
            }),
        };
        let datagram_client = client.clone();
        tokio::spawn(async move { datagram_client.dispatch_datagrams().await });
        Ok(client)
    }

    fn is_alive(&self) -> bool {
        self.inner.connection.close_reason().is_none()
    }

    pub async fn open_tcp(&self, target: ProxyTarget) -> Result<Hysteria2TcpStream> {
        let address = target_name(&target);
        let (mut send, mut recv) = self
            .inner
            .connection
            .open_bi()
            .await
            .with_context(|| format!("open Hysteria2 TCP stream to {address}"))?;
        let mut request = Vec::new();
        encode_varint(HY2_TCP_REQUEST_ID, &mut request)?;
        encode_varint(address.len() as u64, &mut request)?;
        request.extend_from_slice(address.as_bytes());
        encode_varint(0, &mut request)?;
        self.wait_upload(request.len()).await;
        send.write_all(&request)
            .await
            .context("write Hysteria2 TCP request")?;
        read_tcp_response(&mut recv)
            .await
            .with_context(|| format!("open Hysteria2 destination {address}"))?;
        Ok(Hysteria2TcpStream {
            send,
            recv,
            client: self.clone(),
        })
    }

    pub async fn open_udp_session(&self) -> Result<Hysteria2UdpSession> {
        ensure!(
            self.udp_enabled(),
            "Hysteria2 server did not enable UDP relay"
        );
        let session_id = self.next_udp_session_id();
        let incoming = self.register_udp_session(session_id).await;
        Ok(Hysteria2UdpSession {
            client: self.clone(),
            session_id,
            incoming,
        })
    }

    fn udp_enabled(&self) -> bool {
        self.inner.udp_enabled
    }

    fn next_udp_session_id(&self) -> u32 {
        loop {
            let id = self
                .inner
                .next_udp_session_id
                .fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    async fn register_udp_session(&self, session_id: u32) -> mpsc::Receiver<UdpMessage> {
        let (tx, rx) = mpsc::channel(128);
        self.inner.udp_sessions.lock().await.insert(session_id, tx);
        rx
    }

    async fn unregister_udp_session(&self, session_id: u32) {
        self.inner.udp_sessions.lock().await.remove(&session_id);
    }

    async fn wait_upload(&self, bytes: usize) {
        self.inner.upload_limiter.wait(bytes).await;
    }

    async fn send_udp(&self, session_id: u32, target: &ProxyTarget, payload: &[u8]) -> Result<()> {
        self.wait_upload(payload.len()).await;
        let packet_id = self
            .inner
            .next_udp_packet_id
            .fetch_add(1, Ordering::Relaxed);
        for message in encode_udp_messages(
            session_id,
            packet_id,
            target_name(target),
            payload,
            self.inner.connection.max_datagram_size(),
        )? {
            self.inner
                .connection
                .send_datagram(Bytes::from(encode_udp_message(&message)?))
                .context("send Hysteria2 UDP datagram")?;
        }
        Ok(())
    }

    async fn dispatch_datagrams(self) {
        loop {
            let datagram = match self.inner.connection.read_datagram().await {
                Ok(datagram) => datagram,
                Err(error) => {
                    debug_connection_closed_as_udp_end(error);
                    return;
                }
            };
            let message = match decode_udp_message(&datagram) {
                Ok(message) => message,
                Err(error) => {
                    tracing::warn!(?error, "invalid Hysteria2 UDP datagram");
                    continue;
                }
            };
            let message = match reassemble_udp_message(message, &self.inner.udp_fragments).await {
                Ok(Some(message)) => message,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(?error, "invalid Hysteria2 UDP fragment");
                    continue;
                }
            };
            let sender = self
                .inner
                .udp_sessions
                .lock()
                .await
                .get(&message.session_id)
                .cloned();
            if let Some(sender) = sender {
                let _ = sender.send(message).await;
            }
        }
    }
}

impl Hysteria2TcpStream {
    pub async fn read_payload(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buffer = vec![0u8; 32 * 1024];
        let Some(read) = self
            .recv
            .read(&mut buffer)
            .await
            .context("read Hysteria2 TCP payload")?
        else {
            return Ok(None);
        };
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        Ok(Some(buffer))
    }

    pub async fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        self.client.wait_upload(payload.len()).await;
        self.send
            .write_all(payload)
            .await
            .context("write Hysteria2 TCP payload")
    }

    pub fn finish(&mut self) -> Result<()> {
        self.send.finish().context("finish Hysteria2 send stream")
    }

    pub fn into_parts(self) -> (quinn::SendStream, quinn::RecvStream) {
        let Hysteria2TcpStream { send, recv, .. } = self;
        (send, recv)
    }
}

impl Hysteria2UdpSession {
    pub async fn send_to(&self, target: &ProxyTarget, payload: &[u8]) -> Result<()> {
        self.client.send_udp(self.session_id, target, payload).await
    }

    pub async fn recv_from(&mut self) -> Result<Option<(ProxyTarget, Vec<u8>)>> {
        let Some(message) = self.incoming.recv().await else {
            return Ok(None);
        };
        Ok(Some((parse_host_port(&message.address)?, message.payload)))
    }

    pub async fn close(mut self) {
        let session_id = std::mem::take(&mut self.session_id);
        if session_id != 0 {
            self.client.unregister_udp_session(session_id).await;
        }
    }
}

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        if self.session_id == 0 {
            return;
        }
        let client = self.client.clone();
        let session_id = self.session_id;
        tokio::spawn(async move {
            client.unregister_udp_session(session_id).await;
        });
    }
}

pub async fn run_hysteria2_client(config: Hysteria2ClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind local Hysteria2 SOCKS listener on {}", config.listen))?;
    run_hysteria2_client_listener(listener, config).await
}

pub async fn run_hysteria2_client_listener(
    listener: TcpListener,
    config: Hysteria2ClientConfig,
) -> Result<()> {
    let shared = Arc::new(SharedHysteria2Client::new(config));
    tracing::info!(
        "Hysteria2 client listening on socks5://{}",
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
        tokio::spawn(async move {
            if let Err(error) = handle_hy2_socks_client(stream, shared).await {
                tracing::warn!("Hysteria2 SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

struct SharedHysteria2Client {
    config: Hysteria2ClientConfig,
    client: Mutex<Option<Hysteria2Client>>,
}

impl SharedHysteria2Client {
    fn new(config: Hysteria2ClientConfig) -> Self {
        Self {
            config,
            client: Mutex::new(None),
        }
    }

    async fn get_or_connect(&self) -> Result<Hysteria2Client> {
        loop {
            {
                let guard = self.client.lock().await;
                if let Some(client) = guard.as_ref() {
                    if client.is_alive() {
                        return Ok(client.clone());
                    }
                }
            }
            let mut guard = self.client.lock().await;
            if let Some(client) = guard.as_ref() {
                if client.is_alive() {
                    return Ok(client.clone());
                }
                guard.take();
            }
            let client = Hysteria2Client::connect(self.config.clone()).await?;
            guard.replace(client.clone());
            return Ok(client);
        }
    }
}

pub async fn run_hysteria2_server(config: Hysteria2ServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials_with_limits(
        &config.password,
        &config.users,
        CoreUserLimits {
            upload_limit_bps: config
                .upload_bandwidth
                .map(|mbps| mbps.saturating_mul(125_000)),
            ..CoreUserLimits::default()
        },
    );
    run_hysteria2_server_with_core(config, core).await
}

pub async fn run_hysteria2_server_with_core(
    config: Hysteria2ServerConfig,
    core: ProxyCore,
) -> Result<()> {
    let endpoint = build_server_endpoint(&config)?;
    tracing::info!("Hysteria2 server listening on {}", endpoint.local_addr()?);
    while let Some(incoming) = endpoint.accept().await {
        let passwords = auth_passwords(&config.password, &config.users);
        let cc_rx = config.cc_rx.clone();
        let udp = config.udp;
        let core = core.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(error) =
                        handle_hy2_connection(connection, passwords, cc_rx, udp, core).await
                    {
                        tracing::warn!("Hysteria2 connection failed: {error:?}");
                    }
                }
                Err(error) => tracing::warn!("Hysteria2 QUIC handshake failed: {error:?}"),
            }
        });
    }
    Ok(())
}

async fn handle_hy2_socks_client(
    mut local: TcpStream,
    shared: Arc<SharedHysteria2Client>,
) -> Result<()> {
    match socks::read_request(&mut local).await? {
        socks::SocksRequest::Connect(target) => {
            let session = match shared.get_or_connect().await {
                Ok(session) => session,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(error);
                }
            };
            let stream = match session.open_tcp(target.clone()).await {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(error);
                }
            };
            socks::write_reply(&mut local, 0x00).await?;
            tracing::info!("Hysteria2 proxying {}", target_name(&target));
            relay_hy2_tcp(local, stream, session).await
        }
        socks::SocksRequest::UdpAssociate => {
            let session = match shared.get_or_connect().await {
                Ok(session) => session,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(error);
                }
            };
            handle_hy2_udp_associate(local, session).await
        }
    }
}

async fn relay_hy2_tcp(
    local: TcpStream,
    stream: Hysteria2TcpStream,
    session: Hysteria2Client,
) -> Result<()> {
    let (mut local_reader, local_writer) = local.into_split();
    let Hysteria2TcpStream {
        mut send,
        mut recv,
        ..
    } = stream;
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read local TCP payload")?;
            if read == 0 {
                send.finish().context("finish Hysteria2 send stream")?;
                return Ok::<(), anyhow::Error>(());
            }
            session.wait_upload(read).await;
            send.write_all(&buffer[..read])
                .await
                .context("write Hysteria2 TCP payload")?;
        }
    };
    let downlink = write_hy2_payloads(&mut recv, local_writer);
    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

async fn write_hy2_payloads(
    recv: &mut quinn::RecvStream,
    mut local_writer: OwnedWriteHalf,
) -> Result<()> {
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        let Some(read) = recv
            .read(&mut buffer)
            .await
            .context("read Hysteria2 TCP payload")?
        else {
            local_writer
                .shutdown()
                .await
                .context("shutdown local TCP writer")?;
            return Ok(());
        };
        if read == 0 {
            local_writer
                .shutdown()
                .await
                .context("shutdown local TCP writer")?;
            return Ok(());
        }
        local_writer
            .write_all(&buffer[..read])
            .await
            .context("write local TCP payload")?;
    }
}

async fn handle_hy2_udp_associate(mut control: TcpStream, session: Hysteria2Client) -> Result<()> {
    if !session.udp_enabled() {
        socks::write_reply(&mut control, 0x07).await?;
        bail!("Hysteria2 server did not enable UDP relay");
    }
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .with_context(|| format!("bind Hysteria2 SOCKS UDP associate socket on {bind_ip}:0"))?;
    socks::write_reply_with_bind(&mut control, 0x00, udp.local_addr()?).await?;
    let session_id = session.next_udp_session_id();
    let mut incoming = session.register_udp_session(session_id).await;
    let udp = Arc::new(udp);
    let (client_tx, mut client_rx) = mpsc::channel::<SocketAddr>(8);

    let udp_to_hy2 = {
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
                session.send_udp(session_id, &target, payload).await?;
            }
        }
    };

    let hy2_to_udp = {
        let udp = udp.clone();
        async move {
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => if let Some(next_peer) = next_peer { peer = Some(next_peer); },
                    message = incoming.recv() => {
                        let Some(message) = message else { return Ok::<(), anyhow::Error>(()); };
                        let source = parse_host_port(&message.address)?;
                        let response = uot::encode_socks_udp_packet(&source, &message.payload)?;
                        let peer = peer.context("SOCKS UDP peer is not known yet")?;
                        udp.send_to(&response, peer).await.with_context(|| format!("send SOCKS UDP response to {peer}"))?;
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

    let result = tokio::select! { result = udp_to_hy2 => result, result = hy2_to_udp => result, result = control_closed => result };
    session.unregister_udp_session(session_id).await;
    result
}

async fn handle_hy2_connection(
    connection: quinn::Connection,
    passwords: Vec<String>,
    cc_rx: String,
    udp_enabled: bool,
    core: ProxyCore,
) -> Result<()> {
    let (mut h3, session) =
        authenticate_server(&connection, &passwords, &cc_rx, udp_enabled, &core).await?;
    let _keep_h3_alive = &mut h3;
    if udp_enabled {
        tokio::spawn(handle_server_udp_datagrams(
            connection.clone(),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            session.clone(),
        ));
    }
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
            Err(error) => return Err(error).context("accept Hysteria2 TCP stream"),
        };
        let session = session.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_hy2_tcp_stream(send, recv, session).await {
                tracing::warn!("Hysteria2 TCP stream failed: {error:?}");
            }
        });
    }
}

async fn authenticate_server(
    connection: &quinn::Connection,
    passwords: &[String],
    cc_rx: &str,
    udp_enabled: bool,
    core: &ProxyCore,
) -> Result<(
    h3::server::Connection<h3_quinn::Connection, Bytes>,
    CoreSession,
)> {
    let mut h3 = h3::server::builder()
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .context("initialize Hysteria2 HTTP/3 server")?;
    let timeout = tokio::time::sleep(DEFAULT_AUTH_TIMEOUT);
    tokio::pin!(timeout);
    loop {
        let resolver = tokio::select! {
            _ = &mut timeout => bail!("Hysteria2 auth request timed out"),
            resolver = h3.accept() => resolver.context("accept Hysteria2 HTTP/3 request")?.context("Hysteria2 connection closed before auth")?,
        };
        let (request, mut stream) = resolver
            .resolve_request()
            .await
            .context("resolve Hysteria2 HTTP/3 request")?;
        if !is_auth_request(&request) {
            send_h3_status(&mut stream, 404).await?;
            continue;
        }
        let auth = request
            .headers()
            .get("Hysteria-Auth")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .trim();
        if !passwords.iter().any(|password| auth == password.trim()) {
            send_h3_status(&mut stream, 401).await?;
            bail!("Hysteria2 authentication failed");
        }
        let session = core
            .authenticate_from(auth, connection.remote_address())
            .await?;
        let response = http::Response::builder()
            .status(http::StatusCode::from_u16(233).context("build Hysteria2 auth status")?)
            .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
            .header("Hysteria-CC-RX", cc_rx)
            .header("Hysteria-Padding", "")
            .body(())
            .context("build Hysteria2 auth response")?;
        stream
            .send_response(response)
            .await
            .context("send Hysteria2 auth response")?;
        stream
            .finish()
            .await
            .context("finish Hysteria2 auth stream")?;
        return Ok((h3, session));
    }
}

fn is_auth_request(request: &http::Request<()>) -> bool {
    request.method() == http::Method::POST
        && request.uri().path() == AUTH_PATH
        && request
            .uri()
            .authority()
            .map(|authority| authority.as_str().eq_ignore_ascii_case(AUTH_HOST))
            .unwrap_or(false)
}

async fn send_h3_status<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    status: u16,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let response = http::Response::builder()
        .status(status)
        .body(())
        .with_context(|| format!("build Hysteria2 HTTP/3 {status} response"))?;
    stream
        .send_response(response)
        .await
        .with_context(|| format!("send Hysteria2 HTTP/3 {status} response"))?;
    stream
        .finish()
        .await
        .with_context(|| format!("finish Hysteria2 HTTP/3 {status} response"))?;
    Ok(())
}

async fn handle_hy2_tcp_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session: CoreSession,
) -> Result<()> {
    let target = match read_tcp_request(&mut recv).await {
        Ok(target) => target,
        Err(error) => {
            write_tcp_response(&mut send, 1, &error.to_string()).await?;
            let _ = send.finish();
            return Err(error);
        }
    };
    let mut remote = match socket_protect::connect_proxy_target(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            write_tcp_response(&mut send, 1, &error.to_string()).await?;
            let _ = send.finish();
            return Err(error).with_context(|| {
                format!("connect Hysteria2 destination {}", target_name(&target))
            });
        }
    };
    let _ = remote.set_nodelay(true);
    write_tcp_response(&mut send, 0, "").await?;
    let (mut remote_reader, mut remote_writer) = remote.split();
    let client_to_remote = copy_stream(&mut recv, &mut remote_writer, session.clone(), true);
    let remote_to_client = copy_stream(&mut remote_reader, &mut send, session, false);
    let _ = tokio::try_join!(client_to_remote, remote_to_client)?;
    let _ = send.finish();
    Ok(())
}

async fn handle_server_udp_datagrams(
    connection: quinn::Connection,
    sessions: ServerUdpSessions,
    fragments: ServerUdpFragments,
    session: CoreSession,
) {
    let mut cleanup = tokio::time::interval(UDP_FRAGMENT_TIMEOUT);
    loop {
        let datagram = match tokio::select! {
            _ = cleanup.tick() => { cleanup_server_udp_state(&sessions, &fragments).await; continue; }
            datagram = connection.read_datagram() => datagram,
        } {
            Ok(datagram) => datagram,
            Err(error) => {
                debug_connection_closed_as_udp_end(error);
                return;
            }
        };
        let message = match decode_udp_message(&datagram) {
            Ok(message) => message,
            Err(error) => {
                tracing::warn!(?error, "invalid Hysteria2 UDP datagram");
                continue;
            }
        };
        let message = match reassemble_udp_message(message, &fragments).await {
            Ok(Some(message)) => message,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(?error, "invalid Hysteria2 UDP fragment");
                continue;
            }
        };
        let target = match parse_host_port(&message.address) {
            Ok(target) => target,
            Err(error) => {
                tracing::warn!(?error, address = %message.address, "parse Hysteria2 UDP target failed");
                continue;
            }
        };
        let target_addr = match resolve_target_addr(&target).await {
            Ok(addr) => addr,
            Err(error) => {
                tracing::warn!(?error, target = %target_name(&target), "resolve Hysteria2 UDP target failed");
                continue;
            }
        };
        let session = match get_or_create_server_udp_session(
            message.session_id,
            target_addr,
            &connection,
            &sessions,
            session.clone(),
        )
        .await
        {
            Ok(session) => session,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    session_id = message.session_id,
                    "create Hysteria2 UDP session failed"
                );
                continue;
            }
        };
        if let Err(error) = session.core.record_upload(message.payload.len()).await {
            tracing::warn!(?error, "Hysteria2 UDP upload limit rejected packet");
            continue;
        }
        if let Err(error) = session.socket.send_to(&message.payload, target_addr).await {
            tracing::warn!(?error, target = %target_addr, "send Hysteria2 UDP payload failed");
        }
        *session
            .last_seen
            .lock()
            .expect("HY2 UDP session time poisoned") = Instant::now();
    }
}

async fn get_or_create_server_udp_session(
    session_id: u32,
    target: SocketAddr,
    connection: &quinn::Connection,
    sessions: &ServerUdpSessions,
    core: CoreSession,
) -> Result<Arc<ServerUdpSession>> {
    if let Some(session) = sessions.lock().await.get(&session_id).cloned() {
        return Ok(session);
    }
    let socket = Arc::new(bind_udp_socket_for_target(target).await?);
    let response_socket = socket.clone();
    let response_connection = connection.clone();
    let response_core = core.clone();
    let handle = tokio::spawn(async move {
        if let Err(error) = relay_server_udp_responses(
            session_id,
            response_socket,
            response_connection,
            response_core,
        )
        .await
        {
            tracing::warn!(?error, session_id, "Hysteria2 UDP response relay failed");
        }
    });
    let session = Arc::new(ServerUdpSession {
        socket,
        core,
        last_seen: StdMutex::new(Instant::now()),
        response_handle: StdMutex::new(handle),
    });
    sessions.lock().await.insert(session_id, session.clone());
    Ok(session)
}

async fn relay_server_udp_responses(
    session_id: u32,
    socket: Arc<UdpSocket>,
    connection: quinn::Connection,
    core: CoreSession,
) -> Result<()> {
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (read, source) = tokio::select! {
            closed = connection.closed() => { debug_connection_closed_as_udp_end(closed); return Ok(()); }
            result = socket.recv_from(&mut buffer) => result.context("receive Hysteria2 UDP response")?,
        };
        core.record_download(read).await?;
        for message in encode_udp_messages(
            session_id,
            next_udp_packet_id(),
            source.to_string(),
            &buffer[..read],
            connection.max_datagram_size(),
        )? {
            connection
                .send_datagram(Bytes::from(encode_udp_message(&message)?))
                .context("send Hysteria2 UDP response datagram")?;
        }
    }
}

async fn cleanup_server_udp_state(sessions: &ServerUdpSessions, fragments: &ServerUdpFragments) {
    cleanup_udp_fragments(fragments).await;
    let now = Instant::now();
    let expired = {
        let mut guard = sessions.lock().await;
        let ids = guard
            .iter()
            .filter_map(|(id, session)| {
                let last_seen = *session
                    .last_seen
                    .lock()
                    .expect("HY2 UDP session time poisoned");
                (now.saturating_duration_since(last_seen) >= UDP_SESSION_IDLE_TIMEOUT)
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| guard.remove(&id))
            .collect::<Vec<_>>()
    };
    drop(expired);
}

async fn authenticate_client(
    sender: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    config: &Hysteria2ClientConfig,
) -> Result<bool> {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(AUTH_URI)
        .header("Hysteria-Auth", config.password.trim())
        .header("Hysteria-CC-RX", client_cc_rx(config))
        .header("Hysteria-Padding", "")
        .body(())
        .context("build Hysteria2 auth request")?;
    let mut stream = sender
        .send_request(request)
        .await
        .context("send Hysteria2 auth request")?;
    stream
        .finish()
        .await
        .context("finish Hysteria2 auth request")?;
    let response = stream
        .recv_response()
        .await
        .context("read Hysteria2 auth response")?;
    ensure!(
        response.status().as_u16() == 233,
        "Hysteria2 authentication rejected with HTTP {}",
        response.status()
    );
    Ok(response
        .headers()
        .get("Hysteria-UDP")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false))
}

fn client_cc_rx(config: &Hysteria2ClientConfig) -> String {
    config
        .download_bandwidth
        .map(|mbps| mbps.saturating_mul(125_000).to_string())
        .unwrap_or_else(|| "0".to_string())
}

fn build_client_endpoint(config: &Hysteria2ClientConfig, bind_ipv6: bool) -> Result<Endpoint> {
    let mut transport_config = hy2_transport_config(&config.congestion_control)?;
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(HY2_MAX_INCOMING_STREAMS));
    let mut tls = if let Some(fingerprint) = config
        .certificate_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                tls::CertificateFingerprintVerifier::from_sha256(fingerprint)?,
            ))
            .with_no_client_auth()
    } else if config.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(tls::InsecureVerifier))
            .with_no_client_auth()
    } else if !config.pinned_cert_sha256.is_empty() {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                tls::CertificatePinsVerifier::from_sha256_values(&config.pinned_cert_sha256)?,
            ))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        if !config.disable_system_roots {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for path in &config.ca_cert_paths {
            for cert in tls::load_certs(path)? {
                roots.add(cert).with_context(|| {
                    format!("add Hysteria2 custom root certificate {}", path.display())
                })?;
            }
        }
        for (index, pem) in config.ca_certificates.iter().enumerate() {
            for cert in tls::load_certs_from_pem(
                &format!("Hysteria2 inline custom root certificate {}", index + 1),
                pem,
            )? {
                roots.add(cert).with_context(|| {
                    format!("add Hysteria2 inline custom root certificate {}", index + 1)
                })?;
            }
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = vec![H3_ALPN.to_vec()];
    let quic_tls = QuicClientConfig::try_from(Arc::new(tls))
        .context("build Hysteria2 QUIC TLS client config")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    client_config.transport_config(Arc::new(transport_config));
    let socket = bind_client_udp_socket(bind_ipv6)?;
    if let Some(obfs) = salamander_config(config.obfs.as_deref(), config.obfs_password.as_deref())?
    {
        let socket = SalamanderUdpSocket::new(socket, obfs)
            .context("wrap Hysteria2 salamander UDP socket")?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            Arc::new(socket),
            Arc::new(quinn::TokioRuntime),
        )
        .context("bind Hysteria2 salamander UDP endpoint")?;
        endpoint.set_default_client_config(client_config);
        return Ok(endpoint);
    }
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("bind Hysteria2 UDP endpoint")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn build_server_endpoint(config: &Hysteria2ServerConfig) -> Result<Endpoint> {
    let (certs, key) = tls::server_identity(
        tls::present_path(&config.cert_path),
        tls::present_path(&config.key_path),
        &config.certificates,
        config.key.as_deref(),
        "Hysteria2 server TLS",
    )?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| {
            format!(
                "build Hysteria2 TLS server config with cert {} and key {}",
                config.cert_path.display(),
                config.key_path.display()
            )
        })?;
    tls_config.alpn_protocols = vec![H3_ALPN.to_vec()];
    let crypto =
        QuicServerConfig::try_from(tls_config).context("build Hysteria2 QUIC TLS server config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(hy2_transport_config(&config.congestion_control)?));
    let socket = bind_server_udp_socket(config.listen)?;
    if let Some(obfs) = salamander_config(config.obfs.as_deref(), config.obfs_password.as_deref())?
    {
        let socket = SalamanderUdpSocket::new(socket, obfs)
            .context("wrap Hysteria2 salamander UDP server socket")?;
        return Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            Arc::new(socket),
            Arc::new(quinn::TokioRuntime),
        )
        .context("bind Hysteria2 salamander server endpoint");
    }
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("bind Hysteria2 server endpoint")
}

fn hy2_transport_config(congestion_control: &str) -> Result<quinn::TransportConfig> {
    let mut transport_config = quinn::TransportConfig::default();
    let idle_timeout =
        IdleTimeout::try_from(DEFAULT_QUIC_IDLE_TIMEOUT).context("build Hysteria2 idle timeout")?;
    transport_config
        .stream_receive_window(VarInt::from_u32(HY2_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(HY2_CONN_RECEIVE_WINDOW))
        .send_window(u64::from(HY2_CONN_RECEIVE_WINDOW))
        .max_idle_timeout(Some(idle_timeout))
        .datagram_receive_buffer_size(Some(HY2_DATAGRAM_BUFFER_SIZE))
        .datagram_send_buffer_size(HY2_DATAGRAM_BUFFER_SIZE)
        .congestion_controller_factory(
            match congestion_control.trim().to_ascii_lowercase().as_str() {
                "" | "bbr" => Arc::new(quinn::congestion::BbrConfig::default()),
                "reno" | "newreno" => Arc::new(quinn::congestion::NewRenoConfig::default()),
                other => bail!("unsupported Hysteria2 congestion_control {other}"),
            },
        );
    Ok(transport_config)
}

fn auth_passwords(password: &str, users: &[String]) -> Vec<String> {
    std::iter::once(password)
        .chain(users.iter().map(String::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn bind_client_udp_socket(bind_ipv6: bool) -> Result<std::net::UdpSocket> {
    if bind_ipv6 {
        socket_protect::bind_udp_std(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
            .or_else(|_| {
                socket_protect::bind_udp_std(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
            })
            .context("bind Hysteria2 UDP socket")
    } else {
        socket_protect::bind_udp_std(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .context("bind Hysteria2 UDP socket")
    }
}

fn bind_server_udp_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)
        .with_context(|| format!("bind Hysteria2 server UDP socket on {addr}"))?;
    socket
        .set_nonblocking(true)
        .context("set Hysteria2 server UDP socket nonblocking")?;
    Ok(socket)
}

fn salamander_config(
    obfs: Option<&str>,
    password: Option<&str>,
) -> Result<Option<SalamanderConfig>> {
    let Some(obfs) = obfs.map(str::trim).filter(|value| !value.is_empty()) else {
        ensure!(
            password.map(str::trim).unwrap_or_default().is_empty(),
            "Hysteria2 obfs password requires salamander obfs"
        );
        return Ok(None);
    };
    ensure!(
        obfs.eq_ignore_ascii_case("salamander"),
        "Hysteria2 obfs must be salamander"
    );
    let password = password
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("Hysteria2 salamander obfs password is required")?;
    Ok(Some(SalamanderConfig::new(password)?))
}

async fn resolve_host_addr(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}:{port}"))?
        .next()
        .with_context(|| format!("{host}:{port} resolved to no addresses"))
}

async fn bind_udp_socket_for_target(target: SocketAddr) -> Result<UdpSocket> {
    if target.is_ipv6() {
        UdpSocket::bind("[::]:0")
            .await
            .context("bind IPv6 Hysteria2 UDP relay socket")
    } else {
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind IPv4 Hysteria2 UDP relay socket")
    }
}

async fn copy_stream<R, W>(
    reader: &mut R,
    writer: &mut W,
    session: CoreSession,
    upload: bool,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .context("read Hysteria2 proxied chunk")?;
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        if upload {
            session.record_upload(read).await?;
        } else {
            session.record_download(read).await?;
        }
        writer
            .write_all(&buffer[..read])
            .await
            .context("write Hysteria2 proxied chunk")?;
        total += read as u64;
    }
}

async fn read_tcp_request<R>(reader: &mut R) -> Result<ProxyTarget>
where
    R: AsyncRead + Unpin,
{
    let request_id = read_varint(reader).await?;
    ensure!(
        request_id == HY2_TCP_REQUEST_ID,
        "unsupported Hysteria2 request id {request_id:#x}"
    );
    let address_len = read_varint(reader).await?;
    ensure!(address_len > 0, "Hysteria2 address is required");
    ensure!(
        address_len <= MAX_ADDRESS_LEN,
        "Hysteria2 address is too long"
    );
    let mut address = vec![0u8; address_len as usize];
    reader
        .read_exact(&mut address)
        .await
        .context("read Hysteria2 target address")?;
    let padding_len = read_varint(reader).await?;
    ensure!(
        padding_len <= MAX_PADDING_LEN,
        "Hysteria2 padding is too long"
    );
    discard_exact(reader, padding_len as usize).await?;
    parse_host_port(std::str::from_utf8(&address).context("decode Hysteria2 target address")?)
}

async fn read_tcp_response(recv: &mut quinn::RecvStream) -> Result<()> {
    let status = recv
        .read_u8()
        .await
        .context("read Hysteria2 TCP response status")?;
    let message_len = read_varint(recv).await?;
    ensure!(
        message_len <= MAX_ADDRESS_LEN,
        "Hysteria2 TCP response message too long"
    );
    let mut message = vec![0u8; message_len as usize];
    if message_len > 0 {
        recv.read_exact(&mut message)
            .await
            .context("read Hysteria2 TCP response message")?;
    }
    let padding_len = read_varint(recv).await?;
    ensure!(
        padding_len <= MAX_PADDING_LEN,
        "Hysteria2 TCP response padding too long"
    );
    discard_exact(recv, padding_len as usize).await?;
    if status != 0 {
        bail!(
            "Hysteria2 TCP stream rejected: {}",
            String::from_utf8_lossy(&message)
        );
    }
    Ok(())
}

async fn write_tcp_response<W>(writer: &mut W, status: u8, message: &str) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut response = Vec::with_capacity(1 + message.len() + 2);
    response.push(status);
    encode_varint(message.len() as u64, &mut response)?;
    response.extend_from_slice(message.as_bytes());
    encode_varint(0, &mut response)?;
    writer
        .write_all(&response)
        .await
        .context("write Hysteria2 TCP response")
}

pub fn encode_varint(value: u64, output: &mut Vec<u8>) -> Result<()> {
    if value < (1 << 6) {
        output.push(value as u8);
    } else if value < (1 << 14) {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else if value < (1 << 62) {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    } else {
        bail!("Hysteria2 varint value is too large: {value}");
    }
    Ok(())
}

pub async fn read_varint<R>(reader: &mut R) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    let first = reader.read_u8().await.context("read Hysteria2 varint")?;
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..len {
        value = (value << 8) | u64::from(reader.read_u8().await.context("read Hysteria2 varint")?);
    }
    Ok(value)
}

fn read_varint_from_slice(bytes: &mut &[u8]) -> Result<u64> {
    ensure!(!bytes.is_empty(), "Hysteria2 varint is truncated");
    let first = bytes[0];
    let len = 1usize << (first >> 6);
    ensure!(bytes.len() >= len, "Hysteria2 varint is truncated");
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    *bytes = &bytes[len..];
    Ok(value)
}

async fn discard_exact<R>(reader: &mut R, length: usize) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut remaining = length;
    let mut buffer = [0u8; 1024];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        reader
            .read_exact(&mut buffer[..take])
            .await
            .context("discard Hysteria2 padding")?;
        remaining -= take;
    }
    Ok(())
}

fn decode_udp_message(mut bytes: &[u8]) -> Result<UdpMessage> {
    ensure!(bytes.len() >= 8, "Hysteria2 UDP datagram is too short");
    let session_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let packet_id = u16::from_be_bytes([bytes[4], bytes[5]]);
    let fragment_id = bytes[6];
    let fragment_count = bytes[7];
    bytes = &bytes[8..];
    let address_len = read_varint_from_slice(&mut bytes)?;
    ensure!(address_len > 0, "Hysteria2 UDP address is required");
    ensure!(
        address_len <= MAX_ADDRESS_LEN,
        "Hysteria2 UDP address is too long"
    );
    ensure!(
        bytes.len() >= address_len as usize,
        "Hysteria2 UDP address is truncated"
    );
    let (address, payload) = bytes.split_at(address_len as usize);
    Ok(UdpMessage {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address: std::str::from_utf8(address)
            .context("decode Hysteria2 UDP address")?
            .to_string(),
        payload: payload.to_vec(),
    })
}

fn encode_udp_message(message: &UdpMessage) -> Result<Vec<u8>> {
    let address = message.address.as_bytes();
    let mut encoded = Vec::with_capacity(8 + address.len() + message.payload.len() + 8);
    encoded.extend_from_slice(&message.session_id.to_be_bytes());
    encoded.extend_from_slice(&message.packet_id.to_be_bytes());
    encoded.push(message.fragment_id);
    encoded.push(message.fragment_count);
    encode_varint(address.len() as u64, &mut encoded)?;
    encoded.extend_from_slice(address);
    encoded.extend_from_slice(&message.payload);
    Ok(encoded)
}

fn encode_udp_messages(
    session_id: u32,
    packet_id: u16,
    address: String,
    payload: &[u8],
    max_datagram_size: Option<usize>,
) -> Result<Vec<UdpMessage>> {
    let max_datagram_size = max_datagram_size.unwrap_or(usize::MAX);
    let header_len = encoded_udp_header_len(&address)?;
    if header_len + payload.len() <= max_datagram_size {
        return Ok(vec![UdpMessage {
            session_id,
            packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address,
            payload: payload.to_vec(),
        }]);
    }
    ensure!(
        header_len < max_datagram_size,
        "Hysteria2 UDP datagram header exceeds peer limit"
    );
    let fragment_payload_len = max_datagram_size - header_len;
    let fragment_count = payload.len().div_ceil(fragment_payload_len);
    ensure!(
        fragment_count <= u8::MAX as usize,
        "Hysteria2 UDP packet requires too many fragments"
    );
    let mut messages = Vec::with_capacity(fragment_count);
    for (index, chunk) in payload.chunks(fragment_payload_len).enumerate() {
        messages.push(UdpMessage {
            session_id,
            packet_id,
            fragment_id: index as u8,
            fragment_count: fragment_count as u8,
            address: address.clone(),
            payload: chunk.to_vec(),
        });
    }
    Ok(messages)
}

fn encoded_udp_header_len(address: &str) -> Result<usize> {
    let mut varint = Vec::new();
    encode_varint(address.len() as u64, &mut varint)?;
    Ok(8 + varint.len() + address.len())
}

async fn reassemble_udp_message(
    message: UdpMessage,
    fragments: &Mutex<HashMap<(u32, u16), UdpFragmentBuffer>>,
) -> Result<Option<UdpMessage>> {
    ensure!(
        message.fragment_count > 0,
        "Hysteria2 UDP fragment_count must be positive"
    );
    if message.fragment_count == 1 {
        return Ok(Some(message));
    }
    ensure!(
        message.fragment_id < message.fragment_count,
        "Hysteria2 UDP fragment_id must be less than fragment_count"
    );
    let key = (message.session_id, message.packet_id);
    let mut guard = fragments.lock().await;
    let entry = guard.entry(key).or_insert_with(|| UdpFragmentBuffer {
        address: message.address.clone(),
        created_at: Instant::now(),
        fragments: vec![None; usize::from(message.fragment_count)],
    });
    ensure!(
        entry.fragments.len() == usize::from(message.fragment_count),
        "Hysteria2 UDP fragment_count changed for packet"
    );
    ensure!(
        entry.address == message.address,
        "Hysteria2 UDP fragment address changed for packet"
    );
    entry.fragments[usize::from(message.fragment_id)] = Some(message.payload);
    if entry.fragments.iter().any(Option::is_none) {
        return Ok(None);
    }
    let entry = guard
        .remove(&key)
        .expect("Hysteria2 fragment buffer exists");
    let mut payload = Vec::new();
    for fragment in entry.fragments {
        payload.extend(fragment.expect("Hysteria2 fragment present"));
    }
    Ok(Some(UdpMessage {
        session_id: key.0,
        packet_id: key.1,
        fragment_id: 0,
        fragment_count: 1,
        address: entry.address,
        payload,
    }))
}

async fn cleanup_udp_fragments(fragments: &Mutex<HashMap<(u32, u16), UdpFragmentBuffer>>) {
    let now = Instant::now();
    fragments.lock().await.retain(|_, buffer| {
        now.saturating_duration_since(buffer.created_at) < UDP_FRAGMENT_TIMEOUT
    });
}

fn next_udp_packet_id() -> u16 {
    static NEXT_PACKET_ID: AtomicU16 = AtomicU16::new(1);
    NEXT_PACKET_ID.fetch_add(1, Ordering::Relaxed)
}

fn debug_connection_closed_as_udp_end(error: quinn::ConnectionError) {
    match error {
        quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::ConnectionClosed(_) => {}
        error => tracing::warn!(?error, "Hysteria2 UDP datagram receiver stopped"),
    }
}

fn parse_host_port(value: &str) -> Result<ProxyTarget> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(ProxyTarget::Ip(addr));
    }
    let (host, port) = value
        .rsplit_once(':')
        .context("Hysteria2 target address must be host:port")?;
    let port = port
        .trim()
        .parse::<u16>()
        .context("parse Hysteria2 target port")?;
    let host = host.trim();
    ensure!(!host.is_empty(), "Hysteria2 target host is required");
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(ProxyTarget::Ip(SocketAddr::new(ip, port))),
        Err(_) => Ok(ProxyTarget::Domain(host.to_string(), port)),
    }
}

fn salamander_xor(
    password: &[u8],
    salt: &[u8; SALAMANDER_SALT_LEN],
    input: &[u8],
    output: &mut [u8],
) {
    debug_assert_eq!(input.len(), output.len());
    let key = salamander_key(password, salt);
    for (index, (plain, cipher)) in output.iter_mut().zip(input).enumerate() {
        *plain = *cipher ^ key[index % SALAMANDER_KEY_LEN];
    }
}

fn salamander_key(password: &[u8], salt: &[u8; SALAMANDER_SALT_LEN]) -> [u8; SALAMANDER_KEY_LEN] {
    let mut key = [0u8; SALAMANDER_KEY_LEN];
    let mut hasher = Blake2bVar::new(SALAMANDER_KEY_LEN).expect("valid BLAKE2b output length");
    hasher.update(password);
    hasher.update(salt);
    hasher
        .finalize_variable(&mut key)
        .expect("valid BLAKE2b output buffer length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823] {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).unwrap();
            let decoded = read_varint_from_slice(&mut encoded.as_slice()).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn udp_message_roundtrip() {
        let message = UdpMessage {
            session_id: 7,
            packet_id: 9,
            fragment_id: 0,
            fragment_count: 1,
            address: "example.com:53".to_string(),
            payload: b"hello".to_vec(),
        };
        let encoded = encode_udp_message(&message).unwrap();
        assert_eq!(decode_udp_message(&encoded).unwrap(), message);
    }

    #[test]
    fn upload_limiter_maps_mbps_to_bytes_per_second() {
        assert_eq!(
            Hy2ByteRateLimiter::new(Some(8)).bytes_per_second,
            Some(1_000_000)
        );
        assert_eq!(Hy2ByteRateLimiter::new(None).bytes_per_second, None);
    }

    #[test]
    fn salamander_roundtrip() {
        let salt = [7u8; SALAMANDER_SALT_LEN];
        let payload = b"hello hysteria2";
        let mut encrypted = vec![0u8; payload.len()];
        let mut decrypted = vec![0u8; payload.len()];
        salamander_xor(b"secret", &salt, payload, &mut encrypted);
        assert_ne!(encrypted, payload);
        salamander_xor(b"secret", &salt, &encrypted, &mut decrypted);
        assert_eq!(decrypted, payload);
    }
}
