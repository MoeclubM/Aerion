use crate::core::{CoreSession, CoreUser, ProxyCore, relay_bidirectional_counted};
use crate::protocol::{ProxyTarget, resolve_target_addr, target_name};
use crate::socket_protect;
use crate::uot;
use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::time::Instant;

mod crypto;
mod pattern;
mod socks;
mod wire;

use crypto::{MieruCipher, current_mieru_key, hash_mieru_password};
use pattern::write_with_possible_fragment;
pub use pattern::{MieruNoncePattern, MieruNonceType, MieruTcpFragment, MieruTrafficPattern};
use socks::{
    SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_NO_ACCEPTABLE, SOCKS_NO_AUTH, SOCKS_VERSION,
    SocksRequest, read_packet_over_stream, read_socks_greeting, read_socks_request,
    read_socks_request_raw, read_socks_response_raw, write_packet_over_stream,
    write_socks_reply_with_bind,
};
use wire::{
    ACK_CLIENT_TO_SERVER, ACK_SERVER_TO_CLIENT, ACK_WINDOW_SIZE, CLOSE_CONN_REQUEST,
    CLOSE_CONN_RESPONSE, CLOSE_SESSION_REQUEST, CLOSE_SESSION_RESPONSE, DATA_CLIENT_TO_SERVER,
    DATA_SERVER_TO_CLIENT, MAX_PDU, MAX_SESSION_OPEN_PAYLOAD, MieruDataAckMetadata, MieruMetadata,
    MieruSegment, MieruSessionMetadata, OPEN_SESSION_REQUEST, OPEN_SESSION_RESPONSE,
    PACKET_OVERHEAD, PACKET_RETRANSMIT_INTERVAL_MS, STATUS_OK, decode_mieru_packet_segment,
    decode_mieru_packet_segment_for_server, encode_mieru_packet_segment, read_first_server_segment,
    read_mieru_segment,
};

const DEFAULT_MTU: usize = 1500;
const NONCE_LEN: usize = 24;
pub const MIERU_KEY_LEN: usize = 32;
const KEY_LEN: usize = MIERU_KEY_LEN;
const KEY_ITER: usize = 64;
const KEY_REFRESH_SECS: u64 = 120;

#[derive(Clone, Debug)]
pub struct MieruUser {
    pub username: String,
    pub password: String,
    pub hashed_password: Option<[u8; MIERU_KEY_LEN]>,
}

#[derive(Clone, Debug)]
pub struct MieruClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    pub password: String,
    pub hashed_password: Option<[u8; MIERU_KEY_LEN]>,
    pub mtu: usize,
    pub transport: MieruTransport,
    pub traffic_pattern: Option<MieruTrafficPattern>,
}

#[derive(Clone, Debug)]
pub struct MieruServerConfig {
    pub listen: SocketAddr,
    pub username: String,
    pub password: String,
    pub users: Vec<MieruUser>,
    pub mtu: usize,
    pub user_hint_mandatory: bool,
    pub transport: MieruTransport,
    pub traffic_pattern: Option<MieruTrafficPattern>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MieruTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
struct MieruUserSecret {
    username: String,
    password: String,
    hashed_password: [u8; KEY_LEN],
}

struct MieruStreamWriter {
    inner: OwnedWriteHalf,
    cipher: Option<MieruCipher>,
    traffic_pattern: Option<MieruTrafficPattern>,
}

struct MieruPacketWriter {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    cipher: MieruCipher,
    mtu: usize,
}

enum MieruAnyWriter {
    Stream(MieruStreamWriter),
    Packet(MieruPacketWriter),
}

#[derive(Debug)]
pub struct MieruSession {
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound: mpsc::UnboundedSender<SessionCommand>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    close_sent: bool,
}

#[derive(Debug)]
enum SessionCommand {
    Data(Vec<u8>),
    SendSegment(MieruSegment),
    SendAck {
        protocol: u8,
        un_ack_seq: u32,
        window_size: u16,
    },
    PeerAck {
        un_ack_seq: u32,
    },
    Close,
}

#[derive(Clone)]
struct ClientUnderlay {
    writer: Arc<Mutex<MieruAnyWriter>>,
    sessions: MieruSessionMap,
    reliable: bool,
    closed: Arc<Mutex<Option<String>>>,
}

struct SharedMieruClientSession {
    config: MieruClientConfig,
    underlay: Mutex<Option<ClientUnderlay>>,
}

#[derive(Clone)]
struct MieruSessionEntry {
    inbound: mpsc::UnboundedSender<Vec<u8>>,
    outbound: mpsc::UnboundedSender<SessionCommand>,
    ordered: bool,
    recv: Arc<Mutex<MieruReceiveState>>,
}

#[derive(Debug, Default)]
struct MieruReceiveState {
    next_seq: u32,
    pending: BTreeMap<u32, Vec<u8>>,
}

type MieruSessionMap = Arc<Mutex<HashMap<u32, MieruSessionEntry>>>;

impl MieruUser {
    pub fn password(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            hashed_password: None,
        }
    }

    pub fn hashed_password(
        username: impl Into<String>,
        hashed_password: [u8; MIERU_KEY_LEN],
    ) -> Self {
        Self {
            username: username.into(),
            password: String::new(),
            hashed_password: Some(hashed_password),
        }
    }

    fn into_secret(self) -> MieruUserSecret {
        let username = self.username.trim().to_string();
        let password = self.password.trim().to_string();
        let hashed_password = self
            .hashed_password
            .unwrap_or_else(|| hash_mieru_password(password.as_bytes(), username.as_bytes()));
        MieruUserSecret {
            username,
            password,
            hashed_password,
        }
    }
}

impl MieruUserSecret {
    fn core_credential(&self) -> String {
        if self.password.is_empty() {
            hex::encode(self.hashed_password)
        } else {
            self.password.clone()
        }
    }
}

impl Default for MieruTransport {
    fn default() -> Self {
        Self::Tcp
    }
}

impl MieruTransport {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "tcp" | "stream" => Ok(Self::Tcp),
            "udp" | "packet" => Ok(Self::Udp),
            other => bail!("unsupported Mieru transport: {other}"),
        }
    }
}

impl MieruClientConfig {
    fn mtu(&self) -> usize {
        if self.mtu == 0 { DEFAULT_MTU } else { self.mtu }
    }

    fn hashed_password(&self) -> [u8; KEY_LEN] {
        self.hashed_password.unwrap_or_else(|| {
            hash_mieru_password(self.password.as_bytes(), self.username.as_bytes())
        })
    }
}

impl MieruServerConfig {
    fn mtu(&self) -> usize {
        if self.mtu == 0 { DEFAULT_MTU } else { self.mtu }
    }

    fn effective_users(&self) -> Vec<MieruUserSecret> {
        let mut users = Vec::new();
        if !self.password.trim().is_empty() {
            let username = if self.username.trim().is_empty() {
                "default".to_string()
            } else {
                self.username.trim().to_string()
            };
            users.push(MieruUser::password(username, self.password.trim()).into_secret());
        }
        for user in &self.users {
            users.push(user.clone().into_secret());
        }
        users
    }
}

impl SharedMieruClientSession {
    fn new(config: MieruClientConfig) -> Self {
        Self {
            config,
            underlay: Mutex::new(None),
        }
    }

    async fn get_or_connect(&self) -> Result<ClientUnderlay> {
        {
            let guard = self.underlay.lock().await;
            if let Some(underlay) = guard.as_ref() {
                if underlay.is_alive().await {
                    return Ok(underlay.clone());
                }
            }
        }

        let mut guard = self.underlay.lock().await;
        if let Some(underlay) = guard.as_ref() {
            if underlay.is_alive().await {
                return Ok(underlay.clone());
            }
            guard.take();
        }

        let underlay = connect_mieru_underlay(&self.config).await?;
        guard.replace(underlay.clone());
        Ok(underlay)
    }
}

impl MieruStreamWriter {
    fn new(
        inner: OwnedWriteHalf,
        cipher: Option<MieruCipher>,
        traffic_pattern: Option<MieruTrafficPattern>,
    ) -> Self {
        Self {
            inner,
            cipher,
            traffic_pattern,
        }
    }

    fn set_cipher(&mut self, cipher: MieruCipher) {
        self.cipher = Some(cipher);
    }

    async fn write_segment(&mut self, mut segment: MieruSegment) -> Result<()> {
        let cipher = self
            .cipher
            .as_mut()
            .context("Mieru stream send cipher is not initialized")?;
        match &mut segment.metadata {
            MieruMetadata::Session(metadata) => {
                ensure!(
                    segment.payload.len() <= u16::MAX as usize,
                    "Mieru session payload is too large"
                );
                metadata.payload_len = segment.payload.len() as u16;
                metadata.suffix_len = 0;
            }
            MieruMetadata::DataAck(metadata) => {
                ensure!(
                    segment.payload.len() <= u16::MAX as usize,
                    "Mieru data payload is too large"
                );
                metadata.payload_len = segment.payload.len() as u16;
                metadata.prefix_len = 0;
                metadata.suffix_len = 0;
            }
        }
        let encrypted_metadata = cipher.encrypt(&segment.metadata.marshal()?)?;
        write_with_possible_fragment(&mut self.inner, &encrypted_metadata, &self.traffic_pattern)
            .await
            .context("write Mieru encrypted metadata")?;
        if !segment.payload.is_empty() {
            let encrypted_payload = cipher.encrypt(&segment.payload)?;
            write_with_possible_fragment(
                &mut self.inner,
                &encrypted_payload,
                &self.traffic_pattern,
            )
            .await
            .context("write Mieru encrypted payload")?;
        }
        self.inner.flush().await.context("flush Mieru segment")
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await.context("shutdown Mieru writer")
    }
}

impl MieruPacketWriter {
    fn new(socket: Arc<UdpSocket>, peer: SocketAddr, cipher: MieruCipher, mtu: usize) -> Self {
        Self {
            socket,
            peer,
            cipher,
            mtu,
        }
    }

    async fn write_segment(&mut self, segment: MieruSegment) -> Result<()> {
        let packet = encode_mieru_packet_segment(&mut self.cipher, segment, self.mtu)?;
        self.socket
            .send_to(&packet, self.peer)
            .await
            .with_context(|| format!("send Mieru UDP packet to {}", self.peer))?;
        Ok(())
    }
}

impl MieruAnyWriter {
    fn set_cipher(&mut self, cipher: MieruCipher) {
        match self {
            Self::Stream(writer) => writer.set_cipher(cipher),
            Self::Packet(writer) => writer.cipher = cipher,
        }
    }

    async fn write_segment(&mut self, segment: MieruSegment) -> Result<()> {
        match self {
            Self::Stream(writer) => writer.write_segment(segment).await,
            Self::Packet(writer) => writer.write_segment(segment).await,
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        match self {
            Self::Stream(writer) => writer.shutdown().await,
            Self::Packet(_) => Ok(()),
        }
    }
}

impl MieruSession {
    fn new(
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<SessionCommand>,
    ) -> Self {
        Self {
            inbound,
            outbound,
            read_buffer: Vec::new(),
            read_pos: 0,
            close_sent: false,
        }
    }
}

impl AsyncRead for MieruSession {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_pos < self.read_buffer.len() {
                let len = buf
                    .remaining()
                    .min(self.read_buffer.len().saturating_sub(self.read_pos));
                let end = self.read_pos + len;
                buf.put_slice(&self.read_buffer[self.read_pos..end]);
                self.read_pos = end;
                if self.read_pos == self.read_buffer.len() {
                    self.read_buffer.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.inbound).poll_recv(cx) {
                Poll::Ready(Some(payload)) => {
                    if payload.is_empty() {
                        continue;
                    }
                    self.read_buffer = payload;
                    self.read_pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MieruSession {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.outbound
            .send(SessionCommand::Data(buf.to_vec()))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "Mieru session output closed")
            })?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if !self.close_sent {
            let _ = self.outbound.send(SessionCommand::Close);
            self.close_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MieruSession {
    fn drop(&mut self) {
        if !self.close_sent {
            let _ = self.outbound.send(SessionCommand::Close);
            self.close_sent = true;
        }
    }
}

pub async fn run_mieru_client(config: MieruClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Mieru SOCKS listener on {}", config.listen))?;
    run_mieru_client_listener(listener, config).await
}

pub async fn run_mieru_client_listener(
    listener: TcpListener,
    config: MieruClientConfig,
) -> Result<()> {
    tracing::info!(
        "Mieru client listening on socks5://{}",
        listener.local_addr()?
    );
    let shared = Arc::new(SharedMieruClientSession::new(config));
    loop {
        let (stream, peer) = listener.accept().await.context("accept SOCKS client")?;
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_mieru_socks_client(stream, shared).await {
                tracing::warn!("Mieru SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn run_mieru_server(config: MieruServerConfig) -> Result<()> {
    let core_users = config
        .effective_users()
        .into_iter()
        .map(|user| CoreUser::password(user.username.clone(), user.core_credential()))
        .collect();
    let core = ProxyCore::new(core_users)?;
    run_mieru_server_with_core(config, core).await
}

pub async fn run_mieru_server_with_core(config: MieruServerConfig, core: ProxyCore) -> Result<()> {
    if config.transport == MieruTransport::Udp {
        let socket = UdpSocket::bind(config.listen)
            .await
            .with_context(|| format!("bind Mieru UDP server on {}", config.listen))?;
        return run_mieru_packet_server_socket_with_core(socket, config, core).await;
    }
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Mieru server on {}", config.listen))?;
    run_mieru_server_listener_with_core(listener, config, core).await
}

pub async fn run_mieru_server_listener_with_core(
    listener: TcpListener,
    config: MieruServerConfig,
    core: ProxyCore,
) -> Result<()> {
    let users = config.effective_users();
    ensure!(!users.is_empty(), "Mieru server has no configured users");
    ensure!(
        config.transport != MieruTransport::Udp,
        "Mieru TCP listener requires TCP transport"
    );
    tracing::info!("Mieru server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await.context("accept Mieru client")?;
        let _ = stream.set_nodelay(true);
        let users = users.clone();
        let core = core.clone();
        let mtu = config.mtu();
        let user_hint_mandatory = config.user_hint_mandatory;
        let traffic_pattern = config.traffic_pattern.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_mieru_underlay_server(
                stream,
                users,
                core,
                mtu,
                user_hint_mandatory,
                traffic_pattern,
                peer,
            )
            .await
            {
                tracing::warn!("Mieru underlay {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn run_mieru_packet_server_socket_with_core(
    socket: UdpSocket,
    config: MieruServerConfig,
    core: ProxyCore,
) -> Result<()> {
    let users = config.effective_users();
    ensure!(!users.is_empty(), "Mieru server has no configured users");
    ensure!(
        config.transport == MieruTransport::Udp,
        "Mieru UDP socket requires UDP transport"
    );
    run_mieru_packet_server(config, core, users, socket).await
}

pub fn parse_mieru_user(value: &str) -> Result<MieruUser> {
    let value = value.trim();
    ensure!(!value.is_empty(), "Mieru user entry is empty");
    if let Some((username, password)) = value.split_once(':').or_else(|| value.split_once('=')) {
        ensure!(!username.trim().is_empty(), "Mieru username is empty");
        ensure!(!password.trim().is_empty(), "Mieru user password is empty");
        return Ok(MieruUser::password(username.trim(), password.trim()));
    }
    Ok(MieruUser::password(value, value))
}

async fn handle_mieru_socks_client(
    mut local: TcpStream,
    shared: Arc<SharedMieruClientSession>,
) -> Result<()> {
    let greeting = read_socks_greeting(&mut local).await?;
    if !greeting[2..].contains(&SOCKS_NO_AUTH) {
        local
            .write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE])
            .await?;
        bail!("SOCKS client did not offer no-auth method");
    }
    local.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).await?;

    let request = read_socks_request_raw(&mut local).await?;
    let command = request[1];
    let underlay = shared.get_or_connect().await?;
    let mut session = underlay.open_session(shared.config.mtu()).await?;
    session.write_all(&request).await?;
    let response = read_socks_response_raw(&mut session).await?;
    match command {
        SOCKS_CMD_CONNECT => {
            local.write_all(&response).await?;
            ensure!(response[1] == 0, "remote SOCKS CONNECT failed");
            tokio::io::copy_bidirectional(&mut local, &mut session)
                .await
                .context("relay Mieru TCP stream")?;
            Ok(())
        }
        SOCKS_CMD_UDP_ASSOCIATE => handle_mieru_client_udp(local, session, response).await,
        other => bail!("unsupported SOCKS command for Mieru client: {other:#x}"),
    }
}

async fn handle_mieru_client_udp(
    mut control: TcpStream,
    session: MieruSession,
    response: Vec<u8>,
) -> Result<()> {
    if response[1] != 0 {
        control.write_all(&response).await?;
        bail!("remote SOCKS UDP ASSOCIATE failed");
    }
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("bind local Mieru UDP associate socket on {bind_ip}:0"))?,
    );
    write_socks_reply_with_bind(&mut control, 0, udp.local_addr()?).await?;

    let (mut session_reader, session_writer) = split(session);
    let session_writer = Arc::new(Mutex::new(session_writer));
    let peer = Arc::new(Mutex::new(None::<SocketAddr>));

    let udp_to_tunnel = {
        let udp = udp.clone();
        let peer = peer.clone();
        let session_writer = session_writer.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, source) = udp.recv_from(&mut buffer).await?;
                *peer.lock().await = Some(source);
                write_packet_over_stream(&mut *session_writer.lock().await, &buffer[..read])
                    .await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };

    let tunnel_to_udp = {
        let udp = udp.clone();
        let peer = peer.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let read = read_packet_over_stream(&mut session_reader, &mut buffer).await?;
                let peer = (*peer.lock().await).context("SOCKS UDP peer is not known yet")?;
                udp.send_to(&buffer[..read], peer).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };

    let control_closed = async {
        let mut one = [0u8; 1];
        loop {
            if control.read(&mut one).await? == 0 {
                return Ok::<(), anyhow::Error>(());
            }
        }
    };

    tokio::select! {
        result = udp_to_tunnel => result,
        result = tunnel_to_udp => result,
        result = control_closed => result,
    }
}

async fn connect_mieru_underlay(config: &MieruClientConfig) -> Result<ClientUnderlay> {
    if config.transport == MieruTransport::Udp {
        return connect_mieru_packet_underlay(config).await;
    }
    let stream =
        socket_protect::connect_tcp_host_port(config.server_host.as_str(), config.server_port)
            .await
            .with_context(|| {
                format!(
                    "connect Mieru server {}:{}",
                    config.server_host, config.server_port
                )
            })?;
    let (reader, writer) = stream.into_split();
    let key = current_mieru_key(&config.hashed_password())?;
    let traffic_pattern = config.traffic_pattern.clone();
    let send = MieruCipher::new(key, true, config.username.clone(), traffic_pattern.as_ref());
    let recv = MieruCipher::new(key, true, config.username.clone(), traffic_pattern.as_ref());
    let writer = Arc::new(Mutex::new(MieruAnyWriter::Stream(MieruStreamWriter::new(
        writer,
        Some(send),
        traffic_pattern,
    ))));
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    let closed = Arc::new(Mutex::new(None));
    tokio::spawn(run_mieru_client_read_loop(
        reader,
        recv,
        writer.clone(),
        sessions.clone(),
        closed.clone(),
    ));
    Ok(ClientUnderlay {
        writer,
        sessions,
        reliable: false,
        closed,
    })
}

async fn connect_mieru_packet_underlay(config: &MieruClientConfig) -> Result<ClientUnderlay> {
    let server_addr = tokio::net::lookup_host((config.server_host.as_str(), config.server_port))
        .await
        .with_context(|| {
            format!(
                "resolve Mieru UDP server {}:{}",
                config.server_host, config.server_port
            )
        })?
        .next()
        .with_context(|| {
            format!(
                "Mieru UDP server resolved to no addresses: {}:{}",
                config.server_host, config.server_port
            )
        })?;
    let bind = if server_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = Arc::new(socket_protect::bind_udp(bind).await?);
    let key = current_mieru_key(&config.hashed_password())?;
    let send = MieruCipher::new(
        key,
        false,
        config.username.clone(),
        config.traffic_pattern.as_ref(),
    );
    let recv = MieruCipher::new(
        key,
        false,
        config.username.clone(),
        config.traffic_pattern.as_ref(),
    );
    let mtu = config.mtu();
    let writer = Arc::new(Mutex::new(MieruAnyWriter::Packet(MieruPacketWriter::new(
        socket.clone(),
        server_addr,
        send,
        mtu,
    ))));
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    let closed = Arc::new(Mutex::new(None));
    tokio::spawn(run_mieru_packet_client_read_loop(
        socket,
        server_addr,
        recv,
        writer.clone(),
        sessions.clone(),
        closed.clone(),
    ));
    Ok(ClientUnderlay {
        writer,
        sessions,
        reliable: true,
        closed,
    })
}

impl ClientUnderlay {
    async fn is_alive(&self) -> bool {
        self.closed.lock().await.is_none()
    }

    async fn open_session(&self, mtu: usize) -> Result<MieruSession> {
        if let Some(error) = self.closed.lock().await.clone() {
            bail!("Mieru underlay is closed: {error}");
        }
        let mut session_id = random_u32()?;
        while session_id == 0 || self.sessions.lock().await.contains_key(&session_id) {
            session_id = random_u32()?;
        }
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        self.sessions.lock().await.insert(
            session_id,
            MieruSessionEntry {
                inbound: inbound_tx,
                outbound: outbound_tx.clone(),
                ordered: self.reliable,
                recv: Arc::new(Mutex::new(MieruReceiveState::default())),
            },
        );
        tokio::spawn(run_mieru_session_output(
            session_id,
            true,
            false,
            self.writer.clone(),
            outbound_rx,
            self.reliable,
            mtu,
        ));
        Ok(MieruSession::new(inbound_rx, outbound_tx))
    }
}

async fn handle_mieru_underlay_server(
    stream: TcpStream,
    users: Vec<MieruUserSecret>,
    core: ProxyCore,
    mtu: usize,
    user_hint_mandatory: bool,
    traffic_pattern: Option<MieruTrafficPattern>,
    peer: SocketAddr,
) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(MieruAnyWriter::Stream(MieruStreamWriter::new(
        writer,
        None,
        traffic_pattern.clone(),
    ))));
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    run_mieru_server_read_loop(
        reader,
        writer,
        sessions,
        users,
        core,
        mtu,
        user_hint_mandatory,
        traffic_pattern,
        peer,
    )
    .await
}

async fn run_mieru_client_read_loop(
    mut reader: OwnedReadHalf,
    mut recv: MieruCipher,
    writer: Arc<Mutex<MieruAnyWriter>>,
    sessions: MieruSessionMap,
    closed: Arc<Mutex<Option<String>>>,
) {
    let result: Result<()> = async {
        let mut first_read = true;
        loop {
            let segment = read_mieru_segment(&mut reader, &mut recv, first_read).await?;
            first_read = false;
            match segment.metadata.protocol() {
                OPEN_SESSION_RESPONSE | DATA_SERVER_TO_CLIENT => {
                    if let Some(un_ack_seq) = segment.metadata.un_ack_seq() {
                        ack_session_segments(&sessions, segment.metadata.session_id(), un_ack_seq)
                            .await;
                    }
                    route_session_segment(&sessions, segment, None).await?;
                }
                CLOSE_SESSION_REQUEST => {
                    let session_id = segment.metadata.session_id();
                    write_close_response(&writer, session_id).await?;
                    sessions.lock().await.remove(&session_id);
                }
                CLOSE_SESSION_RESPONSE => {
                    sessions.lock().await.remove(&segment.metadata.session_id());
                }
                ACK_SERVER_TO_CLIENT => {
                    ack_session_segments(
                        &sessions,
                        segment.metadata.session_id(),
                        segment.metadata.un_ack_seq().unwrap_or(0),
                    )
                    .await;
                }
                CLOSE_CONN_REQUEST | CLOSE_CONN_RESPONSE => {}
                other => bail!("unexpected Mieru client segment protocol {other}"),
            }
        }
    }
    .await;
    if let Err(error) = result {
        let message = format!("{error:?}");
        *closed.lock().await = Some(message.clone());
        sessions.lock().await.clear();
        tracing::debug!("Mieru client read loop stopped: {message}");
    }
}

async fn run_mieru_server_read_loop(
    mut reader: OwnedReadHalf,
    writer: Arc<Mutex<MieruAnyWriter>>,
    sessions: MieruSessionMap,
    users: Vec<MieruUserSecret>,
    core: ProxyCore,
    mtu: usize,
    user_hint_mandatory: bool,
    traffic_pattern: Option<MieruTrafficPattern>,
    peer: SocketAddr,
) -> Result<()> {
    let mut recv = None::<MieruCipher>;
    let mut user = None::<MieruUserSecret>;
    loop {
        if recv.is_none() {
            let (cipher, matched_user, segment) = read_first_server_segment(
                &mut reader,
                &users,
                user_hint_mandatory,
                traffic_pattern.as_ref(),
            )
            .await?;
            writer
                .lock()
                .await
                .set_cipher(cipher.clone_reset_implicit());
            recv = Some(cipher);
            user = Some(matched_user);
            handle_server_segment(
                segment,
                writer.clone(),
                sessions.clone(),
                core.clone(),
                user.clone().expect("Mieru user is set"),
                mtu,
                false,
                peer,
            )
            .await?;
            continue;
        }
        let segment = read_mieru_segment(
            &mut reader,
            recv.as_mut().expect("Mieru receive cipher is set"),
            false,
        )
        .await?;
        handle_server_segment(
            segment,
            writer.clone(),
            sessions.clone(),
            core.clone(),
            user.clone().expect("Mieru user is set"),
            mtu,
            false,
            peer,
        )
        .await?;
    }
}

async fn run_mieru_packet_client_read_loop(
    socket: Arc<UdpSocket>,
    server_addr: SocketAddr,
    mut recv: MieruCipher,
    writer: Arc<Mutex<MieruAnyWriter>>,
    sessions: MieruSessionMap,
    closed: Arc<Mutex<Option<String>>>,
) {
    let result: Result<()> = async {
        let mut buffer = vec![0u8; u16::MAX as usize];
        loop {
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .await
                .context("receive Mieru UDP packet")?;
            if peer != server_addr {
                continue;
            }
            let segment = decode_mieru_packet_segment(&mut recv, &buffer[..read])?;
            match segment.metadata.protocol() {
                OPEN_SESSION_RESPONSE | DATA_SERVER_TO_CLIENT => {
                    if let Some(un_ack_seq) = segment.metadata.un_ack_seq() {
                        ack_session_segments(&sessions, segment.metadata.session_id(), un_ack_seq)
                            .await;
                    }
                    route_session_segment(&sessions, segment, Some(ACK_CLIENT_TO_SERVER)).await?;
                }
                CLOSE_SESSION_REQUEST => {
                    let session_id = segment.metadata.session_id();
                    write_close_response(&writer, session_id).await?;
                    sessions.lock().await.remove(&session_id);
                }
                CLOSE_SESSION_RESPONSE => {
                    sessions.lock().await.remove(&segment.metadata.session_id());
                }
                ACK_SERVER_TO_CLIENT => {
                    ack_session_segments(
                        &sessions,
                        segment.metadata.session_id(),
                        segment.metadata.un_ack_seq().unwrap_or(0),
                    )
                    .await;
                }
                CLOSE_CONN_REQUEST | CLOSE_CONN_RESPONSE => {}
                other => bail!("unexpected Mieru UDP client segment protocol {other}"),
            }
        }
    }
    .await;
    if let Err(error) = result {
        let message = format!("{error:?}");
        *closed.lock().await = Some(message.clone());
        sessions.lock().await.clear();
        tracing::debug!("Mieru UDP client read loop stopped: {message}");
    }
}

async fn run_mieru_packet_server(
    config: MieruServerConfig,
    core: ProxyCore,
    users: Vec<MieruUserSecret>,
    socket: UdpSocket,
) -> Result<()> {
    let mtu = config.mtu();
    ensure!(
        mtu > PACKET_OVERHEAD,
        "Mieru UDP packet MTU must be larger than {PACKET_OVERHEAD}"
    );
    let socket = Arc::new(socket);
    tracing::info!("Mieru UDP server listening on {}", socket.local_addr()?);
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (read, peer) = socket
            .recv_from(&mut buffer)
            .await
            .context("receive Mieru UDP client packet")?;
        let (segment, user, cipher) = match decode_mieru_packet_segment_for_server(
            &buffer[..read],
            &users,
            config.user_hint_mandatory,
            config.traffic_pattern.as_ref(),
        ) {
            Ok(decoded) => decoded,
            Err(error) => {
                tracing::debug!("drop undecodable Mieru UDP packet from {peer}: {error:?}");
                continue;
            }
        };
        let writer = Arc::new(Mutex::new(MieruAnyWriter::Packet(MieruPacketWriter::new(
            socket.clone(),
            peer,
            cipher,
            mtu,
        ))));
        handle_server_segment(
            segment,
            writer,
            sessions.clone(),
            core.clone(),
            user,
            mtu,
            true,
            peer,
        )
        .await?;
    }
}

async fn handle_server_segment(
    segment: MieruSegment,
    writer: Arc<Mutex<MieruAnyWriter>>,
    sessions: MieruSessionMap,
    core: ProxyCore,
    user: MieruUserSecret,
    mtu: usize,
    reliable: bool,
    peer: SocketAddr,
) -> Result<()> {
    match segment.metadata.protocol() {
        OPEN_SESSION_REQUEST => {
            let session_id = segment.metadata.session_id();
            ensure!(session_id != 0, "Mieru session ID 0 is reserved");
            if sessions.lock().await.contains_key(&session_id) {
                route_session_segment(&sessions, segment, reliable.then_some(ACK_SERVER_TO_CLIENT))
                    .await?;
                return Ok(());
            }
            let core_session = core
                .authenticate_from(&user.core_credential(), peer)
                .await?;
            let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
            sessions.lock().await.insert(
                session_id,
                MieruSessionEntry {
                    inbound: inbound_tx.clone(),
                    outbound: outbound_tx.clone(),
                    ordered: reliable,
                    recv: Arc::new(Mutex::new(MieruReceiveState::default())),
                },
            );
            tokio::spawn(run_mieru_session_output(
                session_id,
                false,
                false,
                writer.clone(),
                outbound_rx,
                reliable,
                mtu,
            ));
            if outbound_tx
                .send(SessionCommand::SendSegment(MieruSegment {
                    metadata: MieruMetadata::Session(MieruSessionMetadata {
                        protocol: OPEN_SESSION_RESPONSE,
                        session_id,
                        seq: 0,
                        status_code: STATUS_OK,
                        payload_len: 0,
                        suffix_len: 0,
                    }),
                    payload: Vec::new(),
                }))
                .is_err()
            {
                bail!("Mieru session {session_id} output queue closed before open response");
            }
            route_session_segment(&sessions, segment, reliable.then_some(ACK_SERVER_TO_CLIENT))
                .await?;
            let session = MieruSession::new(inbound_rx, outbound_tx);
            tokio::spawn(async move {
                if let Err(error) = handle_mieru_server_socks_session(session, core_session).await {
                    tracing::warn!("Mieru session {session_id} failed: {error:?}");
                }
            });
        }
        DATA_CLIENT_TO_SERVER => {
            if let Some(un_ack_seq) = segment.metadata.un_ack_seq() {
                ack_session_segments(&sessions, segment.metadata.session_id(), un_ack_seq).await;
            }
            route_session_segment(&sessions, segment, reliable.then_some(ACK_SERVER_TO_CLIENT))
                .await?;
        }
        CLOSE_SESSION_REQUEST => {
            let session_id = segment.metadata.session_id();
            write_close_response(&writer, session_id).await?;
            sessions.lock().await.remove(&session_id);
        }
        CLOSE_SESSION_RESPONSE => {
            sessions.lock().await.remove(&segment.metadata.session_id());
        }
        ACK_CLIENT_TO_SERVER => {
            ack_session_segments(
                &sessions,
                segment.metadata.session_id(),
                segment.metadata.un_ack_seq().unwrap_or(0),
            )
            .await;
        }
        CLOSE_CONN_REQUEST | CLOSE_CONN_RESPONSE => {}
        other => bail!("unexpected Mieru server segment protocol {other}"),
    }
    Ok(())
}

async fn run_mieru_session_output(
    session_id: u32,
    is_client: bool,
    close_underlay_on_close: bool,
    writer: Arc<Mutex<MieruAnyWriter>>,
    mut outbound: mpsc::UnboundedReceiver<SessionCommand>,
    reliable: bool,
    mtu: usize,
) {
    let result: Result<()> = async {
        let mut next_seq = if is_client { 0 } else { 1 };
        let mut opened = !is_client;
        let mut unacked = BTreeMap::<u32, MieruSegment>::new();
        let retransmit_interval = Duration::from_millis(PACKET_RETRANSMIT_INTERVAL_MS);
        let mut retransmit = tokio::time::interval_at(
            Instant::now() + retransmit_interval,
            retransmit_interval,
        );
        loop {
            tokio::select! {
                command = outbound.recv() => {
                    let Some(command) = command else {
                        return Ok::<(), anyhow::Error>(());
                    };
                    match command {
                        SessionCommand::Data(payload) => {
                            let max_chunk = if reliable {
                                mtu.checked_sub(PACKET_OVERHEAD)
                                    .filter(|size| *size > 0)
                                    .context("Mieru UDP packet MTU is too small")?
                                    .min(MAX_PDU)
                            } else {
                                MAX_PDU
                            };
                            if is_client && !opened {
                                let can_send_as_open_payload =
                                    payload.len() <= MAX_SESSION_OPEN_PAYLOAD
                                        && payload.len() <= max_chunk;
                                let segment = MieruSegment {
                                    metadata: MieruMetadata::Session(MieruSessionMetadata {
                                        protocol: OPEN_SESSION_REQUEST,
                                        session_id,
                                        seq: next_seq,
                                        status_code: STATUS_OK,
                                        payload_len: 0,
                                        suffix_len: 0,
                                    }),
                                    payload: if can_send_as_open_payload {
                                        payload.clone()
                                    } else {
                                        Vec::new()
                                    },
                                };
                                write_output_segment(&writer, segment, reliable, &mut unacked)
                                    .await?;
                                next_seq = next_seq.wrapping_add(1);
                                opened = true;
                                if can_send_as_open_payload {
                                    continue;
                                }
                            }
                            for chunk in payload.chunks(max_chunk) {
                                let protocol = if is_client {
                                    DATA_CLIENT_TO_SERVER
                                } else {
                                    DATA_SERVER_TO_CLIENT
                                };
                                let segment = MieruSegment {
                                    metadata: MieruMetadata::DataAck(MieruDataAckMetadata {
                                        protocol,
                                        session_id,
                                        seq: next_seq,
                                        un_ack_seq: 0,
                                        window_size: ACK_WINDOW_SIZE,
                                        fragment: 0,
                                        prefix_len: 0,
                                        payload_len: 0,
                                        suffix_len: 0,
                                    }),
                                    payload: chunk.to_vec(),
                                };
                                write_output_segment(&writer, segment, reliable, &mut unacked).await?;
                                next_seq = next_seq.wrapping_add(1);
                            }
                        }
                        SessionCommand::SendSegment(segment) => {
                            write_output_segment(&writer, segment, reliable, &mut unacked).await?;
                        }
                        SessionCommand::SendAck {
                            protocol,
                            un_ack_seq,
                            window_size,
                        } => {
                            writer
                                .lock()
                                .await
                                .write_segment(MieruSegment {
                                    metadata: MieruMetadata::DataAck(MieruDataAckMetadata {
                                        protocol,
                                        session_id,
                                        seq: next_seq.saturating_sub(1),
                                        un_ack_seq,
                                        window_size,
                                        fragment: 0,
                                        prefix_len: 0,
                                        payload_len: 0,
                                        suffix_len: 0,
                                    }),
                                    payload: Vec::new(),
                                })
                                .await?;
                        }
                        SessionCommand::PeerAck { un_ack_seq } => {
                            unacked.retain(|seq, _| *seq >= un_ack_seq);
                        }
                        SessionCommand::Close => {
                            let _ = writer
                                .lock()
                                .await
                                .write_segment(MieruSegment {
                                    metadata: MieruMetadata::Session(MieruSessionMetadata {
                                        protocol: CLOSE_SESSION_REQUEST,
                                        session_id,
                                        seq: next_seq,
                                        status_code: STATUS_OK,
                                        payload_len: 0,
                                        suffix_len: 0,
                                    }),
                                    payload: Vec::new(),
                                })
                                .await;
                            if close_underlay_on_close {
                                let _ = writer.lock().await.shutdown().await;
                            }
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                }
                _ = retransmit.tick(), if reliable && !unacked.is_empty() => {
                    for segment in unacked.values().cloned().collect::<Vec<_>>() {
                        writer.lock().await.write_segment(segment).await?;
                    }
                }
            }
        }
    }
    .await;
    if let Err(error) = result {
        tracing::debug!("Mieru session {session_id} output stopped: {error:?}");
    }
}

async fn write_output_segment(
    writer: &Arc<Mutex<MieruAnyWriter>>,
    segment: MieruSegment,
    reliable: bool,
    unacked: &mut BTreeMap<u32, MieruSegment>,
) -> Result<()> {
    let seq = segment.metadata.seq();
    let should_track = reliable
        && matches!(
            segment.metadata.protocol(),
            OPEN_SESSION_REQUEST
                | OPEN_SESSION_RESPONSE
                | DATA_CLIENT_TO_SERVER
                | DATA_SERVER_TO_CLIENT
        );
    writer.lock().await.write_segment(segment.clone()).await?;
    if should_track {
        unacked.insert(seq, segment);
    }
    Ok(())
}

async fn route_session_segment(
    sessions: &MieruSessionMap,
    segment: MieruSegment,
    ack_protocol: Option<u8>,
) -> Result<()> {
    let session_id = segment.metadata.session_id();
    let seq = segment.metadata.seq();
    let payload = segment.payload;
    let entry = sessions.lock().await.get(&session_id).cloned();
    if let Some(entry) = entry {
        let un_ack_seq = if entry.ordered {
            let mut recv = entry.recv.lock().await;
            if seq == recv.next_seq {
                deliver_session_payload(&entry.inbound, payload);
                recv.next_seq = recv.next_seq.wrapping_add(1);
                loop {
                    let next_seq = recv.next_seq;
                    let Some(payload) = recv.pending.remove(&next_seq) else {
                        break;
                    };
                    deliver_session_payload(&entry.inbound, payload);
                    recv.next_seq = recv.next_seq.wrapping_add(1);
                }
            } else if seq > recv.next_seq {
                recv.pending.entry(seq).or_insert(payload);
            }
            recv.next_seq
        } else {
            deliver_session_payload(&entry.inbound, payload);
            seq.wrapping_add(1)
        };
        if let Some(protocol) = ack_protocol {
            let _ = entry.outbound.send(SessionCommand::SendAck {
                protocol,
                un_ack_seq,
                window_size: ACK_WINDOW_SIZE,
            });
        }
    }
    Ok(())
}

fn deliver_session_payload(sender: &mpsc::UnboundedSender<Vec<u8>>, payload: Vec<u8>) {
    if !payload.is_empty() {
        let _ = sender.send(payload);
    }
}

async fn ack_session_segments(sessions: &MieruSessionMap, session_id: u32, un_ack_seq: u32) {
    let entry = sessions.lock().await.get(&session_id).cloned();
    if let Some(entry) = entry {
        let _ = entry.outbound.send(SessionCommand::PeerAck { un_ack_seq });
    }
}

async fn write_close_response(writer: &Arc<Mutex<MieruAnyWriter>>, session_id: u32) -> Result<()> {
    writer
        .lock()
        .await
        .write_segment(MieruSegment {
            metadata: MieruMetadata::Session(MieruSessionMetadata {
                protocol: CLOSE_SESSION_RESPONSE,
                session_id,
                seq: 0,
                status_code: STATUS_OK,
                payload_len: 0,
                suffix_len: 0,
            }),
            payload: Vec::new(),
        })
        .await
}

async fn handle_mieru_server_socks_session(
    mut session: MieruSession,
    core_session: CoreSession,
) -> Result<()> {
    match read_socks_request(&mut session).await? {
        SocksRequest::Connect(target) => {
            let mut remote = socket_protect::connect_proxy_target(&target).await?;
            let _ = remote.set_nodelay(true);
            let bind = remote.local_addr().unwrap_or_else(|_| unspecified_v4());
            write_socks_reply_with_bind(&mut session, 0, bind).await?;
            tracing::info!("Mieru opened {}", target_name(&target));
            relay_bidirectional_counted(&mut session, &mut remote, core_session, "Mieru").await
        }
        SocksRequest::UdpAssociate => handle_mieru_server_udp(session, core_session).await,
    }
}

async fn handle_mieru_server_udp(
    mut session: MieruSession,
    core_session: CoreSession,
) -> Result<()> {
    let udp = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind Mieru UDP")?,
    );
    write_socks_reply_with_bind(&mut session, 0, udp.local_addr()?).await?;
    let (mut reader, writer) = split(session);
    let writer = Arc::new(Mutex::new(writer));
    let udp_to_remote = {
        let udp = udp.clone();
        let core_session = core_session.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let read = read_packet_over_stream(&mut reader, &mut buffer).await?;
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let target = resolve_target_addr(&target).await?;
                core_session.record_upload(payload.len()).await?;
                udp.send_to(payload, target).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };
    let remote_to_udp = {
        let udp = udp.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                let (read, source) = udp.recv_from(&mut buffer).await?;
                core_session.record_download(read).await?;
                let packet =
                    uot::encode_socks_udp_packet(&ProxyTarget::Ip(source), &buffer[..read])?;
                write_packet_over_stream(&mut *writer.lock().await, &packet).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
    };
    tokio::select! {
        result = udp_to_remote => result,
        result = remote_to_udp => result,
    }
}

fn unspecified_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn random_u32() -> Result<u32> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).context("generate Mieru session ID")?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

    #[test]
    fn metadata_roundtrip() -> Result<()> {
        let metadata = MieruMetadata::DataAck(MieruDataAckMetadata {
            protocol: DATA_CLIENT_TO_SERVER,
            session_id: 7,
            seq: 11,
            un_ack_seq: 3,
            window_size: 16,
            fragment: 0,
            prefix_len: 2,
            payload_len: 5,
            suffix_len: 4,
        });
        let parsed = MieruMetadata::parse(&metadata.marshal()?)?;
        match parsed {
            MieruMetadata::DataAck(parsed) => {
                assert_eq!(parsed.protocol, DATA_CLIENT_TO_SERVER);
                assert_eq!(parsed.session_id, 7);
                assert_eq!(parsed.seq, 11);
                assert_eq!(parsed.un_ack_seq, 3);
                assert_eq!(parsed.window_size, 16);
                assert_eq!(parsed.prefix_len, 2);
                assert_eq!(parsed.payload_len, 5);
                assert_eq!(parsed.suffix_len, 4);
            }
            _ => panic!("unexpected metadata type"),
        }
        Ok(())
    }

    #[test]
    fn parses_traffic_pattern_base64_protobuf() -> Result<()> {
        let bytes = vec![
            0x08, 0x07, 0x10, 0x01, 0x1a, 0x04, 0x08, 0x01, 0x10, 0x0a, 0x22, 0x08, 0x08, 0x02,
            0x10, 0x01, 0x18, 0x05, 0x20, 0x0a,
        ];
        let encoded = BASE64_STANDARD.encode(bytes);
        let pattern = MieruTrafficPattern::parse_pair(Some(&encoded), None)?
            .context("traffic pattern parsed")?;
        let fragment = pattern.tcp_fragment.context("tcp fragment")?;
        assert!(fragment.enable);
        assert_eq!(fragment.max_sleep_ms, 10);
        let nonce = pattern.nonce.context("nonce pattern")?;
        assert_eq!(nonce.kind, MieruNonceType::PrintableSubset);
        assert!(nonce.apply_to_all_udp_packet);
        assert_eq!(nonce.min_len, 5);
        assert_eq!(nonce.max_len, 10);
        Ok(())
    }
}
