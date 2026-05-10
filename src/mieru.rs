use crate::core::{CoreSession, CoreUser, ProxyCore};
use crate::protocol::{ProxyTarget, target_name};
use crate::socket_protect;
use crate::uot;
use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, split};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::time::Instant;

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_MTU: usize = 1500;
const METADATA_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const AEAD_OVERHEAD: usize = 16;
pub const MIERU_KEY_LEN: usize = 32;
const KEY_LEN: usize = MIERU_KEY_LEN;
const KEY_ITER: usize = 64;
const KEY_REFRESH_SECS: u64 = 120;
const MAX_PDU: usize = 32 * 1024;
const MAX_SESSION_OPEN_PAYLOAD: usize = 1024;
const PACKET_METADATA_LEN: usize = NONCE_LEN + METADATA_LEN + AEAD_OVERHEAD;
const PACKET_OVERHEAD: usize = PACKET_METADATA_LEN + AEAD_OVERHEAD;
const ACK_WINDOW_SIZE: u16 = 4096;
const PACKET_RETRANSMIT_INTERVAL_MS: u64 = 250;

const CLOSE_CONN_REQUEST: u8 = 0;
const CLOSE_CONN_RESPONSE: u8 = 1;
const OPEN_SESSION_REQUEST: u8 = 2;
const OPEN_SESSION_RESPONSE: u8 = 3;
const CLOSE_SESSION_REQUEST: u8 = 4;
const CLOSE_SESSION_RESPONSE: u8 = 5;
const DATA_CLIENT_TO_SERVER: u8 = 6;
const DATA_SERVER_TO_CLIENT: u8 = 7;
const ACK_CLIENT_TO_SERVER: u8 = 8;
const ACK_SERVER_TO_CLIENT: u8 = 9;
const STATUS_OK: u8 = 0;

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_NO_AUTH: u8 = 0x00;
const SOCKS_NO_ACCEPTABLE: u8 = 0xff;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

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
    id: u32,
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
struct MieruCipher {
    key: [u8; KEY_LEN],
    implicit_nonce: Option<[u8; NONCE_LEN]>,
    implicit: bool,
    username: String,
}

#[derive(Clone, Debug)]
struct MieruSegment {
    metadata: MieruMetadata,
    payload: Vec<u8>,
}

#[derive(Clone, Debug)]
enum MieruMetadata {
    Session(MieruSessionMetadata),
    DataAck(MieruDataAckMetadata),
}

#[derive(Clone, Debug)]
struct MieruSessionMetadata {
    protocol: u8,
    session_id: u32,
    seq: u32,
    status_code: u8,
    payload_len: u16,
    suffix_len: u8,
}

#[derive(Clone, Debug)]
struct MieruDataAckMetadata {
    protocol: u8,
    session_id: u32,
    seq: u32,
    un_ack_seq: u32,
    window_size: u16,
    fragment: u8,
    prefix_len: u8,
    payload_len: u16,
    suffix_len: u8,
}

#[derive(Clone)]
struct ClientUnderlay {
    writer: Arc<Mutex<MieruAnyWriter>>,
    sessions: MieruSessionMap,
    reliable: bool,
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

impl MieruStreamWriter {
    fn new(inner: OwnedWriteHalf, cipher: Option<MieruCipher>) -> Self {
        Self { inner, cipher }
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
        self.inner
            .write_all(&encrypted_metadata)
            .await
            .context("write Mieru encrypted metadata")?;
        if !segment.payload.is_empty() {
            let encrypted_payload = cipher.encrypt(&segment.payload)?;
            self.inner
                .write_all(&encrypted_payload)
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
        id: u32,
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<SessionCommand>,
    ) -> Self {
        Self {
            id,
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

impl MieruCipher {
    fn new(key: [u8; KEY_LEN], implicit: bool, username: String) -> Self {
        Self {
            key,
            implicit_nonce: None,
            implicit,
            username,
        }
    }

    fn clone_reset_implicit(&self) -> Self {
        Self::new(self.key, true, self.username.clone())
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, send_nonce) = if self.implicit {
            if self.implicit_nonce.is_none() {
                let mut nonce = random_nonce()?;
                add_user_hint_to_nonce(&self.username, &mut nonce);
                self.implicit_nonce = Some(nonce);
                (nonce, true)
            } else {
                self.increase_nonce();
                (self.implicit_nonce.expect("implicit nonce is set"), false)
            }
        } else {
            let mut nonce = random_nonce()?;
            add_user_hint_to_nonce(&self.username, &mut nonce);
            (nonce, true)
        };
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid Mieru XChaCha20-Poly1305 key"))?;
        let mut sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 encrypt failed"))?;
        if send_nonce {
            let mut out = nonce.to_vec();
            out.append(&mut sealed);
            Ok(out)
        } else {
            Ok(sealed)
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, payload) = if self.implicit {
            if self.implicit_nonce.is_none() {
                ensure!(
                    ciphertext.len() >= NONCE_LEN,
                    "Mieru ciphertext is shorter than nonce"
                );
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&ciphertext[..NONCE_LEN]);
                self.implicit_nonce = Some(nonce);
                (nonce, &ciphertext[NONCE_LEN..])
            } else {
                self.increase_nonce();
                (
                    self.implicit_nonce.expect("implicit nonce is set"),
                    ciphertext,
                )
            }
        } else {
            ensure!(
                ciphertext.len() >= NONCE_LEN,
                "Mieru ciphertext is shorter than nonce"
            );
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&ciphertext[..NONCE_LEN]);
            (nonce, &ciphertext[NONCE_LEN..])
        };
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid Mieru XChaCha20-Poly1305 key"))?;
        cipher
            .decrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 decrypt failed"))
    }

    fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        ensure!(nonce.len() == NONCE_LEN, "invalid Mieru nonce length");
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid Mieru XChaCha20-Poly1305 key"))?;
        cipher
            .encrypt(XNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 encrypt failed"))
    }

    fn decrypt_with_nonce(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        ensure!(nonce.len() == NONCE_LEN, "invalid Mieru nonce length");
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid Mieru XChaCha20-Poly1305 key"))?;
        cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 decrypt failed"))
    }

    fn increase_nonce(&mut self) {
        let nonce = self
            .implicit_nonce
            .as_mut()
            .expect("implicit nonce must exist before increment");
        for byte in nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}

impl MieruMetadata {
    fn protocol(&self) -> u8 {
        match self {
            Self::Session(metadata) => metadata.protocol,
            Self::DataAck(metadata) => metadata.protocol,
        }
    }

    fn session_id(&self) -> u32 {
        match self {
            Self::Session(metadata) => metadata.session_id,
            Self::DataAck(metadata) => metadata.session_id,
        }
    }

    fn seq(&self) -> u32 {
        match self {
            Self::Session(metadata) => metadata.seq,
            Self::DataAck(metadata) => metadata.seq,
        }
    }

    fn un_ack_seq(&self) -> Option<u32> {
        match self {
            Self::DataAck(metadata) => Some(metadata.un_ack_seq),
            Self::Session(_) => None,
        }
    }

    fn marshal(&self) -> Result<[u8; METADATA_LEN]> {
        let mut bytes = [0u8; METADATA_LEN];
        let timestamp = unix_minutes()?;
        match self {
            Self::Session(metadata) => {
                bytes[0] = metadata.protocol;
                bytes[2..6].copy_from_slice(&timestamp.to_be_bytes());
                bytes[6..10].copy_from_slice(&metadata.session_id.to_be_bytes());
                bytes[10..14].copy_from_slice(&metadata.seq.to_be_bytes());
                bytes[14] = metadata.status_code;
                bytes[15..17].copy_from_slice(&metadata.payload_len.to_be_bytes());
                bytes[17] = metadata.suffix_len;
            }
            Self::DataAck(metadata) => {
                bytes[0] = metadata.protocol;
                bytes[2..6].copy_from_slice(&timestamp.to_be_bytes());
                bytes[6..10].copy_from_slice(&metadata.session_id.to_be_bytes());
                bytes[10..14].copy_from_slice(&metadata.seq.to_be_bytes());
                bytes[14..18].copy_from_slice(&metadata.un_ack_seq.to_be_bytes());
                bytes[18..20].copy_from_slice(&metadata.window_size.to_be_bytes());
                bytes[20] = metadata.fragment;
                bytes[21] = metadata.prefix_len;
                bytes[22..24].copy_from_slice(&metadata.payload_len.to_be_bytes());
                bytes[24] = metadata.suffix_len;
            }
        }
        Ok(bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == METADATA_LEN, "invalid Mieru metadata length");
        let timestamp = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let now = unix_minutes()?;
        ensure!(
            now.abs_diff(timestamp) <= 1,
            "Mieru metadata timestamp is outside accepted window"
        );
        match bytes[0] {
            OPEN_SESSION_REQUEST
            | OPEN_SESSION_RESPONSE
            | CLOSE_SESSION_REQUEST
            | CLOSE_SESSION_RESPONSE
            | CLOSE_CONN_REQUEST
            | CLOSE_CONN_RESPONSE => {
                let payload_len = u16::from_be_bytes([bytes[15], bytes[16]]);
                ensure!(
                    payload_len as usize <= MAX_SESSION_OPEN_PAYLOAD
                        || bytes[0] != OPEN_SESSION_REQUEST,
                    "Mieru open-session payload is too large"
                );
                Ok(Self::Session(MieruSessionMetadata {
                    protocol: bytes[0],
                    session_id: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
                    seq: u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
                    status_code: bytes[14],
                    payload_len,
                    suffix_len: bytes[17],
                }))
            }
            DATA_CLIENT_TO_SERVER
            | DATA_SERVER_TO_CLIENT
            | ACK_CLIENT_TO_SERVER
            | ACK_SERVER_TO_CLIENT => Ok(Self::DataAck(MieruDataAckMetadata {
                protocol: bytes[0],
                session_id: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
                seq: u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
                un_ack_seq: u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]),
                window_size: u16::from_be_bytes([bytes[18], bytes[19]]),
                fragment: bytes[20],
                prefix_len: bytes[21],
                payload_len: u16::from_be_bytes([bytes[22], bytes[23]]),
                suffix_len: bytes[24],
            })),
            other => bail!("unsupported Mieru metadata protocol {other}"),
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
    loop {
        let (stream, peer) = listener.accept().await.context("accept SOCKS client")?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_mieru_socks_client(stream, config).await {
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
    let users = config.effective_users();
    ensure!(!users.is_empty(), "Mieru server has no configured users");
    if config.transport == MieruTransport::Udp {
        return run_mieru_packet_server(config, core, users).await;
    }
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Mieru server on {}", config.listen))?;
    tracing::info!("Mieru server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await.context("accept Mieru client")?;
        let users = users.clone();
        let core = core.clone();
        let mtu = config.mtu();
        let user_hint_mandatory = config.user_hint_mandatory;
        tokio::spawn(async move {
            if let Err(error) =
                handle_mieru_underlay_server(stream, users, core, mtu, user_hint_mandatory, peer)
                    .await
            {
                tracing::warn!("Mieru underlay {peer} failed: {error:?}");
            }
        });
    }
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

async fn handle_mieru_socks_client(mut local: TcpStream, config: MieruClientConfig) -> Result<()> {
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
    let mut session = dial_mieru_session(&config).await?;
    session.write_all(&greeting).await?;
    let mut remote_greeting = [0u8; 2];
    session
        .read_exact(&mut remote_greeting)
        .await
        .context("read remote SOCKS greeting response")?;
    ensure!(
        remote_greeting == [SOCKS_VERSION, SOCKS_NO_AUTH],
        "remote Mieru SOCKS server rejected no-auth method"
    );
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

async fn dial_mieru_session(config: &MieruClientConfig) -> Result<MieruSession> {
    let underlay = connect_mieru_underlay(config).await?;
    underlay.open_session(config.mtu()).await
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
    let send = MieruCipher::new(key, true, config.username.clone());
    let recv = MieruCipher::new(key, true, config.username.clone());
    let writer = Arc::new(Mutex::new(MieruAnyWriter::Stream(MieruStreamWriter::new(
        writer,
        Some(send),
    ))));
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(run_mieru_client_read_loop(
        reader,
        recv,
        writer.clone(),
        sessions.clone(),
    ));
    Ok(ClientUnderlay {
        writer,
        sessions,
        reliable: false,
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
    let send = MieruCipher::new(key, false, config.username.clone());
    let recv = MieruCipher::new(key, false, config.username.clone());
    let mtu = config.mtu();
    let writer = Arc::new(Mutex::new(MieruAnyWriter::Packet(MieruPacketWriter::new(
        socket.clone(),
        server_addr,
        send,
        mtu,
    ))));
    let sessions = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(run_mieru_packet_client_read_loop(
        socket,
        server_addr,
        recv,
        writer.clone(),
        sessions.clone(),
    ));
    Ok(ClientUnderlay {
        writer,
        sessions,
        reliable: true,
    })
}

impl ClientUnderlay {
    async fn open_session(&self, mtu: usize) -> Result<MieruSession> {
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
            true,
            self.writer.clone(),
            outbound_rx,
            self.reliable,
            mtu,
        ));
        Ok(MieruSession::new(session_id, inbound_rx, outbound_tx))
    }
}

async fn handle_mieru_underlay_server(
    stream: TcpStream,
    users: Vec<MieruUserSecret>,
    core: ProxyCore,
    mtu: usize,
    user_hint_mandatory: bool,
    peer: SocketAddr,
) -> Result<()> {
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(MieruAnyWriter::Stream(MieruStreamWriter::new(
        writer, None,
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
        peer,
    )
    .await
}

async fn run_mieru_client_read_loop(
    mut reader: OwnedReadHalf,
    mut recv: MieruCipher,
    writer: Arc<Mutex<MieruAnyWriter>>,
    sessions: MieruSessionMap,
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
        tracing::debug!("Mieru client read loop stopped: {error:?}");
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
    peer: SocketAddr,
) -> Result<()> {
    let mut recv = None::<MieruCipher>;
    let mut user = None::<MieruUserSecret>;
    loop {
        if recv.is_none() {
            let (cipher, matched_user, segment) =
                read_first_server_segment(&mut reader, &users, user_hint_mandatory).await?;
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
        tracing::debug!("Mieru UDP client read loop stopped: {error:?}");
    }
}

async fn run_mieru_packet_server(
    config: MieruServerConfig,
    core: ProxyCore,
    users: Vec<MieruUserSecret>,
) -> Result<()> {
    let mtu = config.mtu();
    ensure!(
        mtu > PACKET_OVERHEAD,
        "Mieru UDP packet MTU must be larger than {PACKET_OVERHEAD}"
    );
    let socket = Arc::new(
        UdpSocket::bind(config.listen)
            .await
            .with_context(|| format!("bind Mieru UDP server on {}", config.listen))?,
    );
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
            let session = MieruSession::new(session_id, inbound_rx, outbound_tx);
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
                            if is_client && !opened {
                                let segment = MieruSegment {
                                    metadata: MieruMetadata::Session(MieruSessionMetadata {
                                        protocol: OPEN_SESSION_REQUEST,
                                        session_id,
                                        seq: next_seq,
                                        status_code: STATUS_OK,
                                        payload_len: 0,
                                        suffix_len: 0,
                                    }),
                                    payload: Vec::new(),
                                };
                                write_output_segment(&writer, segment, reliable, &mut unacked).await?;
                                next_seq = next_seq.wrapping_add(1);
                                opened = true;
                            }
                            let max_chunk = if reliable {
                                mtu.checked_sub(PACKET_OVERHEAD)
                                    .filter(|size| *size > 0)
                                    .context("Mieru UDP packet MTU is too small")?
                                    .min(MAX_PDU)
                            } else {
                                MAX_PDU
                            };
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

async fn read_first_server_segment<R>(
    reader: &mut R,
    users: &[MieruUserSecret],
    user_hint_mandatory: bool,
) -> Result<(MieruCipher, MieruUserSecret, MieruSegment)>
where
    R: AsyncRead + Unpin,
{
    let mut encrypted_metadata = vec![0u8; NONCE_LEN + METADATA_LEN + AEAD_OVERHEAD];
    reader
        .read_exact(&mut encrypted_metadata)
        .await
        .context("read first Mieru metadata")?;
    let nonce = &encrypted_metadata[..NONCE_LEN];
    let mut candidates = Vec::new();
    for user in users {
        if check_user_from_hint(user.username.as_bytes(), nonce) {
            candidates.push(user.clone());
        }
    }
    if candidates.is_empty() && user_hint_mandatory {
        bail!("Mieru user hint did not match any configured user");
    }
    if !user_hint_mandatory {
        for user in users {
            if !candidates
                .iter()
                .any(|candidate| candidate.username == user.username)
            {
                candidates.push(user.clone());
            }
        }
    }
    for user in candidates {
        for key in mieru_keys_for_password(&user.hashed_password)? {
            let mut stateless = MieruCipher::new(key, false, user.username.clone());
            if stateless.decrypt(&encrypted_metadata).is_err() {
                continue;
            }
            let mut stateful = MieruCipher::new(key, true, user.username.clone());
            let plain = stateful.decrypt(&encrypted_metadata)?;
            let metadata = MieruMetadata::parse(&plain)?;
            let payload = read_mieru_payload(reader, &metadata, &mut stateful).await?;
            return Ok((stateful, user, MieruSegment { metadata, payload }));
        }
    }
    bail!("Mieru authentication failed")
}

async fn read_mieru_segment<R>(
    reader: &mut R,
    cipher: &mut MieruCipher,
    first_read: bool,
) -> Result<MieruSegment>
where
    R: AsyncRead + Unpin,
{
    let read_len = METADATA_LEN + AEAD_OVERHEAD + if first_read { NONCE_LEN } else { 0 };
    let mut encrypted_metadata = vec![0u8; read_len];
    reader
        .read_exact(&mut encrypted_metadata)
        .await
        .context("read Mieru encrypted metadata")?;
    let plain = cipher.decrypt(&encrypted_metadata)?;
    let metadata = MieruMetadata::parse(&plain)?;
    let payload = read_mieru_payload(reader, &metadata, cipher).await?;
    Ok(MieruSegment { metadata, payload })
}

async fn read_mieru_payload<R>(
    reader: &mut R,
    metadata: &MieruMetadata,
    cipher: &mut MieruCipher,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    match metadata {
        MieruMetadata::Session(metadata) => {
            let mut payload = Vec::new();
            if metadata.payload_len > 0 {
                let mut encrypted_payload =
                    vec![0u8; metadata.payload_len as usize + AEAD_OVERHEAD];
                reader
                    .read_exact(&mut encrypted_payload)
                    .await
                    .context("read Mieru session payload")?;
                payload = cipher.decrypt(&encrypted_payload)?;
            }
            if metadata.suffix_len > 0 {
                let mut padding = vec![0u8; metadata.suffix_len as usize];
                reader
                    .read_exact(&mut padding)
                    .await
                    .context("read Mieru session suffix padding")?;
            }
            Ok(payload)
        }
        MieruMetadata::DataAck(metadata) => {
            if metadata.prefix_len > 0 {
                let mut padding = vec![0u8; metadata.prefix_len as usize];
                reader
                    .read_exact(&mut padding)
                    .await
                    .context("read Mieru data prefix padding")?;
            }
            let mut payload = Vec::new();
            if metadata.payload_len > 0 {
                let mut encrypted_payload =
                    vec![0u8; metadata.payload_len as usize + AEAD_OVERHEAD];
                reader
                    .read_exact(&mut encrypted_payload)
                    .await
                    .context("read Mieru data payload")?;
                payload = cipher.decrypt(&encrypted_payload)?;
            }
            if metadata.suffix_len > 0 {
                let mut padding = vec![0u8; metadata.suffix_len as usize];
                reader
                    .read_exact(&mut padding)
                    .await
                    .context("read Mieru data suffix padding")?;
            }
            Ok(payload)
        }
    }
}

fn encode_mieru_packet_segment(
    cipher: &mut MieruCipher,
    mut segment: MieruSegment,
    mtu: usize,
) -> Result<Vec<u8>> {
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
    ensure!(
        encrypted_metadata.len() == PACKET_METADATA_LEN,
        "invalid Mieru encrypted packet metadata length"
    );
    let nonce = encrypted_metadata[..NONCE_LEN].to_vec();
    let mut packet = encrypted_metadata;
    if !segment.payload.is_empty() {
        let encrypted_payload = cipher.encrypt_with_nonce(&segment.payload, &nonce)?;
        packet.extend_from_slice(&encrypted_payload);
    }
    ensure!(
        packet.len() <= mtu,
        "Mieru UDP packet length {} exceeds MTU {}",
        packet.len(),
        mtu
    );
    Ok(packet)
}

fn decode_mieru_packet_segment(cipher: &mut MieruCipher, packet: &[u8]) -> Result<MieruSegment> {
    ensure!(
        packet.len() >= PACKET_METADATA_LEN,
        "Mieru UDP packet is shorter than encrypted metadata"
    );
    let encrypted_metadata = &packet[..PACKET_METADATA_LEN];
    let nonce = &encrypted_metadata[..NONCE_LEN];
    let plain = cipher.decrypt(encrypted_metadata)?;
    let metadata = MieruMetadata::parse(&plain)?;
    let payload =
        decode_mieru_packet_payload(cipher, &metadata, nonce, &packet[PACKET_METADATA_LEN..])?;
    Ok(MieruSegment { metadata, payload })
}

fn decode_mieru_packet_segment_for_server(
    packet: &[u8],
    users: &[MieruUserSecret],
    user_hint_mandatory: bool,
) -> Result<(MieruSegment, MieruUserSecret, MieruCipher)> {
    ensure!(
        packet.len() >= PACKET_METADATA_LEN,
        "Mieru UDP packet is shorter than encrypted metadata"
    );
    let nonce = &packet[..NONCE_LEN];
    let mut candidates = Vec::new();
    for user in users {
        if check_user_from_hint(user.username.as_bytes(), nonce) {
            candidates.push(user.clone());
        }
    }
    if candidates.is_empty() && user_hint_mandatory {
        bail!("Mieru UDP user hint did not match any configured user");
    }
    if !user_hint_mandatory {
        for user in users {
            if !candidates
                .iter()
                .any(|candidate| candidate.username == user.username)
            {
                candidates.push(user.clone());
            }
        }
    }
    for user in candidates {
        for key in mieru_keys_for_password(&user.hashed_password)? {
            let mut cipher = MieruCipher::new(key, false, user.username.clone());
            if let Ok(segment) = decode_mieru_packet_segment(&mut cipher, packet) {
                return Ok((segment, user, cipher));
            }
        }
    }
    bail!("Mieru UDP authentication failed")
}

fn decode_mieru_packet_payload(
    cipher: &MieruCipher,
    metadata: &MieruMetadata,
    nonce: &[u8],
    mut remaining: &[u8],
) -> Result<Vec<u8>> {
    match metadata {
        MieruMetadata::Session(metadata) => {
            let mut payload = Vec::new();
            if metadata.payload_len > 0 {
                let encrypted_len = metadata.payload_len as usize + AEAD_OVERHEAD;
                ensure!(
                    remaining.len() >= encrypted_len,
                    "Mieru UDP session payload is incomplete"
                );
                payload = cipher.decrypt_with_nonce(&remaining[..encrypted_len], nonce)?;
                remaining = &remaining[encrypted_len..];
            }
            ensure!(
                remaining.len() == metadata.suffix_len as usize,
                "Mieru UDP session padding size mismatch"
            );
            Ok(payload)
        }
        MieruMetadata::DataAck(metadata) => {
            ensure!(
                remaining.len() >= metadata.prefix_len as usize,
                "Mieru UDP data prefix padding is incomplete"
            );
            remaining = &remaining[metadata.prefix_len as usize..];
            let mut payload = Vec::new();
            if metadata.payload_len > 0 {
                let encrypted_len = metadata.payload_len as usize + AEAD_OVERHEAD;
                ensure!(
                    remaining.len() >= encrypted_len,
                    "Mieru UDP data payload is incomplete"
                );
                payload = cipher.decrypt_with_nonce(&remaining[..encrypted_len], nonce)?;
                remaining = &remaining[encrypted_len..];
            }
            ensure!(
                remaining.len() == metadata.suffix_len as usize,
                "Mieru UDP data padding size mismatch"
            );
            Ok(payload)
        }
    }
}

async fn handle_mieru_server_socks_session(
    mut session: MieruSession,
    core_session: CoreSession,
) -> Result<()> {
    read_socks_greeting_and_reply(&mut session).await?;
    match read_socks_request(&mut session).await? {
        SocksRequest::Connect(target) => {
            let mut remote = connect_target(&target).await?;
            let bind = remote.local_addr().unwrap_or_else(|_| unspecified_v4());
            write_socks_reply_with_bind(&mut session, 0, bind).await?;
            tracing::info!("Mieru opened {}", target_name(&target));
            relay_counted(&mut session, &mut remote, core_session).await
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
                let target = target_socket_addr(&target).await?;
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

async fn relay_counted<A, B>(left: &mut A, right: &mut B, session: CoreSession) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut lr, mut lw) = split(left);
    let (mut rr, mut rw) = split(right);
    let upload_session = session.clone();
    let upload = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = lr.read(&mut buffer).await?;
            if read == 0 {
                let _ = rw.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            upload_session.record_upload(read).await?;
            rw.write_all(&buffer[..read]).await?;
        }
    };
    let download = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = rr.read(&mut buffer).await?;
            if read == 0 {
                let _ = lw.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }
            session.record_download(read).await?;
            lw.write_all(&buffer[..read]).await?;
        }
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn read_socks_greeting_and_reply<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let greeting = read_socks_greeting(stream).await?;
    if greeting[2..].contains(&SOCKS_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).await?;
        Ok(())
    } else {
        stream
            .write_all(&[SOCKS_VERSION, SOCKS_NO_ACCEPTABLE])
            .await?;
        bail!("SOCKS client did not offer no-auth method")
    }
}

async fn read_socks_greeting<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    ensure!(header[0] == SOCKS_VERSION, "unsupported SOCKS version");
    let mut methods = vec![0u8; header[1] as usize];
    reader.read_exact(&mut methods).await?;
    let mut out = header.to_vec();
    out.extend_from_slice(&methods);
    Ok(out)
}

enum SocksRequest {
    Connect(ProxyTarget),
    UdpAssociate,
}

async fn read_socks_request<S>(stream: &mut S) -> Result<SocksRequest>
where
    S: AsyncRead + Unpin,
{
    let request = read_socks_request_raw(stream).await?;
    let target = parse_socks_target_from_request(&request)?;
    match request[1] {
        SOCKS_CMD_CONNECT => Ok(SocksRequest::Connect(target)),
        SOCKS_CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate),
        other => bail!("unsupported SOCKS command {other:#x}"),
    }
}

async fn read_socks_request_raw<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    ensure!(header[0] == SOCKS_VERSION, "invalid SOCKS request version");
    let mut out = header.to_vec();
    read_socks_address_raw(reader, header[3], &mut out).await?;
    Ok(out)
}

async fn read_socks_response_raw<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    ensure!(header[0] == SOCKS_VERSION, "invalid SOCKS response version");
    let mut out = header.to_vec();
    read_socks_address_raw(reader, header[3], &mut out).await?;
    Ok(out)
}

async fn read_socks_address_raw<R>(reader: &mut R, atyp: u8, out: &mut Vec<u8>) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut rest = [0u8; 6];
            reader.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            out.push(len[0]);
            let mut rest = vec![0u8; len[0] as usize + 2];
            reader.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        SOCKS_ATYP_IPV6 => {
            let mut rest = [0u8; 18];
            reader.read_exact(&mut rest).await?;
            out.extend_from_slice(&rest);
        }
        other => bail!("unsupported SOCKS address type {other:#x}"),
    }
    Ok(())
}

fn parse_socks_target_from_request(request: &[u8]) -> Result<ProxyTarget> {
    ensure!(request.len() >= 4, "SOCKS request is too short");
    parse_socks_address(&request[3..]).map(|(target, _)| target)
}

fn parse_socks_address(packet: &[u8]) -> Result<(ProxyTarget, &[u8])> {
    ensure!(!packet.is_empty(), "SOCKS address is empty");
    match packet[0] {
        SOCKS_ATYP_IPV4 => {
            ensure!(packet.len() >= 7, "SOCKS IPv4 address is too short");
            let ip = Ipv4Addr::new(packet[1], packet[2], packet[3], packet[4]);
            let port = u16::from_be_bytes([packet[5], packet[6]]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(ip), port)),
                &packet[7..],
            ))
        }
        SOCKS_ATYP_DOMAIN => {
            ensure!(packet.len() >= 2, "SOCKS domain address is too short");
            let length = packet[1] as usize;
            let port_offset = 2 + length;
            ensure!(packet.len() >= port_offset + 2, "SOCKS domain missing port");
            let host = String::from_utf8(packet[2..port_offset].to_vec())?;
            let port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
            Ok((ProxyTarget::Domain(host, port), &packet[port_offset + 2..]))
        }
        SOCKS_ATYP_IPV6 => {
            ensure!(packet.len() >= 19, "SOCKS IPv6 address is too short");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[1..17]);
            let port = u16::from_be_bytes([packet[17], packet[18]]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                &packet[19..],
            ))
        }
        other => bail!("unsupported SOCKS address type {other:#x}"),
    }
}

async fn write_socks_reply_with_bind<W>(writer: &mut W, code: u8, bind: SocketAddr) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut response = vec![SOCKS_VERSION, code, 0];
    match bind {
        SocketAddr::V4(addr) => {
            response.push(SOCKS_ATYP_IPV4);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            response.push(SOCKS_ATYP_IPV6);
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    writer.write_all(&response).await?;
    Ok(())
}

async fn read_packet_over_stream<R>(reader: &mut R, payload: &mut [u8]) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 1];
    reader.read_exact(&mut prefix).await?;
    ensure!(prefix[0] == 0x00, "invalid packet-over-stream prefix");
    let mut length = [0u8; 2];
    reader.read_exact(&mut length).await?;
    let length = u16::from_be_bytes(length) as usize;
    ensure!(
        payload.len() >= length,
        "packet-over-stream output buffer is too small"
    );
    reader.read_exact(&mut payload[..length]).await?;
    let mut suffix = [0u8; 1];
    reader.read_exact(&mut suffix).await?;
    ensure!(suffix[0] == 0xff, "invalid packet-over-stream suffix");
    Ok(length)
}

async fn write_packet_over_stream<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    ensure!(
        payload.len() <= u16::MAX as usize,
        "packet-over-stream payload is too large"
    );
    writer.write_all(&[0x00]).await?;
    writer
        .write_all(&(payload.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.write_all(&[0xff]).await?;
    writer.flush().await?;
    Ok(())
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

fn unspecified_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn hash_mieru_password(raw_password: &[u8], unique_value: &[u8]) -> [u8; KEY_LEN] {
    let mut input = Vec::with_capacity(raw_password.len() + 1 + unique_value.len());
    input.extend_from_slice(raw_password);
    input.push(0);
    input.extend_from_slice(unique_value);
    Sha256::digest(&input).into()
}

fn current_mieru_key(hashed_password: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN]> {
    let keys = mieru_keys_for_password(hashed_password)?;
    Ok(keys[1])
}

fn mieru_keys_for_password(hashed_password: &[u8; KEY_LEN]) -> Result<Vec<[u8; KEY_LEN]>> {
    let mut keys = Vec::with_capacity(3);
    for salt in salt_from_time(SystemTime::now())? {
        let key = pbkdf2_hmac_sha256(hashed_password, &salt, KEY_ITER, KEY_LEN)?;
        let mut key_array = [0u8; KEY_LEN];
        key_array.copy_from_slice(&key);
        keys.push(key_array);
    }
    Ok(keys)
}

fn salt_from_time(time: SystemTime) -> Result<[[u8; KEY_LEN]; 3]> {
    let seconds = time.duration_since(UNIX_EPOCH)?.as_secs();
    let rounded = ((seconds + KEY_REFRESH_SECS / 2) / KEY_REFRESH_SECS) * KEY_REFRESH_SECS;
    let times = [
        rounded.saturating_sub(KEY_REFRESH_SECS),
        rounded,
        rounded + KEY_REFRESH_SECS,
    ];
    let mut salts = [[0u8; KEY_LEN]; 3];
    for (salt, unix) in salts.iter_mut().zip(times) {
        let digest = Sha256::digest(unix.to_be_bytes());
        salt.copy_from_slice(&digest);
    }
    Ok(salts)
}

fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    key_len: usize,
) -> Result<Vec<u8>> {
    ensure!(!password.is_empty(), "Mieru password is empty");
    let blocks = key_len.div_ceil(KEY_LEN);
    let mut derived = Vec::with_capacity(blocks * KEY_LEN);
    for block_index in 1..=blocks {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(password)?;
        mac.update(salt);
        mac.update(&(block_index as u32).to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(password)?;
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (left, right) in t.iter_mut().zip(&u) {
                *left ^= *right;
            }
        }
        derived.extend_from_slice(&t);
    }
    derived.truncate(key_len);
    Ok(derived)
}

fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).context("generate Mieru nonce")?;
    Ok(nonce)
}

fn random_u32() -> Result<u32> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).context("generate Mieru session ID")?;
    Ok(u32::from_be_bytes(bytes))
}

fn add_user_hint_to_nonce(username: &str, nonce: &mut [u8; NONCE_LEN]) {
    if username.is_empty() {
        return;
    }
    let mut input = Vec::with_capacity(username.len() + 16);
    input.extend_from_slice(username.as_bytes());
    input.extend_from_slice(&nonce[..16]);
    let digest = Sha256::digest(&input);
    nonce[20..24].copy_from_slice(&digest[..4]);
}

fn check_user_from_hint(username: &[u8], nonce: &[u8]) -> bool {
    if username.is_empty() || nonce.len() < 20 {
        return false;
    }
    let mut input = Vec::with_capacity(username.len() + 16);
    input.extend_from_slice(username);
    input.extend_from_slice(&nonce[..16]);
    let digest = Sha256::digest(&input);
    digest[..4].eq(&nonce[nonce.len() - 4..])
}

fn unix_minutes() -> Result<u32> {
    Ok((SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 60) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_uses_username_separator() {
        let hash1 = hash_mieru_password(b"password", b"alice");
        let hash2 = hash_mieru_password(b"passwordalice", b"");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn pbkdf2_vector_matches_rfc6070_shape() -> Result<()> {
        let key = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)?;
        assert_eq!(
            hex::encode(key),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        Ok(())
    }

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
    fn implicit_cipher_roundtrip() -> Result<()> {
        let hashed = hash_mieru_password(b"secret", b"user");
        let key = current_mieru_key(&hashed)?;
        let mut send = MieruCipher::new(key, true, "user".to_string());
        let mut recv = MieruCipher::new(key, true, "user".to_string());
        for payload in [
            b"hello".as_slice(),
            b"world".as_slice(),
            b"mieru".as_slice(),
        ] {
            let encrypted = send.encrypt(payload)?;
            let decrypted = recv.decrypt(&encrypted)?;
            assert_eq!(decrypted, payload);
        }
        Ok(())
    }

    #[test]
    fn user_hint_matches_nonce() -> Result<()> {
        let mut nonce = random_nonce()?;
        add_user_hint_to_nonce("alice", &mut nonce);
        assert!(check_user_from_hint(b"alice", &nonce));
        assert!(!check_user_from_hint(b"bob", &nonce));
        Ok(())
    }
}
