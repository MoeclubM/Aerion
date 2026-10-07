//! SUDOKU-ASCII KIP proxy. Authentication uses independently verified PSKs;
//! the client-provided UserHash is metadata, never an authentication decision.
mod record;
mod table;
mod transport;

use crate::core::{CoreSession, ProxyCore};
use crate::protocol::ProxyTarget;
use crate::relay::relay_bidirectional_half_closed_counted;
use crate::{socket_protect, socks, uot};
use anyhow::{Context, Result, bail, ensure};
use record::{Receiver, Sender, bases};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use table::Table;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SudokuOptions {
    #[serde(alias = "aead-method")]
    pub aead: String,
    #[serde(alias = "table-type", alias = "ascii")]
    pub table_type: String,
    #[serde(alias = "padding-min")]
    pub padding_min: u8,
    #[serde(alias = "padding-max")]
    pub padding_max: u8,
    #[serde(alias = "enable-pure-downlink")]
    pub enable_pure_downlink: bool,
    #[serde(alias = "custom-table")]
    pub custom_table: String,
    #[serde(alias = "custom-tables")]
    pub custom_tables: Vec<String>,
    #[serde(alias = "http-mask-multiplex")]
    pub multiplex: String,
    #[serde(alias = "http-mask")]
    pub http_mask: bool,
    #[serde(alias = "http-mask-mode")]
    pub http_mask_mode: String,
    #[serde(alias = "http-mask-tls")]
    pub http_mask_tls: bool,
    #[serde(alias = "http-mask-host")]
    pub http_mask_host: String,
    #[serde(alias = "path-root")]
    pub path_root: String,
}
impl Default for SudokuOptions {
    fn default() -> Self {
        Self {
            aead: "chacha20-poly1305".into(),
            table_type: "prefer_entropy".into(),
            padding_min: 5,
            padding_max: 15,
            enable_pure_downlink: false,
            custom_table: String::new(),
            custom_tables: Vec::new(),
            multiplex: "off".into(),
            http_mask: false,
            http_mask_mode: "legacy".into(),
            http_mask_tls: false,
            http_mask_host: String::new(),
            path_root: String::new(),
        }
    }
}
impl SudokuOptions {
    pub fn validate(&self) -> Result<()> {
        self.tables("sudoku-options-validation")?;
        ensure!(
            !self.http_mask_host.contains(['\r', '\n']),
            "invalid Sudoku HTTPMask host"
        );
        ensure!(
            self.path_root
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')),
            "invalid Sudoku HTTPMask path root"
        );
        ensure!(
            matches!(self.aead.as_str(), "chacha20-poly1305" | "aes-128-gcm"),
            "Sudoku requires authenticated AEAD (chacha20-poly1305 or aes-128-gcm)"
        );
        ensure!(
            self.padding_min <= self.padding_max && self.padding_max <= 100,
            "invalid Sudoku padding range"
        );
        ensure!(
            matches!(self.multiplex.as_str(), "off" | "on" | "auto"),
            "invalid Sudoku multiplex mode"
        );
        ensure!(
            !self.http_mask_tls || self.http_mask,
            "Sudoku HTTPMask TLS requires HTTPMask"
        );
        ensure!(
            !self.http_mask || matches!(self.http_mask_mode.as_str(), "legacy" | "ws"),
            "Aerion Sudoku HTTPMask supports legacy and ws; stream/poll require a separate HTTP session transport"
        );
        Ok(())
    }
    fn patterns(&self) -> Vec<String> {
        if self.custom_tables.is_empty() {
            vec![self.custom_table.clone()]
        } else {
            self.custom_tables.clone()
        }
    }
    fn tables(&self, key: &str) -> Result<Vec<Table>> {
        self.patterns()
            .iter()
            .map(|pattern| Table::new(key, &self.table_type, pattern))
            .collect()
    }
    fn padding(&self) -> Result<u8> {
        let mut random = [0];
        getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("Sudoku padding random: {e}"))?;
        Ok(self.padding_min + random[0] % (self.padding_max - self.padding_min + 1))
    }
}

#[derive(Clone, Debug)]
pub struct SudokuClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub key: String,
    pub options: SudokuOptions,
}
#[derive(Clone, Debug)]
pub struct SudokuServerConfig {
    pub listen: SocketAddr,
    pub key: String,
    pub users: Vec<String>,
    pub options: SudokuOptions,
}

fn timestamp() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn secret() -> Result<StaticSecret> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("Sudoku ECDH random: {e}"))?;
    Ok(StaticSecret::from(bytes))
}

/// Canonicalize official scalar/split keys while preserving ordinary PSKs.
pub fn sudoku_key_seed(key: &str) -> Result<String> {
    use curve25519_dalek::{
        constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    };
    let key = key.trim();
    ensure!(!key.is_empty(), "Sudoku key is empty");
    let Ok(raw) = hex::decode(key) else {
        return Ok(key.into());
    };
    if raw.len() == 32 {
        let bytes: [u8; 32] = raw.try_into().unwrap();
        if let Some(point) = CompressedEdwardsY(bytes).decompress() {
            return Ok(hex::encode(point.compress().as_bytes()));
        }
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)) {
            return Ok(hex::encode(
                (scalar * ED25519_BASEPOINT_POINT).compress().as_bytes(),
            ));
        }
    } else if raw.len() == 64 {
        let r = Option::<Scalar>::from(Scalar::from_canonical_bytes(raw[..32].try_into()?))
            .context("invalid Sudoku split scalar")?;
        let k = Option::<Scalar>::from(Scalar::from_canonical_bytes(raw[32..].try_into()?))
            .context("invalid Sudoku split scalar")?;
        return Ok(hex::encode(
            ((r + k) * ED25519_BASEPOINT_POINT).compress().as_bytes(),
        ));
    }
    Ok(key.into())
}

async fn client_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    key: &str,
    options: &SudokuOptions,
) -> Result<(Receiver, Sender)> {
    let seed = sudoku_key_seed(key)?;
    let tables = options.tables(&seed)?;
    let mut random = [0; 17];
    getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("Sudoku handshake random: {e}"))?;
    let table = tables[random[16] as usize % tables.len()].clone();
    let ephemeral = secret()?;
    let (up, down) = bases(&seed, None, &[])?;
    let mut receiver = Receiver::new(
        table.clone(),
        true,
        !options.enable_pure_downlink,
        down,
        &options.aead,
    );
    let mut sender = Sender::new(
        table.clone(),
        false,
        false,
        up,
        &options.aead,
        options.padding()?,
    )?;
    let hash = if let Ok(raw) = hex::decode(key) {
        Sha256::digest(raw)
    } else {
        Sha256::digest(seed.as_bytes())
    };
    let mut hello = timestamp()?.to_be_bytes().to_vec();
    hello.extend(&hash[..8]);
    hello.extend(&random[..16]);
    hello.extend(PublicKey::from(&ephemeral).as_bytes());
    hello.extend(7u32.to_be_bytes());
    hello.extend(table.hint.to_be_bytes());
    sender.kip(stream, 1, &hello).await?;
    let (kind, response) = receiver.kip(stream).await?;
    ensure!(
        kind == 2 && response.len() == 52,
        "invalid Sudoku server hello"
    );
    ensure!(
        response[..16] == random[..16],
        "Sudoku handshake nonce mismatch"
    );
    let shared =
        ephemeral.diffie_hellman(&PublicKey::from(<[u8; 32]>::try_from(&response[16..48])?));
    ensure!(shared.was_contributory(), "invalid Sudoku server ECDH key");
    let (up, down) = bases(&seed, Some(shared.as_bytes()), &random[..16])?;
    sender.rekey(up)?;
    receiver.rekey(down);
    Ok((receiver, sender))
}

type ReplayCache = Arc<Mutex<HashMap<(String, [u8; 16]), u64>>>;

async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    options: &SudokuOptions,
    core: &ProxyCore,
    peer: SocketAddr,
    replays: &ReplayCache,
) -> Result<(Receiver, Sender, CoreSession)> {
    let credentials = core.known_credentials();
    let mut candidates = Vec::new();
    for credential in credentials {
        let seed = sudoku_key_seed(&credential)?;
        let (up, down) = bases(&seed, None, &[])?;
        for table in options.tables(&seed)? {
            candidates.push((
                credential.clone(),
                seed.clone(),
                table.clone(),
                down,
                Receiver::new(table, false, false, up, &options.aead),
            ));
        }
    }
    let (credential, seed, table, down, mut receiver) = loop {
        ensure!(
            !candidates.is_empty(),
            "Sudoku client credential did not authenticate"
        );
        let mut wire = [0; 1024];
        let n = stream.read(&mut wire).await?;
        ensure!(n > 0, "truncated Sudoku handshake");
        let mut selected = None;
        let mut valid = Vec::new();
        for (credential, seed, table, down, mut receiver) in candidates {
            let decoded = match receiver.decoder.feed(&wire[..n]) {
                Ok(value) => value,
                Err(_) => continue,
            };
            receiver.decoded.extend(decoded);
            match receiver.take_record() {
                Ok(Some(plain)) if plain.starts_with(b"kip\x01") => {
                    receiver.prepend(plain);
                    selected = Some((credential, seed, table, down, receiver));
                    break;
                }
                Ok(None) => valid.push((credential, seed, table, down, receiver)),
                _ => {}
            }
        }
        if let Some(selected) = selected {
            break selected;
        }
        candidates = valid;
    };
    let (kind, hello) = receiver.kip(stream).await?;
    ensure!(
        kind == 1 && matches!(hello.len(), 68 | 72),
        "invalid Sudoku client hello"
    );
    let now = timestamp()?;
    let ts = u64::from_be_bytes(hello[..8].try_into()?);
    ensure!(now.abs_diff(ts) <= 60, "expired Sudoku handshake");
    let nonce: [u8; 16] = hello[16..32].try_into()?;
    {
        let mut cache = replays.lock().expect("Sudoku replay cache poisoned");
        cache.retain(|_, ts| now.saturating_sub(*ts) <= 120);
        ensure!(
            cache.insert((seed.clone(), nonce), now).is_none(),
            "replayed Sudoku handshake"
        );
    }
    let table = if hello.len() == 72 {
        let hint = u32::from_be_bytes(hello[68..72].try_into()?);
        options
            .tables(&seed)?
            .into_iter()
            .find(|table| table.hint == hint)
            .context("unknown Sudoku table hint")?
    } else {
        table
    };
    // Authenticate the verified key. UserHash is intentionally ignored.
    let session = core.authenticate_from(&credential, peer).await?;
    let ephemeral = secret()?;
    let shared = ephemeral.diffie_hellman(&PublicKey::from(<[u8; 32]>::try_from(&hello[32..64])?));
    ensure!(shared.was_contributory(), "invalid Sudoku client ECDH key");
    let mut sender = Sender::new(
        table,
        true,
        !options.enable_pure_downlink,
        down,
        &options.aead,
        options.padding()?,
    )?;
    let mut response = nonce.to_vec();
    response.extend(PublicKey::from(&ephemeral).as_bytes());
    response.extend((u32::from_be_bytes(hello[64..68].try_into()?) & 7).to_be_bytes());
    sender.kip(stream, 2, &response).await?;
    let (up, down) = bases(&seed, Some(shared.as_bytes()), &nonce)?;
    receiver.rekey(up);
    sender.rekey(down)?;
    Ok((receiver, sender, session))
}

// Duplex adapters keep cryptography outside AsyncRead's poll method. The guard
// aborts the driver when a caller drops a stream, including cancelled sessions.
struct Tunnel {
    stream: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<()>,
    error: Arc<Mutex<Option<String>>>,
    progress: Arc<Progress>,
    written: u64,
    closed: bool,
}
#[derive(Default)]
struct Progress {
    sent: std::sync::atomic::AtomicU64,
    write_closed: std::sync::atomic::AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
}
impl Progress {
    fn advance(&self, n: usize) {
        self.sent
            .fetch_add(n as u64, std::sync::atomic::Ordering::Release);
        self.wake();
    }
    fn register(&self, waker: &std::task::Waker) {
        *self.waker.lock().unwrap() = Some(waker.clone());
    }
    fn finish_write(&self) {
        self.write_closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.wake();
    }
    fn wake(&self) {
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(error) = self.error.lock().unwrap().as_ref() {
            return std::task::Poll::Ready(Err(std::io::Error::other(error.clone())));
        }
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if let Some(error) = self.error.lock().unwrap().as_ref() {
            return std::task::Poll::Ready(Err(std::io::Error::other(error.clone())));
        }
        match std::pin::Pin::new(&mut self.stream).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => {
                self.written += n as u64;
                std::task::Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(std::pin::Pin::new(&mut self.stream).poll_flush(cx))?;
        self.progress.register(cx.waker());
        if let Some(error) = self.error.lock().unwrap().as_ref() {
            return std::task::Poll::Ready(Err(std::io::Error::other(error.clone())));
        }
        if self
            .progress
            .sent
            .load(std::sync::atomic::Ordering::Acquire)
            >= self.written
        {
            std::task::Poll::Ready(Ok(()))
        } else if self.task.is_finished() {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Sudoku tunnel closed before flushing",
            )))
        } else {
            std::task::Poll::Pending
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.closed {
            return std::task::Poll::Ready(Ok(()));
        }
        std::task::ready!(std::pin::Pin::new(&mut self.stream).poll_shutdown(cx))?;
        self.progress.register(cx.waker());
        if let Some(error) = self.error.lock().unwrap().as_ref() {
            return std::task::Poll::Ready(Err(std::io::Error::other(error.clone())));
        }
        if self
            .progress
            .write_closed
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.closed = true;
            std::task::Poll::Ready(Ok(()))
        } else if self.task.is_finished() {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Sudoku tunnel closed before write shutdown",
            )))
        } else {
            std::task::Poll::Pending
        }
    }
}
fn tunnel<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    mut receiver: Receiver,
    mut sender: Sender,
) -> Tunnel {
    let (local, remote) = tokio::io::duplex(65536);
    let error = Arc::new(Mutex::new(None));
    let errors = error.clone();
    let progress = Arc::new(Progress::default());
    let sent = progress.clone();
    let task = tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(stream);
        let (mut plain_read, mut plain_write) = tokio::io::split(remote);
        let up = async {
            let mut buf = [0; 32768];
            loop {
                let n = plain_read.read(&mut buf).await?;
                if n == 0 {
                    write.shutdown().await?;
                    sent.finish_write();
                    return Ok::<_, anyhow::Error>(());
                }
                sender.write(&mut write, &buf[..n]).await?;
                sent.advance(n);
            }
        };
        let down = async {
            loop {
                let plain = receiver.read(&mut read).await?;
                if plain.is_empty() {
                    plain_write.shutdown().await?;
                    return Ok::<_, anyhow::Error>(());
                }
                plain_write.write_all(&plain).await?;
            }
        };
        let result = tokio::try_join!(up, down);
        if let Err(error) = result {
            *errors.lock().unwrap() = Some(format!("{error:#}"));
            tracing::warn!("Sudoku tunnel: {error:#}");
        }
        let _ = plain_write.shutdown().await;
        sent.wake();
    });
    Tunnel {
        stream: local,
        task,
        error,
        progress,
        written: 0,
        closed: false,
    }
}

pub async fn run_sudoku_server(config: SudokuServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.key, &config.users);
    run_sudoku_server_with_core(config, core).await
}
pub async fn run_sudoku_server_with_core(
    config: SudokuServerConfig,
    core: ProxyCore,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    run_sudoku_server_listener_with_core(listener, config, core).await
}
pub async fn run_sudoku_server_listener_with_core(
    listener: TcpListener,
    config: SudokuServerConfig,
    core: ProxyCore,
) -> Result<()> {
    config.options.validate()?;
    tracing::info!("Sudoku server listening on {}", listener.local_addr()?);
    let replays = Arc::new(Mutex::new(HashMap::new()));
    loop {
        let (stream, peer) = crate::listener::accept_tcp(&listener).await?;
        let options = config.options.clone();
        let core = core.clone();
        let replays = replays.clone();
        tokio::spawn(async move {
            let result=async {
                let mut stream=tokio::time::timeout(Duration::from_secs(5),transport::server(stream,&options,&core.known_credentials())).await??;
                let (mut receiver,sender,session)=tokio::time::timeout(Duration::from_secs(5),server_handshake(&mut stream,&options,&core,peer,&replays)).await??;
                let (kind,payload)=tokio::select! {
                    _=session.cancelled()=>return Ok(()),
                    result=tokio::time::timeout(Duration::from_secs(30),receiver.kip(&mut stream))=>result??,
                };
                let mut stream=tunnel(stream,receiver,sender);
                tokio::select! {
                    _=session.cancelled()=>Ok(()),
                    result=async {
                        match kind {
                            0x10=>{ let (target,tail)=uot::read_socks_address(&payload)?;ensure!(tail.is_empty(),"trailing Sudoku target bytes");
                                let mut outbound=socket_protect::connect_proxy_target(&target).await?;
                                relay_bidirectional_half_closed_counted(&mut stream,&mut outbound,session.clone(),"Sudoku").await
                            },
                            0x12=>udp_server(&mut stream,session.clone()).await,
                            0x11=>mux_server(stream,session.clone()).await,
                            _=>bail!("unsupported Sudoku command {kind:#x}"),
                        }
                    }=>result,
                }
            }.await;
            if let Err(error) = result {
                tracing::warn!("Sudoku server {peer}: {error:#}");
            }
        });
    }
}

pub async fn run_sudoku_client(config: SudokuClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    run_sudoku_client_listener(listener, config).await
}
pub async fn run_sudoku_client_listener(
    listener: TcpListener,
    config: SudokuClientConfig,
) -> Result<()> {
    run_sudoku_client_listener_with_core(listener, config, None).await
}
pub async fn run_sudoku_client_listener_with_core(
    listener: TcpListener,
    config: SudokuClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    config.options.validate()?;
    // Validate the complete appearance configuration before accepting clients.
    config.options.tables(&sudoku_key_seed(&config.key)?)?;
    tracing::info!("Sudoku client listening on {}", listener.local_addr()?);
    loop {
        let (mut local, peer) = crate::listener::accept_tcp(&listener).await?;
        let config = config.clone();
        let core = core.clone();
        tokio::spawn(async move {
            let result=async {
                let request=socks::read_request(&mut local).await?;
                let mut upstream=tokio::time::timeout(Duration::from_secs(5),transport::client(&config)).await??;
                let (receiver,mut sender)=tokio::time::timeout(Duration::from_secs(5),client_handshake(&mut upstream,&config.key,&config.options)).await??;
                let session=if let Some(core)=core {core.authenticate(&config.key).await?} else {CoreSession::disabled()};
                match request {
                    socks::SocksRequest::Connect(target)=>{
                        let mut address=Vec::new();uot::write_socks_address(&mut address,&target)?;
                        let multiplex=config.options.multiplex=="on";
                        if multiplex { sender.kip(&mut upstream,0x11,&[]).await?; } else { sender.kip(&mut upstream,0x10,&address).await?; }
                        socks::write_reply(&mut local,0).await?;
                        let mut upstream=tunnel(upstream,receiver,sender);
                        let mut upstream=if multiplex { mux_frame(&mut upstream,1,1,&address).await?; mux_client(upstream) } else { upstream };
                        tokio::select!{_=session.cancelled()=>Ok(()),result=relay_bidirectional_half_closed_counted(&mut local,&mut upstream,session.clone(),"Sudoku client")=>result}
                    },
                    socks::SocksRequest::UdpAssociate=>{
                        sender.kip(&mut upstream,0x12,&[]).await?;
                        let mut upstream=tunnel(upstream,receiver,sender);
                        udp_client(&mut local,&mut upstream,session).await
                    },
                }
            }.await;
            if let Err(error) = result {
                tracing::warn!("Sudoku client {peer}: {error:#}");
            }
        });
    }
}

async fn read_datagram<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(ProxyTarget, Vec<u8>)> {
    let address_len = reader.read_u16().await? as usize;
    let payload_len = reader.read_u16().await? as usize;
    let mut address = vec![0; address_len];
    reader.read_exact(&mut address).await?;
    let (target, tail) = uot::read_socks_address(&address)?;
    ensure!(tail.is_empty(), "trailing Sudoku UDP address");
    let mut payload = vec![0; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok((target, payload))
}
async fn write_datagram<W: AsyncWrite + Unpin>(
    writer: &mut W,
    target: &ProxyTarget,
    payload: &[u8],
) -> Result<()> {
    let mut address = Vec::new();
    uot::write_socks_address(&mut address, target)?;
    ensure!(payload.len() <= 65535, "Sudoku UDP datagram too large");
    let mut packet = (address.len() as u16).to_be_bytes().to_vec();
    packet.extend((payload.len() as u16).to_be_bytes());
    packet.extend(address);
    packet.extend(payload);
    writer.write_all(&packet).await?;
    Ok(())
}
async fn udp_server(stream: &mut Tunnel, session: CoreSession) -> Result<()> {
    let socket = socket_protect::bind_dual_stack_udp().await?;
    let allowed = tokio::sync::Mutex::new(HashSet::new());
    let (mut reader, mut writer) = tokio::io::split(stream);
    let up = async {
        loop {
            let (target, payload) = read_datagram(&mut reader).await?;
            let dest = crate::protocol::resolve_target_addr(&target).await?;
            session.record_upload(payload.len()).await?;
            allowed
                .lock()
                .await
                .insert(crate::protocol::canonicalize_socket_addr(dest));
            socket_protect::send_to_dual_stack(&socket, &payload, dest).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let down = async {
        let mut buf = [0; 65535];
        loop {
            let (n, source) = socket.recv_from(&mut buf).await?;
            let source = crate::protocol::canonicalize_socket_addr(source);
            if allowed.lock().await.contains(&source) {
                session.record_download(n).await?;
                write_datagram(&mut writer, &ProxyTarget::Ip(source), &buf[..n]).await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {_=session.cancelled()=>Ok(()),result=up=>result,result=down=>result}
}
async fn udp_client(
    local: &mut TcpStream,
    upstream: &mut Tunnel,
    session: CoreSession,
) -> Result<()> {
    let bind = SocketAddr::new(local.local_addr()?.ip(), 0);
    let udp = socket_protect::bind_udp(bind).await?;
    socks::write_reply_with_bind(local, 0, udp.local_addr()?).await?;
    let peer = tokio::sync::Mutex::new(None);
    let local_ip = local.peer_addr()?.ip();
    let (mut reader, mut writer) = tokio::io::split(upstream);
    let up = async {
        let mut buf = [0; 65535];
        loop {
            let (n, source) = udp.recv_from(&mut buf).await?;
            let mut guard = peer.lock().await;
            if source.ip() != local_ip || guard.is_some_and(|p| p != source) {
                continue;
            }
            *guard = Some(source);
            drop(guard);
            let (target, payload) = uot::parse_socks_udp_packet(&buf[..n])?;
            session.record_upload(payload.len()).await?;
            write_datagram(&mut writer, &target, payload).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let down = async {
        loop {
            let (target, payload) = read_datagram(&mut reader).await?;
            session.record_download(payload.len()).await?;
            if let Some(peer) = *peer.lock().await {
                udp.send_to(&uot::encode_socks_udp_packet(&target, &payload)?, peer)
                    .await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let mut control = [0];
    tokio::select! {_=session.cancelled()=>Ok(()),result=local.read(&mut control)=>{result?;Ok(())},result=up=>result,result=down=>result}
}

fn mux_client(stream: Tunnel) -> Tunnel {
    let (local, remote) = tokio::io::duplex(65536);
    let error = Arc::new(Mutex::new(None));
    let errors = error.clone();
    let progress = Arc::new(Progress::default());
    let sent = progress.clone();
    let task = tokio::spawn(async move {
        let (mut read, write) = tokio::io::split(stream);
        let write = tokio::sync::Mutex::new(write);
        let (mut plain_read, mut plain_write) = tokio::io::split(remote);
        let up = async {
            let mut buf = [0; 32768];
            loop {
                let n = plain_read.read(&mut buf).await?;
                if n == 0 {
                    mux_frame(&mut *write.lock().await, 3, 1, &[]).await?;
                    sent.finish_write();
                    return Ok::<_, anyhow::Error>(());
                }
                mux_frame(&mut *write.lock().await, 2, 1, &buf[..n]).await?;
                sent.advance(n);
            }
        };
        let down = async {
            loop {
                let kind = read.read_u8().await?;
                let id = read.read_u32().await?;
                let n = read.read_u32().await? as usize;
                ensure!(n <= 256 * 1024, "oversized Sudoku mux frame");
                let mut payload = vec![0; n];
                read.read_exact(&mut payload).await?;
                match kind {
                    2 if id == 1 => plain_write.write_all(&payload).await?,
                    3 if id == 1 => {
                        plain_write.shutdown().await?;
                        return Ok::<_, anyhow::Error>(());
                    }
                    4 if id == 1 => {
                        bail!("Sudoku mux reset: {}", String::from_utf8_lossy(&payload))
                    }
                    5 => mux_frame(&mut *write.lock().await, 6, id, &payload).await?,
                    6 => {}
                    _ => bail!("unexpected Sudoku mux frame"),
                }
            }
        };
        let result = tokio::try_join!(up, down);
        if let Err(error) = result {
            *errors.lock().unwrap() = Some(format!("{error:#}"));
        }
        let _ = plain_write.shutdown().await;
        sent.wake();
    });
    Tunnel {
        stream: local,
        task,
        error,
        progress,
        written: 0,
        closed: false,
    }
}

async fn mux_server(stream: Tunnel, session: CoreSession) -> Result<()> {
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let mut streams: HashMap<
        u32,
        (
            Option<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
            tokio::task::AbortHandle,
        ),
    > = HashMap::new();
    // JoinSet aborts every child on drop, including when the entire session is revoked.
    let mut tasks = tokio::task::JoinSet::new();
    let (completed, mut completion) = tokio::sync::mpsc::unbounded_channel();
    let result = async {
        loop {
            while let Ok(id) = completion.try_recv() {
                streams.remove(&id);
            }
            while tasks.try_join_next().is_some() {}
            let mut kind = [0];
            if reader.read(&mut kind).await? == 0 {
                // A session FIN may follow DATA/CLOSE while a stream is still
                // draining its accepted payload to the destination.
                for (up, _) in streams.values_mut() {
                    if let Some(mut up) = up.take() {
                        let _ = up.shutdown().await;
                    }
                }
                while tasks.join_next().await.is_some() {}
                return Ok::<(), anyhow::Error>(());
            }
            let kind = kind[0];
            let id = reader.read_u32().await?;
            let length = reader.read_u32().await? as usize;
            ensure!(length <= 256 * 1024, "oversized Sudoku mux frame");
            let mut payload = vec![0; length];
            reader.read_exact(&mut payload).await?;
            match kind {
                1 => {
                    ensure!(!streams.contains_key(&id), "duplicate Sudoku mux stream");
                    let (target, tail) = uot::read_socks_address(&payload)?;
                    ensure!(tail.is_empty(), "trailing Sudoku mux target");
                    let (local, mut remote) = tokio::io::duplex(65536);
                    let (mut down, up) = tokio::io::split(local);
                    let output = writer.clone();
                    let tracked = session.clone();
                    let completed = completed.clone();
                    let task = tasks.spawn(async move {
                        let relay = async move {
                            let mut outbound =
                                socket_protect::connect_proxy_target(&target).await?;
                            relay_bidirectional_half_closed_counted(
                                &mut remote,
                                &mut outbound,
                                tracked,
                                "Sudoku mux",
                            )
                            .await
                        };
                        let send_output = output.clone();
                        let send = async move {
                            let mut buf = [0; 32768];
                            loop {
                                let n = down.read(&mut buf).await?;
                                if n == 0 {
                                    mux_frame(&mut *send_output.lock().await, 3, id, &[]).await?;
                                    return Ok::<_, anyhow::Error>(());
                                }
                                mux_frame(&mut *send_output.lock().await, 2, id, &buf[..n]).await?;
                            }
                        };
                        let result = tokio::try_join!(relay, send).map(|_| ());
                        if let Err(error) = result
                            && let Err(error) = mux_frame(
                                &mut *output.lock().await,
                                4,
                                id,
                                error.to_string().as_bytes(),
                            )
                            .await
                        {
                            tracing::warn!("Sudoku mux reset: {error:#}");
                        }
                        let _ = completed.send(id);
                    });
                    streams.insert(id, (Some(up), task));
                }
                2 => {
                    if let Some((Some(up), _)) = streams.get_mut(&id)
                        && up.write_all(&payload).await.is_err()
                    {
                        if let Some((_, task)) = streams.remove(&id) {
                            task.abort();
                        }
                        mux_frame(&mut *writer.lock().await, 4, id, b"stream closed").await?;
                    }
                }
                3 => {
                    if let Some((up, _)) = streams.get_mut(&id)
                        && let Some(mut up) = up.take()
                    {
                        let _ = up.shutdown().await;
                    }
                }
                4 => {
                    if let Some((_, task)) = streams.remove(&id) {
                        task.abort();
                    }
                }
                5 => mux_frame(&mut *writer.lock().await, 6, id, &payload).await?,
                6 => {}
                _ => bail!("invalid Sudoku mux frame {kind}"),
            }
        }
    }
    .await;
    for (_, (_, task)) in streams {
        task.abort();
    }
    result
}
async fn mux_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    id: u32,
    payload: &[u8],
) -> Result<()> {
    let mut frame = vec![kind];
    frame.extend(id.to_be_bytes());
    frame.extend((payload.len() as u32).to_be_bytes());
    frame.extend(payload);
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
