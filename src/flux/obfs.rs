use crate::protocol::constant_time_eq;
use crate::replay_cache::{ReplayCache, ReplayError};
use crate::vless_transport::BoxedTransportStream;
use anyhow::{Context, Result, bail, ensure};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use sha2::Sha256;
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey, StaticSecret};

const OBFS_UDP_SALT_LEN: usize = 8;
const OBFS_PIPE_CAP: usize = 64 * 1024;
const OBFS_MAX_CHUNK: usize = 32 * 1024;
const OBFS_TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;
type IoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

pub struct FluxObfsUdpSocket {
    io: UdpSocket,
    key: Vec<u8>,
    recv_buffer: StdMutex<Vec<u8>>,
}

impl fmt::Debug for FluxObfsUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FluxObfsUdpSocket").finish_non_exhaustive()
    }
}

struct FluxObfsUdpPoller {
    socket: Arc<FluxObfsUdpSocket>,
    future: Option<IoFuture>,
}

impl fmt::Debug for FluxObfsUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FluxObfsUdpPoller").finish_non_exhaustive()
    }
}

impl FluxObfsUdpSocket {
    pub fn new(socket: std::net::UdpSocket, obfs_key: &str) -> Result<Self> {
        ensure!(
            obfs_key.len() >= 4,
            "Flux UDP obfs_key must be at least 4 bytes"
        );
        Ok(Self {
            io: UdpSocket::from_std(socket).context("wrap Flux obfs UDP socket")?,
            key: obfs_key.as_bytes().to_vec(),
            recv_buffer: StdMutex::new(Vec::new()),
        })
    }
}

fn obfs_udp_xor(key: &[u8], salt: &[u8; OBFS_UDP_SALT_LEN], input: &[u8], output: &mut [u8]) {
    let mut hasher = Blake2bVar::new(64).expect("64-byte Blake2bVar valid");
    hasher.update(key);
    hasher.update(salt);
    let mut mask = [0u8; 64];
    hasher
        .finalize_variable(&mut mask)
        .expect("64-byte Blake2bVar output valid");
    for (idx, (dst, src)) in output.iter_mut().zip(input.iter()).enumerate() {
        *dst = *src ^ mask[idx & 63];
    }
}

impl AsyncUdpSocket for FluxObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(FluxObfsUdpPoller {
            socket: self,
            future: None,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut salt = [0u8; OBFS_UDP_SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|e| io::Error::other(format!("Flux obfs salt random: {e}")))?;
        let mut packet = vec![0u8; OBFS_UDP_SALT_LEN + transmit.contents.len()];
        packet[..OBFS_UDP_SALT_LEN].copy_from_slice(&salt);
        obfs_udp_xor(
            &self.key,
            &salt,
            transmit.contents,
            &mut packet[OBFS_UDP_SALT_LEN..],
        );
        let written = self.io.try_send_to(&packet, transmit.destination)?;
        if written == packet.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial Flux obfs UDP send",
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
                .expect("Flux obfs recv buffer poisoned");
            buffer.resize(bufs[0].len() + OBFS_UDP_SALT_LEN, 0);
            match self.io.try_recv_from(&mut buffer) {
                Ok((read, addr)) => {
                    if read <= OBFS_UDP_SALT_LEN {
                        continue;
                    }
                    let mut salt = [0u8; OBFS_UDP_SALT_LEN];
                    salt.copy_from_slice(&buffer[..OBFS_UDP_SALT_LEN]);
                    let out_len = read - OBFS_UDP_SALT_LEN;
                    obfs_udp_xor(
                        &self.key,
                        &salt,
                        &buffer[OBFS_UDP_SALT_LEN..read],
                        &mut bufs[0][..out_len],
                    );
                    meta[0] = RecvMeta {
                        addr,
                        len: out_len,
                        stride: out_len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    continue;
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

impl UdpPoller for FluxObfsUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.future.is_none() {
            let socket = this.socket.clone();
            this.future = Some(Box::pin(async move { socket.io.writable().await }));
        }
        let poll = this
            .future
            .as_mut()
            .expect("Flux obfs writable future set")
            .as_mut()
            .poll(cx);
        if poll.is_ready() {
            this.future = None;
        }
        poll
    }
}

pub struct ObfsStream {
    reader: DuplexStream,
    writer: DuplexStream,
    read_task: JoinHandle<Result<()>>,
    write_task: JoinHandle<Result<()>>,
}

impl Drop for ObfsStream {
    fn drop(&mut self) {
        self.read_task.abort();
        self.write_task.abort();
    }
}

impl AsyncRead for ObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ObfsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

fn hmac_tag(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("init Flux obfs HMAC"))?;
    for part in parts {
        Mac::update(&mut mac, part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn derive_stream_keys(
    obfs_key: &[u8],
    shared_secret: &[u8; 32],
    client_pub: &[u8; 32],
    server_pub: &[u8; 32],
) -> Result<([u8; 32], [u8; 12], [u8; 32], [u8; 12])> {
    let hkdf = Hkdf::<Sha256>::new(Some(obfs_key), shared_secret);
    let mut material = [0u8; 88];
    let mut info = Vec::with_capacity(80);
    info.extend_from_slice(b"flux-obfs-stream-v1");
    info.extend_from_slice(client_pub);
    info.extend_from_slice(server_pub);
    hkdf.expand(&info, &mut material)
        .map_err(|_| anyhow::anyhow!("derive Flux obfs stream keys"))?;
    let mut c2s_key = [0u8; 32];
    let mut c2s_iv = [0u8; 12];
    let mut s2c_key = [0u8; 32];
    let mut s2c_iv = [0u8; 12];
    c2s_key.copy_from_slice(&material[0..32]);
    c2s_iv.copy_from_slice(&material[32..44]);
    s2c_key.copy_from_slice(&material[44..76]);
    s2c_iv.copy_from_slice(&material[76..88]);
    Ok((c2s_key, c2s_iv, s2c_key, s2c_iv))
}

pub async fn client_obfs_handshake(
    mut stream: BoxedTransportStream,
    obfs_key: &str,
) -> Result<BoxedTransportStream> {
    let key_bytes = obfs_key.as_bytes();
    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes).map_err(|e| anyhow::anyhow!("Flux obfs random: {e}"))?;
    let secret = StaticSecret::from(secret_bytes);
    let client_pub = PublicKey::from(&secret).to_bytes();
    let mut pad_seed = [0u8; 1];
    getrandom::fill(&mut pad_seed).map_err(|e| anyhow::anyhow!("Flux obfs pad random: {e}"))?;
    let pad_len = 16usize + usize::from(pad_seed[0] % 49);
    let mut pad = vec![0u8; pad_len];
    getrandom::fill(&mut pad).map_err(|e| anyhow::anyhow!("Flux obfs pad fill: {e}"))?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_be_bytes();
    let pad_len_byte = [pad_len as u8];
    let tag = hmac_tag(
        key_bytes,
        &[b"flux-obfs-c2s", &client_pub, &ts, &pad_len_byte, &pad],
    )?;
    let mut hello = Vec::with_capacity(32 + 8 + 1 + pad_len + 32);
    hello.extend_from_slice(&client_pub);
    hello.extend_from_slice(&ts);
    hello.push(pad_len as u8);
    hello.extend_from_slice(&pad);
    hello.extend_from_slice(&tag);
    stream
        .write_all(&hello)
        .await
        .context("write Flux obfs client hello")?;
    stream
        .flush()
        .await
        .context("flush Flux obfs client hello")?;

    let mut header = [0u8; 33];
    stream
        .read_exact(&mut header)
        .await
        .context("read Flux obfs server hello")?;
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&header[..32]);
    let srv_pad_len = usize::from(header[32]);
    ensure!(srv_pad_len <= 96, "invalid Flux obfs server padding");
    let mut srv_tail = vec![0u8; srv_pad_len + 32];
    stream
        .read_exact(&mut srv_tail)
        .await
        .context("read Flux obfs server hello tail")?;
    let expected_srv_tag = hmac_tag(
        key_bytes,
        &[
            b"flux-obfs-s2c",
            &client_pub,
            &server_pub,
            &[header[32]],
            &srv_tail[..srv_pad_len],
        ],
    )?;
    ensure!(
        constant_time_eq(&expected_srv_tag, &srv_tail[srv_pad_len..]),
        "Flux obfs server authentication failed"
    );
    let shared = secret.diffie_hellman(&PublicKey::from(server_pub));
    ensure!(
        shared.was_contributory(),
        "invalid Flux obfs server ECDH key"
    );
    let (c2s_key, c2s_iv, s2c_key, s2c_iv) =
        derive_stream_keys(key_bytes, shared.as_bytes(), &client_pub, &server_pub)?;
    Ok(Box::new(spawn_obfs_stream(
        stream, c2s_key, c2s_iv, s2c_key, s2c_iv,
    )))
}

pub async fn server_obfs_handshake(
    mut stream: BoxedTransportStream,
    obfs_key: &str,
    replay: &ReplayCache<[u8; 32]>,
) -> Result<BoxedTransportStream> {
    let key_bytes = obfs_key.as_bytes();
    let mut header = [0u8; 41];
    stream
        .read_exact(&mut header)
        .await
        .context("read Flux obfs client hello")?;
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&header[..32]);
    let ts = u64::from_be_bytes(header[32..40].try_into().unwrap());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(now.abs_diff(ts) <= 120, "expired Flux obfs handshake");
    let pad_len = usize::from(header[40]);
    ensure!(pad_len <= 96, "invalid Flux obfs client padding");
    let mut tail = vec![0u8; pad_len + 32];
    stream
        .read_exact(&mut tail)
        .await
        .context("read Flux obfs client hello tail")?;
    let expected_tag = hmac_tag(
        key_bytes,
        &[
            b"flux-obfs-c2s",
            &client_pub,
            &header[32..40],
            &[header[40]],
            &tail[..pad_len],
        ],
    )?;
    ensure!(
        constant_time_eq(&expected_tag, &tail[pad_len..]),
        "Flux obfs client authentication failed"
    );
    match replay.check_and_store(client_pub) {
        Ok(()) => {}
        Err(ReplayError::Replayed) => bail!("replayed Flux obfs handshake"),
        Err(ReplayError::Full) => bail!("Flux obfs replay cache full"),
    }

    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes).map_err(|e| anyhow::anyhow!("Flux obfs random: {e}"))?;
    let secret = StaticSecret::from(secret_bytes);
    let server_pub = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(client_pub));
    ensure!(
        shared.was_contributory(),
        "invalid Flux obfs client ECDH key"
    );

    let mut pad_seed = [0u8; 1];
    getrandom::fill(&mut pad_seed).map_err(|e| anyhow::anyhow!("Flux obfs pad random: {e}"))?;
    let srv_pad_len = 16usize + usize::from(pad_seed[0] % 49);
    let mut srv_pad = vec![0u8; srv_pad_len];
    getrandom::fill(&mut srv_pad).map_err(|e| anyhow::anyhow!("Flux obfs pad fill: {e}"))?;
    let srv_tag = hmac_tag(
        key_bytes,
        &[
            b"flux-obfs-s2c",
            &client_pub,
            &server_pub,
            &[srv_pad_len as u8],
            &srv_pad,
        ],
    )?;
    let mut resp = Vec::with_capacity(32 + 1 + srv_pad_len + 32);
    resp.extend_from_slice(&server_pub);
    resp.push(srv_pad_len as u8);
    resp.extend_from_slice(&srv_pad);
    resp.extend_from_slice(&srv_tag);
    stream
        .write_all(&resp)
        .await
        .context("write Flux obfs server hello")?;
    stream
        .flush()
        .await
        .context("flush Flux obfs server hello")?;

    let (c2s_key, c2s_iv, s2c_key, s2c_iv) =
        derive_stream_keys(key_bytes, shared.as_bytes(), &client_pub, &server_pub)?;
    Ok(Box::new(spawn_obfs_stream(
        stream, s2c_key, s2c_iv, c2s_key, c2s_iv,
    )))
}

fn step_nonce(iv: &[u8; 12], seq: u64) -> ([u8; 12], u16) {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for (dst, src) in nonce[4..12].iter_mut().zip(seq_bytes.iter()) {
        *dst ^= *src;
    }
    let len_mask = u16::from_be_bytes([nonce[0] ^ nonce[6], nonce[1] ^ nonce[7]]);
    (nonce, len_mask)
}

fn spawn_obfs_stream(
    stream: BoxedTransportStream,
    write_key: [u8; 32],
    write_iv: [u8; 12],
    read_key: [u8; 32],
    read_iv: [u8; 12],
) -> ObfsStream {
    let (mut wire_reader, mut wire_writer) = tokio::io::split(stream);
    let (mut app_sink, reader) = duplex(OBFS_PIPE_CAP);
    let (writer, mut app_source) = duplex(OBFS_PIPE_CAP);

    let read_task = tokio::spawn(async move {
        let cipher = ChaCha20Poly1305::new((&read_key).into());
        let mut seq = 0u64;
        let mut len_buf = [0u8; 2];
        loop {
            match wire_reader.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    let _ = app_sink.shutdown().await;
                    return Ok(());
                }
                Err(e) => return Err(e).context("read Flux obfs frame length"),
            }
            let (nonce, mask) = step_nonce(&read_iv, seq);
            seq = seq.checked_add(1).context("Flux obfs read seq overflow")?;
            let cipher_len = usize::from(u16::from_be_bytes(len_buf) ^ mask);
            ensure!(
                (OBFS_TAG_LEN..=OBFS_MAX_CHUNK + OBFS_TAG_LEN).contains(&cipher_len),
                "invalid Flux obfs record length {cipher_len}"
            );
            let mut ct = vec![0u8; cipher_len];
            wire_reader
                .read_exact(&mut ct)
                .await
                .context("read Flux obfs ciphertext")?;
            let plain = cipher
                .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                .map_err(|_| anyhow::anyhow!("decrypt Flux obfs record"))?;
            if plain.is_empty() {
                let _ = app_sink.shutdown().await;
                return Ok(());
            }
            if app_sink.write_all(&plain).await.is_err() {
                return Ok(());
            }
        }
    });

    let write_task = tokio::spawn(async move {
        let cipher = ChaCha20Poly1305::new((&write_key).into());
        let mut seq = 0u64;
        let mut buf = vec![0u8; OBFS_MAX_CHUNK];
        loop {
            let read = app_source
                .read(&mut buf)
                .await
                .context("read local Flux obfs source")?;
            let (nonce, mask) = step_nonce(&write_iv, seq);
            seq = seq.checked_add(1).context("Flux obfs write seq overflow")?;
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), &buf[..read])
                .map_err(|_| anyhow::anyhow!("encrypt Flux obfs record"))?;
            let masked_len = ((ct.len() as u16) ^ mask).to_be_bytes();
            wire_writer
                .write_all(&masked_len)
                .await
                .context("write Flux obfs length")?;
            wire_writer
                .write_all(&ct)
                .await
                .context("write Flux obfs ciphertext")?;
            wire_writer
                .flush()
                .await
                .context("flush Flux obfs stream")?;
            if read == 0 {
                let _ = wire_writer.shutdown().await;
                return Ok(());
            }
        }
    });

    ObfsStream {
        reader,
        writer,
        read_task,
        write_task,
    }
}
