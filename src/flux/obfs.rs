use crate::replay_cache::{ReplayCache, ReplayError};
use crate::vless_transport::BoxedTransportStream;
use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag as XChaChaTag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::Sha256;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey, StaticSecret};

const OBFS_UDP_NONCE_LEN: usize = 24;
const OBFS_UDP_TAG_LEN: usize = 16;
const OBFS_UDP_OVERHEAD: usize = OBFS_UDP_NONCE_LEN + OBFS_UDP_TAG_LEN;
const OBFS_PIPE_CAP: usize = 256 * 1024;
const OBFS_MAX_CHUNK: usize = 32 * 1024;
const OBFS_TAG_LEN: usize = 16;
const OBFS_STREAM_HDR_PLAIN_LEN: usize = 4;
const OBFS_STREAM_HDR_WIRE_LEN: usize = OBFS_STREAM_HDR_PLAIN_LEN + OBFS_TAG_LEN;
const OBFS_HELLO_HDR_PLAIN_LEN: usize = 16;
const OBFS_HELLO_HDR_WIRE_LEN: usize = OBFS_HELLO_HDR_PLAIN_LEN + OBFS_TAG_LEN;
const OBFS_MAX_HELLO_PAD: usize = 128;

pub struct FluxObfsUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    cipher: XChaCha20Poly1305,
}

impl fmt::Debug for FluxObfsUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FluxObfsUdpSocket").finish_non_exhaustive()
    }
}

impl FluxObfsUdpSocket {
    pub fn new(socket: std::net::UdpSocket, server_public_key: &[u8; 32]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"flux-obfs-udp-v2"), server_public_key);
        let mut udp_key = [0u8; 32];
        hkdf.expand(b"xchacha20poly1305", &mut udp_key)
            .map_err(|_| anyhow::anyhow!("derive Flux UDP obfs key"))?;
        let inner = TokioRuntime
            .wrap_udp_socket(socket)
            .context("wrap Flux obfs UDP socket")?;
        Ok(Self {
            inner,
            cipher: XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&udp_key)),
        })
    }
}

impl AsyncUdpSocket for FluxObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut nonce_bytes = [0u8; OBFS_UDP_NONCE_LEN];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| io::Error::other(format!("Flux obfs nonce random: {e}")))?;
        let mut packet = Vec::with_capacity(OBFS_UDP_OVERHEAD + transmit.contents.len());
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(transmit.contents);
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce_bytes),
                &[],
                &mut packet[OBFS_UDP_NONCE_LEN..],
            )
            .map_err(|_| io::Error::other("Flux UDP obfs encrypt failed"))?;
        packet.extend_from_slice(&tag);
        let out = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &packet,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&out)
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let count = ready!(self.inner.poll_recv(cx, bufs, meta))?;
            let mut write_idx = 0usize;
            for idx in 0..count {
                let m = meta[idx];
                if m.len <= OBFS_UDP_OVERHEAD {
                    continue;
                }
                let seg_stride = if m.stride == 0 { m.len } else { m.stride };
                if seg_stride <= OBFS_UDP_OVERHEAD {
                    continue;
                }
                let mut src_off = 0usize;
                let mut dst_off = 0usize;
                let mut segs = 0usize;
                let mut valid = true;
                {
                    let slot_buf = &mut bufs[idx][..m.len];
                    while src_off < m.len {
                        let seg_len = (m.len - src_off).min(seg_stride);
                        if seg_len <= OBFS_UDP_OVERHEAD {
                            valid = false;
                            break;
                        }
                        let mut nonce_bytes = [0u8; OBFS_UDP_NONCE_LEN];
                        nonce_bytes
                            .copy_from_slice(&slot_buf[src_off..src_off + OBFS_UDP_NONCE_LEN]);
                        let plain_len = seg_len - OBFS_UDP_OVERHEAD;
                        let tag_start = src_off + OBFS_UDP_NONCE_LEN + plain_len;
                        let tag = *XChaChaTag::from_slice(&slot_buf[tag_start..src_off + seg_len]);
                        if self
                            .cipher
                            .decrypt_in_place_detached(
                                XNonce::from_slice(&nonce_bytes),
                                &[],
                                &mut slot_buf[src_off + OBFS_UDP_NONCE_LEN..tag_start],
                                &tag,
                            )
                            .is_err()
                        {
                            valid = false;
                            break;
                        }
                        if dst_off != src_off + OBFS_UDP_NONCE_LEN {
                            slot_buf.copy_within(
                                src_off + OBFS_UDP_NONCE_LEN..tag_start,
                                dst_off,
                            );
                        }
                        src_off += seg_len;
                        dst_off += plain_len;
                        segs += 1;
                    }
                }
                if !valid || dst_off == 0 {
                    continue;
                }
                if write_idx < idx {
                    let (left, right) = bufs.split_at_mut(idx);
                    left[write_idx][..dst_off].copy_from_slice(&right[0][..dst_off]);
                }
                meta[write_idx] = RecvMeta {
                    addr: m.addr,
                    len: dst_off,
                    stride: if segs <= 1 {
                        dst_off
                    } else {
                        seg_stride - OBFS_UDP_OVERHEAD
                    },
                    ecn: m.ecn,
                    dst_ip: m.dst_ip,
                };
                write_idx += 1;
            }
            if write_idx > 0 {
                return Poll::Ready(Ok(write_idx));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
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

#[derive(Clone, Copy)]
struct DirectionalKeys {
    hdr_key: [u8; 32],
    hdr_iv: [u8; 12],
    data_key: [u8; 32],
    data_iv: [u8; 12],
}

fn derive_init_key_nonce(
    label: &[u8],
    salt_left: &[u8; 32],
    salt_right: &[u8; 32],
    ikm_parts: &[&[u8]],
) -> Result<([u8; 32], [u8; 12])> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(salt_left);
    salt[32..].copy_from_slice(salt_right);
    let mut ikm = Vec::with_capacity(64);
    for part in ikm_parts {
        ikm.extend_from_slice(part);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut out = [0u8; 44];
    hkdf.expand(label, &mut out)
        .map_err(|_| anyhow::anyhow!("derive Flux obfs init key"))?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&out[..32]);
    nonce.copy_from_slice(&out[32..44]);
    Ok((key, nonce))
}

fn derive_stream_keys(
    static_ss: &[u8; 32],
    eph_ss: &[u8; 32],
    client_pub: &[u8; 32],
    server_pub: &[u8; 32],
) -> Result<(DirectionalKeys, DirectionalKeys, [u8; 32])> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_pub);
    salt[32..].copy_from_slice(server_pub);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(static_ss);
    ikm[32..].copy_from_slice(eph_ss);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut material = [0u8; 208];
    hkdf.expand(b"flux-obfs-stream-v2", &mut material)
        .map_err(|_| anyhow::anyhow!("derive Flux obfs stream keys"))?;
    let take_dir = |offset: usize| -> DirectionalKeys {
        let mut hdr_key = [0u8; 32];
        let mut hdr_iv = [0u8; 12];
        let mut data_key = [0u8; 32];
        let mut data_iv = [0u8; 12];
        hdr_key.copy_from_slice(&material[offset..offset + 32]);
        hdr_iv.copy_from_slice(&material[offset + 32..offset + 44]);
        data_key.copy_from_slice(&material[offset + 44..offset + 76]);
        data_iv.copy_from_slice(&material[offset + 76..offset + 88]);
        DirectionalKeys {
            hdr_key,
            hdr_iv,
            data_key,
            data_iv,
        }
    };
    let mut binding = [0u8; 32];
    binding.copy_from_slice(&material[176..208]);
    Ok((take_dir(0), take_dir(88), binding))
}

pub async fn client_obfs_handshake(
    mut stream: BoxedTransportStream,
    server_public_key: [u8; 32],
) -> Result<(BoxedTransportStream, [u8; 32])> {
    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes).map_err(|e| anyhow::anyhow!("Flux obfs random: {e}"))?;
    let secret = StaticSecret::from(secret_bytes);
    let client_pub = PublicKey::from(&secret).to_bytes();
    let static_ss = secret.diffie_hellman(&PublicKey::from(server_public_key));
    ensure!(
        static_ss.was_contributory(),
        "invalid Flux server X25519 public key"
    );
    let (c2s_key, c2s_nonce) = derive_init_key_nonce(
        b"flux-obfs-c2s-init-v2",
        &client_pub,
        &server_public_key,
        &[static_ss.as_bytes()],
    )?;

    let mut pad_seed = [0u8; 1];
    getrandom::fill(&mut pad_seed).map_err(|e| anyhow::anyhow!("Flux obfs pad random: {e}"))?;
    let pad_len = 16usize + usize::from(pad_seed[0] % 49);
    let mut pad = vec![0u8; pad_len];
    getrandom::fill(&mut pad).map_err(|e| anyhow::anyhow!("Flux obfs pad fill: {e}"))?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_be_bytes();
    let mut hdr_buf = [0u8; OBFS_HELLO_HDR_WIRE_LEN];
    getrandom::fill(&mut hdr_buf[9..OBFS_HELLO_HDR_PLAIN_LEN])
        .map_err(|e| anyhow::anyhow!("Flux obfs header random: {e}"))?;
    hdr_buf[..8].copy_from_slice(&ts);
    hdr_buf[8] = pad_len as u8;
    let c2s_cipher = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, &c2s_key).expect("32-byte ChaCha20 key"),
    );
    let tag = c2s_cipher
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(c2s_nonce),
            Aad::from(&client_pub),
            &mut hdr_buf[..OBFS_HELLO_HDR_PLAIN_LEN],
        )
        .map_err(|_| anyhow::anyhow!("encrypt Flux obfs client hello"))?;
    hdr_buf[OBFS_HELLO_HDR_PLAIN_LEN..].copy_from_slice(tag.as_ref());

    let mut hello = Vec::with_capacity(32 + OBFS_HELLO_HDR_WIRE_LEN + pad_len);
    hello.extend_from_slice(&client_pub);
    hello.extend_from_slice(&hdr_buf);
    hello.extend_from_slice(&pad);
    stream
        .write_all(&hello)
        .await
        .context("write Flux obfs client hello")?;
    stream
        .flush()
        .await
        .context("flush Flux obfs client hello")?;

    let mut srv_prefix = [0u8; 32 + OBFS_HELLO_HDR_WIRE_LEN];
    stream
        .read_exact(&mut srv_prefix)
        .await
        .context("read Flux obfs server hello")?;
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&srv_prefix[..32]);
    let eph_ss = secret.diffie_hellman(&PublicKey::from(server_pub));
    ensure!(
        eph_ss.was_contributory(),
        "invalid Flux obfs server ECDH key"
    );
    let (s2c_key, s2c_nonce) = derive_init_key_nonce(
        b"flux-obfs-s2c-init-v2",
        &client_pub,
        &server_pub,
        &[static_ss.as_bytes(), eph_ss.as_bytes()],
    )?;
    let s2c_cipher = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, &s2c_key).expect("32-byte ChaCha20 key"),
    );
    let mut aad = [0u8; 64];
    aad[..32].copy_from_slice(&client_pub);
    aad[32..].copy_from_slice(&server_pub);
    let plain = s2c_cipher
        .open_in_place(
            Nonce::assume_unique_for_key(s2c_nonce),
            Aad::from(&aad),
            &mut srv_prefix[32..],
        )
        .map_err(|_| anyhow::anyhow!("Flux obfs server authentication failed"))?;
    let srv_pad_len = usize::from(plain[0]);
    ensure!(
        srv_pad_len <= OBFS_MAX_HELLO_PAD,
        "invalid Flux obfs server padding"
    );
    if srv_pad_len > 0 {
        let mut srv_pad = vec![0u8; srv_pad_len];
        stream
            .read_exact(&mut srv_pad)
            .await
            .context("read Flux obfs server padding")?;
    }

    let (c2s_dirs, s2c_dirs, binding) = derive_stream_keys(
        static_ss.as_bytes(),
        eph_ss.as_bytes(),
        &client_pub,
        &server_pub,
    )?;
    Ok((
        Box::new(spawn_obfs_stream(stream, c2s_dirs, s2c_dirs)),
        binding,
    ))
}

pub(crate) async fn server_obfs_handshake(
    mut stream: BoxedTransportStream,
    server_private_key: [u8; 32],
    replay: &ReplayCache<[u8; 32]>,
) -> Result<(BoxedTransportStream, [u8; 32])> {
    let static_secret = StaticSecret::from(server_private_key);
    let static_public = PublicKey::from(&static_secret).to_bytes();

    let mut prefix = [0u8; 32 + OBFS_HELLO_HDR_WIRE_LEN];
    stream
        .read_exact(&mut prefix)
        .await
        .context("read Flux obfs client hello")?;
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&prefix[..32]);
    let static_ss = static_secret.diffie_hellman(&PublicKey::from(client_pub));
    ensure!(
        static_ss.was_contributory(),
        "invalid Flux obfs client ECDH key"
    );
    let (c2s_key, c2s_nonce) = derive_init_key_nonce(
        b"flux-obfs-c2s-init-v2",
        &client_pub,
        &static_public,
        &[static_ss.as_bytes()],
    )?;
    let c2s_cipher = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, &c2s_key).expect("32-byte ChaCha20 key"),
    );
    let plain = c2s_cipher
        .open_in_place(
            Nonce::assume_unique_for_key(c2s_nonce),
            Aad::from(&client_pub),
            &mut prefix[32..],
        )
        .map_err(|_| anyhow::anyhow!("Flux obfs client authentication failed"))?;

    let ts = u64::from_be_bytes(plain[..8].try_into().unwrap());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(now.abs_diff(ts) <= 120, "expired Flux obfs handshake");
    let pad_len = usize::from(plain[8]);
    ensure!(pad_len <= OBFS_MAX_HELLO_PAD, "invalid Flux obfs client padding");
    match replay.check_and_store(client_pub) {
        Ok(()) => {}
        Err(ReplayError::Replayed) => bail!("replayed Flux obfs handshake"),
        Err(ReplayError::Full) => bail!("Flux obfs replay cache full"),
    }
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        stream
            .read_exact(&mut pad)
            .await
            .context("read Flux obfs client padding")?;
    }

    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes).map_err(|e| anyhow::anyhow!("Flux obfs random: {e}"))?;
    let secret = StaticSecret::from(secret_bytes);
    let server_pub = PublicKey::from(&secret).to_bytes();
    let eph_ss = secret.diffie_hellman(&PublicKey::from(client_pub));
    ensure!(
        eph_ss.was_contributory(),
        "invalid Flux obfs client ECDH key"
    );
    let (s2c_key, s2c_nonce) = derive_init_key_nonce(
        b"flux-obfs-s2c-init-v2",
        &client_pub,
        &server_pub,
        &[static_ss.as_bytes(), eph_ss.as_bytes()],
    )?;
    let s2c_cipher = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, &s2c_key).expect("32-byte ChaCha20 key"),
    );

    let mut pad_seed = [0u8; 1];
    getrandom::fill(&mut pad_seed).map_err(|e| anyhow::anyhow!("Flux obfs pad random: {e}"))?;
    let srv_pad_len = 16usize + usize::from(pad_seed[0] % 49);
    let mut srv_pad = vec![0u8; srv_pad_len];
    getrandom::fill(&mut srv_pad).map_err(|e| anyhow::anyhow!("Flux obfs pad fill: {e}"))?;
    let mut srv_hdr = [0u8; OBFS_HELLO_HDR_WIRE_LEN];
    getrandom::fill(&mut srv_hdr[1..OBFS_HELLO_HDR_PLAIN_LEN])
        .map_err(|e| anyhow::anyhow!("Flux obfs server header random: {e}"))?;
    srv_hdr[0] = srv_pad_len as u8;
    let mut aad = [0u8; 64];
    aad[..32].copy_from_slice(&client_pub);
    aad[32..].copy_from_slice(&server_pub);
    let srv_tag = s2c_cipher
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(s2c_nonce),
            Aad::from(&aad),
            &mut srv_hdr[..OBFS_HELLO_HDR_PLAIN_LEN],
        )
        .map_err(|_| anyhow::anyhow!("encrypt Flux obfs server hello"))?;
    srv_hdr[OBFS_HELLO_HDR_PLAIN_LEN..].copy_from_slice(srv_tag.as_ref());

    let mut resp = Vec::with_capacity(32 + OBFS_HELLO_HDR_WIRE_LEN + srv_pad_len);
    resp.extend_from_slice(&server_pub);
    resp.extend_from_slice(&srv_hdr);
    resp.extend_from_slice(&srv_pad);
    stream
        .write_all(&resp)
        .await
        .context("write Flux obfs server hello")?;
    stream
        .flush()
        .await
        .context("flush Flux obfs server hello")?;

    let (c2s_dirs, s2c_dirs, binding) = derive_stream_keys(
        static_ss.as_bytes(),
        eph_ss.as_bytes(),
        &client_pub,
        &server_pub,
    )?;
    Ok((
        Box::new(spawn_obfs_stream(stream, s2c_dirs, c2s_dirs)),
        binding,
    ))
}

fn step_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for (dst, src) in nonce[4..12].iter_mut().zip(seq_bytes.iter()) {
        *dst ^= *src;
    }
    nonce
}

fn spawn_obfs_stream(
    stream: BoxedTransportStream,
    write_dirs: DirectionalKeys,
    read_dirs: DirectionalKeys,
) -> ObfsStream {
    let (mut wire_reader, mut wire_writer) = tokio::io::split(stream);
    let (mut app_sink, reader) = duplex(OBFS_PIPE_CAP);
    let (writer, mut app_source) = duplex(OBFS_PIPE_CAP);

    let read_task = tokio::spawn(async move {
        let hdr_cipher = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &read_dirs.hdr_key).expect("32-byte ChaCha20 key"),
        );
        let data_cipher = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &read_dirs.data_key)
                .expect("32-byte ChaCha20 key"),
        );
        let mut seq = 0u64;
        let mut hdr_wire = [0u8; OBFS_STREAM_HDR_WIRE_LEN];
        let mut body = Vec::with_capacity(OBFS_MAX_CHUNK + OBFS_TAG_LEN + 64);
        loop {
            match wire_reader.read_exact(&mut hdr_wire).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    let _ = app_sink.shutdown().await;
                    return Ok(());
                }
                Err(e) => return Err(e).context("read Flux obfs frame length"),
            }
            let hdr_nonce = step_nonce(&read_dirs.hdr_iv, seq);
            let data_nonce = step_nonce(&read_dirs.data_iv, seq);
            seq = seq.checked_add(1).context("Flux obfs read seq overflow")?;

            let hdr_aad = hdr_wire;
            let hdr_plain = hdr_cipher
                .open_in_place(
                    Nonce::assume_unique_for_key(hdr_nonce),
                    Aad::empty(),
                    &mut hdr_wire,
                )
                .map_err(|_| anyhow::anyhow!("decrypt Flux obfs frame header"))?;
            let payload_len = usize::from(u16::from_be_bytes([hdr_plain[0], hdr_plain[1]]));
            let pad_len = usize::from(hdr_plain[2]);
            ensure!(
                payload_len <= OBFS_MAX_CHUNK,
                "invalid Flux obfs record length {payload_len}"
            );
            if payload_len == 0 {
                if pad_len > 0 {
                    body.resize(pad_len, 0);
                    wire_reader
                        .read_exact(&mut body)
                        .await
                        .context("read Flux obfs EOF padding")?;
                }
                let _ = app_sink.shutdown().await;
                return Ok(());
            }
            let ct_len = payload_len + OBFS_TAG_LEN;
            body.resize(ct_len + pad_len, 0);
            wire_reader
                .read_exact(&mut body)
                .await
                .context("read Flux obfs ciphertext")?;
            let plain = data_cipher
                .open_in_place(
                    Nonce::assume_unique_for_key(data_nonce),
                    Aad::from(&hdr_aad),
                    &mut body[..ct_len],
                )
                .map_err(|_| anyhow::anyhow!("decrypt Flux obfs record"))?;
            if app_sink.write_all(plain).await.is_err() {
                return Ok(());
            }
        }
    });

    let write_task = tokio::spawn(async move {
        let hdr_cipher = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &write_dirs.hdr_key)
                .expect("32-byte ChaCha20 key"),
        );
        let data_cipher = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &write_dirs.data_key)
                .expect("32-byte ChaCha20 key"),
        );
        let mut seq = 0u64;
        let mut buf = vec![0u8; OBFS_MAX_CHUNK];
        let mut write_buf =
            Vec::with_capacity(OBFS_STREAM_HDR_WIRE_LEN + OBFS_MAX_CHUNK + OBFS_TAG_LEN + 64);
        loop {
            let read = app_source
                .read(&mut buf)
                .await
                .context("read local Flux obfs source")?;
            let hdr_nonce = step_nonce(&write_dirs.hdr_iv, seq);
            let data_nonce = step_nonce(&write_dirs.data_iv, seq);
            let pad_len = if read > 0 && read < 256 && seq < 16 {
                let mut r = [0u8; 1];
                let _ = getrandom::fill(&mut r);
                usize::from(r[0] & 0x1f)
            } else {
                0
            };
            seq = seq.checked_add(1).context("Flux obfs write seq overflow")?;

            write_buf.clear();
            let len_bytes = (read as u16).to_be_bytes();
            write_buf.extend_from_slice(&[len_bytes[0], len_bytes[1], pad_len as u8, 0]);
            let hdr_tag = hdr_cipher
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(hdr_nonce),
                    Aad::empty(),
                    &mut write_buf[..OBFS_STREAM_HDR_PLAIN_LEN],
                )
                .map_err(|_| anyhow::anyhow!("encrypt Flux obfs frame header"))?;
            write_buf.extend_from_slice(hdr_tag.as_ref());

            if read > 0 {
                let mut hdr_aad = [0u8; OBFS_STREAM_HDR_WIRE_LEN];
                hdr_aad.copy_from_slice(&write_buf[..OBFS_STREAM_HDR_WIRE_LEN]);
                write_buf.extend_from_slice(&buf[..read]);
                let data_tag = data_cipher
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(data_nonce),
                        Aad::from(&hdr_aad),
                        &mut write_buf[OBFS_STREAM_HDR_WIRE_LEN..],
                    )
                    .map_err(|_| anyhow::anyhow!("encrypt Flux obfs record"))?;
                write_buf.extend_from_slice(data_tag.as_ref());
            }
            if pad_len > 0 {
                let pad_start = write_buf.len();
                write_buf.resize(pad_start + pad_len, 0);
                getrandom::fill(&mut write_buf[pad_start..])
                    .map_err(|e| anyhow::anyhow!("Flux obfs frame pad random: {e}"))?;
            }

            wire_writer
                .write_all(&write_buf)
                .await
                .context("write Flux obfs frame")?;
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

pub fn generate_ephemeral_quic_server_tls(
    server_name: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<rustls::ServerConfig> {
    crate::tls::init_crypto();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generate Flux obfs QUIC Ed25519 key")?;
    let mut params = rcgen::CertificateParams::new(vec![server_name.to_string()])
        .context("build Flux obfs QUIC cert params")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params
        .self_signed(&key)
        .context("self-sign Flux obfs QUIC cert")?;
    let cert_der = CertificateDer::from(cert.der().as_ref().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("build Flux obfs QUIC rustls server config")?;
    tls_config.alpn_protocols = alpn_protocols;
    Ok(tls_config)
}

#[derive(Debug)]
pub struct ObfsQuicCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl Default for ObfsQuicCertVerifier {
    fn default() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for ObfsQuicCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
