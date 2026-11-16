use crate::replay_cache::{ReplayCache, ReplayError};
use crate::vless_transport::BoxedTransportStream;
use anyhow::{Context, Result, bail, ensure};
use bytes::BytesMut;
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey, StaticSecret};

const OBFS_UDP_NONCE_LEN: usize = 24;
const OBFS_UDP_TAG_LEN: usize = 16;
const OBFS_UDP_OVERHEAD: usize = OBFS_UDP_NONCE_LEN + OBFS_UDP_TAG_LEN;
const OBFS_UDP_STACK_BUF_CAP: usize = 2048;
const OBFS_READ_BUF_CAP: usize = 64 * 1024;
const OBFS_MAX_CHUNK: usize = 32 * 1024;
const OBFS_TAG_LEN: usize = 16;
const OBFS_STREAM_HDR_PLAIN_LEN: usize = 4;
const OBFS_STREAM_HDR_WIRE_LEN: usize = OBFS_STREAM_HDR_PLAIN_LEN + OBFS_TAG_LEN;
const OBFS_HELLO_HDR_PLAIN_LEN: usize = 16;
const OBFS_HELLO_HDR_WIRE_LEN: usize = OBFS_HELLO_HDR_PLAIN_LEN + OBFS_TAG_LEN;
const OBFS_MAX_HELLO_PAD: usize = 128;

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

struct FastPadRng(u64);

impl FastPadRng {
    fn from_os_seed() -> Self {
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        let s = u64::from_le_bytes(seed);
        Self(if s == 0 { 0x9e37_79b9_7f4a_7c15 } else { s })
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill_bytes(&mut self, mut dst: &mut [u8]) {
        while dst.len() >= 8 {
            let chunk = self.next_u64().to_le_bytes();
            dst[..8].copy_from_slice(&chunk);
            dst = &mut dst[8..];
        }
        if !dst.is_empty() {
            let chunk = self.next_u64().to_le_bytes();
            dst.copy_from_slice(&chunk[..dst.len()]);
        }
    }
}

pub struct FluxObfsUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    cipher: XChaCha20Poly1305,
    nonce_seed: [u64; 3],
    nonce_seq: AtomicU64,
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
        let mut raw_seed = [0u8; 24];
        getrandom::fill(&mut raw_seed)
            .map_err(|e| anyhow::anyhow!("seed Flux UDP obfs nonce generator: {e}"))?;
        let inner = TokioRuntime
            .wrap_udp_socket(socket)
            .context("wrap Flux obfs UDP socket")?;
        Ok(Self {
            inner,
            cipher: XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&udp_key)),
            nonce_seed: [
                u64::from_le_bytes(raw_seed[0..8].try_into().unwrap()),
                u64::from_le_bytes(raw_seed[8..16].try_into().unwrap()),
                u64::from_le_bytes(raw_seed[16..24].try_into().unwrap()),
            ],
            nonce_seq: AtomicU64::new(1),
        })
    }

    #[inline]
    fn next_nonce(&self) -> [u8; OBFS_UDP_NONCE_LEN] {
        let seq = self.nonce_seq.fetch_add(1, Ordering::Relaxed);
        let w0 = splitmix64(self.nonce_seed[0] ^ seq);
        let w1 = splitmix64(self.nonce_seed[1] ^ seq.rotate_left(21) ^ w0);
        let w2 = splitmix64(self.nonce_seed[2] ^ seq.rotate_left(43) ^ w1);
        let mut out = [0u8; OBFS_UDP_NONCE_LEN];
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out
    }
}

impl AsyncUdpSocket for FluxObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let nonce_bytes = self.next_nonce();
        let total_len = OBFS_UDP_OVERHEAD + transmit.contents.len();
        if total_len <= OBFS_UDP_STACK_BUF_CAP {
            let mut stack_buf = [0u8; OBFS_UDP_STACK_BUF_CAP];
            stack_buf[..OBFS_UDP_NONCE_LEN].copy_from_slice(&nonce_bytes);
            let ct_end = OBFS_UDP_NONCE_LEN + transmit.contents.len();
            stack_buf[OBFS_UDP_NONCE_LEN..ct_end].copy_from_slice(transmit.contents);
            let tag = self
                .cipher
                .encrypt_in_place_detached(
                    XNonce::from_slice(&nonce_bytes),
                    &[],
                    &mut stack_buf[OBFS_UDP_NONCE_LEN..ct_end],
                )
                .map_err(|_| io::Error::other("Flux UDP obfs encrypt failed"))?;
            stack_buf[ct_end..total_len].copy_from_slice(&tag);
            let out = Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &stack_buf[..total_len],
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            return self.inner.try_send(&out);
        }
        let mut packet = Vec::with_capacity(total_len);
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
                            slot_buf.copy_within(src_off + OBFS_UDP_NONCE_LEN..tag_start, dst_off);
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

#[derive(Clone, Copy)]
struct PendingReadRecord {
    payload_len: usize,
    pad_len: usize,
    hdr_aad: [u8; OBFS_STREAM_HDR_WIRE_LEN],
    data_nonce: [u8; 12],
}

pub struct ObfsStream {
    inner: BoxedTransportStream,
    read_hdr_cipher: LessSafeKey,
    read_data_cipher: LessSafeKey,
    read_hdr_iv: [u8; 12],
    read_data_iv: [u8; 12],
    read_seq: u64,
    wire_read_buf: BytesMut,
    plain_read_buf: BytesMut,
    pending_record: Option<PendingReadRecord>,
    read_eof: bool,
    write_hdr_cipher: LessSafeKey,
    write_data_cipher: LessSafeKey,
    write_hdr_iv: [u8; 12],
    write_data_iv: [u8; 12],
    write_seq: u64,
    write_buf: Vec<u8>,
    write_pos: usize,
    write_eof_queued: bool,
    pad_rng: FastPadRng,
}

impl ObfsStream {
    fn flush_pending_write_buf(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write zero to Flux obfs stream",
                )));
            }
            self.write_pos += n;
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn encode_record(&mut self, plain: &[u8]) -> io::Result<()> {
        let read = plain.len();
        let hdr_nonce = step_nonce(&self.write_hdr_iv, self.write_seq);
        let data_nonce = step_nonce(&self.write_data_iv, self.write_seq);
        let pad_len = if read > 0 && read < 256 && self.write_seq < 16 {
            (self.pad_rng.next_u64() as usize) & 0x1f
        } else {
            0
        };
        self.write_seq = self
            .write_seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Flux obfs write seq overflow"))?;

        let base = self.write_buf.len();
        self.write_buf.reserve(
            OBFS_STREAM_HDR_WIRE_LEN + if read > 0 { read + OBFS_TAG_LEN } else { 0 } + pad_len,
        );
        let len_bytes = (read as u16).to_be_bytes();
        self.write_buf
            .extend_from_slice(&[len_bytes[0], len_bytes[1], pad_len as u8, 0]);
        let hdr_tag = self
            .write_hdr_cipher
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(hdr_nonce),
                Aad::empty(),
                &mut self.write_buf[base..base + OBFS_STREAM_HDR_PLAIN_LEN],
            )
            .map_err(|_| io::Error::other("encrypt Flux obfs frame header"))?;
        self.write_buf.extend_from_slice(hdr_tag.as_ref());

        if read > 0 {
            let mut hdr_aad = [0u8; OBFS_STREAM_HDR_WIRE_LEN];
            hdr_aad.copy_from_slice(&self.write_buf[base..base + OBFS_STREAM_HDR_WIRE_LEN]);
            let data_start = self.write_buf.len();
            self.write_buf.extend_from_slice(plain);
            let data_tag = self
                .write_data_cipher
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(data_nonce),
                    Aad::from(&hdr_aad),
                    &mut self.write_buf[data_start..],
                )
                .map_err(|_| io::Error::other("encrypt Flux obfs record"))?;
            self.write_buf.extend_from_slice(data_tag.as_ref());
        }
        if pad_len > 0 {
            let pad_start = self.write_buf.len();
            self.write_buf.resize(pad_start + pad_len, 0);
            self.pad_rng.fill_bytes(&mut self.write_buf[pad_start..]);
        }
        Ok(())
    }

    fn decode_buffered_records(&mut self, dst: &mut ReadBuf<'_>) -> io::Result<()> {
        while !self.read_eof {
            if self.pending_record.is_none() {
                if self.wire_read_buf.len() < OBFS_STREAM_HDR_WIRE_LEN {
                    break;
                }
                let mut hdr_wire = [0u8; OBFS_STREAM_HDR_WIRE_LEN];
                hdr_wire.copy_from_slice(&self.wire_read_buf[..OBFS_STREAM_HDR_WIRE_LEN]);
                let _ = self.wire_read_buf.split_to(OBFS_STREAM_HDR_WIRE_LEN);
                let hdr_aad = hdr_wire;
                let hdr_nonce = step_nonce(&self.read_hdr_iv, self.read_seq);
                let data_nonce = step_nonce(&self.read_data_iv, self.read_seq);
                self.read_seq = self.read_seq.checked_add(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Flux obfs read seq overflow")
                })?;
                let hdr_plain = self
                    .read_hdr_cipher
                    .open_in_place(
                        Nonce::assume_unique_for_key(hdr_nonce),
                        Aad::empty(),
                        &mut hdr_wire,
                    )
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "decrypt Flux obfs frame header")
                    })?;
                let payload_len = usize::from(u16::from_be_bytes([hdr_plain[0], hdr_plain[1]]));
                let pad_len = usize::from(hdr_plain[2]);
                if payload_len > OBFS_MAX_CHUNK {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid Flux obfs record length {payload_len}"),
                    ));
                }
                self.pending_record = Some(PendingReadRecord {
                    payload_len,
                    pad_len,
                    hdr_aad,
                    data_nonce,
                });
            }

            let rec = self.pending_record.unwrap();
            if rec.payload_len == 0 {
                if self.wire_read_buf.len() < rec.pad_len {
                    break;
                }
                if rec.pad_len > 0 {
                    let _ = self.wire_read_buf.split_to(rec.pad_len);
                }
                self.pending_record = None;
                self.read_eof = true;
                break;
            }

            let ct_len = rec.payload_len + OBFS_TAG_LEN;
            let total_body = ct_len + rec.pad_len;
            if self.wire_read_buf.len() < total_body {
                break;
            }
            self.pending_record = None;
            let mut body = self.wire_read_buf.split_to(total_body);
            let plain = self
                .read_data_cipher
                .open_in_place(
                    Nonce::assume_unique_for_key(rec.data_nonce),
                    Aad::from(&rec.hdr_aad),
                    &mut body[..ct_len],
                )
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "decrypt Flux obfs record")
                })?;
            if self.plain_read_buf.is_empty() && plain.len() <= dst.remaining() {
                dst.put_slice(plain);
            } else {
                let direct = dst.remaining().min(plain.len());
                if self.plain_read_buf.is_empty() && direct > 0 {
                    dst.put_slice(&plain[..direct]);
                    self.plain_read_buf.extend_from_slice(&plain[direct..]);
                } else {
                    self.plain_read_buf.extend_from_slice(plain);
                }
            }
        }
        Ok(())
    }
}

impl AsyncRead for ObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = &mut *self;
        if !this.plain_read_buf.is_empty() {
            let n = buf.remaining().min(this.plain_read_buf.len());
            let chunk = this.plain_read_buf.split_to(n);
            buf.put_slice(&chunk);
            if buf.remaining() == 0 || this.wire_read_buf.is_empty() {
                return Poll::Ready(Ok(()));
            }
        }

        let initial_filled = buf.filled().len();
        loop {
            this.decode_buffered_records(buf)?;
            if buf.filled().len() > initial_filled {
                return Poll::Ready(Ok(()));
            }
            if !this.plain_read_buf.is_empty() {
                let n = buf.remaining().min(this.plain_read_buf.len());
                let chunk = this.plain_read_buf.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                return Poll::Ready(Ok(()));
            }

            if this.wire_read_buf.capacity() - this.wire_read_buf.len() < OBFS_MAX_CHUNK + 128 {
                this.wire_read_buf.reserve(OBFS_READ_BUF_CAP);
            }
            let read_n = {
                let spare = this.wire_read_buf.spare_capacity_mut();
                let mut rbuf = ReadBuf::uninit(spare);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rbuf))?;
                rbuf.filled().len()
            };
            if read_n == 0 {
                if this.pending_record.is_none() && this.wire_read_buf.is_empty() {
                    this.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated Flux obfs frame",
                )));
            }
            // SAFETY: `poll_read` initialized `read_n` bytes at the start of `spare_capacity_mut()`.
            unsafe {
                let new_len = this.wire_read_buf.len() + read_n;
                this.wire_read_buf.set_len(new_len);
            }
        }
    }
}

impl AsyncWrite for ObfsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        ready!(this.flush_pending_write_buf(cx))?;
        let chunk = buf.len().min(OBFS_MAX_CHUNK);
        this.encode_record(&buf[..chunk])?;
        if let Poll::Ready(Err(err)) = this.flush_pending_write_buf(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(chunk))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.flush_pending_write_buf(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.flush_pending_write_buf(cx))?;
        if !this.write_eof_queued {
            this.encode_record(&[])?;
            this.write_eof_queued = true;
        }
        ready!(this.flush_pending_write_buf(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
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
    ensure!(
        pad_len <= OBFS_MAX_HELLO_PAD,
        "invalid Flux obfs client padding"
    );
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
    ObfsStream {
        inner: stream,
        read_hdr_cipher: LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &read_dirs.hdr_key).expect("32-byte ChaCha20 key"),
        ),
        read_data_cipher: LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &read_dirs.data_key).expect("32-byte ChaCha20 key"),
        ),
        read_hdr_iv: read_dirs.hdr_iv,
        read_data_iv: read_dirs.data_iv,
        read_seq: 0,
        wire_read_buf: BytesMut::with_capacity(OBFS_READ_BUF_CAP),
        plain_read_buf: BytesMut::with_capacity(16 * 1024),
        pending_record: None,
        read_eof: false,
        write_hdr_cipher: LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &write_dirs.hdr_key).expect("32-byte ChaCha20 key"),
        ),
        write_data_cipher: LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &write_dirs.data_key)
                .expect("32-byte ChaCha20 key"),
        ),
        write_hdr_iv: write_dirs.hdr_iv,
        write_data_iv: write_dirs.data_iv,
        write_seq: 0,
        write_buf: Vec::with_capacity(
            OBFS_STREAM_HDR_WIRE_LEN + OBFS_MAX_CHUNK + OBFS_TAG_LEN + 64,
        ),
        write_pos: 0,
        write_eof_queued: false,
        pad_rng: FastPadRng::from_os_seed(),
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
