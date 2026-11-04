use crate::protocol::constant_time_eq;
use crate::reality::{RealityClientConfig, RealityFallbackLimit, RealityServerConfig};
use crate::replay_cache::ReplayCache;
use crate::socket_protect;
use anyhow::{Context, Result, ensure};
use hmac::{Hmac, Mac};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ConnectionId, ConnectionIdGenerator, UdpPoller};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll, ready};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey, StaticSecret};

pub const REALITY_QUIC_CID_LEN: usize = 16;
const BUCKET_SECS: u64 = 30;
const PEER_AUTH_IDLE_TTL: Duration = Duration::from_secs(180);
const FALLBACK_IDLE_TTL: Duration = Duration::from_secs(30);
const MAX_AUTHORIZED_PEERS: usize = 4096;
const MAX_FALLBACK_RELAYS: usize = 64;

type HmacSha256 = Hmac<Sha256>;
type IoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

pub fn reality_public_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

pub fn derive_quic_reality_seed(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"flux-quic-reality-scid-v1");
    hasher.update(public_key);
    hasher.finalize().into()
}

fn current_bucket() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / BUCKET_SECS
}

fn compute_scid_tag(seed: &[u8; 32], bucket: u64, short_id: &[u8; 8], nonce: &[u8; 6]) -> [u8; 10] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(seed).expect("32-byte HMAC key is valid");
    mac.update(&bucket.to_be_bytes());
    mac.update(short_id);
    mac.update(nonce);
    let digest = mac.finalize().into_bytes();
    let mut tag = [0u8; 10];
    tag.copy_from_slice(&digest[..10]);
    tag
}

pub fn generate_reality_scid(seed: &[u8; 32], short_id: &[u8; 8]) -> [u8; REALITY_QUIC_CID_LEN] {
    let mut nonce = [0u8; 6];
    let _ = getrandom::fill(&mut nonce);
    let tag = compute_scid_tag(seed, current_bucket(), short_id, &nonce);
    let mut out = [0u8; REALITY_QUIC_CID_LEN];
    out[..6].copy_from_slice(&nonce);
    out[6..].copy_from_slice(&tag);
    out
}

pub fn verify_reality_scid(
    seed: &[u8; 32],
    short_ids: &[[u8; 8]],
    scid: &[u8],
    max_skew_buckets: u64,
) -> Option<[u8; REALITY_QUIC_CID_LEN]> {
    if scid.len() != REALITY_QUIC_CID_LEN {
        return None;
    }
    let mut nonce = [0u8; 6];
    nonce.copy_from_slice(&scid[..6]);
    let candidate_tag = &scid[6..16];
    let now = current_bucket();
    let start = now.saturating_sub(max_skew_buckets);
    let end = now.saturating_add(max_skew_buckets);
    let default_sid = [[0u8; 8]];
    let sids = if short_ids.is_empty() {
        default_sid.as_slice()
    } else {
        short_ids
    };
    for bucket in start..=end {
        for sid in sids {
            let expected = compute_scid_tag(seed, bucket, sid, &nonce);
            if constant_time_eq(&expected, candidate_tag) {
                let mut cid = [0u8; REALITY_QUIC_CID_LEN];
                cid.copy_from_slice(scid);
                return Some(cid);
            }
        }
    }
    None
}

fn extract_quic_long_header_scid(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 7 || (packet[0] & 0x80) == 0 {
        return None;
    }
    let dcid_len = usize::from(packet[5]);
    let scid_len_idx = 6usize.checked_add(dcid_len)?;
    let scid_len = usize::from(*packet.get(scid_len_idx)?);
    let scid_start = scid_len_idx + 1;
    let scid_end = scid_start.checked_add(scid_len)?;
    packet.get(scid_start..scid_end)
}

#[derive(Clone, Debug)]
pub struct RealityCidGenerator {
    seed: [u8; 32],
    short_id: [u8; 8],
}

impl RealityCidGenerator {
    pub fn new(config: &RealityClientConfig) -> Self {
        Self {
            seed: derive_quic_reality_seed(&config.public_key),
            short_id: config.short_id,
        }
    }
}

impl ConnectionIdGenerator for RealityCidGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let bytes = generate_reality_scid(&self.seed, &self.short_id);
        ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        REALITY_QUIC_CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

pub fn generate_ephemeral_quic_server_tls(
    server_name: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<rustls::ServerConfig> {
    crate::tls::init_crypto();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generate Flux QUIC REALITY Ed25519 key")?;
    let mut params = rcgen::CertificateParams::new(vec![server_name.to_string()])
        .context("build Flux QUIC REALITY cert params")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params
        .self_signed(&key)
        .context("self-sign Flux QUIC REALITY cert")?;
    let cert_der = CertificateDer::from(cert.der().as_ref().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("build Flux QUIC REALITY rustls server config")?;
    tls_config.alpn_protocols = alpn_protocols;
    Ok(tls_config)
}

#[derive(Debug)]
pub struct RealityQuicCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl Default for RealityQuicCertVerifier {
    fn default() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for RealityQuicCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        // Cryptographic server possession of reality.private_key is enforced
        // immediately on the Flux control handshake before user traffic flows.
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

pub struct RealityUdpSocket {
    io: Arc<UdpSocket>,
    enable_fallback: bool,
    seed: [u8; 32],
    short_ids: Vec<[u8; 8]>,
    max_skew_buckets: u64,
    replay: Arc<ReplayCache<[u8; REALITY_QUIC_CID_LEN]>>,
    authorized_peers: StdMutex<HashMap<SocketAddr, Instant>>,
    fallback_target: Option<(String, u16, RealityFallbackLimit)>,
    fallback_relays: Arc<StdMutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
}

impl fmt::Debug for RealityUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityUdpSocket")
            .field("enable_fallback", &self.enable_fallback)
            .finish_non_exhaustive()
    }
}

struct RealityUdpPoller {
    socket: Arc<RealityUdpSocket>,
    future: Option<IoFuture>,
}

impl fmt::Debug for RealityUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityUdpPoller").finish_non_exhaustive()
    }
}

impl RealityUdpSocket {
    pub fn new(
        socket: std::net::UdpSocket,
        config: &RealityServerConfig,
        enable_fallback_override: Option<bool>,
    ) -> Result<Self> {
        let io = Arc::new(UdpSocket::from_std(socket).context("wrap REALITY tokio UDP socket")?);
        let local_port = io.local_addr()?.port();
        let enable_fallback = enable_fallback_override.unwrap_or(local_port == 443);
        let public_key = reality_public_from_private(&config.private_key);
        let seed = derive_quic_reality_seed(&public_key);
        let max_skew_buckets = if config.max_time_diff_secs == 0 {
            2
        } else {
            (config.max_time_diff_secs / BUCKET_SECS).max(1)
        };
        let replay_ttl = Duration::from_secs((max_skew_buckets * 2 + 2) * BUCKET_SECS);
        let fallback_target = (!config.server_name.trim().is_empty() && config.server_port > 0)
            .then(|| {
                (
                    config.server_name.clone(),
                    config.server_port,
                    config.fallback_limit.clone(),
                )
            });
        ensure!(
            !config.private_key.iter().all(|b| *b == 0),
            "REALITY UDP server private_key cannot be all zeros"
        );
        Ok(Self {
            io,
            enable_fallback,
            seed,
            short_ids: config.short_ids.clone(),
            max_skew_buckets,
            replay: Arc::new(ReplayCache::new(replay_ttl, 8192)),
            authorized_peers: StdMutex::new(HashMap::new()),
            fallback_target,
            fallback_relays: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    fn is_peer_authorized(&self, peer: SocketAddr, now: Instant) -> bool {
        let mut peers = self
            .authorized_peers
            .lock()
            .expect("REALITY UDP authorized_peers lock poisoned");
        if let Some(seen) = peers.get_mut(&peer) {
            if now.duration_since(*seen) <= PEER_AUTH_IDLE_TTL {
                *seen = now;
                return true;
            }
            peers.remove(&peer);
        }
        false
    }

    fn authorize_peer(&self, peer: SocketAddr, now: Instant) {
        let mut peers = self
            .authorized_peers
            .lock()
            .expect("REALITY UDP authorized_peers lock poisoned");
        if peers.len() >= MAX_AUTHORIZED_PEERS {
            peers.retain(|_, seen| now.duration_since(*seen) <= PEER_AUTH_IDLE_TTL);
        }
        if peers.len() < MAX_AUTHORIZED_PEERS {
            peers.insert(peer, now);
        }
    }

    fn forward_probe(&self, peer: SocketAddr, datagram: Vec<u8>) {
        if !self.enable_fallback {
            return;
        }
        let Some((target_host, target_port, limit)) = self.fallback_target.clone() else {
            return;
        };
        let mut relays = self
            .fallback_relays
            .lock()
            .expect("REALITY UDP fallback_relays lock poisoned");
        if let Some(tx) = relays.get(&peer) {
            if tx.try_send(datagram).is_ok() {
                return;
            }
            relays.remove(&peer);
        }
        if relays.len() >= MAX_FALLBACK_RELAYS {
            return;
        }
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
        let _ = tx.try_send(datagram);
        relays.insert(peer, tx);
        let server_io = self.io.clone();
        let relays_map = self.fallback_relays.clone();
        tokio::spawn(async move {
            let _ = run_udp_fallback_relay(
                peer,
                target_host,
                target_port,
                limit,
                server_io,
                &mut rx,
            )
            .await;
            relays_map
                .lock()
                .expect("REALITY UDP fallback_relays lock poisoned")
                .remove(&peer);
        });
    }
}

async fn run_udp_fallback_relay(
    probe_peer: SocketAddr,
    target_host: String,
    target_port: u16,
    limit: RealityFallbackLimit,
    server_io: Arc<UdpSocket>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let target_addr = tokio::net::lookup_host((target_host.as_str(), target_port))
        .await?
        .next()
        .context("resolve REALITY UDP fallback target")?;
    let bind_addr: SocketAddr = if target_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let upstream = socket_protect::bind_udp(bind_addr).await?;
    upstream.connect(target_addr).await?;
    let mut budget = limit.burst_bytes.max(16 * 1024) as f64;
    let rate = limit.bytes_per_sec.max(16 * 1024) as f64;
    let max_burst = budget;
    let mut last_refill = Instant::now();
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = tokio::time::sleep(FALLBACK_IDLE_TTL) => return Ok(()),
            outbound = rx.recv() => {
                let Some(pkt) = outbound else { return Ok(()); };
                let now = Instant::now();
                let add = now.duration_since(last_refill).as_secs_f64() * rate;
                budget = (budget + add).min(max_burst);
                last_refill = now;
                if budget >= pkt.len() as f64 {
                    budget -= pkt.len() as f64;
                    let _ = upstream.send(&pkt).await;
                }
            }
            inbound = upstream.recv(&mut buf) => {
                let read = inbound?;
                let now = Instant::now();
                let add = now.duration_since(last_refill).as_secs_f64() * rate;
                budget = (budget + add).min(max_burst);
                last_refill = now;
                if budget >= read as f64 {
                    budget -= read as f64;
                    let _ = server_io.send_to(&buf[..read], probe_peer).await;
                }
            }
        }
    }
}

impl AsyncUdpSocket for RealityUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(RealityUdpPoller {
            socket: self,
            future: None,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let written = self
            .io
            .try_send_to(transmit.contents, transmit.destination)?;
        if written == transmit.contents.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial REALITY UDP send",
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
            match self.io.try_recv_from(&mut bufs[0]) {
                Ok((read, addr)) => {
                    let now = Instant::now();
                    if self.is_peer_authorized(addr, now) {
                        meta[0] = RecvMeta {
                            addr,
                            len: read,
                            stride: read,
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                    let pkt = &bufs[0][..read];
                    if let Some(scid) = extract_quic_long_header_scid(pkt)
                        && let Some(cid) = verify_reality_scid(
                            &self.seed,
                            &self.short_ids,
                            scid,
                            self.max_skew_buckets,
                        )
                        && self.replay.check_and_store(cid).is_ok()
                    {
                        self.authorize_peer(addr, now);
                        meta[0] = RecvMeta {
                            addr,
                            len: read,
                            stride: read,
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                    self.forward_probe(addr, pkt.to_vec());
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

impl UdpPoller for RealityUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.future.is_none() {
            let io = this.socket.io.clone();
            this.future = Some(Box::pin(async move { io.writable().await }));
        }
        let poll = this
            .future
            .as_mut()
            .expect("REALITY UDP writable future set")
            .as_mut()
            .poll(cx);
        if poll.is_ready() {
            this.future = None;
        }
        poll
    }
}
