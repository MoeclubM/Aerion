use super::auth::{self, derive_blind_key, handshake_key, xor_32};
use super::config::{
    FluxChannelClientConfig, FluxChannelRole, FluxClientConfig, FluxIpStrategy, FluxSecurityMode,
    FluxTransportKind,
};
use super::frame::{
    DEFAULT_STREAM_WINDOW_BYTES, FluxFrame, MAX_FLUX_CHUNK_LEN, RecvOffsetAssembler,
    SendWindowBuffer,
};
use super::transport::{
    FluxChannelGuard, FluxFrameReader, FluxFrameWriter, connect_client_channel,
};
use crate::core::{CoreSession, ProxyCore};
use crate::listener::{self, ListenerStopToken};
use crate::protocol::{ProxyTarget, constant_time_eq, password_hash};
use crate::socks::{self, SocksRequest};
use crate::udp_fragments::{FragmentPayload, MAX_PENDING_PACKETS};
use crate::uot;
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::JoinSet;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_UDP_SLICE_BYTES: usize = 1100;
const CHANNEL_DIAL_TIMEOUT: Duration = Duration::from_secs(8);
const PROBE_INTERVAL: Duration = Duration::from_secs(2);
const UDP_FRAG_TIMEOUT: Duration = Duration::from_secs(20);
const MIN_RTO_MS: u64 = 600;

pub async fn run_flux_client(config: FluxClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Flux local SOCKS listener on {}", config.listen))?;
    run_flux_client_listener(listener, config).await
}

pub async fn run_flux_client_listener(
    listener: TcpListener,
    config: FluxClientConfig,
) -> Result<()> {
    run_flux_client_listener_with_core(listener, config, None).await
}

pub async fn run_flux_client_listener_with_core(
    listener: TcpListener,
    config: FluxClientConfig,
    core: Option<ProxyCore>,
) -> Result<()> {
    run_flux_client_listener_with_core_until(listener, config, core, ListenerStopToken::new()).await
}

pub async fn run_flux_client_listener_with_core_until(
    listener: TcpListener,
    config: FluxClientConfig,
    core: Option<ProxyCore>,
    stop: ListenerStopToken,
) -> Result<()> {
    config.validate()?;
    let pool = FluxClientPool::new(config)?;
    let mut handlers = JoinSet::new();
    let bg_stop = pool.stop.clone();
    let bg_pool = pool.clone();
    let bg_handle = tokio::spawn(async move {
        bg_pool.run_maintenance_loop(bg_stop).await;
    });

    let _cleanup = ClientListenerGuard {
        pool: pool.clone(),
        maintenance: bg_handle.abort_handle(),
    };
    tracing::info!(
        "Flux client listening on socks5://{}",
        listener.local_addr()?
    );

    let res = loop {
        let (stream, peer) = tokio::select! {
            _ = stop.stopped() => break Ok(()),
            _ = handlers.join_next(), if !handlers.is_empty() => continue,
            accepted = listener::accept_client(&listener) => match accepted {
                Ok(pair) => pair,
                Err(listener::AcceptError::Cancelled) => break Ok(()),
                Err(listener::AcceptError::Io(err)) => {
                    break Err(err).context("accept Flux SOCKS client");
                }
            }
        };
        let pool = pool.clone();
        let core = core.clone();
        handlers.spawn(async move {
            if let Err(err) = handle_flux_socks_client(stream, peer, pool, core).await {
                tracing::debug!("Flux SOCKS client {peer} ended: {err:#}");
            }
        });
    };

    bg_handle.abort();
    pool.shutdown_all();
    res
}

struct ClientListenerGuard {
    pool: Arc<FluxClientPool>,
    maintenance: tokio::task::AbortHandle,
}

impl Drop for ClientListenerGuard {
    fn drop(&mut self) {
        self.pool.stop.stop();
        self.maintenance.abort();
        self.pool.shutdown_all();
    }
}

#[derive(Clone, Debug)]
struct CandidateEndpoint {
    spec_idx: usize,
    addr: SocketAddr,
}

pub struct ClientChannelHandle {
    pub uid: u64,
    pub spec_idx: usize,
    pub spec_id: String,
    pub remote_addr: SocketAddr,
    pub transport: FluxTransportKind,
    pub security: FluxSecurityMode,
    pub role: FluxChannelRole,
    pub weight: u8,
    prio_tx: mpsc::UnboundedSender<FluxFrame>,
    stream_tx: mpsc::Sender<FluxFrame>,
    dead: AtomicBool,
    draining: AtomicBool,
    state_notify: Notify,
    active_streams: AtomicUsize,
    last_rx_micros: AtomicU64,
    pending_ping: StdMutex<Option<(u64, u64)>>,
    baseline_rtt_ms: AtomicU64,
    smoothed_rtt_ms: AtomicU64,
    degraded_strikes: AtomicUsize,
    bytes_transferred: AtomicU64,
    throughput_sample: StdMutex<(Instant, u64, u64)>,
    throughput_degraded: AtomicBool,
    created_at: Instant,
    rotate_after: Option<Duration>,
    rotate_bytes_limit: Option<u64>,
    guard: Arc<FluxChannelGuard>,
}

impl ClientChannelHandle {
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub fn is_usable_for_new(&self) -> bool {
        !self.is_dead() && !self.is_draining()
    }

    pub fn mark_dead(&self) {
        if !self.dead.swap(true, Ordering::AcqRel) {
            self.guard.close();
            self.state_notify.notify_waiters();
        }
    }

    pub fn mark_draining(&self) {
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.state_notify.notify_waiters();
        }
    }

    pub async fn wait_needs_migration(&self) {
        loop {
            let notified = self.state_notify.notified();
            if self.is_dead() || self.is_draining() {
                return;
            }
            notified.await;
        }
    }

    pub fn rtt_ms(&self) -> u64 {
        self.smoothed_rtt_ms.load(Ordering::Relaxed).max(1)
    }

    fn record_rtt_sample(&self, rtt_ms: u64) -> bool {
        let sample = rtt_ms.max(1);
        let prev_base = self.baseline_rtt_ms.load(Ordering::Relaxed);
        if sample < prev_base || prev_base == 0 {
            self.baseline_rtt_ms.store(sample, Ordering::Relaxed);
        }
        let prev = self.smoothed_rtt_ms.load(Ordering::Relaxed);
        let next = if prev == 0 {
            sample
        } else {
            (prev * 3 + sample) / 4
        };
        self.smoothed_rtt_ms.store(next, Ordering::Relaxed);
        let base = self.baseline_rtt_ms.load(Ordering::Relaxed).max(15);
        if next > (base * 5) / 2 && next > 80 {
            let strikes = self.degraded_strikes.fetch_add(1, Ordering::Relaxed) + 1;
            strikes >= 2
        } else {
            self.degraded_strikes.store(0, Ordering::Relaxed);
            false
        }
    }

    fn should_proactively_rotate(&self) -> bool {
        if let Some(limit) = self.rotate_after
            && self.created_at.elapsed() >= limit
        {
            return true;
        }
        if let Some(bytes_limit) = self.rotate_bytes_limit
            && self.bytes_transferred.load(Ordering::Relaxed) >= bytes_limit
        {
            return true;
        }
        false
    }

    fn send_prio(&self, frame: FluxFrame) -> bool {
        !self.is_dead() && self.prio_tx.send(frame).is_ok()
    }

    async fn send_stream(&self, frame: FluxFrame) -> bool {
        let notified = self.wait_needs_migration();
        let permit = tokio::select! {
            _ = notified => return false,
            _ = self.guard.closed() => return false,
            _ = tokio::time::sleep(Duration::from_millis((self.rtt_ms() * 3).max(600))) => {
                self.mark_draining();
                return false;
            }
            permit = self.stream_tx.reserve() => match permit {
                Ok(permit) => permit,
                Err(_) => return false,
            },
        };
        if self.is_dead() || self.is_draining() {
            return false;
        }
        if let FluxFrame::StreamData { payload, .. } | FluxFrame::UdpDatagram { payload, .. } =
            &frame
        {
            self.bytes_transferred
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
        permit.send(frame);
        true
    }
}

enum ClientStreamEvent {
    Data {
        epoch: u32,
        offset: u64,
        payload: Bytes,
    },
    Ack {
        ack_offset: u64,
    },
    Fin {
        epoch: u32,
        final_offset: u64,
    },
    Rst {
        code: u8,
    },
}

struct ClientUdpFragmentEntry {
    target: ProxyTarget,
    created_at: Instant,
    fragments: FragmentPayload,
}

pub struct FluxClientPool {
    config: FluxClientConfig,
    stop: ListenerStopToken,
    failed_endpoints: StdMutex<HashMap<(usize, SocketAddr), (Instant, u32)>>,
    session_id: [u8; 16],
    cred_hash: [u8; 32],
    started_at: Instant,
    channels: StdMutex<HashMap<u64, Arc<ClientChannelHandle>>>,
    streams: StdMutex<HashMap<u32, mpsc::Sender<ClientStreamEvent>>>,
    udp_assocs: StdMutex<HashMap<u32, mpsc::Sender<(ProxyTarget, Vec<u8>)>>>,
    udp_fragments: Mutex<HashMap<(u32, u32), ClientUdpFragmentEntry>>,
    dial_mutex: Mutex<()>,
    channel_ready: Notify,
    warmer_wake: Notify,
    next_channel_uid: AtomicU64,
    next_stream_id: AtomicU32,
    next_udp_assoc_id: AtomicU32,
    next_udp_packet_id: AtomicU32,
    next_ping_seq: AtomicU64,
}

impl FluxClientPool {
    pub fn new(config: FluxClientConfig) -> Result<Arc<Self>> {
        config.validate()?;
        let mut session_id = [0u8; 16];
        getrandom::fill(&mut session_id)
            .map_err(|e| anyhow::anyhow!("generate Flux session_id: {e}"))?;
        let cred_hash = password_hash(config.key.trim());
        Ok(Arc::new(Self {
            config,
            stop: ListenerStopToken::new(),
            failed_endpoints: StdMutex::new(HashMap::new()),
            session_id,
            cred_hash,
            started_at: Instant::now(),
            channels: StdMutex::new(HashMap::new()),
            streams: StdMutex::new(HashMap::new()),
            udp_assocs: StdMutex::new(HashMap::new()),
            udp_fragments: Mutex::new(HashMap::new()),
            dial_mutex: Mutex::new(()),
            channel_ready: Notify::new(),
            warmer_wake: Notify::new(),
            next_channel_uid: AtomicU64::new(1),
            next_stream_id: AtomicU32::new(1),
            next_udp_assoc_id: AtomicU32::new(1),
            next_udp_packet_id: AtomicU32::new(1),
            next_ping_seq: AtomicU64::new(1),
        }))
    }

    pub fn shutdown_all(&self) {
        let channels =
            std::mem::take(&mut *self.channels.lock().expect("Flux client channels poisoned"));
        for (_, ch) in channels {
            ch.mark_dead();
        }
    }

    fn now_micros(&self) -> u64 {
        self.started_at.elapsed().as_micros() as u64
    }

    fn target_warm_count(&self) -> usize {
        1 + self.config.options.standby_channels
    }

    async fn discover_candidates(&self) -> Result<Vec<CandidateEndpoint>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for (spec_idx, spec) in self.config.channels.iter().enumerate() {
            let ips = resolve_channel_ips(spec, self.config.options.ip_strategy).await;
            for ip in ips {
                for port in &spec.ports {
                    let addr = SocketAddr::new(ip, *port);
                    if seen.insert((spec_idx, addr)) {
                        out.push(CandidateEndpoint { spec_idx, addr });
                    }
                }
            }
        }
        ensure!(
            !out.is_empty(),
            "Flux client resolved no usable IPv4/IPv6 channel endpoints"
        );
        Ok(out)
    }

    fn usable_channels(&self) -> Vec<Arc<ClientChannelHandle>> {
        self.channels
            .lock()
            .expect("Flux client channels poisoned")
            .values()
            .filter(|ch| ch.is_usable_for_new())
            .cloned()
            .collect()
    }

    fn new_stream_candidates(&self) -> Vec<Arc<ClientChannelHandle>> {
        let mut channels = self.usable_channels();
        if channels
            .iter()
            .any(|ch| ch.role == FluxChannelRole::Primary)
        {
            channels.retain(|ch| ch.role == FluxChannelRole::Primary);
        }
        channels
    }

    fn has_usable_channel_excluding(&self, excluded_uid: Option<u64>) -> bool {
        self.channels
            .lock()
            .expect("Flux client channels poisoned")
            .values()
            .any(|ch| ch.is_usable_for_new() && Some(ch.uid) != excluded_uid)
    }

    async fn ensure_usable_channel(self: &Arc<Self>, excluded_uid: Option<u64>) -> Result<()> {
        loop {
            let notified = self.channel_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.has_usable_channel_excluding(excluded_uid) {
                return Ok(());
            }
            if let Ok(guard) = self.dial_mutex.try_lock() {
                drop(guard);
                let pool = self.clone();
                let mut warm_fut = Box::pin(async move { pool.warm_channels_now().await });
                tokio::select! {
                    res = &mut warm_fut => {
                        if self.has_usable_channel_excluding(excluded_uid) {
                            return Ok(());
                        }
                        return res;
                    }
                    _ = &mut notified => {
                        let stop = self.stop.clone();
                        tokio::spawn(async move {
                            tokio::select! {
                                _ = stop.stopped() => {},
                                _ = warm_fut => {},
                            }
                        });
                        if self.has_usable_channel_excluding(excluded_uid) {
                            return Ok(());
                        }
                    }
                }
            } else {
                tokio::select! {
                    _ = &mut notified => {
                        if self.has_usable_channel_excluding(excluded_uid) {
                            return Ok(());
                        }
                    }
                    guard = self.dial_mutex.lock() => {
                        drop(guard);
                        if self.has_usable_channel_excluding(excluded_uid) {
                            return Ok(());
                        }
                        return self.warm_channels_now().await;
                    }
                }
            }
        }
    }

    fn score_channel_for_stream(&self, ch: &ClientChannelHandle) -> i64 {
        let rtt = ch.rtt_ms() as i64;
        let load = (ch.active_streams.load(Ordering::Relaxed) as i64) * 4;
        let weight_bonus = i64::from(ch.weight) / 10;
        let ip_penalty = match (self.config.options.ip_strategy, ch.remote_addr.is_ipv6()) {
            (FluxIpStrategy::PreferV4, true) => 15,
            (FluxIpStrategy::PreferV6, false) => 15,
            _ => 0,
        };
        let role_penalty = match ch.role {
            FluxChannelRole::Primary => 0,
            FluxChannelRole::Backup => 500,
        };
        rtt + load - weight_bonus + ip_penalty + role_penalty
    }

    async fn pick_channel_for_new_stream(self: &Arc<Self>) -> Result<Arc<ClientChannelHandle>> {
        if let Some(best) = self
            .new_stream_candidates()
            .into_iter()
            .min_by_key(|ch| self.score_channel_for_stream(ch))
        {
            self.warmer_wake.notify_one();
            return Ok(best);
        }
        self.ensure_usable_channel(None).await?;
        self.new_stream_candidates()
            .into_iter()
            .min_by_key(|ch| self.score_channel_for_stream(ch))
            .context("no healthy Flux channel available")
    }

    async fn pick_channel_for_udp(self: &Arc<Self>) -> Result<Arc<ClientChannelHandle>> {
        let usable = self.new_stream_candidates();
        if let Some(best) = usable
            .iter()
            .filter(|ch| ch.transport == FluxTransportKind::Udp)
            .min_by_key(|ch| self.score_channel_for_stream(ch))
            .cloned()
            .or_else(|| {
                usable
                    .into_iter()
                    .min_by_key(|ch| self.score_channel_for_stream(ch))
            })
        {
            return Ok(best);
        }
        self.ensure_usable_channel(None).await?;
        let usable = self.new_stream_candidates();
        usable
            .iter()
            .filter(|ch| ch.transport == FluxTransportKind::Udp)
            .min_by_key(|ch| self.score_channel_for_stream(ch))
            .cloned()
            .or_else(|| {
                usable
                    .into_iter()
                    .min_by_key(|ch| self.score_channel_for_stream(ch))
            })
            .context("no healthy Flux channel available for UDP")
    }

    async fn pick_migration_channel(
        self: &Arc<Self>,
        failed: &ClientChannelHandle,
    ) -> Result<Arc<ClientChannelHandle>> {
        let deadline = tokio::time::Instant::now() + super::config::SESSION_RESUME_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            let candidates = self
                .usable_channels()
                .into_iter()
                .filter(|ch| ch.uid != failed.uid)
                .collect::<Vec<_>>();
            if let Some(best) = candidates.into_iter().max_by_key(|ch| {
                let mut heterogeneity = 0i64;
                if ch.remote_addr.is_ipv6() != failed.remote_addr.is_ipv6() {
                    heterogeneity += 150;
                }
                if ch.transport != failed.transport {
                    heterogeneity += 120;
                }
                if ch.security != failed.security {
                    heterogeneity += 60;
                }
                if ch.spec_idx != failed.spec_idx {
                    heterogeneity += 40;
                }
                if ch.remote_addr != failed.remote_addr {
                    heterogeneity += 20;
                }
                heterogeneity - self.score_channel_for_stream(ch)
            }) {
                self.warmer_wake.notify_one();
                return Ok(best);
            }
            if tokio::time::timeout_at(deadline, self.ensure_usable_channel(Some(failed.uid)))
                .await
                .is_err()
            {
                break;
            }
            tokio::select! {
                _ = self.stop.stopped() => bail!("Flux client stopped"),
                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            }
        }
        bail!("all Flux channels unavailable for stream migration")
    }

    async fn warm_channels_now(self: &Arc<Self>) -> Result<()> {
        let _guard = self.dial_mutex.lock().await;
        ensure!(!self.stop.is_stopped(), "Flux client stopped");
        let target = self.target_warm_count();
        let mut active = self.usable_channels();
        if active.len() >= target {
            return Ok(());
        }

        let candidates = self.discover_candidates().await?;

        let mut remaining = candidates
            .into_iter()
            .filter(|cand| {
                !active
                    .iter()
                    .any(|ch| ch.spec_idx == cand.spec_idx && ch.remote_addr == cand.addr)
            })
            .collect::<Vec<_>>();
        remaining.retain(|cand| {
            self.failed_endpoints
                .lock()
                .expect("Flux failures poisoned")
                .get(&(cand.spec_idx, cand.addr))
                .is_none_or(|(until, _)| *until <= Instant::now())
        });
        let mut dial_set = JoinSet::new();
        let mut last_err = None;
        loop {
            while active.len() + dial_set.len() < target && !remaining.is_empty() {
                let best = remaining
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, cand)| {
                        let spec = &self.config.channels[cand.spec_idx];
                        let mut score = i64::from(spec.weight) / 10;
                        if spec.role == FluxChannelRole::Primary {
                            score += 25;
                        }
                        for ch in &active {
                            if ch.remote_addr.is_ipv6() != cand.addr.is_ipv6() {
                                score += 100;
                            }
                            if ch.transport != spec.transport {
                                score += 80;
                            }
                            if ch.spec_idx != cand.spec_idx {
                                score += 30;
                            }
                        }
                        score
                    })
                    .map(|(idx, _)| idx)
                    .unwrap();
                let cand = remaining.swap_remove(best);
                let pool = self.clone();
                dial_set.spawn(async move {
                    let result = pool.dial_and_register_channel(cand.clone()).await;
                    (cand, result)
                });
            }
            let next = tokio::select! {
                _ = self.stop.stopped() => bail!("Flux client stopped"),
                next = dial_set.join_next() => next,
            };
            let Some(next) = next else {
                break;
            };
            match next {
                Ok((cand, Ok(ch))) => {
                    self.failed_endpoints
                        .lock()
                        .expect("Flux failures poisoned")
                        .remove(&(cand.spec_idx, cand.addr));
                    active.push(ch);
                }
                Ok((cand, Err(err))) => {
                    tracing::debug!(channel = %self.config.channels[cand.spec_idx].id, "Flux channel dial failed: {err:#}");
                    let mut failed = self
                        .failed_endpoints
                        .lock()
                        .expect("Flux failures poisoned");
                    let entry = failed
                        .entry((cand.spec_idx, cand.addr))
                        .or_insert((Instant::now(), 0));
                    entry.1 = entry.1.saturating_add(1);
                    entry.0 = Instant::now() + Duration::from_secs(1u64 << entry.1.min(5));
                    last_err = Some(err);
                }
                Err(err) => last_err = Some(anyhow::anyhow!("Flux dial task failed: {err}")),
            }
        }
        if active.is_empty() {
            return Err(last_err.unwrap_or_else(|| {
                anyhow::anyhow!("no Flux channel available; failed entrances are awaiting retry")
            }));
        }
        Ok(())
    }

    async fn dial_and_register_channel(
        self: &Arc<Self>,
        cand: CandidateEndpoint,
    ) -> Result<Arc<ClientChannelHandle>> {
        let spec = &self.config.channels[cand.spec_idx];
        let t0 = Instant::now();
        let (mut reader, mut writer, guard) = tokio::time::timeout(
            CHANNEL_DIAL_TIMEOUT,
            connect_client_channel(spec, cand.addr),
        )
        .await
        .with_context(|| format!("Flux dial timed out for {} ({})", spec.id, cand.addr))??;

        let mut eph_bytes = [0u8; 32];
        getrandom::fill(&mut eph_bytes).map_err(|e| anyhow::anyhow!("Flux hello random: {e}"))?;

        let client_binding = guard.channel_binding()?;
        let (client_ephemeral_pub, blind_key) = if spec.security == FluxSecurityMode::Reality {
            let reality = spec
                .reality
                .as_ref()
                .context("missing Flux client REALITY config")?;
            let secret = StaticSecret::from(eph_bytes);
            let pub_bytes = PublicKey::from(&secret).to_bytes();
            let shared = secret.diffie_hellman(&PublicKey::from(reality.public_key));
            ensure!(
                shared.was_contributory(),
                "non-contributory Flux REALITY public key"
            );
            let bkey = derive_blind_key(shared.as_bytes(), &self.session_id, &client_binding)?;
            (pub_bytes, bkey)
        } else {
            let secret = spec
                .obfs_key
                .as_deref()
                .map(str::as_bytes)
                .unwrap_or(&client_binding);
            let bkey = derive_blind_key(secret, &self.session_id, &eph_bytes)?;
            (eph_bytes, bkey)
        };

        let blinded_credential = xor_32(&self.cred_hash, &blind_key);
        let auth_key = handshake_key(&blind_key, &self.cred_hash, &client_binding)?;
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut hello = FluxFrame::SessionHello {
            session_id: self.session_id,
            client_ephemeral_pub,
            timestamp_secs,
            channel_id: spec.id.clone(),
            blinded_credential,
            client_proof: [0; 32],
        };
        let proof = auth::client_proof(&auth_key, &hello)?;
        if let FluxFrame::SessionHello { client_proof, .. } = &mut hello {
            *client_proof = proof;
        }
        writer.write_frame(&hello, true).await?;

        let ok_frame = tokio::time::timeout(CHANNEL_DIAL_TIMEOUT, reader.read_frame())
            .await
            .context("Flux SessionOk timed out")??
            .context("Flux channel closed before SessionOk")?;
        let FluxFrame::SessionOk {
            status,
            server_proof,
            udp_enabled,
        } = ok_frame
        else {
            bail!("expected Flux SessionOk frame");
        };
        ensure!(
            status == 0,
            "Flux SessionHello rejected with status {status}"
        );
        ensure!(
            constant_time_eq(
                &server_proof,
                &auth::server_proof(&auth_key, &hello, udp_enabled)?
            ),
            "Flux server proof verification failed"
        );

        let init_rtt_ms = (t0.elapsed().as_millis() as u64).max(1);
        let uid = self.next_channel_uid.fetch_add(1, Ordering::Relaxed);
        let (prio_tx, mut prio_rx) = mpsc::unbounded_channel::<FluxFrame>();
        let (stream_tx, mut stream_rx) = mpsc::channel::<FluxFrame>(256);

        let rotate_after = jitter_duration_secs(self.config.options.rotation_interval_sec, 300);
        let rotate_bytes_limit = jitter_bytes_mb(self.config.options.rotation_bytes_mb, 250);

        let handle = Arc::new(ClientChannelHandle {
            uid,
            spec_idx: cand.spec_idx,
            spec_id: spec.id.clone(),
            remote_addr: cand.addr,
            transport: spec.transport,
            security: spec.security,
            role: spec.role,
            weight: spec.weight,
            prio_tx,
            stream_tx,
            dead: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            state_notify: Notify::new(),
            active_streams: AtomicUsize::new(0),
            last_rx_micros: AtomicU64::new(self.now_micros()),
            pending_ping: StdMutex::new(None),
            baseline_rtt_ms: AtomicU64::new(init_rtt_ms),
            smoothed_rtt_ms: AtomicU64::new(init_rtt_ms),
            degraded_strikes: AtomicUsize::new(0),
            bytes_transferred: AtomicU64::new(0),
            throughput_sample: StdMutex::new((Instant::now(), 0, 0)),
            throughput_degraded: AtomicBool::new(false),
            created_at: Instant::now(),
            rotate_after,
            rotate_bytes_limit,
            guard,
        });

        if self.stop.is_stopped() {
            handle.mark_dead();
            bail!("Flux client stopped during dial");
        }
        self.channels
            .lock()
            .expect("Flux client channels poisoned")
            .insert(uid, handle.clone());
        self.channel_ready.notify_waiters();

        let writer_handle = handle.clone();
        let writer_task = tokio::spawn(async move {
            let res = tokio::select! {
                _ = writer_handle.guard.closed() => Ok(()),
                res = run_client_writer_loop(&mut writer, &mut prio_rx, &mut stream_rx) => res,
            };
            writer_handle.mark_dead();
            let _ = writer.shutdown().await;
            res
        });

        let reader_pool = self.clone();
        let reader_handle = handle.clone();
        tokio::spawn(async move {
            let _ = run_client_reader_loop(&mut reader, &reader_handle, &reader_pool).await;
            reader_handle.mark_dead();
            writer_task.abort();
            reader_pool
                .channels
                .lock()
                .expect("Flux client channels poisoned")
                .remove(&uid);
            reader_pool.warmer_wake.notify_one();
        });

        tracing::debug!(
            "Flux client channel {}#{} ({:?}/{:?}) ready to {} (rtt={}ms)",
            spec.id,
            uid,
            spec.transport,
            spec.security,
            cand.addr,
            init_rtt_ms
        );
        Ok(handle)
    }

    async fn run_maintenance_loop(self: Arc<Self>, stop: ListenerStopToken) {
        let mut warming = JoinSet::new();
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        let mut last_probe = Instant::now() - PROBE_INTERVAL;
        loop {
            tokio::select! {
                _ = stop.stopped() => return,
                _ = warming.join_next(), if !warming.is_empty() => {},
                _ = self.warmer_wake.notified() => {},
                _ = tick.tick() => {
                    self.expire_unanswered_probes();
                    if last_probe.elapsed() >= PROBE_INTERVAL {
                        self.probe_and_rotate_channels().await;
                        last_probe = Instant::now();
                    }
                }
            }
            if warming.is_empty() && self.usable_channels().len() < self.target_warm_count() {
                let pool = self.clone();
                warming.spawn(async move { pool.warm_channels_now().await });
            }
        }
    }

    fn expire_unanswered_probes(&self) {
        let now = self.now_micros();
        for ch in self
            .channels
            .lock()
            .expect("Flux client channels poisoned")
            .values()
        {
            let pending = *ch.pending_ping.lock().expect("Flux ping poisoned");
            if let Some((_, sent)) = pending {
                let timeout_us = (ch.rtt_ms() * 3).max(600) * 1000;
                if now.saturating_sub(sent) > timeout_us
                    && now.saturating_sub(ch.last_rx_micros.load(Ordering::Relaxed)) > timeout_us
                {
                    ch.mark_dead();
                }
            }
        }
    }

    async fn probe_and_rotate_channels(self: &Arc<Self>) {
        let snapshot = self
            .channels
            .lock()
            .expect("Flux client channels poisoned")
            .values()
            .cloned()
            .collect::<Vec<_>>();

        for ch in &snapshot {
            if ch.is_dead() {
                continue;
            }
            {
                let total = ch.bytes_transferred.load(Ordering::Relaxed);
                let mut sample = ch
                    .throughput_sample
                    .lock()
                    .expect("Flux throughput poisoned");
                let rate = (total.saturating_sub(sample.1) as f64
                    / sample.0.elapsed().as_secs_f64().max(0.001))
                    as u64;
                ch.throughput_degraded.store(
                    sample.2 > 0 && rate > 0 && rate < sample.2 / 2,
                    Ordering::Relaxed,
                );
                *sample = (Instant::now(), total, sample.2.max(rate));
            }
            if ch.is_draining() {
                if ch.active_streams.load(Ordering::Relaxed) == 0 {
                    ch.mark_dead();
                }
                continue;
            }
            if ch.should_proactively_rotate() {
                let others_usable = snapshot
                    .iter()
                    .filter(|other| other.uid != ch.uid && other.is_usable_for_new())
                    .count();
                if others_usable > 0 {
                    ch.mark_draining();
                    continue;
                }
            }

            let now = self.now_micros();
            let mut pending = ch.pending_ping.lock().expect("Flux ping poisoned");
            if let Some((_, sent)) = *pending {
                let timeout_us = (ch.rtt_ms() * 3).max(600) * 1000;
                if now.saturating_sub(sent) > timeout_us
                    && now.saturating_sub(ch.last_rx_micros.load(Ordering::Relaxed)) > timeout_us
                {
                    ch.mark_dead();
                }
                continue;
            }
            let seq = self.next_ping_seq.fetch_add(1, Ordering::Relaxed);
            *pending = Some((seq, now));
            drop(pending);
            let mut pad_byte = [0u8; 1];
            let _ = getrandom::fill(&mut pad_byte);
            let pad_len = usize::from(pad_byte[0] % 48);
            let mut pad = vec![0u8; pad_len];
            let _ = getrandom::fill(&mut pad);
            let _ = ch.send_prio(FluxFrame::Ping {
                seq,
                sent_micros: now,
                padding: Bytes::from(pad),
            });
        }
    }
}

fn jitter_duration_secs(base_secs: u64, jitter_permille: u64) -> Option<Duration> {
    if base_secs == 0 {
        return None;
    }
    let mut rand_buf = [0u8; 2];
    let _ = getrandom::fill(&mut rand_buf);
    let span = jitter_permille * 2 + 1;
    let offset = u64::from(u16::from_be_bytes(rand_buf)) % span;
    let permille = 1000u64.saturating_sub(jitter_permille) + offset;
    Some(Duration::from_millis(base_secs.saturating_mul(permille)))
}

fn jitter_bytes_mb(base_mb: u64, jitter_permille: u64) -> Option<u64> {
    if base_mb == 0 {
        return None;
    }
    let mut rand_buf = [0u8; 2];
    let _ = getrandom::fill(&mut rand_buf);
    let span = jitter_permille * 2 + 1;
    let offset = u64::from(u16::from_be_bytes(rand_buf)) % span;
    let permille = 1000u64.saturating_sub(jitter_permille) + offset;
    Some((base_mb.saturating_mul(1024 * 1024).saturating_mul(permille)) / 1000)
}

async fn resolve_channel_ips(
    spec: &FluxChannelClientConfig,
    strategy: FluxIpStrategy,
) -> Vec<IpAddr> {
    let allow_v4 = !matches!(strategy, FluxIpStrategy::V6Only) && spec.ip_version != "ipv6";
    let allow_v6 = !matches!(strategy, FluxIpStrategy::V4Only) && spec.ip_version != "ipv4";

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let host_clean = spec.server_host.trim().trim_matches(['[', ']']);

    if let Ok(ip) = host_clean.parse::<IpAddr>() {
        if ((ip.is_ipv4() && allow_v4) || (ip.is_ipv6() && allow_v6)) && seen.insert(ip) {
            out.push(ip);
        }
        return out;
    }

    if !spec.resolved_v4.is_empty() || !spec.resolved_v6.is_empty() {
        if allow_v4 {
            for v4 in &spec.resolved_v4 {
                let ip = IpAddr::V4(*v4);
                if seen.insert(ip) {
                    out.push(ip);
                }
            }
        }
        if allow_v6 {
            for v6 in &spec.resolved_v6 {
                let ip = IpAddr::V6(*v6);
                if seen.insert(ip) {
                    out.push(ip);
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
    }

    let lookup_port = spec.ports.first().copied().unwrap_or(443);
    if let Ok(addrs) = tokio::net::lookup_host((host_clean, lookup_port)).await {
        for sock_addr in addrs {
            let ip = sock_addr.ip();
            if ((ip.is_ipv4() && allow_v4) || (ip.is_ipv6() && allow_v6)) && seen.insert(ip) {
                out.push(ip);
            }
        }
    }
    out
}

async fn run_client_writer_loop(
    writer: &mut FluxFrameWriter,
    prio_rx: &mut mpsc::UnboundedReceiver<FluxFrame>,
    stream_rx: &mut mpsc::Receiver<FluxFrame>,
) -> Result<()> {
    loop {
        let first = tokio::select! {
            frame = prio_rx.recv() => match frame {
                Some(f) => f,
                None => return Ok(()),
            },
            frame = stream_rx.recv() => match frame {
                Some(f) => f,
                None => return Ok(()),
            },
        };
        let mut batch_has_more = !prio_rx.is_empty() || !stream_rx.is_empty();
        writer.write_frame(&first, !batch_has_more).await?;
        let mut drained = 0usize;
        while batch_has_more && drained < 32 {
            let next = if let Ok(p) = prio_rx.try_recv() {
                Some(p)
            } else {
                stream_rx.try_recv().ok()
            };
            let Some(frame) = next else {
                writer.flush().await?;
                break;
            };
            drained += 1;
            batch_has_more = !prio_rx.is_empty() || !stream_rx.is_empty();
            writer
                .write_frame(&frame, !batch_has_more || drained == 32)
                .await?;
        }
    }
}

async fn run_client_reader_loop(
    reader: &mut FluxFrameReader,
    ch: &Arc<ClientChannelHandle>,
    pool: &Arc<FluxClientPool>,
) -> Result<()> {
    while let Some(frame) = reader.read_frame().await? {
        ch.last_rx_micros
            .store(pool.now_micros(), Ordering::Relaxed);
        match frame {
            FluxFrame::Ping {
                seq,
                sent_micros,
                padding,
            } => {
                let _ = ch.send_prio(FluxFrame::Pong {
                    seq,
                    echo_micros: sent_micros,
                    padding,
                });
            }
            FluxFrame::Pong {
                seq, echo_micros, ..
            } => {
                let valid = {
                    let mut pending = ch.pending_ping.lock().expect("Flux ping poisoned");
                    if *pending == Some((seq, echo_micros)) {
                        *pending = None;
                        true
                    } else {
                        false
                    }
                };
                if !valid {
                    continue;
                }
                let now = pool.now_micros();
                let rtt_ms = now.saturating_sub(echo_micros) / 1000;
                let degraded = ch.record_rtt_sample(rtt_ms.max(1));
                if degraded && ch.throughput_degraded.load(Ordering::Relaxed) {
                    let healthier_exists = pool
                        .usable_channels()
                        .iter()
                        .any(|other| other.uid != ch.uid && other.rtt_ms() * 2 < ch.rtt_ms());
                    if healthier_exists {
                        ch.mark_draining();
                    }
                }
            }
            FluxFrame::StreamData {
                stream_id,
                epoch,
                offset,
                payload,
            } => {
                ch.bytes_transferred
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                let tx = pool
                    .streams
                    .lock()
                    .expect("Flux client streams poisoned")
                    .get(&stream_id)
                    .cloned();
                if let Some(tx) = tx {
                    let _ = tx
                        .send(ClientStreamEvent::Data {
                            epoch,
                            offset,
                            payload,
                        })
                        .await;
                }
            }
            FluxFrame::StreamAck {
                stream_id,
                ack_offset,
            } => {
                let tx = pool
                    .streams
                    .lock()
                    .expect("Flux client streams poisoned")
                    .get(&stream_id)
                    .cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(ClientStreamEvent::Ack { ack_offset }).await;
                }
            }
            FluxFrame::StreamFin {
                stream_id,
                epoch,
                final_offset,
            } => {
                let tx = pool
                    .streams
                    .lock()
                    .expect("Flux client streams poisoned")
                    .get(&stream_id)
                    .cloned();
                if let Some(tx) = tx {
                    let _ = tx
                        .send(ClientStreamEvent::Fin {
                            epoch,
                            final_offset,
                        })
                        .await;
                }
            }
            FluxFrame::StreamRst { stream_id, code } => {
                let tx = pool
                    .streams
                    .lock()
                    .expect("Flux client streams poisoned")
                    .get(&stream_id)
                    .cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(ClientStreamEvent::Rst { code }).await;
                }
            }
            FluxFrame::UdpDatagram {
                assoc_id,
                packet_id,
                frag_index,
                frag_total,
                target,
                payload,
            } => {
                ch.bytes_transferred
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                handle_client_udp_datagram(
                    pool, assoc_id, packet_id, frag_index, frag_total, target, payload,
                )
                .await;
            }
            FluxFrame::SessionHello { .. }
            | FluxFrame::SessionOk { .. }
            | FluxFrame::StreamOpen { .. }
            | FluxFrame::StreamMigrate { .. } => {}
        }
    }
    Ok(())
}

async fn handle_client_udp_datagram(
    pool: &Arc<FluxClientPool>,
    assoc_id: u32,
    packet_id: u32,
    frag_index: u8,
    frag_total: u8,
    target: ProxyTarget,
    payload: Bytes,
) {
    if frag_total == 0 || frag_index >= frag_total {
        return;
    }
    let assembled = if frag_total == 1 {
        (target, payload.to_vec())
    } else {
        let mut frags = pool.udp_fragments.lock().await;
        frags.retain(|_, entry| entry.created_at.elapsed() < UDP_FRAG_TIMEOUT);
        if frags.len() >= MAX_PENDING_PACKETS && !frags.contains_key(&(assoc_id, packet_id)) {
            return;
        }
        let entry = frags
            .entry((assoc_id, packet_id))
            .or_insert_with(|| ClientUdpFragmentEntry {
                target: target.clone(),
                created_at: Instant::now(),
                fragments: FragmentPayload::new(frag_total),
            });
        if entry.fragments.count() != usize::from(frag_total) {
            frags.remove(&(assoc_id, packet_id));
            return;
        }
        match entry.fragments.insert(frag_index, payload.to_vec()) {
            Ok(Some(data)) => {
                let src = entry.target.clone();
                frags.remove(&(assoc_id, packet_id));
                (src, data)
            }
            Ok(None) => return,
            Err(_) => {
                frags.remove(&(assoc_id, packet_id));
                return;
            }
        }
    };

    let tx = pool
        .udp_assocs
        .lock()
        .expect("Flux client udp_assocs poisoned")
        .get(&assoc_id)
        .cloned();
    if let Some(tx) = tx {
        let _ = tx.send(assembled).await;
    }
}

async fn handle_flux_socks_client(
    mut local: TcpStream,
    peer: SocketAddr,
    pool: Arc<FluxClientPool>,
    core: Option<ProxyCore>,
) -> Result<()> {
    let core_session = if let Some(core) = &core {
        Some(core.open_session_from("default", peer).await?)
    } else {
        None
    };

    match socks::read_request(&mut local).await? {
        SocksRequest::Connect(target) => {
            let mut active_ch = match pool.pick_channel_for_new_stream().await {
                Ok(ch) => ch,
                Err(err) => {
                    let _ = socks::write_reply(&mut local, 0x05).await;
                    return Err(err);
                }
            };

            let stream_id = pool.next_stream_id.fetch_add(1, Ordering::Relaxed);
            let (ev_tx, ev_rx) = mpsc::channel::<ClientStreamEvent>(128);
            pool.streams
                .lock()
                .expect("Flux client streams poisoned")
                .insert(stream_id, ev_tx);

            let mut opened = active_ch
                .send_stream(FluxFrame::StreamOpen {
                    stream_id,
                    epoch: 1,
                    target: target.clone(),
                    initial_payload: Bytes::new(),
                })
                .await;
            if !opened {
                active_ch.mark_dead();
                if let Ok(fallback_ch) = pool.pick_migration_channel(&active_ch).await {
                    active_ch = fallback_ch;
                    opened = active_ch
                        .send_stream(FluxFrame::StreamOpen {
                            stream_id,
                            epoch: 1,
                            target: target.clone(),
                            initial_payload: Bytes::new(),
                        })
                        .await;
                }
            }
            if !opened {
                pool.streams
                    .lock()
                    .expect("Flux client streams poisoned")
                    .remove(&stream_id);
                let _ = socks::write_reply(&mut local, 0x05).await;
                bail!("failed to open Flux stream on any channel");
            }

            if let Err(err) = socks::write_reply(&mut local, 0x00).await {
                pool.streams
                    .lock()
                    .expect("Flux client streams poisoned")
                    .remove(&stream_id);
                let _ = active_ch
                    .send_stream(FluxFrame::StreamRst { stream_id, code: 0 })
                    .await;
                return Err(err);
            }

            active_ch.active_streams.fetch_add(1, Ordering::Relaxed);
            let res = run_client_stream(
                local,
                pool.clone(),
                active_ch,
                stream_id,
                target,
                ev_rx,
                core_session,
            )
            .await;
            pool.streams
                .lock()
                .expect("Flux client streams poisoned")
                .remove(&stream_id);
            res
        }
        SocksRequest::UdpAssociate => {
            if !pool.config.udp {
                let _ = socks::write_reply(&mut local, 0x07).await;
                bail!("Flux client UDP is disabled");
            }
            handle_flux_udp_associate(local, pool, core_session).await
        }
    }
}

struct StreamSlotGuard {
    ch: Arc<ClientChannelHandle>,
}

impl StreamSlotGuard {
    fn new(ch: Arc<ClientChannelHandle>) -> Self {
        Self { ch }
    }

    fn switch_to(&mut self, next: Arc<ClientChannelHandle>) {
        self.ch.active_streams.fetch_sub(1, Ordering::Relaxed);
        next.active_streams.fetch_add(1, Ordering::Relaxed);
        self.ch = next;
    }
}

impl Drop for StreamSlotGuard {
    fn drop(&mut self) {
        self.ch.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn run_client_stream(
    mut local: TcpStream,
    pool: Arc<FluxClientPool>,
    initial_ch: Arc<ClientChannelHandle>,
    stream_id: u32,
    target: ProxyTarget,
    mut ev_rx: mpsc::Receiver<ClientStreamEvent>,
    core_session: Option<CoreSession>,
) -> Result<()> {
    let mut slot = StreamSlotGuard::new(initial_ch);
    let mut epoch = 1u32;
    let mut uplink_win = SendWindowBuffer::new(DEFAULT_STREAM_WINDOW_BYTES);
    let mut downlink_recv = RecvOffsetAssembler::default();
    let _ = downlink_recv.accept_migrate(1);
    let mut uplink_done = false;
    let mut downlink_done = false;
    let mut last_ack_or_rx = Instant::now();
    let mut half_close_deadline: Option<Instant> = None;
    let mut read_buf = vec![0u8; MAX_FLUX_CHUNK_LEN];

    loop {
        if uplink_done && downlink_done && !uplink_win.has_unacked() {
            let _ = local.shutdown().await;
            return Ok(());
        }

        let local_read_cap = uplink_win.available_window().min(MAX_FLUX_CHUNK_LEN);
        let can_read_local = !uplink_done && local_read_cap > 0;
        let rto_ms = ((slot.ch.rtt_ms() * 3) / 2).max(MIN_RTO_MS);
        let stall_deadline = uplink_win
            .has_unacked()
            .then(|| last_ack_or_rx + Duration::from_millis(rto_ms));

        let cancel_fut = async {
            if let Some(session) = &core_session {
                session.cancelled().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let stall_fut = async {
            if let Some(deadline) = stall_deadline {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let drain_fut = async {
            if let Some(deadline) = half_close_deadline {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let ch_watch = slot.ch.clone();

        tokio::select! {
            _ = cancel_fut => {
                let _ = slot.ch.send_stream(FluxFrame::StreamRst { stream_id, code: 0 }).await;
                let _ = local.shutdown().await;
                return Err(anyhow::anyhow!("core session cancelled"));
            }
            _ = drain_fut => {
                let _ = local.shutdown().await;
                return Ok(());
            }
            _ = ch_watch.wait_needs_migration() => {
                migrate_client_stream(
                    &pool,
                    &mut slot,
                    stream_id,
                    &mut epoch,
                    &target,
                    &uplink_win,
                    &downlink_recv,
                    uplink_done,
                )
                .await?;
                last_ack_or_rx = Instant::now();
            }
            _ = stall_fut => {
                slot.ch.mark_draining();
                migrate_client_stream(
                    &pool,
                    &mut slot,
                    stream_id,
                    &mut epoch,
                    &target,
                    &uplink_win,
                    &downlink_recv,
                    uplink_done,
                )
                .await?;
                last_ack_or_rx = Instant::now();
            }
            ev = ev_rx.recv() => {
                let Some(ev) = ev else {
                    let _ = local.shutdown().await;
                    return Ok(());
                };
                match ev {
                    ClientStreamEvent::Data { epoch: pkt_epoch, offset, payload } => {
                        last_ack_or_rx = Instant::now();
                        let accepted = downlink_recv.accept_data(pkt_epoch, offset, payload)?;
                        if let Some(fresh) = accepted {
                            if let Some(session) = &core_session {
                                session.record_download(fresh.len()).await?;
                            }
                            if let Err(err) = local.write_all(&fresh).await {
                                let rst = FluxFrame::StreamRst {
                                    stream_id,
                                    code: 0,
                                };
                                let _ = slot.ch.send_stream(rst).await;
                                return Err(err).context("write Flux local SOCKS stream");
                            }
                        }
                        let _ = slot.ch.send_prio(FluxFrame::StreamAck {
                            stream_id,
                            ack_offset: downlink_recv.next_offset(),
                        });
                        if !downlink_done && downlink_recv.is_complete() {
                            downlink_done = true;
                            let _ = local.shutdown().await;
                            if uplink_done && half_close_deadline.is_none() {
                                half_close_deadline = Some(Instant::now() + Duration::from_secs(5));
                            }
                        }
                    }
                    ClientStreamEvent::Ack { ack_offset } => {
                        if uplink_win.ack(ack_offset) > 0 {
                            last_ack_or_rx = Instant::now();
                        }
                    }
                    ClientStreamEvent::Fin { epoch: pkt_epoch, final_offset } => {
                        last_ack_or_rx = Instant::now();
                        if downlink_recv.accept_fin(pkt_epoch, final_offset) && !downlink_done {
                            downlink_done = true;
                            let _ = local.shutdown().await;
                            if uplink_done && half_close_deadline.is_none() {
                                half_close_deadline = Some(Instant::now() + Duration::from_secs(5));
                            }
                        }
                    }
                    ClientStreamEvent::Rst { code } => {
                        let _ = local.shutdown().await;
                        let untouched =
                            downlink_recv.next_offset() == 0 && uplink_win.next_offset() == 0;
                        if code != 0 && untouched {
                            bail!("Flux remote stream reset with code {code}");
                        }
                        return Ok(());
                    }
                }
            }
            read_res = local.read(&mut read_buf[..local_read_cap]), if can_read_local => {
                match read_res {
                    Ok(0) => {
                        uplink_done = true;
                        let final_offset = uplink_win.next_offset();
                        if !slot.ch.send_stream(FluxFrame::StreamFin {
                            stream_id,
                            epoch,
                            final_offset,
                        }).await {
                            migrate_client_stream(
                                &pool,
                                &mut slot,
                                stream_id,
                                &mut epoch,
                                &target,
                                &uplink_win,
                                &downlink_recv,
                                uplink_done,
                            )
                            .await?;
                        }
                        if downlink_done && half_close_deadline.is_none() {
                            half_close_deadline = Some(Instant::now() + Duration::from_secs(5));
                        }
                    }
                    Ok(n) => {
                        if let Some(session) = &core_session {
                            session.record_upload(n).await?;
                        }
                        let chunk = Bytes::copy_from_slice(&read_buf[..n]);
                        let was_empty = !uplink_win.has_unacked();
                        let offset = uplink_win.push(chunk.clone());
                        if was_empty {
                            last_ack_or_rx = Instant::now();
                        }
                        if !slot.ch.send_stream(FluxFrame::StreamData {
                            stream_id,
                            epoch,
                            offset,
                            payload: chunk,
                        }).await {
                            migrate_client_stream(
                                &pool,
                                &mut slot,
                                stream_id,
                                &mut epoch,
                                &target,
                                &uplink_win,
                                &downlink_recv,
                                uplink_done,
                            )
                            .await?;
                            last_ack_or_rx = Instant::now();
                        }
                    }
                    Err(err) => {
                        let rst = FluxFrame::StreamRst {
                            stream_id,
                            code: 0,
                        };
                        let _ = slot.ch.send_stream(rst).await;
                        return Err(err).context("read Flux local SOCKS stream");
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn migrate_client_stream(
    pool: &Arc<FluxClientPool>,
    slot: &mut StreamSlotGuard,
    stream_id: u32,
    epoch: &mut u32,
    target: &ProxyTarget,
    uplink_win: &SendWindowBuffer,
    downlink_recv: &RecvOffsetAssembler,
    uplink_done: bool,
) -> Result<()> {
    for _ in 0..3 {
        let next_ch = pool.pick_migration_channel(&slot.ch).await?;
        *epoch = epoch.saturating_add(1);
        let cur_epoch = *epoch;
        slot.switch_to(next_ch);

        let mut ok = slot
            .ch
            .send_stream(FluxFrame::StreamMigrate {
                stream_id,
                epoch: cur_epoch,
                resume_offset: downlink_recv.next_offset(),
                target: target.clone(),
            })
            .await;

        if ok {
            for (offset, chunk) in uplink_win.unacked_from(uplink_win.acked_offset()) {
                if !slot
                    .ch
                    .send_stream(FluxFrame::StreamData {
                        stream_id,
                        epoch: cur_epoch,
                        offset,
                        payload: chunk,
                    })
                    .await
                {
                    ok = false;
                    break;
                }
            }
        }
        if ok && uplink_done {
            ok = slot
                .ch
                .send_stream(FluxFrame::StreamFin {
                    stream_id,
                    epoch: cur_epoch,
                    final_offset: uplink_win.next_offset(),
                })
                .await;
        }
        if ok {
            return Ok(());
        }
        slot.ch.mark_dead();
    }
    bail!("Flux stream {stream_id} migration exhausted available channels")
}

async fn handle_flux_udp_associate(
    mut control: TcpStream,
    pool: Arc<FluxClientPool>,
    core_session: Option<CoreSession>,
) -> Result<()> {
    let _ = pool.pick_channel_for_udp().await?;
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let local_udp = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("bind Flux SOCKS UDP associate on {bind_ip}:0"))?,
    );
    socks::write_reply_with_bind(&mut control, 0x00, local_udp.local_addr()?).await?;

    let assoc_id = pool.next_udp_assoc_id.fetch_add(1, Ordering::Relaxed);
    let (udp_tx, mut udp_rx) = mpsc::channel::<(ProxyTarget, Vec<u8>)>(128);
    pool.udp_assocs
        .lock()
        .expect("Flux client udp_assocs poisoned")
        .insert(assoc_id, udp_tx);

    let mut client_peer: Option<SocketAddr> = None;
    let mut pkt_buf = vec![0u8; 65535 + 512];
    let mut ctrl_probe = [0u8; 1];

    let res = loop {
        let cancel_fut = async {
            if let Some(session) = &core_session {
                session.cancelled().await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            _ = cancel_fut => break Err(anyhow::anyhow!("core session cancelled")),
            read = control.read(&mut ctrl_probe) => {
                if read.context("read Flux SOCKS UDP control")? == 0 {
                    break Ok(());
                }
            }
            received = local_udp.recv_from(&mut pkt_buf) => {
                let (read, peer) = received.context("recv Flux local SOCKS UDP")?;
                client_peer = Some(peer);
                let (target, payload) = uot::parse_socks_udp_packet(&pkt_buf[..read])?;
                if let Some(session) = &core_session {
                    session.record_upload(payload.len()).await?;
                }
                let out_ch = pool.pick_channel_for_udp().await?;
                let pkt_id = pool.next_udp_packet_id.fetch_add(1, Ordering::Relaxed);
                let slices: Vec<&[u8]> = if payload.is_empty() {
                    vec![&[]]
                } else {
                    payload.chunks(MAX_UDP_SLICE_BYTES).collect()
                };
                if slices.len() <= u8::MAX as usize {
                    let total = slices.len() as u8;
                    for (idx, slice) in slices.into_iter().enumerate() {
                        let _ = out_ch.send_stream(FluxFrame::UdpDatagram {
                            assoc_id,
                            packet_id: pkt_id,
                            frag_index: idx as u8,
                            frag_total: total,
                            target: target.clone(),
                            payload: Bytes::copy_from_slice(slice),
                        }).await;
                    }
                }
            }
            downlink = udp_rx.recv() => {
                let Some((source, payload)) = downlink else {
                    break Ok(());
                };
                if let Some(session) = &core_session {
                    session.record_download(payload.len()).await?;
                }
                if let Some(peer) = client_peer {
                    let encoded = uot::encode_socks_udp_packet(&source, &payload)?;
                    let _ = local_udp.send_to(&encoded, peer).await;
                }
            }
        }
    };

    pool.udp_assocs
        .lock()
        .expect("Flux client udp_assocs poisoned")
        .remove(&assoc_id);
    res
}
