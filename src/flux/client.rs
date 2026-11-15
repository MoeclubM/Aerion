use super::auth::{self, derive_blind_key, handshake_key, xor_32};
use super::config::{
    FluxChannelClientConfig, FluxChannelRole, FluxClientConfig, FluxIpStrategy, FluxSecurityMode,
    FluxTransportKind, parse_flux_x25519_key,
};
use super::frame::{
    DEFAULT_STREAM_WINDOW_BYTES, FluxFrame, MAX_FLUX_CHUNK_LEN, RST_CLIENT_ABORT, RST_REMOTE_RESET,
    RecvOffsetAssembler, SendWindowBuffer, push_coalesced_frame,
};
use super::transport::{
    FluxChannelGuard, FluxFrameReader, FluxFrameWriter, connect_client_channel,
};
use crate::core::{CoreSession, ProxyCore};
use crate::listener::{self, ListenerStopToken};
use crate::protocol::{ProxyTarget, constant_time_eq, password_hash};
use crate::socket_protect;
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
const SILENT_PROBE_US: u64 = 600_000;
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(18);
const WRITER_BATCH_MAX: usize = 64;
const STREAM_EVENT_BURST_MAX: usize = 32;
const MAX_AUTO_SCALE_CHANNELS: usize = 16;
const MAX_UDP_RELAY_CHANNELS: usize = 4;
const RATE_SAMPLE_MIN_US: u64 = 100_000;
const RATE_IDLE_RESET_US: u64 = 600_000;
const SHED_CHANNEL_COOLDOWN_US: u64 = 400_000;
const STREAM_REBALANCE_COOLDOWN: Duration = Duration::from_secs(3);
const IDLE_CHANNEL_SCALE_IN_AGE: Duration = Duration::from_secs(15);

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
    run_flux_client_listener_with_pool_until(listener, pool, core, stop).await
}

pub(crate) async fn run_flux_client_listener_with_pool_until(
    listener: TcpListener,
    pool: Arc<FluxClientPool>,
    core: Option<ProxyCore>,
    stop: ListenerStopToken,
) -> Result<()> {
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
    #[allow(dead_code)]
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
    last_rate_sample_us: AtomicU64,
    cached_rate_bps: AtomicU64,
    rate_state: StdMutex<(u64, u64, u64)>,
    shed_tokens: AtomicUsize,
    shed_notify: Notify,
    last_shed_us: AtomicU64,
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
        self.draining.store(true, Ordering::SeqCst);
    }

    fn try_drain_if_idle(&self) -> bool {
        self.draining.store(true, Ordering::SeqCst);
        if self.active_streams.load(Ordering::SeqCst) == 0 {
            self.mark_dead();
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    pub fn active_stream_count(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn total_bytes_transferred(&self) -> u64 {
        self.bytes_transferred.load(Ordering::Relaxed)
    }

    pub fn sample_rate_bps(&self, now_us: u64) -> u64 {
        let total = self.bytes_transferred.load(Ordering::Relaxed);
        let mut state = self.rate_state.lock().expect("Flux rate_state poisoned");
        let elapsed_us = now_us.saturating_sub(state.0);
        if elapsed_us < RATE_SAMPLE_MIN_US {
            return state.2;
        }
        let delta_bytes = total.saturating_sub(state.1);
        let inst_bps = delta_bytes.saturating_mul(1_000_000) / elapsed_us.max(1);
        let prev = state.2;
        let next = if delta_bytes == 0 && elapsed_us >= RATE_IDLE_RESET_US {
            0
        } else if inst_bps >= prev {
            prev.saturating_add(inst_bps.saturating_mul(3)) / 4
        } else {
            let decayed = prev.saturating_mul(2).saturating_add(inst_bps) / 3;
            if decayed < 16_000 { 0 } else { decayed }
        };
        *state = (now_us, total, next);
        self.cached_rate_bps.store(next, Ordering::Relaxed);
        self.last_rate_sample_us.store(now_us, Ordering::Relaxed);
        next
    }

    pub fn current_rate_bps(&self, now_us: u64) -> u64 {
        let last_us = self.last_rate_sample_us.load(Ordering::Relaxed);
        if now_us.saturating_sub(last_us) >= RATE_SAMPLE_MIN_US {
            self.sample_rate_bps(now_us)
        } else {
            self.cached_rate_bps.load(Ordering::Relaxed)
        }
    }

    fn request_stream_shed(&self, now_us: u64) {
        let prev = self.last_shed_us.load(Ordering::Relaxed);
        if prev > 0 && now_us.saturating_sub(prev) < SHED_CHANNEL_COOLDOWN_US {
            return;
        }
        if self.shed_tokens.load(Ordering::Relaxed) == 0 {
            self.last_shed_us.store(now_us.max(1), Ordering::Relaxed);
            self.shed_tokens.store(1, Ordering::Release);
            self.shed_notify.notify_one();
        }
    }

    async fn wait_shed_requested(&self) {
        loop {
            let notified = self.shed_notify.notified();
            if self
                .shed_tokens
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n > 0).then(|| n - 1)
                })
                .is_ok()
            {
                return;
            }
            notified.await;
        }
    }

    pub async fn wait_needs_migration(&self) {
        loop {
            let notified = self.state_notify.notified();
            if self.is_dead() {
                return;
            }
            notified.await;
        }
    }

    pub fn rtt_ms(&self) -> u64 {
        self.smoothed_rtt_ms.load(Ordering::Relaxed).max(1)
    }

    fn probe_timeout_us(&self) -> u64 {
        (self.rtt_ms() * 8).clamp(1800, 4500) * 1000
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

    fn record_outbound_bytes(&self, frame: &FluxFrame) {
        if let FluxFrame::StreamData { payload, .. } | FluxFrame::UdpDatagram { payload, .. } =
            frame
        {
            self.bytes_transferred
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
    }

    fn try_send_stream(&self, frame: FluxFrame) -> std::result::Result<(), Option<FluxFrame>> {
        if self.is_dead() {
            return Err(None);
        }
        self.record_outbound_bytes(&frame);
        match self.stream_tx.try_send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(returned)) => {
                if let FluxFrame::StreamData { payload, .. }
                | FluxFrame::UdpDatagram { payload, .. } = &returned
                {
                    self.bytes_transferred
                        .fetch_sub(payload.len() as u64, Ordering::Relaxed);
                }
                Err(Some(returned))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(None),
        }
    }

    async fn reserve_stream(&self) -> Option<mpsc::Permit<'_, FluxFrame>> {
        if self.is_dead() {
            return None;
        }
        let notified = self.wait_needs_migration();
        let permit = tokio::select! {
            _ = notified => return None,
            _ = self.guard.closed() => return None,
            permit = self.stream_tx.reserve() => permit.ok()?,
        };
        if self.is_dead() {
            return None;
        }
        Some(permit)
    }

    async fn send_stream(&self, frame: FluxFrame) -> bool {
        let Some(permit) = self.reserve_stream().await else {
            return false;
        };
        self.record_outbound_bytes(&frame);
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
    dual_stack_healthy: AtomicBool,
    last_udp_relay_dial_micros: AtomicU64,
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
        let dual_stack_capable = config_allows_dual_stack(&config);
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
            dual_stack_healthy: AtomicBool::new(dual_stack_capable),
            last_udp_relay_dial_micros: AtomicU64::new(0),
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

    fn maybe_observe_channel_rate(&self, ch: &ClientChannelHandle, now_us: u64) {
        if now_us.saturating_sub(ch.last_rate_sample_us.load(Ordering::Relaxed))
            < RATE_SAMPLE_MIN_US
        {
            return;
        }
        let prev = ch.cached_rate_bps.load(Ordering::Relaxed);
        let next = ch.sample_rate_bps(now_us);
        if let Some(budget_bps) = self.config.options.channel_max_bytes_per_sec() {
            let prewarm_bps = (budget_bps * 3 / 4).max(1);
            if prev < prewarm_bps && next >= prewarm_bps {
                self.warmer_wake.notify_one();
            }
        }
    }

    fn target_warm_count(&self) -> usize {
        let base = 1 + self.config.options.standby_channels;
        let Some(budget_bps) = self.config.options.channel_max_bytes_per_sec() else {
            return base;
        };
        let now_us = self.now_micros();
        let prewarm_bps = (budget_bps * 3 / 4).max(1);
        let mut total_bps = 0u64;
        let mut high_water_count = 0usize;
        let has_non_udp = self.has_non_udp_relay_specs();
        for ch in self
            .channels
            .lock()
            .expect("Flux client channels poisoned")
            .values()
        {
            if !ch.is_usable_for_new() || (has_non_udp && ch.role == FluxChannelRole::UdpRelay) {
                continue;
            }
            let rate = ch.current_rate_bps(now_us);
            total_bps = total_bps.saturating_add(rate);
            if rate >= prewarm_bps {
                high_water_count += 1;
            }
        }
        if high_water_count == 0 && total_bps < prewarm_bps {
            return base;
        }
        let by_total = (total_bps / budget_bps) as usize + 1;
        let active_needed = by_total.max(high_water_count + 1);
        let desired = active_needed + self.config.options.standby_channels.min(2);
        desired.clamp(base, MAX_AUTO_SCALE_CHANNELS.max(base))
    }

    fn has_non_udp_relay_specs(&self) -> bool {
        self.config
            .channels
            .iter()
            .any(|ch| ch.role != FluxChannelRole::UdpRelay)
    }

    fn has_udp_relay_specs(&self) -> bool {
        self.config
            .channels
            .iter()
            .any(|ch| ch.role == FluxChannelRole::UdpRelay)
    }

    fn usable_stream_channels(&self) -> Vec<Arc<ClientChannelHandle>> {
        let usable = self.usable_channels();
        if self.has_non_udp_relay_specs() {
            usable
                .into_iter()
                .filter(|ch| ch.role != FluxChannelRole::UdpRelay)
                .collect()
        } else {
            usable
        }
    }

    fn needs_latency_stack_probe(&self, stream_usable: &[Arc<ClientChannelHandle>]) -> bool {
        if self.config.options.ip_strategy != FluxIpStrategy::Latency
            || !self.dual_stack_healthy.load(Ordering::Relaxed)
        {
            return false;
        }
        let has_v4 = stream_usable.iter().any(|ch| ch.remote_addr.is_ipv4());
        let has_v6 = stream_usable.iter().any(|ch| ch.remote_addr.is_ipv6());
        !(has_v4 && has_v6)
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

    pub(crate) fn usable_channels(&self) -> Vec<Arc<ClientChannelHandle>> {
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
        if channels.iter().any(|ch| ch.role.is_primary_tier()) {
            channels.retain(|ch| ch.role.is_primary_tier());
        } else if channels
            .iter()
            .any(|ch| ch.role != FluxChannelRole::UdpRelay)
        {
            channels.retain(|ch| ch.role != FluxChannelRole::UdpRelay);
        }
        channels
    }

    fn has_usable_channel_excluding(
        &self,
        excluded_uid: Option<u64>,
        prefer_stream_tier: bool,
    ) -> bool {
        let require_non_udp_relay = prefer_stream_tier && self.has_non_udp_relay_specs();
        self.channels
            .lock()
            .expect("Flux client channels poisoned")
            .values()
            .any(|ch| {
                ch.is_usable_for_new()
                    && Some(ch.uid) != excluded_uid
                    && (!require_non_udp_relay || ch.role != FluxChannelRole::UdpRelay)
            })
    }

    async fn ensure_usable_channel(self: &Arc<Self>, excluded_uid: Option<u64>) -> Result<()> {
        self.ensure_usable_channel_inner(excluded_uid, false).await
    }

    async fn ensure_usable_stream_channel(
        self: &Arc<Self>,
        excluded_uid: Option<u64>,
    ) -> Result<()> {
        self.ensure_usable_channel_inner(excluded_uid, true).await
    }

    async fn ensure_usable_channel_inner(
        self: &Arc<Self>,
        excluded_uid: Option<u64>,
        prefer_stream_tier: bool,
    ) -> Result<()> {
        loop {
            let notified = self.channel_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.has_usable_channel_excluding(excluded_uid, prefer_stream_tier) {
                return Ok(());
            }
            if let Ok(guard) = self.dial_mutex.try_lock() {
                drop(guard);
                let pool = self.clone();
                let mut warm_fut = Box::pin(async move { pool.warm_channels_now().await });
                tokio::select! {
                    res = &mut warm_fut => {
                        if self.has_usable_channel_excluding(excluded_uid, prefer_stream_tier) {
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
                        if self.has_usable_channel_excluding(excluded_uid, prefer_stream_tier) {
                            return Ok(());
                        }
                    }
                }
            } else {
                tokio::select! {
                    _ = &mut notified => {
                        if self.has_usable_channel_excluding(excluded_uid, prefer_stream_tier) {
                            return Ok(());
                        }
                    }
                    guard = self.dial_mutex.lock() => {
                        drop(guard);
                        if self.has_usable_channel_excluding(excluded_uid, prefer_stream_tier) {
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
        let active = ch.active_streams.load(Ordering::Relaxed);
        let load = if let Some(budget_bps) = self.config.options.channel_max_bytes_per_sec() {
            let rate = ch.current_rate_bps(self.now_micros());
            if rate >= budget_bps {
                let excess_pct =
                    ((rate - budget_bps).saturating_mul(100) / budget_bps.max(1)) as i64;
                10_000 + excess_pct.min(50_000) + (active as i64) * 20
            } else if active > 0 && active < 64 {
                -20 + (active as i64) / 8
            } else {
                (active as i64) / 8
            }
        } else {
            let load_step = match self.config.options.ip_strategy {
                FluxIpStrategy::Latency => 2,
                _ => 6,
            };
            (active as i64) * load_step
        };
        let weight_bonus = i64::from(ch.weight) / 10;
        let transport_bonus = match ch.transport {
            FluxTransportKind::Tcp | FluxTransportKind::Udp => 0,
            FluxTransportKind::Http => -2,
        };
        let ip_penalty = match (self.config.options.ip_strategy, ch.remote_addr.is_ipv6()) {
            (FluxIpStrategy::PreferV4, true) => 15,
            (FluxIpStrategy::PreferV6, false) => 15,
            _ => 0,
        };
        let role_penalty = match ch.role {
            FluxChannelRole::Prefer => -25,
            FluxChannelRole::Primary => 0,
            FluxChannelRole::Backup => 500,
            FluxChannelRole::UdpRelay => 1000,
        };
        let congestion_penalty = (ch.degraded_strikes.load(Ordering::Relaxed) as i64) * 60
            + if ch.throughput_degraded.load(Ordering::Relaxed) {
                40
            } else {
                0
            };
        rtt + load - weight_bonus - transport_bonus + ip_penalty + role_penalty + congestion_penalty
    }

    fn score_channel_for_udp(&self, ch: &ClientChannelHandle) -> i64 {
        let base = self.score_channel_for_stream(ch);
        if ch.role == FluxChannelRole::UdpRelay {
            base - 1200
        } else {
            base
        }
    }

    pub(crate) async fn pick_channel_for_new_stream(self: &Arc<Self>) -> Result<StreamSlotGuard> {
        let mut candidates = self.new_stream_candidates();
        let needs_stream_warm = candidates.is_empty()
            || (self.has_non_udp_relay_specs()
                && candidates
                    .iter()
                    .all(|ch| ch.role == FluxChannelRole::UdpRelay));
        if !needs_stream_warm {
            candidates.sort_by_key(|ch| self.score_channel_for_stream(ch));
            if let Some(slot) = candidates.into_iter().find_map(StreamSlotGuard::try_acquire) {
                self.warmer_wake.notify_one();
                return Ok(slot);
            }
        }
        let warm_res = self.ensure_usable_stream_channel(None).await;
        let mut refreshed = self.new_stream_candidates();
        refreshed.sort_by_key(|ch| self.score_channel_for_stream(ch));
        if let Some(slot) = refreshed.into_iter().find_map(StreamSlotGuard::try_acquire) {
            self.warmer_wake.notify_one();
            return Ok(slot);
        }
        warm_res?;
        bail!("no healthy Flux channel available")
    }

    fn pick_rebalance_channel(
        &self,
        current: &ClientChannelHandle,
    ) -> Option<Arc<ClientChannelHandle>> {
        let budget_bps = self.config.options.channel_max_bytes_per_sec()?;
        let receiver_cap_bps = (budget_bps * 3 / 4).max(1);
        let now_us = self.now_micros();
        self.new_stream_candidates()
            .into_iter()
            .filter(|ch| {
                ch.uid != current.uid
                    && ch.role.is_primary_tier()
                    && ch.current_rate_bps(now_us) < receiver_cap_bps
            })
            .min_by_key(|ch| self.score_channel_for_stream(ch))
    }

    fn udp_relay_needs_warm(&self, usable: &[Arc<ClientChannelHandle>], now_us: u64) -> bool {
        let relays = usable
            .iter()
            .filter(|ch| ch.role == FluxChannelRole::UdpRelay)
            .collect::<Vec<_>>();
        if relays.is_empty() {
            return true;
        }
        let Some(budget_bps) = self.config.options.channel_max_bytes_per_sec() else {
            return false;
        };
        let prewarm_bps = (budget_bps * 3 / 4).max(1);
        relays.len() < MAX_UDP_RELAY_CHANNELS
            && relays.iter().all(|ch| ch.current_rate_bps(now_us) >= prewarm_bps)
    }

    async fn maybe_warm_udp_relay_channel(self: &Arc<Self>, has_fallback_usable: bool) {
        if !self.has_udp_relay_specs() {
            return;
        }
        let now_us = self.now_micros();
        let initial_usable = self.usable_channels();
        if !self.udp_relay_needs_warm(&initial_usable, now_us) {
            return;
        }
        let has_existing_relay = initial_usable
            .iter()
            .any(|ch| ch.role == FluxChannelRole::UdpRelay);
        if has_fallback_usable || has_existing_relay {
            let prev = self.last_udp_relay_dial_micros.load(Ordering::Relaxed);
            if prev > 0 && now_us.saturating_sub(prev) < 2_000_000 {
                return;
            }
        }
        self.last_udp_relay_dial_micros
            .store(now_us.max(1), Ordering::Relaxed);

        let _guard = self.dial_mutex.lock().await;
        let active_usable = self.usable_channels();
        if self.stop.is_stopped() || !self.udp_relay_needs_warm(&active_usable, self.now_micros()) {
            return;
        }
        let Ok(candidates) = self.discover_candidates().await else {
            return;
        };
        let now = Instant::now();
        let best = candidates
            .into_iter()
            .filter(|cand| {
                self.config.channels[cand.spec_idx].role == FluxChannelRole::UdpRelay
                    && self
                        .failed_endpoints
                        .lock()
                        .expect("Flux failures poisoned")
                        .get(&(cand.spec_idx, cand.addr))
                        .is_none_or(|(until, _)| *until <= now)
            })
            .min_by_key(|cand| {
                let spec = &self.config.channels[cand.spec_idx];
                let existing = active_usable
                    .iter()
                    .filter(|ch| ch.spec_idx == cand.spec_idx && ch.remote_addr == cand.addr)
                    .count() as i64;
                let ip_pen = match (self.config.options.ip_strategy, cand.addr.is_ipv6()) {
                    (FluxIpStrategy::PreferV4, true) => 15i64,
                    (FluxIpStrategy::PreferV6, false) => 15i64,
                    _ => 0i64,
                };
                existing * 10 + ip_pen - i64::from(spec.weight) / 10
            });
        if let Some(cand) = best {
            match self.dial_and_register_channel(cand.clone()).await {
                Ok(_) => {
                    self.failed_endpoints
                        .lock()
                        .expect("Flux failures poisoned")
                        .remove(&(cand.spec_idx, cand.addr));
                }
                Err(err) => {
                    tracing::debug!(
                        channel = %self.config.channels[cand.spec_idx].id,
                        "Flux UDP relay channel dial failed: {err:#}"
                    );
                    let mut failed = self
                        .failed_endpoints
                        .lock()
                        .expect("Flux failures poisoned");
                    let entry = failed
                        .entry((cand.spec_idx, cand.addr))
                        .or_insert((Instant::now(), 0));
                    entry.1 = entry.1.saturating_add(1);
                    entry.0 = Instant::now() + Duration::from_secs(1u64 << entry.1.min(5));
                }
            }
        }
    }

    pub(crate) async fn pick_channel_for_udp(self: &Arc<Self>) -> Result<Arc<ClientChannelHandle>> {
        let usable = self.usable_channels();
        let now_us = self.now_micros();
        if let Some(best_relay) = usable
            .iter()
            .filter(|ch| ch.role == FluxChannelRole::UdpRelay)
            .min_by_key(|ch| self.score_channel_for_udp(ch))
            .cloned()
        {
            if self.udp_relay_needs_warm(&usable, now_us) {
                let pool = self.clone();
                tokio::spawn(async move {
                    pool.maybe_warm_udp_relay_channel(true).await;
                });
            }
            return Ok(best_relay);
        }
        self.maybe_warm_udp_relay_channel(!usable.is_empty()).await;
        let usable = self.usable_channels();
        if let Some(best) = usable
            .into_iter()
            .min_by_key(|ch| self.score_channel_for_udp(ch))
        {
            return Ok(best);
        }
        self.ensure_usable_channel(None).await?;
        self.usable_channels()
            .into_iter()
            .min_by_key(|ch| self.score_channel_for_udp(ch))
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
        let has_stream_specs = self.has_non_udp_relay_specs();
        let mut active = self.usable_stream_channels();
        if active.len() >= target && !self.needs_latency_stack_probe(&active) {
            return Ok(());
        }

        let candidates = self.discover_candidates().await?;
        let now = Instant::now();
        let healthy_candidates = candidates
            .into_iter()
            .filter(|cand| {
                (!has_stream_specs
                    || self.config.channels[cand.spec_idx].role != FluxChannelRole::UdpRelay)
                    && self
                        .failed_endpoints
                        .lock()
                        .expect("Flux failures poisoned")
                        .get(&(cand.spec_idx, cand.addr))
                        .is_none_or(|(until, _)| *until <= now)
            })
            .collect::<Vec<_>>();
        let has_v4 = healthy_candidates.iter().any(|c| c.addr.is_ipv4());
        let has_v6 = healthy_candidates.iter().any(|c| c.addr.is_ipv6());
        self.dual_stack_healthy
            .store(has_v4 && has_v6, Ordering::Relaxed);
        let pass1_target =
            if self.config.options.ip_strategy == FluxIpStrategy::Latency && has_v4 && has_v6 {
                target.max(2)
            } else {
                target
            };
        if active.len() >= pass1_target {
            return Ok(());
        }

        let mut remaining = healthy_candidates
            .iter()
            .filter(|cand| {
                !active
                    .iter()
                    .any(|ch| ch.spec_idx == cand.spec_idx && ch.remote_addr == cand.addr)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut planned: Vec<(usize, SocketAddr, FluxTransportKind)> = active
            .iter()
            .map(|ch| (ch.spec_idx, ch.remote_addr, ch.transport))
            .collect();
        let mut dial_set = JoinSet::new();
        let mut last_err = None;
        loop {
            while active.len() + dial_set.len() < pass1_target && !remaining.is_empty() {
                let best = remaining
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, cand)| {
                        let spec = &self.config.channels[cand.spec_idx];
                        let mut score = i64::from(spec.weight) / 10;
                        score += match spec.role {
                            FluxChannelRole::Prefer => 35,
                            FluxChannelRole::Primary => 25,
                            FluxChannelRole::Backup => 0,
                            FluxChannelRole::UdpRelay => -40,
                        };
                        match (self.config.options.ip_strategy, cand.addr.is_ipv6()) {
                            (FluxIpStrategy::PreferV4, false) => score += 15,
                            (FluxIpStrategy::PreferV6, true) => score += 15,
                            _ => {}
                        }
                        for &(p_spec_idx, p_addr, p_transport) in &planned {
                            if p_addr.is_ipv6() != cand.addr.is_ipv6() {
                                score += 100;
                            }
                            if p_transport != spec.transport {
                                score += 80;
                            }
                            if p_spec_idx != cand.spec_idx {
                                score += 30;
                            }
                        }
                        score
                    })
                    .map(|(idx, _)| idx)
                    .unwrap();
                let cand = remaining.swap_remove(best);
                planned.push((
                    cand.spec_idx,
                    cand.addr,
                    self.config.channels[cand.spec_idx].transport,
                ));
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
                    planned.retain(|&(idx, addr, _)| !(idx == cand.spec_idx && addr == cand.addr));
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

        if !active.is_empty() && active.len() < target {
            let now_scale = Instant::now();
            let mut scale_pool = healthy_candidates
                .iter()
                .filter(|cand| {
                    self.config.channels[cand.spec_idx].role.is_primary_tier()
                        && self
                            .failed_endpoints
                            .lock()
                            .expect("Flux failures poisoned")
                            .get(&(cand.spec_idx, cand.addr))
                            .is_none_or(|(until, _)| *until <= now_scale)
                })
                .cloned()
                .collect::<Vec<_>>();
            if scale_pool.is_empty() {
                scale_pool = healthy_candidates
                    .into_iter()
                    .filter(|cand| {
                        self.failed_endpoints
                            .lock()
                            .expect("Flux failures poisoned")
                            .get(&(cand.spec_idx, cand.addr))
                            .is_none_or(|(until, _)| *until <= now_scale)
                    })
                    .collect();
            }
            if !scale_pool.is_empty() {
                let mut in_flight: HashMap<(usize, SocketAddr), usize> = HashMap::new();
                while active.len() + dial_set.len() < target {
                    let cand = scale_pool
                        .iter()
                        .min_by_key(|cand| {
                            let spec = &self.config.channels[cand.spec_idx];
                            let existing = active
                                .iter()
                                .filter(|ch| {
                                    ch.spec_idx == cand.spec_idx && ch.remote_addr == cand.addr
                                })
                                .count()
                                + in_flight
                                    .get(&(cand.spec_idx, cand.addr))
                                    .copied()
                                    .unwrap_or(0);
                            let role_bias = if spec.role == FluxChannelRole::Prefer {
                                -4i64
                            } else {
                                0i64
                            };
                            let rtt_term = if self.config.options.ip_strategy
                                == FluxIpStrategy::Latency
                            {
                                active
                                    .iter()
                                    .filter(|ch| {
                                        ch.spec_idx == cand.spec_idx && ch.remote_addr == cand.addr
                                    })
                                    .map(|ch| ch.rtt_ms() as i64)
                                    .min()
                                    .unwrap_or(50)
                                    / 5
                            } else {
                                0i64
                            };
                            (existing as i64) * 10 - i64::from(spec.weight) / 20
                                + role_bias
                                + rtt_term
                        })
                        .cloned()
                        .unwrap();
                    *in_flight.entry((cand.spec_idx, cand.addr)).or_insert(0) += 1;
                    let pool = self.clone();
                    dial_set.spawn(async move {
                        let result = pool.dial_and_register_channel(cand.clone()).await;
                        (cand, result)
                    });
                }
                while let Some(next) = tokio::select! {
                    _ = self.stop.stopped() => bail!("Flux client stopped"),
                    next = dial_set.join_next() => next,
                } {
                    if let Ok((cand, res)) = next {
                        match res {
                            Ok(ch) => {
                                self.failed_endpoints
                                    .lock()
                                    .expect("Flux failures poisoned")
                                    .remove(&(cand.spec_idx, cand.addr));
                                active.push(ch);
                            }
                            Err(err) => {
                                let mut failed = self
                                    .failed_endpoints
                                    .lock()
                                    .expect("Flux failures poisoned");
                                let entry = failed
                                    .entry((cand.spec_idx, cand.addr))
                                    .or_insert((Instant::now(), 0));
                                entry.1 = entry.1.saturating_add(1);
                                let delay = Duration::from_secs(1u64 << entry.1.min(5));
                                entry.0 = Instant::now() + delay;
                                last_err = Some(err);
                            }
                        }
                    }
                }
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
        let (mut reader, mut writer, guard) = tokio::time::timeout(
            CHANNEL_DIAL_TIMEOUT,
            connect_client_channel(spec, cand.addr),
        )
        .await
        .with_context(|| format!("Flux dial timed out for {} ({})", spec.id, cand.addr))??;

        let (client_ephemeral_pub, static_ss) = if let Some(pub_str) = spec.public_key.as_deref() {
            let server_pub = parse_flux_x25519_key(pub_str)?;
            let mut priv_bytes = [0u8; 32];
            getrandom::fill(&mut priv_bytes)
                .map_err(|e| anyhow::anyhow!("Flux hello random: {e}"))?;
            let eph_secret = StaticSecret::from(priv_bytes);
            let eph_pub = PublicKey::from(&eph_secret).to_bytes();
            let ss = eph_secret.diffie_hellman(&PublicKey::from(server_pub));
            ensure!(
                ss.was_contributory(),
                "invalid Flux server X25519 public key"
            );
            (eph_pub, Some(*ss.as_bytes()))
        } else {
            let mut eph_bytes = [0u8; 32];
            getrandom::fill(&mut eph_bytes)
                .map_err(|e| anyhow::anyhow!("Flux hello random: {e}"))?;
            (eph_bytes, None)
        };

        let client_binding = guard.channel_binding()?;
        let secret = static_ss.unwrap_or(client_binding);
        let blind_key = derive_blind_key(&secret, &self.session_id, &client_ephemeral_pub)?;

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
        let t_hello = Instant::now();
        writer.write_frame(&hello, true).await?;

        let ok_frame = tokio::time::timeout(CHANNEL_DIAL_TIMEOUT, reader.read_frame())
            .await
            .context("Flux SessionOk timed out")??
            .context("Flux channel closed before SessionOk")?;
        let init_rtt_ms = (t_hello.elapsed().as_millis() as u64).max(1);
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

        let uid = self.next_channel_uid.fetch_add(1, Ordering::Relaxed);
        let (prio_tx, mut prio_rx) = mpsc::unbounded_channel::<FluxFrame>();
        let (stream_tx, mut stream_rx) = mpsc::channel::<FluxFrame>(512);

        let rotate_after = jitter_duration_secs(self.config.options.rotation_interval_sec, 300);
        let rotate_bytes_limit = jitter_bytes_mb(self.config.options.rotation_bytes_mb, 250);
        let init_now_us = self.now_micros();

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
            last_rx_micros: AtomicU64::new(init_now_us),
            pending_ping: StdMutex::new(None),
            baseline_rtt_ms: AtomicU64::new(init_rtt_ms),
            smoothed_rtt_ms: AtomicU64::new(init_rtt_ms),
            degraded_strikes: AtomicUsize::new(0),
            bytes_transferred: AtomicU64::new(0),
            last_rate_sample_us: AtomicU64::new(init_now_us),
            cached_rate_bps: AtomicU64::new(0),
            rate_state: StdMutex::new((init_now_us, 0, 0)),
            shed_tokens: AtomicUsize::new(0),
            shed_notify: Notify::new(),
            last_shed_us: AtomicU64::new(0),
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
                _ = warming.join_next(), if !warming.is_empty() => continue,
                _ = self.warmer_wake.notified() => {},
                _ = tick.tick() => {
                    self.refresh_rates_and_rebalance();
                    self.expire_unanswered_probes();
                    self.probe_silent_active_channels();
                    if last_probe.elapsed() >= PROBE_INTERVAL {
                        self.probe_and_rotate_channels().await;
                        last_probe = Instant::now();
                    }
                }
            }
            if warming.is_empty() {
                let stream_usable = self.usable_stream_channels();
                if stream_usable.len() < self.target_warm_count()
                    || self.needs_latency_stack_probe(&stream_usable)
                {
                    let pool = self.clone();
                    warming.spawn(async move { pool.warm_channels_now().await });
                }
            }
        }
    }

    fn refresh_rates_and_rebalance(&self) {
        let now_us = self.now_micros();
        let snapshot = self
            .channels
            .lock()
            .expect("Flux client channels poisoned")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for ch in &snapshot {
            if !ch.is_dead() {
                ch.sample_rate_bps(now_us);
            }
        }
        let Some(budget_bps) = self.config.options.channel_max_bytes_per_sec() else {
            return;
        };
        let overload_bps = budget_bps.saturating_mul(11) / 10;
        let receiver_cap_bps = (budget_bps * 3 / 4).max(1);
        for ch in &snapshot {
            if !ch.is_usable_for_new() || ch.role == FluxChannelRole::UdpRelay {
                continue;
            }
            if ch.active_streams.load(Ordering::Relaxed) <= 1 {
                continue;
            }
            if ch.current_rate_bps(now_us) <= overload_bps {
                continue;
            }
            let has_underbudget_peer = snapshot.iter().any(|other| {
                other.uid != ch.uid
                    && other.is_usable_for_new()
                    && other.role.is_primary_tier()
                    && other.current_rate_bps(now_us) < receiver_cap_bps
            });
            if has_underbudget_peer {
                ch.request_stream_shed(now_us);
            } else {
                self.warmer_wake.notify_one();
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
                let timeout_us = ch.probe_timeout_us();
                if now.saturating_sub(sent) > timeout_us
                    && now.saturating_sub(ch.last_rx_micros.load(Ordering::Relaxed)) > timeout_us
                {
                    ch.mark_dead();
                }
            }
        }
    }

    fn send_ping_on_channel(&self, ch: &ClientChannelHandle, now: u64) {
        let seq = self.next_ping_seq.fetch_add(1, Ordering::Relaxed);
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
        *ch.pending_ping.lock().expect("Flux ping poisoned") = Some((seq, now));
    }

    fn probe_silent_active_channels(&self) {
        let now = self.now_micros();
        let snapshot = self
            .channels
            .lock()
            .expect("Flux client channels poisoned")
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for ch in &snapshot {
            if ch.is_dead() || ch.active_streams.load(Ordering::Relaxed) == 0 {
                continue;
            }
            if now.saturating_sub(ch.last_rx_micros.load(Ordering::Relaxed)) < SILENT_PROBE_US {
                continue;
            }
            if ch
                .pending_ping
                .lock()
                .expect("Flux ping poisoned")
                .is_none()
            {
                self.send_ping_on_channel(ch, now);
            }
        }
    }

    async fn probe_and_rotate_channels(self: &Arc<Self>) {
        if self.config.options.ip_strategy == FluxIpStrategy::Latency
            && config_allows_dual_stack(&self.config)
            && !self.dual_stack_healthy.load(Ordering::Relaxed)
        {
            let now = Instant::now();
            let mut failed = self
                .failed_endpoints
                .lock()
                .expect("Flux failures poisoned");
            let before = failed.len();
            failed.retain(|_, (until, _)| *until > now);
            if failed.len() < before {
                self.dual_stack_healthy.store(true, Ordering::Relaxed);
            }
        }
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
                if ch.active_streams.load(Ordering::SeqCst) == 0 {
                    ch.mark_dead();
                }
                continue;
            }
            if ch.should_proactively_rotate() {
                let others_usable = snapshot
                    .iter()
                    .filter(|other| {
                        other.uid != ch.uid
                            && other.is_usable_for_new()
                            && (ch.role == FluxChannelRole::UdpRelay
                                || other.role != FluxChannelRole::UdpRelay)
                    })
                    .count();
                if others_usable > 0 {
                    ch.mark_draining();
                    continue;
                }
            }

            let now = self.now_micros();
            let pending = *ch.pending_ping.lock().expect("Flux ping poisoned");
            if let Some((_, sent)) = pending {
                let timeout_us = ch.probe_timeout_us();
                if now.saturating_sub(sent) > timeout_us
                    && now.saturating_sub(ch.last_rx_micros.load(Ordering::Relaxed)) > timeout_us
                {
                    ch.mark_dead();
                }
                continue;
            }
            self.send_ping_on_channel(ch, now);
        }
        self.shrink_idle_excess_channels(&snapshot);
    }

    fn shrink_idle_excess_channels(&self, snapshot: &[Arc<ClientChannelHandle>]) {
        let now_us = self.now_micros();
        let target = self.target_warm_count();
        let preserve_dual_stack = self.config.options.ip_strategy == FluxIpStrategy::Latency
            && self.dual_stack_healthy.load(Ordering::Relaxed);
        let min_stream_keep = if preserve_dual_stack {
            target.max(2)
        } else {
            target
        };
        let has_non_udp = self.has_non_udp_relay_specs();

        let mut stream_channels = snapshot
            .iter()
            .filter(|ch| {
                ch.is_usable_for_new() && (!has_non_udp || ch.role != FluxChannelRole::UdpRelay)
            })
            .cloned()
            .collect::<Vec<_>>();
        if stream_channels.len() > min_stream_keep {
            stream_channels.sort_by_key(|ch| self.score_channel_for_stream(ch));
            let mut keep_uids = HashSet::with_capacity(min_stream_keep);
            if preserve_dual_stack {
                if let Some(best_v4) = stream_channels.iter().find(|ch| ch.remote_addr.is_ipv4()) {
                    keep_uids.insert(best_v4.uid);
                }
                if let Some(best_v6) = stream_channels.iter().find(|ch| ch.remote_addr.is_ipv6()) {
                    keep_uids.insert(best_v6.uid);
                }
            }
            for ch in &stream_channels {
                if keep_uids.len() >= min_stream_keep {
                    break;
                }
                keep_uids.insert(ch.uid);
            }
            for ch in stream_channels.into_iter().rev() {
                if keep_uids.contains(&ch.uid) {
                    continue;
                }
                if ch.active_streams.load(Ordering::SeqCst) == 0
                    && ch.current_rate_bps(now_us) == 0
                    && ch.created_at.elapsed() >= IDLE_CHANNEL_SCALE_IN_AGE
                {
                    let _ = ch.try_drain_if_idle();
                }
            }
        }

        let mut udp_relays = snapshot
            .iter()
            .filter(|ch| ch.is_usable_for_new() && ch.role == FluxChannelRole::UdpRelay)
            .cloned()
            .collect::<Vec<_>>();
        if udp_relays.len() > 1 {
            udp_relays.sort_by_key(|ch| self.score_channel_for_udp(ch));
            let best_relay_uid = udp_relays[0].uid;
            for ch in udp_relays.into_iter().skip(1) {
                if ch.uid == best_relay_uid {
                    continue;
                }
                if ch.active_streams.load(Ordering::SeqCst) == 0
                    && ch.current_rate_bps(now_us) == 0
                    && ch.created_at.elapsed() >= IDLE_CHANNEL_SCALE_IN_AGE
                {
                    let _ = ch.try_drain_if_idle();
                }
            }
        }
    }
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    use std::future::{Future, poll_fn};

    #[tokio::test]
    async fn unavailable_entrances_do_not_spin_maintenance() -> Result<()> {
        let reserved = TcpListener::bind("127.0.0.1:0").await?;
        let port = reserved.local_addr()?.port();
        drop(reserved);
        let proxy: crate::config_compat::mihomo::MihomoFluxProxy = serde_json::from_value(
            serde_json::json!({
                "name": "Flux", "server": "127.0.0.1", "port": port,
                "key": "test-user",
                "channels": [{"id": "tcp", "transport": "tcp", "security": "obfs", "public-key": crate::flux::config::generate_flux_x25519_keypair()?.1}],
            }),
        )?;
        let pool = FluxClientPool::new(proxy.to_client_config("127.0.0.1:0".parse()?)?)?;
        let stop = pool.stop.clone();
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let mut maintenance = Box::pin(pool.run_maintenance_loop(stop.clone()));
        let task = tokio::spawn(async move {
            poll_fn(|cx| {
                observed.fetch_add(1, Ordering::Relaxed);
                maintenance.as_mut().poll(cx)
            })
            .await;
        });
        tokio::time::sleep(Duration::from_millis(650)).await;
        stop.stop();
        task.await?;
        assert!(polls.load(Ordering::Relaxed) < 64);
        Ok(())
    }

    #[tokio::test]
    async fn idle_excess_channels_scale_in_while_preserving_dual_stack_floor() -> Result<()> {
        let pub_key = crate::flux::config::generate_flux_x25519_keypair()?.1;
        let proxy: crate::config_compat::mihomo::MihomoFluxProxy = serde_json::from_value(
            serde_json::json!({
                "name": "Flux",
                "server": "edge.example.com",
                "port": 443,
                "key": "test-user",
                "ip-strategy": "latency",
                "standby-channels": 0,
                "channel-max-mbps": 20,
                "resolved-v4": ["127.0.0.1"],
                "resolved-v6": ["::1"],
                "channels": [
                    {"id": "v4", "transport": "tcp", "ip-version": "ipv4", "security": "obfs", "public-key": pub_key.clone()},
                    {"id": "v6", "transport": "tcp", "ip-version": "ipv6", "security": "obfs", "public-key": pub_key}
                ],
            }),
        )?;
        let pool = FluxClientPool::new(proxy.to_client_config("127.0.0.1:0".parse()?)?)?;
        let old_created = Instant::now() - Duration::from_secs(20);

        let make_handle = |uid: u64, spec_idx: usize, addr: SocketAddr, rtt: u64, created_at: Instant| {
            let (a, _b) = tokio::io::duplex(64);
            let (_, _, guard) =
                super::super::transport::split_boxed_stream_with_binding(Box::new(a), Some([7; 32]));
            let (prio_tx, _prio_rx) = mpsc::unbounded_channel();
            let (stream_tx, _stream_rx) = mpsc::channel(16);
            Arc::new(ClientChannelHandle {
                uid,
                spec_idx,
                spec_id: format!("ch-{uid}"),
                remote_addr: addr,
                transport: FluxTransportKind::Tcp,
                security: FluxSecurityMode::Obfs,
                role: FluxChannelRole::Primary,
                weight: 100,
                prio_tx,
                stream_tx,
                dead: AtomicBool::new(false),
                draining: AtomicBool::new(false),
                state_notify: Notify::new(),
                active_streams: AtomicUsize::new(0),
                last_rx_micros: AtomicU64::new(0),
                pending_ping: StdMutex::new(None),
                baseline_rtt_ms: AtomicU64::new(rtt),
                smoothed_rtt_ms: AtomicU64::new(rtt),
                degraded_strikes: AtomicUsize::new(0),
                bytes_transferred: AtomicU64::new(0),
                last_rate_sample_us: AtomicU64::new(0),
                cached_rate_bps: AtomicU64::new(0),
                rate_state: StdMutex::new((0, 0, 0)),
                shed_tokens: AtomicUsize::new(0),
                shed_notify: Notify::new(),
                last_shed_us: AtomicU64::new(0),
                throughput_sample: StdMutex::new((Instant::now(), 0, 0)),
                throughput_degraded: AtomicBool::new(false),
                created_at,
                rotate_after: None,
                rotate_bytes_limit: None,
                guard,
            })
        };

        let ch1 = make_handle(1, 0, "127.0.0.1:443".parse()?, 20, old_created);
        let ch2 = make_handle(2, 0, "127.0.0.1:443".parse()?, 25, old_created);
        let ch3 = make_handle(3, 0, "127.0.0.1:443".parse()?, 30, Instant::now()); // young (<15s)
        let ch4 = make_handle(4, 1, "[::1]:443".parse()?, 80, old_created); // sole IPv6 channel
        {
            let mut map = pool.channels.lock().unwrap();
            for ch in [&ch1, &ch2, &ch3, &ch4] {
                map.insert(ch.uid, ch.clone());
            }
        }

        let snap = pool.usable_channels();
        pool.shrink_idle_excess_channels(&snap);

        // ch2 (excess old IPv4) shrinks; ch4 (sole IPv6 for dual-stack latency) & ch3 (young) & ch1 stay!
        assert!(!ch1.is_dead());
        assert!(ch2.is_dead());
        assert!(!ch3.is_dead());
        assert!(!ch4.is_dead());
        Ok(())
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

fn config_allows_dual_stack(config: &FluxClientConfig) -> bool {
    if matches!(
        config.options.ip_strategy,
        FluxIpStrategy::V4Only | FluxIpStrategy::V6Only
    ) {
        return false;
    }
    let has_stream_specs = config
        .channels
        .iter()
        .any(|ch| ch.role != FluxChannelRole::UdpRelay);
    let allows_v4 = config.channels.iter().any(|ch| {
        (!has_stream_specs || ch.role != FluxChannelRole::UdpRelay) && ch.ip_version != "ipv6"
    });
    let allows_v6 = config.channels.iter().any(|ch| {
        (!has_stream_specs || ch.role != FluxChannelRole::UdpRelay) && ch.ip_version != "ipv4"
    });
    allows_v4 && allows_v6
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
    let mut batch = Vec::with_capacity(WRITER_BATCH_MAX);
    loop {
        batch.clear();
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
        push_coalesced_frame(&mut batch, first);
        while batch.len() < WRITER_BATCH_MAX {
            if let Ok(p) = prio_rx.try_recv() {
                push_coalesced_frame(&mut batch, p);
            } else if let Ok(s) = stream_rx.try_recv() {
                push_coalesced_frame(&mut batch, s);
            } else {
                break;
            }
        }
        let last_idx = batch.len() - 1;
        for (idx, frame) in batch.iter().enumerate() {
            writer.write_frame(frame, idx == last_idx).await?;
        }
    }
}

async fn run_client_reader_loop(
    reader: &mut FluxFrameReader,
    ch: &Arc<ClientChannelHandle>,
    pool: &Arc<FluxClientPool>,
) -> Result<()> {
    while let Some(frame) = reader.read_frame().await? {
        let rx_now_us = pool.now_micros();
        ch.last_rx_micros.store(rx_now_us, Ordering::Relaxed);
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
                pool.maybe_observe_channel_rate(ch, rx_now_us);
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
                pool.maybe_observe_channel_rate(ch, rx_now_us);
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
            let mut slot = match pool.pick_channel_for_new_stream().await {
                Ok(slot) => slot,
                Err(err) => {
                    let _ = socks::write_reply(&mut local, socks::reply_code_for_proxy_error(&err))
                        .await;
                    return Err(err);
                }
            };

            let stream_id = pool.next_stream_id.fetch_add(1, Ordering::Relaxed);
            let (ev_tx, mut ev_rx) = mpsc::channel::<ClientStreamEvent>(512);
            pool.streams
                .lock()
                .expect("Flux client streams poisoned")
                .insert(stream_id, ev_tx);

            let open_frame = FluxFrame::StreamOpen {
                stream_id,
                epoch: 1,
                target: target.clone(),
                initial_payload: Bytes::new(),
            };
            let mut opened = slot.ch.send_prio(open_frame.clone());
            if !opened {
                slot.ch.mark_dead();
                if let Ok(fallback_ch) = pool.pick_migration_channel(&slot.ch).await {
                    slot.switch_to(fallback_ch);
                    opened = slot.ch.send_prio(open_frame);
                }
            }
            if !opened {
                pool.streams
                    .lock()
                    .expect("Flux client streams poisoned")
                    .remove(&stream_id);
                let _ = socks::write_reply(&mut local, socks::REPLY_GENERAL_FAILURE).await;
                bail!("failed to open Flux stream on any channel");
            }

            let mut initial_epoch = 1u32;
            let initial_event = match wait_flux_stream_open(
                &local,
                &pool,
                &mut slot,
                stream_id,
                &mut initial_epoch,
                &target,
                &mut ev_rx,
                core_session.as_ref(),
            )
            .await
            {
                Ok(event) => event,
                Err((Some(reply_code), err)) => {
                    pool.streams
                        .lock()
                        .expect("Flux client streams poisoned")
                        .remove(&stream_id);
                    let _ = socks::write_reply(&mut local, reply_code).await;
                    return Err(err);
                }
                Err((None, err)) => {
                    pool.streams
                        .lock()
                        .expect("Flux client streams poisoned")
                        .remove(&stream_id);
                    return Err(err);
                }
            };

            if let Err(err) = socks::write_reply(&mut local, socks::REPLY_SUCCEEDED).await {
                pool.streams
                    .lock()
                    .expect("Flux client streams poisoned")
                    .remove(&stream_id);
                let _ = slot
                    .ch
                    .send_stream(FluxFrame::StreamRst {
                        stream_id,
                        code: RST_CLIENT_ABORT,
                    })
                    .await;
                return Err(err);
            }

            let res = run_client_stream(
                local,
                pool.clone(),
                slot,
                stream_id,
                initial_epoch,
                initial_event,
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
                let _ = socks::write_reply(&mut local, socks::REPLY_COMMAND_NOT_SUPPORTED).await;
                bail!("Flux client UDP is disabled");
            }
            handle_flux_udp_associate(local, pool, core_session).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_flux_stream_open(
    local: &TcpStream,
    pool: &Arc<FluxClientPool>,
    slot: &mut StreamSlotGuard,
    stream_id: u32,
    epoch: &mut u32,
    target: &ProxyTarget,
    ev_rx: &mut mpsc::Receiver<ClientStreamEvent>,
    core_session: Option<&CoreSession>,
) -> std::result::Result<Option<ClientStreamEvent>, (Option<u8>, anyhow::Error)> {
    let empty_win = SendWindowBuffer::new(DEFAULT_STREAM_WINDOW_BYTES);
    let empty_recv = RecvOffsetAssembler::default();
    let deadline = tokio::time::Instant::now() + STREAM_OPEN_TIMEOUT;
    let mut watch_local = true;
    let mut peek_buf = [0u8; 1];
    loop {
        let cancel_fut = async {
            if let Some(session) = core_session {
                session.cancelled().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let ch_watch = slot.ch.clone();
        tokio::select! {
            _ = cancel_fut => {
                let _ = slot.ch.send_prio(FluxFrame::StreamRst {
                    stream_id,
                    code: RST_CLIENT_ABORT,
                });
                return Err((
                    Some(socks::REPLY_GENERAL_FAILURE),
                    anyhow::anyhow!("core session cancelled"),
                ));
            }
            _ = tokio::time::sleep_until(deadline) => {
                let _ = slot.ch.send_prio(FluxFrame::StreamRst {
                    stream_id,
                    code: RST_CLIENT_ABORT,
                });
                return Err((
                    Some(socks::REPLY_TTL_EXPIRED),
                    anyhow::anyhow!("Flux stream {stream_id} connect timed out"),
                ));
            }
            peek_res = local.peek(&mut peek_buf), if watch_local => match peek_res {
                Ok(0) => {
                    let _ = slot.ch.send_prio(FluxFrame::StreamRst {
                        stream_id,
                        code: RST_CLIENT_ABORT,
                    });
                    return Err((
                        None,
                        anyhow::anyhow!("Flux local SOCKS client closed before connect reply"),
                    ));
                }
                Err(err) => {
                    let _ = slot.ch.send_prio(FluxFrame::StreamRst {
                        stream_id,
                        code: RST_CLIENT_ABORT,
                    });
                    return Err((
                        None,
                        anyhow::Error::new(err)
                            .context("Flux local SOCKS client aborted before connect reply"),
                    ));
                }
                Ok(_) => {
                    watch_local = false;
                }
            },
            _ = ch_watch.wait_needs_migration() => {
                if let Err(err) = migrate_client_stream(
                    pool,
                    slot,
                    stream_id,
                    epoch,
                    target,
                    &empty_win,
                    &empty_recv,
                    false,
                )
                .await
                {
                    return Err((Some(socks::REPLY_GENERAL_FAILURE), err));
                }
            }
            ev = ev_rx.recv() => match ev {
                Some(ClientStreamEvent::Ack { ack_offset }) => {
                    let initial = (ack_offset > 0).then_some(ClientStreamEvent::Ack { ack_offset });
                    return Ok(initial);
                }
                Some(ev @ ClientStreamEvent::Data { .. })
                | Some(ev @ ClientStreamEvent::Fin { .. }) => {
                    return Ok(Some(ev));
                }
                Some(ClientStreamEvent::Rst { code }) => {
                    let reply = if (0x01..=0x08).contains(&code) {
                        code
                    } else {
                        socks::REPLY_GENERAL_FAILURE
                    };
                    return Err((
                        Some(reply),
                        anyhow::anyhow!(
                            "Flux target connect failed with code {reply:#04x} ({})",
                            socks::reply_code_description(reply)
                        ),
                    ));
                }
                None => {
                    return Err((
                        Some(socks::REPLY_GENERAL_FAILURE),
                        anyhow::anyhow!("Flux stream {stream_id} closed before connect reply"),
                    ));
                }
            }
        }
    }
}

pub(crate) struct StreamSlotGuard {
    pub(crate) ch: Arc<ClientChannelHandle>,
}

impl StreamSlotGuard {
    fn try_acquire(ch: Arc<ClientChannelHandle>) -> Option<Self> {
        ch.active_streams.fetch_add(1, Ordering::SeqCst);
        if !ch.is_usable_for_new() {
            ch.active_streams.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Self { ch })
    }

    fn switch_to(&mut self, next: Arc<ClientChannelHandle>) {
        self.ch.active_streams.fetch_sub(1, Ordering::SeqCst);
        next.active_streams.fetch_add(1, Ordering::SeqCst);
        self.ch = next;
    }
}

impl Drop for StreamSlotGuard {
    fn drop(&mut self) {
        self.ch.active_streams.fetch_sub(1, Ordering::SeqCst);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_client_stream(
    mut local: TcpStream,
    pool: Arc<FluxClientPool>,
    mut slot: StreamSlotGuard,
    stream_id: u32,
    initial_epoch: u32,
    mut pending_initial_event: Option<ClientStreamEvent>,
    target: ProxyTarget,
    mut ev_rx: mpsc::Receiver<ClientStreamEvent>,
    core_session: Option<CoreSession>,
) -> Result<()> {
    let mut epoch = initial_epoch;
    let mut uplink_win = SendWindowBuffer::new(DEFAULT_STREAM_WINDOW_BYTES);
    let mut downlink_recv = RecvOffsetAssembler::default();
    let _ = downlink_recv.accept_migrate(initial_epoch);
    let mut uplink_done = false;
    let mut downlink_done = false;
    let mut pending_uplink: Option<FluxFrame> = None;
    let mut half_close_deadline: Option<Instant> = None;
    let mut last_rebalance: Option<Instant> = None;
    let mut read_buf = vec![0u8; MAX_FLUX_CHUNK_LEN];

    loop {
        if let Some(first_ev) = pending_initial_event.take() {
            match first_ev {
                ClientStreamEvent::Data {
                    epoch: pkt_epoch,
                    offset,
                    payload,
                } => {
                    if let Some(fresh) = downlink_recv.accept_data(pkt_epoch, offset, payload)? {
                        if let Some(session) = &core_session {
                            session.record_download(fresh.len()).await?;
                        }
                        if let Err(err) = local.write_all(&fresh).await {
                            let _ = slot
                                .ch
                                .send_stream(FluxFrame::StreamRst {
                                    stream_id,
                                    code: RST_CLIENT_ABORT,
                                })
                                .await;
                            return Err(err).context("write Flux local SOCKS stream");
                        }
                    }
                    let _ = slot.ch.send_prio(FluxFrame::StreamAck {
                        stream_id,
                        ack_offset: downlink_recv.next_offset(),
                    });
                }
                ClientStreamEvent::Ack { ack_offset } => {
                    uplink_win.ack(ack_offset);
                }
                ClientStreamEvent::Fin {
                    epoch: pkt_epoch,
                    final_offset,
                } => {
                    if downlink_recv.accept_fin(pkt_epoch, final_offset) {
                        downlink_done = true;
                        let _ = local.shutdown().await;
                    }
                }
                ClientStreamEvent::Rst { .. } => {
                    socket_protect::reset_tcp_stream(&local);
                    return Ok(());
                }
            }
        }

        if uplink_done && downlink_done && pending_uplink.is_none() && !uplink_win.has_unacked() {
            let _ = local.shutdown().await;
            return Ok(());
        }

        let local_read_cap = uplink_win.available_window().min(MAX_FLUX_CHUNK_LEN);
        let can_read_local = !uplink_done && pending_uplink.is_none() && local_read_cap > 0;
        let can_rebalance = !uplink_done
            && !downlink_done
            && last_rebalance.is_none_or(|t| t.elapsed() >= STREAM_REBALANCE_COOLDOWN);

        let cancel_fut = async {
            if let Some(session) = &core_session {
                session.cancelled().await;
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
        let ch_pending = slot.ch.clone();

        tokio::select! {
            _ = cancel_fut => {
                let _ = slot
                    .ch
                    .send_stream(FluxFrame::StreamRst {
                        stream_id,
                        code: RST_CLIENT_ABORT,
                    })
                    .await;
                let _ = local.shutdown().await;
                return Err(anyhow::anyhow!("core session cancelled"));
            }
            _ = drain_fut => {
                let _ = local.shutdown().await;
                return Ok(());
            }
            _ = ch_watch.wait_needs_migration() => {
                pending_uplink = None;
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
            _ = ch_watch.wait_shed_requested(), if can_rebalance => {
                if slot.ch.active_streams.load(Ordering::Relaxed) > 1
                    && let Some(next_ch) = pool.pick_rebalance_channel(&slot.ch)
                {
                    pending_uplink = None;
                    epoch = epoch.saturating_add(1);
                    let cur_epoch = epoch;
                    slot.switch_to(next_ch);
                    last_rebalance = Some(Instant::now());
                    if !send_stream_migration_frames(
                        &slot.ch,
                        stream_id,
                        cur_epoch,
                        &target,
                        &uplink_win,
                        &downlink_recv,
                        uplink_done,
                    )
                    .await
                    {
                        slot.ch.mark_dead();
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
                }
            }
            permit_res = ch_pending.reserve_stream(), if pending_uplink.is_some() => {
                match permit_res {
                    Some(permit) => {
                        if let Some(frame) = pending_uplink.take() {
                            ch_pending.record_outbound_bytes(&frame);
                            permit.send(frame);
                        }
                    }
                    None => {
                        pending_uplink = None;
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
                }
            }
            ev = ev_rx.recv() => {
                let Some(ev) = ev else {
                    let _ = local.shutdown().await;
                    return Ok(());
                };
                let mut cur_ev = Some(ev);
                let mut drained = 0usize;
                let mut ack_dirty = false;
                while let Some(event) = cur_ev.take() {
                    match event {
                        ClientStreamEvent::Data {
                            epoch: pkt_epoch,
                            offset,
                            payload,
                        } => {
                            let accepted = downlink_recv.accept_data(pkt_epoch, offset, payload)?;
                            if let Some(fresh) = accepted {
                                if let Some(session) = &core_session {
                                    session.record_download(fresh.len()).await?;
                                }
                                if let Err(err) = local.write_all(&fresh).await {
                                    let rst = FluxFrame::StreamRst {
                                        stream_id,
                                        code: RST_CLIENT_ABORT,
                                    };
                                    let _ = slot.ch.send_stream(rst).await;
                                    return Err(err).context("write Flux local SOCKS stream");
                                }
                            }
                            ack_dirty = true;
                            if !downlink_done && downlink_recv.is_complete() {
                                downlink_done = true;
                                let _ = local.shutdown().await;
                                if uplink_done && half_close_deadline.is_none() {
                                    half_close_deadline =
                                        Some(Instant::now() + Duration::from_secs(5));
                                }
                            }
                        }
                        ClientStreamEvent::Ack { ack_offset } => {
                            uplink_win.ack(ack_offset);
                        }
                        ClientStreamEvent::Fin {
                            epoch: pkt_epoch,
                            final_offset,
                        } => {
                            if downlink_recv.accept_fin(pkt_epoch, final_offset) && !downlink_done {
                                downlink_done = true;
                                let _ = local.shutdown().await;
                                if uplink_done && half_close_deadline.is_none() {
                                    half_close_deadline =
                                        Some(Instant::now() + Duration::from_secs(5));
                                }
                            }
                        }
                        ClientStreamEvent::Rst { code } => {
                            socket_protect::reset_tcp_stream(&local);
                            let untouched =
                                downlink_recv.next_offset() == 0 && uplink_win.next_offset() == 0;
                            if code != 0 && untouched {
                                bail!("Flux remote stream reset with code {code}");
                            }
                            return Ok(());
                        }
                    }
                    drained += 1;
                    if drained < STREAM_EVENT_BURST_MAX {
                        cur_ev = ev_rx.try_recv().ok();
                    }
                }
                if ack_dirty {
                    let _ = slot.ch.send_prio(FluxFrame::StreamAck {
                        stream_id,
                        ack_offset: downlink_recv.next_offset(),
                    });
                }
            }
            read_res = local.read(&mut read_buf[..local_read_cap]), if can_read_local => {
                match read_res {
                    Ok(0) => {
                        uplink_done = true;
                        let final_offset = uplink_win.next_offset();
                        let fin_frame = FluxFrame::StreamFin {
                            stream_id,
                            epoch,
                            final_offset,
                        };
                        match slot.ch.try_send_stream(fin_frame) {
                            Ok(()) => {}
                            Err(Some(returned)) => pending_uplink = Some(returned),
                            Err(None) => {
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
                        let offset = uplink_win.push(chunk.clone());
                        let data_frame = FluxFrame::StreamData {
                            stream_id,
                            epoch,
                            offset,
                            payload: chunk,
                        };
                        match slot.ch.try_send_stream(data_frame) {
                            Ok(()) => {
                                pool.maybe_observe_channel_rate(&slot.ch, pool.now_micros());
                            }
                            Err(Some(returned)) => pending_uplink = Some(returned),
                            Err(None) => {
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
                        }
                    }
                    Err(err) => {
                        let code = if matches!(
                            err.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) {
                            RST_REMOTE_RESET
                        } else {
                            RST_CLIENT_ABORT
                        };
                        let rst = FluxFrame::StreamRst {
                            stream_id,
                            code,
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
async fn send_stream_migration_frames(
    ch: &ClientChannelHandle,
    stream_id: u32,
    cur_epoch: u32,
    target: &ProxyTarget,
    uplink_win: &SendWindowBuffer,
    downlink_recv: &RecvOffsetAssembler,
    uplink_done: bool,
) -> bool {
    let mut ok = ch
        .send_stream(FluxFrame::StreamMigrate {
            stream_id,
            epoch: cur_epoch,
            resume_offset: downlink_recv.next_offset(),
            target: target.clone(),
        })
        .await;
    if ok {
        for (offset, chunk) in uplink_win.unacked_from(uplink_win.acked_offset()) {
            if !ch
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
        ok = ch
            .send_stream(FluxFrame::StreamFin {
                stream_id,
                epoch: cur_epoch,
                final_offset: uplink_win.next_offset(),
            })
            .await;
    }
    ok
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

        if send_stream_migration_frames(
            &slot.ch,
            stream_id,
            cur_epoch,
            target,
            uplink_win,
            downlink_recv,
            uplink_done,
        )
        .await
        {
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
