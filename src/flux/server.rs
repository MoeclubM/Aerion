use super::auth::{self, derive_blind_key, handshake_key, xor_32};
use super::config::{FluxSecurityMode, FluxServerConfig, FluxTransportKind};
use super::frame::{
    DEFAULT_STREAM_WINDOW_BYTES, FluxFrame, MAX_FLUX_CHUNK_LEN, RecvOffsetAssembler,
    SendWindowBuffer, push_coalesced_frame,
};
use super::transport::{
    FluxChannelGuard, FluxFrameReader, FluxFrameWriter, PreparedStreamListener,
    bind_server_tcp_listener, bind_server_udp_socket, build_server_quic_endpoint,
    split_boxed_stream, split_quic_channel,
};
use crate::core::{CoreSession, ProxyCore};
use crate::listener::{self, ListenerStopToken};
use crate::protocol::{
    ProxyTarget, canonicalize_socket_addr, constant_time_eq, resolve_target_addr,
};
use crate::replay_cache::{ReplayCache, ReplayError};
use crate::socket_protect;
use crate::udp_fragments::{FragmentPayload, MAX_PENDING_PACKETS};
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_UDP_SLICE_BYTES: usize = 1100;
const SESSION_ORPHAN_GRACE: Duration = super::config::SESSION_RESUME_TIMEOUT;
const UDP_ASSOC_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const UDP_FRAG_TIMEOUT: Duration = Duration::from_secs(20);
const CLOSED_STREAM_RING_CAP: usize = 512;
const WRITER_BATCH_MAX: usize = 64;
const STREAM_EVENT_BURST_MAX: usize = 32;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Session state is owned by the node controller and survives listener replacement.
#[derive(Clone)]
pub struct FluxServerState {
    registry: Arc<FluxServerRegistry>,
}

impl FluxServerState {
    pub fn new(core: ProxyCore, udp_enabled: bool) -> Self {
        Self {
            registry: Arc::new(FluxServerRegistry::new(core, udp_enabled)),
        }
    }
}

pub struct RunningFluxServer {
    tcp_addrs: Vec<SocketAddr>,
    udp_addrs: Vec<SocketAddr>,
    stop: ListenerStopToken,
    tasks: JoinSet<Result<()>>,
    registry: Arc<FluxServerRegistry>,
    cancel_on_stop: bool,
}

impl Drop for RunningFluxServer {
    fn drop(&mut self) {
        self.stop.stop();
        if self.cancel_on_stop {
            self.registry.core.cancel_all_sessions();
        }
        self.tasks.abort_all();
    }
}

impl RunningFluxServer {
    pub fn tcp_addrs(&self) -> &[SocketAddr] {
        &self.tcp_addrs
    }

    pub fn udp_addrs(&self) -> &[SocketAddr] {
        &self.udp_addrs
    }

    pub fn stop(&self) {
        self.stop.stop();
    }

    pub async fn wait(mut self) -> Result<()> {
        while let Some(res) = self.tasks.join_next().await {
            match res {
                Ok(Ok(())) => {
                    if self.stop.is_stopped() {
                        continue;
                    }
                }
                Ok(Err(err)) => {
                    self.stop.stop();
                    self.tasks.shutdown().await;
                    return Err(err);
                }
                Err(join_err) if join_err.is_cancelled() => {}
                Err(join_err) => {
                    self.stop.stop();
                    self.tasks.shutdown().await;
                    return Err(anyhow::anyhow!("Flux server listener panicked: {join_err}"));
                }
            }
        }
        Ok(())
    }
}

pub async fn run_flux_server(config: FluxServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.key, &config.users);
    run_flux_server_with_core(config, core).await
}

pub async fn run_flux_server_with_core(config: FluxServerConfig, core: ProxyCore) -> Result<()> {
    run_flux_server_with_core_until(config, core, ListenerStopToken::new()).await
}

pub async fn run_flux_server_with_core_until(
    config: FluxServerConfig,
    core: ProxyCore,
    stop: ListenerStopToken,
) -> Result<()> {
    let running = start_flux_server_with_core_and_stop(config, core, stop)?;
    running.wait().await
}

pub fn start_flux_server_with_core(
    config: FluxServerConfig,
    core: ProxyCore,
) -> Result<RunningFluxServer> {
    start_flux_server_with_core_and_stop(config, core, ListenerStopToken::new())
}

pub fn start_flux_server_with_core_and_stop(
    config: FluxServerConfig,
    core: ProxyCore,
    stop: ListenerStopToken,
) -> Result<RunningFluxServer> {
    let state = FluxServerState::new(core, config.udp);
    let mut running = start_flux_server_with_state(config, &state, stop)?;
    running.cancel_on_stop = true;
    Ok(running)
}

pub fn start_flux_server_with_state(
    config: FluxServerConfig,
    state: &FluxServerState,
    stop: ListenerStopToken,
) -> Result<RunningFluxServer> {
    config.validate()?;
    let registry = state.registry.clone();
    registry.udp_enabled.store(config.udp, Ordering::Release);

    let mut explicit_v4_ports = HashSet::<(u16, bool)>::new();
    for listener in &config.listeners {
        if listener.listen_ip.is_ipv4() {
            let is_udp = listener.transport == FluxTransportKind::Udp;
            for port in &listener.ports {
                explicit_v4_ports.insert((*port, is_udp));
            }
        }
    }

    let mut tcp_addrs = Vec::new();
    let mut udp_addrs = Vec::new();
    let mut tasks = JoinSet::<Result<()>>::new();

    for listener_cfg in config.listeners {
        match listener_cfg.transport {
            FluxTransportKind::Udp => {
                for port in &listener_cfg.ports {
                    let bind_addr = SocketAddr::new(listener_cfg.listen_ip, *port);
                    let v6_only = explicit_v4_ports.contains(&(*port, true));
                    let udp_std = bind_server_udp_socket(bind_addr, v6_only)?;
                    let endpoint = build_server_quic_endpoint(&listener_cfg, udp_std)?;
                    let local_addr = endpoint.local_addr()?;
                    udp_addrs.push(local_addr);
                    tracing::info!(
                        "Flux QUIC listener {} bound on {}/udp",
                        listener_cfg.id,
                        local_addr
                    );
                    let reg = registry.clone();
                    let stop_token = stop.clone();
                    let security = listener_cfg.security;
                    let reality_priv = listener_cfg.reality.as_ref().map(|r| r.private_key);
                    let obfs_key = listener_cfg.obfs_key.clone();
                    tasks.spawn(async move {
                        run_quic_listener_loop(
                            endpoint,
                            security,
                            reality_priv,
                            obfs_key,
                            reg,
                            stop_token,
                        )
                        .await
                    });
                }
            }
            FluxTransportKind::Tcp | FluxTransportKind::Http => {
                let prepared = PreparedStreamListener::prepare(listener_cfg.clone())?;
                for port in &listener_cfg.ports {
                    let bind_addr = SocketAddr::new(listener_cfg.listen_ip, *port);
                    let v6_only = explicit_v4_ports.contains(&(*port, false));
                    let tcp_listener = bind_server_tcp_listener(bind_addr, v6_only)?;
                    let local_addr = tcp_listener.local_addr()?;
                    tcp_addrs.push(local_addr);
                    tracing::info!(
                        "Flux {:?} listener {} bound on {}/tcp",
                        listener_cfg.transport,
                        listener_cfg.id,
                        local_addr
                    );
                    let reg = registry.clone();
                    let stop_token = stop.clone();
                    let prepared_clone = prepared.clone();
                    tasks.spawn(async move {
                        run_stream_listener_loop(
                            tcp_listener,
                            local_addr.port(),
                            prepared_clone,
                            reg,
                            stop_token,
                        )
                        .await
                    });
                }
            }
        }
    }

    let reaper_reg = registry.clone();
    let reaper_stop = stop.clone();
    tasks.spawn(async move {
        loop {
            tokio::select! {
                _ = reaper_stop.stopped() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    reaper_reg.reap_idle_sessions().await;
                }
            }
        }
    });

    Ok(RunningFluxServer {
        tcp_addrs,
        udp_addrs,
        stop,
        tasks,
        registry,
        cancel_on_stop: false,
    })
}

async fn run_quic_listener_loop(
    endpoint: quinn::Endpoint,
    security: FluxSecurityMode,
    reality_private_key: Option<[u8; 32]>,
    obfs_key: Option<String>,
    registry: Arc<FluxServerRegistry>,
    stop: ListenerStopToken,
) -> Result<()> {
    loop {
        let incoming = tokio::select! {
            _ = stop.stopped() => {
                endpoint.close(quinn::VarInt::from_u32(0), b"flux server stopped");
                let _ = tokio::time::timeout(Duration::from_millis(50), endpoint.wait_idle()).await;
                let dummy_bind: SocketAddr = match endpoint.local_addr() {
                    Ok(addr) if addr.is_ipv6() => "[::1]:0".parse().unwrap(),
                    _ => "127.0.0.1:0".parse().unwrap(),
                };
                if let Ok(eph1) = socket_protect::bind_udp_std(dummy_bind) {
                    let _ = endpoint.rebind(eph1);
                }
                if let Ok(eph2) = socket_protect::bind_udp_std(dummy_bind) {
                    let _ = endpoint.rebind(eph2);
                }
                drop(endpoint);
                tokio::task::yield_now().await;
                return Ok(());
            }
            next = endpoint.accept() => match next {
                Some(inc) => inc,
                None => return Ok(()),
            }
        };
        let reg = registry.clone();
        let obfs_key = obfs_key.clone();
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::debug!("Flux QUIC handshake failed: {err:#}");
                    return;
                }
            };
            let peer_addr = connection.remote_address();
            let (send, recv) =
                match tokio::time::timeout(Duration::from_secs(10), connection.accept_bi()).await {
                    Ok(Ok(pair)) => pair,
                    _ => return,
                };
            let (reader, writer, guard) = split_quic_channel(send, recv, connection, None);
            if let Err(err) = handle_server_channel(
                reader,
                writer,
                guard,
                peer_addr,
                FluxTransportKind::Udp,
                security,
                reality_private_key,
                obfs_key,
                reg,
            )
            .await
            {
                tracing::debug!("Flux QUIC channel {peer_addr} ended: {err:#}");
            }
        });
    }
}

async fn run_stream_listener_loop(
    listener: tokio::net::TcpListener,
    local_port: u16,
    prepared: PreparedStreamListener,
    registry: Arc<FluxServerRegistry>,
    stop: ListenerStopToken,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = tokio::select! {
            _ = stop.stopped() => return Ok(()),
            accepted = listener::accept_client(&listener) => match accepted {
                Ok(pair) => pair,
                Err(listener::AcceptError::Cancelled) => return Ok(()),
                Err(listener::AcceptError::Io(err)) => {
                    return Err(err).context("accept Flux TCP client");
                }
            }
        };
        let prepared = prepared.clone();
        let reg = registry.clone();
        tokio::spawn(async move {
            let transport_kind = prepared.config.transport;
            let security = prepared.config.security;
            let reality_priv = prepared.config.reality.as_ref().map(|r| r.private_key);
            let obfs_key = prepared.config.obfs_key.clone();
            let res = prepared
                .accept_and_serve(stream, local_port, move |boxed_stream| {
                    let reg = reg.clone();
                    let obfs_key = obfs_key.clone();
                    async move {
                        let (reader, writer, guard) = split_boxed_stream(boxed_stream);
                        handle_server_channel(
                            reader,
                            writer,
                            guard,
                            peer_addr,
                            transport_kind,
                            security,
                            reality_priv,
                            obfs_key,
                            reg,
                        )
                        .await
                    }
                })
                .await;
            if let Err(err) = res {
                tracing::debug!("Flux stream channel {peer_addr} ended: {err:#}");
            }
        });
    }
}

struct ServerChannelHandle {
    uid: u64,
    transport: FluxTransportKind,
    prio_tx: mpsc::UnboundedSender<FluxFrame>,
    stream_tx: mpsc::Sender<FluxFrame>,
    dead: AtomicBool,
    guard: Arc<FluxChannelGuard>,
}

impl ServerChannelHandle {
    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    fn mark_dead(&self) {
        self.dead.store(true, Ordering::Release);
        self.guard.close();
    }

    fn send_prio(&self, frame: FluxFrame) -> bool {
        !self.is_dead() && self.prio_tx.send(frame).is_ok()
    }

    fn try_send_stream(&self, frame: FluxFrame) -> std::result::Result<(), Option<FluxFrame>> {
        if self.is_dead() {
            return Err(None);
        }
        match self.stream_tx.try_send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(returned)) => Err(Some(returned)),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(None),
        }
    }

    async fn reserve_stream(&self) -> Option<mpsc::Permit<'_, FluxFrame>> {
        if self.is_dead() {
            return None;
        }
        let permit = tokio::select! {
            _ = self.guard.closed() => return None,
            permit = self.stream_tx.reserve() => permit.ok()?,
        };
        if self.is_dead() {
            return None;
        }
        Some(permit)
    }

    async fn send_stream(&self, frame: FluxFrame) -> bool {
        if self.is_dead() {
            return false;
        }
        tokio::select! {
            _ = self.guard.closed() => false,
            result = self.stream_tx.send(frame) => result.is_ok(),
        }
    }
}

enum ServerStreamEvent {
    Data {
        epoch: u32,
        offset: u64,
        payload: Bytes,
        reply_ch: Arc<ServerChannelHandle>,
    },
    Ack {
        ack_offset: u64,
    },
    Migrate {
        epoch: u32,
        client_rx_offset: u64,
        new_ch: Arc<ServerChannelHandle>,
    },
    Fin {
        epoch: u32,
        final_offset: u64,
    },
    Rst,
}

struct ServerUdpFragmentEntry {
    target: ProxyTarget,
    created_at: Instant,
    fragments: FragmentPayload,
}

struct ServerUdpAssoc {
    socket: Arc<UdpSocket>,
    preferred_ch: StdMutex<Arc<ServerChannelHandle>>,
    last_seen: StdMutex<Instant>,
    recv_task: StdMutex<Option<JoinHandle<()>>>,
}

impl Drop for ServerUdpAssoc {
    fn drop(&mut self) {
        if let Some(handle) = self
            .recv_task
            .lock()
            .expect("Flux UDP recv_task poisoned")
            .take()
        {
            handle.abort();
        }
    }
}

struct FluxServerSession {
    cred_hash: [u8; 32],
    core_session: CoreSession,
    channels: StdMutex<HashMap<u64, Arc<ServerChannelHandle>>>,
    streams: StdMutex<HashMap<u32, mpsc::Sender<ServerStreamEvent>>>,
    closed_streams: StdMutex<(VecDeque<u32>, HashSet<u32>)>,
    udp_assocs: Mutex<HashMap<u32, Arc<ServerUdpAssoc>>>,
    udp_fragments: Mutex<HashMap<(u32, u32), ServerUdpFragmentEntry>>,
    next_udp_packet_id: AtomicU32,
    last_active_secs: AtomicU64,
}

impl FluxServerSession {
    fn touch(&self) {
        self.last_active_secs
            .store(now_unix_secs(), Ordering::Relaxed);
    }

    fn mark_stream_closed(&self, stream_id: u32) {
        self.streams
            .lock()
            .expect("Flux server streams poisoned")
            .remove(&stream_id);
        let mut closed = self
            .closed_streams
            .lock()
            .expect("Flux closed_streams poisoned");
        if closed.1.insert(stream_id) {
            closed.0.push_back(stream_id);
            while closed.0.len() > CLOSED_STREAM_RING_CAP {
                if let Some(evicted) = closed.0.pop_front() {
                    closed.1.remove(&evicted);
                }
            }
        }
    }

    fn is_stream_closed(&self, stream_id: u32) -> bool {
        self.closed_streams
            .lock()
            .expect("Flux closed_streams poisoned")
            .1
            .contains(&stream_id)
    }

    fn pick_downlink_channel(
        &self,
        preferred: &Arc<ServerChannelHandle>,
    ) -> Option<Arc<ServerChannelHandle>> {
        if !preferred.is_dead() {
            return Some(preferred.clone());
        }
        let channels = self.channels.lock().expect("Flux server channels poisoned");
        channels
            .values()
            .find(|ch| !ch.is_dead() && ch.transport == FluxTransportKind::Udp)
            .or_else(|| channels.values().find(|ch| !ch.is_dead()))
            .cloned()
    }
}

struct FluxServerRegistry {
    core: ProxyCore,
    udp_enabled: AtomicBool,
    hello_replay: ReplayCache<[u8; 48]>,
    sessions: Mutex<HashMap<[u8; 16], Arc<FluxServerSession>>>,
    next_channel_uid: AtomicU64,
}

impl FluxServerRegistry {
    fn new(core: ProxyCore, udp_enabled: bool) -> Self {
        Self {
            core,
            udp_enabled: AtomicBool::new(udp_enabled),
            hello_replay: ReplayCache::new(Duration::from_secs(auth::HELLO_REPLAY_TTL_SECS), 16384),
            sessions: Mutex::new(HashMap::new()),
            next_channel_uid: AtomicU64::new(1),
        }
    }

    async fn get_or_open_session(
        &self,
        session_id: [u8; 16],
        cred_hash: [u8; 32],
        peer_addr: SocketAddr,
    ) -> Result<Arc<FluxServerSession>> {
        let mut guard = self.sessions.lock().await;
        if let Some(existing) = guard.get(&session_id) {
            if !existing.core_session.is_cancelled() {
                ensure!(
                    constant_time_eq(&cred_hash, &existing.cred_hash),
                    "Flux session_id credential mismatch"
                );
                existing.touch();
                return Ok(existing.clone());
            }
            guard.remove(&session_id);
        }

        let core_session = self
            .core
            .authenticate_password_hash_from(&cred_hash, canonicalize_socket_addr(peer_addr))
            .await?;
        let session = Arc::new(FluxServerSession {
            cred_hash,
            core_session,
            channels: StdMutex::new(HashMap::new()),
            streams: StdMutex::new(HashMap::new()),
            closed_streams: StdMutex::new((VecDeque::new(), HashSet::new())),
            udp_assocs: Mutex::new(HashMap::new()),
            udp_fragments: Mutex::new(HashMap::new()),
            next_udp_packet_id: AtomicU32::new(1),
            last_active_secs: AtomicU64::new(now_unix_secs()),
        });
        guard.insert(session_id, session.clone());
        Ok(session)
    }

    async fn reap_idle_sessions(&self) {
        let now_secs = now_unix_secs();
        let mut sessions = self.sessions.lock().await;
        let mut expired_ids = Vec::new();
        for (id, session) in sessions.iter() {
            if session.core_session.is_cancelled() {
                expired_ids.push(*id);
                continue;
            }
            let ch_empty = session
                .channels
                .lock()
                .expect("Flux server channels poisoned")
                .is_empty();
            let idle_secs =
                now_secs.saturating_sub(session.last_active_secs.load(Ordering::Relaxed));
            if ch_empty && idle_secs >= SESSION_ORPHAN_GRACE.as_secs() {
                expired_ids.push(*id);
            }
        }
        for id in expired_ids {
            if let Some(removed) = sessions.remove(&id) {
                let streams = std::mem::take(
                    &mut *removed
                        .streams
                        .lock()
                        .expect("Flux server streams poisoned"),
                );
                for (_, tx) in streams {
                    let _ = tx.try_send(ServerStreamEvent::Rst);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_channel(
    mut reader: FluxFrameReader,
    mut writer: FluxFrameWriter,
    guard: Arc<FluxChannelGuard>,
    peer_addr: SocketAddr,
    transport: FluxTransportKind,
    security: FluxSecurityMode,
    reality_private_key: Option<[u8; 32]>,
    obfs_key: Option<String>,
    registry: Arc<FluxServerRegistry>,
) -> Result<()> {
    let first_frame = tokio::time::timeout(Duration::from_secs(10), reader.read_frame())
        .await
        .context("Flux SessionHello timed out")??
        .context("Flux channel closed before SessionHello")?;
    let FluxFrame::SessionHello {
        session_id,
        client_ephemeral_pub,
        timestamp_secs,
        channel_id: _,
        blinded_credential,
        client_proof,
    } = first_frame.clone()
    else {
        bail!("expected Flux SessionHello as first frame");
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    ensure!(
        now_secs.abs_diff(timestamp_secs) <= auth::HELLO_CLOCK_SKEW_SECS,
        "Flux SessionHello timestamp outside allowed window"
    );

    let binding = guard.channel_binding()?;
    let blind_key = if security == FluxSecurityMode::Reality {
        let priv_key = reality_private_key.context("missing Flux REALITY private key")?;
        let shared =
            StaticSecret::from(priv_key).diffie_hellman(&PublicKey::from(client_ephemeral_pub));
        ensure!(shared.was_contributory(), "invalid Flux REALITY ECDH key");
        derive_blind_key(shared.as_bytes(), &session_id, &binding)?
    } else {
        derive_blind_key(
            obfs_key.as_deref().map(str::as_bytes).unwrap_or(&binding),
            &session_id,
            &client_ephemeral_pub,
        )?
    };
    let cred_hash = xor_32(&blinded_credential, &blind_key);
    let auth_key = handshake_key(&blind_key, &cred_hash, &binding)?;
    ensure!(
        constant_time_eq(&client_proof, &auth::client_proof(&auth_key, &first_frame)?),
        "Flux client proof verification failed"
    );
    registry.core.validate_password_hash(&cred_hash)?;
    let mut replay_key = [0u8; 48];
    replay_key[..16].copy_from_slice(&session_id);
    replay_key[16..].copy_from_slice(&client_ephemeral_pub);
    match registry.hello_replay.check_and_store(replay_key) {
        Ok(()) => {}
        Err(ReplayError::Replayed) => bail!("replayed Flux SessionHello"),
        Err(ReplayError::Full) => bail!("Flux SessionHello replay cache full"),
    }

    let session = registry
        .get_or_open_session(session_id, cred_hash, peer_addr)
        .await?;

    let udp_enabled = registry.udp_enabled.load(Ordering::Acquire);
    let server_proof = auth::server_proof(&auth_key, &first_frame, udp_enabled)?;
    writer
        .write_frame(
            &FluxFrame::SessionOk {
                status: 0,
                server_proof,
                udp_enabled,
            },
            true,
        )
        .await?;

    let uid = registry.next_channel_uid.fetch_add(1, Ordering::Relaxed);
    let (prio_tx, mut prio_rx) = mpsc::unbounded_channel::<FluxFrame>();
    let (stream_tx, mut stream_rx) = mpsc::channel::<FluxFrame>(512);
    let ch_handle = Arc::new(ServerChannelHandle {
        uid,
        transport,
        prio_tx,
        stream_tx,
        dead: AtomicBool::new(false),
        guard,
    });
    session
        .channels
        .lock()
        .expect("Flux server channels poisoned")
        .insert(uid, ch_handle.clone());

    let writer_ch = ch_handle.clone();
    let writer_cancel = session.core_session.clone();
    let writer_task = tokio::spawn(async move {
        let res = tokio::select! {
            _ = writer_ch.guard.closed() => Ok(()),
            res = run_channel_writer_loop(&mut writer, &mut prio_rx, &mut stream_rx, &writer_cancel) => res,
        };
        writer_ch.mark_dead();
        let _ = writer.shutdown().await;
        res
    });

    let read_res =
        run_server_channel_reader(&mut reader, &ch_handle, &session, &registry.udp_enabled).await;
    ch_handle.mark_dead();
    writer_task.abort();
    session
        .channels
        .lock()
        .expect("Flux server channels poisoned")
        .remove(&uid);
    session.touch();
    read_res
}

async fn run_channel_writer_loop(
    writer: &mut FluxFrameWriter,
    prio_rx: &mut mpsc::UnboundedReceiver<FluxFrame>,
    stream_rx: &mut mpsc::Receiver<FluxFrame>,
    core_session: &CoreSession,
) -> Result<()> {
    let mut batch = Vec::with_capacity(WRITER_BATCH_MAX);
    loop {
        batch.clear();
        let first = tokio::select! {
            _ = core_session.cancelled() => return Ok(()),
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

async fn run_server_channel_reader(
    reader: &mut FluxFrameReader,
    ch: &Arc<ServerChannelHandle>,
    session: &Arc<FluxServerSession>,
    udp_enabled: &AtomicBool,
) -> Result<()> {
    loop {
        let frame = tokio::select! {
            _ = session.core_session.cancelled() => return Ok(()),
            next = reader.read_frame() => match next? {
                Some(f) => f,
                None => return Ok(()),
            }
        };
        session.touch();
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
            FluxFrame::Pong { .. } => {}
            FluxFrame::StreamOpen {
                stream_id,
                epoch,
                target,
                initial_payload,
            } => {
                if session.is_stream_closed(stream_id) {
                    continue;
                }
                spawn_or_get_server_stream(session, ch, stream_id, epoch, target, initial_payload)
                    .await;
            }
            FluxFrame::StreamData {
                stream_id,
                epoch,
                offset,
                payload,
            } => {
                let tx = session
                    .streams
                    .lock()
                    .expect("Flux server streams poisoned")
                    .get(&stream_id)
                    .cloned();
                if let Some(tx) = tx {
                    let _ = tx
                        .send(ServerStreamEvent::Data {
                            epoch,
                            offset,
                            payload,
                            reply_ch: ch.clone(),
                        })
                        .await;
                }
            }
            FluxFrame::StreamAck {
                stream_id,
                ack_offset,
            } => {
                let tx = session
                    .streams
                    .lock()
                    .expect("Flux server streams poisoned")
                    .get(&stream_id)
                    .cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(ServerStreamEvent::Ack { ack_offset }).await;
                }
            }
            FluxFrame::StreamMigrate {
                stream_id,
                epoch,
                resume_offset,
                target,
            } => {
                if session.is_stream_closed(stream_id) {
                    let _ = ch
                        .send_stream(FluxFrame::StreamRst { stream_id, code: 1 })
                        .await;
                    continue;
                }
                let existing = session
                    .streams
                    .lock()
                    .expect("Flux server streams poisoned")
                    .get(&stream_id)
                    .cloned();
                if let Some(tx) = existing {
                    let _ = tx
                        .send(ServerStreamEvent::Migrate {
                            epoch,
                            client_rx_offset: resume_offset,
                            new_ch: ch.clone(),
                        })
                        .await;
                } else if resume_offset == 0 {
                    spawn_or_get_server_stream(session, ch, stream_id, epoch, target, Bytes::new())
                        .await;
                } else {
                    let _ = ch
                        .send_stream(FluxFrame::StreamRst { stream_id, code: 2 })
                        .await;
                }
            }
            FluxFrame::StreamFin {
                stream_id,
                epoch,
                final_offset,
            } => {
                let tx = session
                    .streams
                    .lock()
                    .expect("Flux server streams poisoned")
                    .get(&stream_id)
                    .cloned();
                if let Some(tx) = tx {
                    let _ = tx
                        .send(ServerStreamEvent::Fin {
                            epoch,
                            final_offset,
                        })
                        .await;
                }
            }
            FluxFrame::StreamRst { stream_id, .. } => {
                let tx = session
                    .streams
                    .lock()
                    .expect("Flux server streams poisoned")
                    .remove(&stream_id);
                if let Some(tx) = tx {
                    let _ = tx.send(ServerStreamEvent::Rst).await;
                }
                session.mark_stream_closed(stream_id);
            }
            FluxFrame::UdpDatagram {
                assoc_id,
                packet_id,
                frag_index,
                frag_total,
                target,
                payload,
            } => {
                if udp_enabled.load(Ordering::Acquire) {
                    let _ = handle_server_udp_datagram(
                        session, ch, assoc_id, packet_id, frag_index, frag_total, target, payload,
                    )
                    .await;
                }
            }
            FluxFrame::SessionHello { .. } | FluxFrame::SessionOk { .. } => {
                bail!("unexpected Flux handshake frame after session established");
            }
        }
    }
}

async fn spawn_or_get_server_stream(
    session: &Arc<FluxServerSession>,
    ch: &Arc<ServerChannelHandle>,
    stream_id: u32,
    epoch: u32,
    target: ProxyTarget,
    initial_payload: Bytes,
) {
    let (tx, rx) = mpsc::channel::<ServerStreamEvent>(512);
    let existing = {
        let mut streams = session
            .streams
            .lock()
            .expect("Flux server streams poisoned");
        if let Some(existing) = streams.get(&stream_id).cloned() {
            Some(existing)
        } else {
            streams.insert(stream_id, tx);
            None
        }
    };
    if let Some(existing) = existing {
        if !initial_payload.is_empty() {
            let _ = existing
                .send(ServerStreamEvent::Data {
                    epoch,
                    offset: 0,
                    payload: initial_payload,
                    reply_ch: ch.clone(),
                })
                .await;
        }
        return;
    }

    let session_clone = session.clone();
    let ch_clone = ch.clone();
    tokio::spawn(async move {
        if let Err(err) = run_server_stream(
            session_clone.clone(),
            ch_clone,
            stream_id,
            epoch,
            target,
            initial_payload,
            rx,
        )
        .await
        {
            tracing::debug!("Flux server stream {stream_id} closed with error: {err:#}");
        }
        session_clone.mark_stream_closed(stream_id);
    });
}

async fn run_server_stream(
    session: Arc<FluxServerSession>,
    mut active_ch: Arc<ServerChannelHandle>,
    stream_id: u32,
    initial_epoch: u32,
    target: ProxyTarget,
    initial_payload: Bytes,
    mut ev_rx: mpsc::Receiver<ServerStreamEvent>,
) -> Result<()> {
    let mut remote = match socket_protect::connect_proxy_target(&target).await {
        Ok(stream) => stream,
        Err(err) => {
            let _ = active_ch
                .send_stream(FluxFrame::StreamRst { stream_id, code: 1 })
                .await;
            return Err(err);
        }
    };

    let mut uplink_recv = RecvOffsetAssembler::default();
    let _ = uplink_recv.accept_migrate(initial_epoch);
    let mut downlink_win = SendWindowBuffer::new(DEFAULT_STREAM_WINDOW_BYTES);
    let mut downlink_epoch = initial_epoch;
    let mut uplink_done = false;
    let mut downlink_done = false;

    if !initial_payload.is_empty()
        && let Some(fresh) = uplink_recv.accept_data(initial_epoch, 0, initial_payload)?
    {
        session.core_session.record_upload(fresh.len()).await?;
        remote
            .write_all(&fresh)
            .await
            .context("write initial Flux target payload")?;
        let _ = active_ch.send_prio(FluxFrame::StreamAck {
            stream_id,
            ack_offset: uplink_recv.next_offset(),
        });
    }

    let mut read_buf = vec![0u8; MAX_FLUX_CHUNK_LEN];
    let mut pending_downlink: Option<FluxFrame> = None;
    let mut half_close_deadline: Option<Instant> = None;

    loop {
        if uplink_done
            && downlink_done
            && pending_downlink.is_none()
            && !downlink_win.has_unacked()
        {
            let _ = remote.shutdown().await;
            return Ok(());
        }

        let remote_read_cap = downlink_win.available_window().min(MAX_FLUX_CHUNK_LEN);
        let can_read_remote = !downlink_done && pending_downlink.is_none() && remote_read_cap > 0;
        let drain_sleep = async {
            if let Some(deadline) = half_close_deadline {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let pending_ch = active_ch.clone();

        tokio::select! {
            _ = session.core_session.cancelled() => {
                let _ = remote.shutdown().await;
                return Ok(());
            }
            _ = drain_sleep => {
                let _ = remote.shutdown().await;
                return Ok(());
            }
            permit_res = pending_ch.reserve_stream(), if pending_downlink.is_some() => {
                match permit_res {
                    Some(permit) => {
                        if let Some(frame) = pending_downlink.take() {
                            permit.send(frame);
                        }
                    }
                    None => {
                        pending_downlink = None;
                    }
                }
            }
            ev = ev_rx.recv() => {
                let Some(ev) = ev else {
                    let _ = remote.shutdown().await;
                    return Ok(());
                };
                let mut cur_ev = Some(ev);
                let mut drained = 0usize;
                let mut ack_dirty = false;
                while let Some(event) = cur_ev.take() {
                    match event {
                        ServerStreamEvent::Data {
                            epoch,
                            offset,
                            payload,
                            reply_ch,
                        } => {
                            if epoch > downlink_epoch {
                                downlink_epoch = epoch;
                                active_ch = reply_ch;
                            }
                            if let Some(fresh) = uplink_recv.accept_data(epoch, offset, payload)? {
                                session.core_session.record_upload(fresh.len()).await?;
                                if let Err(err) = remote.write_all(&fresh).await {
                                    let rst = FluxFrame::StreamRst {
                                        stream_id,
                                        code: 3,
                                    };
                                    let _ = active_ch.send_stream(rst).await;
                                    return Err(err).context("write Flux target TCP");
                                }
                            }
                            ack_dirty = true;
                            if !uplink_done && uplink_recv.is_complete() {
                                uplink_done = true;
                                let _ = remote.shutdown().await;
                                if downlink_done && half_close_deadline.is_none() {
                                    half_close_deadline =
                                        Some(Instant::now() + Duration::from_secs(5));
                                }
                            }
                        }
                        ServerStreamEvent::Ack { ack_offset } => {
                            downlink_win.ack(ack_offset);
                        }
                        ServerStreamEvent::Migrate {
                            epoch,
                            client_rx_offset,
                            new_ch,
                        } => {
                            if uplink_recv.accept_migrate(epoch) {
                                pending_downlink = None;
                                downlink_epoch = epoch;
                                active_ch = new_ch;
                                downlink_win.ack(client_rx_offset);
                                ack_dirty = false;
                                let _ = active_ch.send_prio(FluxFrame::StreamAck {
                                    stream_id,
                                    ack_offset: uplink_recv.next_offset(),
                                });
                                for (offset, chunk) in downlink_win.unacked_from(client_rx_offset) {
                                    let _ = active_ch
                                        .send_stream(FluxFrame::StreamData {
                                            stream_id,
                                            epoch: downlink_epoch,
                                            offset,
                                            payload: chunk,
                                        })
                                        .await;
                                }
                                if downlink_done {
                                    let _ = active_ch
                                        .send_stream(FluxFrame::StreamFin {
                                            stream_id,
                                            epoch: downlink_epoch,
                                            final_offset: downlink_win.next_offset(),
                                        })
                                        .await;
                                }
                            }
                        }
                        ServerStreamEvent::Fin {
                            epoch,
                            final_offset,
                        } => {
                            if uplink_recv.accept_fin(epoch, final_offset) && !uplink_done {
                                uplink_done = true;
                                let _ = remote.shutdown().await;
                                if downlink_done && half_close_deadline.is_none() {
                                    half_close_deadline =
                                        Some(Instant::now() + Duration::from_secs(5));
                                }
                            }
                        }
                        ServerStreamEvent::Rst => {
                            let _ = remote.shutdown().await;
                            return Ok(());
                        }
                    }
                    drained += 1;
                    if drained < STREAM_EVENT_BURST_MAX {
                        cur_ev = ev_rx.try_recv().ok();
                    }
                }
                if ack_dirty {
                    let _ = active_ch.send_prio(FluxFrame::StreamAck {
                        stream_id,
                        ack_offset: uplink_recv.next_offset(),
                    });
                }
            }
            read_res = remote.read(&mut read_buf[..remote_read_cap]), if can_read_remote => {
                match read_res {
                    Ok(0) => {
                        downlink_done = true;
                        let final_offset = downlink_win.next_offset();
                        let fin_frame = FluxFrame::StreamFin {
                            stream_id,
                            epoch: downlink_epoch,
                            final_offset,
                        };
                        if let Err(Some(returned)) = active_ch.try_send_stream(fin_frame) {
                            pending_downlink = Some(returned);
                        }
                        if uplink_done && half_close_deadline.is_none() {
                            half_close_deadline = Some(Instant::now() + Duration::from_secs(5));
                        }
                    }
                    Ok(n) => {
                        session.core_session.record_download(n).await?;
                        let chunk = Bytes::copy_from_slice(&read_buf[..n]);
                        let offset = downlink_win.push(chunk.clone());
                        let data_frame = FluxFrame::StreamData {
                            stream_id,
                            epoch: downlink_epoch,
                            offset,
                            payload: chunk,
                        };
                        if let Err(Some(returned)) = active_ch.try_send_stream(data_frame) {
                            pending_downlink = Some(returned);
                        }
                    }
                    Err(err) => {
                        let _ = active_ch.send_stream(FluxFrame::StreamRst {
                            stream_id,
                            code: 4,
                        }).await;
                        return Err(err).context("read Flux target TCP");
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_udp_datagram(
    session: &Arc<FluxServerSession>,
    ch: &Arc<ServerChannelHandle>,
    assoc_id: u32,
    packet_id: u32,
    frag_index: u8,
    frag_total: u8,
    target: ProxyTarget,
    payload: Bytes,
) -> Result<()> {
    ensure!(
        frag_total >= 1 && frag_index < frag_total,
        "invalid Flux UDP fragment header"
    );
    let complete = if frag_total == 1 {
        (target, payload.to_vec())
    } else {
        let mut frags = session.udp_fragments.lock().await;
        frags.retain(|_, entry| entry.created_at.elapsed() < UDP_FRAG_TIMEOUT);
        if frags.len() >= MAX_PENDING_PACKETS && !frags.contains_key(&(assoc_id, packet_id)) {
            return Ok(());
        }
        let entry = frags
            .entry((assoc_id, packet_id))
            .or_insert_with(|| ServerUdpFragmentEntry {
                target: target.clone(),
                created_at: Instant::now(),
                fragments: FragmentPayload::new(frag_total),
            });
        if entry.fragments.count() != usize::from(frag_total) {
            frags.remove(&(assoc_id, packet_id));
            return Ok(());
        }
        match entry.fragments.insert(frag_index, payload.to_vec()) {
            Ok(Some(assembled)) => {
                let tgt = entry.target.clone();
                frags.remove(&(assoc_id, packet_id));
                (tgt, assembled)
            }
            Ok(None) => return Ok(()),
            Err(_) => {
                frags.remove(&(assoc_id, packet_id));
                return Ok(());
            }
        }
    };

    let (resolved_target, data) = complete;
    session.core_session.record_upload(data.len()).await?;
    let dest_addr = resolve_target_addr(&resolved_target).await?;
    let assoc = get_or_create_server_udp_assoc(session, ch, assoc_id, dest_addr.is_ipv6()).await?;
    *assoc
        .preferred_ch
        .lock()
        .expect("Flux UDP preferred_ch poisoned") = ch.clone();
    *assoc.last_seen.lock().expect("Flux UDP last_seen poisoned") = Instant::now();
    socket_protect::send_to_dual_stack(&assoc.socket, &data, dest_addr)
        .await
        .context("send Flux outbound UDP")?;
    Ok(())
}

async fn get_or_create_server_udp_assoc(
    session: &Arc<FluxServerSession>,
    ch: &Arc<ServerChannelHandle>,
    assoc_id: u32,
    need_ipv6: bool,
) -> Result<Arc<ServerUdpAssoc>> {
    let mut assocs = session.udp_assocs.lock().await;
    assocs.retain(|_, item| {
        item.last_seen
            .lock()
            .expect("Flux UDP last_seen poisoned")
            .elapsed()
            < UDP_ASSOC_IDLE_TIMEOUT
    });
    if let Some(existing) = assocs.get(&assoc_id) {
        return Ok(existing.clone());
    }

    let socket = match socket_protect::bind_dual_stack_udp().await {
        Ok(sock) => Arc::new(sock),
        Err(_) => {
            let bind_addr = if need_ipv6 {
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            };
            Arc::new(socket_protect::bind_udp(bind_addr).await?)
        }
    };

    let assoc = Arc::new(ServerUdpAssoc {
        socket: socket.clone(),
        preferred_ch: StdMutex::new(ch.clone()),
        last_seen: StdMutex::new(Instant::now()),
        recv_task: StdMutex::new(None),
    });

    let session_weak = Arc::downgrade(session);
    let assoc_weak = Arc::downgrade(&assoc);
    let cancel = session.core_session.clone();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let received = tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(UDP_ASSOC_IDLE_TIMEOUT) => return,
                res = socket.recv_from(&mut buf) => res,
            };
            let Ok((read, src_addr)) = received else {
                return;
            };
            let (Some(sess), Some(assoc_ref)) = (session_weak.upgrade(), assoc_weak.upgrade())
            else {
                return;
            };
            *assoc_ref
                .last_seen
                .lock()
                .expect("Flux UDP last_seen poisoned") = Instant::now();
            if sess.core_session.record_download(read).await.is_err() {
                return;
            }
            let pref = assoc_ref
                .preferred_ch
                .lock()
                .expect("Flux UDP preferred_ch poisoned")
                .clone();
            let Some(out_ch) = sess.pick_downlink_channel(&pref) else {
                continue;
            };
            let pkt_id = sess.next_udp_packet_id.fetch_add(1, Ordering::Relaxed);
            let source = ProxyTarget::Ip(canonicalize_socket_addr(src_addr));
            let slices: Vec<&[u8]> = if read == 0 {
                vec![&[]]
            } else {
                buf[..read].chunks(MAX_UDP_SLICE_BYTES).collect()
            };
            if slices.len() > u8::MAX as usize {
                continue;
            }
            let total = slices.len() as u8;
            for (idx, slice) in slices.into_iter().enumerate() {
                let frame = FluxFrame::UdpDatagram {
                    assoc_id,
                    packet_id: pkt_id,
                    frag_index: idx as u8,
                    frag_total: total,
                    target: source.clone(),
                    payload: Bytes::copy_from_slice(slice),
                };
                let _ = out_ch.send_stream(frame).await;
            }
        }
    });
    *assoc.recv_task.lock().expect("Flux UDP recv_task poisoned") = Some(task);
    assocs.insert(assoc_id, assoc.clone());
    Ok(assoc)
}

#[cfg(test)]
mod authentication_tests {
    use super::*;

    #[tokio::test]
    async fn rejected_credentials_do_not_consume_replay_capacity() -> Result<()> {
        let core = ProxyCore::new(vec![crate::core::CoreUser::password("u", "valid")])?;
        let registry = Arc::new(FluxServerRegistry {
            core,
            udp_enabled: AtomicBool::new(true),
            hello_replay: ReplayCache::new(Duration::from_secs(auth::HELLO_REPLAY_TTL_SECS), 1),
            sessions: Mutex::new(HashMap::new()),
            next_channel_uid: AtomicU64::new(1),
        });
        for (nonce, password, accepted) in
            [(1, "wrong", false), (2, "wrong", false), (3, "valid", true)]
        {
            let (client, server) = tokio::io::duplex(4096);
            let (mut reader, mut writer, _) = split_boxed_stream(Box::new(client));
            let (server_reader, server_writer, guard) = split_boxed_stream(Box::new(server));
            let registry = registry.clone();
            let server_task = tokio::spawn(async move {
                handle_server_channel(
                    server_reader,
                    server_writer,
                    guard,
                    "127.0.0.1:1234".parse().unwrap(),
                    FluxTransportKind::Tcp,
                    FluxSecurityMode::Tls,
                    None,
                    None,
                    registry,
                )
                .await
            });
            let session_id = [nonce; 16];
            let ephemeral = [nonce; 32];
            let credential = crate::protocol::password_hash(password);
            let blind = derive_blind_key(&[0; 32], &session_id, &ephemeral)?;
            let key = handshake_key(&blind, &credential, &[0; 32])?;
            let mut hello = FluxFrame::SessionHello {
                session_id,
                client_ephemeral_pub: ephemeral,
                timestamp_secs: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                channel_id: "test".into(),
                blinded_credential: xor_32(&blind, &credential),
                client_proof: [0; 32],
            };
            let proof = auth::client_proof(&key, &hello)?;
            if let FluxFrame::SessionHello { client_proof, .. } = &mut hello {
                *client_proof = proof;
            }
            writer.write_frame(&hello, true).await?;
            let response = reader.read_frame().await?;
            assert_eq!(response.is_some(), accepted);
            drop(reader);
            drop(writer);
            assert_eq!(server_task.await?.is_ok(), accepted);
        }
        Ok(())
    }
}
