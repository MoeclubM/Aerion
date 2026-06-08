use crate::core::CoreSession;
use crate::protocol::{ProxyTarget, resolve_target_addr};
use crate::socket_protect;
use anyhow::{Context, Result, bail, ensure};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::AbortHandle;

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEPALIVE: u8 = 0x04;
const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;
const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const STREAM_CHUNK_LEN: usize = 8 * 1024;

static NEXT_SESSION_GENERATION: AtomicU64 = AtomicU64::new(1);
type Sessions = Arc<Mutex<HashMap<u16, Arc<SessionEntry>>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetNetwork {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameTarget {
    network: TargetNetwork,
    destination: ProxyTarget,
}

#[derive(Debug)]
struct Frame {
    session_id: u16,
    status: u8,
    has_data: bool,
    has_error: bool,
    target: Option<FrameTarget>,
    payload: Vec<u8>,
}

struct SessionEntry {
    generation: u64,
    kind: SessionKind,
    abort: AbortHandle,
}

enum SessionKind {
    Tcp {
        writer: Arc<AsyncMutex<tokio::io::WriteHalf<TcpStream>>>,
    },
    Udp(UdpSession),
}

#[derive(Clone)]
struct UdpSession {
    socket: Arc<UdpSocket>,
    default_destination: ProxyTarget,
    destination_cache: Arc<Mutex<HashMap<String, SocketAddr>>>,
}

impl SessionEntry {
    async fn shutdown(&self) {
        self.abort.abort();
        if let SessionKind::Tcp { writer } = &self.kind {
            let mut writer = writer.lock().await;
            let _ = writer.shutdown().await;
        }
    }
}

pub async fn relay_server<S>(stream: S, session: CoreSession) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, writer) = split(stream);
    let writer = Arc::new(AsyncMutex::new(writer));
    let sessions = Arc::new(Mutex::new(HashMap::new()));

    let result = relay_frames(&mut reader, writer, sessions.clone(), session).await;
    close_all_sessions(sessions).await;
    result
}

pub async fn relay_single_tcp_client_counted<S, L>(
    mut mux_stream: S,
    local: L,
    target: ProxyTarget,
    session: CoreSession,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let session_id = 1;
    let (mut local_reader, mut local_writer) = split(local);
    let (mut mux_reader, mut mux_writer) = split(&mut mux_stream);
    mux_writer
        .write_all(&encode_frame(
            session_id,
            STATUS_NEW,
            Some(&FrameTarget {
                network: TargetNetwork::Tcp,
                destination: target,
            }),
            &[],
            false,
        )?)
        .await
        .context("write VLESS mux new frame")?;

    let local_to_mux = async {
        let mut buffer = vec![0u8; STREAM_CHUNK_LEN];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read local TCP")?;
            if read == 0 {
                mux_writer
                    .write_all(&encode_frame(session_id, STATUS_END, None, &[], false)?)
                    .await
                    .context("write VLESS mux end frame")?;
                return Ok::<(), anyhow::Error>(());
            }
            session.record_upload(read).await?;
            mux_writer
                .write_all(&encode_frame(
                    session_id,
                    STATUS_KEEP,
                    None,
                    &buffer[..read],
                    false,
                )?)
                .await
                .context("write VLESS mux data frame")?;
        }
    };

    let mux_to_local = async {
        while let Some(frame) = read_frame(&mut mux_reader).await? {
            if frame.session_id != session_id {
                continue;
            }
            if frame.status == STATUS_END {
                if frame.has_error {
                    bail!("VLESS mux stream ended with error");
                }
                return Ok::<(), anyhow::Error>(());
            }
            if frame.has_data {
                session.record_download(frame.payload.len()).await?;
                local_writer
                    .write_all(&frame.payload)
                    .await
                    .context("write local TCP from mux")?;
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(local_to_mux, mux_to_local)?;
    Ok(())
}

async fn relay_frames<R, W>(
    reader: &mut R,
    writer: Arc<AsyncMutex<W>>,
    sessions: Sessions,
    session: CoreSession,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let Some(frame) = read_frame(reader).await? else {
            return Ok(());
        };
        match frame.status {
            STATUS_NEW => handle_new(frame, writer.clone(), &sessions, session.clone()).await?,
            STATUS_KEEP => handle_keep(frame, writer.clone(), &sessions, session.clone()).await?,
            STATUS_END => shutdown_session(&sessions, frame.session_id).await,
            STATUS_KEEPALIVE => {}
            other => bail!("unsupported mux status {other:#x}"),
        }
    }
}

async fn handle_new<W>(
    frame: Frame,
    writer: Arc<AsyncMutex<W>>,
    sessions: &Sessions,
    session: CoreSession,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let target = frame
        .target
        .clone()
        .context("mux new frame is missing its destination")?;
    if let Some(previous) = take_session(sessions, frame.session_id) {
        previous.shutdown().await;
    }

    let entry = match target.network {
        TargetNetwork::Tcp => {
            open_tcp_session(
                frame.session_id,
                target.destination,
                writer.clone(),
                sessions.clone(),
                session.clone(),
            )
            .await?
        }
        TargetNetwork::Udp => {
            open_udp_session(
                frame.session_id,
                target.destination,
                writer.clone(),
                sessions.clone(),
                session.clone(),
            )
            .await?
        }
    };

    insert_session(sessions, frame.session_id, entry.clone());
    if frame.has_data {
        session.record_upload(frame.payload.len()).await?;
        send_frame_to_session(&entry, None, &frame.payload).await?;
    }
    Ok(())
}

async fn handle_keep<W>(
    frame: Frame,
    writer: Arc<AsyncMutex<W>>,
    sessions: &Sessions,
    session: CoreSession,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    if !frame.has_data {
        return Ok(());
    }
    let Some(entry) = get_session(sessions, frame.session_id) else {
        write_end_frame(&writer, frame.session_id, false).await?;
        return Ok(());
    };
    session.record_upload(frame.payload.len()).await?;
    if send_frame_to_session(&entry, frame.target.as_ref(), &frame.payload)
        .await
        .is_err()
    {
        shutdown_session(sessions, frame.session_id).await;
        let _ = write_end_frame(&writer, frame.session_id, true).await;
    }
    Ok(())
}

async fn open_tcp_session<W>(
    session_id: u16,
    destination: ProxyTarget,
    writer: Arc<AsyncMutex<W>>,
    sessions: Sessions,
    session: CoreSession,
) -> Result<Arc<SessionEntry>>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let generation = next_session_generation();
    let remote = socket_protect::connect_proxy_target(&destination).await?;
    let (remote_reader, remote_writer) = split(remote);
    let remote_writer = Arc::new(AsyncMutex::new(remote_writer));
    let task = tokio::spawn({
        let writer = writer.clone();
        let sessions = sessions.clone();
        async move {
            tokio::task::yield_now().await;
            let has_error = relay_tcp_to_client(session_id, remote_reader, writer.clone(), session)
                .await
                .is_err();
            let finished_current =
                take_session_if_generation_matches(&sessions, session_id, generation).is_some();
            if finished_current {
                let _ = write_end_frame(&writer, session_id, has_error).await;
            }
        }
    });
    Ok(Arc::new(SessionEntry {
        generation,
        kind: SessionKind::Tcp {
            writer: remote_writer,
        },
        abort: task.abort_handle(),
    }))
}

async fn open_udp_session<W>(
    session_id: u16,
    destination: ProxyTarget,
    writer: Arc<AsyncMutex<W>>,
    sessions: Sessions,
    session: CoreSession,
) -> Result<Arc<SessionEntry>>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let generation = next_session_generation();
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.context("bind mux UDP")?);
    let udp_session = UdpSession {
        socket: socket.clone(),
        default_destination: destination,
        destination_cache: Arc::new(Mutex::new(HashMap::new())),
    };
    let task = tokio::spawn({
        let writer = writer.clone();
        let sessions = sessions.clone();
        async move {
            tokio::task::yield_now().await;
            let has_error = relay_udp_to_client(session_id, socket, writer.clone(), session)
                .await
                .is_err();
            let finished_current =
                take_session_if_generation_matches(&sessions, session_id, generation).is_some();
            if finished_current {
                let _ = write_end_frame(&writer, session_id, has_error).await;
            }
        }
    });
    Ok(Arc::new(SessionEntry {
        generation,
        kind: SessionKind::Udp(udp_session),
        abort: task.abort_handle(),
    }))
}

async fn send_frame_to_session(
    session: &SessionEntry,
    target_override: Option<&FrameTarget>,
    payload: &[u8],
) -> Result<()> {
    match &session.kind {
        SessionKind::Tcp { writer } => {
            ensure!(
                target_override.is_none(),
                "mux TCP session does not accept per-frame target overrides"
            );
            writer
                .lock()
                .await
                .write_all(payload)
                .await
                .context("write mux TCP payload")
        }
        SessionKind::Udp(session) => {
            let destination = match target_override {
                Some(target) => {
                    ensure!(
                        target.network == TargetNetwork::Udp,
                        "mux UDP session received a non-UDP target override"
                    );
                    &target.destination
                }
                None => &session.default_destination,
            };
            let target = target_socket_addr_cached(destination, &session.destination_cache).await?;
            session
                .socket
                .send_to(payload, target)
                .await
                .with_context(|| format!("send mux UDP payload to {target}"))?;
            Ok(())
        }
    }
}

async fn relay_tcp_to_client<W>(
    session_id: u16,
    mut reader: tokio::io::ReadHalf<TcpStream>,
    writer: Arc<AsyncMutex<W>>,
    session: CoreSession,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = vec![0u8; STREAM_CHUNK_LEN];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .context("read mux TCP response")?;
        if read == 0 {
            return Ok(());
        }
        session.record_download(read).await?;
        write_data_frame(&writer, session_id, None, &buffer[..read]).await?;
    }
}

async fn relay_udp_to_client<W>(
    session_id: u16,
    socket: Arc<UdpSocket>,
    writer: Arc<AsyncMutex<W>>,
    session: CoreSession,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        let (read, source) = socket
            .recv_from(&mut buffer)
            .await
            .context("receive mux UDP")?;
        session.record_download(read).await?;
        write_data_frame(
            &writer,
            session_id,
            Some(&FrameTarget {
                network: TargetNetwork::Udp,
                destination: ProxyTarget::Ip(source),
            }),
            &buffer[..read],
        )
        .await?;
    }
}

async fn write_data_frame<W>(
    writer: &Arc<AsyncMutex<W>>,
    session_id: u16,
    target: Option<&FrameTarget>,
    payload: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .lock()
        .await
        .write_all(&encode_frame(
            session_id,
            STATUS_KEEP,
            target,
            payload,
            false,
        )?)
        .await
        .context("write VLESS mux frame")
}

async fn write_end_frame<W>(
    writer: &Arc<AsyncMutex<W>>,
    session_id: u16,
    has_error: bool,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .lock()
        .await
        .write_all(&encode_frame(session_id, STATUS_END, None, &[], has_error)?)
        .await
        .context("write VLESS mux end frame")
}

async fn read_frame<R>(reader: &mut R) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let Some(metadata_len) = read_length_or_eof(reader, "read VLESS mux metadata length").await?
    else {
        return Ok(None);
    };
    ensure!(
        metadata_len >= 4,
        "short VLESS mux metadata length {metadata_len}"
    );

    let mut metadata = vec![0u8; metadata_len as usize];
    reader
        .read_exact(&mut metadata)
        .await
        .context("read VLESS mux metadata")?;

    let session_id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = metadata[2];
    let has_data = metadata[3] & OPTION_DATA != 0;
    let has_error = metadata[3] & OPTION_ERROR != 0;

    let target = if status == STATUS_NEW {
        ensure!(metadata.len() >= 5, "VLESS mux new frame missing network");
        let (target, consumed) = parse_target(metadata[4], &metadata[5..])?;
        ensure!(
            metadata.len() == 5 + consumed || target.network == TargetNetwork::Udp,
            "unsupported VLESS mux metadata tail"
        );
        Some(target)
    } else if status == STATUS_KEEP && metadata.len() > 4 {
        ensure!(
            metadata[4] == NETWORK_UDP,
            "unsupported VLESS mux keep metadata network {}",
            metadata[4]
        );
        let (target, _) = parse_target(metadata[4], &metadata[5..])?;
        Some(target)
    } else {
        None
    };

    let payload = if has_data {
        let payload_len = read_u16(reader, "read VLESS mux payload length").await? as usize;
        let mut payload = vec![0u8; payload_len];
        reader
            .read_exact(&mut payload)
            .await
            .context("read VLESS mux payload")?;
        payload
    } else {
        Vec::new()
    };

    Ok(Some(Frame {
        session_id,
        status,
        has_data,
        has_error,
        target,
        payload,
    }))
}

fn parse_target(network: u8, bytes: &[u8]) -> Result<(FrameTarget, usize)> {
    let network = match network {
        NETWORK_TCP => TargetNetwork::Tcp,
        NETWORK_UDP => TargetNetwork::Udp,
        other => bail!("unsupported VLESS mux network type {other:#x}"),
    };
    let (destination, consumed) = parse_destination(bytes)?;
    Ok((
        FrameTarget {
            network,
            destination,
        },
        consumed,
    ))
}

fn parse_destination(bytes: &[u8]) -> Result<(ProxyTarget, usize)> {
    ensure!(bytes.len() >= 3, "short VLESS mux destination");
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    match bytes[2] {
        ATYP_IPV4 => {
            ensure!(bytes.len() >= 7, "short VLESS mux IPv4 destination");
            Ok((
                ProxyTarget::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(bytes[3], bytes[4], bytes[5], bytes[6])),
                    port,
                )),
                7,
            ))
        }
        ATYP_IPV6 => {
            ensure!(bytes.len() >= 19, "short VLESS mux IPv6 destination");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[3..19]);
            Ok((
                ProxyTarget::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                19,
            ))
        }
        ATYP_DOMAIN => {
            ensure!(bytes.len() >= 4, "short VLESS mux domain destination");
            let len = bytes[3] as usize;
            ensure!(bytes.len() >= 4 + len, "short VLESS mux domain destination");
            Ok((
                ProxyTarget::Domain(
                    String::from_utf8(bytes[4..4 + len].to_vec())
                        .context("decode VLESS mux domain")?,
                    port,
                ),
                4 + len,
            ))
        }
        other => bail!("unsupported VLESS mux address type {other:#x}"),
    }
}

fn encode_frame(
    session_id: u16,
    status: u8,
    target: Option<&FrameTarget>,
    payload: &[u8],
    has_error: bool,
) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "VLESS mux payload too large"
    );
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&session_id.to_be_bytes());
    metadata.push(status);
    let mut option = 0u8;
    if !payload.is_empty() {
        option |= OPTION_DATA;
    }
    if has_error {
        option |= OPTION_ERROR;
    }
    metadata.push(option);
    if let Some(target) = target {
        metadata.push(match target.network {
            TargetNetwork::Tcp => NETWORK_TCP,
            TargetNetwork::Udp => NETWORK_UDP,
        });
        write_destination(&mut metadata, &target.destination)?;
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    encoded.extend_from_slice(&metadata);
    if !payload.is_empty() {
        encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        encoded.extend_from_slice(payload);
    }
    Ok(encoded)
}

fn write_destination(buffer: &mut Vec<u8>, destination: &ProxyTarget) -> Result<()> {
    let port = match destination {
        ProxyTarget::Ip(addr) => addr.port(),
        ProxyTarget::Domain(_, port) => *port,
    };
    buffer.extend_from_slice(&port.to_be_bytes());
    match destination {
        ProxyTarget::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buffer.push(ATYP_IPV4);
                buffer.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buffer.push(ATYP_IPV6);
                buffer.extend_from_slice(&ip.octets());
            }
        },
        ProxyTarget::Domain(host, _) => {
            ensure!(host.len() <= u8::MAX as usize, "VLESS mux domain too long");
            buffer.push(ATYP_DOMAIN);
            buffer.push(host.len() as u8);
            buffer.extend_from_slice(host.as_bytes());
        }
    }
    Ok(())
}

async fn target_socket_addr_cached(
    target: &ProxyTarget,
    cache: &Arc<Mutex<HashMap<String, SocketAddr>>>,
) -> Result<SocketAddr> {
    match target {
        ProxyTarget::Ip(addr) => Ok(*addr),
        ProxyTarget::Domain(host, port) => {
            let key = format!("{host}:{port}");
            if let Some(addr) = cache
                .lock()
                .expect("vless mux UDP cache poisoned")
                .get(&key)
                .copied()
            {
                return Ok(addr);
            }
            let addr = resolve_target_addr(target).await?;
            cache
                .lock()
                .expect("vless mux UDP cache poisoned")
                .insert(key, addr);
            Ok(addr)
        }
    }
}

async fn close_all_sessions(sessions: Sessions) {
    let entries = {
        let mut sessions = sessions.lock().expect("vless mux session map poisoned");
        std::mem::take(&mut *sessions)
            .into_values()
            .collect::<Vec<_>>()
    };
    for session in entries {
        session.shutdown().await;
    }
}

async fn shutdown_session(sessions: &Sessions, session_id: u16) {
    if let Some(session) = take_session(sessions, session_id) {
        session.shutdown().await;
    }
}

fn insert_session(sessions: &Sessions, session_id: u16, session: Arc<SessionEntry>) {
    sessions
        .lock()
        .expect("vless mux session map poisoned")
        .insert(session_id, session);
}

fn get_session(sessions: &Sessions, session_id: u16) -> Option<Arc<SessionEntry>> {
    sessions
        .lock()
        .expect("vless mux session map poisoned")
        .get(&session_id)
        .cloned()
}

fn take_session(sessions: &Sessions, session_id: u16) -> Option<Arc<SessionEntry>> {
    sessions
        .lock()
        .expect("vless mux session map poisoned")
        .remove(&session_id)
}

fn take_session_if_generation_matches(
    sessions: &Sessions,
    session_id: u16,
    generation: u64,
) -> Option<Arc<SessionEntry>> {
    let mut sessions = sessions.lock().expect("vless mux session map poisoned");
    let current = sessions.get(&session_id)?;
    if current.generation != generation {
        return None;
    }
    sessions.remove(&session_id)
}

fn next_session_generation() -> u64 {
    NEXT_SESSION_GENERATION.fetch_add(1, Ordering::Relaxed)
}

async fn read_length_or_eof<R>(reader: &mut R, context: &str) -> Result<Option<u16>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    match reader.read_exact(&mut bytes).await {
        Ok(_) => Ok(Some(u16::from_be_bytes(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error).context(context.to_string()),
    }
}

async fn read_u16<R>(reader: &mut R, context: &str) -> Result<u16>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    reader
        .read_exact(&mut bytes)
        .await
        .with_context(|| context.to_string())?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mux_frame_roundtrip() -> Result<()> {
        let target = ProxyTarget::Domain("example.com".to_string(), 443);
        let bytes = encode_frame(
            7,
            STATUS_NEW,
            Some(&FrameTarget {
                network: TargetNetwork::Tcp,
                destination: target.clone(),
            }),
            b"abc",
            false,
        )?;
        let frame = read_frame(&mut bytes.as_slice()).await?.context("frame")?;
        assert_eq!(frame.session_id, 7);
        assert_eq!(frame.status, STATUS_NEW);
        assert_eq!(frame.payload, b"abc");
        assert_eq!(frame.target.expect("target").destination, target);
        Ok(())
    }
}
