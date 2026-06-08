use crate::core::{CoreSession, ProxyCore};
use crate::padding::PaddingScheme;
use crate::protocol::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, Frame, ProxyTarget,
    decode_target, parse_settings, read_auth_preface_user, read_frame, resolve_target_addr,
    target_name, write_frame, write_payload_chunks,
};
use crate::socket_protect;
use crate::tls::{self, ServerTlsAcceptor, ServerTlsMaterial, ServerTlsStream, TlsEchServerKeys};
use crate::uot;
use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, interval};

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub password: String,
    pub users: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub certificates: Vec<String>,
    pub key: Option<String>,
    pub padding_scheme: Vec<String>,
    pub heartbeat_interval_secs: u64,
    pub ech: Option<TlsEchServerKeys>,
}

struct EarlyDataTlsStream {
    early_data: Vec<u8>,
    early_pos: usize,
    inner: ServerTlsStream,
}

impl EarlyDataTlsStream {
    fn new(inner: ServerTlsStream, early_data: Vec<u8>) -> Self {
        Self {
            early_data,
            early_pos: 0,
            inner,
        }
    }
}

impl AsyncRead for EarlyDataTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.early_pos < self.early_data.len() {
            let len = buf.remaining().min(self.early_data.len() - self.early_pos);
            let end = self.early_pos + len;
            buf.put_slice(&self.early_data[self.early_pos..end]);
            self.early_pos = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for EarlyDataTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn run_server(config: ServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.password, &config.users);
    run_server_with_core(config, core).await
}

pub async fn run_server_with_core(config: ServerConfig, core: ProxyCore) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Aerion server on {}", config.listen))?;
    run_server_listener_with_core(listener, config, core).await
}

pub async fn run_server_listener(listener: TcpListener, config: ServerConfig) -> Result<()> {
    let core = ProxyCore::from_credentials(&config.password, &config.users);
    run_server_listener_with_core(listener, config, core).await
}

pub async fn run_server_listener_with_core(
    listener: TcpListener,
    config: ServerConfig,
    core: ProxyCore,
) -> Result<()> {
    let tls_config = tls::build_server_tls_acceptor(&ServerTlsMaterial {
        cert_path: tls::present_path(&config.cert_path).map(PathBuf::from),
        key_path: tls::present_path(&config.key_path).map(PathBuf::from),
        certificates: config.certificates.clone(),
        key: config.key.clone(),
        label: "AnyTLS server TLS".to_string(),
        alpn_protocols: Vec::new(),
        early_data: true,
        ech: config.ech.clone(),
    })?;
    let acceptor = tls_config;
    let padding = PaddingScheme::from_lines(config.padding_scheme.clone())?;
    tracing::info!("server listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = listener.accept().await.context("accept Aerion client")?;
        let acceptor = acceptor.clone();
        let passwords = auth_passwords(&config.password, &config.users);
        let padding = padding.clone();
        let core = core.clone();
        let heartbeat_interval_secs = config.heartbeat_interval_secs;
        tokio::spawn(async move {
            if let Err(error) = handle_client(
                stream,
                acceptor,
                passwords,
                padding,
                core,
                heartbeat_interval_secs,
                peer,
            )
            .await
            {
                tracing::warn!("client {peer} failed: {error:?}");
            }
        });
    }
}

async fn handle_client(
    stream: TcpStream,
    acceptor: ServerTlsAcceptor,
    passwords: Vec<String>,
    padding: PaddingScheme,
    core: ProxyCore,
    heartbeat_interval_secs: u64,
    peer: SocketAddr,
) -> Result<()> {
    let mut tls_stream = acceptor.accept(stream).await.context("accept TLS client")?;
    let mut early_data = Vec::new();
    if let Some(mut data) = tls_stream.rustls_early_data() {
        data.read_to_end(&mut early_data)
            .context("read TLS early data")?;
    }
    let mut tls_stream = EarlyDataTlsStream::new(tls_stream, early_data);
    let password_refs = passwords.iter().map(String::as_str).collect::<Vec<_>>();
    let credential = read_auth_preface_user(&mut tls_stream, &password_refs).await?;
    let session = core.authenticate_from(&credential, peer).await?;
    let (mut reader, writer) = split(tls_stream);
    let writer = Arc::new(Mutex::new(writer));
    let mut received_settings = false;
    let mut pending = HashSet::new();
    let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut heartbeat = interval(Duration::from_secs(heartbeat_interval_secs));
    heartbeat.tick().await;

    loop {
        let frame = tokio::select! {
            frame = read_frame(&mut reader) => frame?,
            _ = heartbeat.tick() => {
                if received_settings {
                    let mut writer = writer.lock().await;
                    write_frame(&mut *writer, CMD_HEART_REQUEST, 0, &[]).await?;
                }
                continue;
            }
        };
        match frame.cmd {
            CMD_SYN => {
                if !received_settings {
                    let mut writer = writer.lock().await;
                    write_frame(&mut *writer, CMD_ALERT, 0, b"client did not send settings")
                        .await?;
                    bail!("client did not send settings before SYN");
                }
                pending.insert(frame.stream_id);
            }
            CMD_PSH if streams.contains_key(&frame.stream_id) => {
                let sender = streams.get(&frame.stream_id).expect("stream key exists");
                if sender.send(frame.payload).await.is_err() {
                    streams.remove(&frame.stream_id);
                }
            }
            CMD_PSH if pending.remove(&frame.stream_id) => {
                match open_stream(frame, writer.clone(), session.clone()).await {
                    Ok((stream_id, sender)) => {
                        streams.insert(stream_id, sender);
                    }
                    Err(error) => {
                        tracing::warn!("open stream failed: {error:?}");
                    }
                }
            }
            CMD_FIN => {
                streams.remove(&frame.stream_id);
            }
            CMD_HEART_REQUEST => {
                let mut writer = writer.lock().await;
                write_frame(&mut *writer, CMD_HEART_RESPONSE, frame.stream_id, &[]).await?;
            }
            CMD_SETTINGS => {
                let settings = parse_settings(&frame.payload);
                received_settings = true;
                if settings.get("padding-md5").map(String::as_str) != Some(padding.md5()) {
                    let mut writer = writer.lock().await;
                    write_frame(
                        &mut *writer,
                        CMD_UPDATE_PADDING_SCHEME,
                        0,
                        padding.raw_text().as_bytes(),
                    )
                    .await?;
                }
                let mut writer = writer.lock().await;
                write_frame(&mut *writer, CMD_SERVER_SETTINGS, 0, b"v=2").await?;
            }
            CMD_WASTE | CMD_SERVER_SETTINGS | CMD_UPDATE_PADDING_SCHEME => {}
            CMD_ALERT => {
                bail!("client alert: {}", String::from_utf8_lossy(&frame.payload));
            }
            _ => {}
        }
    }
}

fn auth_passwords(password: &str, users: &[String]) -> Vec<String> {
    std::iter::once(password)
        .chain(users.iter().map(String::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

async fn open_stream(
    frame: Frame,
    writer: Arc<Mutex<WriteHalf<EarlyDataTlsStream>>>,
    session: CoreSession,
) -> Result<(u32, mpsc::Sender<Vec<u8>>)> {
    let stream_id = frame.stream_id;
    let (target, initial_payload) = decode_target(&frame.payload)?;
    if uot::is_magic_target(&target) {
        return open_uot_stream(stream_id, &target, initial_payload, writer, session).await;
    }
    let remote = match socket_protect::connect_proxy_target(&target).await {
        Ok(remote) => remote,
        Err(error) => {
            let mut writer = writer.lock().await;
            write_frame(
                &mut *writer,
                CMD_SYNACK,
                stream_id,
                error.to_string().as_bytes(),
            )
            .await?;
            return Err(error);
        }
    };
    let _ = remote.set_nodelay(true);
    {
        let mut writer = writer.lock().await;
        write_frame(&mut *writer, CMD_SYNACK, stream_id, &[]).await?;
    }
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(32);
    tracing::info!("opened stream {stream_id} to {}", target_name(&target));

    if !initial_payload.is_empty() {
        sender
            .send(initial_payload.to_vec())
            .await
            .context("queue initial stream payload")?;
    }

    let downlink_writer = writer.clone();
    let downlink_session = session.clone();
    tokio::spawn(async move {
        let result = async {
            let mut buffer = vec![0u8; 32 * 1024];
            loop {
                let read = remote_reader
                    .read(&mut buffer)
                    .await
                    .context("read target payload")?;
                if read == 0 {
                    let mut writer = downlink_writer.lock().await;
                    write_frame(&mut *writer, CMD_FIN, stream_id, &[]).await?;
                    return Ok::<(), anyhow::Error>(());
                }
                downlink_session.record_download(read).await?;
                {
                    let mut writer = downlink_writer.lock().await;
                    write_payload_chunks(&mut *writer, stream_id, &buffer[..read]).await?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("stream {stream_id} downlink failed: {error:?}");
        }
    });

    let uplink_session = session;
    tokio::spawn(async move {
        let result = async {
            while let Some(payload) = receiver.recv().await {
                uplink_session.record_upload(payload.len()).await?;
                remote_writer
                    .write_all(&payload)
                    .await
                    .context("write target payload")?;
            }
            remote_writer
                .shutdown()
                .await
                .context("shutdown target writer")
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("stream {stream_id} uplink failed: {error:?}");
        }
    });

    Ok((stream_id, sender))
}

async fn open_uot_stream(
    stream_id: u32,
    target: &ProxyTarget,
    initial_payload: &[u8],
    writer: Arc<Mutex<WriteHalf<EarlyDataTlsStream>>>,
    session: CoreSession,
) -> Result<(u32, mpsc::Sender<Vec<u8>>)> {
    let (request, initial_packet) = uot::decode_request_for_target(target, initial_payload)?;
    let udp = match &request.destination {
        ProxyTarget::Ip(addr) if addr.is_ipv6() => UdpSocket::bind("[::]:0").await?,
        _ => UdpSocket::bind("0.0.0.0:0").await?,
    };
    if request.is_connect {
        let target = resolve_target_addr(&request.destination).await?;
        udp.connect(target)
            .await
            .with_context(|| format!("connect UDP socket to {target}"))?;
    }
    {
        let mut writer = writer.lock().await;
        write_frame(&mut *writer, CMD_SYNACK, stream_id, &[]).await?;
    }
    let udp = Arc::new(udp);
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(32);
    tracing::info!("opened UOT stream {stream_id}");

    if !initial_packet.is_empty() {
        sender
            .send(initial_packet.to_vec())
            .await
            .context("queue initial legacy UOT packet")?;
    }

    let uplink_udp = udp.clone();
    let is_connect = request.is_connect;
    let uplink_session = session.clone();
    tokio::spawn(async move {
        let result = async {
            while let Some(packet) = receiver.recv().await {
                if is_connect {
                    let payload = uot::decode_connect_packet(&packet)?;
                    uplink_session.record_upload(payload.len()).await?;
                    let sent = uplink_udp
                        .send(payload)
                        .await
                        .context("send connected UDP payload")?;
                    if sent != payload.len() {
                        bail!("short UDP send: expected {}, wrote {}", payload.len(), sent);
                    }
                } else {
                    let (target, payload) = uot::decode_associate_packet(&packet)?;
                    let target = resolve_target_addr(&target).await?;
                    uplink_session.record_upload(payload.len()).await?;
                    let sent = uplink_udp
                        .send_to(payload, target)
                        .await
                        .with_context(|| format!("send UDP payload to {target}"))?;
                    if sent != payload.len() {
                        bail!("short UDP send: expected {}, wrote {}", payload.len(), sent);
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("UOT stream {stream_id} uplink failed: {error:?}");
        }
    });

    let downlink_udp = udp.clone();
    let downlink_writer = writer.clone();
    let downlink_session = session;
    tokio::spawn(async move {
        let result: Result<()> = async {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                let (read, source) = if is_connect {
                    let read = downlink_udp
                        .recv(&mut buffer)
                        .await
                        .context("receive connected UDP payload")?;
                    let source = downlink_udp.peer_addr().context("read UDP peer address")?;
                    (read, source)
                } else {
                    downlink_udp
                        .recv_from(&mut buffer)
                        .await
                        .context("receive UDP payload")?
                };
                let packet = if is_connect {
                    uot::encode_connect_packet(&buffer[..read])?
                } else {
                    uot::encode_associate_packet(&ProxyTarget::Ip(source), &buffer[..read])?
                };
                downlink_session.record_download(read).await?;
                {
                    let mut writer = downlink_writer.lock().await;
                    write_payload_chunks(&mut *writer, stream_id, &packet).await?;
                }
            }
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("UOT stream {stream_id} downlink failed: {error:?}");
        }
    });

    Ok((stream_id, sender))
}
