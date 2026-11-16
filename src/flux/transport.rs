use super::config::{
    FluxCertMode, FluxChannelClientConfig, FluxChannelServerConfig, FluxSecurityMode,
    FluxTransportKind, parse_flux_x25519_key,
};
use super::frame::{
    FluxFrame, MAX_FLUX_FRAME_LEN, decode_frame_body_bytes, encode_frame_body,
    encode_length_prefixed_frame_into,
};
use super::obfs::{
    FluxObfsUdpSocket, ObfsQuicCertVerifier, client_obfs_handshake,
    generate_ephemeral_quic_server_tls, server_obfs_handshake,
};
use crate::listener::ListenerStopToken;
use crate::quic;
use crate::replay_cache::ReplayCache;
use crate::socket_protect;
use crate::tls::{self, ServerTlsAcceptor};
use crate::vless_transport::{self, BoxedTransportStream, VlessTransportConfig};
use anyhow::{Context, Result, bail, ensure};
use bytes::BytesMut;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, VarInt};
use rustls::pki_types::ServerName;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(12);
const QUIC_STREAM_WINDOW: u32 = 32 * 1024 * 1024;
const QUIC_CONN_WINDOW: u32 = 48 * 1024 * 1024;
const QUIC_DATAGRAM_BUF: usize = 8 * 1024 * 1024;
const FRAME_IO_BUF_CAP: usize = 64 * 1024;

pub struct FluxChannelGuard {
    stop: ListenerStopToken,
    quic_conn: Option<quinn::Connection>,
    static_binding: Option<[u8; 32]>,
    _quic_endpoint: Option<Endpoint>,
}

impl FluxChannelGuard {
    pub fn close(&self) {
        self.stop.stop();
        if let Some(conn) = &self.quic_conn {
            conn.close(VarInt::from_u32(0), b"flux channel closed");
        }
    }

    pub async fn closed(&self) {
        self.stop.stopped().await;
    }

    pub fn channel_binding(&self) -> Result<[u8; 32]> {
        let mut binding = [0; 32];
        if let Some(conn) = &self.quic_conn {
            conn.export_keying_material(&mut binding, b"EXPORTER-Flux-v2", b"")
                .map_err(|_| anyhow::anyhow!("export Flux QUIC channel binding"))?;
        } else if let Some(static_binding) = self.static_binding {
            binding = static_binding;
        }
        Ok(binding)
    }
}

impl Drop for FluxChannelGuard {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct FluxFrameReader {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    quic_conn: Option<quinn::Connection>,
    buf: BytesMut,
    _guard: Arc<FluxChannelGuard>,
}

pub struct FluxFrameWriter {
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    quic_conn: Option<quinn::Connection>,
    write_buf: BytesMut,
    _guard: Arc<FluxChannelGuard>,
}

impl FluxFrameReader {
    pub async fn read_frame(&mut self) -> Result<Option<FluxFrame>> {
        let guard = self._guard.clone();
        tokio::select! {
            _ = guard.closed() => Ok(None),
            result = self.read_frame_inner() => result,
        }
    }

    async fn read_frame_inner(&mut self) -> Result<Option<FluxFrame>> {
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                    as usize;
                ensure!(
                    (1..=MAX_FLUX_FRAME_LEN).contains(&len),
                    "invalid Flux frame length {len}"
                );
                if self.buf.len() >= 4 + len {
                    let _ = self.buf.split_to(4);
                    let body = self.buf.split_to(len).freeze();
                    return Ok(Some(decode_frame_body_bytes(body)?));
                }
                self.buf.reserve((4 + len).saturating_sub(self.buf.len()));
            } else if self.buf.capacity() - self.buf.len() < FRAME_IO_BUF_CAP {
                self.buf.reserve(FRAME_IO_BUF_CAP);
            }
            if let Some(conn) = &self.quic_conn {
                tokio::select! {
                    read = self.reader.read_buf(&mut self.buf) => {
                        if read.context("read Flux QUIC stream")? == 0 {
                            ensure!(self.buf.is_empty(), "truncated Flux QUIC frame");
                            return Ok(None);
                        }
                    }
                    dgram = conn.read_datagram() => {
                        match dgram {
                            Ok(bytes) => return Ok(Some(decode_frame_body_bytes(bytes)?)),
                            Err(_) => {
                                if self.buf.is_empty() {
                                    return Ok(None);
                                }
                            }
                        }
                    }
                }
            } else {
                let read = self
                    .reader
                    .read_buf(&mut self.buf)
                    .await
                    .context("read Flux stream")?;
                if read == 0 {
                    ensure!(self.buf.is_empty(), "truncated Flux stream frame");
                    return Ok(None);
                }
            }
        }
    }
}

impl FluxFrameWriter {
    pub async fn write_frame(&mut self, frame: &FluxFrame, flush: bool) -> Result<()> {
        let guard = self._guard.clone();
        tokio::select! {
            _ = guard.closed() => bail!("Flux channel closed"),
            result = self.write_frame_inner(frame, flush) => result,
        }
    }

    async fn write_frame_inner(&mut self, frame: &FluxFrame, flush: bool) -> Result<()> {
        if matches!(frame, FluxFrame::UdpDatagram { .. })
            && let Some(conn) = &self.quic_conn
        {
            let body = encode_frame_body(frame)?;
            if conn
                .max_datagram_size()
                .is_some_and(|max| body.len() <= max)
            {
                conn.send_datagram(body)
                    .context("send Flux QUIC datagram")?;
                return Ok(());
            }
        }
        encode_length_prefixed_frame_into(frame, &mut self.write_buf)?;
        if flush || self.write_buf.len() >= FRAME_IO_BUF_CAP {
            self.writer
                .write_all(&self.write_buf)
                .await
                .context("write Flux channel stream")?;
            self.write_buf.clear();
        }
        if flush {
            self.writer
                .flush()
                .await
                .context("flush Flux channel stream")?;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        let guard = self._guard.clone();
        tokio::select! {
            _ = guard.closed() => bail!("Flux channel closed"),
            result = async {
                if !self.write_buf.is_empty() {
                    self.writer
                        .write_all(&self.write_buf)
                        .await
                        .context("write Flux channel stream")?;
                    self.write_buf.clear();
                }
                self.writer
                    .flush()
                    .await
                    .context("flush Flux channel stream")
            } => result,
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self._guard.close();
        Ok(())
    }
}

pub fn split_boxed_stream(
    stream: BoxedTransportStream,
) -> (FluxFrameReader, FluxFrameWriter, Arc<FluxChannelGuard>) {
    split_boxed_stream_with_binding(stream, None)
}

pub fn split_boxed_stream_with_binding(
    stream: BoxedTransportStream,
    static_binding: Option<[u8; 32]>,
) -> (FluxFrameReader, FluxFrameWriter, Arc<FluxChannelGuard>) {
    let (reader, writer) = tokio::io::split(stream);
    let guard = Arc::new(FluxChannelGuard {
        stop: ListenerStopToken::new(),
        quic_conn: None,
        static_binding,
        _quic_endpoint: None,
    });
    (
        FluxFrameReader {
            reader: Box::new(reader),
            quic_conn: None,
            buf: BytesMut::with_capacity(FRAME_IO_BUF_CAP),
            _guard: guard.clone(),
        },
        FluxFrameWriter {
            writer: Box::new(writer),
            quic_conn: None,
            write_buf: BytesMut::with_capacity(FRAME_IO_BUF_CAP),
            _guard: guard.clone(),
        },
        guard,
    )
}

pub fn split_quic_channel(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    connection: quinn::Connection,
    endpoint: Option<Endpoint>,
) -> (FluxFrameReader, FluxFrameWriter, Arc<FluxChannelGuard>) {
    let guard = Arc::new(FluxChannelGuard {
        stop: ListenerStopToken::new(),
        quic_conn: Some(connection.clone()),
        static_binding: None,
        _quic_endpoint: endpoint,
    });
    (
        FluxFrameReader {
            reader: Box::new(recv),
            quic_conn: Some(connection.clone()),
            buf: BytesMut::with_capacity(FRAME_IO_BUF_CAP),
            _guard: guard.clone(),
        },
        FluxFrameWriter {
            writer: Box::new(send),
            quic_conn: Some(connection),
            write_buf: BytesMut::with_capacity(FRAME_IO_BUF_CAP),
            _guard: guard.clone(),
        },
        guard,
    )
}

fn build_quic_transport_config(
    client_keepalive: bool,
    obfs: bool,
) -> Result<quinn::TransportConfig> {
    let mut cfg =
        quic::transport_config_with_idle_timeout(QUIC_IDLE_TIMEOUT, "build Flux QUIC timeout")?;
    cfg.stream_receive_window(VarInt::from_u32(QUIC_STREAM_WINDOW))
        .receive_window(VarInt::from_u32(QUIC_CONN_WINDOW))
        .send_window(u64::from(QUIC_CONN_WINDOW))
        .datagram_receive_buffer_size(Some(QUIC_DATAGRAM_BUF))
        .datagram_send_buffer_size(QUIC_DATAGRAM_BUF)
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    if obfs {
        let mut mtu_cfg = quinn::MtuDiscoveryConfig::default();
        mtu_cfg.upper_bound(1400);
        cfg.mtu_discovery_config(Some(mtu_cfg));
    }
    if client_keepalive {
        cfg.keep_alive_interval(Some(QUIC_KEEPALIVE_INTERVAL));
    }
    Ok(cfg)
}

fn quic_alpn_list(alpn: &[String]) -> Vec<Vec<u8>> {
    if alpn.is_empty() {
        vec![b"h3".to_vec()]
    } else {
        alpn.iter().map(|item| item.as_bytes().to_vec()).collect()
    }
}

pub async fn connect_client_channel(
    channel: &FluxChannelClientConfig,
    remote_addr: SocketAddr,
) -> Result<(FluxFrameReader, FluxFrameWriter, Arc<FluxChannelGuard>)> {
    match channel.transport {
        FluxTransportKind::Udp => connect_client_quic_channel(channel, remote_addr).await,
        FluxTransportKind::Tcp | FluxTransportKind::Http => {
            let (stream, binding) = connect_client_stream_channel(channel, remote_addr).await?;
            Ok(split_boxed_stream_with_binding(stream, binding))
        }
    }
}

async fn connect_client_quic_channel(
    channel: &FluxChannelClientConfig,
    remote_addr: SocketAddr,
) -> Result<(FluxFrameReader, FluxFrameWriter, Arc<FluxChannelGuard>)> {
    tls::init_crypto();
    let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let udp_std = socket_protect::bind_tunnel_udp_std(bind_addr)?;
    let transport_cfg = Arc::new(build_quic_transport_config(
        true,
        channel.security == FluxSecurityMode::Obfs,
    )?);
    let alpn = quic_alpn_list(&channel.alpn);
    let sni_clean = {
        let trimmed = channel.sni.trim().trim_matches(['[', ']']);
        if trimmed.is_empty() {
            "localhost"
        } else {
            trimmed
        }
    };

    let endpoint = match channel.security {
        FluxSecurityMode::Obfs => {
            let public_key = channel
                .public_key
                .as_deref()
                .context("missing Flux UDP public_key")?;
            let public_key_bytes = parse_flux_x25519_key(public_key)?;
            let mut tls_cfg =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(ObfsQuicCertVerifier::default()))
                    .with_no_client_auth();
            tls_cfg.alpn_protocols = alpn;
            let quic_tls = QuicClientConfig::try_from(Arc::new(tls_cfg))
                .context("build Flux obfs QUIC client TLS")?;
            let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
            client_cfg.transport_config(transport_cfg);
            let obfs_socket = FluxObfsUdpSocket::new(udp_std, &public_key_bytes)?;
            let mut ep_cfg = quinn::EndpointConfig::default();
            let _ = ep_cfg.max_udp_payload_size(1440);
            let mut ep = Endpoint::new_with_abstract_socket(
                ep_cfg,
                None,
                Arc::new(obfs_socket),
                Arc::new(quinn::TokioRuntime),
            )
            .context("bind Flux obfs QUIC client endpoint")?;
            ep.set_default_client_config(client_cfg);
            ep
        }
        FluxSecurityMode::Tls => {
            let mut tls_cfg = Arc::unwrap_or_clone(
                tls::client_config_with_fingerprint_and_custom_root_material_options(
                    channel.insecure,
                    channel.fingerprint,
                    &channel.ca_cert_paths,
                    &channel.ca_certificates,
                    false,
                    &channel.pinned_cert_sha256,
                )?,
            );
            tls_cfg.alpn_protocols = alpn;
            let quic_tls = QuicClientConfig::try_from(Arc::new(tls_cfg))
                .context("build Flux TLS QUIC client config")?;
            let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
            client_cfg.transport_config(transport_cfg);
            let mut ep = Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                udp_std,
                Arc::new(quinn::TokioRuntime),
            )
            .context("bind Flux TLS QUIC client endpoint")?;
            ep.set_default_client_config(client_cfg);
            ep
        }
    };

    let connection = endpoint
        .connect(remote_addr, sni_clean)
        .with_context(|| format!("connect Flux QUIC channel {} ({remote_addr})", channel.id))?
        .await
        .with_context(|| format!("handshake Flux QUIC channel {} ({remote_addr})", channel.id))?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("open Flux QUIC control stream")?;
    Ok(split_quic_channel(send, recv, connection, Some(endpoint)))
}

async fn connect_client_stream_channel(
    channel: &FluxChannelClientConfig,
    remote_addr: SocketAddr,
) -> Result<(BoxedTransportStream, Option<[u8; 32]>)> {
    let tcp = socket_protect::connect_tcp_addr(remote_addr)
        .await
        .with_context(|| format!("connect Flux TCP channel {} ({remote_addr})", channel.id))?;
    let vless_tp = channel.to_vless_transport();
    match channel.security {
        FluxSecurityMode::Tls => {
            let mut tls_cfg = Arc::unwrap_or_clone(
                tls::client_config_with_fingerprint_and_custom_root_material_options(
                    channel.insecure,
                    channel.fingerprint,
                    &channel.ca_cert_paths,
                    &channel.ca_certificates,
                    false,
                    &channel.pinned_cert_sha256,
                )?,
            );
            let alpn = if !channel.alpn.is_empty() {
                channel
                    .alpn
                    .iter()
                    .map(|item| item.as_bytes().to_vec())
                    .collect()
            } else {
                vless_tp.alpn_protocols()
            };
            if !alpn.is_empty() {
                tls_cfg.alpn_protocols = alpn;
            }
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
            let sni_clean = channel.sni.trim().trim_matches(['[', ']']).to_string();
            let server_name = ServerName::try_from(sni_clean)
                .with_context(|| format!("invalid Flux TLS SNI {}", channel.sni))?;
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .with_context(|| format!("Flux TLS handshake on channel {}", channel.id))?;
            let binding = if channel.tls_binding {
                let mut exporter = [0u8; 32];
                tls_stream
                    .get_ref()
                    .1
                    .export_keying_material(&mut exporter, b"EXPORTER-Flux-v2", Some(b""))
                    .context("export Flux TLS channel binding")?;
                Some(exporter)
            } else {
                None
            };
            let boxed = vless_transport::apply_client_transport(
                tls_stream,
                &vless_tp,
                &channel.server_host,
            )
            .await?;
            Ok((boxed, binding))
        }
        FluxSecurityMode::Obfs => {
            let public_key = channel
                .public_key
                .as_deref()
                .context("missing Flux public_key")?;
            let public_key_bytes = parse_flux_x25519_key(public_key)?;
            let outer =
                vless_transport::apply_client_transport(tcp, &vless_tp, &channel.server_host)
                    .await?;
            let (stream, binding) = client_obfs_handshake(outer, public_key_bytes).await?;
            Ok((stream, Some(binding)))
        }
    }
}

#[derive(Clone)]
pub struct PreparedStreamListener {
    pub config: FluxChannelServerConfig,
    pub vless_transport: VlessTransportConfig,
    pub tls_acceptor: Option<ServerTlsAcceptor>,
    pub(crate) obfs_replay: Option<Arc<ReplayCache<[u8; 32]>>>,
}

impl PreparedStreamListener {
    pub fn prepare(config: FluxChannelServerConfig) -> Result<Self> {
        let vless_transport = config.to_vless_transport();
        let mut tls_acceptor = None;
        let mut obfs_replay = None;

        match config.security {
            FluxSecurityMode::Tls => {
                if config.cert_mode != FluxCertMode::OriginPlain {
                    let mut material = config
                        .tls_material
                        .clone()
                        .context("missing Flux server TLS material")?;
                    if material.alpn_protocols.is_empty() {
                        material.alpn_protocols = vless_transport.alpn_protocols();
                    }
                    tls_acceptor = Some(tls::build_server_tls_acceptor(&material)?);
                }
            }
            FluxSecurityMode::Obfs => {
                obfs_replay = Some(Arc::new(ReplayCache::new(Duration::from_secs(240), 65_536)));
            }
        }

        Ok(Self {
            config,
            vless_transport,
            tls_acceptor,
            obfs_replay,
        })
    }

    pub async fn accept_and_serve<F, Fut>(&self, stream: TcpStream, handler: F) -> Result<()>
    where
        F: FnMut(BoxedTransportStream, Option<[u8; 32]>) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        match self.config.security {
            FluxSecurityMode::Tls => {
                if self.config.cert_mode == FluxCertMode::OriginPlain {
                    let mut inner_handler = handler;
                    vless_transport::serve_server_transport(
                        stream,
                        &self.vless_transport,
                        move |outer| inner_handler(outer, None),
                    )
                    .await
                } else {
                    let acceptor = self
                        .tls_acceptor
                        .as_ref()
                        .context("missing Flux TLS acceptor")?;
                    let tls_stream = acceptor.accept(stream).await.context("accept Flux TLS")?;
                    let mut binding = [0u8; 32];
                    tls_stream
                        .export_keying_material(&mut binding, b"EXPORTER-Flux-v2", b"")
                        .context("export Flux server TLS channel binding")?;
                    let mut inner_handler = handler;
                    vless_transport::serve_server_transport(
                        tls_stream,
                        &self.vless_transport,
                        move |outer| inner_handler(outer, Some(binding)),
                    )
                    .await
                }
            }
            FluxSecurityMode::Obfs => {
                let private_key_str = self
                    .config
                    .private_key
                    .as_deref()
                    .context("missing Flux server private_key")?;
                let private_key_bytes = parse_flux_x25519_key(private_key_str)?;
                let replay = self
                    .obfs_replay
                    .clone()
                    .context("missing Flux server obfs replay")?;
                let inner_handler = handler;
                vless_transport::serve_server_transport(
                    stream,
                    &self.vless_transport,
                    move |outer| {
                        let replay = replay.clone();
                        let mut next = inner_handler.clone();
                        async move {
                            let (decrypted, binding) =
                                server_obfs_handshake(outer, private_key_bytes, &replay).await?;
                            next(decrypted, Some(binding)).await
                        }
                    },
                )
                .await
            }
        }
    }
}

pub fn bind_server_tcp_listener(addr: SocketAddr, v6_only: bool) -> Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .with_context(|| format!("create Flux TCP listener socket for {addr}"))?;
    let _ = socket.set_reuse_address(true);
    if addr.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
        let _ = socket.set_only_v6(v6_only);
    }
    socket
        .set_nonblocking(true)
        .context("set Flux TCP listener nonblocking")?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind Flux TCP listener on {addr}"))?;
    socket
        .listen(1024)
        .with_context(|| format!("listen Flux TCP on {addr}"))?;
    TcpListener::from_std(socket.into()).context("convert Flux TCP listener to tokio")
}

pub fn bind_server_udp_socket(addr: SocketAddr, v6_only: bool) -> Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .with_context(|| format!("create Flux UDP socket on {addr}"))?;
    let _ = socket.set_reuse_address(true);
    if addr.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
        let _ = socket.set_only_v6(v6_only);
    }
    socket
        .set_nonblocking(true)
        .context("set Flux UDP socket nonblocking")?;
    socket_protect::configure_udp_socket_buffers(&socket);
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind Flux UDP socket on {addr}"))?;
    let std_sock: std::net::UdpSocket = socket.into();
    socket_protect::disable_windows_udp_connreset(&std_sock)?;
    Ok(std_sock)
}

pub fn build_server_quic_endpoint(
    listener: &FluxChannelServerConfig,
    udp_std: std::net::UdpSocket,
) -> Result<Endpoint> {
    tls::init_crypto();
    let transport_cfg = Arc::new(build_quic_transport_config(
        false,
        listener.security == FluxSecurityMode::Obfs,
    )?);
    let default_alpn = vec![b"h3".to_vec()];

    match listener.security {
        FluxSecurityMode::Obfs => {
            let private_key = listener
                .private_key
                .as_deref()
                .context("missing Flux UDP server private_key")?;
            let private_key_bytes = parse_flux_x25519_key(private_key)?;
            let public_key_bytes =
                PublicKey::from(&StaticSecret::from(private_key_bytes)).to_bytes();
            let tls_cfg = generate_ephemeral_quic_server_tls("localhost", default_alpn)?;
            let crypto =
                QuicServerConfig::try_from(tls_cfg).context("build Flux obfs QUIC server TLS")?;
            let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            server_cfg.transport_config(transport_cfg);
            let obfs_sock = FluxObfsUdpSocket::new(udp_std, &public_key_bytes)?;
            let mut ep_cfg = quinn::EndpointConfig::default();
            let _ = ep_cfg.max_udp_payload_size(1440);
            Endpoint::new_with_abstract_socket(
                ep_cfg,
                Some(server_cfg),
                Arc::new(obfs_sock),
                Arc::new(quinn::TokioRuntime),
            )
            .context("bind Flux obfs QUIC server endpoint")
        }
        FluxSecurityMode::Tls => {
            let material = listener
                .tls_material
                .as_ref()
                .context("missing Flux UDP TLS server material")?;
            let (certs, key) = tls::server_identity(
                material.cert_path.as_deref(),
                material.key_path.as_deref(),
                &material.certificates,
                material.key.as_deref(),
                &material.label,
            )?;
            let mut tls_cfg = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .with_context(|| format!("build Flux QUIC server TLS for {}", material.label))?;
            tls_cfg.alpn_protocols = if material.alpn_protocols.is_empty() {
                default_alpn
            } else {
                material.alpn_protocols.clone()
            };
            let crypto =
                QuicServerConfig::try_from(tls_cfg).context("build Flux TLS QUIC server config")?;
            let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            server_cfg.transport_config(transport_cfg);
            Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_cfg),
                udp_std,
                Arc::new(quinn::TokioRuntime),
            )
            .context("bind Flux TLS QUIC server endpoint")
        }
    }
}
