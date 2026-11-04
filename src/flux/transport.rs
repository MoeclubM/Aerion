use super::config::{
    FluxCertMode, FluxChannelClientConfig, FluxChannelServerConfig, FluxHttpMode, FluxSecurityMode,
    FluxTransportKind,
};
use super::frame::{
    FluxFrame, MAX_FLUX_FRAME_LEN, decode_frame_body, encode_frame_body,
    write_length_prefixed_frame,
};
use super::obfs::{FluxObfsUdpSocket, client_obfs_handshake, server_obfs_handshake};
use super::reality_udp::{
    RealityCidGenerator, RealityQuicCertVerifier, RealityUdpSocket,
    generate_ephemeral_quic_server_tls,
};
use crate::listener::ListenerStopToken;
use crate::quic;
use crate::reality::{self, RealityCertificateState, RealityServerConfig};
use crate::reality_tls_client;
use crate::replay_cache::{ReplayCache, ReplayError};
use crate::socket_protect;
use crate::tls::{self, ServerTlsAcceptor};
use crate::utls::UtlsFingerprint;
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

const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const QUIC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(12);
const QUIC_STREAM_WINDOW: u32 = 8 * 1024 * 1024;
const QUIC_CONN_WINDOW: u32 = 20 * 1024 * 1024;
const QUIC_DATAGRAM_BUF: usize = 4 * 1024 * 1024;

pub struct FluxChannelGuard {
    stop: ListenerStopToken,
    quic_conn: Option<quinn::Connection>,
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
                    let body = self.buf.split_to(len);
                    return Ok(Some(decode_frame_body(&body)?));
                }
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
                            Ok(bytes) => return Ok(Some(decode_frame_body(&bytes)?)),
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
        write_length_prefixed_frame(&mut self.writer, frame).await?;
        if flush {
            self.writer
                .flush()
                .await
                .context("flush Flux channel stream")?;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        tokio::select! {
            _ = self._guard.closed() => bail!("Flux channel closed"),
            result = self.writer.flush() => result.context("flush Flux channel stream"),
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
    let (reader, writer) = tokio::io::split(stream);
    let guard = Arc::new(FluxChannelGuard {
        stop: ListenerStopToken::new(),
        quic_conn: None,
        _quic_endpoint: None,
    });
    (
        FluxFrameReader {
            reader: Box::new(reader),
            quic_conn: None,
            buf: BytesMut::with_capacity(16 * 1024),
            _guard: guard.clone(),
        },
        FluxFrameWriter {
            writer: Box::new(writer),
            quic_conn: None,
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
        _quic_endpoint: endpoint,
    });
    (
        FluxFrameReader {
            reader: Box::new(recv),
            quic_conn: Some(connection.clone()),
            buf: BytesMut::with_capacity(16 * 1024),
            _guard: guard.clone(),
        },
        FluxFrameWriter {
            writer: Box::new(send),
            quic_conn: Some(connection),
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
        mtu_cfg.upper_bound(1440);
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
            let stream = connect_client_stream_channel(channel, remote_addr).await?;
            Ok(split_boxed_stream(stream))
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
    let udp_std = socket_protect::bind_udp_std(bind_addr)?;
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
        FluxSecurityMode::Reality => {
            let reality = channel
                .reality
                .as_ref()
                .context("missing Flux UDP REALITY client config")?;
            let mut tls_cfg =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(RealityQuicCertVerifier::default()))
                    .with_no_client_auth();
            tls_cfg.alpn_protocols = alpn;
            let quic_tls = QuicClientConfig::try_from(Arc::new(tls_cfg))
                .context("build Flux REALITY QUIC client TLS")?;
            let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
            client_cfg.transport_config(transport_cfg);
            let mut ep_cfg = quinn::EndpointConfig::default();
            let cid_maker = RealityCidGenerator::new(reality);
            ep_cfg.cid_generator(move || Box::new(cid_maker.clone()));
            let mut ep = Endpoint::new(ep_cfg, None, udp_std, Arc::new(quinn::TokioRuntime))
                .context("bind Flux REALITY QUIC client endpoint")?;
            ep.set_default_client_config(client_cfg);
            ep
        }
        FluxSecurityMode::Obfs => {
            let obfs_key = channel
                .obfs_key
                .as_deref()
                .context("missing Flux UDP obfs_key")?;
            let mut tls_cfg =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(RealityQuicCertVerifier::default()))
                    .with_no_client_auth();
            tls_cfg.alpn_protocols = alpn;
            let quic_tls = QuicClientConfig::try_from(Arc::new(tls_cfg))
                .context("build Flux obfs QUIC client TLS")?;
            let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
            client_cfg.transport_config(transport_cfg);
            let obfs_socket = FluxObfsUdpSocket::new(udp_std, obfs_key)?;
            let mut ep_cfg = quinn::EndpointConfig::default();
            let _ = ep_cfg.max_udp_payload_size(1488);
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
) -> Result<BoxedTransportStream> {
    let tcp = socket_protect::connect_tcp_addr(remote_addr)
        .await
        .with_context(|| format!("connect Flux TCP channel {} ({remote_addr})", channel.id))?;
    let vless_tp = channel.to_vless_transport();
    match channel.security {
        FluxSecurityMode::Reality => {
            let reality = channel
                .reality
                .as_ref()
                .context("missing Flux REALITY client config")?;
            let fingerprint = channel.fingerprint.unwrap_or(UtlsFingerprint::Chrome);
            let alpn = if !channel.alpn.is_empty() {
                Some(
                    channel
                        .alpn
                        .iter()
                        .map(|item| item.as_bytes().to_vec())
                        .collect(),
                )
            } else {
                let tp_alpn = vless_tp.alpn_protocols();
                if tp_alpn.is_empty() {
                    None
                } else {
                    Some(tp_alpn)
                }
            };
            let tls_stream =
                reality_tls_client::connect(tcp, reality, &channel.sni, fingerprint, alpn, None)
                    .await
                    .with_context(|| format!("Flux REALITY handshake on channel {}", channel.id))?;
            vless_transport::apply_client_transport(tls_stream, &vless_tp, &channel.server_host)
                .await
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
            vless_transport::apply_client_transport(tls_stream, &vless_tp, &channel.server_host)
                .await
        }
        FluxSecurityMode::Obfs => {
            let obfs_key = channel
                .obfs_key
                .as_deref()
                .context("missing Flux obfs_key")?;
            let outer =
                vless_transport::apply_client_transport(tcp, &vless_tp, &channel.server_host)
                    .await?;
            client_obfs_handshake(outer, obfs_key).await
        }
    }
}

pub struct PreparedRealityStreamState {
    pub config: RealityServerConfig,
    pub cert_state: RealityCertificateState,
    pub replay: ReplayCache<[u8; 32]>,
    pub fallback_override: Option<bool>,
}

#[derive(Clone)]
pub struct PreparedStreamListener {
    pub config: FluxChannelServerConfig,
    pub vless_transport: VlessTransportConfig,
    pub tls_acceptor: Option<ServerTlsAcceptor>,
    pub reality: Option<Arc<PreparedRealityStreamState>>,
    pub obfs_replay: Option<Arc<ReplayCache<[u8; 32]>>>,
}

impl PreparedStreamListener {
    pub fn prepare(config: FluxChannelServerConfig) -> Result<Self> {
        let vless_transport = config.to_vless_transport();
        let mut tls_acceptor = None;
        let mut reality = None;
        let mut obfs_replay = None;

        match config.security {
            FluxSecurityMode::Reality => {
                let reality_cfg = config
                    .reality
                    .clone()
                    .context("missing Flux server REALITY config")?;
                reality = Some(Arc::new(PreparedRealityStreamState {
                    config: reality_cfg,
                    cert_state: RealityCertificateState::build()?,
                    replay: ReplayCache::new(Duration::from_secs(180), 8192),
                    fallback_override: config.reality_fallback,
                }));
            }
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
                obfs_replay = Some(Arc::new(ReplayCache::new(Duration::from_secs(240), 8192)));
            }
        }

        Ok(Self {
            config,
            vless_transport,
            tls_acceptor,
            reality,
            obfs_replay,
        })
    }

    pub async fn accept_and_serve<F, Fut>(
        &self,
        stream: TcpStream,
        local_port: u16,
        handler: F,
    ) -> Result<()>
    where
        F: FnMut(BoxedTransportStream) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        match self.config.security {
            FluxSecurityMode::Reality => {
                let state = self.reality.as_ref().expect("REALITY state prepared");
                let auth_res = tokio::time::timeout(Duration::from_secs(10), async {
                    let raw = reality::peek_client_hello(&stream).await?;
                    let auth = reality::authenticate_client_hello(&raw, &state.config)?;
                    match state.replay.check_and_store(auth.auth_key) {
                        Ok(()) => Ok(auth),
                        Err(ReplayError::Replayed) => bail!("replayed Flux REALITY ClientHello"),
                        Err(ReplayError::Full) => bail!("Flux REALITY replay cache full"),
                    }
                })
                .await;

                let authenticated = match auth_res {
                    Ok(Ok(auth)) => auth,
                    Ok(Err(err)) => {
                        tracing::debug!(
                            "Flux REALITY probe/unauthenticated on :{local_port}: {err:#}"
                        );
                        handle_unauthenticated_reality_probe(
                            stream,
                            &state.config,
                            local_port,
                            state.fallback_override,
                        )
                        .await;
                        return Ok(());
                    }
                    Err(_) => {
                        return Ok(());
                    }
                };

                let default_h2 = [b"h2".to_vec()];
                let alpn: &[Vec<u8>] = if !state.config.alpn_protocols.is_empty() {
                    &state.config.alpn_protocols
                } else if self.config.transport == FluxTransportKind::Http
                    && self.config.http_mode == FluxHttpMode::H2
                {
                    &default_h2
                } else {
                    &[]
                };
                let server_cfg = state
                    .cert_state
                    .server_config(&authenticated.auth_key, alpn)?;
                let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
                let tls_stream = acceptor
                    .accept(stream)
                    .await
                    .context("accept Flux REALITY TLS")?;
                vless_transport::serve_server_transport(tls_stream, &self.vless_transport, handler)
                    .await
            }
            FluxSecurityMode::Tls => {
                if self.config.cert_mode == FluxCertMode::OriginPlain {
                    vless_transport::serve_server_transport(stream, &self.vless_transport, handler)
                        .await
                } else {
                    let acceptor = self
                        .tls_acceptor
                        .as_ref()
                        .context("missing Flux TLS acceptor")?;
                    let tls_stream = acceptor.accept(stream).await.context("accept Flux TLS")?;
                    vless_transport::serve_server_transport(
                        tls_stream,
                        &self.vless_transport,
                        handler,
                    )
                    .await
                }
            }
            FluxSecurityMode::Obfs => {
                let obfs_key = self
                    .config
                    .obfs_key
                    .clone()
                    .context("missing Flux server obfs_key")?;
                let replay = self
                    .obfs_replay
                    .clone()
                    .context("missing Flux server obfs replay")?;
                let inner_handler = handler;
                vless_transport::serve_server_transport(
                    stream,
                    &self.vless_transport,
                    move |outer| {
                        let obfs_key = obfs_key.clone();
                        let replay = replay.clone();
                        let mut next = inner_handler.clone();
                        async move {
                            let decrypted =
                                server_obfs_handshake(outer, &obfs_key, &replay).await?;
                            next(decrypted).await
                        }
                    },
                )
                .await
            }
        }
    }
}

async fn handle_unauthenticated_reality_probe(
    stream: TcpStream,
    config: &RealityServerConfig,
    local_port: u16,
    fallback_override: Option<bool>,
) {
    let use_fallback = fallback_override.unwrap_or(local_port == 443)
        && !config.server_name.trim().is_empty()
        && config.server_port > 0;
    if use_fallback {
        let _ = reality::proxy_fallback(stream, config).await;
    } else {
        let mut jitter = [0u8; 2];
        let _ = getrandom::fill(&mut jitter);
        let delay_ms = 250 + (u64::from(u16::from_be_bytes(jitter)) % 651);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        drop(stream);
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
        FluxSecurityMode::Reality => {
            let reality = listener
                .reality
                .as_ref()
                .context("missing Flux UDP REALITY server config")?;
            let alpn = if reality.alpn_protocols.is_empty() {
                default_alpn
            } else {
                reality.alpn_protocols.clone()
            };
            let tls_cfg = generate_ephemeral_quic_server_tls(&reality.server_name, alpn)?;
            let crypto = QuicServerConfig::try_from(tls_cfg)
                .context("build Flux REALITY QUIC server TLS")?;
            let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            server_cfg.transport_config(transport_cfg);
            let reality_sock = RealityUdpSocket::new(udp_std, reality, listener.reality_fallback)?;
            Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server_cfg),
                Arc::new(reality_sock),
                Arc::new(quinn::TokioRuntime),
            )
            .context("bind Flux REALITY QUIC server endpoint")
        }
        FluxSecurityMode::Obfs => {
            let obfs_key = listener
                .obfs_key
                .as_deref()
                .context("missing Flux UDP server obfs_key")?;
            let tls_cfg = generate_ephemeral_quic_server_tls("localhost", default_alpn)?;
            let crypto =
                QuicServerConfig::try_from(tls_cfg).context("build Flux obfs QUIC server TLS")?;
            let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            server_cfg.transport_config(transport_cfg);
            let obfs_sock = FluxObfsUdpSocket::new(udp_std, obfs_key)?;
            let mut ep_cfg = quinn::EndpointConfig::default();
            let _ = ep_cfg.max_udp_payload_size(1488);
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
