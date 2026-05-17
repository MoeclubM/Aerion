use crate::core::{CoreSession, CoreUser, ProxyCore};
use crate::protocol::{ProxyTarget, target_name};
use crate::{socket_protect, socks, tls, uot};
use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const NAIVE_PADDING_COUNT: usize = 8;
const NAIVE_MAX_CHUNK: usize = u16::MAX as usize;
const NAIVE_H2_ALPN: &[u8] = b"h2";
const NAIVE_H3_ALPN: &[u8] = b"h3";
const NAIVE_HTTP11_ALPN: &[u8] = b"http/1.1";
const NAIVE_QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const NAIVE_UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

pub fn default_naive_quic_congestion_control() -> String {
    "bbr".to_string()
}

#[derive(Clone, Debug)]
pub struct NaiveClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    pub password: String,
    pub sni: String,
    pub insecure: bool,
    pub extra_headers: Vec<(String, String)>,
    pub udp_over_tcp: bool,
    pub quic: bool,
    pub quic_congestion_control: String,
}

#[derive(Clone, Debug)]
pub struct NaiveServerConfig {
    pub listen: SocketAddr,
    pub username: String,
    pub password: String,
    pub users: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub udp_over_tcp: bool,
    pub tcp: bool,
    pub quic: bool,
    pub quic_congestion_control: String,
}

#[derive(Clone)]
struct NaiveServerRuntime {
    credentials: Arc<Vec<String>>,
    core: ProxyCore,
    tls_config: Arc<rustls::ServerConfig>,
    udp_over_tcp: bool,
}

#[derive(Default)]
struct NaiveReadState {
    read_padding: usize,
    read_remaining: usize,
    padding_remaining: usize,
}

#[derive(Default)]
struct NaiveWriteState {
    write_padding: usize,
}

enum NaiveTunnel {
    Http1 {
        stream: tokio_rustls::client::TlsStream<TcpStream>,
        pending: Vec<u8>,
    },
    Http2 {
        send: h2::SendStream<Bytes>,
        recv: h2::RecvStream,
        driver: JoinHandle<()>,
    },
    Http3 {
        send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
        recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        driver: JoinHandle<()>,
    },
}

pub async fn run_naive_client(config: NaiveClientConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Naive SOCKS listener on {}", config.listen))?;
    run_naive_client_listener(listener, config).await
}

pub async fn run_naive_client_listener(
    listener: TcpListener,
    config: NaiveClientConfig,
) -> Result<()> {
    tracing::info!("Naive client listening on socks5://{}", config.listen);
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("accept Naive SOCKS client")?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_naive_socks_client(stream, config).await {
                tracing::warn!("Naive SOCKS client {peer} failed: {error:?}");
            }
        });
    }
}

pub async fn run_naive_server(config: NaiveServerConfig) -> Result<()> {
    let credentials = naive_credentials(&config.username, &config.password, &config.users);
    let core = ProxyCore::new(
        credentials
            .iter()
            .map(|credential| CoreUser::password(credential, credential))
            .collect(),
    )?;
    run_naive_server_with_core(config, core).await
}

pub async fn run_naive_server_with_core(config: NaiveServerConfig, core: ProxyCore) -> Result<()> {
    ensure!(
        config.tcp || config.quic,
        "Naive server config disables both TCP and QUIC listeners"
    );
    let runtime = NaiveServerRuntime::from_config(&config, core)?;
    if !config.tcp {
        return run_naive_h3_server(config, runtime).await;
    }
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind Naive HTTPS listener on {}", config.listen))?;
    tracing::info!("Naive HTTPS server listening on {}", listener.local_addr()?);
    if config.quic {
        let runtime = runtime.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(error) = run_naive_h3_server(config, runtime).await {
                tracing::warn!("Naive HTTP/3 server exited: {error:?}");
            }
        });
    }
    let acceptor = tokio_rustls::TlsAcceptor::from(runtime.tls_config.clone());
    loop {
        let (stream, peer) = listener.accept().await.context("accept Naive TCP client")?;
        let runtime = runtime.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_naive_server_tcp(stream, peer, acceptor, runtime).await {
                tracing::warn!("Naive TCP client {peer} failed: {error:?}");
            }
        });
    }
}

impl NaiveServerRuntime {
    fn from_config(config: &NaiveServerConfig, core: ProxyCore) -> Result<Self> {
        let mut tls_config =
            Arc::unwrap_or_clone(tls::server_config(&config.cert_path, &config.key_path)?);
        tls_config.alpn_protocols = vec![NAIVE_H2_ALPN.to_vec(), NAIVE_HTTP11_ALPN.to_vec()];
        Ok(Self {
            credentials: Arc::new(naive_credentials(
                &config.username,
                &config.password,
                &config.users,
            )),
            core,
            tls_config: Arc::new(tls_config),
            udp_over_tcp: config.udp_over_tcp,
        })
    }
}

async fn handle_naive_server_tcp(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    runtime: NaiveServerRuntime,
) -> Result<()> {
    let mut tls = acceptor.accept(stream).await.context("accept Naive TLS")?;
    if tls.get_ref().1.alpn_protocol() == Some(NAIVE_H2_ALPN) {
        return handle_naive_h2_connection(tls, peer, runtime).await;
    }
    handle_naive_http1_connection(tls, peer, runtime).await
}

async fn handle_naive_http1_connection(
    mut tls: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
    runtime: NaiveServerRuntime,
) -> Result<()> {
    let (target, authorization, pending) = read_naive_http1_connect(&mut tls).await?;
    let credential = if runtime.credentials.is_empty() {
        None
    } else {
        let Some(credential) =
            naive_auth_credential(authorization.as_deref(), &runtime.credentials)
        else {
            tls.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"naive\"\r\n\r\n")
                .await
                .context("write Naive HTTP/1.1 auth failure")?;
            return Ok(());
        };
        Some(credential)
    };
    let session = naive_core_session(&runtime, credential.as_deref(), peer).await?;
    if uot::is_magic_target(&target) {
        ensure!(
            runtime.udp_over_tcp,
            "Naive HTTP/1.1 UDP-over-TCP is disabled by server config"
        );
        tls.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .context("write Naive HTTP/1.1 UOT response")?;
        return relay_naive_http1_uot(tls, pending, target, session).await;
    }
    let mut remote = connect_proxy_target(&target).await?;
    tls.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("write Naive HTTP/1.1 CONNECT response")?;
    tracing::info!("Naive serving HTTP/1.1 {}", target_name(&target));
    relay_naive_http1_server_tcp(tls, pending, remote, session).await
}

async fn handle_naive_h2_connection(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
    runtime: NaiveServerRuntime,
) -> Result<()> {
    let mut h2 = h2::server::handshake(tls)
        .await
        .context("initialize Naive HTTP/2 server")?;
    while let Some(request) = h2.accept().await {
        let (request, respond) = request.context("accept Naive HTTP/2 request")?;
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_naive_h2_request(request, respond, peer, runtime).await {
                tracing::warn!("Naive HTTP/2 stream failed: {error:?}");
            }
        });
    }
    Ok(())
}

async fn handle_naive_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    peer: SocketAddr,
    runtime: NaiveServerRuntime,
) -> Result<()> {
    let (parts, recv) = request.into_parts();
    let target = naive_request_target(&parts.method, &parts.uri)?;
    let credential = if runtime.credentials.is_empty() {
        None
    } else {
        let Some(credential) = naive_auth_credential(
            parts
                .headers
                .get(http::header::PROXY_AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            &runtime.credentials,
        ) else {
            send_h2_status(&mut respond, 407)?;
            return Ok(());
        };
        Some(credential)
    };
    let session = naive_core_session(&runtime, credential.as_deref(), peer).await?;
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .context("build Naive HTTP/2 CONNECT response")?;
    let send = respond
        .send_response(response, false)
        .context("send Naive HTTP/2 CONNECT response")?;
    if uot::is_magic_target(&target) {
        ensure!(
            runtime.udp_over_tcp,
            "Naive HTTP/2 UDP-over-TCP is disabled by server config"
        );
        return relay_naive_http2_uot(send, recv, target, session).await;
    }
    let remote = connect_proxy_target(&target).await?;
    tracing::info!("Naive serving HTTP/2 {}", target_name(&target));
    relay_naive_http2_server_tcp(send, recv, remote, session).await
}

async fn run_naive_h3_server(config: NaiveServerConfig, runtime: NaiveServerRuntime) -> Result<()> {
    let endpoint = build_naive_server_endpoint(&config)?;
    tracing::info!(
        "Naive HTTP/3 server listening on {}",
        endpoint.local_addr()?
    );
    while let Some(connecting) = endpoint.accept().await {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    if let Err(error) = handle_naive_h3_connection(connection, runtime).await {
                        tracing::warn!("Naive HTTP/3 connection failed: {error:?}");
                    }
                }
                Err(error) => tracing::warn!("Naive HTTP/3 handshake failed: {error:?}"),
            }
        });
    }
    Ok(())
}

async fn handle_naive_h3_connection(
    connection: quinn::Connection,
    runtime: NaiveServerRuntime,
) -> Result<()> {
    let peer = connection.remote_address();
    let mut h3 = h3::server::builder()
        .build(h3_quinn::Connection::new(connection))
        .await
        .context("initialize Naive HTTP/3 server")?;
    loop {
        let Some(resolver) = h3.accept().await.context("accept Naive HTTP/3 request")? else {
            return Ok(());
        };
        let (request, stream) = resolver
            .resolve_request()
            .await
            .context("resolve Naive HTTP/3 request")?;
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_naive_h3_request(request, stream, peer, runtime).await {
                tracing::warn!("Naive HTTP/3 stream failed: {error:?}");
            }
        });
    }
}

async fn handle_naive_h3_request<S>(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    peer: SocketAddr,
    runtime: NaiveServerRuntime,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
    S::SendStream: Send + 'static,
    S::RecvStream: Send + 'static,
{
    let target = naive_request_target(request.method(), request.uri())?;
    let credential = if runtime.credentials.is_empty() {
        None
    } else {
        let Some(credential) = naive_auth_credential(
            request
                .headers()
                .get(http::header::PROXY_AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            &runtime.credentials,
        ) else {
            send_h3_status(&mut stream, 407).await?;
            return Ok(());
        };
        Some(credential)
    };
    let session = naive_core_session(&runtime, credential.as_deref(), peer).await?;
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .context("build Naive HTTP/3 CONNECT response")?;
    stream
        .send_response(response)
        .await
        .context("send Naive HTTP/3 CONNECT response")?;
    let (send, recv) = stream.split();
    if uot::is_magic_target(&target) {
        ensure!(
            runtime.udp_over_tcp,
            "Naive HTTP/3 UDP-over-TCP is disabled by server config"
        );
        return relay_naive_http3_uot(send, recv, target, session).await;
    }
    let remote = connect_proxy_target(&target).await?;
    tracing::info!("Naive serving HTTP/3 {}", target_name(&target));
    relay_naive_http3_server_tcp(send, recv, remote, session).await
}

async fn read_naive_http1_connect(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
) -> Result<(ProxyTarget, Option<String>, Vec<u8>)> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .context("read Naive HTTP/1.1 CONNECT request")?;
        ensure!(read > 0, "Naive HTTP/1.1 client closed before request");
        request.extend_from_slice(&buffer[..read]);
        ensure!(
            request.len() <= 16 * 1024,
            "Naive HTTP/1.1 request header is too large"
        );
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&request[..end]);
            let mut lines = header.lines();
            let request_line = lines.next().context("Naive HTTP/1.1 request is empty")?;
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default();
            let authority = parts.next().unwrap_or_default();
            ensure!(
                method.eq_ignore_ascii_case("CONNECT"),
                "Naive HTTP/1.1 request is not CONNECT"
            );
            let mut authorization = None;
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    if name.trim().eq_ignore_ascii_case("proxy-authorization") {
                        authorization = Some(value.trim().to_string());
                    }
                }
            }
            return Ok((
                parse_authority(authority)?,
                authorization,
                request[end + 4..].to_vec(),
            ));
        }
    }
}

fn naive_request_target(method: &http::Method, uri: &http::Uri) -> Result<ProxyTarget> {
    ensure!(
        *method == http::Method::CONNECT,
        "Naive request is not CONNECT"
    );
    let authority = uri
        .authority()
        .map(http::uri::Authority::as_str)
        .or_else(|| {
            let path = uri.path();
            (!path.is_empty()).then_some(path)
        })
        .context("Naive CONNECT request has no authority")?;
    parse_authority(authority)
}

fn parse_authority(authority: &str) -> Result<ProxyTarget> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .with_context(|| format!("invalid Naive IPv6 authority {authority}"))?;
        let port = port
            .parse::<u16>()
            .with_context(|| format!("invalid Naive authority port {authority}"))?;
        let ip = host
            .parse::<IpAddr>()
            .with_context(|| format!("invalid Naive IPv6 authority {authority}"))?;
        return Ok(ProxyTarget::Ip(SocketAddr::new(ip, port)));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .with_context(|| format!("Naive authority is missing port: {authority}"))?;
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid Naive authority port {authority}"))?;
    Ok(host
        .parse::<IpAddr>()
        .map(|ip| ProxyTarget::Ip(SocketAddr::new(ip, port)))
        .unwrap_or_else(|_| ProxyTarget::Domain(host.to_string(), port)))
}

fn naive_credentials(username: &str, password: &str, users: &[String]) -> Vec<String> {
    std::iter::once(format!("{username}:{password}"))
        .chain(users.iter().cloned())
        .map(|credential| credential.trim().to_string())
        .filter(|credential| !credential.is_empty() && credential != ":")
        .collect()
}

fn naive_auth_credential(header: Option<&str>, credentials: &[String]) -> Option<String> {
    if credentials.is_empty() {
        return None;
    }
    let header = header.map(str::trim)?;
    credentials.iter().find_map(|credential| {
        (header == format!("Basic {}", base64_standard(credential.as_bytes())))
            .then(|| credential.clone())
    })
}

async fn naive_core_session(
    runtime: &NaiveServerRuntime,
    credential: Option<&str>,
    peer: SocketAddr,
) -> Result<Option<CoreSession>> {
    let Some(credential) = credential else {
        return Ok(None);
    };
    runtime
        .core
        .authenticate_from(credential, peer)
        .await
        .map(Some)
}

async fn record_naive_upload(session: &Option<CoreSession>, bytes: usize) -> Result<()> {
    if let Some(session) = session {
        session.record_upload(bytes).await?;
    }
    Ok(())
}

async fn record_naive_download(session: &Option<CoreSession>, bytes: usize) -> Result<()> {
    if let Some(session) = session {
        session.record_download(bytes).await?;
    }
    Ok(())
}

fn send_h2_status(respond: &mut h2::server::SendResponse<Bytes>, status: u16) -> Result<()> {
    let response = http::Response::builder()
        .status(status)
        .body(())
        .with_context(|| format!("build Naive HTTP/2 {status} response"))?;
    let mut send = respond
        .send_response(response, false)
        .with_context(|| format!("send Naive HTTP/2 {status} response"))?;
    send.send_data(Bytes::new(), true)
        .with_context(|| format!("finish Naive HTTP/2 {status} response"))?;
    Ok(())
}

async fn send_h3_status<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    status: u16,
) -> Result<()>
where
    S: h3::quic::SendStream<Bytes>,
{
    let response = http::Response::builder()
        .status(status)
        .body(())
        .with_context(|| format!("build Naive HTTP/3 {status} response"))?;
    stream
        .send_response(response)
        .await
        .with_context(|| format!("send Naive HTTP/3 {status} response"))?;
    stream
        .finish()
        .await
        .with_context(|| format!("finish Naive HTTP/3 {status} response"))?;
    Ok(())
}

async fn handle_naive_socks_client(mut local: TcpStream, config: NaiveClientConfig) -> Result<()> {
    match socks::read_request(&mut local).await? {
        socks::SocksRequest::Connect(target) => {
            let tunnel = match open_naive_tunnel(&config, &target).await {
                Ok(tunnel) => tunnel,
                Err(error) => {
                    let _ = socks::write_reply(&mut local, 0x01).await;
                    return Err(error);
                }
            };
            socks::write_reply(&mut local, 0x00).await?;
            tracing::info!("Naive proxying {}", target_name(&target));
            relay_naive_tcp(local, tunnel).await
        }
        socks::SocksRequest::UdpAssociate => {
            ensure!(
                config.udp_over_tcp,
                "Naive UDP requires udp_over_tcp/uot to be enabled"
            );
            handle_naive_udp_associate(local, config).await
        }
    }
}

async fn open_naive_tunnel(
    config: &NaiveClientConfig,
    target: &ProxyTarget,
) -> Result<NaiveTunnel> {
    if config.quic {
        return open_naive_http3_tunnel(config, target).await;
    }
    let tcp =
        socket_protect::connect_tcp_host_port(&config.server_host, config.server_port).await?;
    let server_name = rustls::pki_types::ServerName::try_from(config.sni.clone())
        .with_context(|| format!("invalid Naive TLS server name: {}", config.sni))?;
    let tls = tokio_rustls::TlsConnector::from(naive_tls_config(
        config,
        vec![NAIVE_H2_ALPN.to_vec(), NAIVE_HTTP11_ALPN.to_vec()],
    ))
    .connect(server_name, tcp)
    .await
    .context("connect Naive HTTPS proxy")?;
    if tls.get_ref().1.alpn_protocol() == Some(NAIVE_H2_ALPN) {
        return open_naive_http2_tunnel(config, target, tls).await;
    }
    open_naive_http1_tunnel(config, target, tls).await
}

fn naive_tls_config(config: &NaiveClientConfig, alpn: Vec<Vec<u8>>) -> Arc<rustls::ClientConfig> {
    let mut tls_config = Arc::unwrap_or_clone(tls::client_config(config.insecure));
    tls_config.alpn_protocols = alpn;
    Arc::new(tls_config)
}

async fn open_naive_http1_tunnel(
    config: &NaiveClientConfig,
    target: &ProxyTarget,
    mut tls: tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<NaiveTunnel> {
    let authority = target_name(target);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: XBClient\r\nPadding: {}\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n",
        naive_padding_header()?
    );
    if !config.username.is_empty() || !config.password.is_empty() {
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&base64_standard(
            format!("{}:{}", config.username, config.password).as_bytes(),
        ));
        request.push_str("\r\n");
    }
    for (key, value) in &config.extra_headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    tls.write_all(request.as_bytes())
        .await
        .context("write Naive HTTP/1.1 CONNECT request")?;

    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = tls
            .read(&mut buffer)
            .await
            .context("read Naive HTTP/1.1 CONNECT response")?;
        ensure!(read > 0, "Naive proxy closed before CONNECT response");
        response.extend_from_slice(&buffer[..read]);
        ensure!(
            response.len() <= 16 * 1024,
            "Naive CONNECT response header is too large"
        );
        if let Some(end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&response[..end]);
            let status = header
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default();
            ensure!(
                status == "200",
                "Naive CONNECT failed: {}",
                header.lines().next().unwrap_or("")
            );
            let pending = response[end + 4..].to_vec();
            return Ok(NaiveTunnel::Http1 {
                stream: tls,
                pending,
            });
        }
    }
}

async fn open_naive_http2_tunnel(
    config: &NaiveClientConfig,
    target: &ProxyTarget,
    tls: tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<NaiveTunnel> {
    let (mut client, connection) = h2::client::handshake(tls)
        .await
        .context("initialize Naive HTTP/2 client")?;
    let driver = tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!("Naive HTTP/2 connection exited: {error:?}");
        }
    });
    let request = naive_request_builder(config, target)?
        .body(())
        .context("build Naive HTTP/2 CONNECT request")?;
    let (response, send) = client
        .send_request(request, false)
        .context("send Naive HTTP/2 CONNECT request")?;
    let response = response
        .await
        .context("read Naive HTTP/2 CONNECT response")?;
    ensure!(
        response.status().as_u16() == 200,
        "Naive HTTP/2 CONNECT failed with HTTP {}",
        response.status()
    );
    Ok(NaiveTunnel::Http2 {
        send,
        recv: response.into_body(),
        driver,
    })
}

async fn open_naive_http3_tunnel(
    config: &NaiveClientConfig,
    target: &ProxyTarget,
) -> Result<NaiveTunnel> {
    let remote_addr = resolve_host_addr(&config.server_host, config.server_port).await?;
    let endpoint = build_naive_quic_endpoint(config, remote_addr.is_ipv6())?;
    let connection = endpoint
        .connect(remote_addr, &config.sni)
        .with_context(|| format!("connect Naive HTTP/3 server {remote_addr}"))?
        .await
        .context("complete Naive HTTP/3 QUIC handshake")?;
    let (mut h3_driver, mut sender) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .context("initialize Naive HTTP/3 client")?;
    let driver = tokio::spawn(async move {
        let error = h3_driver.wait_idle().await;
        tracing::debug!("Naive HTTP/3 client driver exited: {error:?}");
    });
    let request = naive_request_builder(config, target)?
        .body(())
        .context("build Naive HTTP/3 CONNECT request")?;
    let mut stream = sender
        .send_request(request)
        .await
        .context("send Naive HTTP/3 CONNECT request")?;
    let response = stream
        .recv_response()
        .await
        .context("read Naive HTTP/3 CONNECT response")?;
    ensure!(
        response.status().as_u16() == 200,
        "Naive HTTP/3 CONNECT failed with HTTP {}",
        response.status()
    );
    let (send, recv) = stream.split();
    Ok(NaiveTunnel::Http3 {
        send,
        recv,
        endpoint,
        connection,
        driver,
    })
}

fn naive_request_builder(
    config: &NaiveClientConfig,
    target: &ProxyTarget,
) -> Result<http::request::Builder> {
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(target_name(target))
        .header("user-agent", "XBClient")
        .header("padding", naive_padding_header()?);
    if !config.username.is_empty() || !config.password.is_empty() {
        builder = builder.header(
            "proxy-authorization",
            format!(
                "Basic {}",
                base64_standard(format!("{}:{}", config.username, config.password).as_bytes())
            ),
        );
    }
    for (key, value) in &config.extra_headers {
        builder = builder.header(
            http::HeaderName::from_bytes(key.as_bytes())
                .with_context(|| format!("invalid Naive extra header name: {key}"))?,
            http::HeaderValue::from_str(value)
                .with_context(|| format!("invalid Naive extra header value for {key}"))?,
        );
    }
    Ok(builder)
}

async fn resolve_host_addr(host: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve Naive QUIC peer {host}:{port}"))?
        .next()
        .with_context(|| format!("Naive QUIC peer resolved to no addresses: {host}:{port}"))
}

fn build_naive_quic_endpoint(
    config: &NaiveClientConfig,
    bind_ipv6: bool,
) -> Result<quinn::Endpoint> {
    let mut tls = Arc::unwrap_or_clone(tls::client_config(config.insecure));
    tls.alpn_protocols = vec![NAIVE_H3_ALPN.to_vec()];
    let quic_tls =
        QuicClientConfig::try_from(Arc::new(tls)).context("build Naive QUIC TLS client config")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    client_config.transport_config(Arc::new(naive_quic_transport_config(
        &config.quic_congestion_control,
    )?));
    let bind_addr = if bind_ipv6 { "[::]:0" } else { "0.0.0.0:0" }
        .parse()
        .context("build Naive QUIC bind address")?;
    let socket = socket_protect::bind_udp_std(bind_addr)?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("bind Naive QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn build_naive_server_endpoint(config: &NaiveServerConfig) -> Result<quinn::Endpoint> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            tls::load_certs(&config.cert_path)?,
            tls::load_key(&config.key_path)?,
        )
        .with_context(|| {
            format!(
                "build Naive HTTP/3 TLS server config with cert {} and key {}",
                config.cert_path.display(),
                config.key_path.display()
            )
        })?;
    tls_config.alpn_protocols = vec![NAIVE_H3_ALPN.to_vec()];
    let crypto =
        QuicServerConfig::try_from(tls_config).context("build Naive QUIC TLS server config")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(naive_quic_transport_config(
        &config.quic_congestion_control,
    )?));
    let socket = socket_protect::bind_udp_std(config.listen)?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("bind Naive HTTP/3 server endpoint")
}

fn naive_quic_transport_config(congestion_control: &str) -> Result<quinn::TransportConfig> {
    let idle_timeout = quinn::IdleTimeout::try_from(NAIVE_QUIC_IDLE_TIMEOUT)
        .context("build Naive H3 idle timeout")?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(idle_timeout));
    transport.congestion_controller_factory(
        match congestion_control.trim().to_ascii_lowercase().as_str() {
            "" | "bbr" => Arc::new(quinn::congestion::BbrConfig::default()),
            "cubic" => Arc::new(quinn::congestion::CubicConfig::default()),
            "reno" | "newreno" | "new_reno" => {
                Arc::new(quinn::congestion::NewRenoConfig::default())
            }
            other => bail!("unsupported Naive quic_congestion_control {other}"),
        },
    );
    Ok(transport)
}

async fn relay_naive_http1_server_tcp(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    mut pending: Vec<u8>,
    remote: TcpStream,
    session: Option<CoreSession>,
) -> Result<()> {
    let (mut inbound_reader, mut inbound_writer) = tokio::io::split(stream);
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let upload = async {
        let mut state = NaiveReadState::default();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read =
                read_naive_h1_data(&mut inbound_reader, &mut pending, &mut state, &mut buffer)
                    .await?;
            if read == 0 {
                remote_writer
                    .shutdown()
                    .await
                    .context("shutdown Naive HTTP/1.1 upstream writer")?;
                return Ok::<(), anyhow::Error>(());
            }
            record_naive_upload(&session, read).await?;
            remote_writer
                .write_all(&buffer[..read])
                .await
                .context("write Naive HTTP/1.1 upstream payload")?;
        }
    };
    let download = async {
        let mut state = NaiveWriteState::default();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = remote_reader
                .read(&mut buffer)
                .await
                .context("read Naive HTTP/1.1 upstream response")?;
            if read == 0 {
                inbound_writer
                    .shutdown()
                    .await
                    .context("shutdown Naive HTTP/1.1 downstream writer")?;
                return Ok::<(), anyhow::Error>(());
            }
            record_naive_download(&session, read).await?;
            write_naive_h1_data(&mut inbound_writer, &mut state, &buffer[..read]).await?;
        }
    };
    let _ = tokio::try_join!(upload, download)?;
    Ok(())
}

async fn relay_naive_http2_server_tcp(
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    remote: TcpStream,
    session: Option<CoreSession>,
) -> Result<()> {
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let upload = async {
        let mut state = NaiveReadState::default();
        let mut pending = Vec::new();
        let mut flow = recv.flow_control().clone();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read =
                read_naive_h2_data(&mut recv, &mut flow, &mut pending, &mut state, &mut buffer)
                    .await?;
            if read == 0 {
                remote_writer
                    .shutdown()
                    .await
                    .context("shutdown Naive HTTP/2 upstream writer")?;
                return Ok::<(), anyhow::Error>(());
            }
            record_naive_upload(&session, read).await?;
            remote_writer
                .write_all(&buffer[..read])
                .await
                .context("write Naive HTTP/2 upstream payload")?;
        }
    };
    let download = async {
        let mut state = NaiveWriteState::default();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = remote_reader
                .read(&mut buffer)
                .await
                .context("read Naive HTTP/2 upstream response")?;
            if read == 0 {
                send.send_data(Bytes::new(), true)
                    .context("finish Naive HTTP/2 response body")?;
                return Ok::<(), anyhow::Error>(());
            }
            record_naive_download(&session, read).await?;
            send_naive_h2_data(&mut send, &mut state, &buffer[..read]).await?;
        }
    };
    let _ = tokio::try_join!(upload, download)?;
    Ok(())
}

async fn relay_naive_http3_server_tcp<S1, S2>(
    mut send: h3::server::RequestStream<S1, Bytes>,
    mut recv: h3::server::RequestStream<S2, Bytes>,
    remote: TcpStream,
    session: Option<CoreSession>,
) -> Result<()>
where
    S1: h3::quic::SendStream<Bytes>,
    S2: h3::quic::RecvStream,
{
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let upload = async {
        let mut state = NaiveReadState::default();
        let mut pending = Vec::new();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read =
                read_naive_h3_server_data(&mut recv, &mut pending, &mut state, &mut buffer).await?;
            if read == 0 {
                remote_writer
                    .shutdown()
                    .await
                    .context("shutdown Naive HTTP/3 upstream writer")?;
                return Ok::<(), anyhow::Error>(());
            }
            record_naive_upload(&session, read).await?;
            remote_writer
                .write_all(&buffer[..read])
                .await
                .context("write Naive HTTP/3 upstream payload")?;
        }
    };
    let download = async {
        let mut state = NaiveWriteState::default();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = remote_reader
                .read(&mut buffer)
                .await
                .context("read Naive HTTP/3 upstream response")?;
            if read == 0 {
                send.finish()
                    .await
                    .context("finish Naive HTTP/3 response body")?;
                return Ok::<(), anyhow::Error>(());
            }
            record_naive_download(&session, read).await?;
            send_naive_h3_server_data(&mut send, &mut state, &buffer[..read]).await?;
        }
    };
    let _ = tokio::try_join!(upload, download)?;
    Ok(())
}

async fn relay_naive_http1_uot(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    pending: Vec<u8>,
    target: ProxyTarget,
    session: Option<CoreSession>,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut read_state = NaiveReadState::default();
    let mut naive_pending = pending;
    let (request, mut raw_pending) =
        read_uot_request_h1(&mut reader, &mut naive_pending, &mut read_state, &target).await?;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
    let writer_task = tokio::spawn(async move {
        let mut write_state = NaiveWriteState::default();
        while let Some(packet) = rx.recv().await {
            write_naive_h1_data(&mut writer, &mut write_state, &packet).await?;
        }
        writer
            .shutdown()
            .await
            .context("shutdown Naive HTTP/1.1 UOT writer")?;
        Ok::<(), anyhow::Error>(())
    });
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        while let Some((destination, payload, connected)) =
            take_uot_stream_packet(&request, &mut raw_pending)?
        {
            let tx = tx.clone();
            let session = session.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    relay_naive_uot_packet(tx, destination, payload, connected, session).await
                {
                    tracing::warn!("Naive HTTP/1.1 UOT packet failed: {error:?}");
                }
            });
        }
        let read = read_naive_h1_data(
            &mut reader,
            &mut naive_pending,
            &mut read_state,
            &mut buffer,
        )
        .await?;
        if read == 0 {
            drop(tx);
            writer_task
                .await
                .context("join Naive HTTP/1.1 UOT writer")??;
            return Ok(());
        }
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

async fn relay_naive_http2_uot(
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
    target: ProxyTarget,
    session: Option<CoreSession>,
) -> Result<()> {
    let mut read_state = NaiveReadState::default();
    let mut naive_pending = Vec::new();
    let mut flow = recv.flow_control().clone();
    let (request, mut raw_pending) = read_uot_request_h2(
        &mut recv,
        &mut flow,
        &mut naive_pending,
        &mut read_state,
        &target,
    )
    .await?;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
    let writer_task = tokio::spawn(async move {
        let mut write_state = NaiveWriteState::default();
        while let Some(packet) = rx.recv().await {
            send_naive_h2_data(&mut send, &mut write_state, &packet).await?;
        }
        send.send_data(Bytes::new(), true)
            .context("finish Naive HTTP/2 UOT response")?;
        Ok::<(), anyhow::Error>(())
    });
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        while let Some((destination, payload, connected)) =
            take_uot_stream_packet(&request, &mut raw_pending)?
        {
            let tx = tx.clone();
            let session = session.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    relay_naive_uot_packet(tx, destination, payload, connected, session).await
                {
                    tracing::warn!("Naive HTTP/2 UOT packet failed: {error:?}");
                }
            });
        }
        let read = read_naive_h2_data(
            &mut recv,
            &mut flow,
            &mut naive_pending,
            &mut read_state,
            &mut buffer,
        )
        .await?;
        if read == 0 {
            drop(tx);
            writer_task
                .await
                .context("join Naive HTTP/2 UOT writer")??;
            return Ok(());
        }
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

async fn relay_naive_http3_uot<S1, S2>(
    mut send: h3::server::RequestStream<S1, Bytes>,
    mut recv: h3::server::RequestStream<S2, Bytes>,
    target: ProxyTarget,
    session: Option<CoreSession>,
) -> Result<()>
where
    S1: h3::quic::SendStream<Bytes> + Send + 'static,
    S2: h3::quic::RecvStream,
{
    let mut read_state = NaiveReadState::default();
    let mut naive_pending = Vec::new();
    let (request, mut raw_pending) =
        read_uot_request_h3(&mut recv, &mut naive_pending, &mut read_state, &target).await?;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(32);
    let writer_task = tokio::spawn(async move {
        let mut write_state = NaiveWriteState::default();
        while let Some(packet) = rx.recv().await {
            send_naive_h3_server_data(&mut send, &mut write_state, &packet).await?;
        }
        send.finish()
            .await
            .context("finish Naive HTTP/3 UOT response")?;
        Ok::<(), anyhow::Error>(())
    });
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        while let Some((destination, payload, connected)) =
            take_uot_stream_packet(&request, &mut raw_pending)?
        {
            let tx = tx.clone();
            let session = session.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    relay_naive_uot_packet(tx, destination, payload, connected, session).await
                {
                    tracing::warn!("Naive HTTP/3 UOT packet failed: {error:?}");
                }
            });
        }
        let read =
            read_naive_h3_server_data(&mut recv, &mut naive_pending, &mut read_state, &mut buffer)
                .await?;
        if read == 0 {
            drop(tx);
            writer_task
                .await
                .context("join Naive HTTP/3 UOT writer")??;
            return Ok(());
        }
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

async fn read_uot_request_h1<R>(
    reader: &mut R,
    naive_pending: &mut Vec<u8>,
    read_state: &mut NaiveReadState,
    target: &ProxyTarget,
) -> Result<(uot::UotRequest, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    if uot::is_legacy_magic_target(target) {
        return Ok((legacy_uot_request(), Vec::new()));
    }
    let mut raw_pending = Vec::new();
    let mut buffer = vec![0u8; 1024];
    loop {
        if let Some(request) = take_uot_request(&mut raw_pending)? {
            return Ok((request, raw_pending));
        }
        let read = read_naive_h1_data(reader, naive_pending, read_state, &mut buffer).await?;
        ensure!(read > 0, "Naive HTTP/1.1 UOT stream closed before request");
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

async fn read_uot_request_h2(
    recv: &mut h2::RecvStream,
    flow: &mut h2::FlowControl,
    naive_pending: &mut Vec<u8>,
    read_state: &mut NaiveReadState,
    target: &ProxyTarget,
) -> Result<(uot::UotRequest, Vec<u8>)> {
    if uot::is_legacy_magic_target(target) {
        return Ok((legacy_uot_request(), Vec::new()));
    }
    let mut raw_pending = Vec::new();
    let mut buffer = vec![0u8; 1024];
    loop {
        if let Some(request) = take_uot_request(&mut raw_pending)? {
            return Ok((request, raw_pending));
        }
        let read = read_naive_h2_data(recv, flow, naive_pending, read_state, &mut buffer).await?;
        ensure!(read > 0, "Naive HTTP/2 UOT stream closed before request");
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

async fn read_uot_request_h3<S>(
    recv: &mut h3::server::RequestStream<S, Bytes>,
    naive_pending: &mut Vec<u8>,
    read_state: &mut NaiveReadState,
    target: &ProxyTarget,
) -> Result<(uot::UotRequest, Vec<u8>)>
where
    S: h3::quic::RecvStream,
{
    if uot::is_legacy_magic_target(target) {
        return Ok((legacy_uot_request(), Vec::new()));
    }
    let mut raw_pending = Vec::new();
    let mut buffer = vec![0u8; 1024];
    loop {
        if let Some(request) = take_uot_request(&mut raw_pending)? {
            return Ok((request, raw_pending));
        }
        let read = read_naive_h3_server_data(recv, naive_pending, read_state, &mut buffer).await?;
        ensure!(read > 0, "Naive HTTP/3 UOT stream closed before request");
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

fn take_uot_request(pending: &mut Vec<u8>) -> Result<Option<uot::UotRequest>> {
    let Some(length) = uot_request_len(pending)? else {
        return Ok(None);
    };
    if pending.len() < length {
        return Ok(None);
    }
    let request = uot::decode_v2_request(&pending[..length])?;
    pending.drain(..length);
    Ok(Some(request))
}

fn uot_request_len(packet: &[u8]) -> Result<Option<usize>> {
    if packet.len() < 2 {
        return Ok(None);
    }
    let address_offset = 1;
    match packet[address_offset] {
        0x01 => Ok(Some(address_offset + 7)),
        0x04 => Ok(Some(address_offset + 19)),
        0x03 => {
            if packet.len() < address_offset + 2 {
                return Ok(None);
            }
            Ok(Some(
                address_offset + 2 + packet[address_offset + 1] as usize + 2,
            ))
        }
        other => bail!("unsupported Naive UOT request address type: {other}"),
    }
}

fn take_uot_stream_packet(
    request: &uot::UotRequest,
    pending: &mut Vec<u8>,
) -> Result<Option<(ProxyTarget, Vec<u8>, bool)>> {
    if request.is_connect {
        let Some(length) = uot_connect_packet_len(pending)? else {
            return Ok(None);
        };
        if pending.len() < length {
            return Ok(None);
        }
        let payload = uot::decode_connect_packet(&pending[..length])?.to_vec();
        pending.drain(..length);
        return Ok(Some((request.destination.clone(), payload, true)));
    }
    let Some(packet) = take_next_uot_packet(pending)? else {
        return Ok(None);
    };
    let (destination, payload) = uot::decode_associate_packet(&packet)?;
    Ok(Some((destination, payload.to_vec(), false)))
}

fn uot_connect_packet_len(packet: &[u8]) -> Result<Option<usize>> {
    if packet.len() < 2 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([packet[0], packet[1]]) as usize;
    Ok(Some(2 + payload_len))
}

fn legacy_uot_request() -> uot::UotRequest {
    uot::UotRequest {
        is_connect: false,
        destination: ProxyTarget::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
    }
}

async fn relay_naive_uot_packet(
    tx: mpsc::Sender<Vec<u8>>,
    destination: ProxyTarget,
    payload: Vec<u8>,
    connected: bool,
    session: Option<CoreSession>,
) -> Result<()> {
    let target_addr = resolve_proxy_target_addr(&destination).await?;
    let bind_addr = if target_addr.is_ipv6() {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let outbound = socket_protect::bind_udp(bind_addr).await?;
    record_naive_upload(&session, payload.len()).await?;
    outbound
        .send_to(&payload, target_addr)
        .await
        .with_context(|| format!("send Naive UOT payload to {target_addr}"))?;
    let mut buffer = vec![0u8; u16::MAX as usize];
    while let Ok(read) =
        tokio::time::timeout(NAIVE_UDP_SESSION_TIMEOUT, outbound.recv_from(&mut buffer)).await
    {
        let (read, _) = read.context("receive Naive UOT response")?;
        record_naive_download(&session, read).await?;
        let packet = if connected {
            uot::encode_connect_packet(&buffer[..read])?
        } else {
            uot::encode_associate_packet(&destination, &buffer[..read])?
        };
        if tx.send(packet).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

async fn connect_proxy_target(target: &ProxyTarget) -> Result<TcpStream> {
    match target {
        ProxyTarget::Ip(addr) => socket_protect::connect_tcp_addr(*addr).await,
        ProxyTarget::Domain(host, port) => socket_protect::connect_tcp_host_port(host, *port).await,
    }
}

async fn resolve_proxy_target_addr(target: &ProxyTarget) -> Result<SocketAddr> {
    match target {
        ProxyTarget::Ip(addr) => Ok(*addr),
        ProxyTarget::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .with_context(|| format!("resolve Naive UOT target {host}:{port}"))?
            .next()
            .with_context(|| format!("Naive UOT target resolved to no addresses: {host}:{port}")),
    }
}

async fn relay_naive_tcp(local: TcpStream, tunnel: NaiveTunnel) -> Result<()> {
    match tunnel {
        NaiveTunnel::Http1 { stream, pending } => {
            relay_naive_http1_tcp(local, stream, pending).await
        }
        NaiveTunnel::Http2 { send, recv, driver } => {
            let result = relay_naive_http2_tcp(local, send, recv).await;
            driver.abort();
            result
        }
        NaiveTunnel::Http3 {
            send,
            recv,
            endpoint,
            connection,
            driver,
        } => {
            let _endpoint = endpoint;
            let result = relay_naive_http3_tcp(local, send, recv).await;
            connection.close(quinn::VarInt::from_u32(0), b"client closed");
            driver.abort();
            result
        }
    }
}

async fn relay_naive_http1_tcp(
    local: TcpStream,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    pending: Vec<u8>,
) -> Result<()> {
    let (mut local_reader, mut local_writer) = local.into_split();
    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    let upload = async {
        let mut state = NaiveWriteState::default();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read local Naive TCP payload")?;
            if read == 0 {
                remote_writer
                    .shutdown()
                    .await
                    .context("shutdown Naive HTTP/1.1 upload")?;
                return Ok::<(), anyhow::Error>(());
            }
            write_naive_h1_data(&mut remote_writer, &mut state, &buffer[..read]).await?;
        }
    };
    let download = async {
        let mut state = NaiveReadState::default();
        let mut pending = pending;
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read =
                read_naive_h1_data(&mut remote_reader, &mut pending, &mut state, &mut buffer)
                    .await?;
            if read == 0 {
                local_writer
                    .shutdown()
                    .await
                    .context("shutdown local Naive TCP writer")?;
                return Ok::<(), anyhow::Error>(());
            }
            local_writer
                .write_all(&buffer[..read])
                .await
                .context("write local Naive TCP payload")?;
        }
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn relay_naive_http2_tcp(
    local: TcpStream,
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
) -> Result<()> {
    let (mut local_reader, mut local_writer) = local.into_split();
    let upload = async {
        let mut state = NaiveWriteState::default();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read local Naive HTTP/2 payload")?;
            if read == 0 {
                send.send_data(Bytes::new(), true)
                    .context("finish Naive HTTP/2 request body")?;
                return Ok::<(), anyhow::Error>(());
            }
            send_naive_h2_data(&mut send, &mut state, &buffer[..read]).await?;
        }
    };
    let download = async {
        let mut state = NaiveReadState::default();
        let mut pending = Vec::new();
        let mut flow = recv.flow_control().clone();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read =
                read_naive_h2_data(&mut recv, &mut flow, &mut pending, &mut state, &mut buffer)
                    .await?;
            if read == 0 {
                local_writer
                    .shutdown()
                    .await
                    .context("shutdown local Naive HTTP/2 writer")?;
                return Ok::<(), anyhow::Error>(());
            }
            local_writer
                .write_all(&buffer[..read])
                .await
                .context("write local Naive HTTP/2 payload")?;
        }
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn relay_naive_http3_tcp(
    local: TcpStream,
    mut send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
) -> Result<()> {
    let (mut local_reader, mut local_writer) = local.into_split();
    let upload = async {
        let mut state = NaiveWriteState::default();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = local_reader
                .read(&mut buffer)
                .await
                .context("read local Naive HTTP/3 payload")?;
            if read == 0 {
                send.finish()
                    .await
                    .context("finish Naive HTTP/3 request body")?;
                return Ok::<(), anyhow::Error>(());
            }
            send_naive_h3_data(&mut send, &mut state, &buffer[..read]).await?;
        }
    };
    let download = async {
        let mut state = NaiveReadState::default();
        let mut pending = Vec::new();
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let read = read_naive_h3_data(&mut recv, &mut pending, &mut state, &mut buffer).await?;
            if read == 0 {
                local_writer
                    .shutdown()
                    .await
                    .context("shutdown local Naive HTTP/3 writer")?;
                return Ok::<(), anyhow::Error>(());
            }
            local_writer
                .write_all(&buffer[..read])
                .await
                .context("write local Naive HTTP/3 payload")?;
        }
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn handle_naive_udp_associate(
    mut control: TcpStream,
    config: NaiveClientConfig,
) -> Result<()> {
    let bind_ip = match control.local_addr()?.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ip => ip,
    };
    let udp = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .with_context(|| format!("bind Naive SOCKS UDP associate socket on {bind_ip}:0"))?,
    );
    socks::write_reply_with_bind(&mut control, 0x00, udp.local_addr()?).await?;
    let tunnel = open_naive_tunnel(&config, &uot::magic_target()).await?;
    match tunnel {
        NaiveTunnel::Http1 { stream, pending } => {
            handle_naive_udp_h1(control, udp, stream, pending).await
        }
        NaiveTunnel::Http2 { send, recv, driver } => {
            let result = handle_naive_udp_h2(control, udp, send, recv).await;
            driver.abort();
            result
        }
        NaiveTunnel::Http3 {
            send,
            recv,
            endpoint,
            connection,
            driver,
        } => {
            let _endpoint = endpoint;
            let result = handle_naive_udp_h3(control, udp, send, recv).await;
            connection.close(quinn::VarInt::from_u32(0), b"client closed");
            driver.abort();
            result
        }
    }
}

async fn handle_naive_udp_h1(
    mut control: TcpStream,
    udp: Arc<UdpSocket>,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    pending: Vec<u8>,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut write_state = NaiveWriteState::default();
    write_naive_h1_data(
        &mut writer,
        &mut write_state,
        &uot::encode_v2_associate_request()?,
    )
    .await?;
    let (client_tx, mut client_rx) = mpsc::channel::<SocketAddr>(8);
    let udp_to_stream = {
        let udp = udp.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive Naive SOCKS UDP packet")?;
                let _ = client_tx.try_send(peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let packet = uot::encode_associate_packet(&target, payload)?;
                write_naive_h1_data(&mut writer, &mut write_state, &packet).await?;
            }
        }
    };
    let stream_to_udp = {
        let udp = udp.clone();
        async move {
            let mut naive_pending = pending;
            let mut raw_pending = Vec::new();
            let mut read_state = NaiveReadState::default();
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => if let Some(next_peer) = next_peer { peer = Some(next_peer); },
                    packet = read_next_uot_packet_h1(&mut reader, &mut naive_pending, &mut read_state, &mut raw_pending) => {
                        let Some(packet) = packet? else { return Ok::<(), anyhow::Error>(()); };
                        let (source, payload) = uot::decode_associate_packet(&packet)?;
                        let response = uot::encode_socks_udp_packet(&source, payload)?;
                        let peer = peer.context("Naive SOCKS UDP peer is not known yet")?;
                        udp.send_to(&response, peer)
                            .await
                            .with_context(|| format!("send Naive SOCKS UDP response to {peer}"))?;
                    }
                }
            }
        }
    };
    let control_closed = control_closed(&mut control);
    tokio::select! {
        result = udp_to_stream => result,
        result = stream_to_udp => result,
        result = control_closed => result,
    }
}

async fn handle_naive_udp_h2(
    mut control: TcpStream,
    udp: Arc<UdpSocket>,
    mut send: h2::SendStream<Bytes>,
    mut recv: h2::RecvStream,
) -> Result<()> {
    let mut write_state = NaiveWriteState::default();
    send_naive_h2_data(
        &mut send,
        &mut write_state,
        &uot::encode_v2_associate_request()?,
    )
    .await?;
    let (client_tx, mut client_rx) = mpsc::channel::<SocketAddr>(8);
    let udp_to_stream = {
        let udp = udp.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive Naive HTTP/2 SOCKS UDP packet")?;
                let _ = client_tx.try_send(peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let packet = uot::encode_associate_packet(&target, payload)?;
                send_naive_h2_data(&mut send, &mut write_state, &packet).await?;
            }
        }
    };
    let stream_to_udp = {
        let udp = udp.clone();
        async move {
            let mut naive_pending = Vec::new();
            let mut raw_pending = Vec::new();
            let mut read_state = NaiveReadState::default();
            let mut flow = recv.flow_control().clone();
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => if let Some(next_peer) = next_peer { peer = Some(next_peer); },
                    packet = read_next_uot_packet_h2(&mut recv, &mut flow, &mut naive_pending, &mut read_state, &mut raw_pending) => {
                        let Some(packet) = packet? else { return Ok::<(), anyhow::Error>(()); };
                        let (source, payload) = uot::decode_associate_packet(&packet)?;
                        let response = uot::encode_socks_udp_packet(&source, payload)?;
                        let peer = peer.context("Naive HTTP/2 SOCKS UDP peer is not known yet")?;
                        udp.send_to(&response, peer)
                            .await
                            .with_context(|| format!("send Naive HTTP/2 SOCKS UDP response to {peer}"))?;
                    }
                }
            }
        }
    };
    let control_closed = control_closed(&mut control);
    tokio::select! {
        result = udp_to_stream => result,
        result = stream_to_udp => result,
        result = control_closed => result,
    }
}

async fn handle_naive_udp_h3(
    mut control: TcpStream,
    udp: Arc<UdpSocket>,
    mut send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
) -> Result<()> {
    let mut write_state = NaiveWriteState::default();
    send_naive_h3_data(
        &mut send,
        &mut write_state,
        &uot::encode_v2_associate_request()?,
    )
    .await?;
    let (client_tx, mut client_rx) = mpsc::channel::<SocketAddr>(8);
    let udp_to_stream = {
        let udp = udp.clone();
        async move {
            let mut buffer = vec![0u8; u16::MAX as usize + 32];
            loop {
                let (read, peer) = udp
                    .recv_from(&mut buffer)
                    .await
                    .context("receive Naive HTTP/3 SOCKS UDP packet")?;
                let _ = client_tx.try_send(peer);
                let (target, payload) = uot::parse_socks_udp_packet(&buffer[..read])?;
                let packet = uot::encode_associate_packet(&target, payload)?;
                send_naive_h3_data(&mut send, &mut write_state, &packet).await?;
            }
        }
    };
    let stream_to_udp = {
        let udp = udp.clone();
        async move {
            let mut naive_pending = Vec::new();
            let mut raw_pending = Vec::new();
            let mut read_state = NaiveReadState::default();
            let mut peer = None;
            loop {
                tokio::select! {
                    next_peer = client_rx.recv() => if let Some(next_peer) = next_peer { peer = Some(next_peer); },
                    packet = read_next_uot_packet_h3(&mut recv, &mut naive_pending, &mut read_state, &mut raw_pending) => {
                        let Some(packet) = packet? else { return Ok::<(), anyhow::Error>(()); };
                        let (source, payload) = uot::decode_associate_packet(&packet)?;
                        let response = uot::encode_socks_udp_packet(&source, payload)?;
                        let peer = peer.context("Naive HTTP/3 SOCKS UDP peer is not known yet")?;
                        udp.send_to(&response, peer)
                            .await
                            .with_context(|| format!("send Naive HTTP/3 SOCKS UDP response to {peer}"))?;
                    }
                }
            }
        }
    };
    let control_closed = control_closed(&mut control);
    tokio::select! {
        result = udp_to_stream => result,
        result = stream_to_udp => result,
        result = control_closed => result,
    }
}

async fn control_closed(control: &mut TcpStream) -> Result<()> {
    let mut buffer = [0u8; 1];
    loop {
        if control
            .read(&mut buffer)
            .await
            .context("read Naive SOCKS UDP control connection")?
            == 0
        {
            return Ok(());
        }
    }
}

async fn write_naive_h1_data<W>(
    writer: &mut W,
    state: &mut NaiveWriteState,
    data: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    for chunk in encode_naive_chunks(state, data)? {
        writer
            .write_all(&chunk)
            .await
            .context("write Naive padded data")?;
    }
    writer.flush().await.context("flush Naive padded data")
}

async fn send_naive_h2_data(
    send: &mut h2::SendStream<Bytes>,
    state: &mut NaiveWriteState,
    data: &[u8],
) -> Result<()> {
    for chunk in encode_naive_chunks(state, data)? {
        send.send_data(Bytes::from(chunk), false)
            .context("send Naive HTTP/2 padded data")?;
    }
    Ok(())
}

async fn send_naive_h3_data(
    send: &mut h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    state: &mut NaiveWriteState,
    data: &[u8],
) -> Result<()> {
    for chunk in encode_naive_chunks(state, data)? {
        send.send_data(Bytes::from(chunk))
            .await
            .context("send Naive HTTP/3 padded data")?;
    }
    Ok(())
}

async fn send_naive_h3_server_data<S>(
    send: &mut h3::server::RequestStream<S, Bytes>,
    state: &mut NaiveWriteState,
    data: &[u8],
) -> Result<()>
where
    S: h3::quic::SendStream<Bytes>,
{
    for chunk in encode_naive_chunks(state, data)? {
        send.send_data(Bytes::from(chunk))
            .await
            .context("send Naive HTTP/3 server padded data")?;
    }
    Ok(())
}

fn encode_naive_chunks(state: &mut NaiveWriteState, data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut chunks = Vec::new();
    for chunk in data.chunks(NAIVE_MAX_CHUNK) {
        if state.write_padding < NAIVE_PADDING_COUNT {
            let padding_size = random_byte()? as usize;
            let mut encoded = Vec::with_capacity(3 + chunk.len() + padding_size);
            encoded.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            encoded.push(padding_size as u8);
            encoded.extend_from_slice(chunk);
            encoded.resize(encoded.len() + padding_size, 0);
            state.write_padding += 1;
            chunks.push(encoded);
        } else {
            chunks.push(chunk.to_vec());
        }
    }
    Ok(chunks)
}

async fn read_naive_h1_data<R>(
    reader: &mut R,
    pending: &mut Vec<u8>,
    state: &mut NaiveReadState,
    buffer: &mut [u8],
) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    if state.read_remaining > 0 {
        let take = state.read_remaining.min(buffer.len());
        let read = read_raw_h1_some(reader, pending, &mut buffer[..take]).await?;
        state.read_remaining -= read;
        return Ok(read);
    }
    if state.padding_remaining > 0 {
        read_raw_h1_exact(reader, pending, state.padding_remaining).await?;
        state.padding_remaining = 0;
    }
    if state.read_padding < NAIVE_PADDING_COUNT {
        let header = read_raw_h1_exact(reader, pending, 3).await?;
        let data_size = u16::from_be_bytes([header[0], header[1]]) as usize;
        let padding_size = header[2] as usize;
        let take = data_size.min(buffer.len());
        let read = read_raw_h1_some(reader, pending, &mut buffer[..take]).await?;
        state.read_padding += 1;
        state.read_remaining = data_size - read;
        state.padding_remaining = padding_size;
        return Ok(read);
    }
    read_raw_h1_some(reader, pending, buffer).await
}

async fn read_raw_h1_some<R>(
    reader: &mut R,
    pending: &mut Vec<u8>,
    buffer: &mut [u8],
) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    if !pending.is_empty() {
        let take = pending.len().min(buffer.len());
        buffer[..take].copy_from_slice(&pending[..take]);
        pending.drain(..take);
        return Ok(take);
    }
    reader
        .read(buffer)
        .await
        .context("read Naive HTTP/1.1 data")
}

async fn read_raw_h1_exact<R>(reader: &mut R, pending: &mut Vec<u8>, size: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(size);
    if !pending.is_empty() {
        let take = pending.len().min(size);
        output.extend_from_slice(&pending[..take]);
        pending.drain(..take);
    }
    if output.len() < size {
        let old_len = output.len();
        output.resize(size, 0);
        reader
            .read_exact(&mut output[old_len..])
            .await
            .context("read exact Naive HTTP/1.1 data")?;
    }
    Ok(output)
}

async fn read_naive_h2_data(
    recv: &mut h2::RecvStream,
    flow: &mut h2::FlowControl,
    pending: &mut Vec<u8>,
    state: &mut NaiveReadState,
    buffer: &mut [u8],
) -> Result<usize> {
    if state.read_remaining > 0 {
        let take = state.read_remaining.min(buffer.len());
        let read = read_raw_h2_some(recv, flow, pending, &mut buffer[..take]).await?;
        state.read_remaining -= read;
        return Ok(read);
    }
    if state.padding_remaining > 0 {
        read_raw_h2_exact(recv, flow, pending, state.padding_remaining).await?;
        state.padding_remaining = 0;
    }
    if state.read_padding < NAIVE_PADDING_COUNT {
        let header = read_raw_h2_exact(recv, flow, pending, 3).await?;
        let data_size = u16::from_be_bytes([header[0], header[1]]) as usize;
        let padding_size = header[2] as usize;
        let take = data_size.min(buffer.len());
        let read = read_raw_h2_some(recv, flow, pending, &mut buffer[..take]).await?;
        state.read_padding += 1;
        state.read_remaining = data_size - read;
        state.padding_remaining = padding_size;
        return Ok(read);
    }
    read_raw_h2_some(recv, flow, pending, buffer).await
}

async fn read_raw_h2_some(
    recv: &mut h2::RecvStream,
    flow: &mut h2::FlowControl,
    pending: &mut Vec<u8>,
    buffer: &mut [u8],
) -> Result<usize> {
    if pending.is_empty() && !pull_h2_data(recv, flow, pending).await? {
        return Ok(0);
    }
    let take = pending.len().min(buffer.len());
    buffer[..take].copy_from_slice(&pending[..take]);
    pending.drain(..take);
    Ok(take)
}

async fn read_raw_h2_exact(
    recv: &mut h2::RecvStream,
    flow: &mut h2::FlowControl,
    pending: &mut Vec<u8>,
    size: usize,
) -> Result<Vec<u8>> {
    while pending.len() < size {
        ensure!(
            pull_h2_data(recv, flow, pending).await?,
            "Naive HTTP/2 stream closed early"
        );
    }
    let output = pending[..size].to_vec();
    pending.drain(..size);
    Ok(output)
}

async fn pull_h2_data(
    recv: &mut h2::RecvStream,
    flow: &mut h2::FlowControl,
    pending: &mut Vec<u8>,
) -> Result<bool> {
    let Some(chunk) = recv.data().await else {
        return Ok(false);
    };
    let chunk = chunk.context("read Naive HTTP/2 data")?;
    flow.release_capacity(chunk.len())
        .context("release Naive HTTP/2 receive capacity")?;
    pending.extend_from_slice(&chunk);
    Ok(true)
}

async fn read_naive_h3_data(
    recv: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    pending: &mut Vec<u8>,
    state: &mut NaiveReadState,
    buffer: &mut [u8],
) -> Result<usize> {
    if state.read_remaining > 0 {
        let take = state.read_remaining.min(buffer.len());
        let read = read_raw_h3_some(recv, pending, &mut buffer[..take]).await?;
        state.read_remaining -= read;
        return Ok(read);
    }
    if state.padding_remaining > 0 {
        read_raw_h3_exact(recv, pending, state.padding_remaining).await?;
        state.padding_remaining = 0;
    }
    if state.read_padding < NAIVE_PADDING_COUNT {
        let header = read_raw_h3_exact(recv, pending, 3).await?;
        let data_size = u16::from_be_bytes([header[0], header[1]]) as usize;
        let padding_size = header[2] as usize;
        let take = data_size.min(buffer.len());
        let read = read_raw_h3_some(recv, pending, &mut buffer[..take]).await?;
        state.read_padding += 1;
        state.read_remaining = data_size - read;
        state.padding_remaining = padding_size;
        return Ok(read);
    }
    read_raw_h3_some(recv, pending, buffer).await
}

async fn read_raw_h3_some(
    recv: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    pending: &mut Vec<u8>,
    buffer: &mut [u8],
) -> Result<usize> {
    if pending.is_empty() && !pull_h3_data(recv, pending).await? {
        return Ok(0);
    }
    let take = pending.len().min(buffer.len());
    buffer[..take].copy_from_slice(&pending[..take]);
    pending.drain(..take);
    Ok(take)
}

async fn read_raw_h3_exact(
    recv: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    pending: &mut Vec<u8>,
    size: usize,
) -> Result<Vec<u8>> {
    while pending.len() < size {
        ensure!(
            pull_h3_data(recv, pending).await?,
            "Naive HTTP/3 stream closed early"
        );
    }
    let output = pending[..size].to_vec();
    pending.drain(..size);
    Ok(output)
}

async fn pull_h3_data(
    recv: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    pending: &mut Vec<u8>,
) -> Result<bool> {
    let Some(mut chunk) = recv.recv_data().await.context("read Naive HTTP/3 data")? else {
        return Ok(false);
    };
    let len = chunk.remaining();
    pending.extend_from_slice(&chunk.copy_to_bytes(len));
    Ok(true)
}

async fn read_naive_h3_server_data<S>(
    recv: &mut h3::server::RequestStream<S, Bytes>,
    pending: &mut Vec<u8>,
    state: &mut NaiveReadState,
    buffer: &mut [u8],
) -> Result<usize>
where
    S: h3::quic::RecvStream,
{
    if state.read_remaining > 0 {
        let take = state.read_remaining.min(buffer.len());
        let read = read_raw_h3_server_some(recv, pending, &mut buffer[..take]).await?;
        state.read_remaining -= read;
        return Ok(read);
    }
    if state.padding_remaining > 0 {
        read_raw_h3_server_exact(recv, pending, state.padding_remaining).await?;
        state.padding_remaining = 0;
    }
    if state.read_padding < NAIVE_PADDING_COUNT {
        let header = read_raw_h3_server_exact(recv, pending, 3).await?;
        let data_size = u16::from_be_bytes([header[0], header[1]]) as usize;
        let padding_size = header[2] as usize;
        let take = data_size.min(buffer.len());
        let read = read_raw_h3_server_some(recv, pending, &mut buffer[..take]).await?;
        state.read_padding += 1;
        state.read_remaining = data_size - read;
        state.padding_remaining = padding_size;
        return Ok(read);
    }
    read_raw_h3_server_some(recv, pending, buffer).await
}

async fn read_raw_h3_server_some<S>(
    recv: &mut h3::server::RequestStream<S, Bytes>,
    pending: &mut Vec<u8>,
    buffer: &mut [u8],
) -> Result<usize>
where
    S: h3::quic::RecvStream,
{
    if pending.is_empty() && !pull_h3_server_data(recv, pending).await? {
        return Ok(0);
    }
    let take = pending.len().min(buffer.len());
    buffer[..take].copy_from_slice(&pending[..take]);
    pending.drain(..take);
    Ok(take)
}

async fn read_raw_h3_server_exact<S>(
    recv: &mut h3::server::RequestStream<S, Bytes>,
    pending: &mut Vec<u8>,
    size: usize,
) -> Result<Vec<u8>>
where
    S: h3::quic::RecvStream,
{
    while pending.len() < size {
        ensure!(
            pull_h3_server_data(recv, pending).await?,
            "Naive HTTP/3 server stream closed early"
        );
    }
    let output = pending[..size].to_vec();
    pending.drain(..size);
    Ok(output)
}

async fn pull_h3_server_data<S>(
    recv: &mut h3::server::RequestStream<S, Bytes>,
    pending: &mut Vec<u8>,
) -> Result<bool>
where
    S: h3::quic::RecvStream,
{
    let Some(mut chunk) = recv
        .recv_data()
        .await
        .context("read Naive HTTP/3 server data")?
    else {
        return Ok(false);
    };
    let len = chunk.remaining();
    pending.extend_from_slice(&chunk.copy_to_bytes(len));
    Ok(true)
}

async fn read_next_uot_packet_h1<R>(
    reader: &mut R,
    naive_pending: &mut Vec<u8>,
    read_state: &mut NaiveReadState,
    raw_pending: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        if let Some(packet) = take_next_uot_packet(raw_pending)? {
            return Ok(Some(packet));
        }
        let read = read_naive_h1_data(reader, naive_pending, read_state, &mut buffer).await?;
        if read == 0 {
            ensure!(
                raw_pending.is_empty(),
                "Naive UOT stream closed with partial packet"
            );
            return Ok(None);
        }
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

async fn read_next_uot_packet_h2(
    recv: &mut h2::RecvStream,
    flow: &mut h2::FlowControl,
    naive_pending: &mut Vec<u8>,
    read_state: &mut NaiveReadState,
    raw_pending: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        if let Some(packet) = take_next_uot_packet(raw_pending)? {
            return Ok(Some(packet));
        }
        let read = read_naive_h2_data(recv, flow, naive_pending, read_state, &mut buffer).await?;
        if read == 0 {
            ensure!(
                raw_pending.is_empty(),
                "Naive HTTP/2 UOT stream closed with partial packet"
            );
            return Ok(None);
        }
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

async fn read_next_uot_packet_h3(
    recv: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    naive_pending: &mut Vec<u8>,
    read_state: &mut NaiveReadState,
    raw_pending: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        if let Some(packet) = take_next_uot_packet(raw_pending)? {
            return Ok(Some(packet));
        }
        let read = read_naive_h3_data(recv, naive_pending, read_state, &mut buffer).await?;
        if read == 0 {
            ensure!(
                raw_pending.is_empty(),
                "Naive HTTP/3 UOT stream closed with partial packet"
            );
            return Ok(None);
        }
        raw_pending.extend_from_slice(&buffer[..read]);
    }
}

fn take_next_uot_packet(pending: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    let Some(length) = uot_packet_len(pending)? else {
        return Ok(None);
    };
    if pending.len() < length {
        return Ok(None);
    }
    let packet = pending[..length].to_vec();
    pending.drain(..length);
    Ok(Some(packet))
}

fn uot_packet_len(packet: &[u8]) -> Result<Option<usize>> {
    if packet.is_empty() {
        return Ok(None);
    }
    let payload_len_offset = match packet[0] {
        0x00 => {
            if packet.len() < 7 {
                return Ok(None);
            }
            7
        }
        0x01 => {
            if packet.len() < 19 {
                return Ok(None);
            }
            19
        }
        0x02 => {
            if packet.len() < 2 {
                return Ok(None);
            }
            let address_len = packet[1] as usize;
            if packet.len() < 2 + address_len + 2 {
                return Ok(None);
            }
            2 + address_len + 2
        }
        other => bail!("unsupported Naive UOT address family: {other}"),
    };
    if packet.len() < payload_len_offset + 2 {
        return Ok(None);
    }
    let payload_len =
        u16::from_be_bytes([packet[payload_len_offset], packet[payload_len_offset + 1]]) as usize;
    Ok(Some(payload_len_offset + 2 + payload_len))
}

fn naive_padding_header() -> Result<String> {
    let symbols = b"!#$()+<>?@[]^`{}";
    let padding_len = usize::from(random_byte()? % 32) + 30;
    let mut output = String::with_capacity(padding_len);
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).context("generate Naive padding header")?;
    for index in 0..16 {
        output.push(symbols[usize::from(random[index] & 0x0f)] as char);
    }
    for _ in 16..padding_len {
        output.push('~');
    }
    Ok(output)
}

fn random_byte() -> Result<u8> {
    let mut value = [0u8; 1];
    getrandom::fill(&mut value).context("generate Naive random byte")?;
    Ok(value[0])
}

fn base64_standard(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let value = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
        output.push(TABLE[(value & 0x3f) as usize] as char);
    }
    let rest = chunks.remainder();
    if rest.len() == 1 {
        let value = (rest[0] as u32) << 16;
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push('=');
        output.push('=');
    } else if rest.len() == 2 {
        let value = ((rest[0] as u32) << 16) | ((rest[1] as u32) << 8);
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 6) & 0x3f) as usize] as char);
        output.push('=');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_naive_quic_congestion_controls() -> Result<()> {
        for value in ["", "bbr", "cubic", "reno", "newreno", "new_reno"] {
            naive_quic_transport_config(value)
                .with_context(|| format!("accept Naive QUIC congestion control {value:?}"))?;
        }
        let error = naive_quic_transport_config("bbr2").expect_err("bbr2 is not wired in quinn");
        assert!(
            error
                .to_string()
                .contains("unsupported Naive quic_congestion_control bbr2")
        );
        Ok(())
    }
}
