use aerion::config::{
    AerionFileConfig, ClientFileConfig, FileConfig, ServerFileConfig,
    default_heartbeat_interval_secs, load_config,
};
use aerion::http_connect::{
    HttpConnectInboundConfig, HttpProxyClientConfig, run_http_connect_listener,
    run_http_proxy_client, run_http_proxy_client_listener,
};
use aerion::hysteria2::{Hysteria2ClientConfig, Hysteria2ServerConfig};
use aerion::mieru::{
    MieruClientConfig, MieruServerConfig, MieruTrafficPattern, MieruTransport, parse_mieru_user,
};
use aerion::naive::{NaiveClientConfig, NaiveServerConfig};
use aerion::padding::PaddingScheme;
use aerion::tuic::{TuicClientConfig, TuicServerConfig, parse_tuic_user};
use aerion::tun::{
    DEFAULT_TUN_MTU, TunCancellationToken, TunConfig, TunDnsStrategy, TunVerbosity, run_tun,
};
use aerion::vless_transport::VlessTransportConfig;
use aerion::{
    ClientConfig, MihomoClientConfig, MihomoProxy, RealityClientConfig, RealityServerConfig,
    RouteClientConfig, RouteDecision, RouteProxyConfig, RouteTable, ServerConfig,
    ShadowsocksClientConfig, ShadowsocksServerConfig, SingBoxClientConfig, SingBoxConfig,
    SingBoxOutbound, SingBoxServerConfig, SocksProxyClientConfig, TrojanClientConfig,
    TrojanServerConfig, VlessClientConfig, VlessServerConfig, VmessClientConfig, VmessServerConfig,
    XrayClientConfig, XrayOutbound, XrayServerConfig, run_client, run_client_listener,
    run_hysteria2_client, run_hysteria2_client_listener, run_hysteria2_server, run_mieru_client,
    run_mieru_client_listener, run_mieru_server, run_naive_client, run_naive_client_listener,
    run_naive_server, run_route_client, run_route_client_listener, run_route_proxy, run_server,
    run_shadowsocks_client, run_shadowsocks_client_listener, run_shadowsocks_server,
    run_socks_proxy_client, run_socks_proxy_client_listener, run_trojan_client,
    run_trojan_client_listener, run_trojan_server, run_tuic_client, run_tuic_client_listener,
    run_tuic_server, run_vless_client, run_vless_client_listener, run_vless_server,
    run_vmess_client, run_vmess_client_listener, run_vmess_server, tls,
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "aerion")]
#[command(about = "Pure Rust proxy core with client and server modes")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        listen: Option<SocketAddr>,
    },
    Tun {
        #[arg(long)]
        proxy: String,
        #[arg(long)]
        tun: Option<String>,
        #[arg(long = "tun-fd")]
        tun_fd: Option<i32>,
        #[arg(long = "close-fd-on-drop")]
        close_fd_on_drop: bool,
        #[arg(long)]
        setup: bool,
        #[arg(long, default_value_t = DEFAULT_TUN_MTU)]
        mtu: u16,
        #[arg(long, default_value = "direct")]
        dns: TunDnsStrategy,
        #[arg(long = "dns-addr", default_value = "8.8.8.8")]
        dns_addr: IpAddr,
        #[arg(long = "virtual-dns-pool", default_value = "198.18.0.0/15")]
        virtual_dns_pool: String,
        #[arg(long = "bypass")]
        bypass: Vec<String>,
        #[arg(long)]
        ipv6: bool,
        #[arg(long, default_value = "info")]
        verbosity: TunVerbosity,
        #[arg(long = "tcp-timeout", default_value_t = 600)]
        tcp_timeout_secs: u64,
        #[arg(long = "udp-timeout", default_value_t = 10)]
        udp_timeout_secs: u64,
        #[arg(long = "max-sessions", default_value_t = 200)]
        max_sessions: usize,
        #[arg(long = "exit-on-fatal-error")]
        exit_on_fatal_error: bool,
        #[arg(long = "packet-information")]
        packet_information: bool,
    },
    HttpConnect {
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        #[arg(long = "upstream-socks")]
        upstream_socks: SocketAddr,
    },
    Client {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        #[arg(long)]
        server: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        sni: Option<String>,
        #[arg(long)]
        insecure: bool,
        #[arg(long = "padding-line")]
        padding_scheme: Vec<String>,
        #[arg(long, default_value_t = default_heartbeat_interval_secs())]
        heartbeat_interval_secs: u64,
    },
    Server {
        #[arg(long, default_value = "0.0.0.0:8443")]
        listen: SocketAddr,
        #[arg(long)]
        password: String,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "user")]
        users: Vec<String>,
        #[arg(long = "padding-line")]
        padding_scheme: Vec<String>,
        #[arg(long, default_value_t = default_heartbeat_interval_secs())]
        heartbeat_interval_secs: u64,
    },
    Hysteria2Client {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        #[arg(long)]
        server: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        sni: Option<String>,
        #[arg(long)]
        insecure: bool,
        #[arg(long = "certificate-fingerprint")]
        certificate_fingerprint: Option<String>,
        #[arg(long = "ca-cert")]
        ca_cert_paths: Vec<PathBuf>,
        #[arg(long)]
        obfs: Option<String>,
        #[arg(long = "obfs-password")]
        obfs_password: Option<String>,
        #[arg(long = "upload-bandwidth")]
        upload_bandwidth: Option<u64>,
        #[arg(long = "download-bandwidth")]
        download_bandwidth: Option<u64>,
        #[arg(long, default_value_t = true)]
        udp: bool,
        #[arg(long = "congestion-control", default_value = "bbr")]
        congestion_control: String,
    },
    Hysteria2Server {
        #[arg(long, default_value = "0.0.0.0:8443")]
        listen: SocketAddr,
        #[arg(long)]
        password: String,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long = "user")]
        users: Vec<String>,
        #[arg(long)]
        obfs: Option<String>,
        #[arg(long = "obfs-password")]
        obfs_password: Option<String>,
        #[arg(long = "upload-bandwidth")]
        upload_bandwidth: Option<u64>,
        #[arg(long, default_value_t = true)]
        udp: bool,
        #[arg(long, default_value = "0")]
        cc_rx: String,
        #[arg(long = "congestion-control", default_value = "bbr")]
        congestion_control: String,
    },
    MieruClient {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "default")]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 1500)]
        mtu: usize,
        #[arg(long, default_value = "tcp")]
        transport: String,
    },
    MieruServer {
        #[arg(long, default_value = "0.0.0.0:8964")]
        listen: SocketAddr,
        #[arg(long, default_value = "default")]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long = "user")]
        users: Vec<String>,
        #[arg(long, default_value_t = 1500)]
        mtu: usize,
        #[arg(long = "user-hint-mandatory")]
        user_hint_mandatory: bool,
        #[arg(long, default_value = "tcp")]
        transport: String,
    },
    TuicClient {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        #[arg(long)]
        server: String,
        #[arg(long)]
        uuid: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        sni: Option<String>,
        #[arg(long)]
        insecure: bool,
        #[arg(long, default_value_t = true)]
        udp: bool,
        #[arg(long = "udp-relay-mode", default_value = "native")]
        udp_relay_mode: String,
        #[arg(long = "congestion-control", default_value = "cubic")]
        congestion_control: String,
        #[arg(long = "alpn")]
        alpn_protocols: Vec<String>,
        #[arg(long, default_value_t = default_heartbeat_interval_secs())]
        heartbeat_interval_secs: u64,
    },
    TuicServer {
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: SocketAddr,
        #[arg(long)]
        uuid: String,
        #[arg(long)]
        password: String,
        #[arg(long = "user")]
        users: Vec<String>,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = true)]
        udp: bool,
        #[arg(long = "congestion-control", default_value = "cubic")]
        congestion_control: String,
        #[arg(long = "alpn")]
        alpn_protocols: Vec<String>,
        #[arg(long, default_value_t = default_heartbeat_interval_secs())]
        heartbeat_interval_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tls::init_crypto();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "aerion=info".into()))
        .init();

    match Cli::parse().command {
        Command::Run {
            config,
            profile,
            listen,
        } => run_file_config(load_config(&config)?, profile.as_deref(), listen).await,
        Command::Tun {
            proxy,
            tun,
            tun_fd,
            close_fd_on_drop,
            setup,
            mtu,
            dns,
            dns_addr,
            virtual_dns_pool,
            bypass,
            ipv6,
            verbosity,
            tcp_timeout_secs,
            udp_timeout_secs,
            max_sessions,
            exit_on_fatal_error,
            packet_information,
        } => {
            let mut config = TunConfig::new(proxy);
            config.tun_name = tun;
            config.tun_fd = tun_fd;
            config.close_fd_on_drop = close_fd_on_drop;
            config.setup = setup;
            config.mtu = mtu;
            config.packet_information = packet_information;
            config.dns = dns;
            config.dns_addr = dns_addr;
            config.virtual_dns_pool = virtual_dns_pool;
            config.bypass = bypass;
            config.ipv6 = ipv6;
            config.verbosity = verbosity;
            config.tcp_timeout_secs = tcp_timeout_secs;
            config.udp_timeout_secs = udp_timeout_secs;
            config.max_sessions = max_sessions;
            config.exit_on_fatal_error = exit_on_fatal_error;
            run_tun(config, TunCancellationToken::new())
                .await
                .map(|_| ())
        }
        Command::HttpConnect {
            listen,
            upstream_socks,
        } => {
            let listener = TcpListener::bind(listen)
                .await
                .with_context(|| format!("bind HTTP CONNECT inbound on {listen}"))?;
            run_http_connect_listener(listener, HttpConnectInboundConfig { upstream_socks }).await
        }
        Command::Client {
            listen,
            server,
            password,
            sni,
            insecure,
            padding_scheme,
            heartbeat_interval_secs,
        } => {
            let (server_host, server_port) = parse_host_port(&server)?;
            let sni = sni.unwrap_or_else(|| server_host.clone());
            run_client(ClientConfig {
                listen,
                server_host,
                server_port,
                password,
                sni,
                insecure,
                client_fingerprint: None,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                disable_system_roots: false,
                pinned_cert_sha256: Vec::new(),
                padding_scheme: if padding_scheme.is_empty() {
                    PaddingScheme::default_lines()
                } else {
                    padding_scheme
                },
                heartbeat_interval_secs,
            })
            .await
        }
        Command::Server {
            listen,
            password,
            cert,
            key,
            users,
            padding_scheme,
            heartbeat_interval_secs,
        } => {
            run_server(ServerConfig {
                listen,
                password,
                users,
                cert_path: cert,
                key_path: key,
                certificates: Vec::new(),
                key: None,
                padding_scheme: if padding_scheme.is_empty() {
                    PaddingScheme::default_lines()
                } else {
                    padding_scheme
                },
                heartbeat_interval_secs,
            })
            .await
        }
        Command::Hysteria2Client {
            listen,
            server,
            password,
            sni,
            insecure,
            certificate_fingerprint,
            ca_cert_paths,
            obfs,
            obfs_password,
            upload_bandwidth,
            download_bandwidth,
            udp,
            congestion_control,
        } => {
            let (server_host, server_port) = parse_host_port(&server)?;
            let sni = sni.unwrap_or_else(|| server_host.clone());
            run_hysteria2_client(Hysteria2ClientConfig {
                listen,
                server_host,
                server_port,
                password,
                sni,
                insecure,
                certificate_fingerprint,
                ca_cert_paths,
                ca_certificates: Vec::new(),
                disable_system_roots: false,
                pinned_cert_sha256: Vec::new(),
                obfs,
                obfs_password,
                upload_bandwidth,
                download_bandwidth,
                udp,
                congestion_control,
            })
            .await
        }
        Command::Hysteria2Server {
            listen,
            password,
            cert,
            key,
            users,
            obfs,
            obfs_password,
            upload_bandwidth,
            udp,
            cc_rx,
            congestion_control,
        } => {
            run_hysteria2_server(Hysteria2ServerConfig {
                listen,
                password,
                users,
                cert_path: cert,
                key_path: key,
                certificates: Vec::new(),
                key: None,
                obfs,
                obfs_password,
                upload_bandwidth,
                udp,
                cc_rx,
                congestion_control,
            })
            .await
        }
        Command::MieruClient {
            listen,
            server,
            username,
            password,
            mtu,
            transport,
        } => {
            let (server_host, server_port) = parse_host_port(&server)?;
            run_mieru_client(MieruClientConfig {
                listen,
                server_host,
                server_port,
                username,
                password,
                hashed_password: None,
                mtu,
                transport: MieruTransport::parse(&transport)?,
                traffic_pattern: None,
            })
            .await
        }
        Command::MieruServer {
            listen,
            username,
            password,
            users,
            mtu,
            user_hint_mandatory,
            transport,
        } => {
            let users = users
                .iter()
                .map(|user| parse_mieru_user(user))
                .collect::<Result<Vec<_>>>()?;
            run_mieru_server(MieruServerConfig {
                listen,
                username,
                password,
                users,
                mtu,
                user_hint_mandatory,
                transport: MieruTransport::parse(&transport)?,
                traffic_pattern: None,
            })
            .await
        }
        Command::TuicClient {
            listen,
            server,
            uuid,
            password,
            sni,
            insecure,
            udp,
            udp_relay_mode,
            congestion_control,
            alpn_protocols,
            heartbeat_interval_secs,
        } => {
            let (server_host, server_port) = parse_host_port(&server)?;
            let sni = sni.unwrap_or_else(|| server_host.clone());
            run_tuic_client(TuicClientConfig {
                listen,
                server_host,
                server_port,
                uuid,
                password,
                sni,
                insecure,
                ca_cert_paths: Vec::new(),
                ca_certificates: Vec::new(),
                disable_system_roots: false,
                pinned_cert_sha256: Vec::new(),
                udp,
                udp_relay_mode,
                congestion_control,
                alpn_protocols,
                heartbeat_interval_secs,
            })
            .await
        }
        Command::TuicServer {
            listen,
            uuid,
            password,
            users,
            cert,
            key,
            udp,
            congestion_control,
            alpn_protocols,
            heartbeat_interval_secs,
        } => {
            let users = users
                .iter()
                .map(|user| {
                    parse_tuic_user(user).map(|user| format!("{}:{}", user.uuid, user.password))
                })
                .collect::<Result<Vec<_>>>()?;
            run_tuic_server(TuicServerConfig {
                listen,
                uuid,
                password,
                users,
                cert_path: cert,
                key_path: key,
                certificates: Vec::new(),
                key: None,
                udp,
                congestion_control,
                alpn_protocols,
                heartbeat_interval_secs,
            })
            .await
        }
    }
}

enum RunnableClientConfig {
    AnyTls(ClientConfig),
    HttpProxy(HttpProxyClientConfig),
    Hysteria2(Hysteria2ClientConfig),
    Mieru(MieruClientConfig),
    Naive(NaiveClientConfig),
    Route(RouteClientConfig),
    Shadowsocks(ShadowsocksClientConfig),
    SocksProxy(SocksProxyClientConfig),
    Trojan(TrojanClientConfig),
    Tuic(TuicClientConfig),
    Vless(VlessClientConfig),
    Vmess(VmessClientConfig),
}

impl From<MihomoClientConfig> for RunnableClientConfig {
    fn from(config: MihomoClientConfig) -> Self {
        match config {
            MihomoClientConfig::AnyTls(config) => Self::AnyTls(config),
            MihomoClientConfig::HttpProxy(config) => Self::HttpProxy(config),
            MihomoClientConfig::Hysteria2(config) => Self::Hysteria2(config),
            MihomoClientConfig::Mieru(config) => Self::Mieru(config),
            MihomoClientConfig::Naive(config) => Self::Naive(config),
            MihomoClientConfig::Route(config) => Self::Route(config),
            MihomoClientConfig::Shadowsocks(config) => Self::Shadowsocks(config),
            MihomoClientConfig::SocksProxy(config) => Self::SocksProxy(config),
            MihomoClientConfig::Trojan(config) => Self::Trojan(config),
            MihomoClientConfig::Tuic(config) => Self::Tuic(config),
            MihomoClientConfig::Vless(config) => Self::Vless(config),
            MihomoClientConfig::Vmess(config) => Self::Vmess(config),
        }
    }
}

impl From<SingBoxClientConfig> for RunnableClientConfig {
    fn from(config: SingBoxClientConfig) -> Self {
        match config {
            SingBoxClientConfig::AnyTls(config) => Self::AnyTls(config),
            SingBoxClientConfig::HttpProxy(config) => Self::HttpProxy(config),
            SingBoxClientConfig::Hysteria2(config) => Self::Hysteria2(config),
            SingBoxClientConfig::Naive(config) => Self::Naive(config),
            SingBoxClientConfig::Route(config) => Self::Route(config),
            SingBoxClientConfig::Shadowsocks(config) => Self::Shadowsocks(config),
            SingBoxClientConfig::SocksProxy(config) => Self::SocksProxy(config),
            SingBoxClientConfig::Trojan(config) => Self::Trojan(config),
            SingBoxClientConfig::Tuic(config) => Self::Tuic(config),
            SingBoxClientConfig::Vless(config) => Self::Vless(config),
            SingBoxClientConfig::Vmess(config) => Self::Vmess(config),
        }
    }
}

impl From<XrayClientConfig> for RunnableClientConfig {
    fn from(config: XrayClientConfig) -> Self {
        match config {
            XrayClientConfig::HttpProxy(config) => Self::HttpProxy(config),
            XrayClientConfig::Hysteria2(config) => Self::Hysteria2(config),
            XrayClientConfig::Route(config) => Self::Route(config),
            XrayClientConfig::Shadowsocks(config) => Self::Shadowsocks(config),
            XrayClientConfig::SocksProxy(config) => Self::SocksProxy(config),
            XrayClientConfig::Trojan(config) => Self::Trojan(config),
            XrayClientConfig::Vless(config) => Self::Vless(config),
            XrayClientConfig::Vmess(config) => Self::Vmess(config),
        }
    }
}

async fn run_file_config(
    config: FileConfig,
    profile: Option<&str>,
    listen: Option<SocketAddr>,
) -> Result<()> {
    match config {
        FileConfig::Client { client } => run_native_client(client, listen).await,
        FileConfig::Server { server } => run_native_server(server, listen).await,
        FileConfig::Aerion(config) => run_aerion_config(config, profile, listen).await,
        FileConfig::Mihomo(config) => {
            if profile.is_none() && !config.rules.is_empty() {
                return run_mihomo_route_config(config, listen).await;
            }
            if config.tun_enabled() {
                let listen = listen
                    .or(config.local_socks_listen()?)
                    .unwrap_or("127.0.0.1:0".parse()?);
                let listener = bind_client_listener("mihomo", listen).await?;
                let listen = listener.local_addr()?;
                let proxy = select_mihomo_proxy(&config.proxies, profile)?;
                let tun = config
                    .tun_config(listen)?
                    .context("mihomo TUN is enabled but no TUN config was produced")?;
                return run_client_config_with_tun(
                    listener,
                    proxy.to_client_config(listen)?.into(),
                    tun,
                )
                .await;
            }
            let listen = listen
                .or(config.local_socks_listen()?)
                .context("mihomo config has no mixed-port/socks-port/port; pass --listen")?;
            let proxy = select_mihomo_proxy(&config.proxies, profile)?;
            run_client_config(proxy.to_client_config(listen)?.into()).await
        }
        FileConfig::Xray(config) => {
            if config.outbounds.is_empty() {
                let inbound = select_xray_inbound(&config.inbounds, profile)?;
                return run_xray_server_config(inbound.to_server_config()?).await;
            }
            if profile.is_none() && !config.routing.rules.is_empty() {
                return run_xray_route_config(config, listen).await;
            }
            let listen = listen
                .or(config.local_socks_listen()?)
                .context("xray config has no socks inbound; pass --listen")?;
            let outbound = select_xray_outbound(&config.outbounds, profile)?;
            run_client_config(outbound.to_client_config(listen)?.into()).await
        }
        FileConfig::SingBox(config) => {
            if config.outbounds.is_empty() {
                let inbound = select_singbox_inbound(&config.inbounds, profile)?;
                return run_singbox_server_config(inbound.to_server_config()?).await;
            }
            if profile.is_none()
                && config
                    .route
                    .as_ref()
                    .map(|route| !route.rules.is_empty() || route.final_outbound.is_some())
                    .unwrap_or(false)
            {
                return run_singbox_route_config(config, listen).await;
            }
            if config.tun_enabled() {
                let listen = listen
                    .or(config.local_socks_listen()?)
                    .unwrap_or("127.0.0.1:0".parse()?);
                let listener = bind_client_listener("sing-box", listen).await?;
                let listen = listener.local_addr()?;
                let outbound = select_singbox_outbound(&config, profile)?;
                let tun = config
                    .tun_config(listen)?
                    .context("sing-box TUN inbound was found but no TUN config was produced")?;
                return run_client_config_with_tun(
                    listener,
                    outbound.to_client_config(listen)?.into(),
                    tun,
                )
                .await;
            }
            let listen = listen
                .or(config.local_socks_listen()?)
                .context("sing-box config has no mixed/socks inbound; pass --listen")?;
            let outbound = select_singbox_outbound(&config, profile)?;
            run_client_config(outbound.to_client_config(listen)?.into()).await
        }
    }
}

async fn run_mihomo_route_config(
    config: aerion::MihomoConfig,
    listen: Option<SocketAddr>,
) -> Result<()> {
    let routes = config.route_table()?;
    let listen = listen
        .or(config.local_socks_listen()?)
        .or_else(|| config.tun_enabled().then(ephemeral_loopback))
        .context("mihomo route config has no mixed-port/socks-port/port; pass --listen")?;
    let router_listener = bind_client_listener("mihomo route", listen).await?;
    let router_listen = router_listener.local_addr()?;
    let (outbound_tx, outbound_rx) = mpsc::channel(8);
    let mut upstreams = BTreeMap::new();
    for tag in route_proxy_tags(&routes) {
        let listener = bind_client_listener(
            &format!("mihomo route outbound {tag}"),
            ephemeral_loopback(),
        )
        .await?;
        let upstream = listener.local_addr()?;
        let proxy = config
            .proxy(&tag)
            .with_context(|| format!("mihomo route outbound {tag} was not found"))?;
        let runnable = proxy.to_client_config(upstream)?.into();
        spawn_route_outbound(tag.clone(), listener, runnable, outbound_tx.clone());
        upstreams.insert(tag, upstream);
    }
    let tun = if config.tun_enabled() {
        Some(
            config
                .tun_config(router_listen)?
                .context("mihomo TUN is enabled but no TUN config was produced")?,
        )
    } else {
        None
    };
    run_route_stack(
        router_listener,
        RouteProxyConfig { routes, upstreams },
        tun,
        outbound_rx,
    )
    .await
}

async fn run_singbox_route_config(
    config: aerion::SingBoxConfig,
    listen: Option<SocketAddr>,
) -> Result<()> {
    let routes = config.route_table()?;
    let listen = listen
        .or(config.local_socks_listen()?)
        .or_else(|| config.tun_enabled().then(ephemeral_loopback))
        .context("sing-box route config has no mixed/socks inbound; pass --listen")?;
    let router_listener = bind_client_listener("sing-box route", listen).await?;
    let router_listen = router_listener.local_addr()?;
    let (outbound_tx, outbound_rx) = mpsc::channel(8);
    let mut upstreams = BTreeMap::new();
    for tag in route_proxy_tags(&routes) {
        let listener = bind_client_listener(
            &format!("sing-box route outbound {tag}"),
            ephemeral_loopback(),
        )
        .await?;
        let upstream = listener.local_addr()?;
        let outbound = config
            .resolved_outbound(&tag)
            .with_context(|| format!("resolve sing-box route outbound {tag}"))?;
        let runnable = outbound.to_client_config(upstream)?.into();
        spawn_route_outbound(tag.clone(), listener, runnable, outbound_tx.clone());
        upstreams.insert(tag, upstream);
    }
    let tun = if config.tun_enabled() {
        Some(
            config
                .tun_config(router_listen)?
                .context("sing-box TUN inbound was found but no TUN config was produced")?,
        )
    } else {
        None
    };
    run_route_stack(
        router_listener,
        RouteProxyConfig { routes, upstreams },
        tun,
        outbound_rx,
    )
    .await
}

async fn run_xray_route_config(
    config: aerion::XrayConfig,
    listen: Option<SocketAddr>,
) -> Result<()> {
    let routes = config.route_table()?;
    let listen = listen
        .or(config.local_socks_listen()?)
        .context("xray route config has no socks inbound; pass --listen")?;
    let router_listener = bind_client_listener("xray route", listen).await?;
    let (outbound_tx, outbound_rx) = mpsc::channel(8);
    let mut upstreams = BTreeMap::new();
    for tag in route_proxy_tags(&routes) {
        let listener =
            bind_client_listener(&format!("xray route outbound {tag}"), ephemeral_loopback())
                .await?;
        let upstream = listener.local_addr()?;
        let outbound = config
            .outbound(&tag)
            .with_context(|| format!("xray route outbound {tag} was not found"))?;
        let runnable = outbound.to_client_config(upstream)?.into();
        spawn_route_outbound(tag.clone(), listener, runnable, outbound_tx.clone());
        upstreams.insert(tag, upstream);
    }
    run_route_stack(
        router_listener,
        RouteProxyConfig { routes, upstreams },
        None,
        outbound_rx,
    )
    .await
}

async fn run_aerion_config(
    config: AerionFileConfig,
    profile: Option<&str>,
    listen: Option<SocketAddr>,
) -> Result<()> {
    if let Some(profile) = profile {
        if let Some(client) = config
            .clients
            .into_iter()
            .find(|client| native_client_name(client) == profile)
        {
            return run_native_client(client, listen).await;
        }
        if let Some(server) = config
            .servers
            .into_iter()
            .find(|server| native_server_name(server) == profile)
        {
            return run_native_server(server, listen).await;
        }
        bail!("Aerion TOML profile {profile} was not found");
    }

    match (config.clients.len(), config.servers.len()) {
        (1, 0) => run_native_client(config.clients.into_iter().next().unwrap(), listen).await,
        (0, 1) => run_native_server(config.servers.into_iter().next().unwrap(), listen).await,
        _ => bail!(
            "Aerion TOML config has multiple profiles [{}]; pass --profile",
            native_profile_names(&config)
        ),
    }
}

async fn run_native_client(mut client: ClientFileConfig, listen: Option<SocketAddr>) -> Result<()> {
    if let Some(listen) = listen {
        client.listen = listen;
    }
    let (server_host, server_port) = parse_host_port(&client.server)?;
    let sni = client.sni.unwrap_or_else(|| server_host.clone());
    if is_hysteria2(&client.protocol) {
        return run_hysteria2_client(Hysteria2ClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            password: client.password,
            sni,
            insecure: client.insecure,
            certificate_fingerprint: client.certificate_fingerprint,
            ca_cert_paths: client.ca_cert_paths,
            ca_certificates: client.ca_certificates,
            disable_system_roots: client.disable_system_roots,
            pinned_cert_sha256: client.pinned_cert_sha256,
            obfs: client.obfs,
            obfs_password: client.obfs_password,
            upload_bandwidth: client.upload_bandwidth,
            download_bandwidth: client.download_bandwidth,
            udp: client.udp,
            congestion_control: client.congestion_control,
        })
        .await;
    }
    if is_mieru(&client.protocol) {
        return run_mieru_client(MieruClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            username: client.username,
            password: client.password,
            hashed_password: None,
            mtu: client.mtu,
            transport: MieruTransport::parse(&client.transport)?,
            traffic_pattern: MieruTrafficPattern::parse_pair(
                client.traffic_pattern.as_deref(),
                client.nonce_pattern.as_deref(),
            )?,
        })
        .await;
    }
    if is_tuic(&client.protocol) {
        return run_tuic_client(TuicClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            uuid: client.username,
            password: client.password,
            sni,
            insecure: client.insecure,
            ca_cert_paths: client.ca_cert_paths,
            ca_certificates: client.ca_certificates,
            disable_system_roots: client.disable_system_roots,
            pinned_cert_sha256: client.pinned_cert_sha256,
            udp: client.udp,
            udp_relay_mode: client.udp_relay_mode,
            congestion_control: client.congestion_control,
            alpn_protocols: client.alpn_protocols,
            heartbeat_interval_secs: client.heartbeat_interval_secs,
        })
        .await;
    }
    if is_naive(&client.protocol) {
        return run_naive_client(NaiveClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            username: client.username,
            password: client.password,
            sni,
            insecure: client.insecure,
            ca_cert_paths: client.ca_cert_paths,
            ca_certificates: client.ca_certificates,
            disable_system_roots: client.disable_system_roots,
            pinned_cert_sha256: client.pinned_cert_sha256,
            extra_headers: client.headers.into_iter().collect(),
            udp_over_tcp: client.udp_over_tcp,
            quic: client.transport.eq_ignore_ascii_case("quic")
                || client.protocol.eq_ignore_ascii_case("naive+quic"),
            quic_congestion_control: client.quic_congestion_control,
        })
        .await;
    }
    if is_shadowsocks(&client.protocol) {
        return run_shadowsocks_client(ShadowsocksClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            method: client
                .security
                .context("Shadowsocks client requires cipher")?,
            password: client.password,
            udp: client.udp,
            udp_over_tcp: client.udp_over_tcp,
        })
        .await;
    }
    if is_http_proxy(&client.protocol) {
        let tls = client.tls.unwrap_or_else(|| {
            client.protocol.eq_ignore_ascii_case("https")
                || client.protocol.eq_ignore_ascii_case("https-proxy")
                || client.protocol.eq_ignore_ascii_case("http+tls")
        });
        ensure!(
            tls || (!client.insecure
                && client.ca_cert_paths.is_empty()
                && client.ca_certificates.is_empty()
                && !client.disable_system_roots
                && client.pinned_cert_sha256.is_empty()
                && client.client_fingerprint.is_none()),
            "HTTP proxy client sets TLS-only options while TLS is disabled"
        );
        return run_http_proxy_client(HttpProxyClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            username: client.username,
            password: client.password,
            tls,
            sni,
            insecure: client.insecure,
            ca_cert_paths: client.ca_cert_paths,
            ca_certificates: client.ca_certificates,
            disable_system_roots: client.disable_system_roots,
            pinned_cert_sha256: client.pinned_cert_sha256,
            client_fingerprint: client.client_fingerprint,
            extra_headers: client.headers.into_iter().collect(),
        })
        .await;
    }
    if is_socks_proxy(&client.protocol) {
        ensure!(
            !client.tls.unwrap_or(false)
                && !client.insecure
                && client.ca_cert_paths.is_empty()
                && client.ca_certificates.is_empty()
                && !client.disable_system_roots
                && client.pinned_cert_sha256.is_empty()
                && client.client_fingerprint.is_none()
                && client.alpn_protocols.is_empty(),
            "SOCKS proxy client sets TLS-only options"
        );
        ensure!(
            client.headers.is_empty(),
            "SOCKS proxy client sets HTTP headers; SOCKS does not use headers"
        );
        return run_socks_proxy_client(SocksProxyClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            username: client.username,
            password: client.password,
            udp: client.udp,
        })
        .await;
    }
    if is_trojan(&client.protocol) {
        return run_trojan_client(TrojanClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            password: client.password,
            sni,
            insecure: client.insecure,
            ca_cert_paths: client.ca_cert_paths,
            ca_certificates: client.ca_certificates,
            disable_system_roots: client.disable_system_roots,
            pinned_cert_sha256: client.pinned_cert_sha256,
            udp: client.udp,
            client_fingerprint: client.client_fingerprint,
            transport: native_vless_transport(
                client.network.as_deref(),
                client.path,
                client.host,
                client.headers,
            )?,
        })
        .await;
    }
    if is_vless(&client.protocol) {
        let user_id = native_user_id(client.user_id, &client.username, "VLESS client")?;
        let reality = client
            .reality_public_key
            .as_deref()
            .map(|public_key| {
                RealityClientConfig::from_strings(
                    public_key,
                    client.reality_short_id.as_deref().unwrap_or_default(),
                )
            })
            .transpose()?;
        let tls = reality.is_none() && client.tls.unwrap_or(true);
        return run_vless_client(VlessClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            user_id,
            tls,
            sni,
            insecure: client.insecure,
            ca_cert_paths: client.ca_cert_paths,
            ca_certificates: client.ca_certificates,
            disable_system_roots: client.disable_system_roots,
            pinned_cert_sha256: client.pinned_cert_sha256,
            flow: client.flow,
            packet_encoding: client.packet_encoding,
            mux: client.mux,
            udp: client.udp,
            client_fingerprint: client.client_fingerprint,
            reality,
            transport: native_vless_transport(
                client.network.as_deref(),
                client.path,
                client.host,
                client.headers,
            )?,
        })
        .await;
    }
    if is_vmess(&client.protocol) {
        return run_vmess_client(VmessClientConfig {
            listen: client.listen,
            server_host,
            server_port,
            user_id: native_user_id(client.user_id, &client.username, "VMess client")?,
            security: client.security.unwrap_or_else(|| "auto".to_string()),
            packet_encoding: client.packet_encoding,
            udp: client.udp,
            tls: client.tls.unwrap_or(false),
            sni,
            insecure: client.insecure,
            ca_cert_paths: client.ca_cert_paths,
            ca_certificates: client.ca_certificates,
            disable_system_roots: client.disable_system_roots,
            pinned_cert_sha256: client.pinned_cert_sha256,
            client_fingerprint: client.client_fingerprint,
            transport: native_vless_transport(
                client.network.as_deref(),
                client.path,
                client.host,
                client.headers,
            )?,
        })
        .await;
    }
    ensure_supported_protocol(&client.protocol)?;
    run_client(ClientConfig {
        listen: client.listen,
        server_host,
        server_port,
        password: client.password,
        sni,
        insecure: client.insecure,
        client_fingerprint: client.client_fingerprint,
        ca_cert_paths: client.ca_cert_paths,
        ca_certificates: client.ca_certificates,
        disable_system_roots: client.disable_system_roots,
        pinned_cert_sha256: client.pinned_cert_sha256,
        padding_scheme: client.padding_scheme,
        heartbeat_interval_secs: client.heartbeat_interval_secs,
    })
    .await
}

async fn run_native_server(mut server: ServerFileConfig, listen: Option<SocketAddr>) -> Result<()> {
    if let Some(listen) = listen {
        server.listen = listen;
    }
    if is_hysteria2(&server.protocol) {
        let (cert_path, key_path) = native_tls_paths(&server, "Hysteria2")?;
        return run_hysteria2_server(Hysteria2ServerConfig {
            listen: server.listen,
            password: server.password,
            users: server.users,
            cert_path,
            key_path,
            certificates: server.certificates,
            key: server.key_pem,
            obfs: server.obfs,
            obfs_password: server.obfs_password,
            upload_bandwidth: server.upload_bandwidth,
            udp: server.udp,
            cc_rx: server.cc_rx,
            congestion_control: server.congestion_control,
        })
        .await;
    }
    if is_mieru(&server.protocol) {
        let users = server
            .users
            .iter()
            .map(|user| parse_mieru_user(user))
            .collect::<Result<Vec<_>>>()?;
        return run_mieru_server(MieruServerConfig {
            listen: server.listen,
            username: server.username,
            password: server.password,
            users,
            mtu: server.mtu,
            user_hint_mandatory: server.user_hint_mandatory,
            transport: MieruTransport::parse(&server.transport)?,
            traffic_pattern: MieruTrafficPattern::parse_pair(
                server.traffic_pattern.as_deref(),
                server.nonce_pattern.as_deref(),
            )?,
        })
        .await;
    }
    if is_tuic(&server.protocol) {
        let (cert_path, key_path) = native_tls_paths(&server, "TUIC")?;
        let users = server
            .users
            .iter()
            .map(|user| {
                parse_tuic_user(user).map(|user| format!("{}:{}", user.uuid, user.password))
            })
            .collect::<Result<Vec<_>>>()?;
        return run_tuic_server(TuicServerConfig {
            listen: server.listen,
            uuid: server.username,
            password: server.password,
            users,
            cert_path,
            key_path,
            certificates: server.certificates,
            key: server.key_pem,
            udp: server.udp,
            congestion_control: server.congestion_control,
            alpn_protocols: server.alpn_protocols,
            heartbeat_interval_secs: server.heartbeat_interval_secs,
        })
        .await;
    }
    if is_shadowsocks(&server.protocol) {
        return run_shadowsocks_server(ShadowsocksServerConfig {
            listen: server.listen,
            method: server
                .security
                .context("Shadowsocks server requires cipher")?,
            password: server.password,
            users: server.users,
            tcp: true,
            udp: server.udp,
            udp_over_tcp: server.udp_over_tcp,
        })
        .await;
    }
    if is_naive(&server.protocol) {
        let (cert_path, key_path) = native_tls_paths(&server, "Naive")?;
        return run_naive_server(NaiveServerConfig {
            listen: server.listen,
            username: server.username,
            password: server.password,
            users: server.users,
            cert_path,
            key_path,
            certificates: server.certificates,
            key: server.key_pem,
            udp_over_tcp: server.udp_over_tcp,
            tcp: true,
            quic: server.transport.eq_ignore_ascii_case("quic")
                || server.protocol.eq_ignore_ascii_case("naive+quic"),
            quic_congestion_control: server.quic_congestion_control,
        })
        .await;
    }
    if is_trojan(&server.protocol) {
        let (cert_path, key_path) = native_tls_paths(&server, "Trojan")?;
        return run_trojan_server(TrojanServerConfig {
            listen: server.listen,
            password: server.password,
            users: server.users,
            cert_path,
            key_path,
            certificates: server.certificates,
            key: server.key_pem,
            transport: native_vless_transport(
                server.network.as_deref(),
                server.path,
                server.host,
                server.headers,
            )?,
        })
        .await;
    }
    if is_vless(&server.protocol) {
        let tls = server.reality_private_key.is_none() && server.tls.unwrap_or(true);
        let (cert_path, key_path) = if !tls {
            (PathBuf::new(), PathBuf::new())
        } else {
            native_tls_paths(&server, "VLESS")?
        };
        let transport = native_vless_transport(
            server.network.as_deref(),
            server.path,
            server.host,
            server.headers,
        )?;
        let reality = server
            .reality_private_key
            .as_deref()
            .map(|private_key| {
                RealityServerConfig::from_strings(
                    server
                        .reality_server_name
                        .clone()
                        .context("VLESS REALITY server requires reality_server_name")?,
                    server.reality_server_port.unwrap_or(443),
                    server.reality_server_names.clone(),
                    private_key,
                    &server.reality_short_ids,
                    transport.alpn_protocols(),
                )
            })
            .transpose()?;
        let certificates = if tls { server.certificates } else { Vec::new() };
        let key = if tls { server.key_pem } else { None };
        return run_vless_server(VlessServerConfig {
            listen: server.listen,
            user_id: native_user_id(server.user_id, &server.username, "VLESS server")?,
            users: server.users,
            tls,
            cert_path,
            key_path,
            certificates,
            key,
            flow: server.flow,
            reality,
            transport,
        })
        .await;
    }
    if is_vmess(&server.protocol) {
        let tls = server.tls.unwrap_or_else(|| {
            server.cert.is_some()
                || server.key.is_some()
                || !server.certificates.is_empty()
                || server.key_pem.is_some()
        });
        let (cert_path, key_path, certificates, key) = if tls {
            let (cert_path, key_path) = native_tls_paths(&server, "VMess TLS")?;
            (
                Some(cert_path),
                Some(key_path),
                server.certificates,
                server.key_pem,
            )
        } else {
            (None, None, Vec::new(), None)
        };
        return run_vmess_server(VmessServerConfig {
            listen: server.listen,
            user_id: native_user_id(server.user_id, &server.username, "VMess server")?,
            users: server.users,
            tls,
            cert_path,
            key_path,
            certificates,
            key,
            transport: native_vless_transport(
                server.network.as_deref(),
                server.path,
                server.host,
                server.headers,
            )?,
        })
        .await;
    }
    ensure_supported_protocol(&server.protocol)?;
    let (cert_path, key_path) = native_tls_paths(&server, "AnyTLS")?;
    run_server(ServerConfig {
        listen: server.listen,
        password: server.password,
        users: server.users,
        cert_path,
        key_path,
        certificates: server.certificates,
        key: server.key_pem,
        padding_scheme: server.padding_scheme,
        heartbeat_interval_secs: server.heartbeat_interval_secs,
    })
    .await
}

fn native_tls_paths(server: &ServerFileConfig, protocol: &str) -> Result<(PathBuf, PathBuf)> {
    let cert_path = match &server.cert {
        Some(path) => path.clone(),
        None => {
            ensure!(
                !server.certificates.is_empty(),
                "server cert or certificate is required for {protocol}"
            );
            PathBuf::new()
        }
    };
    let key_path = match &server.key {
        Some(path) => path.clone(),
        None => {
            ensure!(
                server.key_pem.is_some(),
                "server key or key_pem is required for {protocol}"
            );
            PathBuf::new()
        }
    };
    Ok((cert_path, key_path))
}

async fn run_client_config(config: RunnableClientConfig) -> Result<()> {
    match config {
        RunnableClientConfig::AnyTls(config) => run_client(config).await,
        RunnableClientConfig::HttpProxy(config) => run_http_proxy_client(config).await,
        RunnableClientConfig::Hysteria2(config) => run_hysteria2_client(config).await,
        RunnableClientConfig::Mieru(config) => run_mieru_client(config).await,
        RunnableClientConfig::Naive(config) => run_naive_client(config).await,
        RunnableClientConfig::Route(config) => run_route_client(config).await,
        RunnableClientConfig::Shadowsocks(config) => run_shadowsocks_client(config).await,
        RunnableClientConfig::SocksProxy(config) => run_socks_proxy_client(config).await,
        RunnableClientConfig::Trojan(config) => run_trojan_client(config).await,
        RunnableClientConfig::Tuic(config) => run_tuic_client(config).await,
        RunnableClientConfig::Vless(config) => run_vless_client(config).await,
        RunnableClientConfig::Vmess(config) => run_vmess_client(config).await,
    }
}

async fn bind_client_listener(format: &str, listen: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {format} local SOCKS listener on {listen}"))
}

async fn run_client_config_with_listener(
    listener: TcpListener,
    config: RunnableClientConfig,
) -> Result<()> {
    match config {
        RunnableClientConfig::AnyTls(config) => run_client_listener(listener, config, None).await,
        RunnableClientConfig::HttpProxy(config) => {
            run_http_proxy_client_listener(listener, config).await
        }
        RunnableClientConfig::Hysteria2(config) => {
            run_hysteria2_client_listener(listener, config).await
        }
        RunnableClientConfig::Mieru(config) => run_mieru_client_listener(listener, config).await,
        RunnableClientConfig::Naive(config) => run_naive_client_listener(listener, config).await,
        RunnableClientConfig::Route(config) => run_route_client_listener(listener, config).await,
        RunnableClientConfig::Shadowsocks(config) => {
            run_shadowsocks_client_listener(listener, config).await
        }
        RunnableClientConfig::SocksProxy(config) => {
            run_socks_proxy_client_listener(listener, config).await
        }
        RunnableClientConfig::Trojan(config) => {
            run_trojan_client_listener(listener, config, None).await
        }
        RunnableClientConfig::Tuic(config) => run_tuic_client_listener(listener, config).await,
        RunnableClientConfig::Vless(config) => {
            run_vless_client_listener(listener, config, None).await
        }
        RunnableClientConfig::Vmess(config) => run_vmess_client_listener(listener, config).await,
    }
}

async fn run_client_config_with_tun(
    listener: TcpListener,
    config: RunnableClientConfig,
    tun: TunConfig,
) -> Result<()> {
    let shutdown = TunCancellationToken::new();
    tokio::select! {
        result = run_client_config_with_listener(listener, config) => {
            shutdown.cancel();
            result
        }
        result = run_tun(tun, shutdown.clone()) => result.map(|_| ()),
    }
}

fn route_proxy_tags(routes: &RouteTable) -> Vec<String> {
    let mut tags = BTreeSet::new();
    for rule in &routes.rules {
        if let RouteDecision::Proxy(tag) = &rule.action {
            tags.insert(tag.clone());
        }
    }
    if let RouteDecision::Proxy(tag) = &routes.default {
        tags.insert(tag.clone());
    }
    tags.into_iter().collect()
}

fn spawn_route_outbound(
    tag: String,
    listener: TcpListener,
    config: RunnableClientConfig,
    exit_tx: mpsc::Sender<(String, std::result::Result<(), String>)>,
) {
    tokio::spawn(async move {
        let result = run_client_config_with_listener(listener, config)
            .await
            .map_err(|error| format!("{error:?}"));
        let _ = exit_tx.send((tag, result)).await;
    });
}

async fn run_route_stack(
    listener: TcpListener,
    config: RouteProxyConfig,
    tun: Option<TunConfig>,
    mut outbound_rx: mpsc::Receiver<(String, std::result::Result<(), String>)>,
) -> Result<()> {
    if let Some(tun) = tun {
        let shutdown = TunCancellationToken::new();
        return tokio::select! {
            result = run_route_proxy(listener, config) => {
                shutdown.cancel();
                result
            }
            result = run_tun(tun, shutdown.clone()) => result.map(|_| ()),
            ended = outbound_rx.recv() => {
                shutdown.cancel();
                route_outbound_result(ended)
            }
        };
    }
    tokio::select! {
        result = run_route_proxy(listener, config) => result,
        ended = outbound_rx.recv() => route_outbound_result(ended),
    }
}

fn route_outbound_result(ended: Option<(String, std::result::Result<(), String>)>) -> Result<()> {
    let (tag, result) = ended.context("route outbound task channel closed")?;
    match result {
        Ok(()) => bail!("route outbound {tag} exited"),
        Err(error) => bail!("route outbound {tag} failed: {error}"),
    }
}

fn ephemeral_loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)
}

async fn run_singbox_server_config(config: SingBoxServerConfig) -> Result<()> {
    match config {
        SingBoxServerConfig::AnyTls(config) => run_server(config).await,
        SingBoxServerConfig::Hysteria2(config) => run_hysteria2_server(config).await,
        SingBoxServerConfig::Naive(config) => run_naive_server(config).await,
        SingBoxServerConfig::Shadowsocks(config) => run_shadowsocks_server(config).await,
        SingBoxServerConfig::Trojan(config) => run_trojan_server(config).await,
        SingBoxServerConfig::Tuic(config) => run_tuic_server(config).await,
        SingBoxServerConfig::Vless(config) => run_vless_server(config).await,
        SingBoxServerConfig::Vmess(config) => run_vmess_server(config).await,
    }
}

async fn run_xray_server_config(config: XrayServerConfig) -> Result<()> {
    match config {
        XrayServerConfig::Shadowsocks(config) => run_shadowsocks_server(config).await,
        XrayServerConfig::Hysteria2(config) => run_hysteria2_server(config).await,
        XrayServerConfig::Trojan(config) => run_trojan_server(config).await,
        XrayServerConfig::Vless(config) => run_vless_server(config).await,
        XrayServerConfig::Vmess(config) => run_vmess_server(config).await,
    }
}

fn select_mihomo_proxy<'a>(
    proxies: &'a [MihomoProxy],
    profile: Option<&str>,
) -> Result<&'a MihomoProxy> {
    if let Some(profile) = profile {
        return proxies
            .iter()
            .find(|proxy| proxy.name() == profile)
            .with_context(|| format!("mihomo proxy {profile} was not found"));
    }
    match proxies {
        [proxy] => Ok(proxy),
        [] => bail!("mihomo config has no proxies"),
        _ => bail!(
            "mihomo config has multiple proxies [{}]; pass --profile",
            proxies
                .iter()
                .map(MihomoProxy::name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn select_xray_outbound<'a>(
    outbounds: &'a [XrayOutbound],
    profile: Option<&str>,
) -> Result<&'a XrayOutbound> {
    if let Some(profile) = profile {
        return outbounds
            .iter()
            .find(|outbound| outbound.name() == profile)
            .with_context(|| format!("xray outbound {profile} was not found"));
    }
    match outbounds {
        [outbound] => Ok(outbound),
        [] => bail!("xray config has no outbounds"),
        _ => bail!(
            "xray config has multiple outbounds [{}]; pass --profile",
            outbounds
                .iter()
                .map(XrayOutbound::name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn select_xray_inbound<'a>(
    inbounds: &'a [aerion::config_compat::xray::XrayInbound],
    profile: Option<&str>,
) -> Result<&'a aerion::config_compat::xray::XrayInbound> {
    if let Some(profile) = profile {
        return inbounds
            .iter()
            .find(|inbound| inbound.name() == profile)
            .with_context(|| format!("xray config has no inbound profile {profile}"));
    }
    match inbounds {
        [] => bail!("xray server config has no inbounds"),
        [inbound] => Ok(inbound),
        _ => bail!(
            "xray config has multiple inbound profiles [{}]; pass --profile",
            inbounds
                .iter()
                .map(|inbound| inbound.name())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn select_singbox_outbound<'a>(
    config: &'a SingBoxConfig,
    profile: Option<&str>,
) -> Result<&'a SingBoxOutbound> {
    if let Some(profile) = profile {
        return config.resolved_outbound_profile(profile);
    }
    match config.outbounds.as_slice() {
        [outbound] => config.resolved_outbound_profile(outbound.name()),
        [] => bail!("sing-box config has no outbounds"),
        _ => bail!(
            "sing-box config has multiple outbounds [{}]; pass --profile",
            config
                .outbounds
                .iter()
                .map(SingBoxOutbound::name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn select_singbox_inbound<'a>(
    inbounds: &'a [aerion::config_compat::singbox::SingBoxInbound],
    profile: Option<&str>,
) -> Result<&'a aerion::config_compat::singbox::SingBoxInbound> {
    if let Some(profile) = profile {
        return inbounds
            .iter()
            .find(|inbound| inbound.name() == profile)
            .with_context(|| format!("sing-box config has no inbound profile {profile}"));
    }
    match inbounds {
        [] => bail!("sing-box server config has no inbounds"),
        [inbound] => Ok(inbound),
        _ => bail!(
            "sing-box config has multiple inbound profiles [{}]; pass --profile",
            inbounds
                .iter()
                .map(|inbound| inbound.name())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn native_client_name(client: &ClientFileConfig) -> &str {
    client.name.as_deref().unwrap_or(&client.protocol)
}

fn native_server_name(server: &ServerFileConfig) -> &str {
    server.name.as_deref().unwrap_or(&server.protocol)
}

fn native_profile_names(config: &AerionFileConfig) -> String {
    config
        .clients
        .iter()
        .map(native_client_name)
        .chain(config.servers.iter().map(native_server_name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .with_context(|| format!("invalid bracketed server address: {value}"))?;
        let port = tail
            .strip_prefix(':')
            .with_context(|| format!("server port is missing: {value}"))?
            .parse::<u16>()
            .with_context(|| format!("parse server port: {value}"))?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = value
        .rsplit_once(':')
        .with_context(|| format!("server address must be host:port: {value}"))?;
    if host.contains(':') {
        bail!("IPv6 server address must use [addr]:port form: {value}");
    }
    Ok((
        host.to_string(),
        port.parse::<u16>()
            .with_context(|| format!("parse server port: {value}"))?,
    ))
}

fn is_hysteria2(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("hysteria2") || protocol.eq_ignore_ascii_case("hy2")
}

fn is_mieru(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("mieru") || protocol.eq_ignore_ascii_case("mierus")
}

fn is_tuic(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("tuic")
}

fn is_naive(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("naive")
        || protocol.eq_ignore_ascii_case("naive+https")
        || protocol.eq_ignore_ascii_case("naive+quic")
}

fn is_shadowsocks(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("shadowsocks") || protocol.eq_ignore_ascii_case("ss")
}

fn is_socks_proxy(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("socks")
        || protocol.eq_ignore_ascii_case("socks5")
        || protocol.eq_ignore_ascii_case("socks5h")
}

fn is_http_proxy(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("http")
        || protocol.eq_ignore_ascii_case("https")
        || protocol.eq_ignore_ascii_case("http-proxy")
        || protocol.eq_ignore_ascii_case("https-proxy")
        || protocol.eq_ignore_ascii_case("http+tls")
}

fn is_trojan(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("trojan")
}

fn is_vless(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("vless")
}

fn is_vmess(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("vmess")
}

fn native_user_id(user_id: Option<String>, username: &str, label: &str) -> Result<String> {
    user_id
        .or_else(|| {
            let username = username.trim();
            (!username.is_empty() && username != "default").then(|| username.to_string())
        })
        .with_context(|| format!("{label} requires uuid/user_id"))
}

fn native_vless_transport(
    network: Option<&str>,
    path: Option<String>,
    host: Option<String>,
    headers: BTreeMap<String, String>,
) -> Result<VlessTransportConfig> {
    VlessTransportConfig::from_network(
        network.unwrap_or("tcp"),
        path,
        host,
        headers.into_iter().collect(),
    )
}

fn ensure_supported_protocol(protocol: &str) -> Result<()> {
    if protocol.eq_ignore_ascii_case("anytls") {
        Ok(())
    } else {
        bail!("unsupported protocol: {protocol}");
    }
}
