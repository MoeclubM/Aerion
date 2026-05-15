use aerion::config::{FileConfig, default_heartbeat_interval_secs, load_config};
use aerion::hysteria2::{Hysteria2ClientConfig, Hysteria2ServerConfig};
use aerion::mieru::{MieruClientConfig, MieruServerConfig, MieruTransport, parse_mieru_user};
use aerion::padding::PaddingScheme;
use aerion::{
    ClientConfig, ServerConfig, run_client, run_hysteria2_client, run_hysteria2_server,
    run_mieru_client, run_mieru_server, run_server, tls,
};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
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
        #[arg(long)]
        obfs: Option<String>,
        #[arg(long = "obfs-password")]
        obfs_password: Option<String>,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tls::init_crypto();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "aerion=info".into()))
        .init();

    match Cli::parse().command {
        Command::Run { config } => match load_config(&config)? {
            FileConfig::Client { client } => {
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
                        obfs: client.obfs,
                        obfs_password: client.obfs_password,
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
                    padding_scheme: client.padding_scheme,
                    heartbeat_interval_secs: client.heartbeat_interval_secs,
                })
                .await
            }
            FileConfig::Server { server } => {
                if is_hysteria2(&server.protocol) {
                    return run_hysteria2_server(Hysteria2ServerConfig {
                        listen: server.listen,
                        password: server.password,
                        users: server.users,
                        cert_path: server
                            .cert
                            .context("server cert is required for Hysteria2")?,
                        key_path: server.key.context("server key is required for Hysteria2")?,
                        obfs: server.obfs,
                        obfs_password: server.obfs_password,
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
                    })
                    .await;
                }
                ensure_supported_protocol(&server.protocol)?;
                run_server(ServerConfig {
                    listen: server.listen,
                    password: server.password,
                    users: server.users,
                    cert_path: server.cert.context("server cert is required for AnyTLS")?,
                    key_path: server.key.context("server key is required for AnyTLS")?,
                    padding_scheme: server.padding_scheme,
                    heartbeat_interval_secs: server.heartbeat_interval_secs,
                })
                .await
            }
            FileConfig::Mihomo(config) => {
                bail!(
                    "mihomo YAML parsed {} proxies, but aerion run needs an explicit Aerion client/server TOML config; use aerion::config_compat::mihomo helpers to select one proxy for the core",
                    config.proxies.len()
                )
            }
            FileConfig::Xray(config) => {
                bail!(
                    "xray JSON parsed {} outbounds, but aerion run needs an explicit Aerion client/server TOML config; use aerion::config_compat::xray helpers to select one outbound for the core",
                    config.outbounds.len()
                )
            }
            FileConfig::SingBox(config) => {
                bail!(
                    "sing-box JSON parsed {} outbounds, but aerion run needs an explicit Aerion client/server TOML config; use aerion::config_compat::singbox helpers to select one outbound for the core",
                    config.outbounds.len()
                )
            }
        },
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
            obfs,
            obfs_password,
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
                obfs,
                obfs_password,
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
                obfs,
                obfs_password,
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
            })
            .await
        }
    }
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

fn ensure_supported_protocol(protocol: &str) -> Result<()> {
    if protocol.eq_ignore_ascii_case("anytls") {
        Ok(())
    } else {
        bail!("unsupported protocol: {protocol}");
    }
}
