pub(crate) const SESSION_RESUME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
use crate::tls::ServerTlsMaterial;
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless_transport::VlessTransportConfig;
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAX_FLUX_EXPANDED_PORTS: usize = 64;
pub const DEFAULT_STANDBY_CHANNELS: usize = 2;
pub const DEFAULT_CHANNEL_MAX_MBPS: u64 = 20;
pub const DEFAULT_ROTATION_INTERVAL_SEC: u64 = 180;
pub const DEFAULT_ROTATION_BYTES_MB: u64 = 96;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FluxIpStrategy {
    #[serde(alias = "auto", alias = "both", alias = "dual-stack")]
    Dual,
    #[default]
    #[serde(
        alias = "latency-first",
        alias = "latency_first",
        alias = "lowest_latency",
        alias = "lowest-latency",
        alias = "rtt"
    )]
    Latency,
    #[serde(alias = "prefer-v4", alias = "ipv4_first")]
    PreferV4,
    #[serde(alias = "prefer-v6", alias = "ipv6_first")]
    PreferV6,
    #[serde(alias = "v4-only", alias = "ipv4", alias = "ipv4_only")]
    V4Only,
    #[serde(alias = "v6-only", alias = "ipv6", alias = "ipv6_only")]
    V6Only,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum FluxTransportKind {
    #[default]
    #[serde(alias = "raw")]
    Tcp,
    #[serde(alias = "quic", alias = "h3")]
    Udp,
    #[serde(alias = "ws", alias = "websocket", alias = "httpupgrade", alias = "h2")]
    Http,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum FluxHttpMode {
    #[default]
    #[serde(alias = "websocket")]
    Ws,
    #[serde(alias = "http-upgrade", alias = "http_upgrade", alias = "upgrade")]
    HttpUpgrade,
    #[serde(alias = "http2", alias = "http")]
    H2,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum FluxSecurityMode {
    #[default]
    #[serde(alias = "salamander")]
    Obfs,
    Tls,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FluxCertMode {
    #[default]
    Inherit,
    #[serde(alias = "path")]
    File,
    #[serde(alias = "origin-plain", alias = "none", alias = "plain")]
    OriginPlain,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FluxChannelRole {
    #[default]
    #[serde(alias = "equal", alias = "normal")]
    Primary,
    #[serde(alias = "high", alias = "preferred")]
    Prefer,
    #[serde(
        alias = "udp_only",
        alias = "udp-only",
        alias = "udp-relay",
        alias = "udp"
    )]
    UdpRelay,
    #[serde(alias = "standby", alias = "failover")]
    Backup,
}

impl FluxChannelRole {
    pub fn normalized_for_transport(self, transport: FluxTransportKind) -> Self {
        if self == Self::UdpRelay && transport != FluxTransportKind::Udp {
            Self::Primary
        } else {
            self
        }
    }

    pub fn is_primary_tier(self) -> bool {
        matches!(self, Self::Primary | Self::Prefer)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct FluxOptions {
    #[serde(alias = "ip-strategy")]
    pub ip_strategy: FluxIpStrategy,
    #[serde(alias = "standby-channels")]
    pub standby_channels: usize,
    #[serde(
        default = "default_channel_max_mbps",
        alias = "channel-max-mbps",
        alias = "channelMaxMbps"
    )]
    pub channel_max_mbps: u64,
    #[serde(alias = "rotation-interval-sec", alias = "rotation-interval")]
    pub rotation_interval_sec: u64,
    #[serde(alias = "rotation-bytes-mb", alias = "rotation-bytes")]
    pub rotation_bytes_mb: u64,
}

fn default_channel_max_mbps() -> u64 {
    DEFAULT_CHANNEL_MAX_MBPS
}

impl Default for FluxOptions {
    fn default() -> Self {
        Self {
            ip_strategy: FluxIpStrategy::Latency,
            standby_channels: DEFAULT_STANDBY_CHANNELS,
            channel_max_mbps: DEFAULT_CHANNEL_MAX_MBPS,
            rotation_interval_sec: DEFAULT_ROTATION_INTERVAL_SEC,
            rotation_bytes_mb: DEFAULT_ROTATION_BYTES_MB,
        }
    }
}

impl FluxOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.standby_channels <= 16,
            "Flux standby_channels must be at most 16"
        );
        ensure!(
            self.channel_max_mbps <= 10_000,
            "Flux channel_max_mbps must be at most 10000"
        );
        Ok(())
    }

    pub fn channel_max_bytes_per_sec(&self) -> Option<u64> {
        (self.channel_max_mbps > 0).then(|| self.channel_max_mbps.saturating_mul(125_000))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum PortSpecInput {
    Number(u16),
    Text(String),
    List(Vec<u16>),
}

impl Default for PortSpecInput {
    fn default() -> Self {
        Self::Text(String::new())
    }
}

impl PortSpecInput {
    pub fn to_spec_string(&self) -> String {
        match self {
            Self::Number(port) => port.to_string(),
            Self::Text(text) => text.trim().to_string(),
            Self::List(list) => list
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

pub fn parse_port_spec(spec: &str, max_ports: usize) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    let mut seen = HashSet::new();
    for token in spec.split([',', ';', ' ']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start_raw, end_raw)) = token.split_once('-') {
            let start: u16 = start_raw
                .trim()
                .parse()
                .with_context(|| format!("invalid Flux port range start: {token}"))?;
            let end: u16 = end_raw
                .trim()
                .parse()
                .with_context(|| format!("invalid Flux port range end: {token}"))?;
            ensure!(
                start > 0 && start <= end,
                "invalid Flux port range {start}-{end}"
            );
            let span = usize::from(end - start) + 1;
            ensure!(
                ports.len() + span <= max_ports,
                "Flux expanded ports exceed limit of {max_ports}"
            );
            for port in start..=end {
                if seen.insert(port) {
                    ports.push(port);
                }
            }
        } else {
            let port: u16 = token
                .parse()
                .with_context(|| format!("invalid Flux port: {token}"))?;
            ensure!(port > 0, "Flux port cannot be 0");
            if seen.insert(port) {
                ensure!(
                    ports.len() < max_ports,
                    "Flux expanded ports exceed limit of {max_ports}"
                );
                ports.push(port);
            }
        }
    }
    ensure!(!ports.is_empty(), "Flux port specification is empty");
    Ok(ports)
}

pub fn parse_flux_x25519_key(raw: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    ensure!(!trimmed.is_empty(), "Flux X25519 key is empty");
    let bytes = if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(trimmed).context("decode Flux hex X25519 key")?
    } else {
        URL_SAFE_NO_PAD
            .decode(trimmed)
            .or_else(|_| URL_SAFE.decode(trimmed))
            .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
            .or_else(|_| STANDARD.decode(trimmed))
            .context("decode Flux base64 X25519 key")?
    };
    ensure!(bytes.len() == 32, "Flux X25519 key must be 32 bytes");
    let key: [u8; 32] = bytes.try_into().expect("32-byte key");
    ensure!(
        key.iter().any(|&b| b != 0),
        "Flux X25519 key cannot be all zeros"
    );
    Ok(key)
}

pub fn generate_flux_x25519_keypair() -> Result<(String, String)> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("Flux X25519 keygen: {e}"))?;
    let secret = StaticSecret::from(raw);
    let public = PublicKey::from(&secret);
    Ok((
        URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        URL_SAFE_NO_PAD.encode(public.to_bytes()),
    ))
}

pub fn derive_flux_x25519_public_key(private_key: &str) -> Result<String> {
    let raw = parse_flux_x25519_key(private_key)?;
    let secret = StaticSecret::from(raw);
    let public = PublicKey::from(&secret);
    Ok(URL_SAFE_NO_PAD.encode(public.to_bytes()))
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FluxChannelWireConfig {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(alias = "connect_host", alias = "connect-host", alias = "host")]
    pub server: String,
    #[serde(
        alias = "connect_ports",
        alias = "connect-ports",
        alias = "port",
        default
    )]
    pub ports: PortSpecInput,
    #[serde(alias = "ip-version", default = "default_auto")]
    pub ip_version: String,
    #[serde(alias = "resolved-v4")]
    pub resolved_v4: Vec<Ipv4Addr>,
    #[serde(alias = "resolved-v6")]
    pub resolved_v6: Vec<Ipv6Addr>,
    pub transport: Option<String>,
    #[serde(alias = "http-mode")]
    pub http_mode: Option<FluxHttpMode>,
    #[serde(alias = "http-host")]
    pub http_host: Option<String>,
    #[serde(alias = "http-path", default = "default_slash")]
    pub http_path: String,
    #[serde(alias = "http-headers")]
    pub http_headers: BTreeMap<String, String>,
    pub security: Option<FluxSecurityMode>,
    #[serde(alias = "servername", alias = "server_name", alias = "server-name")]
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    #[serde(
        default,
        alias = "client-fingerprint",
        alias = "client_fingerprint",
        deserialize_with = "deserialize_optional_fingerprint"
    )]
    pub fingerprint: Option<UtlsFingerprint>,
    #[serde(
        alias = "skip-cert-verify",
        alias = "skip_cert_verify",
        alias = "allow_insecure"
    )]
    pub insecure: Option<bool>,
    #[serde(alias = "public-key", alias = "publicKey")]
    pub public_key: Option<String>,
    #[serde(default = "default_true", alias = "tls-binding")]
    pub tls_binding: bool,
    pub role: FluxChannelRole,
    #[serde(default = "default_weight")]
    pub weight: u8,
}

fn default_true() -> bool {
    true
}

fn default_auto() -> String {
    "auto".to_string()
}

fn default_slash() -> String {
    "/".to_string()
}

fn default_weight() -> u8 {
    100
}

impl FluxChannelWireConfig {
    pub fn into_client_channel(
        self,
        index: usize,
        default_host: &str,
        default_port: u16,
        default_sni: Option<&str>,
        default_fingerprint: Option<UtlsFingerprint>,
        default_insecure: bool,
        remaining_port_budget: usize,
    ) -> Result<Option<FluxChannelClientConfig>> {
        if !self.enabled {
            return Ok(None);
        }
        let id = if self.id.trim().is_empty() {
            format!("ch-{}", index + 1)
        } else {
            self.id.trim().to_string()
        };
        let server_host = if self.server.trim().is_empty() {
            default_host.trim().to_string()
        } else {
            self.server.trim().to_string()
        };
        ensure!(
            !server_host.is_empty(),
            "Flux channel {id} server host is empty"
        );
        let port_spec = self.ports.to_spec_string();
        let ports = if port_spec.is_empty() || port_spec == "0" {
            ensure!(default_port > 0, "Flux channel {id} port is missing");
            ensure!(
                remaining_port_budget >= 1,
                "Flux expanded ports exceed limit of {MAX_FLUX_EXPANDED_PORTS}"
            );
            vec![default_port]
        } else {
            parse_port_spec(&port_spec, remaining_port_budget)?
        };
        let (transport, inferred_http_mode) = parse_transport_and_mode(self.transport.as_deref())?;
        let http_mode = self.http_mode.or(inferred_http_mode).unwrap_or_default();
        let security = self.security.unwrap_or_else(|| {
            if self
                .public_key
                .as_deref()
                .is_some_and(|v| !v.trim().is_empty())
            {
                FluxSecurityMode::Obfs
            } else {
                FluxSecurityMode::Tls
            }
        });
        let role = self.role.normalized_for_transport(transport);
        let ip_version = normalize_ip_version(&self.ip_version)?;
        let sni = self
            .sni
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .or_else(|| default_sni.map(str::trim).filter(|v| !v.is_empty()))
            .unwrap_or(&server_host)
            .to_string();
        let (public_key, tls_binding) = match security {
            FluxSecurityMode::Obfs => {
                let key = self
                    .public_key
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .with_context(|| format!("Flux channel {id} obfs requires public_key"))?;
                let _ = parse_flux_x25519_key(key)
                    .with_context(|| format!("Flux channel {id} has invalid public_key"))?;
                (Some(key.to_string()), false)
            }
            FluxSecurityMode::Tls => (None, self.tls_binding),
        };
        ensure!(
            (1..=100).contains(&self.weight),
            "Flux channel {id} weight must be between 1 and 100"
        );
        Ok(Some(FluxChannelClientConfig {
            id,
            server_host,
            ports,
            ip_version,
            resolved_v4: self.resolved_v4,
            resolved_v6: self.resolved_v6,
            transport,
            http_mode,
            http_host: self.http_host.filter(|h| !h.trim().is_empty()),
            http_path: if self.http_path.trim().is_empty() {
                "/".to_string()
            } else if self.http_path.starts_with('/') {
                self.http_path
            } else {
                format!("/{}", self.http_path)
            },
            http_headers: self.http_headers,
            security,
            sni,
            alpn: self.alpn,
            fingerprint: self.fingerprint.or(default_fingerprint),
            insecure: self.insecure.unwrap_or(default_insecure),
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            pinned_cert_sha256: Vec::new(),
            public_key,
            tls_binding,
            role,
            weight: self.weight,
        }))
    }
}

pub fn parse_transport_and_mode(
    raw: Option<&str>,
) -> Result<(FluxTransportKind, Option<FluxHttpMode>)> {
    let normalized = raw
        .unwrap_or("tcp")
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    match normalized.as_str() {
        "" | "tcp" | "raw" => Ok((FluxTransportKind::Tcp, None)),
        "udp" | "quic" | "h3" => Ok((FluxTransportKind::Udp, None)),
        "http" | "ws" | "websocket" => Ok((FluxTransportKind::Http, Some(FluxHttpMode::Ws))),
        "httpupgrade" | "upgrade" => Ok((FluxTransportKind::Http, Some(FluxHttpMode::HttpUpgrade))),
        "h2" | "http2" => Ok((FluxTransportKind::Http, Some(FluxHttpMode::H2))),
        other => bail!("unsupported Flux channel transport {other}"),
    }
}

pub fn normalize_ip_version(raw: &str) -> Result<String> {
    let v = raw.trim().to_ascii_lowercase().replace(['-', '_'], "");
    match v.as_str() {
        "" | "auto" | "dual" | "both" => Ok("auto".to_string()),
        "ipv4" | "v4" | "4" => Ok("ipv4".to_string()),
        "ipv6" | "v6" | "6" => Ok("ipv6".to_string()),
        other => bail!("unsupported Flux channel ip_version {other}"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FluxChannelClientConfig {
    pub id: String,
    pub server_host: String,
    pub ports: Vec<u16>,
    pub ip_version: String,
    pub resolved_v4: Vec<Ipv4Addr>,
    pub resolved_v6: Vec<Ipv6Addr>,
    pub transport: FluxTransportKind,
    pub http_mode: FluxHttpMode,
    pub http_host: Option<String>,
    pub http_path: String,
    pub http_headers: BTreeMap<String, String>,
    pub security: FluxSecurityMode,
    pub sni: String,
    pub alpn: Vec<String>,
    pub fingerprint: Option<UtlsFingerprint>,
    pub insecure: bool,
    pub ca_cert_paths: Vec<PathBuf>,
    pub ca_certificates: Vec<String>,
    pub pinned_cert_sha256: Vec<String>,
    pub public_key: Option<String>,
    pub tls_binding: bool,
    pub role: FluxChannelRole,
    pub weight: u8,
}

impl FluxChannelClientConfig {
    pub fn to_vless_transport(&self) -> VlessTransportConfig {
        let headers = self
            .http_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        match self.transport {
            FluxTransportKind::Tcp | FluxTransportKind::Udp => VlessTransportConfig::tcp(),
            FluxTransportKind::Http => match self.http_mode {
                FluxHttpMode::Ws => VlessTransportConfig::websocket(
                    Some(self.http_path.clone()),
                    self.http_host.clone(),
                    headers,
                ),
                FluxHttpMode::HttpUpgrade => VlessTransportConfig::http_upgrade(
                    Some(self.http_path.clone()),
                    self.http_host.clone(),
                    headers,
                ),
                FluxHttpMode::H2 => VlessTransportConfig::http2(
                    Some(self.http_path.clone()),
                    self.http_host.clone(),
                    headers,
                ),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FluxClientConfig {
    pub listen: SocketAddr,
    pub server_host: String,
    pub server_port: u16,
    pub key: String,
    pub udp: bool,
    pub options: FluxOptions,
    pub channels: Vec<FluxChannelClientConfig>,
}

impl FluxClientConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.key.trim().is_empty(), "Flux key is empty");
        self.options.validate()?;
        ensure!(
            !self.channels.is_empty(),
            "Flux client requires at least one enabled channel"
        );
        let mut total_ports = 0usize;
        for channel in &self.channels {
            ensure!(
                !channel.server_host.trim().is_empty(),
                "Flux channel {} server_host is empty",
                channel.id
            );
            ensure!(
                !channel.ports.is_empty(),
                "Flux channel {} has no ports",
                channel.id
            );
            total_ports += channel.ports.len();
            ensure!(
                total_ports <= MAX_FLUX_EXPANDED_PORTS,
                "Flux expanded ports exceed limit of {MAX_FLUX_EXPANDED_PORTS}"
            );
            match channel.security {
                FluxSecurityMode::Tls => {
                    ensure!(
                        !channel.sni.trim().is_empty(),
                        "Flux channel {} TLS requires sni",
                        channel.id
                    );
                }
                FluxSecurityMode::Obfs => {
                    let key = channel
                        .public_key
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .with_context(|| {
                            format!("Flux channel {} obfs requires public_key", channel.id)
                        })?;
                    parse_flux_x25519_key(key)?;
                }
            }
        }
        Ok(())
    }

    pub fn all_static_ips(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        if let Ok(ip) = self.server_host.trim_matches(['[', ']']).parse::<IpAddr>()
            && seen.insert(ip)
        {
            out.push(ip);
        }
        for channel in &self.channels {
            if let Ok(ip) = channel
                .server_host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                && seen.insert(ip)
            {
                out.push(ip);
            }
            for v4 in &channel.resolved_v4 {
                let ip = IpAddr::V4(*v4);
                if seen.insert(ip) {
                    out.push(ip);
                }
            }
            for v6 in &channel.resolved_v6 {
                let ip = IpAddr::V6(*v6);
                if seen.insert(ip) {
                    out.push(ip);
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug)]
pub struct FluxChannelServerConfig {
    pub id: String,
    pub listen_ip: IpAddr,
    pub ports: Vec<u16>,
    pub transport: FluxTransportKind,
    pub http_mode: FluxHttpMode,
    pub http_host: Option<String>,
    pub http_path: String,
    pub http_headers: BTreeMap<String, String>,
    pub security: FluxSecurityMode,
    pub cert_mode: FluxCertMode,
    pub tls_material: Option<ServerTlsMaterial>,
    pub private_key: Option<String>,
}

impl FluxChannelServerConfig {
    pub fn to_vless_transport(&self) -> VlessTransportConfig {
        let headers = self
            .http_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        match self.transport {
            FluxTransportKind::Tcp | FluxTransportKind::Udp => VlessTransportConfig::tcp(),
            FluxTransportKind::Http => match self.http_mode {
                FluxHttpMode::Ws => VlessTransportConfig::websocket(
                    Some(self.http_path.clone()),
                    self.http_host.clone(),
                    headers,
                ),
                FluxHttpMode::HttpUpgrade => VlessTransportConfig::http_upgrade(
                    Some(self.http_path.clone()),
                    self.http_host.clone(),
                    headers,
                ),
                FluxHttpMode::H2 => VlessTransportConfig::http2(
                    Some(self.http_path.clone()),
                    self.http_host.clone(),
                    headers,
                ),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct FluxServerConfig {
    pub key: String,
    pub users: Vec<String>,
    pub udp: bool,
    pub listeners: Vec<FluxChannelServerConfig>,
}

impl FluxServerConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.listeners.is_empty(),
            "Flux server requires at least one channel listener"
        );
        let mut total_ports = 0usize;
        let mut bound = HashSet::new();
        for listener in &self.listeners {
            ensure!(
                !listener.ports.is_empty(),
                "Flux server listener {} has no ports",
                listener.id
            );
            total_ports += listener.ports.len();
            ensure!(
                total_ports <= MAX_FLUX_EXPANDED_PORTS,
                "Flux server expanded ports exceed limit of {MAX_FLUX_EXPANDED_PORTS}"
            );
            let is_udp = matches!(listener.transport, FluxTransportKind::Udp);
            for port in &listener.ports {
                ensure!(
                    bound.insert((listener.listen_ip, *port, is_udp)),
                    "conflicting Flux server listener on {}:{}/{}",
                    listener.listen_ip,
                    port,
                    if is_udp { "udp" } else { "tcp" }
                );
            }
            match listener.security {
                FluxSecurityMode::Tls => match listener.cert_mode {
                    FluxCertMode::OriginPlain => {
                        ensure!(
                            !is_udp,
                            "Flux UDP listener {} cannot use origin_plain without TLS",
                            listener.id
                        );
                    }
                    FluxCertMode::Inherit | FluxCertMode::File => {
                        let material = listener.tls_material.as_ref().with_context(|| {
                            format!(
                                "Flux listener {} missing TLS certificate material",
                                listener.id
                            )
                        })?;
                        material.ensure_supported()?;
                    }
                },
                FluxSecurityMode::Obfs => {
                    let key = listener
                        .private_key
                        .as_deref()
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .with_context(|| {
                            format!("Flux listener {} obfs requires private_key", listener.id)
                        })?;
                    parse_flux_x25519_key(key)?;
                }
            }
        }
        Ok(())
    }
}
