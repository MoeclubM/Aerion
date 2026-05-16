use crate::client::ClientConfig;
use crate::hysteria2::Hysteria2ClientConfig;
use crate::mieru::{MieruClientConfig, MieruTrafficPattern, MieruTransport};
use crate::naive::NaiveClientConfig;
use crate::padding::PaddingScheme;
use crate::reality::RealityClientConfig;
use crate::shadowsocks::ShadowsocksClientConfig;
use crate::trojan::TrojanClientConfig;
use crate::tuic::TuicClientConfig;
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::VlessClientConfig;
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::VmessClientConfig;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer, de};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoConfig {
    #[serde(default, rename = "mixed-port", alias = "mixed_port")]
    pub mixed_port: Option<u16>,
    #[serde(default, rename = "socks-port", alias = "socks_port")]
    pub socks_port: Option<u16>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default, rename = "allow-lan", alias = "allow_lan")]
    pub allow_lan: bool,
    #[serde(default, rename = "bind-address", alias = "bind_address")]
    pub bind_address: Option<String>,
    #[serde(default)]
    pub proxies: Vec<MihomoProxy>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum MihomoProxy {
    #[serde(rename = "ss", alias = "shadowsocks")]
    Shadowsocks(MihomoShadowsocksProxy),
    Vless(MihomoVlessProxy),
    Vmess(MihomoVmessProxy),
    Trojan(MihomoTrojanProxy),
    #[serde(rename = "hysteria2", alias = "hy2")]
    Hysteria2(MihomoHysteria2Proxy),
    #[serde(rename = "anytls", alias = "any-tls")]
    AnyTls(MihomoAnyTlsProxy),
    Mieru(MihomoMieruProxy),
    #[serde(rename = "naive", alias = "naive+https", alias = "naive+quic")]
    Naive(MihomoNaiveProxy),
    Tuic(MihomoTuicProxy),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoShadowsocksProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default, rename = "plugin-opts", alias = "plugin_opts")]
    pub plugin_opts: Option<BTreeMap<String, String>>,
    #[serde(default, rename = "udp-over-tcp", alias = "udp_over_tcp")]
    pub udp_over_tcp: Option<MihomoUdpOverTcpOptions>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoVlessProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default = "default_tcp")]
    pub network: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default, rename = "packet-encoding", alias = "packet_encoding")]
    pub packet_encoding: String,
    #[serde(default, alias = "server-name", alias = "sni")]
    pub servername: Option<String>,
    #[serde(
        default,
        rename = "client-fingerprint",
        alias = "client_fingerprint",
        deserialize_with = "deserialize_optional_fingerprint"
    )]
    pub client_fingerprint: Option<UtlsFingerprint>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default, rename = "reality-opts", alias = "reality_opts")]
    pub reality_opts: Option<MihomoRealityOpts>,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default)]
    pub mux: bool,
    #[serde(default)]
    pub smux: Option<MihomoSmuxOptions>,
    #[serde(default, rename = "ws-opts", alias = "ws_opts")]
    pub ws_opts: Option<MihomoWsOptions>,
    #[serde(default, rename = "grpc-opts", alias = "grpc_opts")]
    pub grpc_opts: Option<MihomoGrpcOptions>,
    #[serde(
        default,
        rename = "xhttp-opts",
        alias = "xhttp_opts",
        alias = "splithttp-opts",
        alias = "splithttp_opts"
    )]
    pub xhttp_opts: Option<MihomoXhttpOptions>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoVmessProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default, rename = "alterId", alias = "alter_id")]
    pub alter_id: u16,
    #[serde(default = "default_vmess_cipher")]
    pub cipher: String,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "default_tcp")]
    pub network: String,
    #[serde(default, alias = "server-name", alias = "sni")]
    pub servername: Option<String>,
    #[serde(
        default,
        rename = "client-fingerprint",
        alias = "client_fingerprint",
        deserialize_with = "deserialize_optional_fingerprint"
    )]
    pub client_fingerprint: Option<UtlsFingerprint>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default, rename = "ws-opts", alias = "ws_opts")]
    pub ws_opts: Option<MihomoWsOptions>,
    #[serde(default, rename = "grpc-opts", alias = "grpc_opts")]
    pub grpc_opts: Option<MihomoGrpcOptions>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoTrojanProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default = "default_tcp")]
    pub network: String,
    #[serde(default, alias = "servername", alias = "server-name")]
    pub sni: Option<String>,
    #[serde(
        default,
        rename = "client-fingerprint",
        alias = "client_fingerprint",
        deserialize_with = "deserialize_optional_fingerprint"
    )]
    pub client_fingerprint: Option<UtlsFingerprint>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default, rename = "ws-opts", alias = "ws_opts")]
    pub ws_opts: Option<MihomoWsOptions>,
    #[serde(default, rename = "grpc-opts", alias = "grpc_opts")]
    pub grpc_opts: Option<MihomoGrpcOptions>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoHysteria2Proxy {
    pub name: String,
    pub server: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ports: Option<String>,
    pub password: String,
    #[serde(default, alias = "servername", alias = "server-name")]
    pub sni: Option<String>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, rename = "obfs-password", alias = "obfs_password")]
    pub obfs_password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_bandwidth_mbps")]
    pub down: Option<u64>,
    #[serde(
        default = "default_hy2_congestion_control",
        rename = "congestion-control"
    )]
    pub congestion_control: String,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoMieruProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    pub password: String,
    #[serde(default = "default_tcp")]
    pub transport: String,
    #[serde(default, rename = "traffic-pattern", alias = "traffic_pattern")]
    pub traffic_pattern: Option<String>,
    #[serde(default, rename = "nonce-pattern", alias = "nonce_pattern")]
    pub nonce_pattern: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoAnyTlsProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default, alias = "servername", alias = "server-name", alias = "sni")]
    pub servername: Option<String>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default, rename = "padding-scheme", alias = "padding_scheme")]
    pub padding_scheme: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoNaiveProxy {
    pub name: String,
    pub server: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default, alias = "servername", alias = "server-name", alias = "sni")]
    pub servername: Option<String>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub quic: bool,
    #[serde(default, rename = "udp-over-tcp", alias = "udp_over_tcp")]
    pub udp_over_tcp: Option<MihomoUdpOverTcpOptions>,
    #[serde(default, rename = "extra-headers", alias = "extra_headers")]
    pub extra_headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoTuicProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default, alias = "servername", alias = "server-name", alias = "sni")]
    pub servername: Option<String>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(
        default = "default_tuic_congestion_control",
        rename = "congestion-controller",
        alias = "congestion_control",
        alias = "congestion-control"
    )]
    pub congestion_control: String,
    #[serde(
        default = "default_tuic_udp_relay_mode",
        rename = "udp-relay-mode",
        alias = "udp_relay_mode"
    )]
    pub udp_relay_mode: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoRealityOpts {
    #[serde(rename = "public-key", alias = "public_key")]
    pub public_key: String,
    #[serde(default, rename = "short-id", alias = "short_id")]
    pub short_id: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoSmuxOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default, rename = "max-connections", alias = "max_connections")]
    pub max_connections: Option<u32>,
    #[serde(default, rename = "min-streams", alias = "min_streams")]
    pub min_streams: Option<u32>,
    #[serde(default, rename = "max-streams", alias = "max_streams")]
    pub max_streams: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoWsOptions {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoGrpcOptions {
    #[serde(default, rename = "grpc-service-name", alias = "grpc_service_name")]
    pub grpc_service_name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoXhttpOptions {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoUdpOverTcpOptions {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrManyStrings {
    One(String),
    Many(Vec<String>),
}

#[derive(Clone, Debug)]
pub enum MihomoClientConfig {
    Shadowsocks(ShadowsocksClientConfig),
    Vless(VlessClientConfig),
    Vmess(VmessClientConfig),
    Trojan(TrojanClientConfig),
    Hysteria2(Hysteria2ClientConfig),
    AnyTls(ClientConfig),
    Mieru(MieruClientConfig),
    Naive(NaiveClientConfig),
    Tuic(TuicClientConfig),
}

impl MihomoConfig {
    pub fn proxy(&self, name: &str) -> Option<&MihomoProxy> {
        self.proxies.iter().find(|proxy| proxy.name() == name)
    }

    pub fn local_socks_listen(&self) -> Result<Option<SocketAddr>> {
        let Some(port) = self.mixed_port.or(self.socks_port).or(self.port) else {
            return Ok(None);
        };
        let ip = match self.bind_address.as_deref().map(str::trim) {
            Some("") | None if self.allow_lan => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Some("") | None => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some("*") => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Some(value) => value
                .parse()
                .with_context(|| format!("parse mihomo bind-address {value}"))?,
        };
        Ok(Some(SocketAddr::new(ip, port)))
    }
}

impl MihomoProxy {
    pub fn name(&self) -> &str {
        match self {
            Self::Shadowsocks(proxy) => &proxy.name,
            Self::Vless(proxy) => &proxy.name,
            Self::Vmess(proxy) => &proxy.name,
            Self::Trojan(proxy) => &proxy.name,
            Self::Hysteria2(proxy) => &proxy.name,
            Self::AnyTls(proxy) => &proxy.name,
            Self::Mieru(proxy) => &proxy.name,
            Self::Naive(proxy) => &proxy.name,
            Self::Tuic(proxy) => &proxy.name,
        }
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<MihomoClientConfig> {
        Ok(match self {
            Self::Shadowsocks(proxy) => {
                MihomoClientConfig::Shadowsocks(proxy.to_client_config(listen)?)
            }
            Self::Vless(proxy) => MihomoClientConfig::Vless(proxy.to_client_config(listen)?),
            Self::Vmess(proxy) => MihomoClientConfig::Vmess(proxy.to_client_config(listen)?),
            Self::Trojan(proxy) => MihomoClientConfig::Trojan(proxy.to_client_config(listen)?),
            Self::Hysteria2(proxy) => {
                MihomoClientConfig::Hysteria2(proxy.to_client_config(listen)?)
            }
            Self::AnyTls(proxy) => MihomoClientConfig::AnyTls(proxy.to_client_config(listen)?),
            Self::Mieru(proxy) => MihomoClientConfig::Mieru(proxy.to_client_config(listen)?),
            Self::Naive(proxy) => MihomoClientConfig::Naive(proxy.to_client_config(listen)?),
            Self::Tuic(proxy) => MihomoClientConfig::Tuic(proxy.to_client_config(listen)?),
        })
    }
}

impl MihomoShadowsocksProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<ShadowsocksClientConfig> {
        ensure!(
            self.plugin
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
                && self.plugin_opts.as_ref().is_none_or(BTreeMap::is_empty),
            "mihomo Shadowsocks proxy {} uses SIP003 plugin; Aerion Shadowsocks does not implement plugins",
            self.name
        );
        ensure!(
            !self
                .udp_over_tcp
                .as_ref()
                .map(|opts| opts.enabled)
                .unwrap_or(false),
            "mihomo Shadowsocks proxy {} enables UDP-over-TCP; Aerion Shadowsocks does not implement UDP-over-TCP",
            self.name
        );
        Ok(ShadowsocksClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            method: self.cipher.clone(),
            password: self.password.clone(),
            udp: self.udp,
        })
    }
}

impl MihomoVlessProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<VlessClientConfig> {
        let reality = self
            .reality_opts
            .as_ref()
            .map(MihomoRealityOpts::to_client_config)
            .transpose()?;
        let network = self.network.trim();
        let transport = if network.eq_ignore_ascii_case("grpc") {
            VlessTransportConfig::from_network(
                network,
                self.grpc_opts
                    .as_ref()
                    .and_then(|opts| opts.grpc_service_name.clone()),
                None,
                Vec::new(),
            )?
        } else if network.eq_ignore_ascii_case("xhttp") || network.eq_ignore_ascii_case("splithttp")
        {
            let opts = self.xhttp_opts.as_ref();
            VlessTransportConfig::xhttp(
                opts.and_then(|opts| opts.path.clone()),
                opts.and_then(|opts| opts.host.clone()),
                opts.map(|opts| opts.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
                opts.and_then(|opts| opts.mode.clone()),
            )?
        } else {
            VlessTransportConfig::from_headers(
                network,
                self.ws_opts.as_ref().and_then(|opts| opts.path.clone()),
                self.ws_opts
                    .as_ref()
                    .map(|opts| opts.headers.clone())
                    .unwrap_or_default(),
            )?
        };
        if self.tls || reality.is_some() {
            ensure_vless_alpn(&self.name, &transport, self.alpn.as_ref())?;
        } else {
            ensure!(
                self.client_fingerprint.is_none(),
                "mihomo VLESS proxy {} sets client-fingerprint while TLS is disabled",
                self.name
            );
            ensure_no_alpn(&self.name, self.alpn.as_ref())?;
        }
        ensure_no_smux(&self.name, self.smux.as_ref())?;
        Ok(VlessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            user_id: self.uuid.clone(),
            tls: self.tls && reality.is_none(),
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: if self.tls || reality.is_some() {
                self.skip_cert_verify
            } else {
                false
            },
            flow: self.flow.clone(),
            packet_encoding: self.packet_encoding.clone(),
            mux: self.mux,
            udp: self.udp,
            client_fingerprint: self.client_fingerprint,
            reality,
            transport,
        })
    }
}

impl MihomoVmessProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<VmessClientConfig> {
        ensure!(
            self.alter_id == 0,
            "mihomo VMess proxy {} uses legacy alterId {}; Aerion implements AEAD VMess only",
            self.name,
            self.alter_id
        );
        ensure!(
            self.tls || self.client_fingerprint.is_none(),
            "mihomo VMess proxy {} sets client-fingerprint while TLS is disabled",
            self.name
        );
        ensure_tcp_network(&self.name, &self.network)?;
        ensure_no_alpn(&self.name, self.alpn.as_ref())?;
        Ok(VmessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            user_id: self.uuid.clone(),
            security: self.cipher.clone(),
            udp: self.udp,
            tls: self.tls,
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            client_fingerprint: self.client_fingerprint,
        })
    }
}

impl MihomoTrojanProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<TrojanClientConfig> {
        ensure!(
            self.tls,
            "mihomo Trojan proxy {} disables TLS; Trojan requires TLS in Aerion",
            self.name
        );
        ensure_tcp_network(&self.name, &self.network)?;
        ensure_no_alpn(&self.name, self.alpn.as_ref())?;
        Ok(TrojanClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            password: self.password.clone(),
            sni: sni_or_server(self.sni.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            udp: self.udp,
            client_fingerprint: self.client_fingerprint,
        })
    }
}

impl MihomoHysteria2Proxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<Hysteria2ClientConfig> {
        ensure!(
            self.ports.is_none(),
            "mihomo Hysteria2 proxy {} uses port hopping; Aerion Hysteria2 client expects one fixed port",
            self.name
        );
        let port = self
            .port
            .with_context(|| format!("mihomo Hysteria2 proxy {} is missing port", self.name))?;
        ensure_hy2_alpn(&self.name, self.alpn.as_ref())?;
        Ok(Hysteria2ClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: port,
            password: self.password.clone(),
            sni: sni_or_server(self.sni.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            obfs: self.obfs.clone(),
            obfs_password: self.obfs_password.clone(),
            download_bandwidth: self.down,
            udp: self.udp,
            congestion_control: self.congestion_control.clone(),
        })
    }
}

impl MihomoAnyTlsProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<ClientConfig> {
        Ok(ClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            password: self.password.clone(),
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            padding_scheme: if self.padding_scheme.is_empty() {
                PaddingScheme::default_lines()
            } else {
                self.padding_scheme.clone()
            },
            heartbeat_interval_secs: 30,
        })
    }
}

impl MihomoMieruProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<MieruClientConfig> {
        Ok(MieruClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            username: self
                .username
                .clone()
                .unwrap_or_else(|| self.password.clone()),
            password: self.password.clone(),
            hashed_password: None,
            mtu: 1500,
            transport: MieruTransport::parse(&self.transport)?,
            traffic_pattern: MieruTrafficPattern::parse_pair(
                self.traffic_pattern.as_deref(),
                self.nonce_pattern.as_deref(),
            )
            .with_context(|| format!("parse mihomo Mieru proxy {} traffic pattern", self.name))?,
        })
    }
}

impl MihomoNaiveProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<NaiveClientConfig> {
        Ok(NaiveClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port.unwrap_or(443),
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            extra_headers: self.extra_headers.clone().into_iter().collect(),
            udp_over_tcp: self
                .udp_over_tcp
                .as_ref()
                .map(|options| options.enabled)
                .unwrap_or(false),
            quic: self.quic,
        })
    }
}

impl MihomoTuicProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<TuicClientConfig> {
        ensure!(
            self.token.as_deref().unwrap_or_default().trim().is_empty(),
            "mihomo TUIC proxy {} uses TUIC v4 token; Aerion implements TUIC v5 UUID/password auth",
            self.name
        );
        ensure_tuic_alpn(&self.name, self.alpn.as_ref())?;
        Ok(TuicClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            uuid: self
                .uuid
                .clone()
                .with_context(|| format!("mihomo TUIC proxy {} is missing uuid", self.name))?,
            password: self
                .password
                .clone()
                .with_context(|| format!("mihomo TUIC proxy {} is missing password", self.name))?,
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            udp: self.udp,
            udp_relay_mode: self.udp_relay_mode.clone(),
            congestion_control: self.congestion_control.clone(),
            alpn_protocols: alpn_values(self.alpn.as_ref()),
            heartbeat_interval_secs: 10,
        })
    }
}

impl MihomoRealityOpts {
    pub fn to_client_config(&self) -> Result<RealityClientConfig> {
        RealityClientConfig::from_strings(&self.public_key, &self.short_id)
    }
}

impl MihomoSmuxOptions {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl OneOrManyStrings {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

fn ensure_tcp_network(name: &str, network: &str) -> Result<()> {
    let network = network.trim();
    if network.is_empty() || network.eq_ignore_ascii_case("tcp") {
        return Ok(());
    }
    bail!(
        "mihomo proxy {name} uses network {network}; Aerion currently wires raw TCP transport only"
    )
}

fn ensure_no_smux(name: &str, smux: Option<&MihomoSmuxOptions>) -> Result<()> {
    ensure!(
        !smux.map(MihomoSmuxOptions::is_enabled).unwrap_or(false),
        "mihomo proxy {name} enables smux; Aerion VLESS mux.cool is not wire-compatible with mihomo smux"
    );
    Ok(())
}

fn ensure_no_alpn(name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    ensure!(
        alpn_values(alpn).is_empty(),
        "mihomo proxy {name} sets ALPN, but this Aerion transport does not expose ALPN override"
    );
    Ok(())
}

fn ensure_vless_alpn(
    name: &str,
    transport: &VlessTransportConfig,
    alpn: Option<&OneOrManyStrings>,
) -> Result<()> {
    if matches!(
        transport.kind,
        VlessTransportKind::Http2 | VlessTransportKind::Grpc
    ) {
        let values = alpn_values(alpn);
        ensure!(
            values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("h2")),
            "mihomo VLESS proxy {name} sets ALPN {:?}; {:?} transport requires h2",
            values,
            transport.kind
        );
        return Ok(());
    }
    if matches!(transport.kind, VlessTransportKind::Xhttp) {
        let values = alpn_values(alpn);
        ensure!(
            values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("http/1.1")),
            "mihomo VLESS proxy {name} sets ALPN {:?}; XHTTP stream-one transport requires http/1.1",
            values
        );
        return Ok(());
    }
    ensure_no_alpn(name, alpn)
}

fn ensure_hy2_alpn(name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn_values(alpn);
    ensure!(
        values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("h3")),
        "mihomo Hysteria2 proxy {name} sets ALPN {:?}; Aerion Hysteria2 uses h3",
        values
    );
    Ok(())
}

fn ensure_tuic_alpn(name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn_values(alpn);
    ensure!(
        values.is_empty() || values.iter().any(|value| value.eq_ignore_ascii_case("h3")),
        "mihomo TUIC proxy {name} sets ALPN {:?}; TUIC over QUIC requires h3-compatible ALPN",
        values
    );
    Ok(())
}

fn alpn_values(alpn: Option<&OneOrManyStrings>) -> Vec<String> {
    alpn.map(OneOrManyStrings::to_vec)
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn sni_or_server(value: Option<&str>, server: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(server)
        .to_string()
}

fn default_true() -> bool {
    true
}

fn default_tcp() -> String {
    "tcp".to_string()
}

fn default_vmess_cipher() -> String {
    "auto".to_string()
}

fn default_hy2_congestion_control() -> String {
    "bbr".to_string()
}

fn default_tuic_congestion_control() -> String {
    "cubic".to_string()
}

fn default_tuic_udp_relay_mode() -> String {
    "native".to_string()
}

fn deserialize_optional_bandwidth_mbps<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Bandwidth {
        Number(u64),
        Text(String),
    }

    let value = Option::<Bandwidth>::deserialize(deserializer)?;
    match value {
        Some(Bandwidth::Number(value)) => Ok(Some(value)),
        Some(Bandwidth::Text(value)) => {
            let value = value.trim();
            if value.is_empty() {
                return Ok(None);
            }
            let digits = value
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>();
            if digits.is_empty() {
                return Err(de::Error::custom(format!(
                    "invalid mihomo bandwidth value: {value}"
                )));
            }
            digits.parse::<u64>().map(Some).map_err(de::Error::custom)
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vless_reality_profile() -> Result<()> {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: vless-reality
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.com
    client-fingerprint: chrome
    packet-encoding: xudp
    reality-opts:
      public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
      short-id: a1b2
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.local_socks_listen()?,
            Some("127.0.0.1:7890".parse()?)
        );
        let proxy = config.proxy("vless-reality").context("proxy exists")?;
        let MihomoClientConfig::Vless(vless) = proxy.to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.server_host, "example.com");
        assert_eq!(vless.sni, "www.example.com");
        assert_eq!(vless.client_fingerprint, Some(UtlsFingerprint::Chrome));
        assert!(vless.reality.is_some());
        assert_eq!(vless.packet_encoding, "xudp");
        Ok(())
    }

    #[test]
    fn parses_vless_raw_profile() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vless-raw
    type: vless
    server: example.com
    port: 80
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    tls: false
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Vless(vless) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert!(!vless.tls);
        assert!(vless.reality.is_none());
        assert_eq!(vless.server_port, 80);
        Ok(())
    }

    #[test]
    fn rejects_non_equivalent_smux_mapping() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vless-smux
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    smux:
      enabled: true
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let error = config.proxies[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("smux must be explicit");
        assert!(error.to_string().contains("not wire-compatible"));
        Ok(())
    }

    #[test]
    fn parses_vless_websocket_transport() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vless-ws
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: edge.example.com
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Vless(vless) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(
            vless.transport.kind,
            crate::vless_transport::VlessTransportKind::WebSocket
        );
        assert_eq!(vless.transport.path, "/vless");
        assert_eq!(
            vless.transport.request_host("example.com"),
            "edge.example.com"
        );
        Ok(())
    }

    #[test]
    fn parses_vless_grpc_transport() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vless-grpc
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: grpc
    alpn: h2
    grpc-opts:
      grpc-service-name: TunService
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Vless(vless) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.transport.kind, VlessTransportKind::Grpc);
        assert_eq!(vless.transport.path, "/TunService/Tun");
        Ok(())
    }

    #[test]
    fn parses_vless_xhttp_transport() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vless-xhttp
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: xhttp
    alpn: http/1.1
    xhttp-opts:
      path: /xhttp
      host: edge.example.com
      mode: stream-one
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Vless(vless) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.transport.kind, VlessTransportKind::Xhttp);
        assert_eq!(vless.transport.path, "/xhttp");
        assert_eq!(
            vless.transport.request_host("example.com"),
            "edge.example.com"
        );
        assert_eq!(vless.transport.mode, "stream-one");
        Ok(())
    }

    #[test]
    fn parses_naive_and_tuic_profiles() -> Result<()> {
        let yaml = r#"
proxies:
  - name: naive-h3
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    quic: true
    udp-over-tcp:
      enabled: true
    servername: front.example.com
    skip-cert-verify: true
    extra-headers:
      X-Test: value
  - name: tuic-v5
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    udp: true
    udp-relay-mode: quic
    congestion-controller: bbr
    alpn:
      - h3
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Naive(naive) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Naive")
        };
        assert_eq!(naive.server_host, "naive.example.com");
        assert_eq!(naive.sni, "front.example.com");
        assert!(naive.insecure);
        assert!(naive.quic);
        assert!(naive.udp_over_tcp);
        assert_eq!(
            naive.extra_headers,
            vec![("X-Test".to_string(), "value".to_string())]
        );

        let MihomoClientConfig::Tuic(tuic) =
            config.proxies[1].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected TUIC")
        };
        assert_eq!(tuic.server_host, "tuic.example.com");
        assert_eq!(tuic.udp_relay_mode, "quic");
        assert_eq!(tuic.congestion_control, "bbr");
        assert_eq!(tuic.alpn_protocols, vec!["h3".to_string()]);
        Ok(())
    }

    #[test]
    fn rejects_invalid_mieru_traffic_pattern_without_silent_degrade() -> Result<()> {
        let yaml = r#"
proxies:
  - name: mieru-shaped
    type: mieru
    server: mieru.example.com
    port: 2999
    username: user
    password: pass
    traffic-pattern: abc
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let error = config.proxies[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("Mieru shaping must not be silently ignored");
        assert!(error.to_string().contains("traffic pattern"));
        Ok(())
    }
}
