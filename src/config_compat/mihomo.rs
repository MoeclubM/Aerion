use crate::client::ClientConfig;
use crate::http_connect::HttpProxyClientConfig;
use crate::hysteria2::Hysteria2ClientConfig;
use crate::mieru::{MieruClientConfig, MieruTrafficPattern, MieruTransport};
use crate::naive::{NaiveClientConfig, default_naive_quic_congestion_control};
use crate::padding::PaddingScheme;
use crate::reality::RealityClientConfig;
use crate::router::RouteClientConfig;
use crate::routing::{
    DomainMatcher, IpCidr, PortRange, RouteDecision, RouteNetwork, RouteRule, RouteTable,
};
use crate::shadowsocks::ShadowsocksClientConfig;
use crate::socks::SocksProxyClientConfig;
use crate::trojan::TrojanClientConfig;
use crate::tuic::TuicClientConfig;
use crate::tun::{TunConfig, TunDnsStrategy, socks_proxy_url};
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::VlessClientConfig;
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::{VmessClientConfig, ensure_vmess_packet_encoding};
use anyhow::{Context, Result, bail, ensure};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, de};
use serde_yaml::{Mapping, Value};
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
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub dns: MihomoDnsConfig,
    #[serde(default)]
    pub tun: Option<MihomoTunConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoDnsConfig {
    #[serde(default, rename = "enhanced-mode", alias = "enhanced_mode")]
    pub enhanced_mode: Option<String>,
    #[serde(default, rename = "fake-ip-range", alias = "fake_ip_range")]
    pub fake_ip_range: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoTunConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(
        default,
        alias = "interface-name",
        alias = "interface_name",
        alias = "tun-name",
        alias = "tun_name"
    )]
    pub device: Option<String>,
    #[serde(default, rename = "auto-route", alias = "auto_route")]
    pub auto_route: Option<bool>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default, rename = "dns-hijack", alias = "dns_hijack")]
    pub dns_hijack: Option<OneOrManyStrings>,
    #[serde(
        default,
        rename = "route-exclude-address",
        alias = "route_exclude_address"
    )]
    pub route_exclude_address: Option<OneOrManyStrings>,
    #[serde(
        default,
        rename = "route-exclude-address-set",
        alias = "route_exclude_address_set"
    )]
    pub route_exclude_address_set: Option<OneOrManyStrings>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MihomoProxy {
    Shadowsocks(MihomoShadowsocksProxy),
    Socks(MihomoSocksProxy),
    Http(MihomoHttpProxy),
    Vless(MihomoVlessProxy),
    Vmess(MihomoVmessProxy),
    Trojan(MihomoTrojanProxy),
    Hysteria2(MihomoHysteria2Proxy),
    AnyTls(MihomoAnyTlsProxy),
    Mieru(MihomoMieruProxy),
    Naive(MihomoNaiveProxy),
    Tuic(MihomoTuicProxy),
    Unsupported(MihomoUnsupportedProxy),
}

impl<'de> Deserialize<'de> for MihomoProxy {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let Value::Mapping(mapping) = &value else {
            return Err(de::Error::custom("mihomo proxy entry must be a mapping"));
        };
        let kind = mihomo_mapping_str(mapping, "type")
            .ok_or_else(|| de::Error::custom("mihomo proxy entry is missing type"))?
            .to_string();
        let normalized = kind.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "ss" | "shadowsocks" => {
                decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Shadowsocks)
            }
            "socks" | "socks5" | "socks5h" => {
                decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Socks)
            }
            "http" => decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Http),
            "vless" => decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Vless),
            "vmess" => decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Vmess),
            "trojan" => decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Trojan),
            "hysteria2" | "hy2" => {
                decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Hysteria2)
            }
            "anytls" | "any-tls" => {
                decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::AnyTls)
            }
            "mieru" => decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Mieru),
            "naive" | "naive+https" | "naive+quic" => {
                decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Naive)
            }
            "tuic" => decode_known_mihomo_proxy(&value, mapping, &kind, MihomoProxy::Tuic),
            _ => mihomo_raw_proxy(mapping, &kind),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MihomoUnsupportedProxy {
    pub name: String,
    pub kind: String,
    pub fields: BTreeMap<String, Value>,
}

fn decode_known_mihomo_proxy<T, E, F>(
    value: &Value,
    mapping: &Mapping,
    kind: &str,
    wrap: F,
) -> std::result::Result<MihomoProxy, E>
where
    T: DeserializeOwned,
    E: de::Error,
    F: FnOnce(T) -> MihomoProxy,
{
    match serde_yaml::from_value(value.clone()) {
        Ok(proxy) => Ok(wrap(proxy)),
        Err(_) => mihomo_raw_proxy(mapping, kind),
    }
}

fn mihomo_raw_proxy<E>(mapping: &Mapping, kind: &str) -> std::result::Result<MihomoProxy, E>
where
    E: de::Error,
{
    let name = mihomo_mapping_str(mapping, "name")
        .ok_or_else(|| de::Error::custom("unsupported mihomo proxy is missing name"))?
        .to_string();
    Ok(MihomoProxy::Unsupported(MihomoUnsupportedProxy {
        name,
        kind: kind.to_string(),
        fields: mihomo_string_fields(mapping),
    }))
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
pub struct MihomoSocksProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default)]
    pub tls: bool,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoHttpProxy {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default, alias = "servername", alias = "server-name", alias = "sni")]
    pub servername: Option<String>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(
        default,
        rename = "client-fingerprint",
        alias = "client_fingerprint",
        deserialize_with = "deserialize_optional_fingerprint"
    )]
    pub client_fingerprint: Option<UtlsFingerprint>,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
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
    #[serde(default, rename = "hop-interval", alias = "hop_interval")]
    pub hop_interval: Option<Value>,
    pub password: String,
    #[serde(default, alias = "servername", alias = "server-name")]
    pub sni: Option<String>,
    #[serde(default, rename = "skip-cert-verify", alias = "skip_cert_verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, rename = "obfs-password", alias = "obfs_password")]
    pub obfs_password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_bandwidth_mbps")]
    pub up: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_bandwidth_mbps")]
    pub down: Option<u64>,
    #[serde(default, rename = "bbr-profile", alias = "bbr_profile")]
    pub bbr_profile: Option<String>,
    #[serde(default, rename = "realm-opts", alias = "realm_opts")]
    pub realm_opts: Option<Value>,
    #[serde(
        default,
        rename = "initial-stream-receive-window",
        alias = "initial_stream_receive_window"
    )]
    pub initial_stream_receive_window: Option<Value>,
    #[serde(
        default,
        rename = "max-stream-receive-window",
        alias = "max_stream_receive_window"
    )]
    pub max_stream_receive_window: Option<Value>,
    #[serde(
        default,
        rename = "initial-connection-receive-window",
        alias = "initial_connection_receive_window"
    )]
    pub initial_connection_receive_window: Option<Value>,
    #[serde(
        default,
        rename = "max-connection-receive-window",
        alias = "max_connection_receive_window"
    )]
    pub max_connection_receive_window: Option<Value>,
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
    #[serde(
        default,
        rename = "client-fingerprint",
        alias = "client_fingerprint",
        deserialize_with = "deserialize_optional_fingerprint"
    )]
    pub client_fingerprint: Option<UtlsFingerprint>,
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
    pub ip: Option<String>,
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
    #[serde(default, rename = "disable-sni", alias = "disable_sni")]
    pub disable_sni: bool,
    #[serde(default, rename = "reduce-rtt", alias = "reduce_rtt")]
    pub reduce_rtt: bool,
    #[serde(default, rename = "fast-open", alias = "fast_open")]
    pub fast_open: bool,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default, rename = "heartbeat-interval", alias = "heartbeat_interval")]
    pub heartbeat_interval: Option<u64>,
    #[serde(default, rename = "max-open-streams", alias = "max_open_streams")]
    pub max_open_streams: Option<Value>,
    #[serde(
        default,
        rename = "max-udp-relay-packet-size",
        alias = "max_udp_relay_packet_size"
    )]
    pub max_udp_relay_packet_size: Option<Value>,
    #[serde(default, rename = "request-timeout", alias = "request_timeout")]
    pub request_timeout: Option<Value>,
    #[serde(default, rename = "bbr-profile", alias = "bbr_profile")]
    pub bbr_profile: Option<String>,
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MihomoUdpOverTcpOptions {
    pub enabled: bool,
    pub version: Option<Value>,
}

impl<'de> Deserialize<'de> for MihomoUdpOverTcpOptions {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Object {
                #[serde(default)]
                enabled: bool,
                #[serde(default)]
                version: Option<Value>,
            },
        }

        match Raw::deserialize(deserializer)? {
            Raw::Bool(enabled) => Ok(Self {
                enabled,
                version: None,
            }),
            Raw::Object { enabled, version } => Ok(Self { enabled, version }),
        }
    }
}

impl MihomoUdpOverTcpOptions {
    fn enabled_for(&self, protocol: &str, name: &str) -> Result<bool> {
        if !self.enabled {
            return Ok(false);
        }
        if let Some(version) = &self.version {
            let is_v2 = match version {
                Value::Number(number) => number.as_u64() == Some(2),
                Value::String(text) => text.trim() == "2",
                _ => false,
            };
            ensure!(
                is_v2,
                "mihomo {protocol} proxy {name} sets udp-over-tcp version {:?}; Aerion UDP-over-TCP uses version 2 framing",
                version
            );
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrManyStrings {
    One(String),
    Many(Vec<String>),
}

#[derive(Clone, Debug)]
pub enum MihomoClientConfig {
    Route(RouteClientConfig),
    Shadowsocks(ShadowsocksClientConfig),
    SocksProxy(SocksProxyClientConfig),
    HttpProxy(HttpProxyClientConfig),
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

    pub fn route_table(&self) -> Result<RouteTable> {
        let mut table = RouteTable::default();
        for (index, rule) in self.rules.iter().enumerate() {
            table.rules.push(parse_mihomo_route_rule(rule, index)?);
        }
        Ok(table)
    }

    pub fn tun_enabled(&self) -> bool {
        self.tun.as_ref().map(|tun| tun.enable).unwrap_or(false)
    }

    pub fn tun_config(&self, proxy_listen: SocketAddr) -> Result<Option<TunConfig>> {
        let Some(tun) = &self.tun else {
            return Ok(None);
        };
        if !tun.enable {
            return Ok(None);
        }
        ensure!(
            tun.route_exclude_address_set.is_none(),
            "mihomo tun route-exclude-address-set requires rule-set data"
        );
        let mut config = TunConfig::new(socks_proxy_url(proxy_listen));
        config.tun_name = tun.device.as_ref().map(|value| value.trim().to_string());
        if let Some(auto_route) = tun.auto_route {
            config.setup = auto_route;
        }
        if let Some(mtu) = tun.mtu {
            config.mtu = mtu;
        }
        config.ipv6 = self.ipv6;
        if self
            .dns
            .enhanced_mode
            .as_deref()
            .map(|mode| mode.eq_ignore_ascii_case("fake-ip"))
            .unwrap_or(false)
        {
            config.dns = TunDnsStrategy::Virtual;
        }
        if let Some(fake_ip_range) = &self.dns.fake_ip_range {
            config.virtual_dns_pool = fake_ip_range.trim().to_string();
        }
        if tun.dns_hijack.is_some() && config.dns == TunDnsStrategy::Direct {
            config.dns = TunDnsStrategy::OverTcp;
        }
        if let Some(bypass) = &tun.route_exclude_address {
            config.bypass = bypass.to_vec();
        }
        Ok(Some(config))
    }
}

impl MihomoProxy {
    pub fn name(&self) -> &str {
        match self {
            Self::Shadowsocks(proxy) => &proxy.name,
            Self::Socks(proxy) => &proxy.name,
            Self::Http(proxy) => &proxy.name,
            Self::Vless(proxy) => &proxy.name,
            Self::Vmess(proxy) => &proxy.name,
            Self::Trojan(proxy) => &proxy.name,
            Self::Hysteria2(proxy) => &proxy.name,
            Self::AnyTls(proxy) => &proxy.name,
            Self::Mieru(proxy) => &proxy.name,
            Self::Naive(proxy) => &proxy.name,
            Self::Tuic(proxy) => &proxy.name,
            Self::Unsupported(proxy) => &proxy.name,
        }
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<MihomoClientConfig> {
        Ok(match self {
            Self::Shadowsocks(proxy) => {
                MihomoClientConfig::Shadowsocks(proxy.to_client_config(listen)?)
            }
            Self::Socks(proxy) => MihomoClientConfig::SocksProxy(proxy.to_client_config(listen)?),
            Self::Http(proxy) => MihomoClientConfig::HttpProxy(proxy.to_client_config(listen)?),
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
            Self::Unsupported(proxy) => proxy.to_client_config(listen)?,
        })
    }
}

impl MihomoUnsupportedProxy {
    fn to_client_config(&self, listen: SocketAddr) -> Result<MihomoClientConfig> {
        let value = self.value();
        Ok(match self.kind.trim().to_ascii_lowercase().as_str() {
            "direct" => {
                self.ensure_route_fields()?;
                MihomoClientConfig::Route(RouteClientConfig {
                    listen,
                    default: RouteDecision::Direct,
                })
            }
            "reject" | "block" => {
                self.ensure_route_fields()?;
                MihomoClientConfig::Route(RouteClientConfig {
                    listen,
                    default: RouteDecision::Block,
                })
            }
            "ss" | "shadowsocks" => MihomoClientConfig::Shadowsocks(
                serde_yaml::from_value::<MihomoShadowsocksProxy>(value)
                    .with_context(|| format!("parse mihomo Shadowsocks proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "socks" | "socks5" | "socks5h" => MihomoClientConfig::SocksProxy(
                serde_yaml::from_value::<MihomoSocksProxy>(value)
                    .with_context(|| format!("parse mihomo SOCKS proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "http" => MihomoClientConfig::HttpProxy(
                serde_yaml::from_value::<MihomoHttpProxy>(value)
                    .with_context(|| format!("parse mihomo HTTP proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "vless" => MihomoClientConfig::Vless(
                serde_yaml::from_value::<MihomoVlessProxy>(value)
                    .with_context(|| format!("parse mihomo VLESS proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "vmess" => MihomoClientConfig::Vmess(
                serde_yaml::from_value::<MihomoVmessProxy>(value)
                    .with_context(|| format!("parse mihomo VMess proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "trojan" => MihomoClientConfig::Trojan(
                serde_yaml::from_value::<MihomoTrojanProxy>(value)
                    .with_context(|| format!("parse mihomo Trojan proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "hysteria2" | "hy2" => MihomoClientConfig::Hysteria2(
                serde_yaml::from_value::<MihomoHysteria2Proxy>(value)
                    .with_context(|| format!("parse mihomo Hysteria2 proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "anytls" | "any-tls" => MihomoClientConfig::AnyTls(
                serde_yaml::from_value::<MihomoAnyTlsProxy>(value)
                    .with_context(|| format!("parse mihomo AnyTLS proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "mieru" => MihomoClientConfig::Mieru(
                serde_yaml::from_value::<MihomoMieruProxy>(value)
                    .with_context(|| format!("parse mihomo Mieru proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "naive" | "naive+https" | "naive+quic" => MihomoClientConfig::Naive(
                serde_yaml::from_value::<MihomoNaiveProxy>(value)
                    .with_context(|| format!("parse mihomo Naive proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "tuic" => MihomoClientConfig::Tuic(
                serde_yaml::from_value::<MihomoTuicProxy>(value)
                    .with_context(|| format!("parse mihomo TUIC proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            _ => bail!(
                "unsupported mihomo proxy {} type {}; Aerion cannot run this proxy protocol",
                self.name,
                self.kind
            ),
        })
    }

    fn ensure_route_fields(&self) -> Result<()> {
        let unsupported = self
            .fields
            .keys()
            .filter(|key| {
                !key.eq_ignore_ascii_case("name")
                    && !key.eq_ignore_ascii_case("type")
                    && !key.eq_ignore_ascii_case("udp")
            })
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            unsupported.is_empty(),
            "mihomo proxy {} type {} sets unsupported fields {:?}",
            self.name,
            self.kind,
            unsupported
        );
        ensure!(
            !matches!(self.fields.get("udp"), Some(Value::Bool(false))),
            "mihomo proxy {} type {} disables UDP; Aerion route client exposes TCP and UDP together",
            self.name,
            self.kind
        );
        Ok(())
    }

    fn value(&self) -> Value {
        let mut mapping = Mapping::new();
        for (key, value) in &self.fields {
            mapping.insert(Value::String(key.clone()), value.clone());
        }
        Value::Mapping(mapping)
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
        let udp_over_tcp = self
            .udp_over_tcp
            .as_ref()
            .map(|opts| opts.enabled_for("Shadowsocks", &self.name))
            .transpose()?
            .unwrap_or(false);
        Ok(ShadowsocksClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            method: self.cipher.clone(),
            password: self.password.clone(),
            udp: self.udp,
            udp_over_tcp,
        })
    }
}

impl MihomoSocksProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<SocksProxyClientConfig> {
        ensure!(
            !self.tls && !self.skip_cert_verify && alpn_values(self.alpn.as_ref()).is_empty(),
            "mihomo SOCKS proxy {} sets TLS options; Aerion SOCKS outbound is plain SOCKS5",
            self.name
        );
        Ok(SocksProxyClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            udp: self.udp,
        })
    }
}

impl MihomoHttpProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<HttpProxyClientConfig> {
        if self.tls {
            ensure_http_alpn(&self.name, self.alpn.as_ref())?;
        } else {
            ensure!(
                alpn_values(self.alpn.as_ref()).is_empty()
                    && !self.skip_cert_verify
                    && self.client_fingerprint.is_none(),
                "mihomo HTTP proxy {} sets TLS-only options while tls is disabled",
                self.name
            );
        }
        Ok(HttpProxyClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            tls: self.tls,
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: self.client_fingerprint,
            extra_headers: self.headers.clone().into_iter().collect(),
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
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
        ensure_vmess_packet_encoding(&self.packet_encoding)
            .with_context(|| format!("mihomo VMess proxy {} packet-encoding", self.name))?;
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
        if self.tls {
            ensure_vless_alpn(&self.name, &transport, self.alpn.as_ref())?;
        } else {
            ensure_no_alpn(&self.name, self.alpn.as_ref())?;
        }
        Ok(VmessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            user_id: self.uuid.clone(),
            security: self.cipher.clone(),
            packet_encoding: self.packet_encoding.clone(),
            udp: self.udp,
            tls: self.tls,
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: if self.tls {
                self.skip_cert_verify
            } else {
                false
            },
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: if self.tls {
                self.client_fingerprint
            } else {
                None
            },
            transport,
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
        ensure_vless_alpn(&self.name, &transport, self.alpn.as_ref())?;
        Ok(TrojanClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            password: self.password.clone(),
            sni: sni_or_server(self.sni.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            udp: self.udp,
            client_fingerprint: self.client_fingerprint,
            transport,
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
        ensure!(
            !self
                .hop_interval
                .as_ref()
                .map(value_has_data)
                .unwrap_or(false),
            "mihomo Hysteria2 proxy {} sets hop-interval; Aerion Hysteria2 client expects one fixed port",
            self.name
        );
        ensure!(
            self.bbr_profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
            "mihomo Hysteria2 proxy {} sets bbr-profile {:?}; Aerion Hysteria2 uses the default BBR profile",
            self.name,
            self.bbr_profile
        );
        ensure!(
            !self
                .realm_opts
                .as_ref()
                .map(value_has_data)
                .unwrap_or(false),
            "mihomo Hysteria2 proxy {} sets realm-opts; Aerion Hysteria2 client does not expose realm override",
            self.name
        );
        for (field, value) in [
            (
                "initial-stream-receive-window",
                self.initial_stream_receive_window.as_ref(),
            ),
            (
                "max-stream-receive-window",
                self.max_stream_receive_window.as_ref(),
            ),
            (
                "initial-connection-receive-window",
                self.initial_connection_receive_window.as_ref(),
            ),
            (
                "max-connection-receive-window",
                self.max_connection_receive_window.as_ref(),
            ),
        ] {
            ensure!(
                !value.map(value_has_data).unwrap_or(false),
                "mihomo Hysteria2 proxy {} sets {field}; Aerion Hysteria2 client does not expose QUIC receive window override",
                self.name
            );
        }
        if let Some(obfs) = self
            .obfs
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            ensure!(
                obfs.eq_ignore_ascii_case("salamander"),
                "mihomo Hysteria2 proxy {} uses obfs {}; Aerion supports salamander",
                self.name,
                obfs
            );
        }
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
            certificate_fingerprint: self.fingerprint.clone(),
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            obfs: self.obfs.clone(),
            obfs_password: self.obfs_password.clone(),
            upload_bandwidth: self.up,
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
            client_fingerprint: self.client_fingerprint,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            extra_headers: self.extra_headers.clone().into_iter().collect(),
            udp_over_tcp: self
                .udp_over_tcp
                .as_ref()
                .map(|options| options.enabled_for("Naive", &self.name))
                .transpose()?
                .unwrap_or(false),
            quic: self.quic,
            quic_congestion_control: default_naive_quic_congestion_control(),
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
        ensure!(
            !self.reduce_rtt,
            "mihomo TUIC proxy {} enables reduce-rtt; Aerion TUIC client does not expose 0-RTT handshakes",
            self.name
        );
        ensure!(
            !self.disable_sni,
            "mihomo TUIC proxy {} disables SNI; Aerion TUIC client requires a TLS server name",
            self.name
        );
        ensure!(
            !self.fast_open,
            "mihomo TUIC proxy {} enables fast-open; Aerion TUIC client does not expose TCP fast open",
            self.name
        );
        ensure!(
            self.bbr_profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
            "mihomo TUIC proxy {} sets bbr-profile {:?}; Aerion TUIC uses the default BBR profile",
            self.name,
            self.bbr_profile
        );
        for (field, value) in [
            ("max-open-streams", self.max_open_streams.as_ref()),
            (
                "max-udp-relay-packet-size",
                self.max_udp_relay_packet_size.as_ref(),
            ),
            ("request-timeout", self.request_timeout.as_ref()),
        ] {
            ensure!(
                !value.map(value_has_data).unwrap_or(false),
                "mihomo TUIC proxy {} sets {field}; Aerion TUIC client does not expose this option",
                self.name
            );
        }
        ensure_tuic_alpn(&self.name, self.alpn.as_ref())?;
        let server_host = self
            .ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.server);
        Ok(TuicClientConfig {
            listen,
            server_host: server_host.to_string(),
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
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            udp: self.udp,
            udp_relay_mode: self.udp_relay_mode.clone(),
            congestion_control: self.congestion_control.clone(),
            alpn_protocols: alpn_values(self.alpn.as_ref()),
            heartbeat_interval_secs: self
                .heartbeat_interval
                .map(|millis| millis.saturating_add(999) / 1000)
                .unwrap_or(10),
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

fn value_has_data(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(_) => true,
        Value::String(value) => !value.trim().is_empty(),
        Value::Sequence(value) => !value.is_empty(),
        Value::Mapping(value) => !value.is_empty(),
        Value::Tagged(value) => value_has_data(&value.value),
    }
}

fn mihomo_mapping_str<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a str> {
    mapping
        .get(&Value::String(key.to_string()))
        .and_then(Value::as_str)
}

fn mihomo_string_fields(mapping: &Mapping) -> BTreeMap<String, Value> {
    mapping
        .iter()
        .filter_map(|(key, value)| {
            let Value::String(key) = key else {
                return None;
            };
            Some((key.clone(), value.clone()))
        })
        .collect()
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

fn ensure_http_alpn(name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn_values(alpn);
    ensure!(
        values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("http/1.1")),
        "mihomo HTTP proxy {name} sets ALPN {:?}; Aerion HTTP proxy outbound uses HTTP/1.1 CONNECT",
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

fn parse_mihomo_route_rule(raw: &str, index: usize) -> Result<RouteRule> {
    let parts = raw.split(',').map(str::trim).collect::<Vec<_>>();
    ensure!(
        !parts.is_empty() && !parts[0].is_empty(),
        "mihomo rules[{index}] is empty"
    );
    let kind = parts[0].to_ascii_uppercase();
    let action_index = if matches!(kind.as_str(), "MATCH" | "FINAL") {
        1
    } else {
        2
    };
    ensure!(
        parts.len() > action_index,
        "mihomo rules[{index}] is missing outbound"
    );
    let mut rule = RouteRule::new(RouteDecision::from_outbound(parts[action_index])?);
    match kind.as_str() {
        "DOMAIN" => rule.domains.push(DomainMatcher::exact(parts[1])),
        "DOMAIN-SUFFIX" => rule.domains.push(DomainMatcher::suffix(parts[1])),
        "DOMAIN-KEYWORD" => rule.domains.push(DomainMatcher::keyword(parts[1])),
        "DOMAIN-REGEX" => rule.domains.push(DomainMatcher::regex(parts[1])?),
        "GEOSITE" => rule.add_geosite_set(parts[1]),
        "IP-CIDR" | "IP-CIDR6" => rule.ip_cidrs.push(IpCidr::parse(parts[1])?),
        "GEOIP" if parts[1].eq_ignore_ascii_case("private") => rule.ip_is_private = true,
        "GEOIP" => rule.add_geoip_set(parts[1]),
        "DST-PORT" => rule.ports.push(PortRange::parse(parts[1])?),
        "NETWORK" => rule.networks.push(RouteNetwork::parse(parts[1])?),
        "MATCH" | "FINAL" => {}
        "RULE-SET" => bail!("mihomo rules[{index}] RULE-SET requires rule-set data"),
        "PROCESS-NAME" | "PROCESS-PATH" => {
            bail!("mihomo rules[{index}] process rules require process metadata")
        }
        other => bail!("unsupported mihomo route rule type {other}"),
    }
    Ok(rule)
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
    use anyhow::bail;

    use super::*;
    use crate::protocol::ProxyTarget;

    #[test]
    fn parses_unsupported_proxy_entries_without_breaking_selected_proxy() -> Result<()> {
        let yaml = r#"
proxies:
  - name: direct-out
    type: direct
    udp: true
  - name: wireguard-out
    type: wireguard
    ip: 172.16.0.2
    ipv6: "fd00::2"
    private-key: ignored-by-aerion
    peers:
      - server: wg.example.com
        port: 51820
        public-key: ignored
  - name: naive-h3
    type: naive+quic
    server: naive.example.com
    username: user
    password: pass
    quic: true
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        assert_eq!(
            config.proxy("direct-out").context("direct proxy")?.name(),
            "direct-out"
        );
        let MihomoClientConfig::Route(direct) = config
            .proxy("direct-out")
            .context("direct proxy")?
            .to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected route client")
        };
        assert_eq!(direct.default, RouteDecision::Direct);
        let error = config
            .proxy("wireguard-out")
            .context("wireguard proxy")?
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported proxy must fail explicitly when selected");
        assert!(error.to_string().contains("unsupported mihomo proxy"));

        let MihomoClientConfig::Naive(naive) = config
            .proxy("naive-h3")
            .context("naive proxy")?
            .to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Naive")
        };
        assert!(naive.quic);
        Ok(())
    }

    #[test]
    fn compiles_mihomo_route_rules() -> Result<()> {
        let yaml = r#"
proxies: []
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - DOMAIN-KEYWORD,video,proxy-a
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - DST-PORT,53,DIRECT
  - MATCH,proxy-b
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let routes = config.route_table()?;
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("video.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );
        assert_eq!(
            routes.decide(&ProxyTarget::Ip("10.1.2.3:443".parse()?), RouteNetwork::Tcp),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("unmatched.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-b".to_string())
        );
        Ok(())
    }

    #[test]
    fn compiles_mihomo_tun_config() -> Result<()> {
        let yaml = r#"
mixed-port: 7890
ipv6: true
dns:
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
tun:
  enable: true
  device: utun9
  auto-route: true
  mtu: 9000
  dns-hijack:
    - any:53
  route-exclude-address:
    - 10.0.0.0/8
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        assert!(config.tun_enabled());
        let tun = config
            .tun_config("127.0.0.1:7890".parse()?)?
            .context("tun config")?;
        assert_eq!(tun.proxy_url, "socks5://127.0.0.1:7890");
        assert_eq!(tun.tun_name.as_deref(), Some("utun9"));
        assert_eq!(tun.mtu, 9000);
        assert_eq!(tun.dns, TunDnsStrategy::Virtual);
        assert_eq!(tun.virtual_dns_pool, "198.18.0.0/15");
        assert_eq!(tun.bypass, vec!["10.0.0.0/8"]);
        assert!(tun.ipv6);
        Ok(())
    }

    #[test]
    fn defers_known_proxy_parse_errors_until_selected() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vless-newer-fingerprint
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    client-fingerprint: 123
  - name: naive-h3
    type: naive
    server: naive.example.com
    username: user
    password: pass
    quic: true
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Naive(naive) = config
            .proxy("naive-h3")
            .context("naive proxy")?
            .to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Naive")
        };
        assert!(naive.quic);

        let error = config
            .proxy("vless-newer-fingerprint")
            .context("vless proxy")?
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("known proxy parse error must be deferred");
        assert!(error.to_string().contains("parse mihomo VLESS proxy"));
        Ok(())
    }

    #[test]
    fn parses_shadowsocks_udp_over_tcp_profile() -> Result<()> {
        let yaml = r#"
proxies:
  - name: ss-uot
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp: true
    udp-over-tcp: true
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Shadowsocks(shadowsocks) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Shadowsocks")
        };
        assert!(shadowsocks.udp);
        assert!(shadowsocks.udp_over_tcp);
        Ok(())
    }

    #[test]
    fn parses_anytls_client_fingerprint() -> Result<()> {
        let yaml = r#"
proxies:
  - name: anytls-chrome
    type: anytls
    server: anytls.example.com
    port: 443
    password: secret
    servername: edge.example.com
    client-fingerprint: chrome
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::AnyTls(anytls) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected AnyTLS")
        };
        assert_eq!(anytls.sni, "edge.example.com");
        assert_eq!(anytls.client_fingerprint, Some(UtlsFingerprint::Chrome));
        Ok(())
    }

    #[test]
    fn rejects_unsupported_udp_over_tcp_version() -> Result<()> {
        let yaml = r#"
proxies:
  - name: ss-uot-v1
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp-over-tcp:
      enabled: true
      version: 1
  - name: naive-uot-v1
    type: naive
    server: naive.example.com
    udp-over-tcp:
      enabled: true
      version: "1"
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let ss_error = config.proxies[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("Shadowsocks UOT v1 must be explicit");
        assert!(ss_error.to_string().contains("version 2"));
        let naive_error = config.proxies[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("Naive UOT v1 must be explicit");
        assert!(naive_error.to_string().contains("version 2"));
        Ok(())
    }

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
    fn parses_trojan_websocket_transport() -> Result<()> {
        let yaml = r#"
proxies:
  - name: trojan-ws
    type: trojan
    server: example.com
    port: 443
    password: secret
    network: ws
    ws-opts:
      path: /trojan
      headers:
        Host: edge.example.com
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Trojan(trojan) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Trojan")
        };
        assert_eq!(trojan.transport.kind, VlessTransportKind::WebSocket);
        assert_eq!(trojan.transport.path, "/trojan");
        assert_eq!(
            trojan.transport.request_host("example.com"),
            "edge.example.com"
        );
        Ok(())
    }

    #[test]
    fn parses_vmess_websocket_transport() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vmess-ws
    type: vmess
    server: example.com
    port: 80
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    alterId: 0
    packet-encoding: packetaddr
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: edge.example.com
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Vmess(vmess) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VMess")
        };
        assert!(!vmess.tls);
        assert_eq!(
            vmess.transport.kind,
            crate::vless_transport::VlessTransportKind::WebSocket
        );
        assert_eq!(vmess.transport.path, "/vmess");
        assert_eq!(vmess.packet_encoding, "packetaddr");
        assert_eq!(
            vmess.transport.request_host("example.com"),
            "edge.example.com"
        );
        Ok(())
    }

    #[test]
    fn parses_vmess_xudp_packet_encoding() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vmess-xudp
    type: vmess
    server: example.com
    port: 80
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    alterId: 0
    packet-encoding: xudp
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Vmess(vmess) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.packet_encoding, "xudp");
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
    fn parses_hysteria2_profile() -> Result<()> {
        let yaml = r#"
proxies:
  - name: hy2
    type: hysteria2
    server: example.com
    port: 443
    password: secret
    servername: hy2.example.com
    skip-cert-verify: true
    fingerprint: sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
    obfs: salamander
    obfs-password: obfs-pass
    up: 10 Mbps
    down: 80 Mbps
    congestion-control: reno
    udp: true
    alpn:
      - h3
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Hysteria2(hysteria2) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hysteria2.server_host, "example.com");
        assert_eq!(hysteria2.server_port, 443);
        assert_eq!(hysteria2.password, "secret");
        assert_eq!(hysteria2.sni, "hy2.example.com");
        assert!(hysteria2.insecure);
        assert_eq!(
            hysteria2.certificate_fingerprint.as_deref(),
            Some("sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        );
        assert_eq!(hysteria2.obfs.as_deref(), Some("salamander"));
        assert_eq!(hysteria2.obfs_password.as_deref(), Some("obfs-pass"));
        assert_eq!(hysteria2.upload_bandwidth, Some(10));
        assert_eq!(hysteria2.download_bandwidth, Some(80));
        assert_eq!(hysteria2.congestion_control, "reno");
        Ok(())
    }

    #[test]
    fn rejects_hysteria2_unsupported_fields() -> Result<()> {
        let yaml = r#"
proxies:
  - name: hy2-hop
    type: hysteria2
    server: example.com
    ports: 443,8443
    hop-interval: 30s
    password: secret
  - name: hy2-realm
    type: hysteria2
    server: example.com
    port: 443
    password: secret
    realm-opts:
      name: test
  - name: hy2-window
    type: hysteria2
    server: example.com
    port: 443
    password: secret
    max-stream-receive-window: 8388608
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let hop_error = config.proxies[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("port hopping must be explicit");
        assert!(hop_error.to_string().contains("port hopping"));
        let realm_error = config.proxies[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("realm opts must be explicit");
        assert!(realm_error.to_string().contains("realm-opts"));
        let window_error = config.proxies[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("receive window override must be explicit");
        assert!(window_error.to_string().contains("receive window"));
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
      version: 2
    servername: front.example.com
    skip-cert-verify: true
    extra-headers:
      X-Test: value
  - name: tuic-v5
    type: tuic
    server: tuic.example.com
    ip: 203.0.113.10
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    udp: true
    udp-relay-mode: quic
    congestion-controller: bbr
    heartbeat-interval: 1500
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
        assert_eq!(tuic.server_host, "203.0.113.10");
        assert_eq!(tuic.sni, "tuic.example.com");
        assert_eq!(tuic.udp_relay_mode, "quic");
        assert_eq!(tuic.congestion_control, "bbr");
        assert_eq!(tuic.alpn_protocols, vec!["h3".to_string()]);
        assert_eq!(tuic.heartbeat_interval_secs, 2);
        Ok(())
    }

    #[test]
    fn rejects_tuic_unsupported_fields() -> Result<()> {
        let yaml = r#"
proxies:
  - name: tuic-reduce-rtt
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    reduce-rtt: true
  - name: tuic-disable-sni
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    disable-sni: true
  - name: tuic-open-streams
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    max-open-streams: 64
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let reduce_rtt_error = config.proxies[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("reduce-rtt must be explicit");
        assert!(reduce_rtt_error.to_string().contains("reduce-rtt"));
        let disable_sni_error = config.proxies[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("disable-sni must be explicit");
        assert!(disable_sni_error.to_string().contains("SNI"));
        let stream_error = config.proxies[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("max-open-streams must be explicit");
        assert!(stream_error.to_string().contains("max-open-streams"));
        Ok(())
    }

    #[test]
    fn converts_http_proxy_to_client_config() -> Result<()> {
        let yaml = r#"
proxies:
  - name: http-proxy
    type: http
    server: proxy.example.com
    port: 8080
    username: user
    password: pass
    tls: true
    servername: front.example.com
    skip-cert-verify: true
    alpn:
      - http/1.1
    headers:
      X-Test: value
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::HttpProxy(http) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected HTTP proxy")
        };
        assert_eq!(http.server_host, "proxy.example.com");
        assert_eq!(http.server_port, 8080);
        assert_eq!(http.username, "user");
        assert_eq!(http.password, "pass");
        assert!(http.tls);
        assert_eq!(http.sni, "front.example.com");
        assert!(http.insecure);
        assert_eq!(
            http.extra_headers,
            vec![("X-Test".to_string(), "value".to_string())]
        );
        Ok(())
    }

    #[test]
    fn converts_socks_proxy_to_client_config() -> Result<()> {
        let yaml = r#"
proxies:
  - name: socks-proxy
    type: socks5
    server: proxy.example.com
    port: 1080
    username: user
    password: pass
    udp: true
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::SocksProxy(socks) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected SOCKS proxy")
        };
        assert_eq!(socks.server_host, "proxy.example.com");
        assert_eq!(socks.server_port, 1080);
        assert_eq!(socks.username, "user");
        assert_eq!(socks.password, "pass");
        assert!(socks.udp);
        Ok(())
    }

    #[test]
    fn converts_mihomo_builtin_route_proxies() -> Result<()> {
        let yaml = r#"
proxies:
  - name: direct-out
    type: direct
  - name: reject-out
    type: reject
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Route(direct) =
            config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected direct route client")
        };
        assert_eq!(direct.default, RouteDecision::Direct);
        let MihomoClientConfig::Route(reject) =
            config.proxies[1].to_client_config("127.0.0.1:1081".parse()?)?
        else {
            bail!("expected reject route client")
        };
        assert_eq!(reject.default, RouteDecision::Block);
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
