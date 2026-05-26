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
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoConfig {
    #[serde(default, rename = "mixed-port", alias = "mixed_port")]
    pub mixed_port: Option<u16>,
    #[serde(default, rename = "socks-port", alias = "socks_port")]
    pub socks_port: Option<u16>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default, rename = "redir-port", alias = "redir_port")]
    pub redir_port: Option<Value>,
    #[serde(default, rename = "tproxy-port", alias = "tproxy_port")]
    pub tproxy_port: Option<Value>,
    #[serde(default, rename = "allow-lan", alias = "allow_lan")]
    pub allow_lan: bool,
    #[serde(default, rename = "bind-address", alias = "bind_address")]
    pub bind_address: Option<String>,
    #[serde(default)]
    pub authentication: Option<Value>,
    #[serde(default, rename = "skip-auth-prefixes", alias = "skip_auth_prefixes")]
    pub skip_auth_prefixes: Option<Value>,
    #[serde(default, rename = "lan-allowed-ips", alias = "lan_allowed_ips")]
    pub lan_allowed_ips: Option<Value>,
    #[serde(default, rename = "lan-disallowed-ips", alias = "lan_disallowed_ips")]
    pub lan_disallowed_ips: Option<Value>,
    #[serde(default)]
    pub proxies: Vec<MihomoProxy>,
    #[serde(default, rename = "proxy-groups", alias = "proxy_groups")]
    pub proxy_groups: Vec<MihomoProxyGroup>,
    #[serde(default, rename = "rule-providers", alias = "rule_providers")]
    pub rule_providers: BTreeMap<String, MihomoRuleProvider>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub dns: MihomoDnsConfig,
    #[serde(default)]
    pub tun: Option<MihomoTunConfig>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
    #[serde(skip)]
    pub source_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoDnsConfig {
    #[serde(default, rename = "enhanced-mode", alias = "enhanced_mode")]
    pub enhanced_mode: Option<String>,
    #[serde(default, rename = "fake-ip-range", alias = "fake_ip_range")]
    pub fake_ip_range: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoRuleProvider {
    #[serde(rename = "type")]
    pub kind: String,
    pub behavior: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub payload: Vec<String>,
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub proxies: Vec<String>,
    #[serde(default, rename = "use")]
    pub use_providers: Vec<String>,
    #[serde(default, rename = "disable-udp", alias = "disable_udp")]
    pub disable_udp: bool,
    #[serde(default, rename = "include-all", alias = "include_all")]
    pub include_all: bool,
    #[serde(default, rename = "include-all-proxies", alias = "include_all_proxies")]
    pub include_all_proxies: bool,
    #[serde(
        default,
        rename = "include-all-providers",
        alias = "include_all_providers"
    )]
    pub include_all_providers: bool,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default, rename = "exclude-filter", alias = "exclude_filter")]
    pub exclude_filter: Option<String>,
    #[serde(default, rename = "exclude-type", alias = "exclude_type")]
    pub exclude_type: Option<String>,
    #[serde(default, rename = "interface-name", alias = "interface_name")]
    pub interface_name: Option<Value>,
    #[serde(default, rename = "routing-mark", alias = "routing_mark")]
    pub routing_mark: Option<Value>,
    #[serde(default)]
    pub url: Option<Value>,
    #[serde(default)]
    pub interval: Option<Value>,
    #[serde(default)]
    pub tolerance: Option<Value>,
    #[serde(default)]
    pub strategy: Option<Value>,
    #[serde(default)]
    pub lazy: Option<Value>,
    #[serde(default)]
    pub timeout: Option<Value>,
    #[serde(default, rename = "max-failed-times", alias = "max_failed_times")]
    pub max_failed_times: Option<Value>,
    #[serde(default, rename = "expected-status", alias = "expected_status")]
    pub expected_status: Option<Value>,
    #[serde(default)]
    pub hidden: Option<Value>,
    #[serde(default)]
    pub icon: Option<Value>,
    #[serde(flatten)]
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(default)]
    pub encryption: Option<String>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct MihomoRealityOpts {
    #[serde(rename = "public-key", alias = "public_key")]
    pub public_key: String,
    #[serde(default, rename = "short-id", alias = "short_id")]
    pub short_id: String,
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoWsOptions {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MihomoGrpcOptions {
    #[serde(default, rename = "grpc-service-name", alias = "grpc_service_name")]
    pub grpc_service_name: Option<String>,
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
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
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MihomoUdpOverTcpOptions {
    pub enabled: bool,
    pub version: Option<Value>,
    pub fields: BTreeMap<String, Value>,
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
                #[serde(flatten)]
                fields: BTreeMap<String, Value>,
            },
        }

        match Raw::deserialize(deserializer)? {
            Raw::Bool(enabled) => Ok(Self {
                enabled,
                version: None,
                fields: BTreeMap::new(),
            }),
            Raw::Object {
                enabled,
                version,
                fields,
            } => Ok(Self {
                enabled,
                version,
                fields,
            }),
        }
    }
}

impl MihomoUdpOverTcpOptions {
    fn enabled_for(&self, protocol: &str, name: &str) -> Result<bool> {
        ensure_no_extra_fields(
            &format!("mihomo {protocol} proxy {name} udp-over-tcp"),
            &self.fields,
        )?;
        if !self.enabled {
            ensure!(
                self.version
                    .as_ref()
                    .is_none_or(|value| !value_has_data(value)),
                "mihomo {protocol} proxy {name} sets udp-over-tcp version while udp-over-tcp is disabled"
            );
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

enum MihomoResolvedProxy<'a> {
    Proxy(&'a MihomoProxy),
    Route(RouteDecision),
}

impl MihomoConfig {
    pub fn reject_unsupported_top_level_fields(&self) -> Result<()> {
        ensure_no_extra_fields("mihomo config", &self.extra)?;
        self.dns.reject_unsupported_fields()?;
        if let Some(tun) = &self.tun {
            tun.reject_unsupported_fields()?;
        }
        Ok(())
    }

    pub fn proxy(&self, name: &str) -> Option<&MihomoProxy> {
        self.proxies.iter().find(|proxy| proxy.name() == name)
    }

    pub fn proxy_group(&self, name: &str) -> Option<&MihomoProxyGroup> {
        self.proxy_groups
            .iter()
            .find(|group| group.name.as_str() == name)
    }

    pub fn profile_names(&self) -> Vec<&str> {
        self.proxies
            .iter()
            .map(MihomoProxy::name)
            .chain(self.proxy_groups.iter().map(|group| group.name.as_str()))
            .collect()
    }

    pub fn resolved_proxy_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<MihomoClientConfig> {
        self.reject_unsupported_top_level_fields()?;
        match self.resolve_proxy_target(name)? {
            MihomoResolvedProxy::Proxy(proxy) => proxy.to_client_config(listen),
            MihomoResolvedProxy::Route(default) => {
                Ok(MihomoClientConfig::Route(RouteClientConfig {
                    listen,
                    default,
                }))
            }
        }
    }

    fn resolve_proxy_target<'a>(&'a self, name: &str) -> Result<MihomoResolvedProxy<'a>> {
        let mut current = name.trim().to_string();
        ensure!(!current.is_empty(), "mihomo proxy name is empty");
        let mut seen = BTreeSet::new();
        loop {
            match RouteDecision::from_outbound(&current)? {
                RouteDecision::Direct => {
                    return Ok(MihomoResolvedProxy::Route(RouteDecision::Direct));
                }
                RouteDecision::Block => {
                    return Ok(MihomoResolvedProxy::Route(RouteDecision::Block));
                }
                RouteDecision::Proxy(tag) => current = tag,
            }
            if let Some(proxy) = self.proxy(&current) {
                return Ok(MihomoResolvedProxy::Proxy(proxy));
            }
            ensure!(
                seen.insert(current.clone()),
                "mihomo proxy-group cycle includes {current}"
            );
            let group = self
                .proxy_group(&current)
                .with_context(|| format!("mihomo proxy {current} was not found"))?;
            current = group.static_target()?;
        }
    }

    pub fn local_socks_listen(&self) -> Result<Option<SocketAddr>> {
        self.reject_unsupported_top_level_fields()?;
        self.reject_unsupported_local_listener_options()?;
        let Some(port) = self.mixed_port.or(self.socks_port) else {
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

    fn reject_unsupported_local_listener_options(&self) -> Result<()> {
        ensure!(
            self.port.is_none(),
            "mihomo port is an HTTP proxy listener; Aerion config runner exposes a SOCKS listener only"
        );
        for (field, value, reason) in [
            (
                "redir-port",
                &self.redir_port,
                "redirect transparent proxy listener support",
            ),
            (
                "tproxy-port",
                &self.tproxy_port,
                "TPROXY transparent proxy listener support",
            ),
            (
                "authentication",
                &self.authentication,
                "authenticated local proxy listener support",
            ),
            (
                "skip-auth-prefixes",
                &self.skip_auth_prefixes,
                "local authentication bypass prefix support",
            ),
            (
                "lan-allowed-ips",
                &self.lan_allowed_ips,
                "LAN source allow-list enforcement",
            ),
            (
                "lan-disallowed-ips",
                &self.lan_disallowed_ips,
                "LAN source deny-list enforcement",
            ),
        ] {
            ensure!(
                !value.as_ref().map(value_has_data).unwrap_or(false),
                "mihomo {field} requires {reason}"
            );
        }
        Ok(())
    }

    pub fn route_table(&self) -> Result<RouteTable> {
        self.reject_unsupported_top_level_fields()?;
        let mut table = RouteTable::default();
        for (index, rule) in self.rules.iter().enumerate() {
            table
                .rules
                .extend(self.parse_mihomo_route_rules(rule, index)?);
        }
        Ok(table)
    }

    fn parse_mihomo_route_rules(&self, raw: &str, index: usize) -> Result<Vec<RouteRule>> {
        let location = format!("mihomo rules[{index}]");
        self.parse_mihomo_route_expr(raw, &location, None)
    }

    fn parse_mihomo_route_expr(
        &self,
        raw: &str,
        location: &str,
        action: Option<RouteDecision>,
    ) -> Result<Vec<RouteRule>> {
        let parts = split_mihomo_rule(raw);
        ensure!(
            !parts.is_empty() && !parts[0].is_empty(),
            "{location} is empty"
        );
        let kind = parts[0].to_ascii_uppercase();
        match kind.as_str() {
            "RULE-SET" => self.parse_mihomo_rule_set_expr(&parts, location, action),
            "OR" | "AND" | "NOT" => self.parse_mihomo_logical_expr(raw, location, action),
            _ => Ok(vec![parse_mihomo_route_rule_parts(
                &parts, location, action,
            )?]),
        }
    }

    fn parse_mihomo_rule_set_expr(
        &self,
        parts: &[&str],
        location: &str,
        action: Option<RouteDecision>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            parts.len() > 1 && !parts[1].is_empty(),
            "{location} RULE-SET is missing provider"
        );
        let action = match action {
            Some(action) => {
                ensure!(
                    parts.len() == 2,
                    "{location} RULE-SET child rule sets its own action"
                );
                action
            }
            None => {
                ensure!(parts.len() > 2, "{location} RULE-SET is missing outbound");
                RouteDecision::from_outbound(parts[2])?
            }
        };
        let provider = self
            .rule_providers
            .get(parts[1])
            .with_context(|| format!("{location} RULE-SET provider {} was not found", parts[1]))?;
        provider.to_route_rules(parts[1], self.source_dir.as_deref(), action)
    }

    fn parse_mihomo_logical_expr(
        &self,
        raw: &str,
        location: &str,
        action: Option<RouteDecision>,
    ) -> Result<Vec<RouteRule>> {
        let (kind, payload, action) = split_mihomo_logical_rule(raw, location, action)?;
        parse_mihomo_logical_rules(
            &kind,
            payload,
            location,
            action,
            |child, location, action| self.parse_mihomo_route_expr(child, location, Some(action)),
        )
    }

    pub fn tun_enabled(&self) -> bool {
        self.tun.as_ref().map(|tun| tun.enable).unwrap_or(false)
    }

    pub fn tun_config(&self, proxy_listen: SocketAddr) -> Result<Option<TunConfig>> {
        self.reject_unsupported_top_level_fields()?;
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

impl MihomoDnsConfig {
    fn reject_unsupported_fields(&self) -> Result<()> {
        ensure_no_extra_fields("mihomo dns", &self.extra)
    }
}

impl MihomoTunConfig {
    fn reject_unsupported_fields(&self) -> Result<()> {
        ensure_no_extra_fields("mihomo tun", &self.extra)
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

impl MihomoProxyGroup {
    fn static_target(&self) -> Result<String> {
        let kind = self.kind.trim().to_ascii_lowercase();
        match kind.as_str() {
            "select" => {
                self.ensure_static_group_supported("select")?;
                let target = self
                    .proxies
                    .first()
                    .map(|proxy| proxy.trim())
                    .filter(|proxy| !proxy.is_empty())
                    .with_context(|| {
                        format!("mihomo select proxy-group {} has no proxies", self.name)
                    })?;
                Ok(target.to_string())
            }
            "url-test" | "fallback" | "load-balance" | "relay" => {
                self.ensure_static_group_supported(&kind)?;
                let targets = self
                    .proxies
                    .iter()
                    .map(|proxy| proxy.trim())
                    .filter(|proxy| !proxy.is_empty())
                    .collect::<Vec<_>>();
                match targets.as_slice() {
                    [target] => Ok((*target).to_string()),
                    [] => bail!("mihomo {kind} proxy-group {} has no proxies", self.name),
                    _ if kind == "url-test" => bail!(
                        "mihomo url-test proxy-group {} requires active latency selection; Aerion only resolves single-proxy url-test groups statically",
                        self.name
                    ),
                    _ if kind == "fallback" => bail!(
                        "mihomo fallback proxy-group {} requires active health-check selection; Aerion only resolves single-proxy fallback groups statically",
                        self.name
                    ),
                    _ if kind == "load-balance" => bail!(
                        "mihomo load-balance proxy-group {} requires per-connection policy selection; Aerion only resolves single-proxy load-balance groups statically",
                        self.name
                    ),
                    _ => bail!(
                        "mihomo relay proxy-group {} requires proxy chaining; Aerion only resolves single-proxy relay groups statically",
                        self.name
                    ),
                }
            }
            other => bail!("unsupported mihomo proxy-group {} type {other}", self.name),
        }
    }

    fn ensure_static_group_supported(&self, kind: &str) -> Result<()> {
        ensure!(
            !self.disable_udp,
            "mihomo {kind} proxy-group {} disables UDP; Aerion route clients expose TCP and UDP together",
            self.name
        );
        let mut unsupported = Vec::new();
        if !self.use_providers.is_empty() {
            unsupported.push("use".to_string());
        }
        if self.include_all {
            unsupported.push("include-all".to_string());
        }
        if self.include_all_proxies {
            unsupported.push("include-all-proxies".to_string());
        }
        if self.include_all_providers {
            unsupported.push("include-all-providers".to_string());
        }
        if self.filter.is_some() {
            unsupported.push("filter".to_string());
        }
        if self.exclude_filter.is_some() {
            unsupported.push("exclude-filter".to_string());
        }
        if self.exclude_type.is_some() {
            unsupported.push("exclude-type".to_string());
        }
        if self.interface_name.is_some() {
            unsupported.push("interface-name".to_string());
        }
        if self.routing_mark.is_some() {
            unsupported.push("routing-mark".to_string());
        }
        unsupported.extend(self.fields.keys().cloned());
        ensure!(
            unsupported.is_empty(),
            "mihomo {kind} proxy-group {} has unsupported fields {:?}",
            self.name,
            unsupported
        );
        Ok(())
    }
}

impl MihomoRuleProvider {
    fn to_route_rules(
        &self,
        name: &str,
        source_dir: Option<&Path>,
        action: RouteDecision,
    ) -> Result<Vec<RouteRule>> {
        let lines = self.rule_lines(name, source_dir)?;
        let behavior = self.behavior.trim().to_ascii_lowercase();
        match behavior.as_str() {
            "domain" => {
                let mut rule = RouteRule::new(action);
                for line in lines {
                    rule.domains.push(mihomo_rule_provider_domain(&line)?);
                }
                ensure!(
                    !rule.domains.is_empty(),
                    "mihomo rule-provider {name} domain payload is empty"
                );
                Ok(vec![rule])
            }
            "ipcidr" | "ip-cidr" => {
                let mut rule = RouteRule::new(action);
                for line in lines {
                    rule.ip_cidrs.push(IpCidr::parse(&line)?);
                }
                ensure!(
                    !rule.ip_cidrs.is_empty(),
                    "mihomo rule-provider {name} ipcidr payload is empty"
                );
                Ok(vec![rule])
            }
            "classical" => {
                let mut rules = Vec::new();
                for (index, line) in lines.iter().enumerate() {
                    let location = format!("mihomo rule-provider {name} payload[{index}]");
                    rules.extend(parse_mihomo_route_expr_with_action(
                        line,
                        &location,
                        action.clone(),
                    )?);
                }
                ensure!(
                    !rules.is_empty(),
                    "mihomo rule-provider {name} classical payload is empty"
                );
                Ok(rules)
            }
            other => bail!("unsupported mihomo rule-provider {name} behavior {other}"),
        }
    }

    fn rule_lines(&self, name: &str, source_dir: Option<&Path>) -> Result<Vec<String>> {
        let kind = self.kind.trim().to_ascii_lowercase();
        match kind.as_str() {
            "inline" => Ok(clean_mihomo_rule_provider_lines(&self.payload)),
            "file" => {
                ensure!(
                    self.payload.is_empty(),
                    "mihomo file rule-provider {name} embeds inline payload"
                );
                let path = self
                    .path
                    .as_ref()
                    .with_context(|| format!("mihomo file rule-provider {name} is missing path"))?;
                let path = match (path.is_absolute(), source_dir) {
                    (true, _) | (false, None) => path.clone(),
                    (false, Some(source_dir)) => source_dir.join(path),
                };
                self.load_rule_file(name, &path)
            }
            "http" => bail!("mihomo http rule-provider {name} requires downloading rule-set data"),
            other => bail!("unsupported mihomo rule-provider {name} type {other}"),
        }
    }

    fn load_rule_file(&self, name: &str, path: &Path) -> Result<Vec<String>> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read mihomo rule-provider {name} file {}", path.display()))?;
        match self
            .format
            .as_deref()
            .map(str::trim)
            .filter(|format| !format.is_empty())
            .unwrap_or("yaml")
            .to_ascii_lowercase()
            .as_str()
        {
            "yaml" | "yml" => {
                #[derive(Deserialize)]
                struct RuleProviderFile {
                    payload: Vec<String>,
                }
                let file: RuleProviderFile = serde_yaml::from_str(&text).with_context(|| {
                    format!(
                        "parse mihomo rule-provider {name} YAML file {}",
                        path.display()
                    )
                })?;
                Ok(clean_mihomo_rule_provider_lines(&file.payload))
            }
            "text" => Ok(text
                .lines()
                .filter_map(mihomo_text_rule_provider_line)
                .map(str::to_string)
                .collect()),
            "mrs" => bail!("mihomo rule-provider {name} MRS format is not supported"),
            other => bail!("unsupported mihomo rule-provider {name} format {other}"),
        }
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
        ensure_no_proxy_extra_fields(
            &format!("mihomo Shadowsocks proxy {}", self.name),
            &self.fields,
        )?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo SOCKS proxy {}", self.name), &self.fields)?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo HTTP proxy {}", self.name), &self.fields)?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo VLESS proxy {}", self.name), &self.fields)?;
        if let Some(encryption) = self.encryption.as_deref().map(str::trim) {
            ensure!(
                encryption.is_empty() || encryption.eq_ignore_ascii_case("none"),
                "mihomo VLESS proxy {} uses encryption {}; Aerion VLESS supports none/empty encryption",
                self.name,
                encryption
            );
        }
        let reality = self
            .reality_opts
            .as_ref()
            .map(MihomoRealityOpts::to_client_config)
            .transpose()?;
        let network = self.network.trim();
        let transport = mihomo_transport_config(
            "VLESS",
            &self.name,
            network,
            self.ws_opts.as_ref(),
            self.grpc_opts.as_ref(),
            self.xhttp_opts.as_ref(),
        )?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo VMess proxy {}", self.name), &self.fields)?;
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
        let transport = mihomo_transport_config(
            "VMess",
            &self.name,
            network,
            self.ws_opts.as_ref(),
            self.grpc_opts.as_ref(),
            None,
        )?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo Trojan proxy {}", self.name), &self.fields)?;
        ensure!(
            self.tls,
            "mihomo Trojan proxy {} disables TLS; Trojan requires TLS in Aerion",
            self.name
        );
        let network = self.network.trim();
        let transport = mihomo_transport_config(
            "Trojan",
            &self.name,
            network,
            self.ws_opts.as_ref(),
            self.grpc_opts.as_ref(),
            None,
        )?;
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
        ensure_no_proxy_extra_fields(
            &format!("mihomo Hysteria2 proxy {}", self.name),
            &self.fields,
        )?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo AnyTLS proxy {}", self.name), &self.fields)?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo Mieru proxy {}", self.name), &self.fields)?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo Naive proxy {}", self.name), &self.fields)?;
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
        ensure_no_proxy_extra_fields(&format!("mihomo TUIC proxy {}", self.name), &self.fields)?;
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
        ensure_no_extra_fields("mihomo reality-opts", &self.fields)?;
        RealityClientConfig::from_strings(&self.public_key, &self.short_id)
    }
}

impl MihomoSmuxOptions {
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn has_settings(&self) -> bool {
        self.enabled
            || self
                .protocol
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || self.max_connections.is_some()
            || self.min_streams.is_some()
            || self.max_streams.is_some()
            || !self.fields.is_empty()
    }

    fn ensure_supported(&self, name: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("mihomo proxy {name} smux"), &self.fields)?;
        ensure!(
            !self.has_settings(),
            "mihomo proxy {name} sets smux options; Aerion VLESS mux.cool is not wire-compatible with mihomo smux"
        );
        Ok(())
    }
}

impl MihomoWsOptions {
    fn ensure_supported(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(owner, &self.fields)
    }

    fn has_settings(&self) -> bool {
        self.path
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || !self.headers.is_empty()
            || !self.fields.is_empty()
    }
}

impl MihomoGrpcOptions {
    fn ensure_supported(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(owner, &self.fields)
    }

    fn has_settings(&self) -> bool {
        self.grpc_service_name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || !self.fields.is_empty()
    }
}

impl MihomoXhttpOptions {
    fn ensure_supported(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(owner, &self.fields)
    }

    fn has_settings(&self) -> bool {
        self.path
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || self
                .host
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || self
                .mode
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || !self.headers.is_empty()
            || !self.fields.is_empty()
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

fn ensure_no_extra_fields(owner: &str, fields: &BTreeMap<String, Value>) -> Result<()> {
    ensure!(
        fields.is_empty(),
        "{owner} has unsupported fields {:?}",
        fields.keys().collect::<Vec<_>>()
    );
    Ok(())
}

fn ensure_no_proxy_extra_fields(owner: &str, fields: &BTreeMap<String, Value>) -> Result<()> {
    let unsupported = fields
        .keys()
        .filter(|key| !key.eq_ignore_ascii_case("type"))
        .collect::<Vec<_>>();
    ensure!(
        unsupported.is_empty(),
        "{owner} has unsupported fields {:?}",
        unsupported
    );
    Ok(())
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

fn mihomo_transport_config(
    protocol: &str,
    name: &str,
    network: &str,
    ws_opts: Option<&MihomoWsOptions>,
    grpc_opts: Option<&MihomoGrpcOptions>,
    xhttp_opts: Option<&MihomoXhttpOptions>,
) -> Result<VlessTransportConfig> {
    let normalized = network.trim().to_ascii_lowercase().replace(['-', '_'], "");
    match normalized.as_str() {
        "grpc" => {
            ensure_unused_ws_opts(protocol, name, ws_opts)?;
            ensure_unused_xhttp_opts(protocol, name, xhttp_opts)?;
            if let Some(opts) = grpc_opts {
                opts.ensure_supported(&format!("mihomo {protocol} proxy {name} grpc-opts"))?;
            }
            VlessTransportConfig::from_network(
                network,
                grpc_opts.and_then(|opts| opts.grpc_service_name.clone()),
                None,
                Vec::new(),
            )
        }
        "xhttp" | "splithttp" => {
            ensure!(
                protocol.eq_ignore_ascii_case("VLESS"),
                "mihomo {protocol} proxy {name} uses {network}; Aerion only wires XHTTP transport for VLESS"
            );
            ensure_unused_ws_opts(protocol, name, ws_opts)?;
            ensure_unused_grpc_opts(protocol, name, grpc_opts)?;
            if let Some(opts) = xhttp_opts {
                opts.ensure_supported(&format!("mihomo {protocol} proxy {name} xhttp-opts"))?;
            }
            VlessTransportConfig::xhttp(
                xhttp_opts.and_then(|opts| opts.path.clone()),
                xhttp_opts.and_then(|opts| opts.host.clone()),
                xhttp_opts
                    .map(|opts| opts.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
                xhttp_opts.and_then(|opts| opts.mode.clone()),
            )
        }
        "ws" | "websocket" => {
            ensure_unused_grpc_opts(protocol, name, grpc_opts)?;
            ensure_unused_xhttp_opts(protocol, name, xhttp_opts)?;
            if let Some(opts) = ws_opts {
                opts.ensure_supported(&format!("mihomo {protocol} proxy {name} ws-opts"))?;
            }
            VlessTransportConfig::from_headers(
                network,
                ws_opts.and_then(|opts| opts.path.clone()),
                ws_opts.map(|opts| opts.headers.clone()).unwrap_or_default(),
            )
        }
        _ => {
            ensure_unused_ws_opts(protocol, name, ws_opts)?;
            ensure_unused_grpc_opts(protocol, name, grpc_opts)?;
            ensure_unused_xhttp_opts(protocol, name, xhttp_opts)?;
            VlessTransportConfig::from_network(network, None, None, Vec::new())
        }
    }
}

fn ensure_unused_ws_opts(protocol: &str, name: &str, opts: Option<&MihomoWsOptions>) -> Result<()> {
    if let Some(opts) = opts {
        opts.ensure_supported(&format!("mihomo {protocol} proxy {name} ws-opts"))?;
        ensure!(
            !opts.has_settings(),
            "mihomo {protocol} proxy {name} sets ws-opts while network is not WebSocket"
        );
    }
    Ok(())
}

fn ensure_unused_grpc_opts(
    protocol: &str,
    name: &str,
    opts: Option<&MihomoGrpcOptions>,
) -> Result<()> {
    if let Some(opts) = opts {
        opts.ensure_supported(&format!("mihomo {protocol} proxy {name} grpc-opts"))?;
        ensure!(
            !opts.has_settings(),
            "mihomo {protocol} proxy {name} sets grpc-opts while network is not gRPC"
        );
    }
    Ok(())
}

fn ensure_unused_xhttp_opts(
    protocol: &str,
    name: &str,
    opts: Option<&MihomoXhttpOptions>,
) -> Result<()> {
    if let Some(opts) = opts {
        opts.ensure_supported(&format!("mihomo {protocol} proxy {name} xhttp-opts"))?;
        ensure!(
            !opts.has_settings(),
            "mihomo {protocol} proxy {name} sets xhttp-opts while network is not XHTTP"
        );
    }
    Ok(())
}

fn ensure_no_smux(name: &str, smux: Option<&MihomoSmuxOptions>) -> Result<()> {
    if let Some(smux) = smux {
        smux.ensure_supported(name)?;
    }
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

fn split_mihomo_rule(raw: &str) -> Vec<&str> {
    raw.split(',').map(str::trim).collect()
}

fn split_mihomo_logical_rule<'a>(
    raw: &'a str,
    location: &str,
    action: Option<RouteDecision>,
) -> Result<(String, &'a str, RouteDecision)> {
    let (kind, rest) = raw
        .split_once(',')
        .with_context(|| format!("{location} logical rule is missing payload"))?;
    let kind = kind.trim().to_ascii_uppercase();
    let rest = rest.trim();
    ensure!(
        rest.starts_with('('),
        "{location} {kind} rule is missing payload"
    );
    let mut depth = 0usize;
    let mut payload_end = None;
    for (index, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                ensure!(depth > 0, "{location} {kind} rule has unmatched ')'");
                depth -= 1;
                if depth == 0 {
                    payload_end = Some(index + ch.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }
    let payload_end =
        payload_end.with_context(|| format!("{location} {kind} rule has unclosed payload"))?;
    let payload = &rest[..payload_end];
    let trailing = rest[payload_end..].trim();
    let action = match action {
        Some(action) => {
            ensure!(
                trailing.is_empty(),
                "{location} {kind} child rule sets its own action"
            );
            action
        }
        None => {
            let trailing = trailing
                .strip_prefix(',')
                .map(str::trim)
                .with_context(|| format!("{location} {kind} rule is missing outbound"))?;
            let values = trailing
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            ensure!(
                !values.is_empty(),
                "{location} {kind} rule is missing outbound"
            );
            ensure!(
                values.len() == 1,
                "{location} {kind} rule has unsupported trailing fields {:?}",
                &values[1..]
            );
            RouteDecision::from_outbound(values[0])?
        }
    };
    Ok((kind, payload, action))
}

fn mihomo_logical_children<'a>(payload: &'a str, location: &str) -> Result<Vec<&'a str>> {
    let payload = payload.trim();
    ensure!(
        payload.starts_with('(') && payload.ends_with(')'),
        "{location} logical payload must be enclosed in parentheses"
    );
    let inner = payload[1..payload.len() - 1].trim();
    let mut children = Vec::new();
    let mut cursor = 0usize;
    while cursor < inner.len() {
        let tail = inner[cursor..].trim_start();
        cursor = inner.len() - tail.len();
        if tail.starts_with(',') {
            cursor += 1;
            continue;
        }
        ensure!(
            tail.starts_with('('),
            "{location} logical payload has non-rule text {}",
            tail
        );
        let start = cursor;
        let mut depth = 0usize;
        let mut end = None;
        for (offset, ch) in inner[start..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    ensure!(depth > 0, "{location} logical payload has unmatched ')'");
                    depth -= 1;
                    if depth == 0 {
                        end = Some(start + offset + ch.len_utf8());
                        break;
                    }
                }
                _ => {}
            }
        }
        let end =
            end.with_context(|| format!("{location} logical payload has unclosed child rule"))?;
        children.push(inner[start + 1..end - 1].trim());
        cursor = end;
    }
    Ok(children)
}

fn parse_mihomo_logical_rules<F>(
    kind: &str,
    payload: &str,
    location: &str,
    action: RouteDecision,
    mut parse_child: F,
) -> Result<Vec<RouteRule>>
where
    F: FnMut(&str, &str, RouteDecision) -> Result<Vec<RouteRule>>,
{
    if kind == "NOT" {
        bail!("{location} NOT requires negative route matching");
    }
    let children = mihomo_logical_children(payload, location)?;
    ensure!(
        !children.is_empty(),
        "{location} {kind} rule has no child rules"
    );
    if kind == "OR" {
        let mut rules = Vec::new();
        for (child_index, child) in children.iter().enumerate() {
            let child_location = format!("{location} {kind}[{child_index}]");
            rules.extend(parse_child(child, &child_location, action.clone())?);
        }
        return Ok(rules);
    }

    let mut branches = vec![RouteRule::new(action.clone())];
    for (child_index, child) in children.iter().enumerate() {
        let child_location = format!("{location} {kind}[{child_index}]");
        let child_rules = parse_child(child, &child_location, action.clone())?;
        ensure!(
            !child_rules.is_empty(),
            "{child_location} expands to no route rules"
        );
        let mut next = Vec::new();
        for branch in &branches {
            for child_rule in &child_rules {
                let mut merged = branch.clone();
                merge_mihomo_and_route_rule(&mut merged, child_rule.clone(), &child_location)?;
                next.push(merged);
            }
        }
        branches = next;
    }
    Ok(branches)
}

fn parse_mihomo_route_expr_with_action(
    raw: &str,
    location: &str,
    action: RouteDecision,
) -> Result<Vec<RouteRule>> {
    let parts = split_mihomo_rule(raw);
    ensure!(
        !parts.is_empty() && !parts[0].is_empty(),
        "{location} is empty"
    );
    let kind = parts[0].to_ascii_uppercase();
    match kind.as_str() {
        "RULE-SET" => bail!("{location} nested RULE-SET requires rule-set expansion"),
        "OR" | "AND" | "NOT" => {
            let (kind, payload, action) = split_mihomo_logical_rule(raw, location, Some(action))?;
            parse_mihomo_logical_rules(
                &kind,
                payload,
                location,
                action,
                |child, location, action| {
                    parse_mihomo_route_expr_with_action(child, location, action)
                },
            )
        }
        _ => Ok(vec![parse_mihomo_route_rule_parts(
            &parts,
            location,
            Some(action),
        )?]),
    }
}

fn parse_mihomo_route_rule_parts(
    parts: &[&str],
    location: &str,
    action: Option<RouteDecision>,
) -> Result<RouteRule> {
    ensure!(
        !parts.is_empty() && !parts[0].is_empty(),
        "{location} is empty"
    );
    let kind = parts[0].to_ascii_uppercase();
    let action_index = if matches!(kind.as_str(), "MATCH" | "FINAL") {
        1
    } else {
        2
    };
    let inherited_action = action.is_some();
    let action = match action {
        Some(action) => action,
        None => {
            ensure!(parts.len() > action_index, "{location} is missing outbound");
            RouteDecision::from_outbound(parts[action_index])?
        }
    };
    if !matches!(kind.as_str(), "MATCH" | "FINAL") {
        ensure!(
            parts.len() > 1 && !parts[1].is_empty(),
            "{location} is missing rule value"
        );
    }
    let param_start = if inherited_action {
        if matches!(kind.as_str(), "MATCH" | "FINAL") {
            1
        } else {
            2
        }
    } else {
        action_index + 1
    };
    let params = parts.get(param_start..).unwrap_or(&[]);
    if params.iter().any(|param| param.eq_ignore_ascii_case("src")) {
        bail!("{location} src route parameter requires source IP metadata");
    }
    for param in params.iter().filter(|param| !param.is_empty()) {
        ensure!(
            param.eq_ignore_ascii_case("no-resolve"),
            "{location} unsupported mihomo route parameter {param}"
        );
    }
    let mut rule = RouteRule::new(action);
    match kind.as_str() {
        "DOMAIN" => rule.domains.push(DomainMatcher::exact(parts[1])),
        "DOMAIN-SUFFIX" => rule.domains.push(DomainMatcher::suffix(parts[1])),
        "DOMAIN-KEYWORD" => rule.domains.push(DomainMatcher::keyword(parts[1])),
        "DOMAIN-WILDCARD" => rule.domains.push(DomainMatcher::wildcard(parts[1])?),
        "DOMAIN-REGEX" => rule.domains.push(DomainMatcher::regex(parts[1])?),
        "GEOSITE" => bail!("{location} GEOSITE requires geosite rule-set data"),
        "IP-CIDR" | "IP-CIDR6" => rule.ip_cidrs.push(IpCidr::parse(parts[1])?),
        "GEOIP" if parts[1].eq_ignore_ascii_case("private") => rule.ip_is_private = true,
        "GEOIP" => bail!("{location} GEOIP requires geoip rule-set data"),
        "DST-PORT" => rule.ports.push(PortRange::parse(parts[1])?),
        "NETWORK" => rule.networks.push(RouteNetwork::parse(parts[1])?),
        "MATCH" | "FINAL" => {}
        "RULE-SET" => bail!("{location} nested RULE-SET requires rule-set expansion"),
        "SRC-IP-CIDR" | "SRC-PORT" => bail!("{location} source rules require source metadata"),
        "PROCESS-NAME" | "PROCESS-PATH" => {
            bail!("{location} process rules require process metadata")
        }
        other => bail!("{location} unsupported mihomo route rule type {other}"),
    }
    Ok(rule)
}

fn merge_mihomo_and_route_rule(
    target: &mut RouteRule,
    rule: RouteRule,
    location: &str,
) -> Result<()> {
    ensure!(
        target.networks.is_empty() || rule.networks.is_empty(),
        "{location} AND combines multiple network matchers"
    );
    let target_has_domain = !target.domains.is_empty() || !target.geosite_sets.is_empty();
    let rule_has_domain = !rule.domains.is_empty() || !rule.geosite_sets.is_empty();
    ensure!(
        !target_has_domain || !rule_has_domain,
        "{location} AND combines multiple domain matchers"
    );
    let target_has_ip =
        target.ip_is_private || !target.ip_cidrs.is_empty() || !target.geoip_sets.is_empty();
    let rule_has_ip =
        rule.ip_is_private || !rule.ip_cidrs.is_empty() || !rule.geoip_sets.is_empty();
    ensure!(
        !target_has_domain || !rule_has_ip,
        "{location} AND combines destination domain and IP matchers, which requires DNS resolution"
    );
    ensure!(
        !target_has_ip || !rule_has_domain,
        "{location} AND combines destination IP and domain matchers, which requires DNS resolution"
    );
    ensure!(
        target.ip_cidrs.is_empty() || rule.ip_cidrs.is_empty(),
        "{location} AND combines multiple IP CIDR matchers"
    );
    ensure!(
        target.geoip_sets.is_empty() || rule.geoip_sets.is_empty(),
        "{location} AND combines multiple geoip matchers"
    );
    ensure!(
        target.ports.is_empty() || rule.ports.is_empty(),
        "{location} AND combines multiple port matchers"
    );
    target.networks.extend(rule.networks);
    target.domains.extend(rule.domains);
    target.geosite_sets.extend(rule.geosite_sets);
    target.ip_cidrs.extend(rule.ip_cidrs);
    target.geoip_sets.extend(rule.geoip_sets);
    target.ip_is_private |= rule.ip_is_private;
    target.ports.extend(rule.ports);
    Ok(())
}

fn mihomo_rule_provider_domain(value: &str) -> Result<DomainMatcher> {
    DomainMatcher::clash_wildcard(value)
}

fn clean_mihomo_rule_provider_lines(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn mihomo_text_rule_provider_line(line: &str) -> Option<&str> {
    let line = line.split('#').next().unwrap_or_default().trim();
    (!line.is_empty()).then_some(line)
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
    use std::fs;

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
    fn resolves_select_proxy_group_to_first_proxy() -> Result<()> {
        let yaml = r#"
proxy-groups:
  - name: auto
    type: select
    proxies:
      - http-a
      - DIRECT
proxies:
  - name: http-a
    type: http
    server: proxy.example.com
    port: 8080
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        assert_eq!(config.profile_names(), vec!["http-a", "auto"]);
        let MihomoClientConfig::HttpProxy(http) =
            config.resolved_proxy_config("auto", "127.0.0.1:1080".parse()?)?
        else {
            bail!("expected selected HTTP proxy")
        };
        assert_eq!(http.server_host, "proxy.example.com");
        assert_eq!(http.server_port, 8080);
        Ok(())
    }

    #[test]
    fn resolves_select_proxy_group_to_builtin_route() -> Result<()> {
        let yaml = r#"
proxy-groups:
  - name: direct-group
    type: select
    proxies:
      - DIRECT
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Route(route) =
            config.resolved_proxy_config("direct-group", "127.0.0.1:1080".parse()?)?
        else {
            bail!("expected direct route client")
        };
        assert_eq!(route.default, RouteDecision::Direct);
        Ok(())
    }

    #[test]
    fn rejects_mihomo_proxy_group_cycles() -> Result<()> {
        let yaml = r#"
proxy-groups:
  - name: a
    type: select
    proxies: [b]
  - name: b
    type: select
    proxies: [a]
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let error = config
            .resolved_proxy_config("a", "127.0.0.1:1080".parse()?)
            .expect_err("proxy-group cycles must fail");
        assert!(error.to_string().contains("cycle"));
        Ok(())
    }

    #[test]
    fn resolves_single_mihomo_policy_group_to_target() -> Result<()> {
        let yaml = r#"
proxy-groups:
  - name: auto
    type: url-test
    proxies: [DIRECT]
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let MihomoClientConfig::Route(route) =
            config.resolved_proxy_config("auto", "127.0.0.1:1080".parse()?)?
        else {
            bail!("expected static url-test direct route client")
        };
        assert_eq!(route.default, RouteDecision::Direct);
        Ok(())
    }

    #[test]
    fn rejects_mihomo_policy_proxy_groups_without_static_equivalence() -> Result<()> {
        let yaml = r#"
proxy-groups:
  - name: auto
    type: url-test
    proxies: [DIRECT, REJECT]
    url: https://www.gstatic.com/generate_204
    interval: 300
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let error = config
            .resolved_proxy_config("auto", "127.0.0.1:1080".parse()?)
            .expect_err("url-test requires active selection");
        assert!(error.to_string().contains("single-proxy"));
        Ok(())
    }

    #[test]
    fn compiles_mihomo_route_rules() -> Result<()> {
        let yaml = r#"
proxies: []
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - DOMAIN-KEYWORD,video,proxy-a
  - DOMAIN-WILDCARD,*.cdn?.example.org,proxy-c
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
            routes.decide(
                &ProxyTarget::Domain("img.cdn1.example.org".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-c".to_string())
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
    fn compiles_mihomo_logical_route_rules() -> Result<()> {
        let yaml = r#"
proxies: []
rules:
  - OR,((DOMAIN-SUFFIX,video.example),(DOMAIN-KEYWORD,stream)),proxy-a
  - AND,((DOMAIN-SUFFIX,api.example),(NETWORK,tcp)),proxy-b
  - AND,((OR,((DOMAIN-SUFFIX,cdn.example),(DOMAIN-SUFFIX,asset.example))),(DST-PORT,443)),proxy-c
  - MATCH,DIRECT
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let routes = config.route_table()?;
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("img.video.example".to_string(), 80),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("live.stream.test".to_string(), 80),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("www.api.example".to_string(), 80),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-b".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("www.api.example".to_string(), 80),
                RouteNetwork::Udp
            ),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("edge.asset.example".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-c".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("edge.asset.example".to_string(), 80),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );
        Ok(())
    }

    #[test]
    fn rejects_mihomo_logical_not_and_unrepresentable_and_rules() -> Result<()> {
        let not_yaml = r#"
proxies: []
rules:
  - NOT,((DOMAIN-SUFFIX,example.com)),DIRECT
"#;
        let config: MihomoConfig = serde_yaml::from_str(not_yaml)?;
        let error = config
            .route_table()
            .expect_err("NOT needs negative matching");
        assert!(error.to_string().contains("negative route matching"));

        let and_yaml = r#"
proxies: []
rules:
  - AND,((DOMAIN-SUFFIX,example.com),(DOMAIN-KEYWORD,video)),DIRECT
"#;
        let config: MihomoConfig = serde_yaml::from_str(and_yaml)?;
        let error = config
            .route_table()
            .expect_err("AND of multiple domain matchers must fail explicitly");
        assert!(error.to_string().contains("multiple domain matchers"));

        let src_yaml = r#"
proxies: []
rules:
  - IP-CIDR,10.0.0.0/8,DIRECT,src
"#;
        let config: MihomoConfig = serde_yaml::from_str(src_yaml)?;
        let error = config
            .route_table()
            .expect_err("src route parameter requires source metadata");
        assert!(error.to_string().contains("source IP metadata"));

        let geo_yaml = r#"
proxies: []
rules:
  - GEOSITE,category-ads-all,REJECT
"#;
        let config: MihomoConfig = serde_yaml::from_str(geo_yaml)?;
        let error = config
            .route_table()
            .expect_err("direct GEOSITE must fail without data");
        assert!(error.to_string().contains("geosite rule-set data"));

        let geoip_yaml = r#"
proxies: []
rules:
  - GEOIP,CN,DIRECT
"#;
        let config: MihomoConfig = serde_yaml::from_str(geoip_yaml)?;
        let error = config
            .route_table()
            .expect_err("direct GEOIP must fail without data");
        assert!(error.to_string().contains("geoip rule-set data"));
        Ok(())
    }

    #[test]
    fn compiles_mihomo_inline_rule_providers() -> Result<()> {
        let yaml = r#"
rule-providers:
  ads:
    type: inline
    behavior: domain
    payload:
      - .example.com
      - +.cdn.test
      - '*.media.example.net'
  lan:
    type: inline
    behavior: ipcidr
    payload:
      - 10.0.0.0/8
  mixed:
    type: inline
    behavior: classical
    payload:
      - DOMAIN-KEYWORD,video
      - DST-PORT,53
      - OR,((DOMAIN-SUFFIX,or-a.test),(DOMAIN-SUFFIX,or-b.test))
      - AND,((DOMAIN-SUFFIX,and.test),(DST-PORT,8443))
rules:
  - RULE-SET,ads,REJECT
  - RULE-SET,lan,DIRECT
  - RULE-SET,mixed,proxy-a
  - MATCH,proxy-b
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let routes = config.route_table()?;
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Block
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("cdn.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Block
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("sub.media.example.net".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Block
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("deep.sub.media.example.net".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-b".to_string())
        );
        assert_eq!(
            routes.decide(&ProxyTarget::Ip("10.1.2.3:443".parse()?), RouteNetwork::Tcp),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("video.example.net".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("dns.example.net".to_string(), 53),
                RouteNetwork::Udp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("cdn.or-b.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.and.test".to_string(), 8443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.and.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-b".to_string())
        );
        Ok(())
    }

    #[test]
    fn compiles_mihomo_file_rule_providers_relative_to_config() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(
            dir.path().join("ads.yaml"),
            r#"
payload:
  - +.example.com
"#,
        )?;
        let yaml = r#"
rule-providers:
  ads:
    type: file
    behavior: domain
    path: ads.yaml
rules:
  - RULE-SET,ads,REJECT
  - MATCH,DIRECT
"#;
        let mut config: MihomoConfig = serde_yaml::from_str(yaml)?;
        config.source_dir = Some(dir.path().to_path_buf());
        let routes = config.route_table()?;
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Block
        );
        Ok(())
    }

    #[test]
    fn rejects_mihomo_http_rule_provider_without_remote_loader() -> Result<()> {
        let yaml = r#"
rule-providers:
  remote:
    type: http
    behavior: domain
    url: https://rules.example.test/ads.yaml
    path: ./ads.yaml
rules:
  - RULE-SET,remote,REJECT
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let error = config
            .route_table()
            .expect_err("http rule-provider must fail explicitly");
        assert!(error.to_string().contains("requires downloading"));
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
    fn rejects_mihomo_unsupported_local_listener_options() -> Result<()> {
        let yaml = r#"
socks-port: 7890
authentication:
  - user:pass
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let auth_error = config
            .local_socks_listen()
            .expect_err("local listener authentication must not be ignored");
        assert!(auth_error.to_string().contains("authentication"));

        let yaml = r#"
port: 8080
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let port_error = config
            .local_socks_listen()
            .expect_err("HTTP-only port must not be exposed as SOCKS");
        assert!(port_error.to_string().contains("HTTP proxy listener"));

        let yaml = r#"
socks-port: 7890
redir-port: 7892
lan-allowed-ips:
  - 192.168.0.0/16
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let redir_error = config
            .local_socks_listen()
            .expect_err("transparent proxy listeners must not be ignored");
        assert!(redir_error.to_string().contains("redir-port"));
        Ok(())
    }

    #[test]
    fn rejects_mihomo_unsupported_top_level_options() -> Result<()> {
        let yaml = r#"
log-level: debug
mixed-port: 7890
proxies:
  - name: direct-out
    type: direct
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let error = config
            .local_socks_listen()
            .expect_err("unsupported mihomo top-level options must not be ignored");
        assert!(error.to_string().contains("mihomo config"));
        assert!(error.to_string().contains("log-level"));
        Ok(())
    }

    #[test]
    fn rejects_mihomo_unsupported_dns_and_tun_fields() -> Result<()> {
        let yaml = r#"
mixed-port: 7890
dns:
  enhanced-mode: fake-ip
  nameserver:
    - 1.1.1.1
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let dns_error = config
            .local_socks_listen()
            .expect_err("unsupported mihomo dns fields must not be ignored");
        assert!(dns_error.to_string().contains("mihomo dns"));
        assert!(dns_error.to_string().contains("nameserver"));

        let yaml = r#"
mixed-port: 7890
tun:
  enable: true
  stack: system
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let tun_error = config
            .tun_config("127.0.0.1:7890".parse()?)
            .expect_err("unsupported mihomo tun fields must not be ignored");
        assert!(tun_error.to_string().contains("mihomo tun"));
        assert!(tun_error.to_string().contains("stack"));
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
    fn rejects_mihomo_unsupported_proxy_and_transport_fields() -> Result<()> {
        let yaml = r#"
proxies:
  - name: vless-dialer
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    dialer-proxy: bootstrap
  - name: vless-ws-early
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: ws
    ws-opts:
      path: /vless
      max-early-data: 2048
  - name: vless-unused-ws
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: tcp
    ws-opts:
      path: /ignored
  - name: vless-xhttp-extra
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: xhttp
    alpn: http/1.1
    xhttp-opts:
      path: /xhttp
      no-grpc-header: true
  - name: vless-reality-extra
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    tls: true
    reality-opts:
      public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
      short-id: a1b2
      server-name: www.example.com
  - name: vless-smux-disabled-fields
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    smux:
      enabled: false
      protocol: h2mux
"#;
        let config: MihomoConfig = serde_yaml::from_str(yaml)?;
        let dialer_error = config.proxies[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported proxy fields must not be ignored");
        assert!(dialer_error.to_string().contains("dialer-proxy"));

        let ws_error = config.proxies[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported ws-opts fields must not be ignored");
        assert!(ws_error.to_string().contains("ws-opts"));
        assert!(ws_error.to_string().contains("max-early-data"));

        let unused_ws_error = config.proxies[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unused ws-opts must not be ignored");
        assert!(
            unused_ws_error
                .to_string()
                .contains("network is not WebSocket")
        );

        let xhttp_error = config.proxies[3]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported xhttp-opts fields must not be ignored");
        assert!(xhttp_error.to_string().contains("xhttp-opts"));
        assert!(xhttp_error.to_string().contains("no-grpc-header"));

        let reality_error = config.proxies[4]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported reality-opts fields must not be ignored");
        assert!(reality_error.to_string().contains("reality-opts"));
        assert!(reality_error.to_string().contains("server-name"));

        let smux_error = config.proxies[5]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("disabled smux fields must not be ignored");
        assert!(smux_error.to_string().contains("smux"));
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
