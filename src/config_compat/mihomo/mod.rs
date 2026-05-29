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
    route_set_name,
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

use crate::config_compat::common::alpn_values;

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
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
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
        self.route_table_with_assets(None)
    }

    pub fn route_table_with_assets(&self, assets_dir: Option<&Path>) -> Result<RouteTable> {
        self.reject_unsupported_top_level_fields()?;
        let mut table = RouteTable::default();
        for (index, rule) in self.rules.iter().enumerate() {
            table
                .rules
                .extend(self.parse_mihomo_route_rules(rule, index)?);
        }
        if let Some(dir) = assets_dir {
            load_mihomo_route_assets(&mut table, dir)?;
        } else {
            ensure_mihomo_route_assets(&table, None)?;
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


mod proxy;
mod route;

pub use route::load_mihomo_route_assets;
use route::*;

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

fn option_text_has_data(value: Option<&String>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
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
mod tests;
