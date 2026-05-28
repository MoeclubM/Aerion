use crate::client::ClientConfig;
use crate::config_compat::mihomo::OneOrManyStrings;
use crate::http_connect::HttpProxyClientConfig;
use crate::hysteria2::{Hysteria2ClientConfig, Hysteria2ServerConfig};
use crate::mieru::{
    MieruClientConfig, MieruServerConfig, MieruTrafficPattern, MieruTransport, MieruUser,
};
use crate::naive::{NaiveClientConfig, NaiveServerConfig, default_naive_quic_congestion_control};
use crate::padding::PaddingScheme;
use crate::reality::{RealityClientConfig, RealityServerConfig};
use crate::router::RouteClientConfig;
use crate::routing::{
    DomainMatcher, IpCidr, PortRange, RouteDecision, RouteNetwork, RouteRule, RouteTable,
};
use crate::server::ServerConfig;
use crate::shadowsocks::{ShadowsocksClientConfig, ShadowsocksServerConfig};
use crate::socks::SocksProxyClientConfig;
use crate::tls_ech::{TlsEchServerKeys, tls_ech_from_singbox_value};
use crate::trojan::{TrojanClientConfig, TrojanServerConfig};
use crate::tuic::{TuicClientConfig, TuicServerConfig};
use crate::tun::{TunConfig, socks_proxy_url};
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::{VlessClientConfig, VlessServerConfig};
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::{VmessClientConfig, VmessServerConfig, ensure_vmess_packet_encoding};
use anyhow::{Context, Result, bail, ensure};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxConfig {
    #[serde(default)]
    pub inbounds: Vec<SingBoxInbound>,
    #[serde(default)]
    pub outbounds: Vec<SingBoxOutbound>,
    #[serde(default)]
    pub route: Option<SingBoxRouteConfig>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
    #[serde(skip)]
    pub source_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxRouteConfig {
    #[serde(default)]
    pub rules: Vec<SingBoxRouteRule>,
    #[serde(default, rename = "rule_set")]
    pub rule_sets: Vec<SingBoxRuleSet>,
    #[serde(default, rename = "final")]
    pub final_outbound: Option<String>,
    #[serde(default, rename = "auto_detect_interface")]
    pub auto_detect_interface: Option<Value>,
    #[serde(default, rename = "override_android_vpn")]
    pub override_android_vpn: Option<Value>,
    #[serde(default, rename = "default_interface")]
    pub default_interface: Option<Value>,
    #[serde(default, rename = "default_mark")]
    pub default_mark: Option<Value>,
    #[serde(default, rename = "default_domain_resolver")]
    pub default_domain_resolver: Option<Value>,
    #[serde(default, rename = "default_network_strategy")]
    pub default_network_strategy: Option<Value>,
    #[serde(default, rename = "default_network_type")]
    pub default_network_type: Option<Value>,
    #[serde(default, rename = "default_fallback_network_type")]
    pub default_fallback_network_type: Option<Value>,
    #[serde(default, rename = "default_fallback_delay")]
    pub default_fallback_delay: Option<Value>,
    #[serde(default, rename = "find_process")]
    pub find_process: Option<Value>,
    #[serde(default, rename = "find_neighbor")]
    pub find_neighbor: Option<Value>,
    #[serde(default, rename = "dhcp_lease_files")]
    pub dhcp_lease_files: Option<Value>,
    #[serde(default, rename = "default_http_client")]
    pub default_http_client: Option<Value>,
    #[serde(default, rename = "default_transport")]
    pub default_transport: Option<Value>,
    #[serde(default, rename = "default_udp_timeout")]
    pub default_udp_timeout: Option<Value>,
    #[serde(default, rename = "geoip")]
    pub geoip: Option<Value>,
    #[serde(default, rename = "geosite")]
    pub geosite: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxRouteRule {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub outbound: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub invert: bool,
    #[serde(default)]
    pub rules: Vec<SingBoxRouteRule>,
    #[serde(default)]
    pub network: Option<Value>,
    #[serde(default)]
    pub domain: Option<Value>,
    #[serde(default, rename = "domain_suffix")]
    pub domain_suffix: Option<Value>,
    #[serde(default, rename = "domain_keyword")]
    pub domain_keyword: Option<Value>,
    #[serde(default, rename = "domain_regex")]
    pub domain_regex: Option<Value>,
    #[serde(default)]
    pub geosite: Option<Value>,
    #[serde(default)]
    pub inbound: Option<Value>,
    #[serde(default, rename = "ip_version")]
    pub ip_version: Option<Value>,
    #[serde(default, rename = "auth_user")]
    pub auth_user: Option<Value>,
    #[serde(default)]
    pub protocol: Option<Value>,
    #[serde(default)]
    pub client: Option<Value>,
    #[serde(default, rename = "ip_cidr")]
    pub ip_cidr: Option<Value>,
    #[serde(default)]
    pub geoip: Option<Value>,
    #[serde(default, rename = "ip_is_private")]
    pub ip_is_private: bool,
    #[serde(default, rename = "source_geoip")]
    pub source_geoip: Option<Value>,
    #[serde(default, rename = "source_ip_cidr")]
    pub source_ip_cidr: Option<Value>,
    #[serde(default, rename = "source_ip_is_private")]
    pub source_ip_is_private: Option<Value>,
    #[serde(default)]
    pub port: Option<Value>,
    #[serde(default, rename = "port_range")]
    pub port_range: Option<Value>,
    #[serde(default, rename = "source_port")]
    pub source_port: Option<Value>,
    #[serde(default, rename = "source_port_range")]
    pub source_port_range: Option<Value>,
    #[serde(default, rename = "process_name")]
    pub process_name: Option<Value>,
    #[serde(default, rename = "process_path")]
    pub process_path: Option<Value>,
    #[serde(default, rename = "process_path_regex")]
    pub process_path_regex: Option<Value>,
    #[serde(default, rename = "package_name")]
    pub package_name: Option<Value>,
    #[serde(default, rename = "package_name_regex")]
    pub package_name_regex: Option<Value>,
    #[serde(default)]
    pub user: Option<Value>,
    #[serde(default, rename = "user_id")]
    pub user_id: Option<Value>,
    #[serde(default, rename = "clash_mode")]
    pub clash_mode: Option<Value>,
    #[serde(default, rename = "network_type")]
    pub network_type: Option<Value>,
    #[serde(default, rename = "network_is_expensive")]
    pub network_is_expensive: Option<Value>,
    #[serde(default, rename = "network_is_constrained")]
    pub network_is_constrained: Option<Value>,
    #[serde(default, rename = "interface_address")]
    pub interface_address: Option<Value>,
    #[serde(default, rename = "network_interface_address")]
    pub network_interface_address: Option<Value>,
    #[serde(default, rename = "default_interface_address")]
    pub default_interface_address: Option<Value>,
    #[serde(default, rename = "wifi_ssid")]
    pub wifi_ssid: Option<Value>,
    #[serde(default, rename = "wifi_bssid")]
    pub wifi_bssid: Option<Value>,
    #[serde(default, rename = "preferred_by")]
    pub preferred_by: Option<Value>,
    #[serde(default, rename = "source_mac_address")]
    pub source_mac_address: Option<Value>,
    #[serde(default, rename = "source_hostname")]
    pub source_hostname: Option<Value>,
    #[serde(default, rename = "rule_set")]
    pub rule_set: Option<Value>,
    #[serde(
        default,
        rename = "rule_set_ip_cidr_match_source",
        alias = "rule_set_ipcidr_match_source"
    )]
    pub rule_set_ip_cidr_match_source: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxRuleSet {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    pub tag: String,
    #[serde(default)]
    pub rules: Vec<SingBoxRouteRule>,
    #[serde(default)]
    pub format: Option<Value>,
    #[serde(default)]
    pub path: Option<Value>,
    #[serde(default)]
    pub url: Option<Value>,
    #[serde(default, rename = "http_client")]
    pub http_client: Option<Value>,
    #[serde(default, rename = "update_interval")]
    pub update_interval: Option<Value>,
    #[serde(default, rename = "download_detour")]
    pub download_detour: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct SingBoxSourceRuleSet {
    pub version: u64,
    pub rules: Vec<SingBoxRouteRule>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxInbound {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(
        default,
        rename = "listen_port",
        deserialize_with = "deserialize_optional_u16"
    )]
    pub listen_port: Option<u16>,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxTunInbound {
    #[serde(default, rename = "interface_name")]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default, rename = "auto_route")]
    pub auto_route: Option<bool>,
    #[serde(default, rename = "route_exclude_address")]
    pub route_exclude_address: Option<Value>,
    #[serde(default, rename = "route_exclude_address_set")]
    pub route_exclude_address_set: Option<Value>,
    #[serde(default)]
    pub address: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxNaiveInbound {
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub users: Vec<SingBoxNaiveUser>,
    pub tls: SingBoxTlsOptions,
    #[serde(default, rename = "quic_congestion_control")]
    pub quic_congestion_control: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxNaiveUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxVlessInbound {
    #[serde(default)]
    pub users: Vec<SingBoxVlessUser>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub multiplex: Option<SingBoxMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxVlessUser {
    pub uuid: String,
    #[serde(default)]
    pub flow: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxShadowsocksInbound {
    #[serde(default)]
    pub network: Option<String>,
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub users: Vec<SingBoxShadowsocksUser>,
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub multiplex: Option<SingBoxMultiplexOptions>,
    #[serde(default)]
    pub destinations: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxShadowsocksUser {
    pub name: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxVmessInbound {
    #[serde(default)]
    pub users: Vec<SingBoxVmessUser>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub multiplex: Option<SingBoxMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxVmessUser {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default, rename = "alterId", alias = "alter_id")]
    pub alter_id: u16,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxTrojanInbound {
    #[serde(default)]
    pub users: Vec<SingBoxTrojanUser>,
    #[serde(default)]
    pub network: Option<String>,
    pub tls: SingBoxTlsOptions,
    #[serde(default)]
    pub multiplex: Option<SingBoxMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<Value>,
    #[serde(default)]
    pub fallback: Option<Value>,
    #[serde(default, rename = "fallback_for_alpn")]
    pub fallback_for_alpn: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxTrojanUser {
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxAnyTlsInbound {
    #[serde(default)]
    pub users: Vec<SingBoxAnyTlsUser>,
    pub tls: SingBoxTlsOptions,
    #[serde(default)]
    pub padding_scheme: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxAnyTlsUser {
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxMieruInbound {
    #[serde(default)]
    pub users: Vec<SingBoxMieruUser>,
    #[serde(default = "default_tcp")]
    pub transport: String,
    #[serde(default)]
    pub mtu: usize,
    #[serde(default, rename = "user_hint_mandatory")]
    pub user_hint_mandatory: bool,
    #[serde(default, rename = "traffic_pattern")]
    pub traffic_pattern: Option<String>,
    #[serde(default, rename = "nonce_pattern")]
    pub nonce_pattern: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxMieruUser {
    #[serde(default)]
    pub username: Option<String>,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxHysteria2Inbound {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub users: Vec<SingBoxHysteria2User>,
    pub tls: SingBoxTlsOptions,
    #[serde(default)]
    pub obfs: Option<SingBoxHysteria2Obfs>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "down_mbps")]
    pub down_mbps: Option<u64>,
    #[serde(default, rename = "down")]
    pub down: Option<u64>,
    #[serde(default, rename = "up_mbps")]
    pub up_mbps: Option<u64>,
    #[serde(default)]
    pub masquerade: Option<Value>,
    #[serde(default, rename = "bbr_profile")]
    pub bbr_profile: Option<String>,
    #[serde(default, rename = "brutal_debug")]
    pub brutal_debug: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxHysteria2User {
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxTuicInbound {
    #[serde(default)]
    pub users: Vec<SingBoxTuicUser>,
    pub tls: SingBoxTlsOptions,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "congestion_control")]
    pub congestion_control: Option<String>,
    #[serde(default, rename = "zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,
    #[serde(default)]
    pub heartbeat: Option<String>,
    #[serde(default, rename = "udp_relay_mode")]
    pub udp_relay_mode: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxTuicUser {
    pub uuid: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxOutbound {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxVlessOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub uuid: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "packet_encoding")]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub multiplex: Option<SingBoxMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxVmessOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub uuid: String,
    #[serde(default = "default_vmess_security")]
    pub security: String,
    #[serde(default, rename = "alter_id")]
    pub alter_id: u16,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "packet_encoding")]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub multiplex: Option<SingBoxMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxTrojanOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub password: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub multiplex: Option<SingBoxMultiplexOptions>,
    #[serde(default)]
    pub transport: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxShadowsocksOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub plugin: Option<Value>,
    #[serde(default, rename = "plugin_opts")]
    pub plugin_opts: Option<Value>,
    #[serde(default)]
    pub multiplex: Option<SingBoxMultiplexOptions>,
    #[serde(default, rename = "udp_over_tcp")]
    pub udp_over_tcp: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxSocksOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxHttpOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxHysteria2Outbound {
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default, rename = "server_port")]
    pub server_port: Option<u16>,
    #[serde(default, rename = "server_ports")]
    pub server_ports: Option<Value>,
    pub password: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "up_mbps")]
    pub up_mbps: Option<u64>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub obfs: Option<SingBoxHysteria2Obfs>,
    #[serde(default, rename = "down_mbps")]
    pub down_mbps: Option<u64>,
    #[serde(default, rename = "down")]
    pub down: Option<u64>,
    #[serde(default)]
    pub realm: Option<Value>,
    #[serde(default, rename = "hop_interval")]
    pub hop_interval: Option<String>,
    #[serde(default, rename = "hop_interval_max")]
    pub hop_interval_max: Option<String>,
    #[serde(default, rename = "bbr_profile")]
    pub bbr_profile: Option<String>,
    #[serde(default, rename = "brutal_debug")]
    pub brutal_debug: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxAnyTlsOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub password: String,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxMieruOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    #[serde(default)]
    pub username: Option<String>,
    pub password: String,
    #[serde(default = "default_tcp")]
    pub transport: String,
    #[serde(default)]
    pub mtu: usize,
    #[serde(default, rename = "traffic_pattern")]
    pub traffic_pattern: Option<String>,
    #[serde(default, rename = "nonce_pattern")]
    pub nonce_pattern: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxNaiveOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "extra_headers")]
    pub extra_headers: BTreeMap<String, String>,
    #[serde(default, rename = "udp_over_tcp")]
    pub udp_over_tcp: Option<Value>,
    #[serde(default)]
    pub quic: bool,
    #[serde(default, rename = "insecure_concurrency")]
    pub insecure_concurrency: Option<u16>,
    #[serde(default, rename = "quic_congestion_control")]
    pub quic_congestion_control: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxTuicOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub uuid: String,
    pub password: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default, rename = "congestion_control")]
    pub congestion_control: Option<String>,
    #[serde(default, rename = "udp_relay_mode")]
    pub udp_relay_mode: Option<String>,
    #[serde(default)]
    pub heartbeat: Option<String>,
    #[serde(default, rename = "zero_rtt_handshake")]
    pub zero_rtt_handshake: bool,
    #[serde(default, rename = "udp_over_stream")]
    pub udp_over_stream: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxSelectorOutbound {
    #[serde(default)]
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default, rename = "interrupt_exist_connections")]
    pub interrupt_exist_connections: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxUrlTestOutbound {
    #[serde(default)]
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub url: Option<Value>,
    #[serde(default)]
    pub interval: Option<Value>,
    #[serde(default)]
    pub tolerance: Option<Value>,
    #[serde(default, rename = "idle_timeout")]
    pub idle_timeout: Option<Value>,
    #[serde(default, rename = "interrupt_exist_connections")]
    pub interrupt_exist_connections: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxTlsOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub engine: Option<Value>,
    #[serde(default, rename = "server_name")]
    pub server_name: Option<String>,
    #[serde(default, rename = "disable_sni")]
    pub disable_sni: Option<bool>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, rename = "disable_system_root")]
    pub disable_system_root: bool,
    #[serde(default, rename = "min_version")]
    pub min_version: Option<Value>,
    #[serde(default, rename = "max_version")]
    pub max_version: Option<Value>,
    #[serde(default, rename = "cipher_suites")]
    pub cipher_suites: Option<Value>,
    #[serde(default, rename = "curve_preferences")]
    pub curve_preferences: Option<Value>,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default)]
    pub utls: Option<SingBoxUtlsOptions>,
    #[serde(default)]
    pub reality: Option<SingBoxRealityOptions>,
    #[serde(default, rename = "certificate_public_key_sha256")]
    pub certificate_public_key_sha256: Option<Value>,
    #[serde(default)]
    pub certificate: Option<Value>,
    #[serde(default)]
    pub key: Option<Value>,
    #[serde(default, rename = "certificate_path")]
    pub certificate_path: Option<Value>,
    #[serde(default, rename = "key_path")]
    pub key_path: Option<Value>,
    #[serde(default, rename = "client_certificate")]
    pub client_certificate: Option<Value>,
    #[serde(default, rename = "client_certificate_path")]
    pub client_certificate_path: Option<Value>,
    #[serde(default, rename = "client_key")]
    pub client_key: Option<Value>,
    #[serde(default, rename = "client_key_path")]
    pub client_key_path: Option<Value>,
    #[serde(default, rename = "client_authentication")]
    pub client_authentication: Option<Value>,
    #[serde(default, rename = "client_certificate_public_key_sha256")]
    pub client_certificate_public_key_sha256: Option<Value>,
    #[serde(default, rename = "kernel_tx")]
    pub kernel_tx: Option<Value>,
    #[serde(default, rename = "kernel_rx")]
    pub kernel_rx: Option<Value>,
    #[serde(default, rename = "handshake_timeout")]
    pub handshake_timeout: Option<Value>,
    #[serde(default, rename = "certificate_provider")]
    pub certificate_provider: Option<Value>,
    #[serde(default)]
    pub ech: Option<Value>,
    #[serde(default)]
    pub fragment: Option<Value>,
    #[serde(default, rename = "fragment_fallback_delay")]
    pub fragment_fallback_delay: Option<Value>,
    #[serde(default, rename = "record_fragment")]
    pub record_fragment: Option<Value>,
    #[serde(default)]
    pub spoof: Option<Value>,
    #[serde(default, rename = "spoof_method")]
    pub spoof_method: Option<Value>,
    #[serde(default)]
    pub acme: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxUtlsOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_fingerprint",
        alias = "client_fingerprint"
    )]
    pub fingerprint: Option<UtlsFingerprint>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxRealityOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, rename = "public_key")]
    pub public_key: Option<String>,
    #[serde(default, rename = "short_id")]
    pub short_id: Option<OneOrManyStrings>,
    #[serde(default)]
    pub handshake: Option<SingBoxRealityHandshake>,
    #[serde(default, rename = "private_key")]
    pub private_key: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxRealityHandshake {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxMultiplexOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxTransportOptions {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, rename = "service_name", alias = "serviceName")]
    pub service_name: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxHysteria2Obfs {
    #[serde(rename = "type")]
    pub kind: String,
    pub password: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug)]
pub enum SingBoxClientConfig {
    Route(RouteClientConfig),
    Shadowsocks(ShadowsocksClientConfig),
    SocksProxy(SocksProxyClientConfig),
    HttpProxy(HttpProxyClientConfig),
    Vless(VlessClientConfig),
    Vmess(VmessClientConfig),
    Trojan(TrojanClientConfig),
    Hysteria2(Hysteria2ClientConfig),
    Mieru(MieruClientConfig),
    AnyTls(ClientConfig),
    Naive(NaiveClientConfig),
    Tuic(TuicClientConfig),
}

pub enum SingBoxServerConfig {
    AnyTls(ServerConfig),
    Hysteria2(Hysteria2ServerConfig),
    Mieru(MieruServerConfig),
    Naive(NaiveServerConfig),
    Shadowsocks(ShadowsocksServerConfig),
    Trojan(TrojanServerConfig),
    Tuic(TuicServerConfig),
    Vless(VlessServerConfig),
    Vmess(VmessServerConfig),
}

impl SingBoxConfig {
    pub fn reject_unsupported_top_level_fields(&self) -> Result<()> {
        ensure_no_extra_fields("sing-box config", &self.extra)
    }

    pub fn outbound(&self, tag: &str) -> Option<&SingBoxOutbound> {
        self.outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
    }

    pub fn resolved_outbound(&self, tag: &str) -> Result<&SingBoxOutbound> {
        let outbound = self
            .outbound(tag)
            .with_context(|| format!("sing-box outbound {tag} was not found"))?;
        self.resolve_policy_outbound(outbound)
    }

    pub fn resolved_outbound_profile(&self, profile: &str) -> Result<&SingBoxOutbound> {
        let outbound = self
            .outbounds
            .iter()
            .find(|outbound| outbound.name() == profile)
            .with_context(|| format!("sing-box outbound {profile} was not found"))?;
        self.resolve_policy_outbound(outbound)
    }

    fn resolve_policy_outbound<'a>(
        &'a self,
        mut outbound: &'a SingBoxOutbound,
    ) -> Result<&'a SingBoxOutbound> {
        let mut seen = BTreeSet::new();
        loop {
            ensure!(
                seen.insert(outbound.name().to_string()),
                "sing-box selector outbound cycle includes {}",
                outbound.name()
            );
            let Some(target) = outbound.static_policy_target()? else {
                return Ok(outbound);
            };
            outbound = self
                .outbound(&target)
                .with_context(|| format!("sing-box outbound {target} was not found"))?;
        }
    }

    pub fn local_socks_listen(&self) -> Result<Option<SocketAddr>> {
        self.reject_unsupported_top_level_fields()?;
        for inbound in &self.inbounds {
            ensure!(
                inbound.kind.eq_ignore_ascii_case("socks")
                    || inbound.kind.eq_ignore_ascii_case("mixed")
                    || inbound.kind.eq_ignore_ascii_case("tun"),
                "sing-box inbound {} type {} is not a local SOCKS/mixed/TUN listener; Aerion config runner exposes SOCKS and TUN listeners only",
                inbound.name(),
                inbound.kind
            );
        }
        let Some(inbound) = self.inbounds.iter().find(|inbound| {
            inbound.kind.eq_ignore_ascii_case("socks") || inbound.kind.eq_ignore_ascii_case("mixed")
        }) else {
            return Ok(None);
        };
        ensure_no_extra_fields(
            &format!("sing-box local SOCKS inbound {}", inbound.name()),
            &inbound.fields,
        )?;
        let port = inbound.listen_port.with_context(|| {
            format!("sing-box inbound {} is missing listen_port", inbound.name())
        })?;
        let host = inbound.listen.as_deref().unwrap_or("0.0.0.0");
        Ok(Some(SocketAddr::new(
            parse_listen_ip("sing-box", host)?,
            port,
        )))
    }

    pub fn route_table(&self) -> Result<RouteTable> {
        self.reject_unsupported_top_level_fields()?;
        match &self.route {
            Some(route) => route.to_route_table(self.source_dir.as_deref(), &self.outbounds),
            None => Ok(RouteTable::default()),
        }
    }

    pub fn tun_enabled(&self) -> bool {
        self.inbounds
            .iter()
            .any(|inbound| inbound.kind.eq_ignore_ascii_case("tun"))
    }

    pub fn tun_config(&self, proxy_listen: SocketAddr) -> Result<Option<TunConfig>> {
        let Some(inbound) = self
            .inbounds
            .iter()
            .find(|inbound| inbound.kind.eq_ignore_ascii_case("tun"))
        else {
            return Ok(None);
        };
        let tun = inbound.decode::<SingBoxTunInbound>()?;
        ensure!(
            tun.extra.is_empty(),
            "sing-box TUN inbound {} has unsupported fields {:?}",
            inbound.name(),
            tun.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            tun.route_exclude_address_set.is_none(),
            "sing-box TUN inbound {} route_exclude_address_set requires rule-set data",
            inbound.name()
        );
        let mut config = TunConfig::new(socks_proxy_url(proxy_listen));
        config.tun_name = tun
            .interface_name
            .as_ref()
            .map(|value| value.trim().to_string());
        if let Some(auto_route) = tun.auto_route {
            config.setup = auto_route;
        }
        if let Some(mtu) = tun.mtu {
            config.mtu = mtu;
        }
        config.bypass = route_value_strings(tun.route_exclude_address.as_ref())?;
        for value in route_value_strings(tun.address.as_ref())? {
            if value.contains(':') {
                config.ipv6 = true;
            }
        }
        Ok(Some(config))
    }
}

impl SingBoxRouteConfig {
    pub fn to_route_table(
        &self,
        source_dir: Option<&Path>,
        outbounds: &[SingBoxOutbound],
    ) -> Result<RouteTable> {
        self.reject_unsupported_route_options()?;
        let rule_sets = self.static_rule_sets(source_dir)?;
        let default = match self
            .final_outbound
            .as_deref()
            .map(RouteDecision::from_outbound)
            .transpose()?
        {
            Some(default) => default,
            None => singbox_default_route_decision(outbounds)?,
        };
        let mut table = RouteTable {
            rules: Vec::new(),
            default,
            ..RouteTable::default()
        };
        for (index, rule) in self.rules.iter().enumerate() {
            table.rules.extend(rule.to_route_rules(index, &rule_sets)?);
        }
        Ok(table)
    }

    fn reject_unsupported_route_options(&self) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "sing-box route has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        for (field, value, reason) in [
            (
                "auto_detect_interface",
                &self.auto_detect_interface,
                "active platform interface detection",
            ),
            (
                "override_android_vpn",
                &self.override_android_vpn,
                "Android VPN route ownership",
            ),
            (
                "default_interface",
                &self.default_interface,
                "platform interface binding",
            ),
            (
                "default_mark",
                &self.default_mark,
                "platform socket mark support",
            ),
            (
                "default_domain_resolver",
                &self.default_domain_resolver,
                "DNS resolver integration during routing",
            ),
            (
                "default_network_strategy",
                &self.default_network_strategy,
                "DNS network strategy integration",
            ),
            (
                "default_network_type",
                &self.default_network_type,
                "platform network metadata",
            ),
            (
                "default_fallback_network_type",
                &self.default_fallback_network_type,
                "platform network fallback metadata",
            ),
            (
                "default_fallback_delay",
                &self.default_fallback_delay,
                "platform network fallback timers",
            ),
            (
                "find_process",
                &self.find_process,
                "process metadata lookup",
            ),
            (
                "find_neighbor",
                &self.find_neighbor,
                "LAN neighbor metadata lookup",
            ),
            (
                "dhcp_lease_files",
                &self.dhcp_lease_files,
                "DHCP lease metadata lookup",
            ),
            (
                "default_http_client",
                &self.default_http_client,
                "remote rule-set HTTP client integration",
            ),
            (
                "default_transport",
                &self.default_transport,
                "global dialer transport policy",
            ),
            (
                "default_udp_timeout",
                &self.default_udp_timeout,
                "global UDP session timeout policy",
            ),
            (
                "geoip",
                &self.geoip,
                "loading sing-box legacy geoip databases",
            ),
            (
                "geosite",
                &self.geosite,
                "loading sing-box legacy geosite databases",
            ),
        ] {
            ensure!(
                !value.as_ref().map(value_has_data).unwrap_or(false),
                "sing-box route {field} requires {reason}"
            );
        }
        Ok(())
    }

    fn static_rule_sets(
        &self,
        source_dir: Option<&Path>,
    ) -> Result<BTreeMap<String, Vec<SingBoxRouteRule>>> {
        let mut rule_sets = BTreeMap::new();
        for rule_set in &self.rule_sets {
            let tag = rule_set.tag.trim();
            ensure!(!tag.is_empty(), "sing-box route.rule_set tag is empty");
            ensure!(
                rule_sets
                    .insert(tag.to_string(), rule_set.static_rules(source_dir)?)
                    .is_none(),
                "sing-box route.rule_set {tag} is duplicated"
            );
        }
        Ok(rule_sets)
    }
}

impl SingBoxRuleSet {
    fn static_rules(&self, source_dir: Option<&Path>) -> Result<Vec<SingBoxRouteRule>> {
        ensure!(
            self.extra.is_empty(),
            "sing-box route.rule_set {} has unsupported fields {:?}",
            self.tag,
            self.extra.keys().collect::<Vec<_>>()
        );
        let kind = self
            .kind
            .as_deref()
            .map(str::trim)
            .filter(|kind| !kind.is_empty())
            .unwrap_or("inline")
            .to_ascii_lowercase();
        match kind.as_str() {
            "inline" => {
                ensure!(
                    self.format.is_none()
                        && self.path.is_none()
                        && self.url.is_none()
                        && self.http_client.is_none()
                        && self.update_interval.is_none()
                        && self.download_detour.is_none(),
                    "sing-box inline route.rule_set {} sets local/remote rule-set fields",
                    self.tag
                );
                ensure!(
                    !self.rules.is_empty(),
                    "sing-box inline route.rule_set {} has no rules",
                    self.tag
                );
                Ok(self.rules.clone())
            }
            "local" => self.local_source_rules(source_dir),
            "remote" => bail!(
                "sing-box remote route.rule_set {} requires downloading rule-set data",
                self.tag
            ),
            other => bail!(
                "unsupported sing-box route.rule_set {} type {other}",
                self.tag
            ),
        }
    }

    fn local_source_rules(&self, source_dir: Option<&Path>) -> Result<Vec<SingBoxRouteRule>> {
        ensure!(
            self.rules.is_empty()
                && self.url.is_none()
                && self.http_client.is_none()
                && self.update_interval.is_none()
                && self.download_detour.is_none(),
            "sing-box local route.rule_set {} sets inline/remote rule-set fields",
            self.tag
        );
        let path = value_path(self.path.as_ref()).with_context(|| {
            format!("sing-box local route.rule_set {} is missing path", self.tag)
        })?;
        let format = self.rule_set_format(Some(&path))?;
        ensure!(
            format == "source",
            "sing-box local route.rule_set {} format {format} is not supported",
            self.tag
        );
        let path = match (path.is_absolute(), source_dir) {
            (true, _) | (false, None) => path,
            (false, Some(source_dir)) => source_dir.join(path),
        };
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "read sing-box local route.rule_set {} file {}",
                self.tag,
                path.display()
            )
        })?;
        let source: SingBoxSourceRuleSet = serde_json::from_str(&text).with_context(|| {
            format!(
                "parse sing-box local route.rule_set {} source file {}",
                self.tag,
                path.display()
            )
        })?;
        ensure!(
            source.extra.is_empty(),
            "sing-box local route.rule_set {} source has unsupported fields {:?}",
            self.tag,
            source.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            source.version > 0,
            "sing-box local route.rule_set {} source version is invalid",
            self.tag
        );
        ensure!(
            !source.rules.is_empty(),
            "sing-box local route.rule_set {} source has no rules",
            self.tag
        );
        Ok(source.rules)
    }

    fn rule_set_format(&self, path: Option<&Path>) -> Result<String> {
        if let Some(value) = &self.format {
            return value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .with_context(|| {
                    format!(
                        "sing-box route.rule_set {} format must be a string",
                        self.tag
                    )
                });
        }
        let extension = path
            .and_then(Path::extension)
            .and_then(|value| value.to_str())
            .map(str::trim)
            .unwrap_or_default();
        if extension.eq_ignore_ascii_case("json") {
            return Ok("source".to_string());
        }
        if extension.eq_ignore_ascii_case("srs") {
            return Ok("binary".to_string());
        }
        bail!("sing-box route.rule_set {} is missing format", self.tag)
    }
}

fn singbox_default_route_decision(outbounds: &[SingBoxOutbound]) -> Result<RouteDecision> {
    let Some(outbound) = outbounds.first() else {
        return Ok(RouteDecision::Direct);
    };
    if let Some(tag) = outbound
        .tag
        .as_deref()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
    {
        return RouteDecision::from_outbound(tag);
    }
    match outbound.kind.trim().to_ascii_lowercase().as_str() {
        "direct" => Ok(RouteDecision::Direct),
        "block" => Ok(RouteDecision::Block),
        kind => bail!(
            "sing-box route default uses first outbound type {kind} without tag; Aerion route proxy requires a tag"
        ),
    }
}

impl SingBoxRouteRule {
    fn to_route_rules(
        &self,
        index: usize,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            self.extra.is_empty(),
            "sing-box route.rules[{index}] has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        let kind = self
            .kind
            .as_deref()
            .map(str::trim)
            .filter(|kind| !kind.is_empty());
        if matches!(kind, Some(kind) if kind.eq_ignore_ascii_case("logical")) {
            return self.to_logical_route_rules(index, None, rule_sets);
        }
        if let Some(kind) = kind {
            ensure!(
                kind.eq_ignore_ascii_case("default"),
                "unsupported sing-box route.rules[{index}] type {kind}"
            );
        }
        self.to_default_route_rules(index, None, rule_sets)
    }

    fn to_default_route_rules(
        &self,
        index: usize,
        action_override: Option<&RouteDecision>,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            !self.rule_set_ip_cidr_match_source,
            "sing-box route.rules[{index}] rule_set_ip_cidr_match_source requires source IP matching"
        );
        let rule_set_refs = route_value_strings(self.rule_set.as_ref())?;
        ensure!(
            action_override.is_none() || rule_set_refs.is_empty(),
            "sing-box route.rules[{index}] inherited-action rule uses nested rule_set"
        );
        let base = self.to_default_route_rule(index, action_override)?;
        if rule_set_refs.is_empty() {
            return Ok(vec![base]);
        }
        let action = base.action.clone();
        let mut rules = Vec::new();
        for tag in rule_set_refs {
            let set_rules = rule_sets.get(&tag).with_context(|| {
                format!("sing-box route.rules[{index}] rule_set {tag} is missing")
            })?;
            for set_rule in set_rules {
                for branch in set_rule.to_child_route_rules(index, &action, rule_sets)? {
                    let mut merged = base.clone();
                    merge_singbox_and_route_rule(&mut merged, branch, index)?;
                    rules.push(merged);
                }
            }
        }
        ensure!(
            !rules.is_empty(),
            "sing-box route.rules[{index}] rule_set expanded to no rules"
        );
        Ok(rules)
    }

    fn to_default_route_rule(
        &self,
        index: usize,
        action_override: Option<&RouteDecision>,
    ) -> Result<RouteRule> {
        ensure!(
            self.extra.is_empty(),
            "sing-box route.rules[{index}] has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            !self.invert,
            "sing-box route.rules[{index}] invert requires negative route matching"
        );
        ensure!(
            self.mode.is_none() && self.rules.is_empty(),
            "sing-box route.rules[{index}] sets logical fields on a default rule"
        );
        self.reject_unsupported_metadata_matchers(index)?;
        let mut rule = RouteRule::new(match action_override {
            Some(action) => action.clone(),
            None => self.route_decision(index)?,
        });
        for value in route_value_strings(self.network.as_ref())? {
            ensure!(
                !value.eq_ignore_ascii_case("icmp"),
                "sing-box route.rules[{index}] network icmp requires ICMP routing support"
            );
            rule.networks.push(RouteNetwork::parse(&value)?);
        }
        for value in route_value_strings(self.domain.as_ref())? {
            rule.domains.push(DomainMatcher::exact(&value));
        }
        for value in route_value_strings(self.domain_suffix.as_ref())? {
            rule.domains.push(DomainMatcher::suffix(&value));
        }
        for value in route_value_strings(self.domain_keyword.as_ref())? {
            rule.domains.push(DomainMatcher::keyword(&value));
        }
        for value in route_value_strings(self.domain_regex.as_ref())? {
            rule.domains.push(DomainMatcher::regex(&value)?);
        }
        for value in route_value_strings(self.geosite.as_ref())? {
            bail!("sing-box route.rules[{index}] geosite {value} requires geosite rule-set data");
        }
        for value in route_value_strings(self.ip_cidr.as_ref())? {
            rule.ip_cidrs.push(IpCidr::parse(&value)?);
        }
        for value in route_value_strings(self.geoip.as_ref())? {
            if value.eq_ignore_ascii_case("private") {
                rule.ip_is_private = true;
            } else {
                bail!("sing-box route.rules[{index}] geoip {value} requires geoip rule-set data");
            }
        }
        rule.ip_is_private |= self.ip_is_private;
        for value in route_value_strings(self.port.as_ref())? {
            rule.ports.push(PortRange::parse(&value)?);
        }
        for value in route_value_strings(self.port_range.as_ref())? {
            rule.ports.push(PortRange::parse(&value)?);
        }
        Ok(rule)
    }

    fn reject_unsupported_metadata_matchers(&self, index: usize) -> Result<()> {
        for (field, value, reason) in [
            ("inbound", &self.inbound, "inbound tag metadata"),
            ("ip_version", &self.ip_version, "IP-version route metadata"),
            (
                "auth_user",
                &self.auth_user,
                "authenticated inbound user metadata",
            ),
            ("protocol", &self.protocol, "sniffed protocol metadata"),
            ("client", &self.client, "sniffed client metadata"),
            ("source_geoip", &self.source_geoip, "source IP metadata"),
            ("source_ip_cidr", &self.source_ip_cidr, "source IP metadata"),
            (
                "source_ip_is_private",
                &self.source_ip_is_private,
                "source IP metadata",
            ),
            ("source_port", &self.source_port, "source port metadata"),
            (
                "source_port_range",
                &self.source_port_range,
                "source port metadata",
            ),
            ("process_name", &self.process_name, "process metadata"),
            ("process_path", &self.process_path, "process metadata"),
            (
                "process_path_regex",
                &self.process_path_regex,
                "process metadata",
            ),
            ("package_name", &self.package_name, "process metadata"),
            (
                "package_name_regex",
                &self.package_name_regex,
                "process metadata",
            ),
            ("user", &self.user, "process owner metadata"),
            ("user_id", &self.user_id, "process owner metadata"),
            ("clash_mode", &self.clash_mode, "Clash mode state"),
            (
                "network_type",
                &self.network_type,
                "platform network metadata",
            ),
            (
                "network_is_expensive",
                &self.network_is_expensive,
                "platform network metadata",
            ),
            (
                "network_is_constrained",
                &self.network_is_constrained,
                "platform network metadata",
            ),
            (
                "interface_address",
                &self.interface_address,
                "platform interface metadata",
            ),
            (
                "network_interface_address",
                &self.network_interface_address,
                "platform interface metadata",
            ),
            (
                "default_interface_address",
                &self.default_interface_address,
                "platform interface metadata",
            ),
            ("wifi_ssid", &self.wifi_ssid, "platform Wi-Fi metadata"),
            ("wifi_bssid", &self.wifi_bssid, "platform Wi-Fi metadata"),
            (
                "preferred_by",
                &self.preferred_by,
                "platform route ownership metadata",
            ),
            (
                "source_mac_address",
                &self.source_mac_address,
                "source device metadata",
            ),
            (
                "source_hostname",
                &self.source_hostname,
                "source device metadata",
            ),
        ] {
            ensure!(
                value.is_none(),
                "sing-box route.rules[{index}] {field} requires {reason}"
            );
        }
        Ok(())
    }

    fn to_logical_route_rules(
        &self,
        index: usize,
        action_override: Option<&RouteDecision>,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            !self.invert,
            "sing-box route.rules[{index}] logical invert requires negative route matching"
        );
        let mode = self
            .mode
            .as_deref()
            .map(str::trim)
            .filter(|mode| !mode.is_empty())
            .with_context(|| format!("sing-box route.rules[{index}] logical rule is missing mode"))?
            .to_ascii_lowercase();
        ensure!(
            !self.rules.is_empty(),
            "sing-box route.rules[{index}] logical rule has no child rules"
        );
        ensure!(
            !self.has_match_fields(),
            "sing-box route.rules[{index}] logical rule sets parent match fields"
        );
        let action = match action_override {
            Some(action) => {
                ensure!(
                    self.outbound.is_none() && self.action.is_none(),
                    "sing-box route.rules[{index}] inherited logical child sets its own action"
                );
                action.clone()
            }
            None => self.route_decision(index)?,
        };
        match mode.as_str() {
            "or" => {
                let mut rules = Vec::new();
                for rule in &self.rules {
                    rules.extend(rule.to_child_route_rules(index, &action, rule_sets)?);
                }
                Ok(rules)
            }
            "and" => self
                .to_logical_and_route_rule(index, &action, rule_sets)
                .map(|rule| vec![rule]),
            other => bail!("unsupported sing-box route.rules[{index}] logical mode {other}"),
        }
    }

    fn to_child_route_rules(
        &self,
        index: usize,
        action: &RouteDecision,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            self.outbound.is_none() && self.action.is_none(),
            "sing-box route.rules[{index}] logical child sets its own action"
        );
        let kind = self
            .kind
            .as_deref()
            .map(str::trim)
            .filter(|kind| !kind.is_empty());
        if matches!(kind, Some(kind) if kind.eq_ignore_ascii_case("logical")) {
            return self.to_logical_route_rules(index, Some(action), rule_sets);
        }
        if let Some(kind) = kind {
            ensure!(
                kind.eq_ignore_ascii_case("default"),
                "unsupported sing-box route.rules[{index}] logical child type {kind}"
            );
        }
        self.to_default_route_rules(index, Some(action), rule_sets)
    }

    fn to_logical_and_route_rule(
        &self,
        index: usize,
        action: &RouteDecision,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<RouteRule> {
        let mut merged = RouteRule::new(action.clone());
        for child in &self.rules {
            let mut rules = child.to_child_route_rules(index, action, rule_sets)?;
            ensure!(
                rules.len() == 1,
                "sing-box route.rules[{index}] logical and child expands to multiple branches"
            );
            merge_singbox_and_route_rule(&mut merged, rules.remove(0), index)?;
        }
        Ok(merged)
    }

    fn route_decision(&self, index: usize) -> Result<RouteDecision> {
        let outbound = self
            .outbound
            .as_deref()
            .map(str::trim)
            .filter(|outbound| !outbound.is_empty());
        let action = self
            .action
            .as_deref()
            .map(str::trim)
            .filter(|action| !action.is_empty());
        let Some(action) = action else {
            let outbound = outbound
                .with_context(|| format!("sing-box route.rules[{index}] is missing outbound"))?;
            return RouteDecision::from_outbound(outbound);
        };
        match action.to_ascii_lowercase().as_str() {
            "route" => {
                let outbound = outbound.with_context(|| {
                    format!("sing-box route.rules[{index}] route action is missing outbound")
                })?;
                RouteDecision::from_outbound(outbound)
            }
            "direct" => {
                ensure!(
                    outbound.is_none(),
                    "sing-box route.rules[{index}] direct action must not set outbound"
                );
                Ok(RouteDecision::Direct)
            }
            "reject" | "block" => {
                ensure!(
                    outbound.is_none(),
                    "sing-box route.rules[{index}] reject action must not set outbound"
                );
                Ok(RouteDecision::Block)
            }
            other => bail!("unsupported sing-box route.rules[{index}] action {other}"),
        }
    }

    fn has_match_fields(&self) -> bool {
        self.network.is_some()
            || self.domain.is_some()
            || self.domain_suffix.is_some()
            || self.domain_keyword.is_some()
            || self.domain_regex.is_some()
            || self.geosite.is_some()
            || self.inbound.is_some()
            || self.ip_version.is_some()
            || self.auth_user.is_some()
            || self.protocol.is_some()
            || self.client.is_some()
            || self.ip_cidr.is_some()
            || self.geoip.is_some()
            || self.ip_is_private
            || self.source_geoip.is_some()
            || self.source_ip_cidr.is_some()
            || self.source_ip_is_private.is_some()
            || self.port.is_some()
            || self.port_range.is_some()
            || self.source_port.is_some()
            || self.source_port_range.is_some()
            || self.process_name.is_some()
            || self.process_path.is_some()
            || self.process_path_regex.is_some()
            || self.package_name.is_some()
            || self.package_name_regex.is_some()
            || self.user.is_some()
            || self.user_id.is_some()
            || self.clash_mode.is_some()
            || self.network_type.is_some()
            || self.network_is_expensive.is_some()
            || self.network_is_constrained.is_some()
            || self.interface_address.is_some()
            || self.network_interface_address.is_some()
            || self.default_interface_address.is_some()
            || self.wifi_ssid.is_some()
            || self.wifi_bssid.is_some()
            || self.preferred_by.is_some()
            || self.source_mac_address.is_some()
            || self.source_hostname.is_some()
            || self.rule_set.is_some()
            || self.rule_set_ip_cidr_match_source
    }
}

fn merge_singbox_and_route_rule(
    target: &mut RouteRule,
    rule: RouteRule,
    index: usize,
) -> Result<()> {
    ensure!(
        target.networks.is_empty() || rule.networks.is_empty(),
        "sing-box route.rules[{index}] logical and combines multiple network matchers"
    );
    let target_has_domain = !target.domains.is_empty() || !target.geosite_sets.is_empty();
    let rule_has_domain = !rule.domains.is_empty() || !rule.geosite_sets.is_empty();
    ensure!(
        !target_has_domain || !rule_has_domain,
        "sing-box route.rules[{index}] logical and combines multiple domain matchers"
    );
    ensure!(
        target.ip_cidrs.is_empty() || rule.ip_cidrs.is_empty(),
        "sing-box route.rules[{index}] logical and combines multiple IP CIDR matchers"
    );
    ensure!(
        target.geoip_sets.is_empty() || rule.geoip_sets.is_empty(),
        "sing-box route.rules[{index}] logical and combines multiple geoip matchers"
    );
    ensure!(
        target.ports.is_empty() || rule.ports.is_empty(),
        "sing-box route.rules[{index}] logical and combines multiple port matchers"
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

impl SingBoxInbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.kind)
    }

    pub fn to_server_config(&self) -> Result<SingBoxServerConfig> {
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "naive" => Ok(SingBoxServerConfig::Naive(
                self.decode::<SingBoxNaiveInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "anytls" => Ok(SingBoxServerConfig::AnyTls(
                self.decode::<SingBoxAnyTlsInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "hysteria2" | "hy2" => Ok(SingBoxServerConfig::Hysteria2(
                self.decode::<SingBoxHysteria2Inbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "mieru" => Ok(SingBoxServerConfig::Mieru(
                self.decode::<SingBoxMieruInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "shadowsocks" | "ss" => Ok(SingBoxServerConfig::Shadowsocks(
                self.decode::<SingBoxShadowsocksInbound>()?
                    .to_server_config(self.name(), self.listen.as_deref(), self.listen_port)?,
            )),
            "trojan" => Ok(SingBoxServerConfig::Trojan(
                self.decode::<SingBoxTrojanInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "tuic" => Ok(SingBoxServerConfig::Tuic(
                self.decode::<SingBoxTuicInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "vless" => Ok(SingBoxServerConfig::Vless(
                self.decode::<SingBoxVlessInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "vmess" => Ok(SingBoxServerConfig::Vmess(
                self.decode::<SingBoxVmessInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            other => bail!(
                "unsupported sing-box inbound {} type {}; Aerion cannot run this inbound protocol as a server",
                self.name(),
                other
            ),
        }
    }

    fn decode<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(Value::Object(self.fields.clone()))
            .with_context(|| format!("parse sing-box inbound {}", self.name()))
    }
}

impl SingBoxNaiveInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<NaiveServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Naive inbound {name}"), &self.extra)?;
        ensure!(
            self.tls.enabled,
            "sing-box Naive inbound {name} disables TLS; Naive requires HTTPS/TLS"
        );
        ensure_disabled_utls(name, &self.tls)?;
        ensure_disabled_reality(name, &self.tls)?;
        let (tcp, quic) = naive_inbound_network(name, self.network.as_deref())?;
        ensure_naive_inbound_alpn(name, self.tls.alpn.as_ref(), tcp, quic)?;
        ensure!(
            !json_value_non_empty_option(self.tls.ech.as_ref()),
            "sing-box Naive inbound {name} sets ECH; Aerion Naive server does not expose ECH"
        );
        let (username, password, users) = self.credentials();
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "Naive", name)?;
        Ok(NaiveServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Naive inbound {name} is missing listen_port")
                })?,
            ),
            username,
            password,
            users,
            cert_path,
            key_path,
            certificates,
            key,
            udp_over_tcp: false,
            tcp,
            quic,
            quic_congestion_control: self
                .quic_congestion_control
                .clone()
                .unwrap_or_else(default_naive_quic_congestion_control),
        })
    }

    fn credentials(&self) -> (String, String, Vec<String>) {
        if let Some(primary) = self.users.first() {
            return (
                primary.username.clone(),
                primary.password.clone(),
                self.users
                    .iter()
                    .skip(1)
                    .map(|user| format!("{}:{}", user.username, user.password))
                    .collect(),
            );
        }
        (
            self.username.clone().unwrap_or_default(),
            self.password.clone().unwrap_or_default(),
            Vec::new(),
        )
    }
}

impl SingBoxVlessInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<VlessServerConfig> {
        ensure_no_extra_fields(&format!("sing-box VLESS inbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box VLESS inbound", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        let tls = self.tls.as_ref();
        let tls_enabled = tls.map(|tls| tls.enabled).unwrap_or(false);
        if let Some(tls) = tls {
            tls.reject_unsupported_fields("VLESS", name, "inbound")?;
        }
        let reality = tls
            .and_then(|tls| tls.reality.as_ref())
            .filter(|reality| reality.enabled);
        ensure!(
            reality.is_none() || tls_enabled,
            "sing-box VLESS inbound {name} enables REALITY while TLS is disabled"
        );
        if tls_enabled || reality.is_some() {
            ensure_vless_alpn(
                "sing-box",
                name,
                &transport,
                tls.and_then(|tls| tls.alpn.as_ref()),
            )?;
        } else if let Some(tls) = tls {
            ensure_disabled_utls(name, tls)?;
            ensure_disabled_reality(name, tls)?;
            ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
        }
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box VLESS inbound {name} is missing users"))?;
        let flow = primary.flow.clone();
        let users = self
            .users
            .iter()
            .skip(1)
            .map(|user| {
                ensure!(
                    user.flow == flow,
                    "sing-box VLESS inbound {name} uses per-user flow; Aerion VLESS server expects one flow for the inbound"
                );
                Ok(user.uuid.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let reality = if let Some(reality) = reality {
            let handshake = reality.handshake.as_ref().with_context(|| {
                format!("sing-box VLESS inbound {name} REALITY is missing handshake")
            })?;
            ensure!(
                reality.public_key.is_none(),
                "sing-box VLESS inbound {name} REALITY sets client-side public_key; Aerion server expects private_key"
            );
            Some(RealityServerConfig::from_strings(
                handshake.server.clone(),
                handshake.server_port,
                Vec::new(),
                reality.private_key.as_deref().with_context(|| {
                    format!("sing-box VLESS inbound {name} REALITY is missing private_key")
                })?,
                &reality_short_ids(reality.short_id.as_ref()),
                transport.alpn_protocols(),
            )?)
        } else {
            None
        };
        let (cert_path, key_path, certificates, key) = if tls_enabled && reality.is_none() {
            let tls =
                tls.with_context(|| format!("sing-box VLESS inbound {name} is missing tls"))?;
            tls.ensure_supported_server_options("VLESS", name, false)?;
            singbox_tls_server_identity(tls, "VLESS", name)?
        } else {
            if let Some(tls) = tls {
                ensure_disabled_utls(name, tls)?;
                ensure!(
                    !json_value_non_empty_option(tls.certificate.as_ref())
                        && !json_value_non_empty_option(tls.key.as_ref())
                        && !json_value_non_empty_option(tls.certificate_path.as_ref())
                        && !json_value_non_empty_option(tls.key_path.as_ref()),
                    "sing-box VLESS inbound {name} sets TLS certificate fields while TLS certificate mode is disabled"
                );
            }
            (PathBuf::new(), PathBuf::new(), Vec::new(), None)
        };
        let ech = if tls_enabled && reality.is_none() {
            tls.and_then(|settings| settings.ech.as_ref())
                .map(tls_ech_from_singbox_value)
                .transpose()?
                .flatten()
        } else {
            None
        };
        Ok(VlessServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box VLESS inbound {name} is missing listen_port")
                })?,
            ),
            user_id: primary.uuid.clone(),
            users,
            tls: tls_enabled && reality.is_none(),
            cert_path,
            key_path,
            certificates,
            key,
            flow,
            reality,
            transport,
            ech,
        })
    }
}

impl SingBoxAnyTlsInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<ServerConfig> {
        ensure_no_extra_fields(&format!("sing-box AnyTLS inbound {name}"), &self.extra)?;
        ensure!(
            self.tls.enabled,
            "sing-box AnyTLS inbound {name} disables TLS; AnyTLS requires TLS"
        );
        self.tls
            .ensure_supported_server_options("AnyTLS", name, false)?;
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box AnyTLS inbound {name} is missing users"))?;
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "AnyTLS", name)?;
        let ech = self
            .tls
            .ech
            .as_ref()
            .map(tls_ech_from_singbox_value)
            .transpose()?
            .flatten();
        Ok(ServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box AnyTLS inbound {name} is missing listen_port")
                })?,
            ),
            password: primary.password.clone(),
            users: self
                .users
                .iter()
                .skip(1)
                .map(|user| user.password.clone())
                .collect(),
            cert_path,
            key_path,
            certificates,
            key,
            padding_scheme: if self.padding_scheme.is_empty() {
                PaddingScheme::default_lines()
            } else {
                self.padding_scheme.clone()
            },
            heartbeat_interval_secs: 30,
            ech,
        })
    }
}

impl SingBoxMieruInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<MieruServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Mieru inbound {name}"), &self.extra)?;
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box Mieru inbound {name} is missing users"))?;
        let users = self
            .users
            .iter()
            .skip(1)
            .map(|user| {
                MieruUser::password(
                    user.username
                        .as_deref()
                        .unwrap_or(&user.password)
                        .to_string(),
                    user.password.clone(),
                )
            })
            .collect();
        Ok(MieruServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Mieru inbound {name} is missing listen_port")
                })?,
            ),
            username: primary
                .username
                .clone()
                .unwrap_or_else(|| primary.password.clone()),
            password: primary.password.clone(),
            users,
            mtu: self.mtu,
            user_hint_mandatory: self.user_hint_mandatory,
            transport: MieruTransport::parse(&self.transport)?,
            traffic_pattern: MieruTrafficPattern::parse_pair(
                self.traffic_pattern.as_deref(),
                self.nonce_pattern.as_deref(),
            )
            .with_context(|| format!("parse sing-box Mieru inbound {name} traffic pattern"))?,
        })
    }
}

impl SingBoxHysteria2Inbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<Hysteria2ServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Hysteria2 inbound {name}"), &self.extra)?;
        ensure!(
            self.tls.enabled,
            "sing-box Hysteria2 inbound {name} disables TLS; Hysteria2 requires TLS"
        );
        self.tls
            .ensure_supported_server_options("Hysteria2", name, false)?;
        ensure_supported_network("sing-box Hysteria2", name, self.network.as_deref())?;
        ensure_hy2_alpn("sing-box", name, self.tls.alpn.as_ref())?;
        ensure!(
            !json_value_non_empty_option(self.masquerade.as_ref()),
            "sing-box Hysteria2 inbound {name} sets masquerade; Aerion Hysteria2 server does not expose HTTP masquerade"
        );
        ensure!(
            self.bbr_profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
            "sing-box Hysteria2 inbound {name} sets bbr_profile {:?}; Aerion Hysteria2 uses the default BBR profile",
            self.bbr_profile
        );
        ensure!(
            !self.brutal_debug,
            "sing-box Hysteria2 inbound {name} enables brutal_debug; Aerion Hysteria2 server does not expose brutal debug"
        );
        let password = self
            .users
            .first()
            .map(|user| user.password.clone())
            .or_else(|| self.password.clone())
            .with_context(|| format!("sing-box Hysteria2 inbound {name} is missing password"))?;
        let users = if self.users.is_empty() {
            Vec::new()
        } else {
            self.users
                .iter()
                .skip(1)
                .map(|user| user.password.clone())
                .collect()
        };
        let obfs = match &self.obfs {
            Some(obfs) => {
                ensure_no_extra_fields(
                    &format!("sing-box Hysteria2 inbound {name} obfs"),
                    &obfs.extra,
                )?;
                ensure!(
                    obfs.kind.eq_ignore_ascii_case("salamander"),
                    "sing-box Hysteria2 inbound {name} uses obfs {}; Aerion supports salamander",
                    obfs.kind
                );
                (Some(obfs.kind.clone()), Some(obfs.password.clone()))
            }
            None => (None, None),
        };
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "Hysteria2", name)?;
        Ok(Hysteria2ServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Hysteria2 inbound {name} is missing listen_port")
                })?,
            ),
            password,
            users,
            cert_path,
            key_path,
            certificates,
            key,
            obfs: obfs.0,
            obfs_password: obfs.1,
            upload_bandwidth: self.up_mbps,
            udp: network_allows_udp(self.network.as_deref()),
            cc_rx: self
                .down_mbps
                .or(self.down)
                .map(|mbps| mbps.saturating_mul(125_000).to_string())
                .unwrap_or_else(|| "0".to_string()),
            congestion_control: "bbr".to_string(),
        })
    }
}

impl SingBoxTuicInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<TuicServerConfig> {
        ensure_no_extra_fields(&format!("sing-box TUIC inbound {name}"), &self.extra)?;
        ensure!(
            self.tls.enabled,
            "sing-box TUIC inbound {name} disables TLS; TUIC requires TLS"
        );
        self.tls
            .ensure_supported_server_options("TUIC", name, false)?;
        ensure_supported_network("sing-box TUIC", name, self.network.as_deref())?;
        ensure_tuic_alpn("sing-box", name, self.tls.alpn.as_ref())?;
        ensure!(
            !self.zero_rtt_handshake,
            "sing-box TUIC inbound {name} enables zero_rtt_handshake; Aerion TUIC server does not expose 0-RTT handshakes"
        );
        if let Some(mode) = self.udp_relay_mode.as_deref().map(str::trim) {
            ensure!(
                mode.is_empty()
                    || mode.eq_ignore_ascii_case("native")
                    || mode.eq_ignore_ascii_case("quic"),
                "sing-box TUIC inbound {name} sets udp_relay_mode {mode}; Aerion supports native and quic TUIC UDP relay commands"
            );
        }
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box TUIC inbound {name} is missing users"))?;
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "TUIC", name)?;
        Ok(TuicServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box TUIC inbound {name} is missing listen_port")
                })?,
            ),
            uuid: primary.uuid.clone(),
            password: primary.password.clone(),
            users: self
                .users
                .iter()
                .skip(1)
                .map(|user| format!("{}:{}", user.uuid, user.password))
                .collect(),
            cert_path,
            key_path,
            certificates,
            key,
            udp: network_allows_udp(self.network.as_deref()),
            congestion_control: self
                .congestion_control
                .clone()
                .unwrap_or_else(|| "cubic".to_string()),
            alpn_protocols: alpn_values(self.tls.alpn.as_ref()),
            heartbeat_interval_secs: self
                .heartbeat
                .as_deref()
                .map(parse_duration_secs)
                .transpose()?
                .unwrap_or(10),
        })
    }
}

impl SingBoxShadowsocksInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<ShadowsocksServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Shadowsocks inbound {name}"), &self.extra)?;
        ensure!(
            !self.managed,
            "sing-box Shadowsocks inbound {name} enables managed users; Aerion does not implement the SSM API"
        );
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure!(
            !json_value_non_empty_option(self.destinations.as_ref()),
            "sing-box Shadowsocks inbound {name} sets relay destinations; Aerion Shadowsocks server does not implement relay mode"
        );
        let (tcp, udp) = tcp_udp_network(
            "sing-box Shadowsocks inbound",
            name,
            self.network.as_deref(),
        )?;
        Ok(ShadowsocksServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Shadowsocks inbound {name} is missing listen_port")
                })?,
            ),
            method: self.method.clone(),
            password: self.password.clone(),
            users: self
                .users
                .iter()
                .map(|user| format!("{}:{}", user.name, user.password))
                .collect(),
            tcp,
            udp,
            udp_over_tcp: false,
        })
    }
}

impl SingBoxTrojanInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<TrojanServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Trojan inbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure!(
            !json_value_non_empty_option(self.fallback.as_ref())
                && self.fallback_for_alpn.is_empty(),
            "sing-box Trojan inbound {name} sets fallback; Aerion Trojan server does not expose fallback routing"
        );
        ensure!(
            self.tls.enabled,
            "sing-box Trojan inbound {name} disables TLS; Trojan requires TLS in Aerion"
        );
        self.tls
            .ensure_supported_server_options("Trojan", name, false)?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        ensure_vless_alpn("sing-box", name, &transport, self.tls.alpn.as_ref())?;
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box Trojan inbound {name} is missing users"))?;
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "Trojan", name)?;
        let ech = self
            .tls
            .ech
            .as_ref()
            .map(tls_ech_from_singbox_value)
            .transpose()?
            .flatten();
        Ok(TrojanServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Trojan inbound {name} is missing listen_port")
                })?,
            ),
            password: primary.password.clone(),
            users: self
                .users
                .iter()
                .skip(1)
                .map(|user| user.password.clone())
                .collect(),
            cert_path,
            key_path,
            certificates,
            key,
            transport,
            ech,
        })
    }
}

impl SingBoxVmessInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<VmessServerConfig> {
        ensure_no_extra_fields(&format!("sing-box VMess inbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box VMess inbound {name} is missing users"))?;
        ensure!(
            primary.alter_id == 0,
            "sing-box VMess inbound {name} primary user uses legacy alterId {}; Aerion implements AEAD VMess only",
            primary.alter_id
        );
        let user_id = primary.uuid.clone().with_context(|| {
            format!("sing-box VMess inbound {name} primary user is missing uuid")
        })?;
        let users = self
            .users
            .iter()
            .skip(1)
            .map(|user| {
                ensure!(
                    user.alter_id == 0,
                    "sing-box VMess inbound {name} extra user uses legacy alterId {}; Aerion implements AEAD VMess only",
                    user.alter_id
                );
                user.uuid
                    .clone()
                    .with_context(|| format!("sing-box VMess inbound {name} extra user is missing uuid"))
            })
            .collect::<Result<Vec<_>>>()?;
        let tls_enabled = self.tls.as_ref().map(|tls| tls.enabled).unwrap_or(false);
        if tls_enabled {
            let tls = self
                .tls
                .as_ref()
                .with_context(|| format!("sing-box VMess inbound {name} is missing tls"))?;
            tls.ensure_supported_server_options("VMess", name, false)?;
            ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
            let (cert_path, key_path, certificates, key) =
                singbox_tls_server_identity(tls, "VMess", name)?;
            let ech = tls
                .ech
                .as_ref()
                .map(tls_ech_from_singbox_value)
                .transpose()?
                .flatten();
            Ok(VmessServerConfig {
                listen: SocketAddr::new(
                    parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                    listen_port.with_context(|| {
                        format!("sing-box VMess inbound {name} is missing listen_port")
                    })?,
                ),
                user_id,
                users,
                tls: true,
                cert_path: Some(cert_path),
                key_path: Some(key_path),
                certificates,
                key,
                transport,
                ech,
            })
        } else {
            if let Some(tls) = &self.tls {
                tls.ensure_supported_server_options("VMess", name, true)?;
                ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
            }
            Ok(VmessServerConfig {
                listen: SocketAddr::new(
                    parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                    listen_port.with_context(|| {
                        format!("sing-box VMess inbound {name} is missing listen_port")
                    })?,
                ),
                user_id,
                users,
                tls: false,
                cert_path: None,
                key_path: None,
                certificates: Vec::new(),
                key: None,
                transport,
                ech: None,
            })
        }
    }
}

impl SingBoxOutbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.kind)
    }

    fn static_policy_target(&self) -> Result<Option<String>> {
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "selector" => Ok(Some(
                self.decode::<SingBoxSelectorOutbound>()?
                    .selected_target(self.name())?,
            )),
            "urltest" => Ok(Some(
                self.decode::<SingBoxUrlTestOutbound>()?
                    .static_target(self.name())?,
            )),
            _ => Ok(None),
        }
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<SingBoxClientConfig> {
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "direct" => {
                ensure!(
                    self.fields.is_empty(),
                    "sing-box direct outbound {} has unsupported fields {:?}",
                    self.name(),
                    self.fields.keys().collect::<Vec<_>>()
                );
                Ok(SingBoxClientConfig::Route(RouteClientConfig {
                    listen,
                    default: RouteDecision::Direct,
                }))
            }
            "block" => {
                ensure!(
                    self.fields.is_empty(),
                    "sing-box block outbound {} has unsupported fields {:?}",
                    self.name(),
                    self.fields.keys().collect::<Vec<_>>()
                );
                Ok(SingBoxClientConfig::Route(RouteClientConfig {
                    listen,
                    default: RouteDecision::Block,
                }))
            }
            "shadowsocks" | "ss" => Ok(SingBoxClientConfig::Shadowsocks(
                self.decode::<SingBoxShadowsocksOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "socks" | "socks5" => Ok(SingBoxClientConfig::SocksProxy(
                self.decode::<SingBoxSocksOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "http" => Ok(SingBoxClientConfig::HttpProxy(
                self.decode::<SingBoxHttpOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "vless" => Ok(SingBoxClientConfig::Vless(
                self.decode::<SingBoxVlessOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "vmess" => Ok(SingBoxClientConfig::Vmess(
                self.decode::<SingBoxVmessOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "trojan" => Ok(SingBoxClientConfig::Trojan(
                self.decode::<SingBoxTrojanOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "hysteria2" | "hy2" => Ok(SingBoxClientConfig::Hysteria2(
                self.decode::<SingBoxHysteria2Outbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "mieru" => Ok(SingBoxClientConfig::Mieru(
                self.decode::<SingBoxMieruOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "anytls" => Ok(SingBoxClientConfig::AnyTls(
                self.decode::<SingBoxAnyTlsOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "naive" => Ok(SingBoxClientConfig::Naive(
                self.decode::<SingBoxNaiveOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "tuic" => Ok(SingBoxClientConfig::Tuic(
                self.decode::<SingBoxTuicOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "selector" => bail!(
                "sing-box selector outbound {} must be resolved through its selected outbound before conversion",
                self.name()
            ),
            "urltest" => bail!(
                "sing-box urltest outbound {} must be resolved through its statically selected outbound before conversion",
                self.name()
            ),
            other => bail!("unsupported sing-box outbound type {other}"),
        }
    }

    fn decode<T>(&self) -> Result<T>
    where
        T: DeserializeOwned,
    {
        serde_json::from_value(Value::Object(self.fields.clone()))
            .with_context(|| format!("parse sing-box outbound {}", self.name()))
    }
}

impl SingBoxSelectorOutbound {
    fn selected_target(&self, name: &str) -> Result<String> {
        ensure!(
            !self.outbounds.is_empty(),
            "sing-box selector outbound {name} has no outbounds"
        );
        ensure!(
            self.extra.is_empty(),
            "sing-box selector outbound {name} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            self.interrupt_exist_connections.is_none(),
            "sing-box selector outbound {name} interrupt_exist_connections requires runtime selector state"
        );
        let target = self
            .default
            .as_deref()
            .map(str::trim)
            .filter(|default| !default.is_empty())
            .unwrap_or(&self.outbounds[0]);
        ensure!(
            self.outbounds.iter().any(|outbound| outbound == target),
            "sing-box selector outbound {name} default {target} is not listed in outbounds"
        );
        Ok(target.to_string())
    }
}

impl SingBoxUrlTestOutbound {
    fn static_target(&self, name: &str) -> Result<String> {
        ensure!(
            self.extra.is_empty(),
            "sing-box urltest outbound {name} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        for (field, value) in [
            ("url", &self.url),
            ("interval", &self.interval),
            ("tolerance", &self.tolerance),
            ("idle_timeout", &self.idle_timeout),
        ] {
            ensure!(
                !value.as_ref().map(value_has_data).unwrap_or(false),
                "sing-box urltest outbound {name} {field} requires active latency testing"
            );
        }
        ensure!(
            self.interrupt_exist_connections.is_none(),
            "sing-box urltest outbound {name} interrupt_exist_connections requires runtime policy state"
        );
        let outbounds = self
            .outbounds
            .iter()
            .map(|outbound| outbound.trim())
            .filter(|outbound| !outbound.is_empty())
            .collect::<Vec<_>>();
        match outbounds.as_slice() {
            [target] => Ok((*target).to_string()),
            [] => bail!("sing-box urltest outbound {name} has no outbounds"),
            _ => bail!(
                "sing-box urltest outbound {name} requires active latency selection; Aerion only resolves single-outbound urltest policies statically"
            ),
        }
    }
}

impl SingBoxShadowsocksOutbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<ShadowsocksClientConfig> {
        ensure_no_extra_fields(
            &format!("sing-box Shadowsocks outbound {name}"),
            &self.extra,
        )?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure!(
            self.plugin.is_none() && self.plugin_opts.is_none(),
            "sing-box Shadowsocks outbound {name} sets SIP003 plugin; Aerion Shadowsocks does not implement plugins"
        );
        let udp_over_tcp = singbox_uot_enabled("Shadowsocks", name, self.udp_over_tcp.as_ref())?;
        Ok(ShadowsocksClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            method: self.method.clone(),
            password: self.password.clone(),
            udp: network_allows_udp(self.network.as_deref()) || udp_over_tcp,
            udp_over_tcp,
        })
    }
}

impl SingBoxSocksOutbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<SocksProxyClientConfig> {
        ensure_no_extra_fields(&format!("sing-box SOCKS outbound {name}"), &self.extra)?;
        let (tcp, udp) = tcp_udp_network("sing-box SOCKS outbound", name, self.network.as_deref())?;
        ensure!(
            tcp,
            "sing-box SOCKS outbound {name} uses udp-only network; Aerion SOCKS outbound requires TCP control channel"
        );
        Ok(SocksProxyClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            udp,
        })
    }
}

impl SingBoxHttpOutbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<HttpProxyClientConfig> {
        ensure_no_extra_fields(&format!("sing-box HTTP outbound {name}"), &self.extra)?;
        let tls_enabled = self.tls.as_ref().map(|tls| tls.enabled).unwrap_or(false);
        if let Some(tls) = &self.tls {
            tls.ensure_supported_client_options("HTTP", name, true)?;
            if tls_enabled {
                ensure_http_alpn("sing-box", name, tls.alpn.as_ref())?;
            } else {
                ensure_disabled_utls(name, tls)?;
                ensure_disabled_reality(name, tls)?;
                ensure!(
                    alpn_values(tls.alpn.as_ref()).is_empty()
                        && !tls.insecure
                        && !tls.disable_system_root
                        && !json_value_non_empty_option(tls.certificate.as_ref())
                        && !json_value_non_empty_option(tls.certificate_path.as_ref()),
                    "sing-box HTTP outbound {name} sets TLS-only options while tls.enabled is false"
                );
            }
        }
        Ok(HttpProxyClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            tls: tls_enabled,
            sni: sni_or_server(
                self.tls.as_ref().and_then(|tls| tls.server_name.as_deref()),
                &self.server,
            ),
            insecure: self.tls.as_ref().map(|tls| tls.insecure).unwrap_or(false),
            ca_cert_paths: value_paths(
                self.tls
                    .as_ref()
                    .and_then(|tls| tls.certificate_path.as_ref()),
            )?,
            ca_certificates: Vec::new(),
            disable_system_roots: self
                .tls
                .as_ref()
                .map(|tls| tls.disable_system_root)
                .unwrap_or(false),
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: self
                .tls
                .as_ref()
                .map(|tls| tls.utls_fingerprint(name))
                .transpose()?
                .flatten(),
            extra_headers: self.headers.clone().into_iter().collect(),
        })
    }
}

impl SingBoxVlessOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<VlessClientConfig> {
        ensure_no_extra_fields(&format!("sing-box VLESS outbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        let tls_enabled = self.tls.as_ref().map(|tls| tls.enabled).unwrap_or(false);
        let reality = if tls_enabled {
            self.tls
                .as_ref()
                .map(|tls| tls.reality_client_config(name))
                .transpose()?
                .flatten()
        } else {
            None
        };
        if let Some(tls) = &self.tls {
            tls.ensure_supported_client_options("VLESS", name, true)?;
            if tls_enabled || reality.is_some() {
                ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
            } else {
                ensure_disabled_utls(name, tls)?;
                ensure_disabled_reality(name, tls)?;
                ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
            }
        }
        Ok(VlessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            user_id: self.uuid.clone(),
            tls: tls_enabled && reality.is_none(),
            sni: sni_or_server(
                self.tls.as_ref().and_then(|tls| tls.server_name.as_deref()),
                &self.server,
            ),
            insecure: if tls_enabled {
                self.tls.as_ref().map(|tls| tls.insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths: value_paths(
                self.tls
                    .as_ref()
                    .and_then(|tls| tls.certificate_path.as_ref()),
            )?,
            ca_certificates: value_strings(
                self.tls.as_ref().and_then(|tls| tls.certificate.as_ref()),
            )?,
            disable_system_roots: tls_enabled
                && self
                    .tls
                    .as_ref()
                    .map(|tls| tls.disable_system_root)
                    .unwrap_or(false),
            pinned_cert_sha256: Vec::new(),
            flow: self.flow.clone(),
            packet_encoding: self
                .packet_encoding
                .clone()
                .unwrap_or_else(|| "xudp".to_string()),
            mux: false,
            udp: network_allows_udp(self.network.as_deref()),
            client_fingerprint: self
                .tls
                .as_ref()
                .map(|tls| tls.utls_fingerprint(name))
                .transpose()?
                .flatten(),
            reality,
            transport,
        })
    }
}

impl SingBoxVmessOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<VmessClientConfig> {
        ensure_no_extra_fields(&format!("sing-box VMess outbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        ensure!(
            self.alter_id == 0,
            "sing-box VMess outbound {name} uses legacy alter_id {}; Aerion implements AEAD VMess only",
            self.alter_id
        );
        let packet_encoding = self.packet_encoding.clone().unwrap_or_default();
        ensure_vmess_packet_encoding(&packet_encoding)
            .with_context(|| format!("sing-box VMess outbound {name} packet_encoding"))?;
        if let Some(tls) = &self.tls {
            tls.ensure_supported_client_options("VMess", name, true)?;
            if tls.enabled {
                ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
            } else {
                ensure_disabled_utls(name, tls)?;
                ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
            }
        }
        let tls_enabled = self.tls.as_ref().map(|tls| tls.enabled).unwrap_or(false);
        let server_name = self.tls.as_ref().and_then(|tls| tls.server_name.as_deref());
        Ok(VmessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            user_id: self.uuid.clone(),
            security: self.security.clone(),
            packet_encoding,
            udp: network_allows_udp(self.network.as_deref()),
            tls: tls_enabled,
            sni: sni_or_server(server_name, &self.server),
            insecure: if tls_enabled {
                self.tls.as_ref().map(|tls| tls.insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths: value_paths(
                self.tls
                    .as_ref()
                    .and_then(|tls| tls.certificate_path.as_ref()),
            )?,
            ca_certificates: value_strings(
                self.tls.as_ref().and_then(|tls| tls.certificate.as_ref()),
            )?,
            disable_system_roots: tls_enabled
                && self
                    .tls
                    .as_ref()
                    .map(|tls| tls.disable_system_root)
                    .unwrap_or(false),
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: if tls_enabled {
                self.tls
                    .as_ref()
                    .map(|tls| tls.utls_fingerprint(name))
                    .transpose()?
                    .flatten()
            } else {
                None
            },
            transport,
        })
    }
}

impl SingBoxTrojanOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<TrojanClientConfig> {
        ensure_no_extra_fields(&format!("sing-box Trojan outbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box Trojan outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box Trojan outbound {name} disables TLS; Trojan requires TLS in Aerion"
        );
        tls.ensure_supported_client_options("Trojan", name, true)?;
        ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
        Ok(TrojanClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            udp: network_allows_udp(self.network.as_deref()),
            client_fingerprint: tls.utls_fingerprint(name)?,
            transport,
        })
    }
}

impl SingBoxHysteria2Outbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<Hysteria2ClientConfig> {
        ensure_no_extra_fields(&format!("sing-box Hysteria2 outbound {name}"), &self.extra)?;
        ensure_supported_network("sing-box", name, self.network.as_deref())?;
        ensure!(
            !self
                .server_ports
                .as_ref()
                .map(value_has_data)
                .unwrap_or(false)
                && self.hop_interval.is_none()
                && self.hop_interval_max.is_none(),
            "sing-box Hysteria2 outbound {name} enables port hopping; Aerion Hysteria2 client expects one fixed port"
        );
        ensure!(
            !self.realm.as_ref().map(value_has_data).unwrap_or(false),
            "sing-box Hysteria2 outbound {name} sets realm; Aerion Hysteria2 client does not expose realm override"
        );
        ensure!(
            self.bbr_profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
            "sing-box Hysteria2 outbound {name} sets bbr_profile {:?}; Aerion Hysteria2 uses the default BBR profile",
            self.bbr_profile
        );
        ensure!(
            !self.brutal_debug,
            "sing-box Hysteria2 outbound {name} enables brutal_debug; Aerion Hysteria2 client does not expose brutal debug"
        );
        let server_port = self.server_port.with_context(|| {
            format!("sing-box Hysteria2 outbound {name} is missing server_port")
        })?;
        let server = self
            .server
            .as_ref()
            .with_context(|| format!("sing-box Hysteria2 outbound {name} is missing server"))?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box Hysteria2 outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box Hysteria2 outbound {name} disables TLS; Hysteria2 requires TLS in Aerion"
        );
        tls.ensure_supported_client_options("Hysteria2", name, true)?;
        ensure_hy2_alpn("sing-box", name, tls.alpn.as_ref())?;
        let (obfs, obfs_password) = match &self.obfs {
            Some(obfs) => {
                ensure_no_extra_fields(
                    &format!("sing-box Hysteria2 outbound {name} obfs"),
                    &obfs.extra,
                )?;
                ensure!(
                    obfs.kind.eq_ignore_ascii_case("salamander"),
                    "sing-box Hysteria2 outbound {name} uses obfs {}; Aerion supports salamander",
                    obfs.kind
                );
                (Some(obfs.kind.clone()), Some(obfs.password.clone()))
            }
            None => (None, None),
        };
        Ok(Hysteria2ClientConfig {
            listen,
            server_host: server.clone(),
            server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), server),
            insecure: tls.insecure,
            certificate_fingerprint: None,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            obfs,
            obfs_password,
            upload_bandwidth: self.up_mbps,
            download_bandwidth: self.down_mbps.or(self.down),
            udp: network_allows_udp(self.network.as_deref()),
            congestion_control: "bbr".to_string(),
        })
    }
}

impl SingBoxAnyTlsOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<ClientConfig> {
        ensure_no_extra_fields(&format!("sing-box AnyTLS outbound {name}"), &self.extra)?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box AnyTLS outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box AnyTLS outbound {name} disables TLS; AnyTLS requires TLS"
        );
        tls.ensure_supported_client_options("AnyTLS", name, true)?;
        Ok(ClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            client_fingerprint: tls.utls_fingerprint(name)?,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
        })
    }
}

impl SingBoxMieruOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<MieruClientConfig> {
        ensure_no_extra_fields(&format!("sing-box Mieru outbound {name}"), &self.extra)?;
        Ok(MieruClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self
                .username
                .clone()
                .unwrap_or_else(|| self.password.clone()),
            password: self.password.clone(),
            hashed_password: None,
            mtu: self.mtu,
            transport: MieruTransport::parse(&self.transport)?,
            traffic_pattern: MieruTrafficPattern::parse_pair(
                self.traffic_pattern.as_deref(),
                self.nonce_pattern.as_deref(),
            )
            .with_context(|| format!("parse sing-box Mieru outbound {name} traffic pattern"))?,
        })
    }
}

impl SingBoxNaiveOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<NaiveClientConfig> {
        ensure_no_extra_fields(&format!("sing-box Naive outbound {name}"), &self.extra)?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box Naive outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box Naive outbound {name} disables TLS; Naive requires HTTPS/TLS"
        );
        tls.ensure_supported_client_options("Naive", name, true)?;
        ensure!(
            self.insecure_concurrency.unwrap_or(0) == 0,
            "sing-box Naive outbound {name} sets insecure_concurrency; Aerion Naive client does not implement speculative parallel connections"
        );
        let udp_over_tcp = singbox_uot_enabled("Naive", name, self.udp_over_tcp.as_ref())?;
        Ok(NaiveClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            extra_headers: self.extra_headers.clone().into_iter().collect(),
            udp_over_tcp,
            quic: self.quic
                || self
                    .network
                    .as_deref()
                    .map(|network| {
                        matches!(
                            network.to_ascii_lowercase().as_str(),
                            "quic" | "h3" | "http3"
                        )
                    })
                    .unwrap_or(false),
            quic_congestion_control: self
                .quic_congestion_control
                .clone()
                .unwrap_or_else(default_naive_quic_congestion_control),
        })
    }
}

impl SingBoxTuicOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<TuicClientConfig> {
        ensure_no_extra_fields(&format!("sing-box TUIC outbound {name}"), &self.extra)?;
        ensure_supported_network("sing-box", name, self.network.as_deref())?;
        ensure!(
            !self.zero_rtt_handshake,
            "sing-box TUIC outbound {name} enables zero_rtt_handshake; Aerion TUIC client does not expose 0-RTT handshakes"
        );
        ensure!(
            !singbox_enabled_option(
                "TUIC",
                name,
                "udp_over_stream",
                self.udp_over_stream.as_ref()
            )?,
            "sing-box TUIC outbound {name} enables udp_over_stream; Aerion TUIC client does not implement UDP-over-stream"
        );
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box TUIC outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box TUIC outbound {name} disables TLS; TUIC requires QUIC TLS"
        );
        tls.ensure_supported_client_options("TUIC", name, true)?;
        ensure_tuic_alpn("sing-box", name, tls.alpn.as_ref())?;
        Ok(TuicClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            uuid: self.uuid.clone(),
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            udp: network_allows_udp(self.network.as_deref()),
            udp_relay_mode: self
                .udp_relay_mode
                .clone()
                .unwrap_or_else(|| "native".to_string()),
            congestion_control: self
                .congestion_control
                .clone()
                .unwrap_or_else(|| "cubic".to_string()),
            alpn_protocols: alpn_values(tls.alpn.as_ref()),
            heartbeat_interval_secs: self
                .heartbeat
                .as_deref()
                .map(parse_duration_secs)
                .transpose()?
                .unwrap_or(10),
        })
    }
}

impl SingBoxTlsOptions {
    fn ensure_supported_client_options(
        &self,
        protocol: &str,
        name: &str,
        allow_certificate_path: bool,
    ) -> Result<()> {
        self.reject_unsupported_fields(protocol, name, "outbound")?;
        ensure!(
            (allow_certificate_path || !json_value_non_empty_option(self.certificate.as_ref()))
                && !self.key.as_ref().map(json_value_non_empty).unwrap_or(false)
                && !self
                    .key_path
                    .as_ref()
                    .map(json_value_non_empty)
                    .unwrap_or(false),
            "sing-box {protocol} outbound {name} sets unsupported TLS private key material"
        );
        ensure!(
            allow_certificate_path
                || !self
                    .certificate_path
                    .as_ref()
                    .map(json_value_non_empty)
                    .unwrap_or(false),
            "sing-box {protocol} outbound {name} sets custom TLS certificate roots; Aerion client expects certificate_path support to be wired explicitly"
        );
        ensure!(
            !singbox_enabled_option(protocol, name, "tls.ech", self.ech.as_ref())?,
            "sing-box {protocol} outbound {name} enables ECH; Aerion client does not implement ECH"
        );
        Ok(())
    }

    fn ensure_supported_server_options(
        &self,
        protocol: &str,
        name: &str,
        tls_disabled: bool,
    ) -> Result<()> {
        self.reject_unsupported_fields(protocol, name, "inbound")?;
        ensure_disabled_utls(name, self)?;
        ensure_disabled_reality(name, self)?;
        if tls_disabled {
            ensure!(
                !json_value_non_empty_option(self.certificate_path.as_ref())
                    && !json_value_non_empty_option(self.key_path.as_ref())
                    && !json_value_non_empty_option(self.certificate.as_ref())
                    && !json_value_non_empty_option(self.key.as_ref()),
                "sing-box {protocol} inbound {name} sets TLS certificate fields while TLS is disabled"
            );
        }
        Ok(())
    }

    fn reject_unsupported_fields(&self, protocol: &str, name: &str, direction: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "sing-box {protocol} {direction} {name} tls has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        for (field, value, reason) in [
            (
                "engine",
                self.engine.as_ref(),
                "TLS engine/backend selection",
            ),
            (
                "min_version",
                self.min_version.as_ref(),
                "TLS version policy override",
            ),
            (
                "max_version",
                self.max_version.as_ref(),
                "TLS version policy override",
            ),
            (
                "cipher_suites",
                self.cipher_suites.as_ref(),
                "TLS cipher suite policy",
            ),
            (
                "curve_preferences",
                self.curve_preferences.as_ref(),
                "TLS curve preference policy",
            ),
            (
                "certificate_public_key_sha256",
                self.certificate_public_key_sha256.as_ref(),
                "certificate public key pinning",
            ),
            (
                "client_certificate",
                self.client_certificate.as_ref(),
                "mutual TLS client certificate support",
            ),
            (
                "client_certificate_path",
                self.client_certificate_path.as_ref(),
                "mutual TLS client certificate support",
            ),
            (
                "client_key",
                self.client_key.as_ref(),
                "mutual TLS client key support",
            ),
            (
                "client_key_path",
                self.client_key_path.as_ref(),
                "mutual TLS client key support",
            ),
            (
                "client_certificate_public_key_sha256",
                self.client_certificate_public_key_sha256.as_ref(),
                "client certificate public key pinning",
            ),
            (
                "kernel_tx",
                self.kernel_tx.as_ref(),
                "kernel TLS transmit offload",
            ),
            (
                "kernel_rx",
                self.kernel_rx.as_ref(),
                "kernel TLS receive offload",
            ),
            (
                "handshake_timeout",
                self.handshake_timeout.as_ref(),
                "TLS handshake timeout policy",
            ),
            (
                "certificate_provider",
                self.certificate_provider.as_ref(),
                "certificate provider integration",
            ),
            (
                "fragment",
                self.fragment.as_ref(),
                "TLS fragmentation policy",
            ),
            (
                "fragment_fallback_delay",
                self.fragment_fallback_delay.as_ref(),
                "TLS fragmentation fallback timing",
            ),
            (
                "record_fragment",
                self.record_fragment.as_ref(),
                "TLS record fragmentation policy",
            ),
            ("spoof", self.spoof.as_ref(), "TLS ClientHello spoofing"),
            (
                "spoof_method",
                self.spoof_method.as_ref(),
                "TLS ClientHello spoofing",
            ),
            ("acme", self.acme.as_ref(), "ACME certificate automation"),
        ] {
            ensure!(
                !value.is_some_and(value_has_data),
                "sing-box {protocol} {direction} {name} tls.{field} requires {reason}"
            );
        }
        if let Some(client_authentication) = &self.client_authentication {
            let no_client_authentication = client_authentication
                .as_str()
                .map(str::trim)
                .is_some_and(|value| value.is_empty() || value.eq_ignore_ascii_case("no"));
            ensure!(
                no_client_authentication || !value_has_data(client_authentication),
                "sing-box {protocol} {direction} {name} tls.client_authentication requires mutual TLS client authentication policy"
            );
        }
        ensure!(
            !self.disable_sni.unwrap_or(false),
            "sing-box {protocol} {direction} {name} tls.disable_sni requires TLS SNI suppression support"
        );
        if let Some(utls) = &self.utls {
            utls.reject_unsupported_fields(&format!(
                "sing-box {protocol} {direction} {name} tls.utls"
            ))?;
        }
        if let Some(reality) = &self.reality {
            reality.reject_unsupported_fields(&format!(
                "sing-box {protocol} {direction} {name} tls.reality"
            ))?;
        }
        Ok(())
    }

    fn utls_fingerprint(&self, name: &str) -> Result<Option<UtlsFingerprint>> {
        let Some(utls) = &self.utls else {
            return Ok(None);
        };
        if utls.enabled {
            return Ok(Some(utls.fingerprint.unwrap_or(UtlsFingerprint::Chrome)));
        }
        ensure!(
            utls.fingerprint.is_none(),
            "sing-box outbound {name} sets uTLS fingerprint while utls.enabled is false"
        );
        Ok(None)
    }

    fn reality_client_config(&self, name: &str) -> Result<Option<RealityClientConfig>> {
        let Some(reality) = &self.reality else {
            return Ok(None);
        };
        if !reality.enabled {
            ensure!(
                reality.public_key.is_none()
                    && reality.short_id.is_none()
                    && reality.handshake.is_none()
                    && reality.private_key.is_none(),
                "sing-box outbound {name} sets REALITY fields while reality.enabled is false"
            );
            return Ok(None);
        }
        ensure!(
            reality.handshake.is_none() && reality.private_key.is_none(),
            "sing-box outbound {name} sets REALITY server-only fields"
        );
        let short_id = reality
            .short_id
            .as_ref()
            .and_then(|short_id| short_id.to_vec().into_iter().next())
            .unwrap_or_default();
        Ok(Some(RealityClientConfig::from_strings(
            reality.public_key.as_deref().with_context(|| {
                format!("sing-box REALITY outbound {name} is missing public_key")
            })?,
            &short_id,
        )?))
    }
}

impl SingBoxUtlsOptions {
    fn reject_unsupported_fields(&self, owner: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "{owner} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        Ok(())
    }
}

impl SingBoxRealityOptions {
    fn reject_unsupported_fields(&self, owner: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "{owner} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        if let Some(handshake) = &self.handshake {
            handshake.reject_unsupported_fields(&format!("{owner}.handshake"))?;
        }
        Ok(())
    }
}

impl SingBoxRealityHandshake {
    fn reject_unsupported_fields(&self, owner: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "{owner} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        Ok(())
    }
}

fn ensure_disabled_utls(name: &str, tls: &SingBoxTlsOptions) -> Result<()> {
    if let Some(utls) = &tls.utls {
        utls.reject_unsupported_fields(&format!("sing-box profile {name} tls.utls"))?;
    }
    ensure!(
        tls.utls
            .as_ref()
            .is_none_or(|utls| !utls.enabled && utls.fingerprint.is_none()),
        "sing-box profile {name} sets uTLS but this Aerion transport does not implement uTLS"
    );
    Ok(())
}

fn ensure_disabled_reality(name: &str, tls: &SingBoxTlsOptions) -> Result<()> {
    if let Some(reality) = &tls.reality {
        reality.reject_unsupported_fields(&format!("sing-box profile {name} tls.reality"))?;
    }
    ensure!(
        tls.reality.as_ref().is_none_or(|reality| {
            !reality.enabled
                && reality.public_key.is_none()
                && reality.short_id.is_none()
                && reality.handshake.is_none()
                && reality.private_key.is_none()
        }),
        "sing-box profile {name} sets REALITY but TLS is disabled"
    );
    Ok(())
}

fn ensure_supported_network(format: &str, name: &str, network: Option<&str>) -> Result<()> {
    let network = network.unwrap_or_default().trim();
    ensure!(
        network.is_empty()
            || network.eq_ignore_ascii_case("tcp")
            || network.eq_ignore_ascii_case("udp"),
        "{format} profile {name} uses network {network}; Aerion supports sing-box tcp or udp network selection"
    );
    Ok(())
}

fn tcp_udp_network(format: &str, name: &str, network: Option<&str>) -> Result<(bool, bool)> {
    match network
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" => Ok((true, true)),
        "tcp" => Ok((true, false)),
        "udp" => Ok((false, true)),
        "both" | "tcp+udp" | "tcp,udp" | "tcp_and_udp" => Ok((true, true)),
        other => bail!("{format} {name} uses network {other}; Aerion supports tcp or udp"),
    }
}

fn value_has_data(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_u64().unwrap_or(1) != 0,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn ensure_no_extra_fields(owner: &str, extra: &Map<String, Value>) -> Result<()> {
    ensure!(
        extra.is_empty(),
        "{owner} has unsupported fields {:?}",
        extra.keys().collect::<Vec<_>>()
    );
    Ok(())
}

fn network_allows_udp(network: Option<&str>) -> bool {
    !network
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("tcp")
}

fn naive_inbound_network(name: &str, network: Option<&str>) -> Result<(bool, bool)> {
    match network
        .unwrap_or("tcp")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "tcp" | "raw" | "http" | "https" | "h2" => Ok((true, false)),
        "udp" | "quic" | "h3" | "http3" => Ok((false, true)),
        "both" | "tcp+udp" | "tcp,udp" | "tcp_and_udp" => Ok((true, true)),
        other => bail!(
            "sing-box Naive inbound {name} uses network {other}; Aerion supports tcp or udp Naive inbound networks"
        ),
    }
}

fn vless_transport_config(
    format: &str,
    name: &str,
    network: Option<&str>,
    transport: Option<&Value>,
) -> Result<VlessTransportConfig> {
    let network = network.unwrap_or_default();
    if let Some(Value::Object(map)) = transport {
        if map.is_empty() {
            return VlessTransportConfig::from_network(network, None, None, Vec::new());
        }
        let options: SingBoxTransportOptions =
            serde_json::from_value(Value::Object(map.clone()))
                .with_context(|| format!("parse {format} VLESS {name} transport"))?;
        ensure_no_extra_fields(&format!("{format} VLESS {name} transport"), &options.extra)?;
        let kind = if options.kind.trim().is_empty() {
            network
        } else {
            options.kind.as_str()
        };
        let host = options.host.or_else(|| {
            options
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("host"))
                .map(|(_, value)| value.clone())
        });
        let path = if kind.eq_ignore_ascii_case("grpc") {
            options.service_name.or(options.path)
        } else {
            options.path
        };
        if kind.eq_ignore_ascii_case("xhttp") || kind.eq_ignore_ascii_case("splithttp") {
            return VlessTransportConfig::xhttp(
                path,
                host,
                options.headers.into_iter().collect(),
                options.mode,
            );
        }
        return VlessTransportConfig::from_network(
            kind,
            path,
            host,
            options.headers.into_iter().collect(),
        );
    } else if transport.is_some() {
        bail!("{format} VLESS {name} transport must be an object");
    }
    VlessTransportConfig::from_network(network, None, None, Vec::new())
}

fn ensure_multiplex_disabled(
    format: &str,
    name: &str,
    multiplex: Option<&SingBoxMultiplexOptions>,
) -> Result<()> {
    if let Some(multiplex) = multiplex {
        ensure_no_extra_fields(
            &format!("{format} profile {name} multiplex"),
            &multiplex.extra,
        )?;
        ensure!(
            !multiplex.enabled
                && multiplex
                    .protocol
                    .as_deref()
                    .is_none_or(|protocol| protocol.trim().is_empty()),
            "{format} profile {name} sets multiplex options; Aerion does not implement sing-box multiplex because it is not wire-compatible with Aerion mux.cool"
        );
    }
    ensure!(
        !multiplex
            .map(|multiplex| multiplex.enabled)
            .unwrap_or(false),
        "{format} profile {name} enables multiplex; Aerion does not implement sing-box multiplex because it is not wire-compatible with Aerion mux.cool"
    );
    Ok(())
}

fn ensure_no_alpn(format: &str, name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn_values(alpn);
    ensure!(
        values.is_empty(),
        "{format} outbound {name} sets ALPN {:?}; this Aerion transport does not expose ALPN override",
        values
    );
    Ok(())
}

fn ensure_vless_alpn(
    format: &str,
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
            "{format} VLESS outbound {name} sets ALPN {:?}; {:?} transport requires h2",
            values,
            transport.kind
        );
        return Ok(());
    }
    if matches!(transport.kind, VlessTransportKind::Xhttp) {
        let values = alpn_values(alpn);
        ensure!(
            values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("http/1.1")),
            "{format} VLESS outbound {name} sets ALPN {:?}; XHTTP stream-one transport requires http/1.1",
            values
        );
        return Ok(());
    }
    ensure_no_alpn(format, name, alpn)
}

fn ensure_hy2_alpn(format: &str, name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn_values(alpn);
    ensure!(
        values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("h3")),
        "{format} Hysteria2 outbound {name} sets ALPN {:?}; Aerion Hysteria2 uses h3",
        values
    );
    Ok(())
}

fn ensure_tuic_alpn(format: &str, name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn_values(alpn);
    ensure!(
        values.is_empty() || values.iter().any(|value| value.eq_ignore_ascii_case("h3")),
        "{format} TUIC outbound {name} sets ALPN {:?}; TUIC over QUIC requires h3-compatible ALPN",
        values
    );
    Ok(())
}

fn ensure_http_alpn(format: &str, name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn_values(alpn);
    ensure!(
        values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("http/1.1")),
        "{format} HTTP outbound {name} sets ALPN {:?}; Aerion HTTP proxy outbound uses HTTP/1.1 CONNECT",
        values
    );
    Ok(())
}

fn ensure_naive_inbound_alpn(
    name: &str,
    alpn: Option<&OneOrManyStrings>,
    tcp: bool,
    quic: bool,
) -> Result<()> {
    for value in alpn_values(alpn) {
        let lower = value.to_ascii_lowercase();
        ensure!(
            (tcp && matches!(lower.as_str(), "h2" | "http/1.1")) || (quic && lower == "h3"),
            "sing-box Naive inbound {name} sets ALPN {value}; Aerion Naive server exposes h2/http/1.1 on TCP and h3 on QUIC"
        );
    }
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

fn reality_short_ids(short_id: Option<&OneOrManyStrings>) -> Vec<String> {
    short_id.map(OneOrManyStrings::to_vec).unwrap_or_default()
}

fn singbox_enabled_option(
    protocol: &str,
    name: &str,
    field: &str,
    value: Option<&Value>,
) -> Result<bool> {
    match value {
        Some(Value::Bool(value)) => Ok(*value),
        Some(Value::Object(map)) => match map.get("enabled") {
            Some(Value::Bool(value)) => Ok(*value),
            Some(other) => {
                bail!(
                    "sing-box {protocol} outbound {name} sets {field}.enabled to {other}; expected boolean"
                )
            }
            None => Ok(true),
        },
        Some(other) => {
            bail!(
                "sing-box {protocol} outbound {name} sets {field} to {other}; expected boolean or object"
            )
        }
        None => Ok(false),
    }
}

fn singbox_uot_enabled(protocol: &str, name: &str, value: Option<&Value>) -> Result<bool> {
    let enabled = singbox_enabled_option(protocol, name, "udp_over_tcp", value)?;
    if !enabled {
        return Ok(false);
    }
    if let Some(Value::Object(map)) = value {
        if let Some(version) = map.get("version") {
            let is_v2 = match version {
                Value::Number(number) => number.as_u64() == Some(2),
                Value::String(text) => text.trim() == "2",
                _ => false,
            };
            ensure!(
                is_v2,
                "sing-box {protocol} outbound {name} sets udp_over_tcp version {version}; Aerion UDP-over-TCP uses version 2 framing"
            );
        }
    }
    Ok(true)
}

fn json_value_non_empty(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        _ => true,
    }
}

fn json_value_non_empty_option(value: Option<&Value>) -> bool {
    value.map(json_value_non_empty).unwrap_or(false)
}

fn value_path(value: Option<&Value>) -> Option<PathBuf> {
    match value {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(PathBuf::from(value)),
        Some(Value::Array(values)) if values.len() == 1 => value_path(values.first()),
        _ => None,
    }
}

fn value_paths(value: Option<&Value>) -> Result<Vec<PathBuf>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(vec![PathBuf::from(value)]),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .context("sing-box TLS certificate_path array contains a non-string path")
            })
            .collect(),
        Some(_) => bail!("sing-box TLS certificate_path must be a string or string array"),
    }
}

fn value_strings(value: Option<&Value>) -> Result<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(value)) if !value.trim().is_empty() => {
            Ok(vec![value.trim().to_string()])
        }
        Some(Value::Array(values)) => {
            let lines = values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .context("sing-box TLS certificate array contains a non-string certificate")
                })
                .collect::<Result<Vec<_>>>()?;
            if lines.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![lines.join("\n")])
            }
        }
        Some(_) => bail!("sing-box TLS certificate must be a string or string array"),
    }
}

fn route_value_strings(value: Option<&Value>) -> Result<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect()),
        Some(Value::Number(value)) => Ok(vec![value.to_string()]),
        Some(Value::Array(values)) => {
            let mut result = Vec::new();
            for value in values {
                match value {
                    Value::String(text) => result.extend(
                        text.split(',')
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(str::to_string),
                    ),
                    Value::Number(number) => result.push(number.to_string()),
                    Value::Null => {}
                    _ => bail!("sing-box route array value must contain strings or numbers"),
                }
            }
            Ok(result)
        }
        Some(_) => bail!("sing-box route value must be a string, number, or array"),
    }
}

fn singbox_tls_server_identity(
    tls: &SingBoxTlsOptions,
    protocol: &str,
    name: &str,
) -> Result<(PathBuf, PathBuf, Vec<String>, Option<String>)> {
    let cert_path = value_path(tls.certificate_path.as_ref());
    let key_path = value_path(tls.key_path.as_ref());
    let certificates = value_strings(tls.certificate.as_ref())?;
    let key = value_strings(tls.key.as_ref())?.into_iter().next();
    ensure!(
        cert_path.is_some() || !certificates.is_empty(),
        "sing-box {protocol} inbound {name} is missing certificate_path or certificate"
    );
    ensure!(
        key_path.is_some() || key.is_some(),
        "sing-box {protocol} inbound {name} is missing key_path or key"
    );
    Ok((
        cert_path.unwrap_or_default(),
        key_path.unwrap_or_default(),
        certificates,
        key,
    ))
}

fn parse_duration_secs(value: &str) -> Result<u64> {
    let value = value.trim();
    let seconds = value.strip_suffix('s').unwrap_or(value).trim();
    seconds
        .parse::<u64>()
        .with_context(|| format!("parse duration seconds {value}"))
}

fn sni_or_server(value: Option<&str>, server: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(server)
        .to_string()
}

fn parse_listen_ip(format: &str, value: &str) -> Result<IpAddr> {
    let value = value.trim();
    match value {
        "" | "0.0.0.0" => Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        "localhost" => Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        value => value
            .parse()
            .with_context(|| format!("parse {format} listen address {value}")),
    }
}

fn default_vmess_security() -> String {
    "auto".to_string()
}

fn default_tcp() -> String {
    "tcp".to_string()
}

pub fn deserialize_optional_u64_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumberOrText {
        Number(u64),
        Text(String),
    }

    match Option::<NumberOrText>::deserialize(deserializer)? {
        Some(NumberOrText::Number(value)) => Ok(Some(value)),
        Some(NumberOrText::Text(value)) => value
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

fn deserialize_optional_u16<'de, D>(deserializer: D) -> std::result::Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Number(number) => Ok(number.as_u64().and_then(|value| u16::try_from(value).ok())),
        Value::String(text) => Ok(text.trim().parse::<u16>().ok()),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::protocol::ProxyTarget;

    #[test]
    fn parses_singbox_inbound_string_ports() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    { "type": "mixed", "listen": "127.0.0.1", "listen_port": "7890" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(config.inbounds[0].listen_port, Some(7890));
        assert_eq!(
            config.local_socks_listen()?,
            Some("127.0.0.1:7890".parse()?)
        );
        Ok(())
    }

    #[test]
    fn rejects_singbox_unsupported_local_socks_inbound_fields() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 7890,
      "sniff": true
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .local_socks_listen()
            .expect_err("local mixed inbound sniffing must not be ignored");
        assert!(error.to_string().contains("sniff"));

        let json = r#"
{
  "inbounds": [
    {
      "type": "http",
      "tag": "http-in",
      "listen": "127.0.0.1",
      "listen_port": 8080
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .local_socks_listen()
            .expect_err("local HTTP inbound must not be ignored");
        assert!(error.to_string().contains("local SOCKS/mixed/TUN listener"));
        assert!(error.to_string().contains("http"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_unsupported_top_level_options() -> Result<()> {
        let json = r#"
{
  "log": { "level": "debug" },
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "domain_suffix": "example.com", "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("unsupported sing-box top-level options must not be ignored");
        assert!(error.to_string().contains("sing-box config"));
        assert!(error.to_string().contains("log"));
        Ok(())
    }

    #[test]
    fn compiles_singbox_route_rules() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "domain_suffix": ["example.com"], "outbound": "direct" },
      { "domain_keyword": "video", "outbound": "proxy-a" },
      { "ip_cidr": ["10.0.0.0/8"], "port": [53], "network": "udp", "outbound": "direct" }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
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
            routes.decide(&ProxyTarget::Ip("10.1.2.3:53".parse()?), RouteNetwork::Udp),
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
    fn singbox_route_default_uses_first_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    { "type": "vless", "tag": "proxy-a" }
  ],
  "route": {
    "rules": [
      { "domain_suffix": ["example.com"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
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
                &ProxyTarget::Domain("unmatched.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );

        let json = r#"
{
  "outbounds": [
    { "type": "vless" }
  ],
  "route": {
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("tagless default proxy outbound cannot be spawned");
        assert!(error.to_string().contains("requires a tag"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_route_top_level_runtime_options() -> Result<()> {
        let json = r#"
{
  "route": {
    "auto_detect_interface": true,
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("platform interface detection must not be ignored");
        assert!(error.to_string().contains("auto_detect_interface"));

        let json = r#"
{
  "route": {
    "default_domain_resolver": "local",
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("default resolver must not be ignored");
        assert!(error.to_string().contains("default_domain_resolver"));

        let json = r#"
{
  "route": {
    "dhcp_lease_files": ["/var/lib/misc/dnsmasq.leases"],
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("DHCP lease lookup must not be ignored");
        assert!(error.to_string().contains("dhcp_lease_files"));

        let json = r#"
{
  "route": {
    "default_http_client": "rule-set-fetcher",
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("remote rule-set HTTP client must not be ignored");
        assert!(error.to_string().contains("default_http_client"));

        let json = r#"
{
  "route": {
    "unknown_route_option": true,
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("unknown route options must not be ignored");
        assert!(error.to_string().contains("unsupported fields"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_icmp_route_network() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "network": "icmp", "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("ICMP route rules require ICMP routing support");
        assert!(error.to_string().contains("network icmp"));
        Ok(())
    }

    #[test]
    fn compiles_singbox_route_actions() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "domain_suffix": ["example.com"], "action": "route", "outbound": "direct" },
      { "domain_suffix": ["blocked.test"], "action": "reject" }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
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
                &ProxyTarget::Domain("www.blocked.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Block
        );
        Ok(())
    }

    #[test]
    fn compiles_singbox_logical_or_route_rules() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      {
        "type": "logical",
        "mode": "or",
        "action": "route",
        "outbound": "direct",
        "rules": [
          { "domain_suffix": ["example.com"] },
          { "ip_cidr": ["10.0.0.0/8"] }
        ]
      }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let routes = config.route_table()?;
        assert_eq!(routes.rules.len(), 2);
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
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
    fn compiles_singbox_logical_and_route_rules() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      {
        "type": "logical",
        "mode": "and",
        "outbound": "direct",
        "rules": [
          { "domain_suffix": ["example.com"] },
          { "port": [443] },
          { "network": "tcp" }
        ]
      }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
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
                &ProxyTarget::Domain("api.example.com".to_string(), 80),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-b".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Udp
            ),
            RouteDecision::Proxy("proxy-b".to_string())
        );
        Ok(())
    }

    #[test]
    fn compiles_singbox_inline_route_rule_set() -> Result<()> {
        let json = r#"
{
  "route": {
    "rule_set": [
      {
        "type": "inline",
        "tag": "static-set",
        "rules": [
          { "domain_suffix": ["example.com"] },
          {
            "type": "logical",
            "mode": "or",
            "rules": [
              { "ip_cidr": ["10.0.0.0/8"] },
              { "domain_keyword": "video" }
            ]
          }
        ]
      }
    ],
    "rules": [
      { "rule_set": ["static-set"], "action": "route", "outbound": "direct" }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let routes = config.route_table()?;
        assert_eq!(routes.rules.len(), 3);
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(&ProxyTarget::Ip("10.1.2.3:443".parse()?), RouteNetwork::Tcp),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("video.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
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
    fn rejects_singbox_geo_route_rules_without_data() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "geosite": ["category-ads-all"], "outbound": "block" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("geosite needs explicit route-set data");
        assert!(error.to_string().contains("geosite rule-set data"));

        let json = r#"
{
  "route": {
    "rules": [
      { "geoip": ["cn"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("geoip needs explicit route-set data");
        assert!(error.to_string().contains("geoip rule-set data"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_metadata_route_matchers() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "source_ip_cidr": ["10.0.0.0/8"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("source route matcher requires metadata");
        assert!(error.to_string().contains("source IP metadata"));

        let json = r#"
{
  "route": {
    "rules": [
      { "process_name": ["curl"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("process route matcher requires metadata");
        assert!(error.to_string().contains("process metadata"));

        let json = r#"
{
  "route": {
    "rules": [
      { "inbound": ["mixed-in"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("inbound route matcher requires metadata");
        assert!(error.to_string().contains("inbound tag metadata"));
        Ok(())
    }

    #[test]
    fn compiles_singbox_local_source_route_rule_set() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(
            dir.path().join("geo.json"),
            r#"
{
  "version": 3,
  "rules": [
    { "domain_suffix": ["example.com"] },
    {
      "type": "logical",
      "mode": "or",
      "rules": [
        { "ip_cidr": ["10.0.0.0/8"] },
        { "domain_keyword": "video" }
      ]
    }
  ]
}
"#,
        )?;
        let json = r#"
{
  "route": {
    "rule_set": [
      {
        "type": "local",
        "tag": "geo",
        "format": "source",
        "path": "geo.json"
      }
    ],
    "rules": [
      { "rule_set": ["geo"], "action": "route", "outbound": "direct" }
    ],
    "final": "proxy-b"
  }
}
"#;
        let mut config: SingBoxConfig = serde_json::from_str(json)?;
        config.source_dir = Some(dir.path().to_path_buf());
        let routes = config.route_table()?;
        assert_eq!(routes.rules.len(), 3);
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(&ProxyTarget::Ip("10.1.2.3:443".parse()?), RouteNetwork::Tcp),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("video.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
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
    fn rejects_singbox_binary_route_rule_set() -> Result<()> {
        let json = r#"
{
  "route": {
    "rule_set": [
      {
        "type": "local",
        "tag": "geo",
        "path": "geo.srs"
      }
    ],
    "rules": [
      { "rule_set": ["geo"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("binary rule-set loading must fail explicitly");
        assert!(error.to_string().contains("format binary"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_remote_route_rule_set() -> Result<()> {
        let json = r#"
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "geo",
        "format": "source",
        "url": "https://rules.example.test/geo.json"
      }
    ],
    "rules": [
      { "rule_set": ["geo"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("remote rule-set loading must fail explicitly");
        assert!(error.to_string().contains("requires downloading"));
        Ok(())
    }

    #[test]
    fn compiles_singbox_tun_inbound() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "mtu": 9000,
      "auto_route": true,
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "route_exclude_address": ["10.0.0.0/8"]
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "proxy-a",
      "server": "example.com",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert!(config.tun_enabled());
        let tun = config
            .tun_config("127.0.0.1:7890".parse()?)?
            .context("tun config")?;
        assert_eq!(tun.proxy_url, "socks5://127.0.0.1:7890");
        assert_eq!(tun.tun_name.as_deref(), Some("tun0"));
        assert_eq!(tun.mtu, 9000);
        assert_eq!(tun.bypass, vec!["10.0.0.0/8"]);
        assert!(tun.ipv6);
        Ok(())
    }

    #[test]
    fn converts_naive_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "naive",
      "tag": "naive-h3",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "network": "udp",
      "users": [
        { "username": "user", "password": "pass" },
        { "username": "alice", "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key",
        "alpn": ["h3"]
      },
      "quic_congestion_control": "reno"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Naive(naive) = config.inbounds[0].to_server_config()? else {
            bail!("expected Naive")
        };
        assert_eq!(naive.listen, "127.0.0.1:8443".parse()?);
        assert_eq!(naive.username, "user");
        assert_eq!(naive.password, "pass");
        assert_eq!(naive.users, vec!["alice:alice-pass".to_string()]);
        assert_eq!(naive.cert_path, PathBuf::from("server.crt"));
        assert_eq!(naive.key_path, PathBuf::from("server.key"));
        assert!(!naive.tcp);
        assert!(naive.quic);
        assert_eq!(naive.quic_congestion_control, "reno");
        Ok(())
    }

    #[test]
    fn converts_vless_reality_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf" }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h2"],
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.example.com",
            "server_port": 443
          },
          "private_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
          "short_id": ["a1b2"]
        }
      },
      "transport": {
        "type": "grpc",
        "service_name": "TunService"
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        let reality = vless.reality.context("REALITY config")?;
        assert_eq!(vless.listen, "127.0.0.1:8443".parse()?);
        assert!(!vless.tls);
        assert_eq!(vless.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(reality.server_name, "www.example.com");
        assert_eq!(reality.server_port, 443);
        assert_eq!(reality.short_ids[0], [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reality.alpn_protocols, vec![b"h2".to_vec()]);
        assert_eq!(vless.transport.kind, VlessTransportKind::Grpc);
        assert_eq!(vless.transport.path, "/TunService/Tun");
        Ok(())
    }

    #[test]
    fn converts_vless_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-tls",
      "listen": "127.0.0.1",
      "listen_port": 9443,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf", "flow": "xtls-rprx-vision" },
        { "uuid": "433722e1-0f8c-4724-9089-d5bc6d0c51ef", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key"
      },
      "transport": {
        "type": "ws",
        "path": "/ws",
        "headers": { "Host": "front.example.com" }
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.listen, "127.0.0.1:9443".parse()?);
        assert!(vless.tls);
        assert_eq!(vless.cert_path, PathBuf::from("server.crt"));
        assert_eq!(vless.key_path, PathBuf::from("server.key"));
        assert_eq!(vless.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(
            vless.users,
            vec!["433722e1-0f8c-4724-9089-d5bc6d0c51ef".to_string()]
        );
        assert_eq!(vless.flow, "xtls-rprx-vision");
        assert_eq!(vless.transport.kind, VlessTransportKind::WebSocket);
        assert_eq!(vless.transport.path, "/ws");
        assert_eq!(vless.transport.host, Some("front.example.com".to_string()));
        Ok(())
    }

    #[test]
    fn converts_vless_inline_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-inline-tls",
      "listen": "127.0.0.1",
      "listen_port": 9443,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf" }
      ],
      "tls": {
        "enabled": true,
        "certificate": ["cert-line-1", "cert-line-2"],
        "key": ["key-line-1", "key-line-2"]
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.cert_path, PathBuf::new());
        assert_eq!(vless.key_path, PathBuf::new());
        assert_eq!(vless.certificates, vec!["cert-line-1\ncert-line-2"]);
        assert_eq!(vless.key.as_deref(), Some("key-line-1\nkey-line-2"));
        Ok(())
    }

    #[test]
    fn converts_anytls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "anytls",
      "tag": "anytls",
      "listen": "127.0.0.1",
      "listen_port": 8444,
      "users": [
        { "password": "primary-pass" },
        { "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key"
      },
      "padding_scheme": ["stop=8"]
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::AnyTls(anytls) = config.inbounds[0].to_server_config()? else {
            bail!("expected AnyTLS")
        };
        assert_eq!(anytls.listen, "127.0.0.1:8444".parse()?);
        assert_eq!(anytls.password, "primary-pass");
        assert_eq!(anytls.users, vec!["alice-pass".to_string()]);
        assert_eq!(anytls.cert_path, PathBuf::from("server.crt"));
        assert_eq!(anytls.key_path, PathBuf::from("server.key"));
        assert_eq!(anytls.padding_scheme, vec!["stop=8".to_string()]);
        Ok(())
    }

    #[test]
    fn converts_mieru_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "mieru",
      "tag": "mieru",
      "listen": "127.0.0.1",
      "listen_port": 8964,
      "users": [
        { "username": "default", "password": "primary-pass" },
        { "username": "alice", "password": "alice-pass" }
      ],
      "transport": "udp",
      "mtu": 1400,
      "user_hint_mandatory": true
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Mieru(mieru) = config.inbounds[0].to_server_config()? else {
            bail!("expected Mieru")
        };
        assert_eq!(mieru.listen, "127.0.0.1:8964".parse()?);
        assert_eq!(mieru.username, "default");
        assert_eq!(mieru.password, "primary-pass");
        assert_eq!(mieru.users.len(), 1);
        assert_eq!(mieru.mtu, 1400);
        assert!(mieru.user_hint_mandatory);
        assert_eq!(mieru.transport, MieruTransport::Udp);
        Ok(())
    }

    #[test]
    fn converts_hysteria2_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "127.0.0.1",
      "listen_port": 8445,
      "users": [
        { "password": "primary-pass" },
        { "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key",
        "alpn": ["h3"]
      },
      "obfs": {
        "type": "salamander",
        "password": "obfs-pass"
      },
      "up_mbps": 5,
      "down_mbps": 10
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Hysteria2(hy2) = config.inbounds[0].to_server_config()? else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hy2.listen, "127.0.0.1:8445".parse()?);
        assert_eq!(hy2.password, "primary-pass");
        assert_eq!(hy2.users, vec!["alice-pass".to_string()]);
        assert_eq!(hy2.cert_path, PathBuf::from("server.crt"));
        assert_eq!(hy2.key_path, PathBuf::from("server.key"));
        assert_eq!(hy2.obfs, Some("salamander".to_string()));
        assert_eq!(hy2.obfs_password, Some("obfs-pass".to_string()));
        assert_eq!(hy2.upload_bandwidth, Some(5));
        assert_eq!(hy2.cc_rx, "1250000");
        assert!(hy2.udp);
        Ok(())
    }

    #[test]
    fn converts_tuic_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "127.0.0.1",
      "listen_port": 9445,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf", "password": "primary-pass" },
        { "uuid": "433722e1-0f8c-4724-9089-d5bc6d0c51ef", "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key",
        "alpn": ["h3"]
      },
      "congestion_control": "bbr",
      "heartbeat": "15s"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Tuic(tuic) = config.inbounds[0].to_server_config()? else {
            bail!("expected TUIC")
        };
        assert_eq!(tuic.listen, "127.0.0.1:9445".parse()?);
        assert_eq!(tuic.uuid, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(tuic.password, "primary-pass");
        assert_eq!(
            tuic.users,
            vec!["433722e1-0f8c-4724-9089-d5bc6d0c51ef:alice-pass".to_string()]
        );
        assert_eq!(tuic.cert_path, PathBuf::from("server.crt"));
        assert_eq!(tuic.key_path, PathBuf::from("server.key"));
        assert_eq!(tuic.congestion_control, "bbr");
        assert_eq!(tuic.alpn_protocols, vec!["h3".to_string()]);
        assert_eq!(tuic.heartbeat_interval_secs, 15);
        Ok(())
    }

    #[test]
    fn converts_shadowsocks_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-udp",
      "listen": "127.0.0.1",
      "listen_port": 8388,
      "network": "udp",
      "method": "aes-128-gcm",
      "password": "primary-pass",
      "users": [
        { "name": "alice", "password": "alice-pass" }
      ]
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Shadowsocks(shadowsocks) =
            config.inbounds[0].to_server_config()?
        else {
            bail!("expected Shadowsocks")
        };
        assert_eq!(shadowsocks.listen, "127.0.0.1:8388".parse()?);
        assert_eq!(shadowsocks.method, "aes-128-gcm");
        assert_eq!(shadowsocks.password, "primary-pass");
        assert_eq!(shadowsocks.users, vec!["alice:alice-pass".to_string()]);
        assert!(!shadowsocks.tcp);
        assert!(shadowsocks.udp);
        Ok(())
    }

    #[test]
    fn converts_trojan_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-ws",
      "listen": "127.0.0.1",
      "listen_port": 9443,
      "users": [
        { "password": "primary-pass" },
        { "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": ["server.crt"],
        "key_path": "server.key",
        "ech": { "key_path": "trojan-ech.keys" }
      },
      "transport": {
        "type": "ws",
        "path": "/trojan"
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Trojan(trojan) = config.inbounds[0].to_server_config()? else {
            bail!("expected Trojan")
        };
        assert_eq!(trojan.listen, "127.0.0.1:9443".parse()?);
        assert_eq!(trojan.password, "primary-pass");
        assert_eq!(trojan.users, vec!["alice-pass".to_string()]);
        assert_eq!(trojan.cert_path, PathBuf::from("server.crt"));
        assert_eq!(trojan.key_path, PathBuf::from("server.key"));
        assert_eq!(trojan.transport.kind, VlessTransportKind::WebSocket);
        assert_eq!(trojan.transport.path, "/trojan");
        assert!(trojan.ech.is_some());
        Ok(())
    }

    #[test]
    fn converts_vmess_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "vmess",
      "tag": "vmess-h2",
      "listen": "127.0.0.1",
      "listen_port": 9444,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf", "alterId": 0 },
        { "uuid": "433722e1-0f8c-4724-9089-d5bc6d0c51ef" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key",
        "alpn": ["h2"],
        "ech": { "key_path": "vmess-ech.keys" }
      },
      "transport": {
        "type": "http",
        "path": "/vmess"
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Vmess(vmess) = config.inbounds[0].to_server_config()? else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.listen, "127.0.0.1:9444".parse()?);
        assert!(vmess.tls);
        assert_eq!(vmess.cert_path, Some(PathBuf::from("server.crt")));
        assert_eq!(vmess.key_path, Some(PathBuf::from("server.key")));
        assert_eq!(vmess.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(
            vmess.users,
            vec!["433722e1-0f8c-4724-9089-d5bc6d0c51ef".to_string()]
        );
        assert_eq!(vmess.transport.kind, VlessTransportKind::Http2);
        assert_eq!(vmess.transport.path, "/vmess");
        assert!(vmess.ech.is_some());
        Ok(())
    }

    #[test]
    fn parses_shadowsocks_udp_over_tcp_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-uot",
      "server": "example.com",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret",
      "network": "tcp",
      "udp_over_tcp": { "enabled": true, "version": 2 }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-no-uot",
      "server": "example.com",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret",
      "network": "tcp",
      "udp_over_tcp": { "enabled": false, "version": 1 }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Shadowsocks(shadowsocks) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Shadowsocks")
        };
        assert!(shadowsocks.udp);
        assert!(shadowsocks.udp_over_tcp);
        let SingBoxClientConfig::Shadowsocks(disabled) =
            config.outbounds[1].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Shadowsocks")
        };
        assert!(!disabled.udp);
        assert!(!disabled.udp_over_tcp);
        Ok(())
    }

    #[test]
    fn parses_vless_reality_outbound() -> Result<()> {
        let json = r#"
{
  "inbounds": [{ "type": "mixed", "listen": "127.0.0.1", "listen_port": 7890 }],
  "outbounds": [{
    "type": "vless",
    "tag": "proxy",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "flow": "xtls-rprx-vision",
    "packet_encoding": "xudp",
    "tls": {
      "enabled": true,
      "server_name": "www.example.com",
      "utls": { "enabled": true, "fingerprint": "chrome" },
      "reality": {
        "enabled": true,
        "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "short_id": "a1b2"
      }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(
            config.local_socks_listen()?,
            Some("127.0.0.1:7890".parse()?)
        );
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.sni, "www.example.com");
        assert_eq!(vless.client_fingerprint, Some(UtlsFingerprint::Chrome));
        assert!(vless.reality.is_some());
        Ok(())
    }

    #[test]
    fn parses_vless_raw_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "vless-raw",
    "server": "example.com",
    "server_port": 80,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": false }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert!(!vless.tls);
        assert!(vless.reality.is_none());
        assert_eq!(vless.server_port, 80);
        Ok(())
    }

    #[test]
    fn rejects_sing_box_multiplex() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "muxed",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true },
    "multiplex": { "enabled": true }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("multiplex must be explicit");
        assert!(error.to_string().contains("not wire-compatible"));
        Ok(())
    }

    #[test]
    fn parses_vless_websocket_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "vless-ws",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true },
    "transport": {
      "type": "ws",
      "path": "/vless",
      "headers": { "Host": "edge.example.com" }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
        let json = r#"
{
  "outbounds": [{
    "type": "trojan",
    "tag": "trojan-ws",
    "server": "example.com",
    "server_port": 443,
    "password": "secret",
    "tls": { "enabled": true },
    "transport": {
      "type": "ws",
      "path": "/trojan",
      "headers": { "Host": "edge.example.com" }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Trojan(trojan) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
        let json = r#"
{
  "outbounds": [{
    "type": "vmess",
    "tag": "vmess-ws",
    "server": "example.com",
    "server_port": 80,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "alter_id": 0,
    "packet_encoding": "packetaddr",
    "transport": {
      "type": "ws",
      "path": "/vmess",
      "headers": { "Host": "edge.example.com" }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vmess(vmess) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
        let json = r#"
{
  "outbounds": [{
    "type": "vmess",
    "tag": "vmess-xudp",
    "server": "example.com",
    "server_port": 80,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "alter_id": 0,
    "packet_encoding": "xudp"
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vmess(vmess) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.packet_encoding, "xudp");
        Ok(())
    }

    #[test]
    fn parses_vless_http2_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "vless-h2",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true, "alpn": "h2" },
    "transport": {
      "type": "http2",
      "path": "/h2",
      "host": "edge.example.com"
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.transport.kind, VlessTransportKind::Http2);
        assert_eq!(vless.transport.path, "/h2");
        assert_eq!(
            vless.transport.request_host("example.com"),
            "edge.example.com"
        );
        Ok(())
    }

    #[test]
    fn parses_vless_grpc_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "vless-grpc",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true, "alpn": "h2" },
    "transport": {
      "type": "grpc",
      "service_name": "TunService",
      "headers": { "Host": "edge.example.com" }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.transport.kind, VlessTransportKind::Grpc);
        assert_eq!(vless.transport.path, "/TunService/Tun");
        assert_eq!(
            vless.transport.request_host("example.com"),
            "edge.example.com"
        );
        Ok(())
    }

    #[test]
    fn parses_vless_xhttp_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "vless-xhttp",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true, "alpn": "http/1.1" },
    "transport": {
      "type": "xhttp",
      "path": "/xhttp",
      "host": "edge.example.com",
      "mode": "stream-one"
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
    fn parses_hysteria2_udp_network() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "hysteria2",
    "tag": "hy2-udp",
    "server": "example.com",
    "server_port": 443,
    "password": "secret",
    "network": "udp",
    "up_mbps": 10,
    "down_mbps": 80,
    "tls": {
      "enabled": true,
      "server_name": "hy2.example.com",
      "insecure": true,
      "disable_system_root": true,
      "alpn": ["h3"],
      "certificate_path": ["ca.pem", "backup-ca.pem"],
      "certificate": ["hy2-inline-ca"]
    },
    "obfs": {
      "type": "salamander",
      "password": "obfs-pass"
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Hysteria2(hysteria2) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hysteria2.server_host, "example.com");
        assert_eq!(hysteria2.server_port, 443);
        assert_eq!(hysteria2.password, "secret");
        assert_eq!(hysteria2.sni, "hy2.example.com");
        assert!(hysteria2.insecure);
        assert!(hysteria2.disable_system_roots);
        assert_eq!(
            hysteria2.ca_cert_paths,
            vec![PathBuf::from("ca.pem"), PathBuf::from("backup-ca.pem")]
        );
        assert_eq!(hysteria2.ca_certificates, vec!["hy2-inline-ca"]);
        assert!(hysteria2.udp);
        assert_eq!(hysteria2.obfs.as_deref(), Some("salamander"));
        assert_eq!(hysteria2.obfs_password.as_deref(), Some("obfs-pass"));
        assert_eq!(hysteria2.upload_bandwidth, Some(10));
        assert_eq!(hysteria2.download_bandwidth, Some(80));
        Ok(())
    }

    #[test]
    fn parses_client_custom_tls_roots() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-tls",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "tls": {
        "enabled": true,
        "certificate_path": ["vless-ca.pem"],
        "certificate": ["vless-inline-ca"]
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-tls",
      "server": "vmess.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "alter_id": 0,
      "tls": {
        "enabled": true,
        "certificate_path": "vmess-ca.pem",
        "certificate": "vmess-inline-ca"
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-tls",
      "server": "trojan.example.com",
      "server_port": 443,
      "password": "secret",
      "tls": {
        "enabled": true,
        "certificate_path": "trojan-ca.pem",
        "certificate": "trojan-inline-ca"
      }
    },
    {
      "type": "anytls",
      "tag": "anytls",
      "server": "anytls.example.com",
      "server_port": 443,
      "password": "secret",
      "tls": {
        "enabled": true,
        "certificate_path": "anytls-ca.pem",
        "disable_system_root": true,
        "certificate": ["anytls-inline-ca"],
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-v5",
      "server": "tuic.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "password": "secret",
      "tls": {
        "enabled": true,
        "certificate_path": "tuic-ca.pem",
        "certificate": "tuic-inline-ca"
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.ca_cert_paths, vec![PathBuf::from("vless-ca.pem")]);
        assert_eq!(vless.ca_certificates, vec!["vless-inline-ca"]);

        let SingBoxClientConfig::Vmess(vmess) =
            config.outbounds[1].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.ca_cert_paths, vec![PathBuf::from("vmess-ca.pem")]);
        assert_eq!(vmess.ca_certificates, vec!["vmess-inline-ca"]);

        let SingBoxClientConfig::Trojan(trojan) =
            config.outbounds[2].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Trojan")
        };
        assert_eq!(trojan.ca_cert_paths, vec![PathBuf::from("trojan-ca.pem")]);
        assert_eq!(trojan.ca_certificates, vec!["trojan-inline-ca"]);

        let SingBoxClientConfig::AnyTls(anytls) =
            config.outbounds[3].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected AnyTLS")
        };
        assert_eq!(anytls.ca_cert_paths, vec![PathBuf::from("anytls-ca.pem")]);
        assert_eq!(anytls.ca_certificates, vec!["anytls-inline-ca"]);
        assert!(anytls.disable_system_roots);
        assert_eq!(anytls.client_fingerprint, Some(UtlsFingerprint::Chrome));

        let SingBoxClientConfig::Tuic(tuic) =
            config.outbounds[4].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected TUIC")
        };
        assert_eq!(tuic.ca_cert_paths, vec![PathBuf::from("tuic-ca.pem")]);
        assert_eq!(tuic.ca_certificates, vec!["tuic-inline-ca"]);
        Ok(())
    }

    #[test]
    fn rejects_singbox_unsupported_tls_options() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-min-version",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "tls": {
        "enabled": true,
        "min_version": "1.3"
      }
    },
    {
      "type": "naive",
      "tag": "naive-disable-sni",
      "server": "naive.example.com",
      "server_port": 443,
      "tls": {
        "enabled": true,
        "disable_sni": true
      }
    },
    {
      "type": "http",
      "tag": "http-utls-extra",
      "server": "proxy.example.com",
      "server_port": 443,
      "tls": {
        "enabled": true,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome",
          "randomized": true
        }
      }
    }
  ],
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-mtls",
      "listen_port": 8443,
      "users": [{ "password": "secret" }],
      "tls": {
        "enabled": true,
        "client_authentication": "require"
      }
    },
    {
      "type": "anytls",
      "tag": "anytls-unknown-tls",
      "listen_port": 8444,
      "users": [{ "password": "secret" }],
      "tls": {
        "enabled": true,
        "unexpected_tls_field": true
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let version_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("TLS min_version must not be ignored");
        assert!(version_error.to_string().contains("tls.min_version"));

        let disable_sni_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("TLS disable_sni must not be ignored");
        assert!(disable_sni_error.to_string().contains("tls.disable_sni"));

        let utls_error = config.outbounds[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unknown uTLS fields must not be ignored");
        assert!(utls_error.to_string().contains("tls.utls"));

        let mtls_error = config.inbounds[0]
            .to_server_config()
            .err()
            .context("TLS client_authentication must not be ignored")?;
        assert!(mtls_error.to_string().contains("tls.client_authentication"));

        let unknown_error = config.inbounds[1]
            .to_server_config()
            .err()
            .context("unknown TLS fields must not be ignored")?;
        assert!(unknown_error.to_string().contains("unsupported fields"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_unsupported_profile_fields() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-dialer",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "tls": { "enabled": true },
      "dialer_proxy": "bootstrap"
    },
    {
      "type": "vless",
      "tag": "vless-ws-early",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "tls": { "enabled": true },
      "transport": {
        "type": "ws",
        "path": "/vless",
        "max_early_data": 2048
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-mux-fields",
      "server": "ss.example.com",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret",
      "multiplex": {
        "enabled": false,
        "protocol": "smux"
      }
    }
  ],
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-sniff",
      "listen_port": 8443,
      "users": [{ "password": "secret" }],
      "tls": { "enabled": true, "certificate_path": "server.crt", "key_path": "server.key" },
      "sniff": true
    },
    {
      "type": "hysteria2",
      "tag": "hy2-obfs-extra",
      "listen_port": 8444,
      "password": "secret",
      "tls": { "enabled": true, "certificate_path": "server.crt", "key_path": "server.key" },
      "obfs": {
        "type": "salamander",
        "password": "obfs-pass",
        "padding": true
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let dialer_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported outbound fields must not be ignored");
        assert!(dialer_error.to_string().contains("dialer_proxy"));

        let transport_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported transport fields must not be ignored");
        assert!(transport_error.to_string().contains("transport"));
        assert!(transport_error.to_string().contains("max_early_data"));

        let multiplex_error = config.outbounds[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("disabled multiplex settings must not be ignored");
        assert!(multiplex_error.to_string().contains("multiplex"));

        let inbound_error = config.inbounds[0]
            .to_server_config()
            .err()
            .context("unsupported inbound fields must not be ignored")?;
        assert!(inbound_error.to_string().contains("sniff"));

        let obfs_error = config.inbounds[1]
            .to_server_config()
            .err()
            .context("unsupported obfs fields must not be ignored")?;
        assert!(obfs_error.to_string().contains("obfs"));
        assert!(obfs_error.to_string().contains("padding"));
        Ok(())
    }

    #[test]
    fn rejects_hysteria2_port_hopping() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "hysteria2",
    "tag": "hy2-hop",
    "server": "example.com",
    "server_ports": [443, 8443],
    "hop_interval": "30s",
    "password": "secret",
    "tls": { "enabled": true }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("port hopping must be explicit");
        assert!(error.to_string().contains("port hopping"));
        Ok(())
    }

    #[test]
    fn parses_hysteria2_upload_bandwidth() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "hysteria2",
    "tag": "hy2-up",
    "server": "example.com",
    "server_port": 443,
    "password": "secret",
    "up_mbps": 10,
    "tls": { "enabled": true }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Hysteria2(hysteria2) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hysteria2.upload_bandwidth, Some(10));
        Ok(())
    }

    #[test]
    fn parses_naive_and_tuic_outbounds() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "naive",
      "tag": "naive-h3",
      "server": "naive.example.com",
      "server_port": 443,
      "username": "user",
      "password": "pass",
      "quic": true,
      "quic_congestion_control": "reno",
      "udp_over_tcp": { "enabled": true, "version": 2 },
      "tls": {
        "enabled": true,
        "server_name": "front.example.com",
        "certificate_path": ["ca.pem", "backup-ca.pem"],
        "certificate": "naive-inline-ca"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-v5",
      "server": "tuic.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "password": "secret",
      "network": "tcp",
      "udp_relay_mode": "quic",
      "congestion_control": "bbr",
      "heartbeat": "15s",
      "tls": {
        "enabled": true,
        "server_name": "front.example.com",
        "alpn": ["h3"],
        "certificate": ["tuic-inline-ca"]
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Naive(naive) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Naive")
        };
        assert_eq!(naive.server_host, "naive.example.com");
        assert_eq!(naive.sni, "front.example.com");
        assert!(!naive.insecure);
        assert_eq!(
            naive.ca_cert_paths,
            vec![PathBuf::from("ca.pem"), PathBuf::from("backup-ca.pem")]
        );
        assert_eq!(naive.ca_certificates, vec!["naive-inline-ca"]);
        assert!(naive.quic);
        assert!(naive.udp_over_tcp);
        assert_eq!(naive.quic_congestion_control, "reno");

        let SingBoxClientConfig::Tuic(tuic) =
            config.outbounds[1].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected TUIC")
        };
        assert_eq!(tuic.server_host, "tuic.example.com");
        assert_eq!(tuic.sni, "front.example.com");
        assert!(!tuic.udp);
        assert_eq!(tuic.udp_relay_mode, "quic");
        assert_eq!(tuic.congestion_control, "bbr");
        assert_eq!(tuic.alpn_protocols, vec!["h3".to_string()]);
        assert_eq!(tuic.heartbeat_interval_secs, 15);
        assert_eq!(tuic.ca_certificates, vec!["tuic-inline-ca"]);
        Ok(())
    }

    #[test]
    fn rejects_unmapped_naive_options() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "naive",
      "tag": "naive-uot-v1",
      "server": "naive.example.com",
      "server_port": 443,
      "udp_over_tcp": { "enabled": true, "version": 1 },
      "tls": { "enabled": true }
    },
    {
      "type": "naive",
      "tag": "naive-concurrency",
      "server": "naive.example.com",
      "server_port": 443,
      "insecure_concurrency": 2,
      "tls": { "enabled": true }
    },
    {
      "type": "naive",
      "tag": "naive-ech",
      "server": "naive.example.com",
      "server_port": 443,
      "tls": {
        "enabled": true,
        "ech": { "enabled": true }
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let uot_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("UOT v1 must be explicit");
        assert!(uot_error.to_string().contains("version 2"));

        let concurrency_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("insecure_concurrency must be explicit");
        assert!(
            concurrency_error
                .to_string()
                .contains("insecure_concurrency")
        );

        let ech_error = config.outbounds[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("ECH must be explicit");
        assert!(ech_error.to_string().contains("ECH"));
        Ok(())
    }

    #[test]
    fn rejects_unmapped_tuic_options() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "tuic",
      "tag": "tuic-0rtt",
      "server": "tuic.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "password": "secret",
      "zero_rtt_handshake": true,
      "tls": { "enabled": true }
    },
    {
      "type": "tuic",
      "tag": "tuic-uos",
      "server": "tuic.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "password": "secret",
      "udp_over_stream": true,
      "tls": { "enabled": true }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let zero_rtt_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("0-RTT must be explicit");
        assert!(zero_rtt_error.to_string().contains("zero_rtt"));
        let udp_over_stream_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("udp_over_stream must be explicit");
        assert!(
            udp_over_stream_error
                .to_string()
                .contains("udp_over_stream")
        );
        Ok(())
    }

    #[test]
    fn converts_http_outbound_to_client_config() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "http",
      "tag": "http-proxy",
      "server": "proxy.example.com",
      "server_port": 8443,
      "username": "user",
      "password": "pass",
      "headers": {
        "X-Test": "value"
      },
      "tls": {
        "enabled": true,
        "server_name": "front.example.com",
        "insecure": true,
        "alpn": "http/1.1",
        "utls": { "enabled": true, "fingerprint": "chrome" }
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::HttpProxy(http) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected HTTP proxy")
        };
        assert_eq!(http.server_host, "proxy.example.com");
        assert_eq!(http.server_port, 8443);
        assert_eq!(http.username, "user");
        assert_eq!(http.password, "pass");
        assert!(http.tls);
        assert_eq!(http.sni, "front.example.com");
        assert!(http.insecure);
        assert_eq!(http.client_fingerprint, Some(UtlsFingerprint::Chrome));
        assert_eq!(
            http.extra_headers,
            vec![("X-Test".to_string(), "value".to_string())]
        );
        Ok(())
    }

    #[test]
    fn converts_socks_outbound_to_client_config() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "socks",
      "tag": "socks-proxy",
      "server": "proxy.example.com",
      "server_port": 1080,
      "username": "user",
      "password": "pass",
      "network": "tcp+udp"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::SocksProxy(socks) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
    fn converts_builtin_route_outbounds_to_client_config() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    { "type": "direct", "tag": "direct-out" },
    { "type": "block", "tag": "block-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Route(direct) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected direct route client")
        };
        assert_eq!(direct.default, RouteDecision::Direct);
        let SingBoxClientConfig::Route(block) =
            config.outbounds[1].to_client_config("127.0.0.1:1081".parse()?)?
        else {
            bail!("expected block route client")
        };
        assert_eq!(block.default, RouteDecision::Block);
        Ok(())
    }

    #[test]
    fn resolves_selector_outbound_default() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "select",
      "outbounds": ["direct-out", "block-out"],
      "default": "block-out"
    },
    { "type": "direct", "tag": "direct-out" },
    { "type": "block", "tag": "block-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(config.resolved_outbound("select")?.name(), "block-out");
        let SingBoxClientConfig::Route(block) = config
            .resolved_outbound_profile("select")?
            .to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected selected block route client")
        };
        assert_eq!(block.default, RouteDecision::Block);
        Ok(())
    }

    #[test]
    fn resolves_selector_first_outbound_without_default() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "select",
      "outbounds": ["direct-out", "block-out"]
    },
    { "type": "direct", "tag": "direct-out" },
    { "type": "block", "tag": "block-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(config.resolved_outbound("select")?.name(), "direct-out");
        Ok(())
    }

    #[test]
    fn rejects_selector_cycle() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "a",
      "outbounds": ["b"],
      "default": "b"
    },
    {
      "type": "selector",
      "tag": "b",
      "outbounds": ["a"],
      "default": "a"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .resolved_outbound("a")
            .expect_err("selector cycles must fail");
        assert!(error.to_string().contains("cycle"));
        Ok(())
    }

    #[test]
    fn resolves_single_urltest_policy_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["direct-out"]
    },
    { "type": "direct", "tag": "direct-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(config.resolved_outbound("auto")?.name(), "direct-out");
        let SingBoxClientConfig::Route(route) = config
            .resolved_outbound_profile("auto")?
            .to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected static urltest direct route client")
        };
        assert_eq!(route.default, RouteDecision::Direct);
        Ok(())
    }

    #[test]
    fn rejects_selector_runtime_policy_fields() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "select",
      "outbounds": ["direct-out"],
      "interrupt_exist_connections": false
    },
    { "type": "direct", "tag": "direct-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .resolved_outbound("select")
            .expect_err("selector runtime policy must not be ignored");
        assert!(error.to_string().contains("interrupt_exist_connections"));
        Ok(())
    }

    #[test]
    fn rejects_urltest_runtime_policy_fields() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["direct-out"],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "3m"
    },
    { "type": "direct", "tag": "direct-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .resolved_outbound("auto")
            .expect_err("urltest runtime policy must not be ignored");
        assert!(error.to_string().contains("active latency testing"));
        assert!(error.to_string().contains("url"));
        Ok(())
    }

    #[test]
    fn rejects_urltest_policy_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["direct-out", "block-out"]
    },
    { "type": "direct", "tag": "direct-out" },
    { "type": "block", "tag": "block-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .resolved_outbound("auto")
            .expect_err("urltest requires active latency selection");
        assert!(error.to_string().contains("single-outbound"));
        Ok(())
    }
}
