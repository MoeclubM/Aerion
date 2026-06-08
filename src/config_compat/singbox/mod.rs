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
use crate::tls_ech::tls_ech_from_singbox_value;
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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::config_compat::common::{
    alpn_values, deserialize_optional_u16, ensure_no_extra_fields, parse_listen_ip, value_has_data,
};

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

mod inbound;
mod outbound;
mod route;
mod tls;

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

#[cfg(test)]
mod tests;
