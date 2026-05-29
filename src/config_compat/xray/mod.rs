use crate::client::ClientConfig;
use crate::config_compat::mihomo::OneOrManyStrings;
use crate::http_connect::HttpProxyClientConfig;
use crate::hysteria2::{Hysteria2ClientConfig, Hysteria2ServerConfig};
use crate::mieru::{MieruClientConfig, MieruServerConfig, MieruTransport, MieruUser};
use crate::padding::PaddingScheme;
use crate::reality::{RealityClientConfig, RealityServerConfig};
use crate::router::RouteClientConfig;
use crate::routing::{
    DomainMatcher, IpCidr, PortRange, RouteDecision, RouteNetwork, RouteRule, RouteTable,
};
use crate::server::ServerConfig;
use crate::shadowsocks::{ShadowsocksClientConfig, ShadowsocksServerConfig};
use crate::socks::SocksProxyClientConfig;
use crate::tls_ech::{TlsEchServerKeys, tls_ech_from_compat_reference};
use crate::trojan::{TrojanClientConfig, TrojanServerConfig};
use crate::tun::{TunConfig, socks_proxy_url};
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::{VlessClientConfig, VlessServerConfig};
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::{VmessClientConfig, VmessServerConfig, ensure_vmess_packet_encoding};
use anyhow::{Context, Result, bail, ensure};
use serde::de;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::config_compat::common::{
    deserialize_optional_u16, ensure_no_extra_fields, parse_listen_ip, value_has_data,
};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayConfig {
    #[serde(default)]
    pub inbounds: Vec<XrayInbound>,
    #[serde(default)]
    pub outbounds: Vec<XrayOutbound>,
    #[serde(default)]
    pub routing: XrayRoutingConfig,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayRoutingConfig {
    #[serde(default)]
    pub rules: Vec<XrayRoutingRule>,
    #[serde(default)]
    pub balancers: Vec<XrayBalancer>,
    #[serde(default, rename = "domainStrategy", alias = "domain_strategy")]
    pub domain_strategy: Option<String>,
    #[serde(default, rename = "domainMatcher", alias = "domain_matcher")]
    pub domain_matcher: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayRoutingRule {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default, rename = "outboundTag", alias = "outbound_tag")]
    pub outbound_tag: String,
    #[serde(default, rename = "balancerTag", alias = "balancer_tag")]
    pub balancer_tag: String,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub port: Option<Value>,
    #[serde(default, rename = "sourcePort", alias = "source_port")]
    pub source_port: Option<Value>,
    #[serde(default, rename = "localPort", alias = "local_port")]
    pub local_port: Option<Value>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "sourceIP", alias = "source", alias = "source_ip")]
    pub source_ip: Option<Value>,
    #[serde(default, rename = "localIP", alias = "local_ip")]
    pub local_ip: Option<Value>,
    #[serde(default)]
    pub user: Option<Value>,
    #[serde(default, rename = "vlessRoute", alias = "vless_route")]
    pub vless_route: Option<Value>,
    #[serde(default, rename = "inboundTag", alias = "inbound_tag")]
    pub inbound_tag: Option<Value>,
    #[serde(default)]
    pub protocol: Option<Value>,
    #[serde(default)]
    pub attrs: Option<Value>,
    #[serde(default)]
    pub process: Option<Value>,
    #[serde(default, rename = "ruleTag", alias = "rule_tag")]
    pub rule_tag: Option<Value>,
    #[serde(default)]
    pub webhook: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayBalancer {
    pub tag: String,
    #[serde(default)]
    pub selector: Vec<String>,
    #[serde(default, rename = "fallbackTag", alias = "fallback_tag")]
    pub fallback_tag: String,
    #[serde(default)]
    pub strategy: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayInbound {
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_u16")]
    pub port: Option<u16>,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub settings: XrayOutboundSettings,
    #[serde(default, rename = "streamSettings")]
    pub stream_settings: XrayStreamSettings,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XrayOutbound {
    pub tag: Option<String>,
    pub protocol: String,
    pub settings: XrayOutboundSettings,
    pub stream_settings: XrayStreamSettings,
    pub mux: Option<XrayMuxOptions>,
    pub decode_error: Option<String>,
    pub extra: Map<String, Value>,
}

#[derive(Deserialize)]
struct XrayOutboundDecoded {
    #[serde(default)]
    tag: Option<String>,
    protocol: String,
    #[serde(default)]
    settings: XrayOutboundSettings,
    #[serde(default, rename = "streamSettings")]
    stream_settings: XrayStreamSettings,
    #[serde(default)]
    mux: Option<XrayMuxOptions>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl<'de> Deserialize<'de> for XrayOutbound {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = Map::<String, Value>::deserialize(deserializer)?;
        let tag = fields
            .get("tag")
            .and_then(Value::as_str)
            .map(str::to_string);
        let protocol = fields
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let decoded = serde_json::from_value::<XrayOutboundDecoded>(Value::Object(fields));
        match decoded {
            Ok(decoded) => Ok(Self {
                tag: decoded.tag,
                protocol: decoded.protocol,
                settings: decoded.settings,
                stream_settings: decoded.stream_settings,
                mux: decoded.mux,
                decode_error: None,
                extra: decoded.extra,
            }),
            Err(error) => {
                if protocol.trim().is_empty() {
                    return Err(de::Error::custom(error));
                }
                Ok(Self {
                    tag,
                    protocol,
                    settings: XrayOutboundSettings::default(),
                    stream_settings: XrayStreamSettings::default(),
                    mux: None,
                    decode_error: Some(error.to_string()),
                    extra: Map::new(),
                })
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayOutboundSettings {
    #[serde(default)]
    pub version: Option<u8>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default, rename = "pass")]
    pub pass: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default, rename = "domainStrategy", alias = "domain_strategy")]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub redirect: Option<String>,
    #[serde(default, rename = "userLevel", alias = "user_level")]
    pub user_level: Option<Value>,
    #[serde(default)]
    pub response: Option<Value>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default, rename = "packetEncoding", alias = "packet_encoding")]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default, rename = "alterId", alias = "alter_id")]
    pub alter_id: Option<u16>,
    #[serde(default, alias = "users")]
    pub clients: Vec<XrayUser>,
    #[serde(default)]
    pub fallbacks: Vec<Value>,
    #[serde(default)]
    pub vnext: Vec<XrayVnext>,
    #[serde(default)]
    pub servers: Vec<XrayServer>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct XrayVnext {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub users: Vec<XrayUser>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayUser {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default, rename = "packetEncoding", alias = "packet_encoding")]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default, rename = "alterId", alias = "alter_id")]
    pub alter_id: Option<u16>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayServer {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub users: Vec<XrayHttpUser>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayHttpUser {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default, rename = "pass")]
    pub pass: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct XrayStreamSettings {
    #[serde(default = "default_tcp_network")]
    pub network: String,
    #[serde(default)]
    pub security: String,
    #[serde(
        default,
        rename = "rawSettings",
        alias = "raw_settings",
        alias = "tcpSettings",
        alias = "tcp_settings"
    )]
    pub raw_settings: Option<Value>,
    #[serde(
        default,
        rename = "kcpSettings",
        alias = "kcp_settings",
        alias = "mkcpSettings",
        alias = "mKCPSettings",
        alias = "mkcp_settings"
    )]
    pub kcp_settings: Option<Value>,
    #[serde(default, rename = "quicSettings", alias = "quic_settings")]
    pub quic_settings: Option<Value>,
    #[serde(default, rename = "dsSettings", alias = "ds_settings")]
    pub ds_settings: Option<Value>,
    #[serde(default)]
    pub sockopt: Option<Value>,
    #[serde(default, rename = "hysteriaSettings", alias = "hysteria_settings")]
    pub hysteria_settings: Option<XrayHysteriaSettings>,
    #[serde(default)]
    pub finalmask: Option<XrayFinalMask>,
    #[serde(default, rename = "tlsSettings", alias = "tls_settings")]
    pub tls_settings: Option<XrayTlsSettings>,
    #[serde(default, rename = "realitySettings", alias = "reality_settings")]
    pub reality_settings: Option<XrayRealitySettings>,
    #[serde(default, rename = "wsSettings", alias = "ws_settings")]
    pub ws_settings: Option<XrayWsSettings>,
    #[serde(
        default,
        rename = "httpupgradeSettings",
        alias = "httpUpgradeSettings",
        alias = "http_upgrade_settings"
    )]
    pub http_upgrade_settings: Option<XrayHttpUpgradeSettings>,
    #[serde(default, rename = "grpcSettings", alias = "grpc_settings")]
    pub grpc_settings: Option<XrayGrpcSettings>,
    #[serde(
        default,
        rename = "httpSettings",
        alias = "h2Settings",
        alias = "http_settings",
        alias = "h2_settings"
    )]
    pub http_settings: Option<XrayHttpSettings>,
    #[serde(default, rename = "xhttpSettings", alias = "xhttp_settings")]
    pub xhttp_settings: Option<XrayXhttpSettings>,
    #[serde(
        default,
        rename = "splithttpSettings",
        alias = "splitHTTPSettings",
        alias = "splitHttpSettings",
        alias = "split_http_settings"
    )]
    pub split_http_settings: Option<XrayXhttpSettings>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for XrayStreamSettings {
    fn default() -> Self {
        Self {
            network: default_tcp_network(),
            security: String::new(),
            raw_settings: None,
            kcp_settings: None,
            quic_settings: None,
            ds_settings: None,
            sockopt: None,
            hysteria_settings: None,
            finalmask: None,
            tls_settings: None,
            reality_settings: None,
            ws_settings: None,
            http_upgrade_settings: None,
            grpc_settings: None,
            http_settings: None,
            xhttp_settings: None,
            split_http_settings: None,
            extra: Map::new(),
        }
    }
}

impl XrayOutboundSettings {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("{owner} settings"), &self.extra)?;
        for (index, client) in self.clients.iter().enumerate() {
            ensure_no_extra_fields(&format!("{owner} settings.clients[{index}]"), &client.extra)?;
        }
        for (vnext_index, vnext) in self.vnext.iter().enumerate() {
            ensure_no_extra_fields(
                &format!("{owner} settings.vnext[{vnext_index}]"),
                &vnext.extra,
            )?;
            for (user_index, user) in vnext.users.iter().enumerate() {
                ensure_no_extra_fields(
                    &format!("{owner} settings.vnext[{vnext_index}].users[{user_index}]"),
                    &user.extra,
                )?;
            }
        }
        for (server_index, server) in self.servers.iter().enumerate() {
            ensure_no_extra_fields(
                &format!("{owner} settings.servers[{server_index}]"),
                &server.extra,
            )?;
            for (user_index, user) in server.users.iter().enumerate() {
                ensure_no_extra_fields(
                    &format!("{owner} settings.servers[{server_index}].users[{user_index}]"),
                    &user.extra,
                )?;
            }
        }
        Ok(())
    }

    fn reject_local_socks_fields(&self, owner: &str) -> Result<()> {
        self.reject_unsupported_extra_fields(owner)?;
        let auth = self.auth.as_deref().unwrap_or_default().trim();
        ensure!(
            auth.is_empty() || auth.eq_ignore_ascii_case("noauth"),
            "{owner} settings.auth {auth} requires an authenticated local SOCKS listener"
        );
        let mut fields = Vec::new();
        if self.version.is_some() {
            fields.push("version");
        }
        if option_text_has_data(&self.address) {
            fields.push("address");
        }
        if self.port.is_some() {
            fields.push("port");
        }
        if option_text_has_data(&self.id) {
            fields.push("id");
        }
        if option_text_has_data(&self.password) {
            fields.push("password");
        }
        if option_text_has_data(&self.user) {
            fields.push("user");
        }
        if option_text_has_data(&self.pass) {
            fields.push("pass");
        }
        if !self.headers.is_empty() {
            fields.push("headers");
        }
        if option_text_has_data(&self.network) {
            fields.push("network");
        }
        if option_text_has_data(&self.domain_strategy) {
            fields.push("domainStrategy");
        }
        if option_text_has_data(&self.redirect) {
            fields.push("redirect");
        }
        if self
            .user_level
            .as_ref()
            .map(value_has_data)
            .unwrap_or(false)
        {
            fields.push("userLevel");
        }
        if self.response.as_ref().map(value_has_data).unwrap_or(false) {
            fields.push("response");
        }
        if option_text_has_data(&self.flow) {
            fields.push("flow");
        }
        if option_text_has_data(&self.packet_encoding) {
            fields.push("packetEncoding");
        }
        if option_text_has_data(&self.security) {
            fields.push("security");
        }
        if option_text_has_data(&self.method) {
            fields.push("method");
        }
        if option_text_has_data(&self.decryption) {
            fields.push("decryption");
        }
        if self.alter_id.is_some() {
            fields.push("alterId");
        }
        if !self.clients.is_empty() {
            fields.push("clients");
        }
        if !self.fallbacks.is_empty() {
            fields.push("fallbacks");
        }
        if !self.vnext.is_empty() {
            fields.push("vnext");
        }
        if !self.servers.is_empty() {
            fields.push("servers");
        }
        ensure!(
            fields.is_empty(),
            "{owner} settings has unsupported local SOCKS fields {:?}",
            fields
        );
        Ok(())
    }
}

impl XrayStreamSettings {
    fn reject_unsupported_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("{owner} streamSettings"), &self.extra)?;
        ensure!(
            !self
                .raw_settings
                .as_ref()
                .map(xray_raw_settings_has_unsupported_data)
                .unwrap_or(false),
            "{owner} streamSettings rawSettings/tcpSettings requires raw TCP header options"
        );
        for (field, value, reason) in [
            (
                "kcpSettings",
                &self.kcp_settings,
                "mKCP stream transport support",
            ),
            (
                "quicSettings",
                &self.quic_settings,
                "QUIC stream transport support",
            ),
            (
                "dsSettings",
                &self.ds_settings,
                "domain-socket stream transport support",
            ),
            ("sockopt", &self.sockopt, "socket option plumbing"),
        ] {
            ensure!(
                !value.as_ref().map(value_has_data).unwrap_or(false),
                "{owner} streamSettings {field} requires {reason}"
            );
        }
        if let Some(tls) = &self.tls_settings {
            tls.reject_unsupported_fields(owner)?;
        }
        if let Some(reality) = &self.reality_settings {
            reality.reject_unsupported_extra_fields(owner)?;
        }
        if let Some(hysteria) = &self.hysteria_settings {
            hysteria.reject_unsupported_extra_fields(owner)?;
        }
        if let Some(finalmask) = &self.finalmask {
            finalmask.reject_unsupported_extra_fields(owner)?;
        }
        if let Some(ws) = &self.ws_settings {
            ws.reject_unsupported_extra_fields(owner)?;
        }
        if let Some(http_upgrade) = &self.http_upgrade_settings {
            http_upgrade.reject_unsupported_extra_fields(owner)?;
        }
        if let Some(grpc) = &self.grpc_settings {
            grpc.reject_unsupported_extra_fields(owner)?;
        }
        if let Some(http) = &self.http_settings {
            http.reject_unsupported_extra_fields(owner)?;
        }
        if let Some(xhttp) = &self.xhttp_settings {
            xhttp.reject_unsupported_extra_fields(owner, "xhttpSettings")?;
        }
        if let Some(split_http) = &self.split_http_settings {
            split_http.reject_unsupported_extra_fields(owner, "splitHTTPSettings")?;
        }
        Ok(())
    }

    fn reject_local_socks_listener_fields(&self, owner: &str) -> Result<()> {
        self.reject_unsupported_fields(owner)?;
        let network = self.network.trim();
        ensure!(
            network.is_empty()
                || network.eq_ignore_ascii_case("tcp")
                || network.eq_ignore_ascii_case("raw"),
            "{owner} uses stream network {network}; Aerion local SOCKS listener accepts raw TCP only"
        );
        let security = self.security.trim();
        ensure!(
            security.is_empty() || security.eq_ignore_ascii_case("none"),
            "{owner} uses stream security {security}; Aerion local SOCKS listener accepts raw TCP only"
        );
        ensure!(
            self.hysteria_settings.is_none()
                && self.finalmask.is_none()
                && self.tls_settings.is_none()
                && self.reality_settings.is_none()
                && self.ws_settings.is_none()
                && self.http_upgrade_settings.is_none()
                && self.grpc_settings.is_none()
                && self.http_settings.is_none()
                && self.xhttp_settings.is_none()
                && self.split_http_settings.is_none(),
            "{owner} sets stream transport options; Aerion local SOCKS listener accepts plain SOCKS over TCP"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayHysteriaSettings {
    #[serde(default)]
    pub version: Option<u8>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub congestion: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_xray_bandwidth")]
    pub up: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_xray_bandwidth")]
    pub down: Option<u64>,
    #[serde(default, rename = "udpHop", alias = "udphop", alias = "udp_hop")]
    pub udp_hop: Option<Value>,
    #[serde(default)]
    pub masquerade: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayFinalMask {
    #[serde(default)]
    pub tcp: Vec<XrayMask>,
    #[serde(default)]
    pub udp: Vec<XrayMask>,
    #[serde(default, rename = "quicParams", alias = "quic_params")]
    pub quic_params: Option<XrayQuicParams>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct XrayMask {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub settings: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayQuicParams {
    #[serde(default)]
    pub congestion: Option<String>,
    #[serde(default)]
    pub debug: bool,
    #[serde(default, rename = "bbrProfile", alias = "bbr_profile")]
    pub bbr_profile: Option<String>,
    #[serde(
        default,
        rename = "brutalUp",
        alias = "brutal_up",
        deserialize_with = "deserialize_optional_xray_bandwidth"
    )]
    pub brutal_up: Option<u64>,
    #[serde(
        default,
        rename = "brutalDown",
        alias = "brutal_down",
        deserialize_with = "deserialize_optional_xray_bandwidth"
    )]
    pub brutal_down: Option<u64>,
    #[serde(default, rename = "udpHop", alias = "udp_hop")]
    pub udp_hop: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayWsSettings {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayHttpUpgradeSettings {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayGrpcSettings {
    #[serde(default, rename = "serviceName", alias = "service_name")]
    pub service_name: Option<String>,
    #[serde(default)]
    pub authority: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayHttpSettings {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<OneOrManyStrings>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayXhttpSettings {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<OneOrManyStrings>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayTlsSettings {
    #[serde(default, rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    #[serde(default, rename = "allowInsecure", alias = "allow_insecure")]
    pub allow_insecure: bool,
    #[serde(
        default,
        rename = "verifyPeerCertByName",
        alias = "verify_peer_cert_by_name"
    )]
    pub verify_peer_cert_by_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_fingerprint",
        alias = "clientFingerprint",
        alias = "client_fingerprint"
    )]
    pub fingerprint: Option<UtlsFingerprint>,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default, rename = "disableSystemRoot", alias = "disable_system_root")]
    pub disable_system_root: bool,
    #[serde(
        default,
        rename = "pinnedPeerCertSha256",
        alias = "pinned_peer_cert_sha256",
        alias = "pinnedPeerCertificateChainSha256"
    )]
    pub pinned_peer_cert_sha256: Option<String>,
    #[serde(default, rename = "rejectUnknownSni", alias = "reject_unknown_sni")]
    pub reject_unknown_sni: bool,
    #[serde(default, rename = "minVersion", alias = "min_version")]
    pub min_version: Option<String>,
    #[serde(default, rename = "maxVersion", alias = "max_version")]
    pub max_version: Option<String>,
    #[serde(default, rename = "cipherSuites", alias = "cipher_suites")]
    pub cipher_suites: Option<String>,
    #[serde(
        default,
        rename = "enableSessionResumption",
        alias = "enable_session_resumption"
    )]
    pub enable_session_resumption: bool,
    #[serde(default, rename = "curvePreferences", alias = "curve_preferences")]
    pub curve_preferences: Option<Value>,
    #[serde(default, rename = "masterKeyLog", alias = "master_key_log")]
    pub master_key_log: Option<String>,
    #[serde(default, rename = "echServerKeys", alias = "ech_server_keys")]
    pub ech_server_keys: Option<String>,
    #[serde(default, rename = "echConfigList", alias = "ech_config_list")]
    pub ech_config_list: Option<String>,
    #[serde(default, rename = "echSockopt", alias = "ech_sockopt")]
    pub ech_sockopt: Option<Value>,
    #[serde(default)]
    pub certificates: Vec<XrayCertificate>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayCertificate {
    #[serde(default)]
    pub usage: Option<String>,
    #[serde(default)]
    pub certificate: Vec<String>,
    #[serde(default)]
    pub key: Vec<String>,
    #[serde(default, rename = "certificateFile", alias = "certificate_file")]
    pub certificate_file: Option<PathBuf>,
    #[serde(default, rename = "keyFile", alias = "key_file")]
    pub key_file: Option<PathBuf>,
    #[serde(default, rename = "ocspStapling", alias = "ocsp_stapling")]
    pub ocsp_stapling: Option<Value>,
    #[serde(default, rename = "oneTimeLoading", alias = "one_time_loading")]
    pub one_time_loading: bool,
    #[serde(default, rename = "buildChain", alias = "build_chain")]
    pub build_chain: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl XrayTlsSettings {
    fn reject_unsupported_fields(&self, owner: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "{owner} tlsSettings has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        for (field, value, reason) in [
            (
                "verifyPeerCertByName",
                &self.verify_peer_cert_by_name,
                "separate certificate name verification",
            ),
            ("minVersion", &self.min_version, "TLS version policy"),
            ("maxVersion", &self.max_version, "TLS version policy"),
            (
                "cipherSuites",
                &self.cipher_suites,
                "TLS cipher suite policy",
            ),
            ("masterKeyLog", &self.master_key_log, "TLS key log output"),
            ("echConfigList", &self.ech_config_list, "ECH client support"),
        ] {
            ensure!(
                !option_text_has_data(value),
                "{owner} tlsSettings {field} requires {reason}"
            );
        }
        for (field, value, reason) in [
            (
                "rejectUnknownSni",
                self.reject_unknown_sni,
                "SNI-based server rejection",
            ),
            (
                "enableSessionResumption",
                self.enable_session_resumption,
                "TLS session resumption policy",
            ),
        ] {
            ensure!(!value, "{owner} tlsSettings {field} requires {reason}");
        }
        for (field, value, reason) in [
            (
                "curvePreferences",
                &self.curve_preferences,
                "TLS curve preference policy",
            ),
            (
                "echSockopt",
                &self.ech_sockopt,
                "ECH socket option plumbing",
            ),
        ] {
            ensure!(
                !value.as_ref().map(value_has_data).unwrap_or(false),
                "{owner} tlsSettings {field} requires {reason}"
            );
        }
        for (index, certificate) in self.certificates.iter().enumerate() {
            certificate.reject_unsupported_fields(owner, index)?;
        }
        Ok(())
    }
}

impl XrayCertificate {
    fn reject_unsupported_fields(&self, owner: &str, index: usize) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "{owner} tlsSettings.certificates[{index}] has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        for (field, value, reason) in [
            (
                "ocspStapling",
                self.ocsp_stapling
                    .as_ref()
                    .map(value_has_data)
                    .unwrap_or(false),
                "OCSP stapling",
            ),
            (
                "oneTimeLoading",
                self.one_time_loading,
                "certificate one-time loading policy",
            ),
            ("buildChain", self.build_chain, "certificate chain building"),
        ] {
            ensure!(
                !value,
                "{owner} tlsSettings.certificates[{index}] {field} requires {reason}"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayRealitySettings {
    #[serde(default)]
    pub dest: Option<String>,
    #[serde(default, rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    #[serde(default, rename = "serverNames", alias = "server_names")]
    pub server_names: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_fingerprint",
        alias = "clientFingerprint",
        alias = "client_fingerprint"
    )]
    pub fingerprint: Option<UtlsFingerprint>,
    #[serde(
        default,
        rename = "publicKey",
        alias = "public_key",
        alias = "password"
    )]
    pub public_key: Option<String>,
    #[serde(default, rename = "privateKey", alias = "private_key")]
    pub private_key: Option<String>,
    #[serde(default, rename = "shortId", alias = "short_id")]
    pub short_id: Option<String>,
    #[serde(default, rename = "shortIds", alias = "short_ids")]
    pub short_ids: Vec<String>,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayMuxOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl XrayHysteriaSettings {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(
            &format!("{owner} streamSettings.hysteriaSettings"),
            &self.extra,
        )
    }
}

impl XrayFinalMask {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("{owner} streamSettings.finalmask"), &self.extra)?;
        for (index, mask) in self.tcp.iter().enumerate() {
            mask.reject_unsupported_extra_fields(&format!(
                "{owner} streamSettings.finalmask.tcp[{index}]"
            ))?;
        }
        for (index, mask) in self.udp.iter().enumerate() {
            mask.reject_unsupported_extra_fields(&format!(
                "{owner} streamSettings.finalmask.udp[{index}]"
            ))?;
        }
        if let Some(quic_params) = &self.quic_params {
            quic_params.reject_unsupported_extra_fields(owner)?;
        }
        Ok(())
    }
}

impl XrayMask {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(owner, &self.extra)?;
        if let Some(Value::Object(settings)) = &self.settings {
            let unsupported = settings
                .keys()
                .filter(|key| key.as_str() != "password")
                .collect::<Vec<_>>();
            ensure!(
                unsupported.is_empty(),
                "{owner} settings has unsupported fields {:?}",
                unsupported
            );
        }
        Ok(())
    }
}

impl XrayQuicParams {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(
            &format!("{owner} streamSettings.finalmask.quicParams"),
            &self.extra,
        )
    }
}

impl XrayWsSettings {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("{owner} streamSettings.wsSettings"), &self.extra)
    }
}

impl XrayHttpUpgradeSettings {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(
            &format!("{owner} streamSettings.httpUpgradeSettings"),
            &self.extra,
        )
    }
}

impl XrayGrpcSettings {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("{owner} streamSettings.grpcSettings"), &self.extra)
    }
}

impl XrayHttpSettings {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("{owner} streamSettings.httpSettings"), &self.extra)
    }
}

impl XrayXhttpSettings {
    fn reject_unsupported_extra_fields(&self, owner: &str, field: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("{owner} streamSettings.{field}"), &self.extra)
    }
}

impl XrayRealitySettings {
    fn reject_unsupported_extra_fields(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(
            &format!("{owner} streamSettings.realitySettings"),
            &self.extra,
        )
    }
}

#[derive(Clone, Debug)]
pub enum XrayClientConfig {
    AnyTls(ClientConfig),
    Route(RouteClientConfig),
    HttpProxy(HttpProxyClientConfig),
    Shadowsocks(ShadowsocksClientConfig),
    SocksProxy(SocksProxyClientConfig),
    Mieru(MieruClientConfig),
    Vless(VlessClientConfig),
    Vmess(VmessClientConfig),
    Trojan(TrojanClientConfig),
    Hysteria2(Hysteria2ClientConfig),
}

pub enum XrayServerConfig {
    AnyTls(ServerConfig),
    Shadowsocks(ShadowsocksServerConfig),
    Hysteria2(Hysteria2ServerConfig),
    Mieru(MieruServerConfig),
    Trojan(TrojanServerConfig),
    Vless(VlessServerConfig),
    Vmess(VmessServerConfig),
}

struct XrayServerUser {
    address: String,
    port: u16,
    user: XrayUser,
}

impl XrayConfig {
    pub fn reject_unsupported_top_level_fields(&self) -> Result<()> {
        ensure_no_extra_fields("xray config", &self.extra)
    }

    pub fn outbound(&self, tag: &str) -> Option<&XrayOutbound> {
        self.outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
    }

    pub fn local_socks_listen(&self) -> Result<Option<SocketAddr>> {
        self.reject_unsupported_top_level_fields()?;
        for inbound in &self.inbounds {
            let protocol = inbound.protocol.trim();
            ensure!(
                protocol.eq_ignore_ascii_case("socks") || protocol.eq_ignore_ascii_case("tun"),
                "xray inbound {} protocol {protocol} is not a local SOCKS/TUN listener; Aerion config runner exposes SOCKS and TUN listeners only",
                inbound.name()
            );
        }
        let Some(inbound) = self
            .inbounds
            .iter()
            .find(|inbound| inbound.protocol.eq_ignore_ascii_case("socks"))
        else {
            return Ok(None);
        };
        let owner = format!("xray SOCKS inbound {}", inbound.name());
        ensure_no_extra_fields(&owner, &inbound.extra)?;
        inbound.settings.reject_local_socks_fields(&owner)?;
        inbound
            .stream_settings
            .reject_local_socks_listener_fields(&owner)?;
        let port = inbound.port.context("xray socks inbound is missing port")?;
        let host = inbound.listen.as_deref().unwrap_or("0.0.0.0");
        Ok(Some(SocketAddr::new(parse_listen_ip("xray", host)?, port)))
    }

    pub fn tun_enabled(&self) -> bool {
        self.inbounds
            .iter()
            .any(|inbound| inbound.protocol.eq_ignore_ascii_case("tun"))
    }

    pub fn tun_config(&self, proxy_listen: SocketAddr) -> Result<Option<TunConfig>> {
        let Some(inbound) = self
            .inbounds
            .iter()
            .find(|inbound| inbound.protocol.eq_ignore_ascii_case("tun"))
        else {
            return Ok(None);
        };
        ensure_no_extra_fields(
            &format!("xray TUN inbound {}", inbound.name()),
            &inbound.extra,
        )?;
        inbound
            .stream_settings
            .reject_local_socks_listener_fields(&format!("xray TUN inbound {}", inbound.name()))?;
        let settings = &inbound.settings;
        ensure!(
            settings.version.is_none()
                && settings.clients.is_empty()
                && settings.vnext.is_empty()
                && settings.servers.is_empty()
                && settings.fallbacks.is_empty()
                && settings.port.is_none()
                && settings.id.is_none()
                && settings.password.is_none()
                && settings.auth.is_none()
                && settings.user.is_none()
                && settings.pass.is_none()
                && settings.headers.is_empty()
                && settings.network.is_none()
                && settings.domain_strategy.is_none()
                && settings.redirect.is_none()
                && settings.user_level.is_none()
                && settings.response.is_none()
                && settings.flow.is_none()
                && settings.packet_encoding.is_none()
                && settings.security.is_none()
                && settings.method.is_none()
                && settings.decryption.is_none()
                && settings.alter_id.is_none(),
            "xray TUN inbound {} sets proxy protocol settings; TUN only accepts interface settings",
            inbound.name()
        );
        let mut config = TunConfig::new(socks_proxy_url(proxy_listen));
        if let Some(name) = xray_extra_string(&settings.extra, "interfaceName")
            .or_else(|| xray_extra_string(&settings.extra, "interface_name"))
            .or_else(|| xray_extra_string(&settings.extra, "device"))
        {
            config.tun_name = Some(name);
        }
        if let Some(mtu) = xray_extra_u16(&settings.extra, "mtu") {
            config.mtu = mtu;
        }
        if let Some(auto_route) = xray_extra_bool(&settings.extra, "autoRoute")
            .or_else(|| xray_extra_bool(&settings.extra, "auto_route"))
        {
            config.setup = auto_route;
        }
        config.bypass = xray_route_value_strings(
            settings
                .extra
                .get("routeExcludeAddress")
                .or_else(|| settings.extra.get("route_exclude_address")),
        )?;
        let allowed = [
            "interfaceName",
            "interface_name",
            "device",
            "mtu",
            "autoRoute",
            "auto_route",
            "routeExcludeAddress",
            "route_exclude_address",
            "address",
            "addresses",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        if settings
            .address
            .as_deref()
            .map(|address| address.contains(':'))
            .unwrap_or(false)
        {
            config.ipv6 = true;
        }
        for value in xray_route_value_strings(settings.extra.get("address"))? {
            if value.contains(':') {
                config.ipv6 = true;
            }
        }
        for value in xray_route_value_strings(settings.extra.get("addresses"))? {
            if value.contains(':') {
                config.ipv6 = true;
            }
        }
        let unsupported = settings
            .extra
            .keys()
            .filter(|key| !allowed.contains(key.as_str()))
            .collect::<Vec<_>>();
        ensure!(
            unsupported.is_empty(),
            "xray TUN inbound {} settings has unsupported fields {:?}",
            inbound.name(),
            unsupported
        );
        Ok(Some(config))
    }

    pub fn route_table(&self) -> Result<RouteTable> {
        self.reject_unsupported_top_level_fields()?;
        self.routing.to_route_table(&self.outbounds)
    }
}


mod inbound;
mod outbound;
mod route;

fn ensure_tcp_network(format: &str, name: &str, network: &str) -> Result<()> {
    let network = network.trim();
    if network.is_empty()
        || network.eq_ignore_ascii_case("tcp")
        || network.eq_ignore_ascii_case("raw")
    {
        return Ok(());
    }
    bail!(
        "{format} outbound {name} uses network {network}; Aerion currently wires raw TCP transport only"
    )
}

fn xray_mux_enabled(owner: &str, mux: Option<&XrayMuxOptions>) -> Result<bool> {
    let Some(mux) = mux else {
        return Ok(false);
    };
    ensure_no_extra_fields(&format!("{owner} mux"), &mux.extra)?;
    Ok(mux.enabled)
}

fn ensure_xray_mux_disabled(owner: &str, mux: Option<&XrayMuxOptions>, reason: &str) -> Result<()> {
    ensure!(
        !xray_mux_enabled(owner, mux)?,
        "{owner} enables mux; {reason}"
    );
    Ok(())
}

fn ensure_empty_route_settings(
    settings: &XrayOutboundSettings,
    protocol: &str,
    name: &str,
) -> Result<()> {
    let mut fields = Vec::new();
    if settings.version.is_some() {
        fields.push("version");
    }
    if option_text_has_data(&settings.address) {
        fields.push("address");
    }
    if settings.port.is_some() {
        fields.push("port");
    }
    if option_text_has_data(&settings.id) {
        fields.push("id");
    }
    if option_text_has_data(&settings.password) {
        fields.push("password");
    }
    if option_text_has_data(&settings.auth) {
        fields.push("auth");
    }
    if option_text_has_data(&settings.user) {
        fields.push("user");
    }
    if option_text_has_data(&settings.pass) {
        fields.push("pass");
    }
    if !settings.headers.is_empty() {
        fields.push("headers");
    }
    if option_text_has_data(&settings.network) {
        fields.push("network");
    }
    if option_text_has_data(&settings.domain_strategy) {
        fields.push("domainStrategy");
    }
    if option_text_has_data(&settings.redirect) {
        fields.push("redirect");
    }
    if settings
        .user_level
        .as_ref()
        .map(value_has_data)
        .unwrap_or(false)
    {
        fields.push("userLevel");
    }
    if settings
        .response
        .as_ref()
        .map(value_has_data)
        .unwrap_or(false)
    {
        fields.push("response");
    }
    if option_text_has_data(&settings.flow) {
        fields.push("flow");
    }
    if option_text_has_data(&settings.packet_encoding) {
        fields.push("packetEncoding");
    }
    if option_text_has_data(&settings.security) {
        fields.push("security");
    }
    if option_text_has_data(&settings.method) {
        fields.push("method");
    }
    if option_text_has_data(&settings.decryption) {
        fields.push("decryption");
    }
    if settings.alter_id.is_some() {
        fields.push("alterId");
    }
    if !settings.clients.is_empty() {
        fields.push("clients");
    }
    if !settings.fallbacks.is_empty() {
        fields.push("fallbacks");
    }
    if !settings.vnext.is_empty() {
        fields.push("vnext");
    }
    if !settings.servers.is_empty() {
        fields.push("servers");
    }
    ensure!(
        fields.is_empty(),
        "xray {protocol} outbound {name} sets unsupported route settings fields {:?}",
        fields
    );
    Ok(())
}

fn option_text_has_data(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn value_is_empty_object(value: &Value) -> bool {
    matches!(value, Value::Object(object) if object.is_empty())
}

fn xray_tcp_udp_network(network: Option<&str>) -> Result<(bool, bool)> {
    match network
        .unwrap_or("tcp")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "tcp" => Ok((true, false)),
        "udp" => Ok((false, true)),
        "tcp,udp" | "tcp+udp" | "both" => Ok((true, true)),
        other => bail!("xray Shadowsocks inbound uses network {other}; Aerion supports tcp or udp"),
    }
}

fn xray_tcp_udp_outbound_network(network: Option<&str>) -> Result<(bool, bool)> {
    match network
        .unwrap_or("tcp,udp")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "tcp,udp" | "tcp+udp" | "both" => Ok((true, true)),
        "tcp" => Ok((true, false)),
        "udp" => Ok((false, true)),
        other => bail!("xray SOCKS outbound uses network {other}; Aerion supports tcp or udp"),
    }
}

fn ensure_tls_or_reality(format: &str, name: &str, security: &str) -> Result<()> {
    let security = security.trim();
    ensure!(
        security.eq_ignore_ascii_case("tls") || security.eq_ignore_ascii_case("reality"),
        "{format} outbound {name} uses stream security {security}; Aerion requires TLS/REALITY for this protocol"
    );
    Ok(())
}

fn ensure_raw_or_tls_stream_security(format: &str, name: &str, security: &str) -> Result<()> {
    let security = security.trim();
    ensure!(
        security.is_empty()
            || security.eq_ignore_ascii_case("none")
            || security.eq_ignore_ascii_case("tls"),
        "{format} outbound {name} uses stream security {security}; Aerion VMess supports raw TCP or TLS"
    );
    Ok(())
}

fn ensure_no_alpn(format: &str, name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn
        .map(OneOrManyStrings::to_vec)
        .unwrap_or_default()
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
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
        let values = alpn
            .map(OneOrManyStrings::to_vec)
            .unwrap_or_default()
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect::<Vec<_>>();
        ensure!(
            values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("h2")),
            "{format} VLESS outbound {name} sets ALPN {:?}; {:?} transport requires h2",
            values,
            transport.kind
        );
        return Ok(());
    }
    if matches!(transport.kind, VlessTransportKind::Xhttp) {
        let values = alpn
            .map(OneOrManyStrings::to_vec)
            .unwrap_or_default()
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect::<Vec<_>>();
        ensure!(
            values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("http/1.1")),
            "{format} VLESS outbound {name} sets ALPN {:?}; XHTTP stream-one transport requires http/1.1",
            values
        );
        return Ok(());
    }
    ensure_no_alpn(format, name, alpn)
}

fn ensure_hysteria_alpn(format: &str, name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn
        .map(OneOrManyStrings::to_vec)
        .unwrap_or_default()
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    ensure!(
        values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("h3")),
        "{format} Hysteria outbound {name} sets ALPN {:?}; Aerion Hysteria2 uses h3",
        values
    );
    Ok(())
}

fn ensure_http_alpn(format: &str, name: &str, alpn: Option<&OneOrManyStrings>) -> Result<()> {
    let values = alpn
        .map(OneOrManyStrings::to_vec)
        .unwrap_or_default()
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>();
    ensure!(
        values.is_empty() || (values.len() == 1 && values[0].eq_ignore_ascii_case("http/1.1")),
        "{format} HTTP outbound {name} sets ALPN {:?}; Aerion HTTP proxy outbound uses HTTP/1.1 CONNECT",
        values
    );
    Ok(())
}

fn xray_raw_settings_has_unsupported_data(value: &Value) -> bool {
    let Value::Object(settings) = value else {
        return value_has_data(value);
    };
    for (field, value) in settings {
        match field.as_str() {
            "acceptProxyProtocol" | "accept_proxy_protocol" => {
                if value_has_data(value) {
                    return true;
                }
            }
            "header" => {
                let Value::Object(header) = value else {
                    if value_has_data(value) {
                        return true;
                    }
                    continue;
                };
                for (field, value) in header {
                    match field.as_str() {
                        "type" => {
                            let kind = value.as_str().map(str::trim).unwrap_or_default();
                            if !kind.is_empty()
                                && !kind.eq_ignore_ascii_case("none")
                                && value_has_data(value)
                            {
                                return true;
                            }
                        }
                        _ => {
                            if value_has_data(value) {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {
                if value_has_data(value) {
                    return true;
                }
            }
        }
    }
    false
}

fn xray_tls_ech_server_keys(tls: Option<&XrayTlsSettings>) -> Result<Option<TlsEchServerKeys>> {
    let Some(value) = tls
        .and_then(|settings| settings.ech_server_keys.as_ref())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    Ok(Some(tls_ech_from_compat_reference(value)))
}

fn xray_tls_server_identity(
    certificate: &XrayCertificate,
    protocol: &str,
    name: &str,
) -> Result<(PathBuf, PathBuf, Vec<String>, Option<String>)> {
    let certificates = if certificate.certificate.is_empty() {
        Vec::new()
    } else {
        vec![certificate.certificate.join("\n")]
    };
    let key = if certificate.key.is_empty() {
        None
    } else {
        Some(certificate.key.join("\n"))
    };
    ensure!(
        certificate.certificate_file.is_some() || !certificates.is_empty(),
        "xray {protocol} inbound {name} TLS certificate is missing certificate or certificateFile"
    );
    ensure!(
        certificate.key_file.is_some() || key.is_some(),
        "xray {protocol} inbound {name} TLS certificate is missing key or keyFile"
    );
    Ok((
        certificate.certificate_file.clone().unwrap_or_default(),
        certificate.key_file.clone().unwrap_or_default(),
        certificates,
        key,
    ))
}

fn xray_first_server_certificate<'a>(
    tls: Option<&'a XrayTlsSettings>,
    protocol: &str,
    name: &str,
) -> Result<&'a XrayCertificate> {
    tls.and_then(|tls| {
        tls.certificates.iter().find(|certificate| {
            !certificate
                .usage
                .as_deref()
                .map(|usage| usage.eq_ignore_ascii_case("verify"))
                .unwrap_or(false)
        })
    })
    .with_context(|| format!("xray {protocol} inbound {name} TLS is missing certificates"))
}

fn xray_tls_client_roots(tls: Option<&XrayTlsSettings>) -> Result<(Vec<PathBuf>, Vec<String>)> {
    let Some(tls) = tls else {
        return Ok((Vec::new(), Vec::new()));
    };
    if !tls.disable_system_root {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut paths = Vec::new();
    let mut certificates = Vec::new();
    for certificate in tls.certificates.iter().filter(|certificate| {
        certificate
            .usage
            .as_deref()
            .map(|usage| usage.eq_ignore_ascii_case("verify"))
            .unwrap_or(false)
    }) {
        ensure!(
            certificate.certificate_file.is_some() || !certificate.certificate.is_empty(),
            "xray TLS verify certificate is missing certificate or certificateFile"
        );
        if let Some(path) = &certificate.certificate_file {
            paths.push(path.clone());
        }
        if !certificate.certificate.is_empty() {
            certificates.push(certificate.certificate.join("\n"));
        }
    }
    Ok((paths, certificates))
}

fn xray_disable_system_roots(tls: Option<&XrayTlsSettings>, tls_enabled: bool) -> bool {
    tls_enabled
        && tls
            .map(|settings| settings.disable_system_root)
            .unwrap_or(false)
}

fn xray_pinned_cert_sha256(tls: Option<&XrayTlsSettings>, tls_enabled: bool) -> Vec<String> {
    if !tls_enabled {
        return Vec::new();
    }
    tls.and_then(|settings| settings.pinned_peer_cert_sha256.clone())
        .into_iter()
        .collect()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum XrayBandwidthValue {
    Number(u64),
    Text(String),
}

fn deserialize_optional_xray_bandwidth<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<XrayBandwidthValue>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match value {
        XrayBandwidthValue::Number(0) => Ok(None),
        XrayBandwidthValue::Number(value) => Ok(Some(value)),
        XrayBandwidthValue::Text(value) => {
            let value = value.trim();
            if value.is_empty() {
                return Ok(None);
            }
            let mut split = value.len();
            for (idx, ch) in value.char_indices() {
                if !ch.is_ascii_digit() && ch != '.' {
                    split = idx;
                    break;
                }
            }
            let number = value[..split].parse::<f64>().map_err(de::Error::custom)?;
            let unit = value[split..].trim().to_ascii_lowercase();
            let mbps = match unit.as_str() {
                "" | "m" | "mb" | "mbps" => number,
                "b" | "bps" => number / 1_000_000.0,
                "k" | "kb" | "kbps" => number / 1024.0,
                "g" | "gb" | "gbps" => number * 1024.0,
                "t" | "tb" | "tbps" => number * 1024.0 * 1024.0,
                _ => {
                    return Err(de::Error::custom(format!(
                        "unsupported xray bandwidth unit: {unit}"
                    )));
                }
            };
            if mbps <= 0.0 {
                return Ok(None);
            }
            Ok(Some(mbps.ceil() as u64))
        }
    }
}

fn xray_route_value_strings(value: Option<&Value>) -> Result<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(value)) => Ok(value
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
                    _ => bail!("xray route array value must contain strings or numbers"),
                }
            }
            Ok(result)
        }
        Some(_) => bail!("xray route value must be a string, number, or array"),
    }
}

fn xray_extra_string(extra: &Map<String, Value>, key: &str) -> Option<String> {
    extra
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn xray_extra_u16(extra: &Map<String, Value>, key: &str) -> Option<u16> {
    extra
        .get(key)
        .and_then(|value| value.as_u64().and_then(|value| u16::try_from(value).ok()))
}

fn xray_extra_bool(extra: &Map<String, Value>, key: &str) -> Option<bool> {
    extra.get(key).and_then(Value::as_bool)
}

fn sni_or_server(value: Option<&str>, server: &str, name: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| if server.is_empty() { name } else { server })
        .to_string()
}

fn xray_reality_server_config(
    name: &str,
    settings: &XrayRealitySettings,
    transport: &VlessTransportConfig,
) -> Result<RealityServerConfig> {
    let dest = settings
        .dest
        .as_deref()
        .with_context(|| format!("xray REALITY inbound {name} is missing realitySettings.dest"))?;
    let (server_name, server_port) =
        parse_host_port(dest).with_context(|| format!("parse xray REALITY inbound {name} dest"))?;
    let private_key = settings.private_key.as_deref().with_context(|| {
        format!("xray REALITY inbound {name} is missing realitySettings.privateKey")
    })?;
    let mut short_ids = settings.short_ids.clone();
    if short_ids.is_empty() {
        if let Some(short_id) = &settings.short_id {
            short_ids.push(short_id.clone());
        }
    }
    let alpn_protocols = settings
        .alpn
        .as_ref()
        .map(|alpn| {
            alpn.to_vec()
                .into_iter()
                .map(String::into_bytes)
                .collect::<Vec<_>>()
        })
        .filter(|alpn| !alpn.is_empty())
        .unwrap_or_else(|| transport.alpn_protocols());
    RealityServerConfig::from_strings(
        server_name,
        server_port,
        settings.server_names.clone(),
        private_key,
        &short_ids,
        alpn_protocols,
    )
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .with_context(|| format!("address must be host:port: {value}"))?;
    let port = port
        .parse::<u16>()
        .with_context(|| format!("parse port in {value}"))?;
    Ok((host.trim_matches(&['[', ']'][..]).to_string(), port))
}

fn default_tcp_network() -> String {
    "tcp".to_string()
}

#[cfg(test)]
mod tests;
