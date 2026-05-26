use crate::config_compat::mihomo::OneOrManyStrings;
use crate::http_connect::HttpProxyClientConfig;
use crate::hysteria2::{Hysteria2ClientConfig, Hysteria2ServerConfig};
use crate::reality::{RealityClientConfig, RealityServerConfig};
use crate::router::RouteClientConfig;
use crate::routing::{
    DomainMatcher, IpCidr, PortRange, RouteDecision, RouteNetwork, RouteRule, RouteTable,
};
use crate::shadowsocks::{ShadowsocksClientConfig, ShadowsocksServerConfig};
use crate::socks::SocksProxyClientConfig;
use crate::trojan::{TrojanClientConfig, TrojanServerConfig};
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::{VlessClientConfig, VlessServerConfig};
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::{VmessClientConfig, VmessServerConfig, ensure_vmess_packet_encoding};
use anyhow::{Context, Result, bail, ensure};
use serde::de;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

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
            ("echServerKeys", &self.ech_server_keys, "ECH server support"),
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
    Route(RouteClientConfig),
    HttpProxy(HttpProxyClientConfig),
    Shadowsocks(ShadowsocksClientConfig),
    SocksProxy(SocksProxyClientConfig),
    Vless(VlessClientConfig),
    Vmess(VmessClientConfig),
    Trojan(TrojanClientConfig),
    Hysteria2(Hysteria2ClientConfig),
}

pub enum XrayServerConfig {
    Shadowsocks(ShadowsocksServerConfig),
    Hysteria2(Hysteria2ServerConfig),
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
                protocol.eq_ignore_ascii_case("socks"),
                "xray inbound {} protocol {protocol} is not a local SOCKS listener; Aerion config runner exposes a SOCKS listener only",
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

    pub fn route_table(&self) -> Result<RouteTable> {
        self.reject_unsupported_top_level_fields()?;
        self.routing.to_route_table(&self.outbounds)
    }
}

impl XrayRoutingConfig {
    pub fn to_route_table(&self, outbounds: &[XrayOutbound]) -> Result<RouteTable> {
        ensure!(
            self.extra.is_empty(),
            "xray routing has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        if let Some(matcher) = self.domain_matcher.as_deref().map(str::trim) {
            ensure!(
                matcher.is_empty()
                    || matcher.eq_ignore_ascii_case("linear")
                    || matcher.eq_ignore_ascii_case("hybrid")
                    || matcher.eq_ignore_ascii_case("mph"),
                "unsupported xray routing.domainMatcher {matcher}"
            );
        }
        if let Some(strategy) = self.domain_strategy.as_deref().map(str::trim) {
            ensure!(
                strategy.is_empty() || strategy.eq_ignore_ascii_case("AsIs"),
                "xray routing.domainStrategy {strategy} requires DNS resolution during routing"
            );
        }
        let mut table = RouteTable {
            default: xray_default_route_decision(outbounds)?,
            ..RouteTable::default()
        };
        for (index, rule) in self.rules.iter().enumerate() {
            table
                .rules
                .push(rule.to_route_rule(index, &self.balancers, outbounds)?);
        }
        Ok(table)
    }
}

impl XrayRoutingRule {
    fn to_route_rule(
        &self,
        index: usize,
        balancers: &[XrayBalancer],
        outbounds: &[XrayOutbound],
    ) -> Result<RouteRule> {
        ensure!(
            self.extra.is_empty(),
            "xray routing.rules[{index}] has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        self.reject_unsupported_match_metadata(index)?;
        if let Some(rule_tag) = &self.rule_tag {
            ensure!(
                rule_tag.as_str().is_some(),
                "xray routing.rules[{index}] ruleTag must be a string"
            );
        }
        ensure!(
            self.kind.trim().is_empty() || self.kind.eq_ignore_ascii_case("field"),
            "unsupported xray routing.rules[{index}] type {}",
            self.kind
        );
        let action = if !self.outbound_tag.trim().is_empty() {
            RouteDecision::from_outbound(&self.outbound_tag)?
        } else if !self.balancer_tag.trim().is_empty() {
            let balancer = balancers
                .iter()
                .find(|balancer| balancer.tag == self.balancer_tag)
                .with_context(|| {
                    format!(
                        "xray routing.rules[{index}] balancerTag {} was not found",
                        self.balancer_tag
                    )
                })?;
            RouteDecision::Proxy(balancer.static_target(outbounds)?)
        } else {
            bail!("xray routing.rules[{index}] is missing outboundTag or balancerTag");
        };
        let mut rule = RouteRule::new(action);
        for domain in &self.domain {
            if let Some(name) = DomainMatcher::geosite_name(domain) {
                bail!("xray routing.rules[{index}] geosite {name} requires geosite rule-set data");
            } else if let Some(matcher) = DomainMatcher::xray(domain)? {
                rule.domains.push(matcher);
            }
        }
        for ip in &self.ip {
            let ip = ip.trim();
            if let Some(value) = ip.strip_prefix('!') {
                ensure!(
                    !value.trim().is_empty(),
                    "xray routing.rules[{index}] inverse IP matcher is empty"
                );
                bail!(
                    "xray routing.rules[{index}] inverse IP matcher {value} requires negative route matching"
                );
            } else if ip
                .get(..4)
                .map(|prefix| prefix.eq_ignore_ascii_case("ext:"))
                .unwrap_or(false)
            {
                bail!(
                    "xray routing.rules[{index}] external IP matcher {ip} requires geoip rule-set data"
                );
            } else if ip.eq_ignore_ascii_case("geoip:private") {
                rule.ip_is_private = true;
            } else if let Some(name) = IpCidr::geoip_name(ip) {
                bail!("xray routing.rules[{index}] geoip {name} requires geoip rule-set data");
            } else {
                rule.ip_cidrs.push(IpCidr::parse(ip)?);
            }
        }
        if let Some(network) = &self.network {
            for value in network
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                rule.networks.push(RouteNetwork::parse(value)?);
            }
        }
        for value in xray_route_value_strings(self.port.as_ref())? {
            rule.ports.push(PortRange::parse(&value)?);
        }
        Ok(rule)
    }

    fn reject_unsupported_match_metadata(&self, index: usize) -> Result<()> {
        for (field, value, reason) in [
            (
                "sourcePort",
                &self.source_port,
                "source port matching metadata",
            ),
            ("localPort", &self.local_port, "local inbound port metadata"),
            (
                "sourceIP/source",
                &self.source_ip,
                "source IP matching metadata",
            ),
            ("localIP", &self.local_ip, "local inbound IP metadata"),
            ("user", &self.user, "authenticated inbound user metadata"),
            (
                "vlessRoute",
                &self.vless_route,
                "VLESS inbound route metadata",
            ),
            ("inboundTag", &self.inbound_tag, "inbound tag metadata"),
            ("protocol", &self.protocol, "sniffed protocol metadata"),
            ("attrs", &self.attrs, "sniffed HTTP attribute metadata"),
            ("process", &self.process, "process metadata"),
            ("webhook", &self.webhook, "route-hit webhook side effects"),
        ] {
            ensure!(
                value.is_none(),
                "xray routing.rules[{index}] {field} requires {reason}"
            );
        }
        Ok(())
    }
}

fn xray_default_route_decision(outbounds: &[XrayOutbound]) -> Result<RouteDecision> {
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
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(RouteDecision::Direct),
        "blackhole" => Ok(RouteDecision::Block),
        protocol => bail!(
            "xray routing default uses first outbound protocol {protocol} without tag; Aerion route proxy requires a tag"
        ),
    }
}

impl XrayBalancer {
    fn static_target(&self, outbounds: &[XrayOutbound]) -> Result<String> {
        ensure!(
            self.extra.is_empty(),
            "xray routing.balancers {} has unsupported fields {:?}",
            self.tag,
            self.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            self.fallback_tag.trim().is_empty(),
            "xray routing.balancers {} fallbackTag requires active observatory state",
            self.tag
        );
        ensure!(
            self.strategy
                .as_ref()
                .map(value_is_empty_object)
                .unwrap_or(true),
            "xray routing.balancers {} strategy requires active load balancing policy",
            self.tag
        );
        let selectors = self
            .selector
            .iter()
            .map(|selector| selector.trim())
            .filter(|selector| !selector.is_empty())
            .collect::<Vec<_>>();
        ensure!(
            !selectors.is_empty(),
            "xray routing.balancers {} has no selector",
            self.tag
        );
        let mut matches = Vec::new();
        for outbound in outbounds {
            let tag = outbound.tag.as_deref().unwrap_or_default();
            if !tag.is_empty()
                && selectors.iter().any(|selector| tag.starts_with(selector))
                && !matches.iter().any(|matched| matched == tag)
            {
                matches.push(tag.to_string());
            }
        }
        ensure!(
            matches.len() == 1,
            "xray routing.balancers {} matches {} outbounds [{}]; Aerion only supports statically equivalent single-outbound balancers",
            self.tag,
            matches.len(),
            matches.join(", ")
        );
        Ok(matches.remove(0))
    }
}

impl XrayInbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.protocol)
    }

    pub fn to_server_config(&self) -> Result<XrayServerConfig> {
        let owner = format!("xray {} inbound {}", self.protocol, self.name());
        ensure_no_extra_fields(&owner, &self.extra)?;
        self.settings.reject_unsupported_extra_fields(&owner)?;
        self.stream_settings.reject_unsupported_fields(&owner)?;
        match self.protocol.trim().to_ascii_lowercase().as_str() {
            "shadowsocks" | "ss" => Ok(XrayServerConfig::Shadowsocks(
                self.to_shadowsocks_server_config()
                    .with_context(|| format!("convert xray Shadowsocks inbound {}", self.name()))?,
            )),
            "hysteria" | "hysteria2" | "hy2" => Ok(XrayServerConfig::Hysteria2(
                self.to_hysteria2_server_config()
                    .with_context(|| format!("convert xray Hysteria2 inbound {}", self.name()))?,
            )),
            "trojan" => Ok(XrayServerConfig::Trojan(
                self.to_trojan_server_config()
                    .with_context(|| format!("convert xray Trojan inbound {}", self.name()))?,
            )),
            "vless" => Ok(XrayServerConfig::Vless(
                self.to_vless_server_config()
                    .with_context(|| format!("convert xray VLESS inbound {}", self.name()))?,
            )),
            "vmess" => Ok(XrayServerConfig::Vmess(
                self.to_vmess_server_config()
                    .with_context(|| format!("convert xray VMess inbound {}", self.name()))?,
            )),
            other => bail!(
                "unsupported xray inbound {} protocol {}; Aerion cannot run this inbound protocol as a server",
                self.name(),
                other
            ),
        }
    }

    fn to_shadowsocks_server_config(&self) -> Result<ShadowsocksServerConfig> {
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray Shadowsocks inbound {} uses stream security {}; Aerion Shadowsocks expects raw Shadowsocks transport",
            self.name(),
            stream_security
        );
        let primary = self.settings.clients.first();
        let method = primary
            .and_then(|user| user.method.clone().or(user.security.clone()))
            .or(self.settings.method.clone())
            .or(self.settings.security.clone())
            .with_context(|| {
                format!("xray Shadowsocks inbound {} is missing method", self.name())
            })?;
        let password = primary
            .and_then(|user| user.password.clone())
            .or(self.settings.password.clone())
            .with_context(|| {
                format!(
                    "xray Shadowsocks inbound {} is missing password",
                    self.name()
                )
            })?;
        let (tcp, udp) = xray_tcp_udp_network(self.settings.network.as_deref())?;
        Ok(ShadowsocksServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray Shadowsocks inbound {} is missing port", self.name())
                })?,
            ),
            method: method.clone(),
            password,
            users: self
                .settings
                .clients
                .iter()
                .skip(1)
                .map(|user| {
                    let user_method = user
                        .method
                        .as_deref()
                        .or(user.security.as_deref())
                        .unwrap_or_default();
                    ensure!(
                        user_method.trim().is_empty() || user_method.eq_ignore_ascii_case(&method),
                        "xray Shadowsocks inbound {} extra client uses method {}; Aerion Shadowsocks server expects one method per inbound",
                        self.name(),
                        user_method
                    );
                    user.password.clone().with_context(|| {
                        format!(
                            "xray Shadowsocks inbound {} extra client is missing password",
                            self.name()
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            tcp,
            udp,
            udp_over_tcp: false,
        })
    }

    fn to_hysteria2_server_config(&self) -> Result<Hysteria2ServerConfig> {
        let hysteria = self.stream_settings.hysteria_settings.as_ref();
        let version = self
            .settings
            .version
            .or_else(|| hysteria.and_then(|settings| settings.version));
        ensure!(
            !self.protocol.eq_ignore_ascii_case("hysteria") || version == Some(2),
            "xray Hysteria inbound {} uses version {:?}; Aerion supports Hysteria2 version 2",
            self.name(),
            version
        );
        if let Some(version) = version {
            ensure!(
                version == 2,
                "xray Hysteria inbound {} uses version {}; Aerion supports Hysteria2 version 2",
                self.name(),
                version
            );
        }
        let network = self.stream_settings.network.trim();
        ensure!(
            network.eq_ignore_ascii_case("hysteria"),
            "xray Hysteria inbound {} uses network {}; Aerion Hysteria2 expects hysteria transport",
            self.name(),
            network
        );
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty()
                || stream_security.eq_ignore_ascii_case("none")
                || stream_security.eq_ignore_ascii_case("tls"),
            "xray Hysteria inbound {} uses stream security {}; Aerion Hysteria2 expects TLS-backed hysteria transport",
            self.name(),
            stream_security
        );
        ensure!(
            !hysteria
                .and_then(|settings| settings.udp_hop.as_ref())
                .map(value_has_data)
                .unwrap_or(false),
            "xray Hysteria inbound {} enables UDP port hopping; Aerion Hysteria2 server expects one fixed port",
            self.name()
        );
        ensure!(
            !hysteria
                .and_then(|settings| settings.masquerade.as_ref())
                .map(value_has_data)
                .unwrap_or(false),
            "xray Hysteria inbound {} sets masquerade; Aerion Hysteria2 server does not expose HTTP masquerade",
            self.name()
        );
        let tls = self.stream_settings.tls_settings.as_ref();
        ensure_hysteria_alpn(
            "xray",
            self.name(),
            tls.and_then(|settings| settings.alpn.as_ref()),
        )?;
        let certificate = xray_first_server_certificate(tls, "Hysteria", self.name())?;
        let finalmask = self.stream_settings.finalmask.as_ref();
        if let Some(finalmask) = finalmask {
            ensure!(
                finalmask.tcp.is_empty(),
                "xray Hysteria inbound {} sets finalmask TCP masks; Aerion Hysteria2 only maps salamander UDP obfs",
                self.name()
            );
            ensure!(
                finalmask.udp.len() <= 1,
                "xray Hysteria inbound {} sets multiple finalmask UDP masks; Aerion Hysteria2 exposes one obfs layer",
                self.name()
            );
            ensure!(
                !finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.udp_hop.as_ref())
                    .map(value_has_data)
                    .unwrap_or(false),
                "xray Hysteria inbound {} enables finalmask UDP port hopping; Aerion Hysteria2 server expects one fixed port",
                self.name()
            );
            ensure!(
                finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.bbr_profile.as_deref())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
                "xray Hysteria inbound {} sets finalmask bbrProfile {:?}; Aerion Hysteria2 uses the default BBR profile",
                self.name(),
                finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.bbr_profile.as_ref())
            );
            ensure!(
                !finalmask
                    .quic_params
                    .as_ref()
                    .map(|params| params.debug)
                    .unwrap_or(false),
                "xray Hysteria inbound {} enables finalmask quicParams debug; Aerion Hysteria2 server does not expose QUIC debug toggles",
                self.name()
            );
        }
        let (obfs, obfs_password) = match finalmask.and_then(|finalmask| finalmask.udp.first()) {
            Some(mask) => {
                ensure!(
                    mask.kind.eq_ignore_ascii_case("salamander"),
                    "xray Hysteria inbound {} uses finalmask UDP mask {}; Aerion supports salamander",
                    self.name(),
                    mask.kind
                );
                let password = mask
                    .settings
                    .as_ref()
                    .and_then(|settings| settings.get("password"))
                    .and_then(Value::as_str)
                    .with_context(|| {
                        format!(
                            "xray Hysteria inbound {} salamander mask is missing password",
                            self.name()
                        )
                    })?
                    .to_string();
                (Some("salamander".to_string()), Some(password))
            }
            None => (None, None),
        };
        let congestion_control = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.congestion.clone())
            .or_else(|| hysteria.and_then(|settings| settings.congestion.clone()))
            .unwrap_or_else(|| "bbr".to_string());
        ensure!(
            congestion_control.trim().is_empty()
                || congestion_control.eq_ignore_ascii_case("bbr")
                || congestion_control.eq_ignore_ascii_case("reno"),
            "xray Hysteria inbound {} uses congestion {}; Aerion Hysteria2 supports bbr or reno",
            self.name(),
            congestion_control
        );
        let password = self
            .settings
            .clients
            .first()
            .and_then(|user| user.auth.clone().or(user.password.clone()))
            .or_else(|| hysteria.and_then(|settings| settings.auth.clone()))
            .or(self.settings.auth.clone())
            .or(self.settings.password.clone())
            .with_context(|| format!("xray Hysteria inbound {} is missing auth", self.name()))?;
        let users = self
            .settings
            .clients
            .iter()
            .skip(1)
            .map(|user| {
                user.auth
                    .clone()
                    .or(user.password.clone())
                    .with_context(|| {
                        format!(
                            "xray Hysteria inbound {} extra client is missing auth",
                            self.name()
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let cc_rx = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.brutal_down)
            .or_else(|| hysteria.and_then(|settings| settings.down))
            .map(|mbps| mbps.saturating_mul(125_000).to_string())
            .unwrap_or_else(|| "0".to_string());
        let (cert_path, key_path, certificates, key) =
            xray_tls_server_identity(certificate, "Hysteria", self.name())?;
        let upload_bandwidth = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.brutal_up)
            .or_else(|| hysteria.and_then(|settings| settings.up));
        Ok(Hysteria2ServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray Hysteria inbound {} is missing port", self.name())
                })?,
            ),
            password,
            users,
            cert_path,
            key_path,
            certificates,
            key,
            obfs,
            obfs_password,
            upload_bandwidth,
            udp: true,
            cc_rx,
            congestion_control,
        })
    }

    fn to_trojan_server_config(&self) -> Result<TrojanServerConfig> {
        ensure!(
            self.settings.fallbacks.is_empty(),
            "xray Trojan inbound {} sets fallbacks; Aerion Trojan server does not expose fallback routing",
            self.name()
        );
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.eq_ignore_ascii_case("tls"),
            "xray Trojan inbound {} uses stream security {}; Aerion Trojan server requires TLS",
            self.name(),
            stream_security
        );
        let transport = XrayOutbound {
            tag: self.tag.clone(),
            protocol: self.protocol.clone(),
            settings: XrayOutboundSettings::default(),
            stream_settings: self.stream_settings.clone(),
            mux: None,
            decode_error: None,
            extra: Map::new(),
        }
        .vless_transport_config()?;
        ensure_vless_alpn(
            "xray",
            self.name(),
            &transport,
            self.stream_settings
                .tls_settings
                .as_ref()
                .and_then(|tls| tls.alpn.as_ref()),
        )?;
        let certificate = xray_first_server_certificate(
            self.stream_settings.tls_settings.as_ref(),
            "Trojan",
            self.name(),
        )?;
        let primary = self
            .settings
            .clients
            .first()
            .context("xray Trojan inbound is missing settings.clients")?;
        let (cert_path, key_path, certificates, key) =
            xray_tls_server_identity(certificate, "Trojan", self.name())?;
        Ok(TrojanServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray Trojan inbound {} is missing port", self.name())
                })?,
            ),
            password: primary
                .password
                .clone()
                .context("xray Trojan inbound primary client is missing password")?,
            users: self
                .settings
                .clients
                .iter()
                .skip(1)
                .map(|user| {
                    user.password
                        .clone()
                        .context("xray Trojan inbound extra client is missing password")
                })
                .collect::<Result<Vec<_>>>()?,
            cert_path,
            key_path,
            certificates,
            key,
            transport,
        })
    }

    fn to_vless_server_config(&self) -> Result<VlessServerConfig> {
        let decryption = self.settings.decryption.as_deref().unwrap_or("none");
        ensure!(
            decryption.trim().is_empty() || decryption.eq_ignore_ascii_case("none"),
            "xray VLESS inbound {} uses decryption {}; Aerion supports VLESS decryption none",
            self.name(),
            decryption
        );
        ensure!(
            self.settings.fallbacks.is_empty(),
            "xray VLESS inbound {} sets fallbacks; Aerion VLESS server does not expose fallback routing",
            self.name()
        );
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty()
                || stream_security.eq_ignore_ascii_case("none")
                || stream_security.eq_ignore_ascii_case("tls")
                || stream_security.eq_ignore_ascii_case("reality"),
            "xray VLESS inbound {} uses stream security {}; Aerion maps raw TCP, TLS, or REALITY VLESS server configs",
            self.name(),
            stream_security
        );
        let tls = self.stream_settings.tls_settings.as_ref();
        let reality_settings = self.stream_settings.reality_settings.as_ref();
        let transport = XrayOutbound {
            tag: self.tag.clone(),
            protocol: self.protocol.clone(),
            settings: XrayOutboundSettings::default(),
            stream_settings: self.stream_settings.clone(),
            mux: None,
            decode_error: None,
            extra: Map::new(),
        }
        .vless_transport_config()?;
        if stream_security.eq_ignore_ascii_case("tls")
            || stream_security.eq_ignore_ascii_case("reality")
        {
            ensure_vless_alpn(
                "xray",
                self.name(),
                &transport,
                if stream_security.eq_ignore_ascii_case("reality") {
                    reality_settings.and_then(|settings| settings.alpn.as_ref())
                } else {
                    tls.and_then(|settings| settings.alpn.as_ref())
                },
            )?;
        } else {
            ensure_no_alpn("xray", self.name(), tls.and_then(|tls| tls.alpn.as_ref()))?;
        }
        let primary = self
            .settings
            .clients
            .first()
            .context("xray VLESS inbound is missing settings.clients")?;
        let user_id = primary
            .id
            .clone()
            .context("xray VLESS inbound primary client is missing id")?;
        let flow = primary
            .flow
            .clone()
            .or(self.settings.flow.clone())
            .unwrap_or_default();
        let users = self
            .settings
            .clients
            .iter()
            .skip(1)
            .map(|user| {
                let id = user
                    .id
                    .clone()
                    .context("xray VLESS inbound extra client is missing id")?;
                let user_flow = user
                    .flow
                    .clone()
                    .or(self.settings.flow.clone())
                    .unwrap_or_default();
                ensure!(
                    user_flow == flow,
                    "xray VLESS inbound {} uses per-client flow; Aerion VLESS server expects one flow for the inbound",
                    self.name()
                );
                Ok(id)
            })
            .collect::<Result<Vec<_>>>()?;
        let (cert_path, key_path, certificates, key) =
            if stream_security.eq_ignore_ascii_case("tls") {
                let certificate = xray_first_server_certificate(tls, "VLESS", self.name())?;
                xray_tls_server_identity(certificate, "VLESS", self.name())?
            } else {
                (PathBuf::new(), PathBuf::new(), Vec::new(), None)
            };
        let reality = if stream_security.eq_ignore_ascii_case("reality") {
            let settings = reality_settings.with_context(|| {
                format!(
                    "xray VLESS inbound {} is missing realitySettings",
                    self.name()
                )
            })?;
            Some(xray_reality_server_config(
                self.name(),
                settings,
                &transport,
            )?)
        } else {
            None
        };
        Ok(VlessServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray VLESS inbound {} is missing port", self.name())
                })?,
            ),
            user_id,
            users,
            tls: stream_security.eq_ignore_ascii_case("tls"),
            cert_path,
            key_path,
            certificates,
            key,
            flow,
            reality,
            transport,
        })
    }

    fn to_vmess_server_config(&self) -> Result<VmessServerConfig> {
        ensure_raw_or_tls_stream_security(
            "xray VMess",
            self.name(),
            &self.stream_settings.security,
        )?;
        let transport = XrayOutbound {
            tag: self.tag.clone(),
            protocol: self.protocol.clone(),
            settings: XrayOutboundSettings::default(),
            stream_settings: self.stream_settings.clone(),
            mux: None,
            decode_error: None,
            extra: Map::new(),
        }
        .vless_transport_config()?;
        let tls_enabled = self
            .stream_settings
            .security
            .trim()
            .eq_ignore_ascii_case("tls");
        if tls_enabled {
            ensure_vless_alpn(
                "xray",
                self.name(),
                &transport,
                self.stream_settings
                    .tls_settings
                    .as_ref()
                    .and_then(|tls| tls.alpn.as_ref()),
            )?;
        } else {
            ensure_no_alpn(
                "xray",
                self.name(),
                self.stream_settings
                    .tls_settings
                    .as_ref()
                    .and_then(|tls| tls.alpn.as_ref()),
            )?;
        }
        let primary = self
            .settings
            .clients
            .first()
            .context("xray VMess inbound is missing settings.clients")?;
        let alter_id = primary.alter_id.or(self.settings.alter_id).unwrap_or(0);
        ensure!(
            alter_id == 0,
            "xray VMess inbound {} primary client uses legacy alterId {}; Aerion implements AEAD VMess only",
            self.name(),
            alter_id
        );
        let user_id = primary
            .id
            .clone()
            .context("xray VMess inbound primary client is missing id")?;
        let users = self
            .settings
            .clients
            .iter()
            .skip(1)
            .map(|user| {
                let alter_id = user.alter_id.or(self.settings.alter_id).unwrap_or(0);
                ensure!(
                    alter_id == 0,
                    "xray VMess inbound {} extra client uses legacy alterId {}; Aerion implements AEAD VMess only",
                    self.name(),
                    alter_id
                );
                user.id
                    .clone()
                    .context("xray VMess inbound extra client is missing id")
            })
            .collect::<Result<Vec<_>>>()?;
        let (cert_path, key_path, certificates, key) = if tls_enabled {
            let certificate = xray_first_server_certificate(
                self.stream_settings.tls_settings.as_ref(),
                "VMess",
                self.name(),
            )?;
            let (cert_path, key_path, certificates, key) =
                xray_tls_server_identity(certificate, "VMess", self.name())?;
            (Some(cert_path), Some(key_path), certificates, key)
        } else {
            (None, None, Vec::new(), None)
        };
        Ok(VmessServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray VMess inbound {} is missing port", self.name())
                })?,
            ),
            user_id,
            users,
            tls: tls_enabled,
            cert_path,
            key_path,
            certificates,
            key,
            transport,
        })
    }
}

impl XrayOutbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.protocol)
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<XrayClientConfig> {
        ensure!(
            self.decode_error.is_none(),
            "parse xray outbound {} failed: {}",
            self.name(),
            self.decode_error.as_deref().unwrap_or_default()
        );
        let owner = format!("xray {} outbound {}", self.protocol, self.name());
        ensure_no_extra_fields(&owner, &self.extra)?;
        self.settings.reject_unsupported_extra_fields(&owner)?;
        self.stream_settings.reject_unsupported_fields(&owner)?;
        match self.protocol.trim().to_ascii_lowercase().as_str() {
            "freedom" => Ok(XrayClientConfig::Route(
                self.to_route_client_config(listen, RouteDecision::Direct)?,
            )),
            "blackhole" => Ok(XrayClientConfig::Route(
                self.to_route_client_config(listen, RouteDecision::Block)?,
            )),
            "shadowsocks" | "ss" => Ok(XrayClientConfig::Shadowsocks(
                self.to_shadowsocks_client_config(listen)?,
            )),
            "socks" | "socks5" => Ok(XrayClientConfig::SocksProxy(
                self.to_socks_client_config(listen)?,
            )),
            "http" => Ok(XrayClientConfig::HttpProxy(
                self.to_http_client_config(listen)?,
            )),
            "vless" => Ok(XrayClientConfig::Vless(
                self.to_vless_client_config(listen)?,
            )),
            "vmess" => Ok(XrayClientConfig::Vmess(
                self.to_vmess_client_config(listen)?,
            )),
            "trojan" => Ok(XrayClientConfig::Trojan(
                self.to_trojan_client_config(listen)?,
            )),
            "hysteria" | "hysteria2" | "hy2" => Ok(XrayClientConfig::Hysteria2(
                self.to_hysteria2_client_config(listen)?,
            )),
            other => bail!("unsupported xray outbound protocol {other}"),
        }
    }

    fn to_route_client_config(
        &self,
        listen: SocketAddr,
        default: RouteDecision,
    ) -> Result<RouteClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray {} outbound {}", self.protocol, self.name()),
            self.mux.as_ref(),
            "Aerion route client does not use Xray mux",
        )?;
        ensure_tcp_network("xray route", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray {} outbound {} uses stream security {}; Aerion route client does not use Xray stream security",
            self.protocol,
            self.name(),
            stream_security
        );
        ensure!(
            self.stream_settings.hysteria_settings.is_none()
                && self.stream_settings.finalmask.is_none()
                && self.stream_settings.tls_settings.is_none()
                && self.stream_settings.reality_settings.is_none()
                && self.stream_settings.ws_settings.is_none()
                && self.stream_settings.http_upgrade_settings.is_none()
                && self.stream_settings.grpc_settings.is_none()
                && self.stream_settings.http_settings.is_none()
                && self.stream_settings.xhttp_settings.is_none()
                && self.stream_settings.split_http_settings.is_none(),
            "xray {} outbound {} sets stream transport options; Aerion route client handles plain direct/block routing",
            self.protocol,
            self.name()
        );
        ensure_empty_route_settings(&self.settings, &self.protocol, self.name())?;
        Ok(RouteClientConfig { listen, default })
    }

    fn to_http_client_config(&self, listen: SocketAddr) -> Result<HttpProxyClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray HTTP outbound {}", self.name()),
            self.mux.as_ref(),
            "HTTP CONNECT proxying does not use Xray mux",
        )?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty()
                || stream_security.eq_ignore_ascii_case("none")
                || stream_security.eq_ignore_ascii_case("tls"),
            "xray HTTP outbound {} uses stream security {}; Aerion HTTP proxy supports raw TCP or TLS",
            self.name(),
            stream_security
        );
        let tls_enabled = stream_security.eq_ignore_ascii_case("tls");
        if tls_enabled {
            ensure_http_alpn("xray", self.name(), self.stream_alpn())?;
        } else {
            ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
        }
        let tls = self.stream_settings.tls_settings.as_ref();
        if !tls_enabled {
            ensure!(
                tls.is_none_or(|settings| {
                    !settings.allow_insecure
                        && settings.fingerprint.is_none()
                        && settings
                            .server_name
                            .as_deref()
                            .map(str::trim)
                            .unwrap_or_default()
                            .is_empty()
                        && !settings.disable_system_root
                        && settings.pinned_peer_cert_sha256.is_none()
                        && settings.certificates.is_empty()
                }),
                "xray HTTP outbound {} sets TLS-only options while stream security is not tls",
                self.name()
            );
        }
        let (ca_cert_paths, ca_certificates) = if tls_enabled {
            xray_tls_client_roots(tls)?
        } else {
            (Vec::new(), Vec::new())
        };
        let server = self.first_trojan_server()?;
        let server_user = server.users.first();
        let server_host = server.address.clone();
        Ok(HttpProxyClientConfig {
            listen,
            server_host: server_host.clone(),
            server_port: server.port,
            username: self
                .settings
                .user
                .clone()
                .or_else(|| server_user.and_then(|user| user.user.clone()))
                .unwrap_or_default(),
            password: self
                .settings
                .pass
                .clone()
                .or_else(|| server_user.and_then(|user| user.pass.clone()))
                .unwrap_or_default(),
            tls: tls_enabled,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server_host,
                self.name(),
            ),
            insecure: if tls_enabled {
                tls.map(|settings| settings.allow_insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, tls_enabled),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, tls_enabled),
            client_fingerprint: if tls_enabled {
                tls.and_then(|settings| settings.fingerprint)
            } else {
                None
            },
            extra_headers: self.settings.headers.clone().into_iter().collect(),
        })
    }

    fn to_socks_client_config(&self, listen: SocketAddr) -> Result<SocksProxyClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray SOCKS outbound {}", self.name()),
            self.mux.as_ref(),
            "SOCKS proxying does not use Xray mux",
        )?;
        ensure_tcp_network("xray SOCKS", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray SOCKS outbound {} uses stream security {}; Aerion SOCKS outbound is plain SOCKS5",
            self.name(),
            stream_security
        );
        ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
        let tls = self.stream_settings.tls_settings.as_ref();
        ensure!(
            tls.is_none_or(|settings| {
                !settings.allow_insecure
                    && settings.fingerprint.is_none()
                    && settings
                        .server_name
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or_default()
                        .is_empty()
                    && !settings.disable_system_root
                    && settings.pinned_peer_cert_sha256.is_none()
                    && settings.certificates.is_empty()
            }),
            "xray SOCKS outbound {} sets TLS-only options",
            self.name()
        );
        ensure!(
            self.settings.headers.is_empty(),
            "xray SOCKS outbound {} sets HTTP headers; SOCKS does not use headers",
            self.name()
        );
        let (tcp, udp) = xray_tcp_udp_outbound_network(self.settings.network.as_deref())?;
        ensure!(
            tcp,
            "xray SOCKS outbound {} uses udp-only network; Aerion SOCKS outbound requires TCP control channel",
            self.name()
        );
        let server = self.first_trojan_server()?;
        let server_user = server.users.first();
        Ok(SocksProxyClientConfig {
            listen,
            server_host: server.address.clone(),
            server_port: server.port,
            username: self
                .settings
                .user
                .clone()
                .or_else(|| server_user.and_then(|user| user.user.clone()))
                .unwrap_or_default(),
            password: self
                .settings
                .pass
                .clone()
                .or_else(|| server_user.and_then(|user| user.pass.clone()))
                .unwrap_or_default(),
            udp,
        })
    }

    fn to_vless_client_config(&self, listen: SocketAddr) -> Result<VlessClientConfig> {
        let peer = self.first_vless_or_vmess_peer()?;
        let mux = xray_mux_enabled(
            &format!("xray VLESS outbound {}", self.name()),
            self.mux.as_ref(),
        )?;
        ensure!(
            peer.user
                .encryption
                .as_deref()
                .unwrap_or("none")
                .eq_ignore_ascii_case("none"),
            "xray VLESS outbound {} uses encryption {:?}; Aerion supports VLESS encryption none",
            self.name(),
            peer.user.encryption
        );
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty()
                || stream_security.eq_ignore_ascii_case("none")
                || stream_security.eq_ignore_ascii_case("tls")
                || stream_security.eq_ignore_ascii_case("reality"),
            "xray VLESS outbound {} uses stream security {}; Aerion VLESS supports raw TCP, TLS, or REALITY",
            self.name(),
            stream_security
        );
        let transport = self.vless_transport_config()?;
        let tls_enabled = stream_security.eq_ignore_ascii_case("tls");
        let reality = if self.is_reality() {
            Some(self.reality_client_config()?)
        } else {
            None
        };
        if tls_enabled || reality.is_some() {
            ensure_vless_alpn("xray", self.name(), &transport, self.stream_alpn())?;
        } else {
            ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
        }
        let tls = self.stream_settings.tls_settings.as_ref();
        let reality_settings = self.stream_settings.reality_settings.as_ref();
        let tls_server_name = if reality.is_some() {
            reality_settings.and_then(|settings| settings.server_name.as_deref())
        } else if tls_enabled {
            tls.and_then(|settings| settings.server_name.as_deref())
        } else {
            None
        };
        let client_fingerprint = if reality.is_some() {
            reality_settings.and_then(|settings| settings.fingerprint)
        } else if tls_enabled {
            tls.and_then(|settings| settings.fingerprint)
        } else {
            None
        };
        let (ca_cert_paths, ca_certificates) = if tls_enabled {
            xray_tls_client_roots(tls)?
        } else {
            (Vec::new(), Vec::new())
        };
        let server_host = peer.address.clone();
        Ok(VlessClientConfig {
            listen,
            server_host: server_host.clone(),
            server_port: peer.port,
            user_id: peer.user.id.with_context(|| {
                format!("xray VLESS outbound {} is missing user id", self.name())
            })?,
            tls: tls_enabled,
            sni: sni_or_server(tls_server_name, &server_host, self.name()),
            insecure: if tls_enabled {
                tls.map(|settings| settings.allow_insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, tls_enabled),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, tls_enabled),
            flow: peer
                .user
                .flow
                .or(self.settings.flow.clone())
                .unwrap_or_default(),
            packet_encoding: peer
                .user
                .packet_encoding
                .or(self.settings.packet_encoding.clone())
                .unwrap_or_default(),
            mux,
            udp: true,
            client_fingerprint,
            reality,
            transport,
        })
    }

    fn to_shadowsocks_client_config(&self, listen: SocketAddr) -> Result<ShadowsocksClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray Shadowsocks outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion Shadowsocks client does not use Xray mux",
        )?;
        let server = self.first_trojan_server()?;
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray Shadowsocks outbound {} uses stream security {}; Aerion Shadowsocks expects raw Shadowsocks transport",
            self.name(),
            stream_security
        );
        Ok(ShadowsocksClientConfig {
            listen,
            server_host: server.address.clone(),
            server_port: server.port,
            method: server
                .method
                .or(self.settings.method.clone())
                .or(self.settings.security.clone())
                .with_context(|| {
                    format!(
                        "xray Shadowsocks outbound {} is missing method",
                        self.name()
                    )
                })?,
            password: server.password.with_context(|| {
                format!(
                    "xray Shadowsocks outbound {} is missing password",
                    self.name()
                )
            })?,
            udp: true,
            udp_over_tcp: false,
        })
    }

    fn to_vmess_client_config(&self, listen: SocketAddr) -> Result<VmessClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray VMess outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion VMess client does not use Xray mux",
        )?;
        let peer = self.first_vless_or_vmess_peer()?;
        ensure_raw_or_tls_stream_security(
            "xray VMess",
            self.name(),
            &self.stream_settings.security,
        )?;
        let transport = self.vless_transport_config()?;
        let alter_id = peer.user.alter_id.or(self.settings.alter_id).unwrap_or(0);
        ensure!(
            alter_id == 0,
            "xray VMess outbound {} uses legacy alterId {}; Aerion implements AEAD VMess only",
            self.name(),
            alter_id
        );
        let packet_encoding = peer
            .user
            .packet_encoding
            .clone()
            .or(self.settings.packet_encoding.clone())
            .unwrap_or_default();
        ensure_vmess_packet_encoding(&packet_encoding)
            .with_context(|| format!("xray VMess outbound {} packetEncoding", self.name()))?;
        let tls = self.stream_settings.tls_settings.as_ref();
        let tls_enabled = self
            .stream_settings
            .security
            .trim()
            .eq_ignore_ascii_case("tls");
        if tls_enabled {
            ensure_vless_alpn("xray", self.name(), &transport, self.stream_alpn())?;
        } else {
            ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
        }
        let (ca_cert_paths, ca_certificates) = if tls_enabled {
            xray_tls_client_roots(tls)?
        } else {
            (Vec::new(), Vec::new())
        };
        let server_host = peer.address.clone();
        Ok(VmessClientConfig {
            listen,
            server_host: server_host.clone(),
            server_port: peer.port,
            user_id: peer.user.id.with_context(|| {
                format!("xray VMess outbound {} is missing user id", self.name())
            })?,
            security: peer
                .user
                .security
                .or(self.settings.security.clone())
                .unwrap_or_else(|| "auto".to_string()),
            packet_encoding,
            udp: true,
            tls: tls_enabled,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server_host,
                self.name(),
            ),
            insecure: if tls_enabled {
                tls.map(|settings| settings.allow_insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, tls_enabled),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, tls_enabled),
            client_fingerprint: if tls_enabled {
                tls.and_then(|settings| settings.fingerprint)
            } else {
                None
            },
            transport,
        })
    }

    fn to_trojan_client_config(&self, listen: SocketAddr) -> Result<TrojanClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray Trojan outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion Trojan client does not use Xray mux",
        )?;
        let server = self.first_trojan_server()?;
        let transport = self.vless_transport_config()?;
        ensure_tls_or_reality("xray Trojan", self.name(), &self.stream_settings.security)?;
        ensure!(
            !self.is_reality(),
            "xray Trojan outbound {} uses REALITY; Aerion only wires REALITY on VLESS",
            self.name()
        );
        ensure_vless_alpn("xray", self.name(), &transport, self.stream_alpn())?;
        let tls = self.stream_settings.tls_settings.as_ref();
        let (ca_cert_paths, ca_certificates) = xray_tls_client_roots(tls)?;
        let server_host = server.address.clone();
        Ok(TrojanClientConfig {
            listen,
            server_host: server_host.clone(),
            server_port: server.port,
            password: server.password.with_context(|| {
                format!("xray Trojan outbound {} is missing password", self.name())
            })?,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server_host,
                self.name(),
            ),
            insecure: tls.map(|settings| settings.allow_insecure).unwrap_or(false),
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, true),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, true),
            udp: true,
            client_fingerprint: tls.and_then(|settings| settings.fingerprint),
            transport,
        })
    }

    fn to_hysteria2_client_config(&self, listen: SocketAddr) -> Result<Hysteria2ClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray Hysteria outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion Hysteria2 client does not use Xray mux",
        )?;
        let server = self.first_trojan_server()?;
        let hysteria = self.stream_settings.hysteria_settings.as_ref();
        let version = self
            .settings
            .version
            .or_else(|| hysteria.and_then(|settings| settings.version));
        ensure!(
            !self.protocol.eq_ignore_ascii_case("hysteria") || version == Some(2),
            "xray Hysteria outbound {} uses version {:?}; Aerion supports Hysteria2 version 2",
            self.name(),
            version
        );
        if let Some(version) = version {
            ensure!(
                version == 2,
                "xray Hysteria outbound {} uses version {}; Aerion supports Hysteria2 version 2",
                self.name(),
                version
            );
        }
        let network = self.stream_settings.network.trim();
        if self.protocol.eq_ignore_ascii_case("hysteria") {
            ensure!(
                network.eq_ignore_ascii_case("hysteria"),
                "xray Hysteria outbound {} uses network {}; Xray Hysteria profiles use hysteria transport",
                self.name(),
                network
            );
        } else {
            ensure!(
                network.is_empty()
                    || network.eq_ignore_ascii_case("tcp")
                    || network.eq_ignore_ascii_case("hysteria"),
                "xray Hysteria2 outbound {} uses network {}; Aerion Hysteria2 expects hysteria transport",
                self.name(),
                network
            );
        }
        let tls = self.stream_settings.tls_settings.as_ref();
        ensure_hysteria_alpn(
            "xray",
            self.name(),
            tls.and_then(|settings| settings.alpn.as_ref()),
        )?;
        ensure!(
            !hysteria
                .and_then(|settings| settings.udp_hop.as_ref())
                .map(value_has_data)
                .unwrap_or(false),
            "xray Hysteria outbound {} enables UDP port hopping; Aerion Hysteria2 client expects one fixed port",
            self.name()
        );
        ensure!(
            !hysteria
                .and_then(|settings| settings.masquerade.as_ref())
                .map(value_has_data)
                .unwrap_or(false),
            "xray Hysteria outbound {} sets masquerade; Aerion Hysteria2 client binding does not expose masquerade",
            self.name()
        );
        let finalmask = self.stream_settings.finalmask.as_ref();
        if let Some(finalmask) = finalmask {
            ensure!(
                finalmask.tcp.is_empty(),
                "xray Hysteria outbound {} sets finalmask TCP masks; Aerion Hysteria2 only maps salamander UDP obfs",
                self.name()
            );
            ensure!(
                finalmask.udp.len() <= 1,
                "xray Hysteria outbound {} sets multiple finalmask UDP masks; Aerion Hysteria2 exposes one obfs layer",
                self.name()
            );
            ensure!(
                !finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.udp_hop.as_ref())
                    .map(value_has_data)
                    .unwrap_or(false),
                "xray Hysteria outbound {} enables finalmask UDP port hopping; Aerion Hysteria2 client expects one fixed port",
                self.name()
            );
            ensure!(
                finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.bbr_profile.as_deref())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
                "xray Hysteria outbound {} sets finalmask bbrProfile {:?}; Aerion Hysteria2 uses the default BBR profile",
                self.name(),
                finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.bbr_profile.as_ref())
            );
            ensure!(
                !finalmask
                    .quic_params
                    .as_ref()
                    .map(|params| params.debug)
                    .unwrap_or(false),
                "xray Hysteria outbound {} enables finalmask quicParams debug; Aerion Hysteria2 client does not expose QUIC debug toggles",
                self.name()
            );
        }
        let (obfs, obfs_password) = match finalmask.and_then(|finalmask| finalmask.udp.first()) {
            Some(mask) => {
                ensure!(
                    mask.kind.eq_ignore_ascii_case("salamander"),
                    "xray Hysteria outbound {} uses finalmask UDP mask {}; Aerion supports salamander",
                    self.name(),
                    mask.kind
                );
                let password = mask
                    .settings
                    .as_ref()
                    .and_then(|settings| settings.get("password"))
                    .and_then(Value::as_str)
                    .with_context(|| {
                        format!(
                            "xray Hysteria outbound {} salamander mask is missing password",
                            self.name()
                        )
                    })?
                    .to_string();
                (Some("salamander".to_string()), Some(password))
            }
            None => (None, None),
        };
        let congestion_control = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.congestion.clone())
            .or_else(|| hysteria.and_then(|settings| settings.congestion.clone()))
            .unwrap_or_else(|| "bbr".to_string());
        ensure!(
            congestion_control.trim().is_empty()
                || congestion_control.eq_ignore_ascii_case("bbr")
                || congestion_control.eq_ignore_ascii_case("reno"),
            "xray Hysteria outbound {} uses congestion {}; Aerion Hysteria2 supports bbr or reno",
            self.name(),
            congestion_control
        );
        let download_bandwidth = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.brutal_down)
            .or_else(|| hysteria.and_then(|settings| settings.down));
        let upload_bandwidth = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.brutal_up)
            .or_else(|| hysteria.and_then(|settings| settings.up));
        let (ca_cert_paths, ca_certificates) = xray_tls_client_roots(tls)?;
        Ok(Hysteria2ClientConfig {
            listen,
            server_host: server.address.clone(),
            server_port: server.port,
            password: hysteria
                .and_then(|settings| settings.auth.clone())
                .or(server.password)
                .with_context(|| {
                    format!(
                        "xray Hysteria2 outbound {} is missing password",
                        self.name()
                    )
                })?,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server.address,
                self.name(),
            ),
            insecure: tls.map(|settings| settings.allow_insecure).unwrap_or(false),
            certificate_fingerprint: None,
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, true),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, true),
            obfs,
            obfs_password,
            upload_bandwidth,
            download_bandwidth,
            udp: true,
            congestion_control,
        })
    }

    fn first_vless_or_vmess_peer(&self) -> Result<XrayServerUser> {
        if let Some(vnext) = self.settings.vnext.first() {
            let user = vnext
                .users
                .first()
                .cloned()
                .with_context(|| format!("xray outbound {} has no users", self.name()))?;
            return Ok(XrayServerUser {
                address: vnext.address.clone(),
                port: vnext.port,
                user,
            });
        }
        Ok(XrayServerUser {
            address: self
                .settings
                .address
                .clone()
                .with_context(|| format!("xray outbound {} is missing address", self.name()))?,
            port: self
                .settings
                .port
                .with_context(|| format!("xray outbound {} is missing port", self.name()))?,
            user: XrayUser {
                id: self.settings.id.clone(),
                password: self.settings.password.clone(),
                auth: self.settings.auth.clone(),
                method: self.settings.method.clone(),
                encryption: None,
                flow: self.settings.flow.clone(),
                packet_encoding: self.settings.packet_encoding.clone(),
                security: self.settings.security.clone(),
                alter_id: self.settings.alter_id,
                extra: Map::new(),
            },
        })
    }

    fn first_trojan_server(&self) -> Result<XrayServer> {
        if let Some(server) = self.settings.servers.first() {
            return Ok(server.clone());
        }
        Ok(XrayServer {
            address: self
                .settings
                .address
                .clone()
                .with_context(|| format!("xray outbound {} is missing address", self.name()))?,
            port: self
                .settings
                .port
                .with_context(|| format!("xray outbound {} is missing port", self.name()))?,
            password: self.settings.password.clone(),
            method: self.settings.method.clone(),
            users: Vec::new(),
            extra: Map::new(),
        })
    }

    fn is_reality(&self) -> bool {
        self.stream_settings
            .security
            .trim()
            .eq_ignore_ascii_case("reality")
    }

    fn reality_client_config(&self) -> Result<RealityClientConfig> {
        let settings = self
            .stream_settings
            .reality_settings
            .as_ref()
            .with_context(|| {
                format!(
                    "xray REALITY outbound {} is missing realitySettings",
                    self.name()
                )
            })?;
        RealityClientConfig::from_strings(
            settings.public_key.as_deref().with_context(|| {
                format!("xray REALITY outbound {} is missing publicKey", self.name())
            })?,
            settings.short_id.as_deref().unwrap_or_default(),
        )
    }

    fn stream_alpn(&self) -> Option<&OneOrManyStrings> {
        if self.is_reality() {
            self.stream_settings
                .reality_settings
                .as_ref()
                .and_then(|settings| settings.alpn.as_ref())
        } else {
            self.stream_settings
                .tls_settings
                .as_ref()
                .and_then(|settings| settings.alpn.as_ref())
        }
    }

    fn vless_transport_config(&self) -> Result<VlessTransportConfig> {
        if self.stream_settings.network.eq_ignore_ascii_case("ws")
            || self
                .stream_settings
                .network
                .eq_ignore_ascii_case("websocket")
        {
            return VlessTransportConfig::from_headers(
                &self.stream_settings.network,
                self.stream_settings
                    .ws_settings
                    .as_ref()
                    .and_then(|settings| settings.path.clone()),
                self.stream_settings
                    .ws_settings
                    .as_ref()
                    .map(|settings| settings.headers.clone())
                    .unwrap_or_default(),
            );
        }
        if self
            .stream_settings
            .network
            .trim()
            .eq_ignore_ascii_case("httpupgrade")
        {
            let settings = self.stream_settings.http_upgrade_settings.as_ref();
            return VlessTransportConfig::from_network(
                &self.stream_settings.network,
                settings.and_then(|settings| settings.path.clone()),
                settings.and_then(|settings| settings.host.clone()),
                settings
                    .map(|settings| settings.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
            );
        }
        if self
            .stream_settings
            .network
            .trim()
            .eq_ignore_ascii_case("grpc")
        {
            let settings = self.stream_settings.grpc_settings.as_ref();
            return VlessTransportConfig::from_network(
                &self.stream_settings.network,
                settings.and_then(|settings| settings.service_name.clone()),
                settings.and_then(|settings| settings.authority.clone()),
                settings
                    .map(|settings| settings.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
            );
        }
        if self
            .stream_settings
            .network
            .trim()
            .eq_ignore_ascii_case("h2")
            || self
                .stream_settings
                .network
                .trim()
                .eq_ignore_ascii_case("http2")
        {
            let settings = self.stream_settings.http_settings.as_ref();
            return VlessTransportConfig::from_network(
                &self.stream_settings.network,
                settings.and_then(|settings| settings.path.clone()),
                settings.and_then(|settings| {
                    settings
                        .host
                        .as_ref()
                        .and_then(|host| host.to_vec().into_iter().next())
                }),
                settings
                    .map(|settings| settings.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
            );
        }
        if self
            .stream_settings
            .network
            .trim()
            .eq_ignore_ascii_case("xhttp")
            || self
                .stream_settings
                .network
                .trim()
                .eq_ignore_ascii_case("splithttp")
        {
            let settings = self
                .stream_settings
                .xhttp_settings
                .as_ref()
                .or(self.stream_settings.split_http_settings.as_ref());
            return VlessTransportConfig::xhttp(
                settings.and_then(|settings| settings.path.clone()),
                settings.and_then(|settings| {
                    settings
                        .host
                        .as_ref()
                        .and_then(|host| host.to_vec().into_iter().next())
                }),
                settings
                    .map(|settings| settings.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
                settings.and_then(|settings| settings.mode.clone()),
            );
        }
        VlessTransportConfig::from_network(&self.stream_settings.network, None, None, Vec::new())
    }
}

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

fn ensure_no_extra_fields(owner: &str, extra: &Map<String, Value>) -> Result<()> {
    ensure!(
        extra.is_empty(),
        "{owner} has unsupported fields {:?}",
        extra.keys().collect::<Vec<_>>()
    );
    Ok(())
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

fn default_tcp_network() -> String {
    "tcp".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ProxyTarget;

    #[test]
    fn parses_vless_reality_outbound() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "settings": { "auth": "noauth" }
  }],
  "outbounds": [{
    "tag": "proxy",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{
          "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
          "encryption": "none",
          "flow": "xtls-rprx-vision",
          "packetEncoding": "xudp"
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "serverName": "www.example.com",
        "fingerprint": "chrome",
        "publicKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "shortId": "a1b2"
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        assert_eq!(
            config.local_socks_listen()?,
            Some("127.0.0.1:1080".parse()?)
        );
        let XrayClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.server_host, "example.com");
        assert_eq!(vless.sni, "www.example.com");
        assert_eq!(vless.client_fingerprint, Some(UtlsFingerprint::Chrome));
        assert!(vless.reality.is_some());
        Ok(())
    }

    #[test]
    fn rejects_xray_unsupported_local_socks_inbound_fields() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "settings": { "auth": "password" }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let auth_error = config
            .local_socks_listen()
            .expect_err("local SOCKS auth must not be ignored");
        assert!(auth_error.to_string().contains("settings.auth"));

        let json = r#"
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "streamSettings": {
      "network": "ws",
      "wsSettings": { "path": "/socks" }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let transport_error = config
            .local_socks_listen()
            .expect_err("local SOCKS transport must not be ignored");
        assert!(transport_error.to_string().contains("local SOCKS listener"));
        assert!(transport_error.to_string().contains("network ws"));

        let json = r#"
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "sniffing": { "enabled": true }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let sniff_error = config
            .local_socks_listen()
            .expect_err("local SOCKS sniffing must not be ignored");
        assert!(sniff_error.to_string().contains("sniffing"));

        let json = r#"
{
  "inbounds": [{
    "tag": "http-in",
    "protocol": "http",
    "listen": "127.0.0.1",
    "port": 8080
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let http_error = config
            .local_socks_listen()
            .expect_err("local HTTP inbound must not be ignored");
        assert!(http_error.to_string().contains("local SOCKS listener"));
        assert!(http_error.to_string().contains("http"));
        Ok(())
    }

    #[test]
    fn compiles_xray_routing_rules() -> Result<()> {
        let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "outboundTag": "direct" },
      { "type": "field", "domain": ["keyword:video"], "outboundTag": "proxy-a" },
      { "type": "field", "domain": ["cdn"], "outboundTag": "proxy-c" },
      { "type": "field", "ip": ["10.0.0.0/8"], "port": "53", "network": "udp", "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
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
                &ProxyTarget::Domain("static-cdn.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-c".to_string())
        );
        assert_eq!(
            routes.decide(&ProxyTarget::Ip("10.1.2.3:53".parse()?), RouteNetwork::Udp),
            RouteDecision::Direct
        );
        Ok(())
    }

    #[test]
    fn xray_route_default_uses_first_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    { "tag": "proxy-a", "protocol": "socks" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
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
    { "protocol": "socks" }
  ],
  "routing": {
    "rules": []
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("tagless default proxy outbound cannot be spawned");
        assert!(error.to_string().contains("requires a tag"));
        Ok(())
    }

    #[test]
    fn handles_xray_routing_top_level_options_explicitly() -> Result<()> {
        let json = r#"
{
  "routing": {
    "domainMatcher": "hybrid",
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let routes = config.route_table()?;
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );

        let json = r#"
{
  "routing": {
    "domainMatcher": "unknown",
    "rules": []
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("unknown domain matcher must not be ignored");
        assert!(error.to_string().contains("domainMatcher"));

        let json = r#"
{
  "routing": {
    "observatory": {},
    "rules": []
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("unknown routing fields must not be ignored");
        assert!(error.to_string().contains("unsupported fields"));
        Ok(())
    }

    #[test]
    fn rejects_xray_unsupported_top_level_options() -> Result<()> {
        let json = r#"
{
  "log": { "loglevel": "debug" },
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("unsupported xray top-level options must not be ignored");
        assert!(error.to_string().contains("xray config"));
        assert!(error.to_string().contains("log"));
        Ok(())
    }

    #[test]
    fn handles_xray_route_rule_tags_and_action_precedence() -> Result<()> {
        let json = r#"
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": ["domain:example.com"],
        "outboundTag": "direct",
        "balancerTag": "missing-balancer",
        "ruleTag": "debug-label"
      }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let routes = config.route_table()?;
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );

        let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "ruleTag": 7, "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("non-string ruleTag must be rejected");
        assert!(error.to_string().contains("ruleTag"));
        Ok(())
    }

    #[test]
    fn rejects_xray_geo_route_rules_without_data() -> Result<()> {
        let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("geosite needs explicit route-set data");
        assert!(error.to_string().contains("geosite rule-set data"));

        let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("geoip needs explicit route-set data");
        assert!(error.to_string().contains("geoip rule-set data"));

        let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "ip": ["ext:geoip.dat:cn"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("external geoip needs explicit route-set data");
        assert!(error.to_string().contains("external IP matcher"));
        assert!(error.to_string().contains("geoip rule-set data"));

        let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "ip": ["!geoip:cn"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("inverse IP matcher needs negative matching");
        assert!(error.to_string().contains("inverse IP matcher"));
        assert!(error.to_string().contains("negative route matching"));
        Ok(())
    }

    #[test]
    fn rejects_xray_metadata_route_matchers() -> Result<()> {
        let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "source": ["10.0.0.0/8"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("source route matcher requires metadata");
        assert!(error.to_string().contains("source IP matching metadata"));

        let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "process": ["curl"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("process route matcher requires metadata");
        assert!(error.to_string().contains("process metadata"));
        Ok(())
    }

    #[test]
    fn rejects_xray_routing_domain_strategy_that_requires_dns() -> Result<()> {
        let json = r#"
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "direct" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("xray domainStrategy must not be ignored");
        assert!(error.to_string().contains("domainStrategy"));
        Ok(())
    }

    #[test]
    fn resolves_static_xray_balancer_rule() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    { "tag": "proxy-a", "protocol": "freedom" },
    { "tag": "direct-out", "protocol": "freedom" }
  ],
  "routing": {
    "balancers": [
      { "tag": "single", "selector": ["proxy-a"], "strategy": {} }
    ],
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "balancerTag": "single" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let routes = config.route_table()?;
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-a".to_string())
        );
        Ok(())
    }

    #[test]
    fn rejects_dynamic_xray_balancer_rule() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    { "tag": "proxy-a", "protocol": "freedom" },
    { "tag": "proxy-b", "protocol": "freedom" }
  ],
  "routing": {
    "balancers": [
      { "tag": "multi", "selector": ["proxy-"] }
    ],
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "balancerTag": "multi" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("multi-outbound balancer needs a real policy");
        assert!(error.to_string().contains("single-outbound"));
        Ok(())
    }

    #[test]
    fn rejects_xray_balancer_runtime_policy_fields() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    { "tag": "proxy-a", "protocol": "freedom" }
  ],
  "routing": {
    "balancers": [
      { "tag": "runtime", "selector": ["proxy-a"], "fallbackTag": "direct", "strategy": { "type": "leastPing" } }
    ],
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "balancerTag": "runtime" }
    ]
  }
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("fallbackTag requires observatory state");
        assert!(error.to_string().contains("fallbackTag"));
        Ok(())
    }

    #[test]
    fn defers_xray_outbound_decode_errors_until_selected() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "tag": "broken-vless",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" }]
        }]
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": { "fingerprint": 123 }
      }
    },
    {
      "tag": "ss-ok",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{
          "address": "ss.example.com",
          "port": 8388,
          "method": "aes-128-gcm",
          "password": "secret"
        }]
      }
    }
  ]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Shadowsocks(shadowsocks) = config
            .outbound("ss-ok")
            .context("ss outbound")?
            .to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Shadowsocks")
        };
        assert_eq!(shadowsocks.server_host, "ss.example.com");

        let error = config
            .outbound("broken-vless")
            .context("broken outbound")?
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("broken outbound parse must be deferred");
        assert!(
            error
                .to_string()
                .contains("parse xray outbound broken-vless failed")
        );
        Ok(())
    }

    #[test]
    fn parses_xray_local_socks_string_port() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    { "tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": "1080" }
  ],
  "outbounds": []
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        assert_eq!(config.inbounds[0].port, Some(1080));
        assert_eq!(
            config.local_socks_listen()?,
            Some("127.0.0.1:1080".parse()?)
        );
        Ok(())
    }

    #[test]
    fn converts_vless_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "tag": "vless-server",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": 8443,
    "settings": {
      "decryption": "none",
      "clients": [
        { "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" },
        { "id": "e4d909c2-0a31-4ebf-8a8e-582c8f1f6e5a" }
      ]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "server.crt",
          "keyFile": "server.key"
        }]
      },
      "wsSettings": {
        "path": "/vless",
        "headers": { "Host": "edge.example.com" }
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.listen, "127.0.0.1:8443".parse()?);
        assert_eq!(vless.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(
            vless.users,
            vec!["e4d909c2-0a31-4ebf-8a8e-582c8f1f6e5a".to_string()]
        );
        assert!(vless.tls);
        assert_eq!(vless.cert_path, PathBuf::from("server.crt"));
        assert_eq!(vless.key_path, PathBuf::from("server.key"));
        assert_eq!(vless.flow, "");
        assert_eq!(vless.transport.kind, VlessTransportKind::WebSocket);
        assert_eq!(vless.transport.path, "/vless");
        assert_eq!(
            vless.transport.request_host("example.com"),
            "edge.example.com"
        );
        Ok(())
    }

    #[test]
    fn converts_vless_inline_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "tag": "vless-inline-server",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": 8443,
    "settings": {
      "decryption": "none",
      "clients": [
        { "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" }
      ]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificate": ["cert-line-1", "cert-line-2"],
          "key": ["key-line-1", "key-line-2"]
        }]
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.cert_path, PathBuf::new());
        assert_eq!(vless.key_path, PathBuf::new());
        assert_eq!(vless.certificates, vec!["cert-line-1\ncert-line-2"]);
        assert_eq!(vless.key.as_deref(), Some("key-line-1\nkey-line-2"));
        Ok(())
    }

    #[test]
    fn converts_vless_reality_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "tag": "vless-reality",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": 8443,
    "settings": {
      "decryption": "none",
      "clients": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" }]
    },
    "streamSettings": {
      "network": "grpc",
      "security": "reality",
      "realitySettings": {
        "dest": "www.example.com:443",
        "serverNames": ["front.example.com"],
        "privateKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "shortIds": ["a1b2"],
        "alpn": ["h2"]
      },
      "grpcSettings": {
        "serviceName": "TunService"
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        let reality = vless.reality.context("REALITY config")?;
        assert!(!vless.tls);
        assert_eq!(reality.server_name, "www.example.com");
        assert_eq!(reality.server_port, 443);
        assert_eq!(reality.server_names, vec!["front.example.com".to_string()]);
        assert_eq!(reality.short_ids[0], [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reality.alpn_protocols, vec![b"h2".to_vec()]);
        assert_eq!(vless.transport.kind, VlessTransportKind::Grpc);
        assert_eq!(vless.transport.path, "/TunService/Tun");
        Ok(())
    }

    #[test]
    fn converts_vmess_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "tag": "vmess-tls",
    "protocol": "vmess",
    "listen": "127.0.0.1",
    "port": 9443,
    "settings": {
      "clients": [
        { "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "alterId": 0 },
        { "id": "433722e1-0f8c-4724-9089-d5bc6d0c51ef" }
      ]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{ "certificateFile": "server.crt", "keyFile": "server.key" }]
      },
      "wsSettings": { "path": "/vmess" }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayServerConfig::Vmess(vmess) = config.inbounds[0].to_server_config()? else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.listen, "127.0.0.1:9443".parse()?);
        assert!(vmess.tls);
        assert_eq!(vmess.cert_path, Some(PathBuf::from("server.crt")));
        assert_eq!(vmess.key_path, Some(PathBuf::from("server.key")));
        assert_eq!(vmess.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(
            vmess.users,
            vec!["433722e1-0f8c-4724-9089-d5bc6d0c51ef".to_string()]
        );
        assert_eq!(vmess.transport.kind, VlessTransportKind::WebSocket);
        assert_eq!(vmess.transport.path, "/vmess");
        Ok(())
    }

    #[test]
    fn converts_trojan_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "tag": "trojan-tls",
    "protocol": "trojan",
    "listen": "127.0.0.1",
    "port": 9444,
    "settings": {
      "clients": [
        { "password": "primary-pass" },
        { "password": "alice-pass" }
      ]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{ "certificateFile": "server.crt", "keyFile": "server.key" }]
      },
      "wsSettings": { "path": "/trojan" }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayServerConfig::Trojan(trojan) = config.inbounds[0].to_server_config()? else {
            bail!("expected Trojan")
        };
        assert_eq!(trojan.listen, "127.0.0.1:9444".parse()?);
        assert_eq!(trojan.password, "primary-pass");
        assert_eq!(trojan.users, vec!["alice-pass".to_string()]);
        assert_eq!(trojan.cert_path, PathBuf::from("server.crt"));
        assert_eq!(trojan.key_path, PathBuf::from("server.key"));
        assert_eq!(trojan.transport.kind, VlessTransportKind::WebSocket);
        assert_eq!(trojan.transport.path, "/trojan");
        Ok(())
    }

    #[test]
    fn converts_shadowsocks_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "tag": "ss",
    "protocol": "shadowsocks",
    "listen": "127.0.0.1",
    "port": 8388,
    "settings": {
      "method": "aes-128-gcm",
      "password": "secret",
      "network": "tcp,udp"
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayServerConfig::Shadowsocks(shadowsocks) = config.inbounds[0].to_server_config()?
        else {
            bail!("expected Shadowsocks")
        };
        assert_eq!(shadowsocks.listen, "127.0.0.1:8388".parse()?);
        assert_eq!(shadowsocks.method, "aes-128-gcm");
        assert_eq!(shadowsocks.password, "secret");
        assert!(shadowsocks.tcp);
        assert!(shadowsocks.udp);
        Ok(())
    }

    #[test]
    fn converts_hysteria2_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [{
    "tag": "hy2",
    "protocol": "hysteria",
    "listen": "127.0.0.1",
    "port": 8445,
    "settings": {
      "version": 2,
      "users": [
        { "auth": "primary-pass" },
        { "auth": "alice-pass" }
      ]
    },
    "streamSettings": {
      "network": "hysteria",
      "security": "tls",
      "tlsSettings": {
        "alpn": ["h3"],
        "certificates": [{ "certificateFile": "server.crt", "keyFile": "server.key" }]
      },
      "hysteriaSettings": {
        "version": 2
      },
      "finalmask": {
        "udp": [{
          "type": "salamander",
          "settings": { "password": "obfs-pass" }
        }],
        "quicParams": {
          "congestion": "reno",
          "brutalUp": "20mbps",
          "brutalDown": "80mbps"
        }
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayServerConfig::Hysteria2(hy2) = config.inbounds[0].to_server_config()? else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hy2.listen, "127.0.0.1:8445".parse()?);
        assert_eq!(hy2.password, "primary-pass");
        assert_eq!(hy2.users, vec!["alice-pass".to_string()]);
        assert_eq!(hy2.cert_path, PathBuf::from("server.crt"));
        assert_eq!(hy2.key_path, PathBuf::from("server.key"));
        assert_eq!(hy2.obfs.as_deref(), Some("salamander"));
        assert_eq!(hy2.obfs_password.as_deref(), Some("obfs-pass"));
        assert_eq!(hy2.upload_bandwidth, Some(20));
        assert_eq!(hy2.cc_rx, "10000000");
        assert_eq!(hy2.congestion_control, "reno");
        assert!(hy2.udp);
        Ok(())
    }

    #[test]
    fn parses_vless_raw_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "vless-raw",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 80,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": { "network": "tcp", "security": "none" }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Vless(vless) =
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
    fn parses_vmess_tls_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "vmess-tls",
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{
          "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
          "alterId": 0,
          "packetEncoding": "packetaddr"
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "vmess.example.com",
        "disableSystemRoot": true,
        "pinnedPeerCertSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "certificates": [
          { "usage": "verify", "certificateFile": "vmess-ca.pem" },
          { "usage": "verify", "certificate": ["vmess-inline-ca"] },
          { "usage": "encipherment", "certificateFile": "ignored-ca.pem" }
        ]
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Vmess(vmess) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VMess")
        };
        assert!(vmess.tls);
        assert_eq!(vmess.sni, "vmess.example.com");
        assert_eq!(vmess.ca_cert_paths, vec![PathBuf::from("vmess-ca.pem")]);
        assert_eq!(vmess.ca_certificates, vec!["vmess-inline-ca"]);
        assert!(vmess.disable_system_roots);
        assert_eq!(
            vmess.pinned_cert_sha256,
            vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        );
        Ok(())
    }

    #[test]
    fn parses_vmess_websocket_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "vmess-ws",
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 80,
        "users": [{
          "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
          "alterId": 0,
          "packetEncoding": "packetaddr"
        }]
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "none",
      "wsSettings": {
        "path": "/vmess",
        "headers": { "Host": "edge.example.com" }
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Vmess(vmess) =
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
    "tag": "vmess-xudp",
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 80,
        "users": [{
          "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
          "alterId": 0,
          "packetEncoding": "xudp"
        }]
      }]
    },
    "streamSettings": { "network": "tcp", "security": "none" }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Vmess(vmess) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.packet_encoding, "xudp");
        Ok(())
    }

    #[test]
    fn parses_hysteria2_transport_profile() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "hy2",
    "protocol": "hysteria",
    "settings": {
      "version": 2,
      "address": "example.com",
      "port": 443
    },
    "streamSettings": {
      "network": "hysteria",
      "security": "tls",
      "tlsSettings": {
        "serverName": "hy2.example.com",
        "allowInsecure": true,
        "disableSystemRoot": true,
        "alpn": ["h3"],
        "certificates": [
          { "usage": "verify", "certificateFile": "hy2-ca.pem" },
          { "usage": "verify", "certificate": ["hy2-inline-ca"] }
        ]
      },
      "hysteriaSettings": {
        "version": 2,
        "auth": "secret"
      },
      "finalmask": {
        "udp": [{
          "type": "salamander",
          "settings": { "password": "obfs-pass" }
        }],
        "quicParams": {
          "congestion": "reno",
          "brutalUp": "10mbps",
          "brutalDown": "80mbps"
        }
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Hysteria2(hysteria2) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hysteria2.server_host, "example.com");
        assert_eq!(hysteria2.server_port, 443);
        assert_eq!(hysteria2.password, "secret");
        assert_eq!(hysteria2.sni, "hy2.example.com");
        assert!(hysteria2.insecure);
        assert_eq!(hysteria2.ca_cert_paths, vec![PathBuf::from("hy2-ca.pem")]);
        assert_eq!(hysteria2.ca_certificates, vec!["hy2-inline-ca"]);
        assert!(hysteria2.disable_system_roots);
        assert_eq!(hysteria2.obfs.as_deref(), Some("salamander"));
        assert_eq!(hysteria2.obfs_password.as_deref(), Some("obfs-pass"));
        assert_eq!(hysteria2.upload_bandwidth, Some(10));
        assert_eq!(hysteria2.download_bandwidth, Some(80));
        assert_eq!(hysteria2.congestion_control, "reno");
        Ok(())
    }

    #[test]
    fn parses_hysteria2_upload_bandwidth_and_rejects_unmapped_quic_options() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "tag": "hy2-up",
      "protocol": "hysteria",
      "settings": {
        "version": 2,
        "address": "example.com",
        "port": 443
      },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "hysteriaSettings": {
          "version": 2,
          "auth": "secret",
          "up": "10mbps"
        }
      }
    },
    {
      "tag": "hy2-brutal-up",
      "protocol": "hysteria",
      "settings": {
        "version": 2,
        "address": "example.com",
        "port": 443
      },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "hysteriaSettings": {
          "version": 2,
          "auth": "secret"
        },
        "finalmask": {
          "quicParams": {
            "brutalUp": "10mbps"
          }
        }
      }
    },
    {
      "tag": "hy2-bbr-profile",
      "protocol": "hysteria",
      "settings": {
        "version": 2,
        "address": "example.com",
        "port": 443
      },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "hysteriaSettings": {
          "version": 2,
          "auth": "secret"
        },
        "finalmask": {
          "quicParams": {
            "bbrProfile": "aggressive"
          }
        }
      }
    }
  ]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Hysteria2(up) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Hysteria2")
        };
        assert_eq!(up.upload_bandwidth, Some(10));
        let XrayClientConfig::Hysteria2(brutal_up) =
            config.outbounds[1].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Hysteria2")
        };
        assert_eq!(brutal_up.upload_bandwidth, Some(10));
        let bbr_profile_error = config.outbounds[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("bbrProfile must be explicit");
        assert!(bbr_profile_error.to_string().contains("bbrProfile"));
        Ok(())
    }

    #[test]
    fn parses_trojan_websocket_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "trojan-ws",
    "protocol": "trojan",
    "settings": {
      "servers": [{ "address": "example.com", "port": 443, "password": "secret" }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {
        "path": "/trojan",
        "headers": { "Host": "edge.example.com" }
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Trojan(trojan) =
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
    fn parses_vless_websocket_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "vless-ws",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {
        "path": "/vless",
        "headers": { "Host": "edge.example.com" }
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Vless(vless) =
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
    fn parses_vless_http2_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "vless-h2",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "h2",
      "security": "tls",
      "tlsSettings": { "alpn": ["h2"] },
      "httpSettings": {
        "path": "/h2",
        "host": ["edge.example.com"]
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Vless(vless) =
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
    "tag": "vless-grpc",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "grpc",
      "security": "tls",
      "tlsSettings": { "alpn": ["h2"] },
      "grpcSettings": {
        "serviceName": "TunService",
        "authority": "edge.example.com"
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Vless(vless) =
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
    "tag": "vless-xhttp",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": { "alpn": ["http/1.1"] },
      "xhttpSettings": {
        "path": "/xhttp",
        "host": ["edge.example.com"],
        "mode": "stream-one"
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Vless(vless) =
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
    fn rejects_xray_unsupported_stream_settings() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "direct-out",
    "protocol": "freedom",
    "streamSettings": {
      "network": "tcp",
      "tcpSettings": {
        "acceptProxyProtocol": false,
        "header": { "type": "none" }
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Route(route) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected route client")
        };
        assert_eq!(route.default, RouteDecision::Direct);

        let json = r#"
{
  "outbounds": [{
    "tag": "http-proxy",
    "protocol": "http",
    "settings": {
      "address": "proxy.example.com",
      "port": 8443
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tcpSettings": {
        "header": { "type": "http" }
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("raw TCP header options must not be ignored");
        assert!(error.to_string().contains("streamSettings"));
        assert!(error.to_string().contains("tcpSettings"));

        let json = r#"
{
  "outbounds": [{
    "tag": "direct-out",
    "protocol": "freedom",
    "streamSettings": {
      "sockopt": { "interface": "eth0" }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("socket options must not be ignored");
        assert!(error.to_string().contains("sockopt"));
        assert!(error.to_string().contains("socket option"));

        let json = r#"
{
  "outbounds": [{
    "tag": "direct-out",
    "protocol": "freedom",
    "streamSettings": {
      "unknownStreamField": true
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unknown streamSettings fields must not be ignored");
        assert!(error.to_string().contains("unsupported fields"));
        assert!(error.to_string().contains("unknownStreamField"));
        Ok(())
    }

    #[test]
    fn rejects_xray_unsupported_profile_fields() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "tag": "vless-send-through",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
        }]
      },
      "streamSettings": { "network": "tcp", "security": "none" },
      "sendThrough": "192.0.2.1"
    },
    {
      "tag": "vless-user-email",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{
            "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
            "encryption": "none",
            "email": "user@example.com"
          }]
        }]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    {
      "tag": "vless-ws-extra",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
        }]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/ws",
          "maxEarlyData": 2048
        }
      }
    },
    {
      "tag": "ss-mux-fields",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{
          "address": "ss.example.com",
          "port": 8388,
          "method": "aes-128-gcm",
          "password": "secret"
        }]
      },
      "mux": {
        "enabled": false,
        "concurrency": 8
      }
    }
  ],
  "inbounds": [
    {
      "tag": "trojan-sniffing",
      "protocol": "trojan",
      "sniffing": { "enabled": true }
    },
    {
      "tag": "hy2-mask-extra",
      "protocol": "hysteria2",
      "streamSettings": {
        "network": "hysteria",
        "finalmask": {
          "udp": [{
            "type": "salamander",
            "settings": {
              "password": "obfs-pass",
              "padding": true
            }
          }]
        }
      }
    }
  ]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let top_level_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported xray outbound fields must not be ignored");
        assert!(top_level_error.to_string().contains("sendThrough"));

        let user_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported xray user fields must not be ignored");
        assert!(user_error.to_string().contains("users[0]"));
        assert!(user_error.to_string().contains("email"));

        let ws_error = config.outbounds[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported xray wsSettings fields must not be ignored");
        assert!(ws_error.to_string().contains("wsSettings"));
        assert!(ws_error.to_string().contains("maxEarlyData"));

        let mux_error = config.outbounds[3]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("disabled mux settings must not be ignored");
        assert!(mux_error.to_string().contains("mux"));
        assert!(mux_error.to_string().contains("concurrency"));

        let inbound_error = config.inbounds[0]
            .to_server_config()
            .err()
            .context("unsupported xray inbound fields must not be ignored")?;
        assert!(inbound_error.to_string().contains("sniffing"));

        let mask_error = config.inbounds[1]
            .to_server_config()
            .err()
            .context("unsupported xray finalmask settings must not be ignored")?;
        assert!(mask_error.to_string().contains("finalmask"));
        assert!(mask_error.to_string().contains("padding"));
        Ok(())
    }

    #[test]
    fn rejects_xray_unsupported_tls_settings() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "http-proxy",
    "protocol": "http",
    "settings": {
      "address": "proxy.example.com",
      "port": 8443
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "minVersion": "1.2"
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("TLS version policy must not be ignored");
        assert!(error.to_string().contains("tlsSettings"));
        assert!(error.to_string().contains("minVersion"));
        assert!(error.to_string().contains("TLS version policy"));

        let json = r#"
{
  "outbounds": [{
    "tag": "http-proxy",
    "protocol": "http",
    "settings": {
      "address": "proxy.example.com",
      "port": 8443
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "disableSystemRoot": true,
        "certificates": [{
          "usage": "verify",
          "certificate": ["ca-line"],
          "oneTimeLoading": true
        }]
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("certificate loading policy must not be ignored");
        assert!(error.to_string().contains("certificates[0]"));
        assert!(error.to_string().contains("oneTimeLoading"));

        let json = r#"
{
  "inbounds": [{
    "tag": "vless-server",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": 8443,
    "settings": {
      "decryption": "none",
      "clients": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "rejectUnknownSni": true
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config.inbounds[0]
            .to_server_config()
            .err()
            .context("SNI rejection policy must not be ignored")?;
        assert!(error.to_string().contains("rejectUnknownSni"));
        assert!(error.to_string().contains("SNI-based server rejection"));

        let json = r#"
{
  "outbounds": [{
    "tag": "direct-out",
    "protocol": "freedom",
    "streamSettings": {
      "tlsSettings": {
        "unknownTlsOption": true
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unknown tlsSettings fields must not be ignored");
        assert!(error.to_string().contains("unsupported fields"));
        assert!(error.to_string().contains("unknownTlsOption"));
        Ok(())
    }

    #[test]
    fn converts_http_outbound_to_client_config() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "tag": "http-proxy",
    "protocol": "http",
    "settings": {
      "address": "proxy.example.com",
      "port": 8443,
      "user": "user",
      "pass": "pass",
      "headers": {
        "X-Test": "value"
      }
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "front.example.com",
        "allowInsecure": true,
        "fingerprint": "chrome",
        "alpn": ["http/1.1"]
      }
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::HttpProxy(http) =
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
  "outbounds": [{
    "tag": "socks-proxy",
    "protocol": "socks",
    "settings": {
      "servers": [{
        "address": "proxy.example.com",
        "port": 1080,
        "users": [{
          "user": "user",
          "pass": "pass"
        }]
      }],
      "network": "tcp+udp"
    }
  }]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::SocksProxy(socks) =
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
    {
      "tag": "direct-out",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "blackhole-out",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        let XrayClientConfig::Route(direct) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected direct route client")
        };
        assert_eq!(direct.default, RouteDecision::Direct);
        let XrayClientConfig::Route(blackhole) =
            config.outbounds[1].to_client_config("127.0.0.1:1081".parse()?)?
        else {
            bail!("expected blackhole route client")
        };
        assert_eq!(blackhole.default, RouteDecision::Block);
        Ok(())
    }
}
