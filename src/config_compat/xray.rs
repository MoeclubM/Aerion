use crate::config_compat::mihomo::OneOrManyStrings;
use crate::hysteria2::Hysteria2ClientConfig;
use crate::reality::{RealityClientConfig, RealityServerConfig};
use crate::shadowsocks::ShadowsocksClientConfig;
use crate::trojan::TrojanClientConfig;
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::{VlessClientConfig, VlessServerConfig};
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::{VmessClientConfig, ensure_vmess_packet_encoding};
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
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XrayOutbound {
    pub tag: Option<String>,
    pub protocol: String,
    pub settings: XrayOutboundSettings,
    pub stream_settings: XrayStreamSettings,
    pub mux: Option<XrayMuxOptions>,
    pub decode_error: Option<String>,
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
    #[serde(default)]
    pub clients: Vec<XrayUser>,
    #[serde(default)]
    pub fallbacks: Vec<Value>,
    #[serde(default)]
    pub vnext: Vec<XrayVnext>,
    #[serde(default)]
    pub servers: Vec<XrayServer>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct XrayVnext {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub users: Vec<XrayUser>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayUser {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
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
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayServer {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct XrayStreamSettings {
    #[serde(default = "default_tcp_network")]
    pub network: String,
    #[serde(default)]
    pub security: String,
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
}

impl Default for XrayStreamSettings {
    fn default() -> Self {
        Self {
            network: default_tcp_network(),
            security: String::new(),
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
        }
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
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayFinalMask {
    #[serde(default)]
    pub tcp: Vec<XrayMask>,
    #[serde(default)]
    pub udp: Vec<XrayMask>,
    #[serde(default, rename = "quicParams", alias = "quic_params")]
    pub quic_params: Option<XrayQuicParams>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct XrayMask {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub settings: Option<Value>,
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
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayWsSettings {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayHttpUpgradeSettings {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayGrpcSettings {
    #[serde(default, rename = "serviceName", alias = "service_name")]
    pub service_name: Option<String>,
    #[serde(default)]
    pub authority: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayHttpSettings {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<OneOrManyStrings>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
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
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayTlsSettings {
    #[serde(default, rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
    #[serde(default, rename = "allowInsecure", alias = "allow_insecure")]
    pub allow_insecure: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_fingerprint",
        alias = "clientFingerprint",
        alias = "client_fingerprint"
    )]
    pub fingerprint: Option<UtlsFingerprint>,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default)]
    pub certificates: Vec<XrayCertificate>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayCertificate {
    #[serde(default, rename = "certificateFile", alias = "certificate_file")]
    pub certificate_file: Option<PathBuf>,
    #[serde(default, rename = "keyFile", alias = "key_file")]
    pub key_file: Option<PathBuf>,
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
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayMuxOptions {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub enum XrayClientConfig {
    Shadowsocks(ShadowsocksClientConfig),
    Vless(VlessClientConfig),
    Vmess(VmessClientConfig),
    Trojan(TrojanClientConfig),
    Hysteria2(Hysteria2ClientConfig),
}

pub enum XrayServerConfig {
    Vless(VlessServerConfig),
}

struct XrayServerUser {
    address: String,
    port: u16,
    user: XrayUser,
}

impl XrayConfig {
    pub fn outbound(&self, tag: &str) -> Option<&XrayOutbound> {
        self.outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
    }

    pub fn local_socks_listen(&self) -> Result<Option<SocketAddr>> {
        let Some(inbound) = self
            .inbounds
            .iter()
            .find(|inbound| inbound.protocol.eq_ignore_ascii_case("socks"))
        else {
            return Ok(None);
        };
        let port = inbound.port.context("xray socks inbound is missing port")?;
        let host = inbound.listen.as_deref().unwrap_or("0.0.0.0");
        Ok(Some(SocketAddr::new(parse_listen_ip("xray", host)?, port)))
    }
}

impl XrayInbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.protocol)
    }

    pub fn to_server_config(&self) -> Result<XrayServerConfig> {
        match self.protocol.trim().to_ascii_lowercase().as_str() {
            "vless" => Ok(XrayServerConfig::Vless(
                self.to_vless_server_config()
                    .with_context(|| format!("convert xray VLESS inbound {}", self.name()))?,
            )),
            other => bail!(
                "unsupported xray inbound {} protocol {}; Aerion cannot run this inbound protocol as a server",
                self.name(),
                other
            ),
        }
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
        let (cert_path, key_path) = if stream_security.eq_ignore_ascii_case("tls") {
            let certificate = tls
                .and_then(|tls| tls.certificates.first())
                .context("xray VLESS inbound TLS is missing certificates")?;
            (
                certificate
                    .certificate_file
                    .clone()
                    .context("xray VLESS inbound TLS certificate is missing certificateFile")?,
                certificate
                    .key_file
                    .clone()
                    .context("xray VLESS inbound TLS certificate is missing keyFile")?,
            )
        } else {
            (PathBuf::new(), PathBuf::new())
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
            flow,
            reality,
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
        match self.protocol.trim().to_ascii_lowercase().as_str() {
            "shadowsocks" | "ss" => Ok(XrayClientConfig::Shadowsocks(
                self.to_shadowsocks_client_config(listen)?,
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

    fn to_vless_client_config(&self, listen: SocketAddr) -> Result<VlessClientConfig> {
        let peer = self.first_vless_or_vmess_peer()?;
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
            mux: self.mux.as_ref().map(|mux| mux.enabled).unwrap_or(false),
            udp: true,
            client_fingerprint,
            reality,
            transport,
        })
    }

    fn to_shadowsocks_client_config(&self, listen: SocketAddr) -> Result<ShadowsocksClientConfig> {
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
            client_fingerprint: if tls_enabled {
                tls.and_then(|settings| settings.fingerprint)
            } else {
                None
            },
            transport,
        })
    }

    fn to_trojan_client_config(&self, listen: SocketAddr) -> Result<TrojanClientConfig> {
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
            udp: true,
            client_fingerprint: tls.and_then(|settings| settings.fingerprint),
            transport,
        })
    }

    fn to_hysteria2_client_config(&self, listen: SocketAddr) -> Result<Hysteria2ClientConfig> {
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
            hysteria.and_then(|settings| settings.up).is_none(),
            "xray Hysteria outbound {} sets upload bandwidth; Aerion Hysteria2 client does not expose upload bandwidth",
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
                    .and_then(|params| params.brutal_up)
                    .is_none(),
                "xray Hysteria outbound {} sets finalmask brutalUp; Aerion Hysteria2 client does not expose upload bandwidth",
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
            obfs,
            obfs_password,
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
                encryption: None,
                flow: self.settings.flow.clone(),
                packet_encoding: self.settings.packet_encoding.clone(),
                security: self.settings.security.clone(),
                alter_id: self.settings.alter_id,
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

    #[test]
    fn parses_vless_reality_outbound() -> Result<()> {
        let json = r#"
{
  "inbounds": [{ "protocol": "socks", "listen": "127.0.0.1", "port": 1080 }],
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
    fn parses_xray_inbound_string_and_range_ports() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    { "tag": "range", "protocol": "vless", "listen": "0.0.0.0", "port": "10000-10100" },
    { "tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": "1080" }
  ],
  "outbounds": []
}
"#;
        let config: XrayConfig = serde_json::from_str(json)?;
        assert_eq!(config.inbounds[0].port, None);
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
        let XrayServerConfig::Vless(vless) = config.inbounds[0].to_server_config()?;
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
        let XrayServerConfig::Vless(vless) = config.inbounds[0].to_server_config()?;
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
    "streamSettings": { "network": "tcp", "security": "tls" }
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
        assert_eq!(vmess.sni, "example.com");
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
        "alpn": ["h3"]
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
        assert_eq!(hysteria2.obfs.as_deref(), Some("salamander"));
        assert_eq!(hysteria2.obfs_password.as_deref(), Some("obfs-pass"));
        assert_eq!(hysteria2.download_bandwidth, Some(80));
        assert_eq!(hysteria2.congestion_control, "reno");
        Ok(())
    }

    #[test]
    fn rejects_hysteria2_unmapped_quic_options() -> Result<()> {
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
        let up_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("upload bandwidth must be explicit");
        assert!(up_error.to_string().contains("upload bandwidth"));
        let brutal_up_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("brutalUp must be explicit");
        assert!(brutal_up_error.to_string().contains("brutalUp"));
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
}
