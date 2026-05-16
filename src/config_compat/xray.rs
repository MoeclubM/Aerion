use crate::config_compat::mihomo::OneOrManyStrings;
use crate::hysteria2::Hysteria2ClientConfig;
use crate::reality::RealityClientConfig;
use crate::shadowsocks::ShadowsocksClientConfig;
use crate::trojan::TrojanClientConfig;
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::VlessClientConfig;
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::{VmessClientConfig, ensure_vmess_packet_encoding};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub protocol: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayOutbound {
    #[serde(default)]
    pub tag: Option<String>,
    pub protocol: String,
    #[serde(default)]
    pub settings: XrayOutboundSettings,
    #[serde(default, rename = "streamSettings")]
    pub stream_settings: XrayStreamSettings,
    #[serde(default)]
    pub mux: Option<XrayMuxOptions>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayOutboundSettings {
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
    #[serde(default, rename = "alterId", alias = "alter_id")]
    pub alter_id: Option<u16>,
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
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct XrayRealitySettings {
    #[serde(default, rename = "serverName", alias = "server_name")]
    pub server_name: Option<String>,
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
    #[serde(default, rename = "shortId", alias = "short_id")]
    pub short_id: Option<String>,
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

impl XrayOutbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.protocol)
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<XrayClientConfig> {
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
            "hysteria2" | "hy2" => Ok(XrayClientConfig::Hysteria2(
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
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        ensure_tls_or_reality("xray Trojan", self.name(), &self.stream_settings.security)?;
        ensure!(
            !self.is_reality(),
            "xray Trojan outbound {} uses REALITY; Aerion only wires REALITY on VLESS",
            self.name()
        );
        ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
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
        })
    }

    fn to_hysteria2_client_config(&self, listen: SocketAddr) -> Result<Hysteria2ClientConfig> {
        let server = self.first_trojan_server()?;
        Ok(Hysteria2ClientConfig {
            listen,
            server_host: server.address.clone(),
            server_port: server.port,
            password: server.password.with_context(|| {
                format!(
                    "xray Hysteria2 outbound {} is missing password",
                    self.name()
                )
            })?,
            sni: sni_or_server(None, &server.address, self.name()),
            insecure: false,
            obfs: None,
            obfs_password: None,
            download_bandwidth: None,
            udp: true,
            congestion_control: "bbr".to_string(),
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

fn sni_or_server(value: Option<&str>, server: &str, name: &str) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| if server.is_empty() { name } else { server })
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
