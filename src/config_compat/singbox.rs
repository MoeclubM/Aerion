use crate::client::ClientConfig;
use crate::config_compat::mihomo::OneOrManyStrings;
use crate::hysteria2::Hysteria2ClientConfig;
use crate::naive::NaiveClientConfig;
use crate::padding::PaddingScheme;
use crate::reality::RealityClientConfig;
use crate::shadowsocks::ShadowsocksClientConfig;
use crate::trojan::TrojanClientConfig;
use crate::tuic::TuicClientConfig;
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::VlessClientConfig;
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::{VmessClientConfig, ensure_vmess_packet_encoding};
use anyhow::{Context, Result, bail, ensure};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxConfig {
    #[serde(default)]
    pub inbounds: Vec<SingBoxInbound>,
    #[serde(default)]
    pub outbounds: Vec<SingBoxOutbound>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxInbound {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default, rename = "listen_port")]
    pub listen_port: Option<u16>,
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxAnyTlsOutbound {
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub password: String,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
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
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxTlsOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, rename = "server_name")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Option<OneOrManyStrings>,
    #[serde(default)]
    pub utls: Option<SingBoxUtlsOptions>,
    #[serde(default)]
    pub reality: Option<SingBoxRealityOptions>,
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
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxRealityOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, rename = "public_key")]
    pub public_key: Option<String>,
    #[serde(default, rename = "short_id")]
    pub short_id: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SingBoxMultiplexOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: Option<String>,
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SingBoxHysteria2Obfs {
    #[serde(rename = "type")]
    pub kind: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub enum SingBoxClientConfig {
    Shadowsocks(ShadowsocksClientConfig),
    Vless(VlessClientConfig),
    Vmess(VmessClientConfig),
    Trojan(TrojanClientConfig),
    Hysteria2(Hysteria2ClientConfig),
    AnyTls(ClientConfig),
    Naive(NaiveClientConfig),
    Tuic(TuicClientConfig),
}

impl SingBoxConfig {
    pub fn outbound(&self, tag: &str) -> Option<&SingBoxOutbound> {
        self.outbounds
            .iter()
            .find(|outbound| outbound.tag.as_deref() == Some(tag))
    }

    pub fn local_socks_listen(&self) -> Result<Option<SocketAddr>> {
        let Some(inbound) = self.inbounds.iter().find(|inbound| {
            inbound.kind.eq_ignore_ascii_case("socks") || inbound.kind.eq_ignore_ascii_case("mixed")
        }) else {
            return Ok(None);
        };
        let port = inbound.listen_port.with_context(|| {
            format!("sing-box inbound {} is missing listen_port", inbound.name())
        })?;
        let host = inbound.listen.as_deref().unwrap_or("0.0.0.0");
        Ok(Some(SocketAddr::new(
            parse_listen_ip("sing-box", host)?,
            port,
        )))
    }
}

impl SingBoxInbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.kind)
    }
}

impl SingBoxOutbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.kind)
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<SingBoxClientConfig> {
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "shadowsocks" | "ss" => Ok(SingBoxClientConfig::Shadowsocks(
                self.decode::<SingBoxShadowsocksOutbound>()?
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

impl SingBoxShadowsocksOutbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<ShadowsocksClientConfig> {
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure!(
            self.plugin.is_none() && self.plugin_opts.is_none(),
            "sing-box Shadowsocks outbound {name} sets SIP003 plugin; Aerion Shadowsocks does not implement plugins"
        );
        let udp_over_tcp = value_bool_or_object(self.udp_over_tcp.as_ref());
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

impl SingBoxVlessOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<VlessClientConfig> {
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
        ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
        Ok(TrojanClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
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
            self.up_mbps.unwrap_or(0) == 0,
            "sing-box Hysteria2 outbound {name} sets up_mbps; Aerion Hysteria2 client does not expose upload bandwidth"
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
        ensure_hy2_alpn("sing-box", name, tls.alpn.as_ref())?;
        let (obfs, obfs_password) = match &self.obfs {
            Some(obfs) => {
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
            obfs,
            obfs_password,
            download_bandwidth: self.down_mbps.or(self.down),
            udp: network_allows_udp(self.network.as_deref()),
            congestion_control: "bbr".to_string(),
        })
    }
}

impl SingBoxAnyTlsOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<ClientConfig> {
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box AnyTLS outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box AnyTLS outbound {name} disables TLS; AnyTLS requires TLS"
        );
        Ok(ClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
        })
    }
}

impl SingBoxNaiveOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<NaiveClientConfig> {
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box Naive outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box Naive outbound {name} disables TLS; Naive requires HTTPS/TLS"
        );
        Ok(NaiveClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            extra_headers: self.extra_headers.clone().into_iter().collect(),
            udp_over_tcp: value_bool_or_object(self.udp_over_tcp.as_ref()),
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
        })
    }
}

impl SingBoxTuicOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<TuicClientConfig> {
        ensure_supported_network("sing-box", name, self.network.as_deref())?;
        ensure!(
            !self.zero_rtt_handshake,
            "sing-box TUIC outbound {name} enables zero_rtt_handshake; Aerion TUIC client does not expose 0-RTT handshakes"
        );
        ensure!(
            !value_bool_or_object(self.udp_over_stream.as_ref()),
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
        ensure_tuic_alpn("sing-box", name, tls.alpn.as_ref())?;
        Ok(TuicClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            uuid: self.uuid.clone(),
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
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
                reality.public_key.is_none() && reality.short_id.is_none(),
                "sing-box outbound {name} sets REALITY fields while reality.enabled is false"
            );
            return Ok(None);
        }
        Ok(Some(RealityClientConfig::from_strings(
            reality.public_key.as_deref().with_context(|| {
                format!("sing-box REALITY outbound {name} is missing public_key")
            })?,
            reality.short_id.as_deref().unwrap_or_default(),
        )?))
    }
}

fn ensure_disabled_utls(name: &str, tls: &SingBoxTlsOptions) -> Result<()> {
    ensure!(
        tls.utls
            .as_ref()
            .is_none_or(|utls| !utls.enabled && utls.fingerprint.is_none()),
        "sing-box outbound {name} sets uTLS but this Aerion transport does not implement uTLS"
    );
    Ok(())
}

fn ensure_disabled_reality(name: &str, tls: &SingBoxTlsOptions) -> Result<()> {
    ensure!(
        tls.reality.as_ref().is_none_or(|reality| {
            !reality.enabled && reality.public_key.is_none() && reality.short_id.is_none()
        }),
        "sing-box outbound {name} sets REALITY but TLS is disabled"
    );
    Ok(())
}

fn ensure_supported_network(format: &str, name: &str, network: Option<&str>) -> Result<()> {
    let network = network.unwrap_or_default().trim();
    ensure!(
        network.is_empty()
            || network.eq_ignore_ascii_case("tcp")
            || network.eq_ignore_ascii_case("udp"),
        "{format} outbound {name} uses network {network}; Aerion supports sing-box tcp or udp network selection"
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

fn network_allows_udp(network: Option<&str>) -> bool {
    !network
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("tcp")
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
                .with_context(|| format!("parse {format} VLESS outbound {name} transport"))?;
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
        bail!("{format} VLESS outbound {name} transport must be an object");
    }
    VlessTransportConfig::from_network(network, None, None, Vec::new())
}

fn ensure_multiplex_disabled(
    format: &str,
    name: &str,
    multiplex: Option<&SingBoxMultiplexOptions>,
) -> Result<()> {
    ensure!(
        !multiplex
            .map(|multiplex| multiplex.enabled)
            .unwrap_or(false),
        "{format} outbound {name} enables multiplex; Aerion VLESS mux.cool is not wire-compatible with sing-box multiplex"
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

fn alpn_values(alpn: Option<&OneOrManyStrings>) -> Vec<String> {
    alpn.map(OneOrManyStrings::to_vec)
        .unwrap_or_default()
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn value_bool_or_object(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::Object(_)) => true,
        _ => false,
    }
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
mod tests {
    use super::*;

    #[test]
    fn parses_shadowsocks_udp_over_tcp_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "shadowsocks",
    "tag": "ss-uot",
    "server": "example.com",
    "server_port": 8388,
    "method": "aes-128-gcm",
    "password": "secret",
    "network": "tcp",
    "udp_over_tcp": { "enabled": true }
  }]
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
    "down_mbps": 80,
    "tls": {
      "enabled": true,
      "server_name": "hy2.example.com",
      "insecure": true,
      "alpn": ["h3"]
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
        assert!(hysteria2.udp);
        assert_eq!(hysteria2.obfs.as_deref(), Some("salamander"));
        assert_eq!(hysteria2.obfs_password.as_deref(), Some("obfs-pass"));
        assert_eq!(hysteria2.download_bandwidth, Some(80));
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
    fn rejects_hysteria2_upload_bandwidth() -> Result<()> {
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
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("up_mbps must be explicit");
        assert!(error.to_string().contains("up_mbps"));
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
      "udp_over_tcp": { "enabled": true },
      "tls": {
        "enabled": true,
        "server_name": "front.example.com",
        "insecure": true
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
        "alpn": ["h3"]
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
        assert!(naive.insecure);
        assert!(naive.quic);
        assert!(naive.udp_over_tcp);

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
}
