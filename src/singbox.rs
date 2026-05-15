use crate::hysteria2::Hysteria2ClientConfig;
use crate::mihomo::OneOrManyStrings;
use crate::reality::RealityClientConfig;
use crate::shadowsocks::ShadowsocksClientConfig;
use crate::trojan::TrojanClientConfig;
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use crate::vless::VlessClientConfig;
use crate::vless_transport::{VlessTransportConfig, VlessTransportKind};
use crate::vmess::VmessClientConfig;
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
    pub server: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub password: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub tls: Option<SingBoxTlsOptions>,
    #[serde(default)]
    pub obfs: Option<SingBoxHysteria2Obfs>,
    #[serde(default, rename = "down_mbps")]
    pub down_mbps: Option<u64>,
    #[serde(default, rename = "down")]
    pub down: Option<u64>,
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
        ensure!(
            self.udp_over_tcp.is_none(),
            "sing-box Shadowsocks outbound {name} sets udp_over_tcp; Aerion Shadowsocks does not implement UDP-over-TCP"
        );
        Ok(ShadowsocksClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            method: self.method.clone(),
            password: self.password.clone(),
            udp: network_allows_udp(self.network.as_deref()),
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
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box VLESS outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box VLESS outbound {name} disables TLS; Aerion VLESS client currently requires TLS"
        );
        ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
        Ok(VlessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            user_id: self.uuid.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            flow: self.flow.clone(),
            packet_encoding: self
                .packet_encoding
                .clone()
                .unwrap_or_else(|| "xudp".to_string()),
            mux: false,
            udp: network_allows_udp(self.network.as_deref()),
            client_fingerprint: tls.utls_fingerprint(name)?,
            reality: tls.reality_client_config(name)?,
            transport,
        })
    }
}

impl SingBoxVmessOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<VmessClientConfig> {
        ensure_transport_is_raw("sing-box", name, self.transport.as_ref())?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure_tcp_network("sing-box", name, self.network.as_deref())?;
        ensure!(
            self.alter_id == 0,
            "sing-box VMess outbound {name} uses legacy alter_id {}; Aerion implements AEAD VMess only",
            self.alter_id
        );
        ensure!(
            self.packet_encoding
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty(),
            "sing-box VMess outbound {name} sets packet_encoding; Aerion VMess UDP uses VMess chunk stream and does not expose this switch"
        );
        if let Some(tls) = &self.tls {
            if tls.enabled {
                ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
            } else {
                ensure_disabled_utls(name, tls)?;
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
            udp: network_allows_udp(self.network.as_deref()),
            tls: tls_enabled,
            sni: sni_or_server(server_name, &self.server),
            insecure: self.tls.as_ref().map(|tls| tls.insecure).unwrap_or(false),
            client_fingerprint: self
                .tls
                .as_ref()
                .map(|tls| tls.utls_fingerprint(name))
                .transpose()?
                .flatten(),
        })
    }
}

impl SingBoxTrojanOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<TrojanClientConfig> {
        ensure_transport_is_raw("sing-box", name, self.transport.as_ref())?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure_tcp_network("sing-box", name, self.network.as_deref())?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box Trojan outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box Trojan outbound {name} disables TLS; Trojan requires TLS in Aerion"
        );
        ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
        Ok(TrojanClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            udp: network_allows_udp(self.network.as_deref()),
            client_fingerprint: tls.utls_fingerprint(name)?,
        })
    }
}

impl SingBoxHysteria2Outbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<Hysteria2ClientConfig> {
        ensure_tcp_network("sing-box", name, self.network.as_deref())?;
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
            server_host: self.server.clone(),
            server_port: self.server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            obfs,
            obfs_password,
            download_bandwidth: self.down_mbps.or(self.down),
            udp: network_allows_udp(self.network.as_deref()),
            congestion_control: "bbr".to_string(),
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

fn ensure_tcp_network(format: &str, name: &str, network: Option<&str>) -> Result<()> {
    let network = network.unwrap_or_default().trim();
    ensure!(
        network.is_empty() || network.eq_ignore_ascii_case("tcp"),
        "{format} outbound {name} uses network {network}; this Aerion local client requires TCP-capable relay"
    );
    Ok(())
}

fn network_allows_udp(network: Option<&str>) -> bool {
    !network
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("tcp")
}

fn ensure_transport_is_raw(format: &str, name: &str, transport: Option<&Value>) -> Result<()> {
    if let Some(Value::Object(map)) = transport {
        ensure!(
            map.is_empty(),
            "{format} outbound {name} sets transport; Aerion currently wires raw TCP transport only"
        );
    }
    ensure!(
        transport.is_none() || matches!(transport, Some(Value::Object(map)) if map.is_empty()),
        "{format} outbound {name} sets transport; Aerion currently wires raw TCP transport only"
    );
    Ok(())
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
}
