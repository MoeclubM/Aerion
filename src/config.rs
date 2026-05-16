use crate::config_compat::mihomo::MihomoConfig;
use crate::config_compat::singbox::SingBoxConfig;
use crate::config_compat::xray::XrayConfig;
use crate::padding::PaddingScheme;
use crate::utls::{UtlsFingerprint, deserialize_optional_fingerprint};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum FileConfig {
    Client { client: ClientFileConfig },
    Server { server: ServerFileConfig },
    Aerion(AerionFileConfig),
    Mihomo(MihomoConfig),
    Xray(XrayConfig),
    SingBox(SingBoxConfig),
}

#[derive(Debug, Deserialize)]
struct TomlFileConfig {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    client: Option<ClientFileConfig>,
    #[serde(default)]
    server: Option<ServerFileConfig>,
    #[serde(default)]
    clients: Vec<ClientFileConfig>,
    #[serde(default)]
    servers: Vec<ServerFileConfig>,
}

#[derive(Debug)]
pub struct AerionFileConfig {
    pub clients: Vec<ClientFileConfig>,
    pub servers: Vec<ServerFileConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ClientFileConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub listen: SocketAddr,
    pub server: String,
    #[serde(default = "default_mieru_username")]
    pub username: String,
    #[serde(default, alias = "uuid", alias = "id", alias = "user-id")]
    pub user_id: Option<String>,
    pub password: String,
    pub sni: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default, alias = "cipher")]
    pub security: Option<String>,
    #[serde(default)]
    pub flow: String,
    #[serde(default, alias = "packet-encoding", alias = "packetEncoding")]
    pub packet_encoding: String,
    #[serde(default)]
    pub mux: bool,
    #[serde(
        default,
        alias = "client-fingerprint",
        alias = "clientFingerprint",
        deserialize_with = "deserialize_optional_fingerprint"
    )]
    pub client_fingerprint: Option<UtlsFingerprint>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(
        default,
        alias = "public-key",
        alias = "publicKey",
        alias = "reality-public-key",
        alias = "realityPublicKey"
    )]
    pub reality_public_key: Option<String>,
    #[serde(
        default,
        alias = "short-id",
        alias = "shortId",
        alias = "reality-short-id",
        alias = "realityShortId"
    )]
    pub reality_short_id: Option<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, alias = "obfs-password", alias = "obfsPassword")]
    pub obfs_password: Option<String>,
    #[serde(default, alias = "down", alias = "download", alias = "down-mbps")]
    pub download_bandwidth: Option<u64>,
    #[serde(default = "default_udp")]
    pub udp: bool,
    #[serde(default = "default_hy2_congestion_control")]
    pub congestion_control: String,
    #[serde(
        default = "default_tuic_udp_relay_mode",
        alias = "udp-relay-mode",
        alias = "udpRelayMode"
    )]
    pub udp_relay_mode: String,
    #[serde(default, alias = "alpn")]
    pub alpn_protocols: Vec<String>,
    #[serde(default = "PaddingScheme::default_lines")]
    pub padding_scheme: Vec<String>,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default)]
    pub mtu: usize,
    #[serde(default = "default_mieru_transport")]
    pub transport: String,
    #[serde(default, alias = "traffic-pattern", alias = "trafficPattern")]
    pub traffic_pattern: Option<String>,
    #[serde(default, alias = "nonce-pattern", alias = "noncePattern")]
    pub nonce_pattern: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServerFileConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub listen: SocketAddr,
    #[serde(default = "default_mieru_username")]
    pub username: String,
    #[serde(default, alias = "uuid", alias = "id", alias = "user-id")]
    pub user_id: Option<String>,
    pub password: String,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default, alias = "cipher")]
    pub security: Option<String>,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default, alias = "reality-private-key", alias = "realityPrivateKey")]
    pub reality_private_key: Option<String>,
    #[serde(default, alias = "reality-server-name", alias = "realityServerName")]
    pub reality_server_name: Option<String>,
    #[serde(default, alias = "reality-server-port", alias = "realityServerPort")]
    pub reality_server_port: Option<u16>,
    #[serde(default, alias = "reality-server-names", alias = "realityServerNames")]
    pub reality_server_names: Vec<String>,
    #[serde(default, alias = "short-ids", alias = "shortIds")]
    pub reality_short_ids: Vec<String>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, alias = "obfs-password", alias = "obfsPassword")]
    pub obfs_password: Option<String>,
    #[serde(default = "default_udp")]
    pub udp: bool,
    #[serde(default = "default_cc_rx")]
    pub cc_rx: String,
    #[serde(default = "default_hy2_congestion_control")]
    pub congestion_control: String,
    #[serde(
        default = "default_tuic_udp_relay_mode",
        alias = "udp-relay-mode",
        alias = "udpRelayMode"
    )]
    pub udp_relay_mode: String,
    #[serde(default, alias = "alpn")]
    pub alpn_protocols: Vec<String>,
    #[serde(default = "PaddingScheme::default_lines")]
    pub padding_scheme: Vec<String>,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default)]
    pub mtu: usize,
    #[serde(default, alias = "user-hint-mandatory", alias = "userHintMandatory")]
    pub user_hint_mandatory: bool,
    #[serde(default = "default_mieru_transport")]
    pub transport: String,
    #[serde(default, alias = "traffic-pattern", alias = "trafficPattern")]
    pub traffic_pattern: Option<String>,
    #[serde(default, alias = "nonce-pattern", alias = "noncePattern")]
    pub nonce_pattern: Option<String>,
}

pub fn load_config(path: &Path) -> Result<FileConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read config file {}", path.display()))?;
    if is_yaml(path) {
        return serde_yaml::from_str(&text)
            .map(FileConfig::Mihomo)
            .with_context(|| format!("parse mihomo config file {}", path.display()));
    }
    if is_json(path) {
        let json = load_jsonc_value(&text)
            .with_context(|| format!("parse json/jsonc config file {}", path.display()))?;
        return match detect_json_proxy_format(&json)? {
            JsonProxyFormat::Xray => serde_json::from_value(json)
                .map(FileConfig::Xray)
                .with_context(|| format!("parse xray config file {}", path.display())),
            JsonProxyFormat::SingBox => serde_json::from_value(json)
                .map(FileConfig::SingBox)
                .with_context(|| format!("parse sing-box config file {}", path.display())),
        };
    }
    toml::from_str::<TomlFileConfig>(&text)
        .with_context(|| format!("parse config file {}", path.display()))?
        .into_file_config()
        .with_context(|| format!("load Aerion TOML config file {}", path.display()))
}

pub fn load_mihomo_config(path: &Path) -> Result<MihomoConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read mihomo config file {}", path.display()))?;
    serde_yaml::from_str(&text)
        .with_context(|| format!("parse mihomo config file {}", path.display()))
}

pub fn load_xray_config(path: &Path) -> Result<XrayConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read xray config file {}", path.display()))?;
    serde_json::from_value(load_jsonc_value(&text)?)
        .with_context(|| format!("parse xray config file {}", path.display()))
}

pub fn load_singbox_config(path: &Path) -> Result<SingBoxConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read sing-box config file {}", path.display()))?;
    serde_json::from_value(load_jsonc_value(&text)?)
        .with_context(|| format!("parse sing-box config file {}", path.display()))
}

pub fn default_heartbeat_interval_secs() -> u64 {
    30
}

pub fn default_protocol() -> String {
    "anytls".to_string()
}

pub fn default_udp() -> bool {
    true
}

pub fn default_cc_rx() -> String {
    "0".to_string()
}

pub fn default_hy2_congestion_control() -> String {
    "bbr".to_string()
}

pub fn default_tuic_udp_relay_mode() -> String {
    "native".to_string()
}

pub fn default_mieru_username() -> String {
    "default".to_string()
}

pub fn default_mieru_transport() -> String {
    "tcp".to_string()
}

impl TomlFileConfig {
    fn into_file_config(self) -> Result<FileConfig> {
        let mode = self.mode.as_deref().map(str::trim).map(str::to_string);
        match mode.as_deref() {
            Some(mode) if mode.eq_ignore_ascii_case("client") => {
                ensure!(
                    self.server.is_none() && self.clients.is_empty() && self.servers.is_empty(),
                    "mode = \"client\" must use a single [client] profile"
                );
                Ok(FileConfig::Client {
                    client: self.client.context("mode = \"client\" requires [client]")?,
                })
            }
            Some(mode) if mode.eq_ignore_ascii_case("server") => {
                ensure!(
                    self.client.is_none() && self.clients.is_empty() && self.servers.is_empty(),
                    "mode = \"server\" must use a single [server] profile"
                );
                Ok(FileConfig::Server {
                    server: self.server.context("mode = \"server\" requires [server]")?,
                })
            }
            Some(mode) => bail!("unsupported Aerion config mode: {mode}"),
            None => {
                let mut clients = self.clients;
                if let Some(client) = self.client {
                    clients.insert(0, client);
                }
                let mut servers = self.servers;
                if let Some(server) = self.server {
                    servers.insert(0, server);
                }
                ensure!(
                    !clients.is_empty() || !servers.is_empty(),
                    "Aerion TOML config has no [client], [server], [[clients]], or [[servers]] profiles"
                );
                Ok(FileConfig::Aerion(AerionFileConfig { clients, servers }))
            }
        }
    }
}

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
        })
        .unwrap_or(false)
}

fn is_json(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            extension.eq_ignore_ascii_case("json") || extension.eq_ignore_ascii_case("jsonc")
        })
        .unwrap_or(false)
}

enum JsonProxyFormat {
    Xray,
    SingBox,
}

fn detect_json_proxy_format(value: &Value) -> Result<JsonProxyFormat> {
    let outbounds = value
        .get("outbounds")
        .and_then(Value::as_array)
        .context("JSON proxy config is missing outbounds array")?;
    let has_sing_box = outbounds
        .iter()
        .any(|outbound| outbound.get("type").is_some());
    let has_xray = outbounds
        .iter()
        .any(|outbound| outbound.get("protocol").is_some());
    match (has_xray, has_sing_box) {
        (true, false) => Ok(JsonProxyFormat::Xray),
        (false, true) => Ok(JsonProxyFormat::SingBox),
        (true, true) => {
            bail!("JSON config mixes xray protocol outbounds and sing-box type outbounds")
        }
        (false, false) => {
            bail!("JSON config outbounds have neither xray protocol nor sing-box type fields")
        }
    }
}

fn load_jsonc_value(text: &str) -> Result<Value> {
    serde_json::from_str(&strip_json_comments(text)).context("parse JSON/JSONC")
}

fn strip_json_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            output.push(ch);
            continue;
        }
        if ch == '/' {
            match chars.peek().copied() {
                Some('/') => {
                    chars.next();
                    for next in chars.by_ref() {
                        if next == '\n' {
                            output.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    let mut prev = '\0';
                    for next in chars.by_ref() {
                        if next == '\n' {
                            output.push('\n');
                        }
                        if prev == '*' && next == '/' {
                            break;
                        }
                        prev = next;
                    }
                }
                _ => output.push(ch),
            }
        } else {
            output.push(ch);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_client_example() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.client.example.toml");
        assert!(matches!(
            load_config(&path).expect("client config"),
            FileConfig::Aerion(config) if config.clients.len() == 10 && config.servers.is_empty()
        ));
    }

    #[test]
    fn parses_server_example() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.server.example.toml");
        assert!(matches!(
            load_config(&path).expect("server config"),
            FileConfig::Aerion(config) if config.clients.is_empty() && config.servers.len() == 8
        ));
    }

    #[test]
    fn parses_mihomo_yaml() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.mihomo.example.yaml");
        assert!(matches!(
            load_config(&path).expect("mihomo config"),
            FileConfig::Mihomo(config) if config.proxies.len() == 9
        ));
    }

    #[test]
    fn parses_xray_json() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.xray.example.json");
        assert!(matches!(
            load_config(&path).expect("xray config"),
            FileConfig::Xray(config) if config.outbounds.len() == 5
        ));
    }

    #[test]
    fn parses_singbox_json() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.singbox.example.json");
        assert!(matches!(
            load_config(&path).expect("sing-box config"),
            FileConfig::SingBox(config) if config.outbounds.len() == 8
        ));
    }

    #[test]
    fn compat_examples_convert_all_profiles() -> Result<()> {
        let listen = "127.0.0.1:1080".parse()?;

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.mihomo.example.yaml");
        let FileConfig::Mihomo(config) = load_config(&path)? else {
            bail!("expected mihomo config")
        };
        for proxy in &config.proxies {
            proxy
                .to_client_config(listen)
                .with_context(|| format!("convert mihomo proxy {}", proxy.name()))?;
        }

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.xray.example.json");
        let FileConfig::Xray(config) = load_config(&path)? else {
            bail!("expected xray config")
        };
        for outbound in &config.outbounds {
            outbound
                .to_client_config(listen)
                .with_context(|| format!("convert xray outbound {}", outbound.name()))?;
        }

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.singbox.example.json");
        let FileConfig::SingBox(config) = load_config(&path)? else {
            bail!("expected sing-box config")
        };
        for outbound in &config.outbounds {
            outbound
                .to_client_config(listen)
                .with_context(|| format!("convert sing-box outbound {}", outbound.name()))?;
        }

        Ok(())
    }

    #[test]
    fn strips_json_comments_without_touching_strings() -> Result<()> {
        let value = load_jsonc_value(r#"{ "url": "https://example.com/a//b", /* c */ "n": 1 }"#)?;
        assert_eq!(value["url"], "https://example.com/a//b");
        assert_eq!(value["n"], 1);
        Ok(())
    }
}
