use crate::mihomo::MihomoConfig;
use crate::padding::PaddingScheme;
use crate::singbox::SingBoxConfig;
use crate::xray::XrayConfig;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum FileConfig {
    Client { client: ClientFileConfig },
    Server { server: ServerFileConfig },
    Mihomo(MihomoConfig),
    Xray(XrayConfig),
    SingBox(SingBoxConfig),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum TomlFileConfig {
    Client { client: ClientFileConfig },
    Server { server: ServerFileConfig },
}

#[derive(Debug, Deserialize)]
pub struct ClientFileConfig {
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub listen: SocketAddr,
    pub server: String,
    #[serde(default = "default_mieru_username")]
    pub username: String,
    pub password: String,
    pub sni: Option<String>,
    #[serde(default)]
    pub insecure: bool,
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
    #[serde(default = "PaddingScheme::default_lines")]
    pub padding_scheme: Vec<String>,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default)]
    pub mtu: usize,
    #[serde(default = "default_mieru_transport")]
    pub transport: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerFileConfig {
    #[serde(default = "default_protocol")]
    pub protocol: String,
    pub listen: SocketAddr,
    #[serde(default = "default_mieru_username")]
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub cert: Option<PathBuf>,
    #[serde(default)]
    pub key: Option<PathBuf>,
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
        .map(Into::into)
        .with_context(|| format!("parse config file {}", path.display()))
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

pub fn default_mieru_username() -> String {
    "default".to_string()
}

pub fn default_mieru_transport() -> String {
    "tcp".to_string()
}

impl From<TomlFileConfig> for FileConfig {
    fn from(config: TomlFileConfig) -> Self {
        match config {
            TomlFileConfig::Client { client } => Self::Client { client },
            TomlFileConfig::Server { server } => Self::Server { server },
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
            FileConfig::Client { .. }
        ));
    }

    #[test]
    fn parses_server_example() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.server.example.toml");
        assert!(matches!(
            load_config(&path).expect("server config"),
            FileConfig::Server { .. }
        ));
    }

    #[test]
    fn parses_hysteria2_examples() {
        for name in [
            "config.hy2.client.example.toml",
            "config.hy2.server.example.toml",
        ] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
            load_config(&path).expect("hysteria2 config");
        }
    }

    #[test]
    fn parses_mieru_examples() {
        for name in [
            "config.mieru.client.example.toml",
            "config.mieru.server.example.toml",
        ] {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
            load_config(&path).expect("mieru config");
        }
    }

    #[test]
    fn parses_mihomo_yaml() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.mihomo.example.yaml");
        assert!(matches!(
            load_config(&path).expect("mihomo config"),
            FileConfig::Mihomo(config) if config.proxies.len() == 4
        ));
    }

    #[test]
    fn parses_xray_json() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.xray.example.json");
        assert!(matches!(
            load_config(&path).expect("xray config"),
            FileConfig::Xray(config) if config.outbounds.len() == 3
        ));
    }

    #[test]
    fn parses_singbox_json() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.singbox.example.json");
        assert!(matches!(
            load_config(&path).expect("sing-box config"),
            FileConfig::SingBox(config) if config.outbounds.len() == 4
        ));
    }

    #[test]
    fn strips_json_comments_without_touching_strings() -> Result<()> {
        let value = load_jsonc_value(r#"{ "url": "https://example.com/a//b", /* c */ "n": 1 }"#)?;
        assert_eq!(value["url"], "https://example.com/a//b");
        assert_eq!(value["n"], 1);
        Ok(())
    }
}
