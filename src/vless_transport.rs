use anyhow::{Result, bail};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlessTransportKind {
    Tcp,
    WebSocket,
    HttpUpgrade,
    Http2,
    Grpc,
    Xhttp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessTransportConfig {
    pub kind: VlessTransportKind,
    pub path: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
    pub mode: String,
}

impl Default for VlessTransportConfig {
    fn default() -> Self {
        Self::tcp()
    }
}

impl VlessTransportConfig {
    pub fn tcp() -> Self {
        Self {
            kind: VlessTransportKind::Tcp,
            path: "/".to_string(),
            host: None,
            headers: Vec::new(),
            mode: String::new(),
        }
    }

    pub fn websocket(
        path: Option<String>,
        host: Option<String>,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            kind: VlessTransportKind::WebSocket,
            path: normalize_path(path),
            host,
            headers,
            mode: String::new(),
        }
    }

    pub fn http_upgrade(
        path: Option<String>,
        host: Option<String>,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            kind: VlessTransportKind::HttpUpgrade,
            path: normalize_path(path),
            host,
            headers,
            mode: String::new(),
        }
    }

    pub fn http2(
        path: Option<String>,
        host: Option<String>,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            kind: VlessTransportKind::Http2,
            path: normalize_path(path),
            host,
            headers,
            mode: String::new(),
        }
    }

    pub fn grpc(
        service_name: Option<String>,
        host: Option<String>,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            kind: VlessTransportKind::Grpc,
            path: grpc_service_path(service_name),
            host,
            headers,
            mode: String::new(),
        }
    }

    pub fn xhttp(
        path: Option<String>,
        host: Option<String>,
        headers: Vec<(String, String)>,
        mode: Option<String>,
    ) -> Result<Self> {
        let mode = normalize_xhttp_mode(mode)?;
        Ok(Self {
            kind: VlessTransportKind::Xhttp,
            path: normalize_path(path),
            host,
            headers,
            mode,
        })
    }

    pub fn from_network(
        network: &str,
        path: Option<String>,
        host: Option<String>,
        headers: Vec<(String, String)>,
    ) -> Result<Self> {
        let network = network.trim().to_ascii_lowercase().replace(['-', '_'], "");
        match network.as_str() {
            "" | "tcp" | "raw" => Ok(Self::tcp()),
            "ws" | "websocket" => Ok(Self::websocket(path, host, headers)),
            "httpupgrade" => Ok(Self::http_upgrade(path, host, headers)),
            "h2" | "http" | "http2" => Ok(Self::http2(path, host, headers)),
            "grpc" => Ok(Self::grpc(path, host, headers)),
            "xhttp" | "splithttp" => Self::xhttp(path, host, headers, None),
            other => bail!("unsupported VLESS transport network {other}"),
        }
    }

    pub fn from_headers(
        network: &str,
        path: Option<String>,
        headers: BTreeMap<String, String>,
    ) -> Result<Self> {
        let host = header_value(&headers, "host");
        Self::from_network(network, path, host, headers.into_iter().collect())
    }

    pub fn request_host(&self, default_host: &str) -> String {
        self.host
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .unwrap_or(default_host)
            .to_string()
    }

    pub fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        match self.kind {
            VlessTransportKind::Http2 | VlessTransportKind::Grpc => vec![b"h2".to_vec()],
            VlessTransportKind::Xhttp => vec![b"http/1.1".to_vec()],
            VlessTransportKind::Tcp
            | VlessTransportKind::WebSocket
            | VlessTransportKind::HttpUpgrade => Vec::new(),
        }
    }
}

pub fn normalize_xhttp_mode(mode: Option<String>) -> Result<String> {
    let mode = mode
        .as_deref()
        .map(str::trim)
        .filter(|mode| !mode.is_empty())
        .unwrap_or("stream-one")
        .to_ascii_lowercase();
    match mode.as_str() {
        "auto" | "stream-one" => Ok("stream-one".to_string()),
        "stream-up" | "packet-up" => {
            bail!("VLESS XHTTP mode {mode} is parsed but Aerion currently implements stream-one")
        }
        other => bail!("unsupported VLESS XHTTP mode {other}"),
    }
}

fn normalize_path(path: Option<String>) -> String {
    let path = path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .unwrap_or("/");
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn header_value(headers: &BTreeMap<String, String>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn grpc_service_path(service_name: Option<String>) -> String {
    let service_name = service_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("GunService");
    if !service_name.starts_with('/') {
        return format!("/{}/Tun", percent_encode_path_segment(service_name));
    }
    let raw_last_index = service_name.rfind('/').unwrap_or(0);
    let last_index = raw_last_index.max(1);
    let raw_service = &service_name[1..last_index];
    let mut service = String::new();
    for part in raw_service.split('/') {
        if !service.is_empty() {
            service.push('/');
        }
        service.push_str(&percent_encode_path_segment(part));
    }
    let ending = &service_name[raw_last_index + 1..];
    let stream = ending.split('|').next().unwrap_or("Tun");
    if service.is_empty() {
        format!("/{}", percent_encode_path_segment(stream))
    } else {
        format!("/{}/{}", service, percent_encode_path_segment(stream))
    }
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_service_name_maps_to_tun_path() {
        let transport = VlessTransportConfig::grpc(Some("TunService".to_string()), None, vec![]);
        assert_eq!(transport.path, "/TunService/Tun");
    }

    #[test]
    fn grpc_xray_style_path_uses_stream_before_pipe() {
        let transport =
            VlessTransportConfig::grpc(Some("/my/service/Tun|TunMulti".to_string()), None, vec![]);
        assert_eq!(transport.path, "/my/service/Tun");
    }

    #[test]
    fn xhttp_accepts_auto_as_stream_one() -> Result<()> {
        let transport = VlessTransportConfig::xhttp(
            Some("x".to_string()),
            None,
            vec![],
            Some("auto".to_string()),
        )?;
        assert_eq!(transport.kind, VlessTransportKind::Xhttp);
        assert_eq!(transport.path, "/x");
        assert_eq!(transport.mode, "stream-one");
        Ok(())
    }

    #[test]
    fn xhttp_rejects_split_modes_until_wired() {
        let error = VlessTransportConfig::xhttp(
            Some("/x".to_string()),
            None,
            vec![],
            Some("packet-up".to_string()),
        )
        .expect_err("packet-up is not stream-one");
        assert!(error.to_string().contains("stream-one"));
    }

    #[test]
    fn splithttp_is_stream_one_xhttp_alias() -> Result<()> {
        let transport = VlessTransportConfig::from_network(
            "splithttp",
            Some("/split".to_string()),
            None,
            vec![],
        )?;
        assert_eq!(transport.kind, VlessTransportKind::Xhttp);
        assert_eq!(transport.path, "/split");
        assert_eq!(transport.mode, "stream-one");
        Ok(())
    }
}
