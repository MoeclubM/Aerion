//! TLS Encrypted Client Hello (ECH) server key parsing and optional BoringSSL backend.
//!
//! rustls 0.23 (ring) does not expose server-side ECH yet. When `ech_server_keys` is configured,
//! Aerion uses BoringSSL via the `server-ech` feature (enabled by default on desktop builds).

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use std::path::{Path, PathBuf};

/// Server ECH key material in Xray `echServerKeys` binary encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EchServerKeyEntry {
    pub private_key: Vec<u8>,
    pub config: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsEchServerKeys {
    pub path: Option<PathBuf>,
    pub inline: Option<String>,
}

impl TlsEchServerKeys {
    pub fn is_configured(&self) -> bool {
        self.path
            .as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty())
            || self
                .inline
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty())
    }

    pub fn load_entries(&self) -> Result<Vec<EchServerKeyEntry>> {
        let raw = if let Some(path) = self.path.as_ref().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::read(path)
                .with_context(|| format!("read ECH server keys from {}", path.display()))?
        } else {
            decode_ech_keys_text(
                self.inline
                    .as_deref()
                    .context("ECH server keys inline material is missing")?,
            )?
        };
        parse_xray_ech_keys(&raw).context("parse ECH server keys")
    }
}

pub fn ensure_server_ech_available(ech: &Option<TlsEchServerKeys>) -> Result<()> {
    if ech.as_ref().is_some_and(TlsEchServerKeys::is_configured) {
        #[cfg(not(feature = "server-ech"))]
        {
            bail!(
                "TLS ECH server keys are configured but Aerion was built without the `server-ech` feature; \
                 rustls does not support server ECH yet — rebuild with `--features server-ech`"
            );
        }
        #[cfg(feature = "server-ech")]
        {
            ech.as_ref()
                .expect("checked above")
                .load_entries()
                .context("load configured ECH server keys")?;
        }
    }
    Ok(())
}

pub fn decode_ech_keys_text(text: &str) -> Result<Vec<u8>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("ECH server keys material is empty");
    }
    if trimmed.contains("BEGIN ECH KEYS") {
        let body = trimmed
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .context("base64-decode PEM ECH KEYS block")
    } else if looks_like_base64(trimmed) {
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .context("base64-decode inline ECH server keys")
    } else {
        Ok(trimmed.as_bytes().to_vec())
    }
}

fn looks_like_base64(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '\n' | '\r'))
}

/// Parse Xray / Go `EncryptedClientHelloKeys` wire format.
pub fn parse_xray_ech_keys(data: &[u8]) -> Result<Vec<EchServerKeyEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        ensure!(
            offset + 4 <= data.len(),
            "truncated ECH server keys at offset {offset}"
        );
        let key_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        let config_length =
            u16::from_be_bytes([data[offset + 2 + key_length], data[offset + 3 + key_length]])
                as usize;
        let record_len = 2 + key_length + 2 + config_length;
        ensure!(
            offset + record_len <= data.len(),
            "invalid ECH key record length at offset {offset}"
        );
        let key_start = offset + 2;
        let config_start = key_start + key_length + 2;
        entries.push(EchServerKeyEntry {
            private_key: data[key_start..key_start + key_length].to_vec(),
            config: data[config_start..config_start + config_length].to_vec(),
        });
        offset += record_len;
    }
    ensure!(!entries.is_empty(), "ECH server keys contain no entries");
    Ok(entries)
}

pub fn tls_ech_from_path(path: impl AsRef<Path>) -> TlsEchServerKeys {
    TlsEchServerKeys {
        path: Some(path.as_ref().to_path_buf()),
        inline: None,
    }
}

pub fn tls_ech_from_inline(inline: impl Into<String>) -> TlsEchServerKeys {
    TlsEchServerKeys {
        path: None,
        inline: Some(inline.into()),
    }
}

pub fn tls_ech_from_compat_reference(value: &str) -> TlsEchServerKeys {
    let value = value.trim();
    if value.contains("BEGIN ECH KEYS") || looks_like_base64(value) {
        tls_ech_from_inline(value)
    } else {
        tls_ech_from_path(value)
    }
}

pub fn tls_ech_from_singbox_value(value: &serde_json::Value) -> Result<Option<TlsEchServerKeys>> {
    if value.is_null() {
        return Ok(None);
    }
    let enabled = value
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    if !enabled {
        return Ok(None);
    }
    if let Some(keys) = value.get("key").or_else(|| value.get("keys")) {
        let inline = match keys {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Array(items) => items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
            _ => bail!("sing-box tls.ech.key must be a string or string array"),
        };
        ensure!(!inline.trim().is_empty(), "sing-box tls.ech.key is empty");
        return Ok(Some(tls_ech_from_inline(inline)));
    }
    if let Some(path) = value
        .get("key_path")
        .or_else(|| value.get("keyPath"))
        .and_then(serde_json::Value::as_str)
    {
        ensure!(
            !path.trim().is_empty(),
            "sing-box tls.ech.key_path is empty"
        );
        return Ok(Some(tls_ech_from_path(path)));
    }
    if value
        .get("config")
        .or_else(|| value.get("config_path"))
        .or_else(|| value.get("configPath"))
        .is_some()
    {
        bail!(
            "sing-box tls.ech requires key/key_path with Xray-format ECH server keys; config-only ECH is client-side"
        );
    }
    bail!("sing-box tls.ech is enabled but missing key material")
}

#[cfg(feature = "server-ech")]
pub mod boring_backend {
    use super::{EchServerKeyEntry, TlsEchServerKeys};
    use anyhow::{Context, Result, ensure};
    use boring::hpke::HpkeKey;
    use boring::pkey::PKey;
    use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod, SslVerifyMode};
    use boring::x509::X509;
    use std::path::Path;
    use std::sync::Arc;
    use tokio_boring::SslStream;

    pub struct BoringTlsAcceptor {
        inner: SslAcceptor,
    }

    impl BoringTlsAcceptor {
        pub async fn accept(
            &self,
            stream: tokio::net::TcpStream,
        ) -> Result<SslStream<tokio::net::TcpStream>> {
            tokio_boring::accept(&self.inner, stream)
                .await
                .map_err(|error| anyhow::anyhow!("BoringSSL TLS accept failed: {error:?}"))
        }
    }

    pub fn build_boring_acceptor(
        cert_path: Option<&Path>,
        key_path: Option<&Path>,
        certificates: &[String],
        key_pem: Option<&str>,
        label: &str,
        alpn_protocols: &[Vec<u8>],
        ech: &Option<TlsEchServerKeys>,
    ) -> Result<Arc<BoringTlsAcceptor>> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .with_context(|| format!("create BoringSSL acceptor for {label}"))?;
        builder.set_verify(SslVerifyMode::NONE);
        install_identity(
            &mut builder,
            cert_path,
            key_path,
            certificates,
            key_pem,
            label,
        )?;
        if !alpn_protocols.is_empty() {
            builder
                .set_alpn_protos(
                    &alpn_protocols
                        .iter()
                        .flat_map(|proto| {
                            std::iter::once(proto.len() as u8).chain(proto.iter().copied())
                        })
                        .collect::<Vec<_>>(),
                )
                .with_context(|| format!("set ALPN protocols for {label}"))?;
        }
        if let Some(ech) = ech {
            install_ech_keys(&mut builder, ech).context("install ECH server keys")?;
        }
        Ok(Arc::new(BoringTlsAcceptor {
            inner: builder.build(),
        }))
    }

    fn install_identity(
        builder: &mut SslAcceptorBuilder,
        cert_path: Option<&Path>,
        key_path: Option<&Path>,
        certificates: &[String],
        key_pem: Option<&str>,
        label: &str,
    ) -> Result<()> {
        if let Some(path) = cert_path.filter(|path| !path.as_os_str().is_empty()) {
            builder
                .set_certificate_file(path, SslFiletype::PEM)
                .with_context(|| format!("load {label} certificate {}", path.display()))?;
        } else {
            ensure!(!certificates.is_empty(), "{label} is missing certificate");
            for (index, pem) in certificates.iter().enumerate() {
                let cert = X509::from_pem(pem.as_bytes())
                    .with_context(|| format!("parse {label} inline certificate {}", index + 1))?;
                builder
                    .set_certificate(&cert)
                    .with_context(|| format!("install {label} inline certificate {}", index + 1))?;
            }
        }
        if let Some(path) = key_path.filter(|path| !path.as_os_str().is_empty()) {
            builder
                .set_private_key_file(path, SslFiletype::PEM)
                .with_context(|| format!("load {label} private key {}", path.display()))?;
        } else {
            let pem = key_pem.with_context(|| format!("{label} is missing private key"))?;
            let key = PKey::private_key_from_pem(pem.as_bytes())
                .with_context(|| format!("parse {label} inline private key"))?;
            builder
                .set_private_key(&key)
                .with_context(|| format!("install {label} inline private key"))?;
        }
        builder
            .check_private_key()
            .with_context(|| format!("validate {label} certificate and private key"))?;
        Ok(())
    }

    fn install_ech_keys(builder: &mut SslAcceptorBuilder, ech: &TlsEchServerKeys) -> Result<()> {
        let entries = ech.load_entries()?;
        let mut keys = boring::ssl::SslEchKeys::builder().context("allocate SslEchKeys")?;
        for (index, entry) in entries.iter().enumerate() {
            add_ech_entry(&mut keys, entry, index == 0)
                .with_context(|| format!("add ECH server key entry {}", index + 1))?;
        }
        builder
            .set_ech_keys(&keys.build())
            .context("register ECH server keys on TLS context")?;
        Ok(())
    }

    fn add_ech_entry(
        keys: &mut boring::ssl::SslEchKeysBuilder,
        entry: &EchServerKeyEntry,
        is_retry_config: bool,
    ) -> Result<()> {
        ensure!(
            !entry.private_key.is_empty() && !entry.config.is_empty(),
            "ECH key entry is missing private key or config"
        );
        let hpke_key =
            HpkeKey::dhkem_p256_sha256(&entry.private_key).context("parse ECH HPKE private key")?;
        keys.add_key(is_retry_config, &entry.config, hpke_key)
            .context("register ECH config and private key")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xray_ech_key_record() -> Result<()> {
        let private_key = vec![0x11; 32];
        let config = vec![0x22; 48];
        let mut raw = Vec::new();
        raw.extend_from_slice(&(private_key.len() as u16).to_be_bytes());
        raw.extend_from_slice(&private_key);
        raw.extend_from_slice(&(config.len() as u16).to_be_bytes());
        raw.extend_from_slice(&config);
        let entries = parse_xray_ech_keys(&raw)?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].private_key, private_key);
        assert_eq!(entries[0].config, config);
        Ok(())
    }

    #[test]
    fn rejects_empty_ech_keys() {
        assert!(parse_xray_ech_keys(&[]).is_err());
    }

    #[test]
    fn ensure_server_ech_available_without_config() -> Result<()> {
        ensure_server_ech_available(&None)?;
        ensure_server_ech_available(&Some(TlsEchServerKeys::default()))?;
        Ok(())
    }

    #[test]
    fn decode_inline_base64_ech_keys() -> Result<()> {
        let private_key = vec![0x11; 32];
        let config = vec![0x22; 48];
        let mut raw = Vec::new();
        raw.extend_from_slice(&(private_key.len() as u16).to_be_bytes());
        raw.extend_from_slice(&private_key);
        raw.extend_from_slice(&(config.len() as u16).to_be_bytes());
        raw.extend_from_slice(&config);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);
        let decoded = decode_ech_keys_text(&encoded)?;
        assert_eq!(decoded, raw);
        Ok(())
    }

    #[cfg(feature = "server-ech")]
    #[test]
    fn ensure_server_ech_available_loads_inline_keys() -> Result<()> {
        let private_key = vec![0x11; 32];
        let config = vec![0x22; 48];
        let mut raw = Vec::new();
        raw.extend_from_slice(&(private_key.len() as u16).to_be_bytes());
        raw.extend_from_slice(&private_key);
        raw.extend_from_slice(&(config.len() as u16).to_be_bytes());
        raw.extend_from_slice(&config);
        let inline = base64::engine::general_purpose::STANDARD.encode(&raw);
        let ech = Some(tls_ech_from_inline(inline));
        ensure_server_ech_available(&ech)?;
        Ok(())
    }
}
