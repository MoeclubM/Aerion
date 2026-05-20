use crate::utls::UtlsFingerprint;
use anyhow::{Context, Result, ensure};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, ServerConfig,
    SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const MAX_EARLY_DATA_SIZE: u32 = 64 * 1024;

#[derive(Debug)]
pub(crate) struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_signature_schemes()
    }
}

#[derive(Debug)]
pub(crate) struct CertificateFingerprintVerifier {
    fingerprint: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl CertificateFingerprintVerifier {
    pub(crate) fn from_sha256(value: &str) -> Result<Self> {
        let value = value.trim();
        let value = if value
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sha256:"))
        {
            &value[7..]
        } else {
            value
        };
        let value = value
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace() && *ch != ':')
            .collect::<String>();
        ensure!(
            value.len() == 64,
            "Hysteria2 certificate fingerprint must be a SHA-256 hex digest"
        );
        let bytes = hex::decode(&value).context("decode Hysteria2 certificate fingerprint")?;
        Ok(Self {
            fingerprint: bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("Hysteria2 certificate fingerprint length is invalid")
            })?,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }
}

impl ServerCertVerifier for CertificateFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() == self.fingerprint.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "Hysteria2 server certificate SHA-256 fingerprint mismatch".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub(crate) struct CertificatePinsVerifier {
    fingerprints: Vec<[u8; 32]>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl CertificatePinsVerifier {
    pub(crate) fn from_sha256_values(values: &[String]) -> Result<Self> {
        Ok(Self {
            fingerprints: parse_certificate_sha256_pins(values)?,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }
}

impl ServerCertVerifier for CertificatePinsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let digest = Sha256::digest(end_entity.as_ref());
        if self
            .fingerprints
            .iter()
            .any(|fingerprint| digest.as_slice() == fingerprint.as_slice())
        {
            return Ok(ServerCertVerified::assertion());
        }
        Err(RustlsError::General(
            "server certificate SHA-256 pin mismatch".to_string(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn parse_certificate_sha256_pins(values: &[String]) -> Result<Vec<[u8; 32]>> {
    let mut fingerprints = Vec::new();
    for value in values {
        for value in value.split(',') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let value = if value
                .get(..7)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sha256:"))
            {
                &value[7..]
            } else {
                value
            };
            let value = value
                .chars()
                .filter(|ch| !ch.is_ascii_whitespace() && *ch != ':')
                .collect::<String>();
            ensure!(
                value.len() == 64,
                "certificate SHA-256 pin must be a hex digest"
            );
            let bytes = hex::decode(&value).context("decode certificate SHA-256 pin")?;
            fingerprints.push(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("certificate SHA-256 pin length is invalid"))?,
            );
        }
    }
    Ok(fingerprints)
}

fn supported_signature_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ED25519,
    ]
}

pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn client_config(insecure: bool) -> Arc<ClientConfig> {
    client_config_with_fingerprint(insecure, None)
}

pub fn client_config_early_data(insecure: bool) -> Arc<ClientConfig> {
    client_config_with_fingerprint_early_data(insecure, None)
}

pub fn client_config_with_fingerprint(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
) -> Arc<ClientConfig> {
    build_client_config(insecure, fingerprint, false)
}

pub fn client_config_with_fingerprint_early_data(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
) -> Arc<ClientConfig> {
    build_client_config(insecure, fingerprint, true)
}

pub fn client_config_with_custom_roots(
    insecure: bool,
    ca_cert_paths: &[PathBuf],
) -> Result<Arc<ClientConfig>> {
    client_config_with_custom_root_material(insecure, ca_cert_paths, &[])
}

pub fn client_config_with_custom_roots_early_data(
    insecure: bool,
    ca_cert_paths: &[PathBuf],
) -> Result<Arc<ClientConfig>> {
    client_config_with_custom_root_material_early_data(insecure, ca_cert_paths, &[])
}

pub fn client_config_with_custom_root_material(
    insecure: bool,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
) -> Result<Arc<ClientConfig>> {
    client_config_with_custom_root_material_and_system_roots(
        insecure,
        ca_cert_paths,
        ca_certificates,
        false,
    )
}

pub fn client_config_with_custom_root_material_and_system_roots(
    insecure: bool,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
    disable_system_roots: bool,
) -> Result<Arc<ClientConfig>> {
    client_config_with_custom_root_material_options(
        insecure,
        ca_cert_paths,
        ca_certificates,
        disable_system_roots,
        &[],
    )
}

pub fn client_config_with_custom_root_material_options(
    insecure: bool,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
    disable_system_roots: bool,
    pinned_cert_sha256: &[String],
) -> Result<Arc<ClientConfig>> {
    client_config_with_fingerprint_and_custom_root_material_options(
        insecure,
        None,
        ca_cert_paths,
        ca_certificates,
        disable_system_roots,
        pinned_cert_sha256,
    )
}

pub fn client_config_with_custom_root_material_early_data(
    insecure: bool,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
) -> Result<Arc<ClientConfig>> {
    client_config_with_custom_root_material_early_data_and_system_roots(
        insecure,
        ca_cert_paths,
        ca_certificates,
        false,
    )
}

pub fn client_config_with_custom_root_material_early_data_and_system_roots(
    insecure: bool,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
    disable_system_roots: bool,
) -> Result<Arc<ClientConfig>> {
    client_config_with_custom_root_material_early_data_options(
        insecure,
        ca_cert_paths,
        ca_certificates,
        disable_system_roots,
        &[],
    )
}

pub fn client_config_with_custom_root_material_early_data_options(
    insecure: bool,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
    disable_system_roots: bool,
    pinned_cert_sha256: &[String],
) -> Result<Arc<ClientConfig>> {
    build_client_config_with_custom_roots(
        insecure,
        None,
        true,
        ca_cert_paths,
        ca_certificates,
        disable_system_roots,
        pinned_cert_sha256,
    )
}

pub fn client_config_with_fingerprint_and_custom_roots(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
    ca_cert_paths: &[PathBuf],
) -> Result<Arc<ClientConfig>> {
    client_config_with_fingerprint_and_custom_root_material(
        insecure,
        fingerprint,
        ca_cert_paths,
        &[],
    )
}

pub fn client_config_with_fingerprint_and_custom_root_material(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
) -> Result<Arc<ClientConfig>> {
    client_config_with_fingerprint_and_custom_root_material_and_system_roots(
        insecure,
        fingerprint,
        ca_cert_paths,
        ca_certificates,
        false,
    )
}

pub fn client_config_with_fingerprint_and_custom_root_material_and_system_roots(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
    disable_system_roots: bool,
) -> Result<Arc<ClientConfig>> {
    client_config_with_fingerprint_and_custom_root_material_options(
        insecure,
        fingerprint,
        ca_cert_paths,
        ca_certificates,
        disable_system_roots,
        &[],
    )
}

pub fn client_config_with_fingerprint_and_custom_root_material_options(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
    disable_system_roots: bool,
    pinned_cert_sha256: &[String],
) -> Result<Arc<ClientConfig>> {
    build_client_config_with_custom_roots(
        insecure,
        fingerprint,
        false,
        ca_cert_paths,
        ca_certificates,
        disable_system_roots,
        pinned_cert_sha256,
    )
}

pub fn client_config_with_fingerprint_and_custom_root_material_early_data_options(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
    disable_system_roots: bool,
    pinned_cert_sha256: &[String],
) -> Result<Arc<ClientConfig>> {
    build_client_config_with_custom_roots(
        insecure,
        fingerprint,
        true,
        ca_cert_paths,
        ca_certificates,
        disable_system_roots,
        pinned_cert_sha256,
    )
}

fn build_client_config_with_custom_roots(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
    early_data: bool,
    ca_cert_paths: &[PathBuf],
    ca_certificates: &[String],
    disable_system_roots: bool,
    pinned_cert_sha256: &[String],
) -> Result<Arc<ClientConfig>> {
    if insecure {
        return Ok(build_client_config(insecure, fingerprint, early_data));
    }
    if !pinned_cert_sha256.is_empty() {
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(
                CertificatePinsVerifier::from_sha256_values(pinned_cert_sha256)?,
            ))
            .with_no_client_auth();
        config.alpn_protocols = fingerprint
            .map(UtlsFingerprint::rustls_alpn_protocols)
            .unwrap_or_default();
        config.enable_early_data = early_data;
        return Ok(Arc::new(config));
    }
    if ca_cert_paths.is_empty() && ca_certificates.is_empty() && !disable_system_roots {
        return Ok(build_client_config(insecure, fingerprint, early_data));
    }
    let mut roots = RootCertStore::empty();
    if !disable_system_roots {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for path in ca_cert_paths {
        for cert in load_certs(path)? {
            roots
                .add(cert)
                .with_context(|| format!("add custom root certificate {}", path.display()))?;
        }
    }
    for (index, pem) in ca_certificates.iter().enumerate() {
        let label = format!("inline custom root certificate {}", index + 1);
        for cert in load_certs_from_pem(&label, pem)? {
            roots.add(cert).with_context(|| format!("add {label}"))?;
        }
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = fingerprint
        .map(UtlsFingerprint::rustls_alpn_protocols)
        .unwrap_or_default();
    config.enable_early_data = early_data;
    if let Some(fingerprint) = fingerprint {
        tracing::debug!(
            fingerprint = %fingerprint,
            profile = fingerprint.rustls_profile_note(),
            "applied uTLS-like rustls client profile"
        );
    }
    Ok(Arc::new(config))
}

fn build_client_config(
    insecure: bool,
    fingerprint: Option<UtlsFingerprint>,
    early_data: bool,
) -> Arc<ClientConfig> {
    let mut config = if insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = fingerprint
        .map(UtlsFingerprint::rustls_alpn_protocols)
        .unwrap_or_default();
    config.enable_early_data = early_data;
    if let Some(fingerprint) = fingerprint {
        tracing::debug!(
            fingerprint = %fingerprint,
            profile = fingerprint.rustls_profile_note(),
            "applied uTLS-like rustls client profile"
        );
    }
    Arc::new(config)
}

pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let (certs, key) = server_identity(Some(cert_path), Some(key_path), &[], None, "TLS server")?;
    let mut config = build_server_config(
        certs,
        key,
        &format!(
            "cert {} and key {}",
            DisplayPath(cert_path),
            DisplayPath(key_path)
        ),
    )?;
    config.alpn_protocols.clear();
    Ok(Arc::new(config))
}

pub fn server_config_early_data(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let mut config = Arc::unwrap_or_clone(server_config(cert_path, key_path)?);
    config.max_early_data_size = MAX_EARLY_DATA_SIZE;
    Ok(Arc::new(config))
}

pub fn server_config_from_material(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    certificates: &[String],
    key: Option<&str>,
    label: &str,
) -> Result<Arc<ServerConfig>> {
    let (certs, key) = server_identity(cert_path, key_path, certificates, key, label)?;
    let mut config = build_server_config(certs, key, label)?;
    config.alpn_protocols.clear();
    Ok(Arc::new(config))
}

pub fn server_config_early_data_from_material(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    certificates: &[String],
    key: Option<&str>,
    label: &str,
) -> Result<Arc<ServerConfig>> {
    let mut config = Arc::unwrap_or_clone(server_config_from_material(
        cert_path,
        key_path,
        certificates,
        key,
        label,
    )?);
    config.max_early_data_size = MAX_EARLY_DATA_SIZE;
    Ok(Arc::new(config))
}

pub fn server_identity(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    certificates: &[String],
    key: Option<&str>,
    label: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = if let Some(path) = cert_path {
        load_certs(path)?
    } else {
        ensure!(!certificates.is_empty(), "{label} is missing certificate");
        load_certs_from_pem(&format!("{label} certificate"), &certificates.join("\n"))?
    };
    let key = if let Some(path) = key_path {
        load_key(path)?
    } else {
        load_key_from_pem(
            &format!("{label} private key"),
            key.with_context(|| format!("{label} is missing private key"))?,
        )?
    };
    Ok((certs, key))
}

pub fn present_path(path: &Path) -> Option<&Path> {
    (!path.as_os_str().is_empty()).then_some(path)
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    label: &str,
) -> Result<ServerConfig> {
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| format!("build TLS server config with {label}"))
}

pub(crate) fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("open certificate {}", DisplayPath(path)))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("read certificate {}", DisplayPath(path)))?;
    anyhow::ensure!(
        !certs.is_empty(),
        "certificate file contains no certificate"
    );
    Ok(certs)
}

pub(crate) fn load_certs_from_pem(label: &str, pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("read {label}"))?;
    anyhow::ensure!(!certs.is_empty(), "{label} contains no certificate");
    Ok(certs)
}

pub(crate) fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("open private key {}", DisplayPath(path)))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("read private key {}", DisplayPath(path)))?
        .with_context(|| format!("private key file contains no key: {}", DisplayPath(path)))
}

pub(crate) fn load_key_from_pem(label: &str, pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("read {label}"))?
        .with_context(|| format!("{label} contains no private key"))
}

struct DisplayPath<'a>(&'a Path);

impl fmt::Display for DisplayPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use std::io::Read;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[tokio::test]
    async fn accepts_tls13_early_data_after_ticket_resumption() -> Result<()> {
        init_crypto();

        let temp = tempfile::tempdir()?;
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_path = temp.path().join("early.crt");
        let key_path = temp.path().join("early.key");
        std::fs::write(&cert_path, certified.cert.pem())?;
        std::fs::write(&key_path, certified.key_pair.serialize_pem())?;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(server_config_early_data(&cert_path, &key_path)?);
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await?;
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut stream = acceptor.accept(stream).await?;
                    if let Some(mut early_data) = stream.get_mut().1.early_data() {
                        let mut buf = Vec::new();
                        early_data.read_to_end(&mut buf)?;
                        if !buf.is_empty() {
                            stream.write_all(b"EARLY:").await?;
                            stream.write_all(&buf).await?;
                        }
                    }
                    stream.write_all(b"LATE:").await?;
                    let mut buf = [0u8; 1024];
                    loop {
                        let read = stream.read(&mut buf).await?;
                        if read == 0 {
                            stream.shutdown().await?;
                            return Ok::<(), anyhow::Error>(());
                        }
                        stream.write_all(&buf[..read]).await?;
                    }
                });
            }
            Ok::<(), anyhow::Error>(())
        });

        let config = client_config_early_data(true);
        let (accepted, body) = early_data_roundtrip(config.clone(), addr, b"hello").await?;
        assert!(!accepted);
        assert_eq!(body, b"LATE:hello");

        let (accepted, body) = early_data_roundtrip(config, addr, b"world").await?;
        assert!(accepted);
        assert_eq!(body, b"EARLY:worldLATE:");

        server_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn accepts_inline_server_certificate_material() -> Result<()> {
        init_crypto();

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_pem = certified.cert.pem();
        let key_pem = certified.key_pair.serialize_pem();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(server_config_from_material(
            None,
            None,
            std::slice::from_ref(&cert_pem),
            Some(&key_pem),
            "inline TLS test",
        )?);
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = acceptor.accept(stream).await?;
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await?;
            stream.write_all(&buf).await?;
            Ok::<(), anyhow::Error>(())
        });

        let config =
            client_config_with_custom_root_material(false, &[], std::slice::from_ref(&cert_pem))?;
        let tcp = TcpStream::connect(addr).await?;
        let server_name = ServerName::try_from("localhost").context("build server name")?;
        let mut stream = TlsConnector::from(config)
            .connect(server_name, tcp)
            .await
            .context("connect inline TLS server")?;
        stream.write_all(b"hello").await?;
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(&echoed, b"hello");
        server_task.await??;
        Ok(())
    }

    async fn early_data_roundtrip(
        config: Arc<ClientConfig>,
        addr: std::net::SocketAddr,
        payload: &[u8],
    ) -> Result<(bool, Vec<u8>)> {
        let tcp = TcpStream::connect(addr).await?;
        let server_name = ServerName::try_from("localhost").context("build server name")?;
        let mut stream = TlsConnector::from(config)
            .early_data(true)
            .connect(server_name, tcp)
            .await
            .context("connect with early data")?;
        stream.write_all(payload).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await?;
        let accepted = stream.get_ref().1.is_early_data_accepted();
        Ok((accepted, body))
    }
}
