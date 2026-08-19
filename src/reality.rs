use crate::client_hello::{BuiltClientHello, ClientHelloParams, build_client_hello};
use crate::protocol::constant_time_eq;
use crate::utls::UtlsFingerprint;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Sha256, Sha512};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const TLS_GROUP_X25519: u16 = 29;
const TLS_GROUP_X25519_KYBER768_DRAFT00: u16 = 0x6399;
const TLS_GROUP_X25519_MLKEM768: u16 = 0x11ec;
const TLS_MAX_RECORD_LEN: usize = u16::MAX as usize;
const REALITY_SESSION_ID_LEN: usize = 32;
const REALITY_AUTH_PLAIN_LEN: usize = 16;

type HmacSha512 = Hmac<Sha512>;

const REALITY_MAX_CLIENT_VERSION: [u8; 4] = [0, 0, 0, 1];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityFallbackLimit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes: u64,
}

impl Default for RealityFallbackLimit {
    fn default() -> Self {
        Self {
            after_bytes: 0,
            bytes_per_sec: 64 * 1024,
            burst_bytes: 256 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityServerConfig {
    pub server_name: String,
    pub server_port: u16,
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub max_time_diff_secs: u64,
    pub max_client_version: Option<[u8; 4]>,
    pub fallback_limit: RealityFallbackLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityClientConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawClientHello {
    pub prefix: Vec<u8>,
    pub handshake: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedClientHello {
    pub server_name: String,
    pub client_version: [u8; 4],
    pub client_time: u32,
    pub short_id: [u8; 8],
    pub auth_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltRealityClientHello {
    pub raw: RawClientHello,
    pub client_hello: BuiltClientHello,
    pub auth_key: [u8; 32],
}

#[derive(Debug)]
pub struct RealityCertificateState {
    key_der: Vec<u8>,
    public_key: [u8; 32],
    certificate_template: Vec<u8>,
    signature_offset: usize,
}

impl RealityServerConfig {
    pub fn from_strings(
        server_name: impl Into<String>,
        server_port: u16,
        server_names: Vec<String>,
        private_key: &str,
        short_ids: &[String],
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let server_name = server_name.into();
        let mut names = server_names
            .into_iter()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        if names.is_empty() {
            names.push(server_name.clone());
        }
        Ok(Self {
            server_name,
            server_port,
            server_names: names,
            private_key: parse_reality_key(private_key)?,
            short_ids: parse_short_ids(short_ids)?,
            alpn_protocols,
            max_time_diff_secs: 0,
            max_client_version: Some(REALITY_MAX_CLIENT_VERSION),
            fallback_limit: RealityFallbackLimit::default(),
        })
    }
}

impl RealityClientConfig {
    pub fn from_strings(public_key: &str, short_id: &str) -> Result<Self> {
        Ok(Self {
            public_key: parse_reality_key(public_key).context("decode REALITY public key")?,
            short_id: parse_short_id(short_id)?,
        })
    }
}

pub fn build_reality_client_hello(
    config: &RealityClientConfig,
    server_name: &str,
    fingerprint: UtlsFingerprint,
) -> Result<BuiltRealityClientHello> {
    build_reality_client_hello_with_alpn(config, server_name, fingerprint, None)
}

pub fn build_reality_client_hello_with_alpn(
    config: &RealityClientConfig,
    server_name: &str,
    fingerprint: UtlsFingerprint,
    alpn_protocols: Option<Vec<Vec<u8>>>,
) -> Result<BuiltRealityClientHello> {
    build_reality_client_hello_with_time(
        config,
        server_name,
        fingerprint,
        alpn_protocols,
        [0, 0, 0, 1],
        unix_time_u32()?,
    )
}

pub fn build_reality_client_hello_with_time(
    config: &RealityClientConfig,
    server_name: &str,
    fingerprint: UtlsFingerprint,
    alpn_protocols: Option<Vec<Vec<u8>>>,
    client_version: [u8; 4],
    client_time: u32,
) -> Result<BuiltRealityClientHello> {
    let mut client_hello = build_client_hello(ClientHelloParams {
        server_name: server_name.to_string(),
        fingerprint,
        alpn_protocols,
        session_id: Some([0u8; REALITY_SESSION_ID_LEN]),
        ..ClientHelloParams::default()
    })?;
    let shared_key = StaticSecret::from(client_hello.private_key)
        .diffie_hellman(&PublicKey::from(config.public_key))
        .to_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&client_hello.random[..20]), &shared_key);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("derive REALITY client auth key failed"))?;

    let mut plaintext = Vec::with_capacity(REALITY_AUTH_PLAIN_LEN);
    plaintext.extend_from_slice(&client_version);
    plaintext.extend_from_slice(&client_time.to_be_bytes());
    plaintext.extend_from_slice(&config.short_id);
    let encrypted = Aes256Gcm::new_from_slice(&auth_key)
        .context("initialize REALITY client session id cipher")?
        .encrypt(
            Nonce::from_slice(&client_hello.random[20..]),
            Payload {
                msg: &plaintext,
                aad: &client_hello.handshake,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt REALITY client session id"))?;
    ensure!(
        encrypted.len() == REALITY_SESSION_ID_LEN,
        "REALITY encrypted session id must be 32 bytes"
    );
    let session_range = client_hello.session_id_offset
        ..client_hello.session_id_offset + client_hello.session_id_len;
    client_hello.handshake[session_range.clone()].copy_from_slice(&encrypted);
    client_hello.record[5 + session_range.start..5 + session_range.end].copy_from_slice(&encrypted);
    Ok(BuiltRealityClientHello {
        raw: RawClientHello {
            prefix: client_hello.record.clone(),
            handshake: client_hello.handshake.clone(),
        },
        client_hello,
        auth_key,
    })
}

impl RealityCertificateState {
    pub fn build() -> Result<Self> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .context("generate REALITY Ed25519 key")?;
        let public_key = key.public_key_raw();
        ensure!(
            public_key.len() == 32,
            "REALITY Ed25519 public key length mismatch"
        );
        let mut public = [0u8; 32];
        public.copy_from_slice(public_key);

        let certificate = rcgen::CertificateParams::default()
            .self_signed(&key)
            .context("build REALITY certificate template")?;
        let certificate_template = certificate.der().as_ref().to_vec();
        let signature_offset = certificate_signature_offset(&certificate_template)?;
        Ok(Self {
            key_der: key.serialize_der(),
            public_key: public,
            certificate_template,
            signature_offset,
        })
    }

    pub fn server_config(
        &self,
        auth_key: &[u8; 32],
        alpn: &[Vec<u8>],
    ) -> Result<Arc<ServerConfig>> {
        crate::tls::init_crypto();
        let certificate = self.certificate_for_auth_key(auth_key)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(certificate)], key)
            .context("build REALITY TLS server config")?;
        config.alpn_protocols = alpn.to_vec();
        Ok(Arc::new(config))
    }

    fn certificate_for_auth_key(&self, auth_key: &[u8; 32]) -> Result<Vec<u8>> {
        let mut hmac = <HmacSha512 as Mac>::new_from_slice(auth_key)
            .context("initialize REALITY certificate HMAC")?;
        hmac.update(&self.public_key);
        let signature = hmac.finalize().into_bytes();
        let mut certificate = self.certificate_template.clone();
        ensure!(
            self.signature_offset + signature.len() <= certificate.len(),
            "REALITY certificate template signature offset is invalid"
        );
        certificate[self.signature_offset..self.signature_offset + signature.len()]
            .copy_from_slice(&signature);
        Ok(certificate)
    }
}

pub async fn peek_client_hello(stream: &TcpStream) -> Result<RawClientHello> {
    let mut buffer = vec![0u8; 5];
    loop {
        let read = stream
            .peek(&mut buffer)
            .await
            .context("peek REALITY ClientHello")?;
        ensure!(read > 0, "REALITY ClientHello stream closed");
        match parse_client_hello_prefix(&buffer[..read])? {
            PrefixParse::Complete(client_hello) => return Ok(client_hello),
            PrefixParse::NeedMore(size) => {
                if buffer.len() < size {
                    buffer.resize(size, 0);
                } else {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        }
    }
}

pub fn authenticate_client_hello(
    client_hello: &RawClientHello,
    config: &RealityServerConfig,
) -> Result<AuthenticatedClientHello> {
    let parsed = parse_client_hello(&client_hello.handshake)?;
    ensure!(
        config
            .server_names
            .iter()
            .any(|name| name == &parsed.server_name),
        "REALITY ClientHello SNI {} does not match configured server_names {}",
        parsed.server_name,
        config.server_names.join(",")
    );

    let peer_public_key = parse_peer_public_key(parsed.key_share)?;
    let shared_key = derive_shared_key(config.private_key, peer_public_key)?;
    let hkdf = Hkdf::<Sha256>::new(Some(&parsed.random[..20]), &shared_key);
    let mut auth_key = [0u8; 32];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("derive REALITY auth key failed"))?;

    let mut aad = client_hello.handshake.clone();
    aad[parsed.session_start..parsed.session_start + parsed.session_id.len()].fill(0);
    let plain = Aes256Gcm::new_from_slice(&auth_key)
        .context("initialize REALITY session id cipher")?
        .decrypt(
            Nonce::from_slice(&parsed.random[20..]),
            Payload {
                msg: parsed.session_id,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("decrypt REALITY session id"))?;
    ensure!(
        plain.len() == REALITY_AUTH_PLAIN_LEN,
        "REALITY decrypted session id prefix must be 16 bytes"
    );

    let mut client_version = [0u8; 4];
    client_version.copy_from_slice(&plain[..4]);
    let client_time = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]);
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plain[8..16]);
    ensure!(
        short_id_allowed(&config.short_ids, &short_id),
        "REALITY ClientHello short_id {} does not match configured short_id",
        hex::encode(short_id)
    );
    if let Some(max_version) = config.max_client_version {
        ensure!(
            u32::from_be_bytes(client_version) <= u32::from_be_bytes(max_version),
            "REALITY client version {:?} is newer than {:?}",
            client_version,
            max_version
        );
    }
    if config.max_time_diff_secs > 0 {
        let now = unix_time_u32()?;
        let delta = now.abs_diff(client_time);
        ensure!(
            u64::from(delta) <= config.max_time_diff_secs,
            "REALITY client time {client_time} is outside maxTimeDiff window {delta}s"
        );
    }

    Ok(AuthenticatedClientHello {
        server_name: parsed.server_name,
        client_version,
        client_time,
        short_id,
        auth_key,
    })
}

pub async fn proxy_fallback(stream: TcpStream, config: &RealityServerConfig) -> Result<()> {
    let fallback = TcpStream::connect((config.server_name.as_str(), config.server_port))
        .await
        .with_context(|| {
            format!(
                "connect REALITY fallback {}:{}",
                config.server_name, config.server_port
            )
        })?;
    let (mut client_reader, mut client_writer) = stream.into_split();
    let (mut fallback_reader, mut fallback_writer) = fallback.into_split();
    let result = tokio::select! {
        result = copy_limited(
            &mut client_reader,
            &mut fallback_writer,
            &config.fallback_limit
        ) => result,
        result = copy_limited(
            &mut fallback_reader,
            &mut client_writer,
            &config.fallback_limit
        ) => result,
    };
    let _ = fallback_writer.shutdown().await;
    let _ = client_writer.shutdown().await;
    result.map(|_| ())
}

async fn copy_limited<R, W>(
    reader: &mut R,
    writer: &mut W,
    limit: &RealityFallbackLimit,
) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut copied = 0u64;
    let mut buffer = vec![0u8; 16 * 1024];
    let started = Instant::now();
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await.ok();
            return Ok(copied);
        }
        if limit.bytes_per_sec > 0 && copied >= limit.after_bytes {
            let elapsed = started.elapsed().as_secs_f64();
            let allowed = limit.after_bytes
                + (elapsed * limit.bytes_per_sec as f64) as u64
                + limit.burst_bytes;
            let projected = copied + read as u64;
            if projected > allowed {
                let extra = projected - allowed;
                let sleep = Duration::from_secs_f64(extra as f64 / limit.bytes_per_sec as f64);
                tokio::time::sleep(sleep).await;
            }
        }
        writer.write_all(&buffer[..read]).await?;
        copied += read as u64;
    }
}

fn short_id_allowed(ids: &[[u8; 8]], candidate: &[u8; 8]) -> bool {
    let mut allowed = false;
    for id in ids {
        allowed |= constant_time_eq(id, candidate);
    }
    allowed
}

enum PrefixParse {
    NeedMore(usize),
    Complete(RawClientHello),
}

fn parse_client_hello_prefix(data: &[u8]) -> Result<PrefixParse> {
    let mut offset = 0usize;
    let mut handshake = Vec::new();
    let mut expected_handshake_len = None;

    loop {
        if data.len() < offset + 5 {
            return Ok(PrefixParse::NeedMore(offset + 5));
        }
        let record_header = &data[offset..offset + 5];
        ensure!(
            record_header[0] == TLS_CONTENT_TYPE_HANDSHAKE,
            "REALITY expected initial TLS handshake record"
        );
        let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
        ensure!(
            record_len <= TLS_MAX_RECORD_LEN,
            "REALITY TLS record is too large"
        );
        let record_end = offset + 5 + record_len;
        if data.len() < record_end {
            return Ok(PrefixParse::NeedMore(record_end));
        }

        let mut payload = &data[offset + 5..record_end];
        while !payload.is_empty() {
            let expected_len = match expected_handshake_len {
                Some(expected_len) => expected_len,
                None => {
                    ensure!(
                        payload.len() >= 4,
                        "truncated REALITY ClientHello handshake header"
                    );
                    ensure!(
                        payload[0] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
                        "REALITY expected ClientHello handshake message"
                    );
                    let declared_len = read_be_u24(payload, 1, "REALITY ClientHello length")?;
                    handshake.extend_from_slice(&payload[..4]);
                    payload = &payload[4..];
                    let expected_len = declared_len as usize + 4;
                    expected_handshake_len = Some(expected_len);
                    expected_len
                }
            };

            let missing = expected_len.saturating_sub(handshake.len());
            let take = missing.min(payload.len());
            handshake.extend_from_slice(&payload[..take]);
            payload = &payload[take..];
            if handshake.len() == expected_len {
                return Ok(PrefixParse::Complete(RawClientHello {
                    prefix: data[..record_end].to_vec(),
                    handshake,
                }));
            }
        }
        offset = record_end;
    }
}

struct ParsedClientHello<'a> {
    server_name: String,
    random: [u8; 32],
    session_id: &'a [u8],
    session_start: usize,
    key_share: &'a [u8],
}

fn parse_client_hello(raw: &[u8]) -> Result<ParsedClientHello<'_>> {
    ensure!(raw.len() >= 4 + 2 + 32 + 1, "truncated REALITY ClientHello");
    ensure!(
        raw[0] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
        "REALITY expected ClientHello handshake message"
    );
    let declared_len = read_be_u24(raw, 1, "REALITY ClientHello length")? as usize;
    ensure!(
        declared_len + 4 == raw.len(),
        "REALITY ClientHello length does not match payload"
    );

    let mut offset = 4;
    offset += 2;
    ensure!(
        offset + 32 <= raw.len(),
        "truncated REALITY ClientHello random"
    );
    let mut random = [0u8; 32];
    random.copy_from_slice(&raw[offset..offset + 32]);
    offset += 32;

    ensure!(
        offset < raw.len(),
        "truncated REALITY ClientHello session id length"
    );
    let session_len = raw[offset] as usize;
    offset += 1;
    let session_start = offset;
    let session_end = session_start + session_len;
    ensure!(
        session_end <= raw.len(),
        "truncated REALITY ClientHello session id"
    );
    let session_id = &raw[session_start..session_end];
    ensure!(
        session_id.len() == REALITY_SESSION_ID_LEN,
        "REALITY ClientHello session id must be 32 bytes"
    );
    offset = session_end;

    let cipher_suites_len =
        read_be_u16(raw, offset, "REALITY ClientHello cipher suites length")? as usize;
    offset += 2;
    ensure!(
        offset + cipher_suites_len <= raw.len(),
        "truncated REALITY ClientHello cipher suites"
    );
    offset += cipher_suites_len;

    ensure!(
        offset < raw.len(),
        "truncated REALITY ClientHello compression methods length"
    );
    let compression_methods_len = raw[offset] as usize;
    offset += 1;
    ensure!(
        offset + compression_methods_len <= raw.len(),
        "truncated REALITY ClientHello compression methods"
    );
    offset += compression_methods_len;

    let extensions_len =
        read_be_u16(raw, offset, "REALITY ClientHello extensions length")? as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    ensure!(
        extensions_end == raw.len(),
        "REALITY ClientHello extensions length does not match payload"
    );

    let mut server_name = None;
    let mut key_share = None;
    let mut supports_tls13 = false;
    while offset < extensions_end {
        let extension_type = read_be_u16(raw, offset, "REALITY ClientHello extension type")?;
        let extension_len =
            read_be_u16(raw, offset + 2, "REALITY ClientHello extension length")? as usize;
        let data_start = offset + 4;
        let data_end = data_start + extension_len;
        ensure!(
            data_end <= extensions_end,
            "truncated REALITY ClientHello extension"
        );
        let data = &raw[data_start..data_end];

        match extension_type {
            0 => server_name = Some(parse_server_name_extension(data)?),
            43 => supports_tls13 = parse_supported_versions_extension(data)?,
            51 => key_share = Some(data),
            _ => {}
        }
        offset = data_end;
    }
    ensure!(supports_tls13, "REALITY ClientHello must support TLS 1.3");

    Ok(ParsedClientHello {
        server_name: server_name.context("REALITY ClientHello missing SNI")?,
        random,
        session_id,
        session_start,
        key_share: key_share.context("REALITY ClientHello missing key_share")?,
    })
}

fn parse_server_name_extension(bytes: &[u8]) -> Result<String> {
    let list_len = read_be_u16(bytes, 0, "REALITY server_name list length")? as usize;
    ensure!(
        list_len + 2 == bytes.len(),
        "REALITY server_name list length does not match payload"
    );
    let mut offset = 2;
    while offset < bytes.len() {
        ensure!(
            offset + 3 <= bytes.len(),
            "truncated REALITY server_name entry"
        );
        let name_type = bytes[offset];
        let name_len = read_be_u16(bytes, offset + 1, "REALITY server_name length")? as usize;
        let name_start = offset + 3;
        let name_end = name_start + name_len;
        ensure!(
            name_end <= bytes.len(),
            "truncated REALITY server_name bytes"
        );
        if name_type == 0 {
            let server_name = std::str::from_utf8(&bytes[name_start..name_end])
                .context("decode REALITY server_name as UTF-8")?;
            ensure!(
                !server_name.is_empty(),
                "REALITY ClientHello SNI cannot be empty"
            );
            return Ok(server_name.to_string());
        }
        offset = name_end;
    }
    bail!("REALITY ClientHello missing host_name SNI entry")
}

fn parse_supported_versions_extension(bytes: &[u8]) -> Result<bool> {
    ensure!(
        !bytes.is_empty(),
        "truncated REALITY supported_versions extension"
    );
    let declared_len = bytes[0] as usize;
    ensure!(
        declared_len + 1 == bytes.len(),
        "REALITY supported_versions length does not match payload"
    );
    ensure!(
        declared_len % 2 == 0,
        "REALITY supported_versions payload must contain whole versions"
    );
    Ok(bytes[1..]
        .chunks_exact(2)
        .any(|version| version == [0x03, 0x04]))
}

fn parse_peer_public_key(key_share: &[u8]) -> Result<&[u8]> {
    let declared_len = read_be_u16(key_share, 0, "REALITY key_share list length")? as usize;
    ensure!(
        declared_len + 2 == key_share.len(),
        "REALITY key_share list length does not match payload"
    );
    let mut offset = 2;
    let mut hybrid_public_key = None;
    while offset < key_share.len() {
        ensure!(
            offset + 4 <= key_share.len(),
            "truncated REALITY key_share entry"
        );
        let group = u16::from_be_bytes([key_share[offset], key_share[offset + 1]]);
        let data_len = u16::from_be_bytes([key_share[offset + 2], key_share[offset + 3]]) as usize;
        let data_start = offset + 4;
        let data_end = data_start + data_len;
        ensure!(
            data_end <= key_share.len(),
            "truncated REALITY key_share data"
        );
        let data = &key_share[data_start..data_end];
        if group == TLS_GROUP_X25519 && data.len() == 32 {
            return Ok(data);
        }
        if group == TLS_GROUP_X25519_KYBER768_DRAFT00 && data.len() >= 32 {
            hybrid_public_key = Some(&data[..32]);
        }
        if group == TLS_GROUP_X25519_MLKEM768 && data.len() >= 32 {
            hybrid_public_key = Some(&data[data.len() - 32..]);
        }
        offset = data_end;
    }
    hybrid_public_key.context("REALITY ClientHello missing X25519 key_share")
}

fn derive_shared_key(private_key: [u8; 32], peer_public_key: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        peer_public_key.len() == 32,
        "REALITY X25519 public key must be 32 bytes"
    );
    let secret = StaticSecret::from(private_key);
    let public = PublicKey::from(
        <[u8; 32]>::try_from(peer_public_key).context("load REALITY X25519 peer key")?,
    );
    Ok(secret.diffie_hellman(&public).to_bytes())
}

fn certificate_signature_offset(certificate: &[u8]) -> Result<usize> {
    let root = read_der_element(certificate, 0)?;
    ensure!(
        root.tag == 0x30,
        "REALITY certificate root is not a SEQUENCE"
    );
    ensure!(
        root.end == certificate.len(),
        "REALITY certificate has trailing DER data"
    );
    let tbs = read_der_element(certificate, root.content_start)?;
    ensure!(tbs.tag == 0x30, "REALITY certificate TBS is not a SEQUENCE");
    let algorithm = read_der_element(certificate, tbs.end)?;
    ensure!(
        algorithm.tag == 0x30,
        "REALITY certificate signature algorithm is not a SEQUENCE"
    );
    let signature = read_der_element(certificate, algorithm.end)?;
    ensure!(
        signature.tag == 0x03,
        "REALITY certificate signature is not a BIT STRING"
    );
    ensure!(
        signature.content_end == root.content_end,
        "REALITY certificate signature is not the final element"
    );
    ensure!(
        signature.content_end >= signature.content_start + 1 + 64,
        "REALITY certificate signature BIT STRING is too short"
    );
    ensure!(
        certificate[signature.content_start] == 0,
        "REALITY certificate signature BIT STRING has unused bits"
    );
    Ok(signature.content_start + 1)
}

struct DerElement {
    tag: u8,
    content_start: usize,
    content_end: usize,
    end: usize,
}

fn read_der_element(bytes: &[u8], offset: usize) -> Result<DerElement> {
    ensure!(offset + 2 <= bytes.len(), "truncated DER element");
    let tag = bytes[offset];
    let first_len = bytes[offset + 1];
    let (len, content_start) = if first_len & 0x80 == 0 {
        (first_len as usize, offset + 2)
    } else {
        let len_len = (first_len & 0x7f) as usize;
        ensure!(len_len > 0, "indefinite DER length is not supported");
        ensure!(len_len <= 4, "DER length field is too large");
        ensure!(offset + 2 + len_len <= bytes.len(), "truncated DER length");
        let mut len = 0usize;
        for &byte in &bytes[offset + 2..offset + 2 + len_len] {
            len = (len << 8) | byte as usize;
        }
        (len, offset + 2 + len_len)
    };
    let content_end = content_start + len;
    ensure!(content_end <= bytes.len(), "truncated DER content");
    Ok(DerElement {
        tag,
        content_start,
        content_end,
        end: content_end,
    })
}

fn read_be_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16> {
    ensure!(offset + 2 <= bytes.len(), "truncated {label}");
    Ok(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_be_u24(bytes: &[u8], offset: usize, label: &str) -> Result<u32> {
    ensure!(offset + 3 <= bytes.len(), "truncated {label}");
    Ok(((bytes[offset] as u32) << 16)
        | ((bytes[offset + 1] as u32) << 8)
        | bytes[offset + 2] as u32)
}

fn parse_reality_key(value: &str) -> Result<[u8; 32]> {
    let decoded = decode_base64(value.trim()).context("decode REALITY private key")?;
    ensure!(
        decoded.len() == 32,
        "REALITY private key must decode to 32 bytes"
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn parse_short_ids(values: &[String]) -> Result<Vec<[u8; 8]>> {
    ensure!(!values.is_empty(), "REALITY shortIds must not be empty");
    let mut ids = Vec::new();
    for value in values {
        ids.push(parse_short_id(value)?);
    }
    Ok(ids)
}

fn parse_short_id(value: &str) -> Result<[u8; 8]> {
    let text = value.trim();
    ensure!(
        text.len() <= 16 && text.len() % 2 == 0,
        "REALITY short_id must be 0 to 16 hex characters"
    );
    let mut id = [0u8; 8];
    if !text.is_empty() {
        let decoded = hex::decode(text).context("decode REALITY short_id")?;
        id[..decoded.len()].copy_from_slice(&decoded);
    }
    Ok(id)
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .context("decode base64")
}

fn unix_time_u32() -> Result<u32> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?
        .as_secs();
    ensure!(seconds <= u32::MAX as u64, "UNIX time exceeds u32");
    Ok(seconds as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_hello::encode_tls_record;
    use aes_gcm::aead::Aead;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn certificate_state_builds_dynamic_rustls_config() -> Result<()> {
        let state = RealityCertificateState::build()?;
        let cert = state.certificate_for_auth_key(&[7u8; 32])?;
        ensure!(cert.len() == state.certificate_template.len());
        state.server_config(&[7u8; 32], &[])?;
        Ok(())
    }

    #[test]
    fn authenticates_generated_client_hello() -> Result<()> {
        let mut server_private_bytes = [0u8; 32];
        let mut client_private_bytes = [0u8; 32];
        getrandom::fill(&mut server_private_bytes)?;
        getrandom::fill(&mut client_private_bytes)?;
        let server_private = StaticSecret::from(server_private_bytes);
        let client_private = StaticSecret::from(client_private_bytes);
        let client_public = PublicKey::from(&client_private).to_bytes();
        let config = RealityServerConfig {
            server_name: "reality.example.com".to_string(),
            server_port: 443,
            server_names: vec!["reality.example.com".to_string()],
            private_key: server_private.to_bytes(),
            short_ids: vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]],
            alpn_protocols: Vec::new(),
            max_time_diff_secs: 0,
            max_client_version: None,
            fallback_limit: RealityFallbackLimit::default(),
        };
        let handshake = build_test_client_hello(
            &config,
            &client_private,
            client_public,
            "reality.example.com",
            [1, 2, 3, 4],
            1_700_000_000,
            [0xa1, 0xb2, 0, 0, 0, 0, 0, 0],
        )?;
        let raw = RawClientHello {
            prefix: encode_tls_record(&handshake)?,
            handshake,
        };
        let authenticated = authenticate_client_hello(&raw, &config)?;
        assert_eq!(authenticated.server_name, "reality.example.com");
        assert_eq!(authenticated.client_version, [1, 2, 3, 4]);
        assert_eq!(authenticated.client_time, 1_700_000_000);
        assert_eq!(authenticated.short_id, [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);
        Ok(())
    }

    #[test]
    fn authenticates_custom_profile_reality_client_hello() -> Result<()> {
        let mut server_private_bytes = [0u8; 32];
        getrandom::fill(&mut server_private_bytes)?;
        let server_private = StaticSecret::from(server_private_bytes);
        let server_public = PublicKey::from(&server_private).to_bytes();
        let server = RealityServerConfig {
            server_name: "reality.example.com".to_string(),
            server_port: 443,
            server_names: vec!["reality.example.com".to_string()],
            private_key: server_private.to_bytes(),
            short_ids: vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]],
            alpn_protocols: Vec::new(),
            max_time_diff_secs: 0,
            max_client_version: None,
            fallback_limit: RealityFallbackLimit::default(),
        };
        let client = RealityClientConfig {
            public_key: server_public,
            short_id: [0xa1, 0xb2, 0, 0, 0, 0, 0, 0],
        };
        let hello = build_reality_client_hello_with_time(
            &client,
            "reality.example.com",
            UtlsFingerprint::Chrome,
            None,
            [0, 0, 0, 1],
            1_700_000_001,
        )?;
        let authenticated = authenticate_client_hello(&hello.raw, &server)?;
        assert_eq!(authenticated.server_name, "reality.example.com");
        assert_eq!(authenticated.client_time, 1_700_000_001);
        assert_eq!(authenticated.auth_key, hello.auth_key);
        assert!(hello.client_hello.ja3.starts_with("771,4865-4866-4867"));
        Ok(())
    }

    #[test]
    fn rejects_empty_short_ids() {
        let error = parse_short_ids(&[]).unwrap_err();
        assert!(error.to_string().contains("shortIds must not be empty"));
    }

    #[test]
    fn rejects_client_hello_outside_time_window() -> Result<()> {
        let mut server_private_bytes = [0u8; 32];
        getrandom::fill(&mut server_private_bytes)?;
        let server_private = StaticSecret::from(server_private_bytes);
        let server_public = PublicKey::from(&server_private).to_bytes();
        let server = RealityServerConfig {
            server_name: "reality.example.com".to_string(),
            server_port: 443,
            server_names: vec!["reality.example.com".to_string()],
            private_key: server_private.to_bytes(),
            short_ids: vec![[0xa1, 0xb2, 0, 0, 0, 0, 0, 0]],
            alpn_protocols: Vec::new(),
            max_time_diff_secs: 60,
            max_client_version: Some([0, 0, 0, 1]),
            fallback_limit: RealityFallbackLimit::default(),
        };
        let client = RealityClientConfig {
            public_key: server_public,
            short_id: [0xa1, 0xb2, 0, 0, 0, 0, 0, 0],
        };
        let hello = build_reality_client_hello_with_time(
            &client,
            "reality.example.com",
            UtlsFingerprint::Chrome,
            None,
            [0, 0, 0, 1],
            1_700_000_001,
        )?;
        let error = authenticate_client_hello(&hello.raw, &server).unwrap_err();
        assert!(error.to_string().contains("maxTimeDiff"));
        Ok(())
    }

    #[tokio::test]
    async fn peeks_client_hello_without_consuming_tcp_stream() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await?;
            let payload = encode_tls_record(&build_plain_test_client_hello())?;
            stream.write_all(&payload).await?;
            Ok::<Vec<u8>, anyhow::Error>(payload)
        });
        let (mut stream, _) = listener.accept().await?;
        let hello = peek_client_hello(&stream).await?;
        ensure!(hello.handshake == build_plain_test_client_hello());
        let payload = client.await??;
        let mut read_back = vec![0u8; payload.len()];
        stream.read_exact(&mut read_back).await?;
        ensure!(read_back == payload);
        Ok(())
    }

    fn build_test_client_hello(
        config: &RealityServerConfig,
        client_private: &StaticSecret,
        client_public: [u8; 32],
        server_name: &str,
        client_version: [u8; 4],
        client_time: u32,
        short_id: [u8; 8],
    ) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)?;
        body.extend_from_slice(&random);
        body.push(32);
        let session_start = body.len();
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&encode_server_name_extension(server_name));
        extensions.extend_from_slice(&encode_supported_versions_extension());
        extensions.extend_from_slice(&encode_key_share_extension(&client_public));
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let server_public = PublicKey::from(&StaticSecret::from(config.private_key));
        let shared_key = client_private.diffie_hellman(&server_public).to_bytes();
        let hkdf = Hkdf::<Sha256>::new(Some(&body[2..22]), &shared_key);
        let mut auth_key = [0u8; 32];
        hkdf.expand(b"REALITY", &mut auth_key)
            .map_err(|_| anyhow::anyhow!("expand REALITY auth key failed"))?;

        let mut plaintext = Vec::with_capacity(16);
        plaintext.extend_from_slice(&client_version);
        plaintext.extend_from_slice(&client_time.to_be_bytes());
        plaintext.extend_from_slice(&short_id);
        let encrypted = Aes256Gcm::new_from_slice(&auth_key)
            .context("initialize test REALITY cipher")?
            .encrypt(
                Nonce::from_slice(&body[22..34]),
                Payload {
                    msg: &plaintext,
                    aad: &handshake,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt test REALITY session id"))?;
        ensure!(
            encrypted.len() == REALITY_AUTH_PLAIN_LEN + 16,
            "unexpected test REALITY encrypted session id length"
        );
        handshake[4 + session_start..4 + session_start + 32].copy_from_slice(&encrypted);
        Ok(handshake)
    }

    fn build_plain_test_client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x11; 32]);
        body.push(32);
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&encode_server_name_extension("reality.example.com"));
        extensions.extend_from_slice(&encode_supported_versions_extension());
        extensions.extend_from_slice(&encode_key_share_extension(&[0x33; 32]));
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![TLS_HANDSHAKE_TYPE_CLIENT_HELLO];
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);
        handshake
    }

    fn encode_server_name_extension(server_name: &str) -> Vec<u8> {
        let server_name = server_name.as_bytes();
        let mut payload = Vec::new();
        let list_len = 1 + 2 + server_name.len();
        payload.extend_from_slice(&(list_len as u16).to_be_bytes());
        payload.push(0);
        payload.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        payload.extend_from_slice(server_name);
        let mut extension = Vec::new();
        extension.extend_from_slice(&0u16.to_be_bytes());
        extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extension.extend_from_slice(&payload);
        extension
    }

    fn encode_supported_versions_extension() -> Vec<u8> {
        let mut extension = Vec::new();
        extension.extend_from_slice(&43u16.to_be_bytes());
        extension.extend_from_slice(&3u16.to_be_bytes());
        extension.push(2);
        extension.extend_from_slice(&0x0304u16.to_be_bytes());
        extension
    }

    fn encode_key_share_extension(client_public: &[u8; 32]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&36u16.to_be_bytes());
        payload.extend_from_slice(&TLS_GROUP_X25519.to_be_bytes());
        payload.extend_from_slice(&32u16.to_be_bytes());
        payload.extend_from_slice(client_public);
        let mut extension = Vec::new();
        extension.extend_from_slice(&51u16.to_be_bytes());
        extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        extension.extend_from_slice(&payload);
        extension
    }
}
