use crate::utls::UtlsFingerprint;
use anyhow::{Context, Result, bail, ensure};
use x25519_dalek::{PublicKey, StaticSecret};

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const TLS_LEGACY_VERSION: u16 = 0x0303;
const TLS_RECORD_VERSION: u16 = 0x0301;
const TLS_VERSION_13: u16 = 0x0304;
const TLS_VERSION_12: u16 = 0x0303;
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SIGNED_CERT_TIMESTAMP: u16 = 0x0012;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

#[derive(Clone, Debug)]
pub struct ClientHelloParams {
    pub server_name: String,
    pub fingerprint: UtlsFingerprint,
    pub alpn_protocols: Option<Vec<Vec<u8>>>,
    pub session_id: Option<[u8; 32]>,
    pub random: Option<[u8; 32]>,
    pub private_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltClientHello {
    pub record: Vec<u8>,
    pub handshake: Vec<u8>,
    pub random: [u8; 32],
    pub session_id_offset: usize,
    pub session_id_len: usize,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub ja3: String,
}

#[derive(Clone, Copy)]
enum ExtensionKind {
    Grease,
    ServerName,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedGroups,
    EcPointFormats,
    SessionTicket,
    Alpn,
    StatusRequest,
    SignatureAlgorithms,
    SignedCertificateTimestamp,
    SupportedVersions,
    PskModes,
    KeyShare,
    CompressCertificate,
    Padding,
}

#[derive(Clone)]
struct ProfileSpec {
    ciphers: Vec<u16>,
    groups: Vec<u16>,
    signatures: Vec<u16>,
    extensions: Vec<ExtensionKind>,
    include_grease: bool,
    padding_len: usize,
}

impl Default for ClientHelloParams {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            fingerprint: UtlsFingerprint::Chrome,
            alpn_protocols: None,
            session_id: None,
            random: None,
            private_key: None,
        }
    }
}

impl ClientHelloParams {
    pub fn new(server_name: impl Into<String>, fingerprint: UtlsFingerprint) -> Self {
        Self {
            server_name: server_name.into(),
            fingerprint,
            ..Self::default()
        }
    }
}

pub fn build_client_hello(params: ClientHelloParams) -> Result<BuiltClientHello> {
    ensure!(
        !params.server_name.trim().is_empty(),
        "ClientHello SNI is required"
    );
    let mut profile = profile_spec(params.fingerprint)?;
    let grease = if profile.include_grease {
        Some(random_grease()?)
    } else {
        None
    };
    let mut random = params.random.unwrap_or([0u8; 32]);
    if params.random.is_none() {
        getrandom::fill(&mut random).context("generate ClientHello random")?;
    }
    let session_id = match params.session_id {
        Some(session_id) => session_id.to_vec(),
        None => {
            let mut session_id = [0u8; 32];
            getrandom::fill(&mut session_id).context("generate ClientHello session id")?;
            session_id.to_vec()
        }
    };
    let private_key = match params.private_key {
        Some(private_key) => private_key,
        None => {
            let mut private_key = [0u8; 32];
            getrandom::fill(&mut private_key).context("generate ClientHello X25519 key")?;
            private_key
        }
    };
    let secret = StaticSecret::from(private_key);
    let public_key = PublicKey::from(&secret).to_bytes();
    let alpn = params
        .alpn_protocols
        .unwrap_or_else(|| params.fingerprint.rustls_alpn_protocols());
    if params.fingerprint.is_randomized() {
        shuffle_u16(&mut profile.ciphers)?;
        shuffle_extensions(&mut profile.extensions)?;
    }

    let mut body = Vec::new();
    push_u16(&mut body, TLS_LEGACY_VERSION);
    body.extend_from_slice(&random);
    ensure!(
        session_id.len() <= u8::MAX as usize,
        "ClientHello session id is too long"
    );
    body.push(session_id.len() as u8);
    let session_id_offset = 4 + body.len();
    body.extend_from_slice(&session_id);

    let ciphers = cipher_suites(&profile, grease);
    push_u16(
        &mut body,
        checked_u16_len(ciphers.len() * 2, "ClientHello cipher suites")?,
    );
    for cipher in &ciphers {
        push_u16(&mut body, *cipher);
    }
    body.push(1);
    body.push(0);

    let extensions = encode_extensions(&profile, &params.server_name, &alpn, public_key, grease)?;
    push_u16(
        &mut body,
        checked_u16_len(extensions.len(), "ClientHello extensions")?,
    );
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
    push_u24(
        &mut handshake,
        checked_u24_len(body.len(), "ClientHello body")?,
    );
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(TLS_CONTENT_TYPE_HANDSHAKE);
    push_u16(&mut record, TLS_RECORD_VERSION);
    push_u16(
        &mut record,
        checked_u16_len(handshake.len(), "ClientHello record")?,
    );
    record.extend_from_slice(&handshake);

    let extension_types = extension_types(&profile, &alpn, grease);
    let ja3 = ja3_string(&ciphers, &extension_types, &group_list(&profile, grease));
    Ok(BuiltClientHello {
        record,
        handshake,
        random,
        session_id_offset,
        session_id_len: session_id.len(),
        private_key,
        public_key,
        ja3,
    })
}

pub fn encode_tls_record(handshake: &[u8]) -> Result<Vec<u8>> {
    let mut record = Vec::new();
    record.push(TLS_CONTENT_TYPE_HANDSHAKE);
    push_u16(&mut record, TLS_RECORD_VERSION);
    push_u16(
        &mut record,
        checked_u16_len(handshake.len(), "TLS handshake record")?,
    );
    record.extend_from_slice(handshake);
    Ok(record)
}

fn profile_spec(fingerprint: UtlsFingerprint) -> Result<ProfileSpec> {
    Ok(match fingerprint {
        UtlsFingerprint::Firefox => ProfileSpec {
            ciphers: vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            groups: vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
            signatures: vec![
                0x0403, 0x0804, 0x0807, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            extensions: vec![
                ExtensionKind::ServerName,
                ExtensionKind::ExtendedMasterSecret,
                ExtensionKind::RenegotiationInfo,
                ExtensionKind::SupportedGroups,
                ExtensionKind::EcPointFormats,
                ExtensionKind::SignatureAlgorithms,
                ExtensionKind::StatusRequest,
                ExtensionKind::Alpn,
                ExtensionKind::SupportedVersions,
                ExtensionKind::PskModes,
                ExtensionKind::KeyShare,
                ExtensionKind::Padding,
            ],
            include_grease: false,
            padding_len: 32,
        },
        UtlsFingerprint::Safari | UtlsFingerprint::Ios => ProfileSpec {
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc024,
                0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d,
                0x003c, 0x0035, 0x002f,
            ],
            groups: vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
            signatures: vec![
                0x0403, 0x0804, 0x0807, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            extensions: vec![
                ExtensionKind::ServerName,
                ExtensionKind::ExtendedMasterSecret,
                ExtensionKind::RenegotiationInfo,
                ExtensionKind::SupportedGroups,
                ExtensionKind::EcPointFormats,
                ExtensionKind::Alpn,
                ExtensionKind::StatusRequest,
                ExtensionKind::SignatureAlgorithms,
                ExtensionKind::SignedCertificateTimestamp,
                ExtensionKind::KeyShare,
                ExtensionKind::PskModes,
                ExtensionKind::SupportedVersions,
                ExtensionKind::Padding,
            ],
            include_grease: true,
            padding_len: 18,
        },
        UtlsFingerprint::RandomizedNoAlpn => {
            let mut spec = chrome_like_profile(true)?;
            spec.extensions
                .retain(|kind| !matches!(kind, ExtensionKind::Alpn));
            spec
        }
        UtlsFingerprint::Random | UtlsFingerprint::Randomized | UtlsFingerprint::RandomizedAlpn => {
            chrome_like_profile(true)?
        }
        _ => chrome_like_profile(false)?,
    })
}

fn chrome_like_profile(randomized: bool) -> Result<ProfileSpec> {
    Ok(ProfileSpec {
        ciphers: vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        groups: vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
        signatures: vec![
            0x0403, 0x0804, 0x0807, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        extensions: vec![
            ExtensionKind::Grease,
            ExtensionKind::ServerName,
            ExtensionKind::ExtendedMasterSecret,
            ExtensionKind::RenegotiationInfo,
            ExtensionKind::SupportedGroups,
            ExtensionKind::EcPointFormats,
            ExtensionKind::SessionTicket,
            ExtensionKind::Alpn,
            ExtensionKind::StatusRequest,
            ExtensionKind::SignatureAlgorithms,
            ExtensionKind::SignedCertificateTimestamp,
            ExtensionKind::KeyShare,
            ExtensionKind::PskModes,
            ExtensionKind::SupportedVersions,
            ExtensionKind::CompressCertificate,
            ExtensionKind::Padding,
        ],
        include_grease: true,
        padding_len: if randomized {
            1 + random_byte()? as usize % 64
        } else {
            21
        },
    })
}

fn cipher_suites(profile: &ProfileSpec, grease: Option<u16>) -> Vec<u16> {
    let mut ciphers = Vec::with_capacity(profile.ciphers.len() + 1);
    if let Some(grease) = grease {
        ciphers.push(grease);
    }
    ciphers.extend_from_slice(&profile.ciphers);
    ciphers
}

fn group_list(profile: &ProfileSpec, grease: Option<u16>) -> Vec<u16> {
    let mut groups = Vec::with_capacity(profile.groups.len() + 1);
    if let Some(grease) = grease {
        groups.push(grease);
    }
    groups.extend_from_slice(&profile.groups);
    groups
}

fn extension_types(profile: &ProfileSpec, alpn: &[Vec<u8>], grease: Option<u16>) -> Vec<u16> {
    let mut types = Vec::new();
    for kind in &profile.extensions {
        match kind {
            ExtensionKind::Grease => {
                if let Some(grease) = grease {
                    types.push(grease);
                }
            }
            ExtensionKind::Alpn if alpn.is_empty() => {}
            ExtensionKind::ServerName => types.push(EXT_SERVER_NAME),
            ExtensionKind::ExtendedMasterSecret => types.push(EXT_EXTENDED_MASTER_SECRET),
            ExtensionKind::RenegotiationInfo => types.push(EXT_RENEGOTIATION_INFO),
            ExtensionKind::SupportedGroups => types.push(EXT_SUPPORTED_GROUPS),
            ExtensionKind::EcPointFormats => types.push(EXT_EC_POINT_FORMATS),
            ExtensionKind::SessionTicket => types.push(EXT_SESSION_TICKET),
            ExtensionKind::Alpn => types.push(EXT_ALPN),
            ExtensionKind::StatusRequest => types.push(EXT_STATUS_REQUEST),
            ExtensionKind::SignatureAlgorithms => types.push(EXT_SIGNATURE_ALGORITHMS),
            ExtensionKind::SignedCertificateTimestamp => types.push(EXT_SIGNED_CERT_TIMESTAMP),
            ExtensionKind::SupportedVersions => types.push(EXT_SUPPORTED_VERSIONS),
            ExtensionKind::PskModes => types.push(EXT_PSK_KEY_EXCHANGE_MODES),
            ExtensionKind::KeyShare => types.push(EXT_KEY_SHARE),
            ExtensionKind::CompressCertificate => types.push(EXT_COMPRESS_CERTIFICATE),
            ExtensionKind::Padding => types.push(0x0015),
        }
    }
    types
}

fn encode_extensions(
    profile: &ProfileSpec,
    server_name: &str,
    alpn: &[Vec<u8>],
    public_key: [u8; 32],
    grease: Option<u16>,
) -> Result<Vec<u8>> {
    let mut extensions = Vec::new();
    for kind in &profile.extensions {
        match kind {
            ExtensionKind::Grease => {
                if let Some(grease) = grease {
                    write_extension(&mut extensions, grease, &[])?;
                }
            }
            ExtensionKind::ServerName => write_extension(
                &mut extensions,
                EXT_SERVER_NAME,
                &server_name_payload(server_name)?,
            )?,
            ExtensionKind::ExtendedMasterSecret => {
                write_extension(&mut extensions, EXT_EXTENDED_MASTER_SECRET, &[])?
            }
            ExtensionKind::RenegotiationInfo => {
                write_extension(&mut extensions, EXT_RENEGOTIATION_INFO, &[0])?
            }
            ExtensionKind::SupportedGroups => write_extension(
                &mut extensions,
                EXT_SUPPORTED_GROUPS,
                &u16_list_payload(&group_list(profile, grease))?,
            )?,
            ExtensionKind::EcPointFormats => {
                write_extension(&mut extensions, EXT_EC_POINT_FORMATS, &[1, 0])?
            }
            ExtensionKind::SessionTicket => {
                write_extension(&mut extensions, EXT_SESSION_TICKET, &[])?
            }
            ExtensionKind::Alpn => {
                if !alpn.is_empty() {
                    write_extension(&mut extensions, EXT_ALPN, &alpn_payload(alpn)?)?;
                }
            }
            ExtensionKind::StatusRequest => {
                write_extension(&mut extensions, EXT_STATUS_REQUEST, &[1, 0, 0, 0, 0])?
            }
            ExtensionKind::SignatureAlgorithms => write_extension(
                &mut extensions,
                EXT_SIGNATURE_ALGORITHMS,
                &u16_list_payload(&profile.signatures)?,
            )?,
            ExtensionKind::SignedCertificateTimestamp => {
                write_extension(&mut extensions, EXT_SIGNED_CERT_TIMESTAMP, &[])?
            }
            ExtensionKind::SupportedVersions => write_extension(
                &mut extensions,
                EXT_SUPPORTED_VERSIONS,
                &supported_versions_payload(grease)?,
            )?,
            ExtensionKind::PskModes => {
                write_extension(&mut extensions, EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1])?
            }
            ExtensionKind::KeyShare => write_extension(
                &mut extensions,
                EXT_KEY_SHARE,
                &key_share_payload(public_key, grease)?,
            )?,
            ExtensionKind::CompressCertificate => {
                write_extension(&mut extensions, EXT_COMPRESS_CERTIFICATE, &[2, 0, 2])?
            }
            ExtensionKind::Padding => {
                write_extension(&mut extensions, 0x0015, &vec![0u8; profile.padding_len])?
            }
        }
    }
    Ok(extensions)
}

fn server_name_payload(server_name: &str) -> Result<Vec<u8>> {
    let server_name = server_name.as_bytes();
    ensure!(
        server_name.len() <= u16::MAX as usize,
        "ClientHello SNI is too long"
    );
    let mut names = Vec::new();
    names.push(0);
    push_u16(&mut names, server_name.len() as u16);
    names.extend_from_slice(server_name);
    let mut payload = Vec::new();
    push_u16(
        &mut payload,
        checked_u16_len(names.len(), "ClientHello SNI list")?,
    );
    payload.extend_from_slice(&names);
    Ok(payload)
}

fn alpn_payload(protocols: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut list = Vec::new();
    for protocol in protocols {
        ensure!(
            !protocol.is_empty() && protocol.len() <= u8::MAX as usize,
            "ClientHello ALPN protocol length is invalid"
        );
        list.push(protocol.len() as u8);
        list.extend_from_slice(protocol);
    }
    let mut payload = Vec::new();
    push_u16(
        &mut payload,
        checked_u16_len(list.len(), "ClientHello ALPN list")?,
    );
    payload.extend_from_slice(&list);
    Ok(payload)
}

fn u16_list_payload(values: &[u16]) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    push_u16(
        &mut payload,
        checked_u16_len(values.len() * 2, "ClientHello u16 list")?,
    );
    for value in values {
        push_u16(&mut payload, *value);
    }
    Ok(payload)
}

fn supported_versions_payload(grease: Option<u16>) -> Result<Vec<u8>> {
    let mut versions = Vec::new();
    if let Some(grease) = grease {
        versions.push(grease);
    }
    versions.push(TLS_VERSION_13);
    versions.push(TLS_VERSION_12);
    let mut payload = Vec::new();
    payload.push(checked_u8_len(versions.len() * 2, "ClientHello versions")?);
    for version in versions {
        push_u16(&mut payload, version);
    }
    Ok(payload)
}

fn key_share_payload(public_key: [u8; 32], grease: Option<u16>) -> Result<Vec<u8>> {
    let mut entries = Vec::new();
    if let Some(grease) = grease {
        push_u16(&mut entries, grease);
        push_u16(&mut entries, 1);
        entries.push(0);
    }
    push_u16(&mut entries, GROUP_X25519);
    push_u16(&mut entries, public_key.len() as u16);
    entries.extend_from_slice(&public_key);
    let mut payload = Vec::new();
    push_u16(
        &mut payload,
        checked_u16_len(entries.len(), "ClientHello key_share")?,
    );
    payload.extend_from_slice(&entries);
    Ok(payload)
}

fn write_extension(out: &mut Vec<u8>, ty: u16, payload: &[u8]) -> Result<()> {
    push_u16(out, ty);
    push_u16(
        out,
        checked_u16_len(payload.len(), "ClientHello extension payload")?,
    );
    out.extend_from_slice(payload);
    Ok(())
}

fn ja3_string(ciphers: &[u16], extensions: &[u16], groups: &[u16]) -> String {
    format!(
        "771,{},{},{},0",
        join_u16_no_grease(ciphers),
        join_u16_no_grease(extensions),
        join_u16_no_grease(groups)
    )
}

fn join_u16_no_grease(values: &[u16]) -> String {
    values
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

fn random_grease() -> Result<u16> {
    const GREASE: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    Ok(GREASE[random_byte()? as usize % GREASE.len()])
}

fn random_byte() -> Result<u8> {
    let mut byte = [0u8; 1];
    getrandom::fill(&mut byte).context("generate ClientHello random byte")?;
    Ok(byte[0])
}

fn shuffle_u16(values: &mut [u16]) -> Result<()> {
    for index in (1..values.len()).rev() {
        values.swap(index, random_byte()? as usize % (index + 1));
    }
    Ok(())
}

fn shuffle_extensions(values: &mut Vec<ExtensionKind>) -> Result<()> {
    let mut fixed = Vec::new();
    let mut randomizable = Vec::new();
    for kind in values.drain(..) {
        if matches!(
            kind,
            ExtensionKind::ServerName | ExtensionKind::KeyShare | ExtensionKind::SupportedVersions
        ) {
            fixed.push(kind);
        } else {
            randomizable.push(kind);
        }
    }
    for index in (1..randomizable.len()).rev() {
        randomizable.swap(index, random_byte()? as usize % (index + 1));
    }
    values.extend(fixed);
    values.extend(randomizable);
    Ok(())
}

fn checked_u8_len(len: usize, label: &str) -> Result<u8> {
    if len <= u8::MAX as usize {
        Ok(len as u8)
    } else {
        bail!("{label} exceeds u8 length")
    }
}

fn checked_u16_len(len: usize, label: &str) -> Result<u16> {
    if len <= u16::MAX as usize {
        Ok(len as u16)
    } else {
        bail!("{label} exceeds u16 length")
    }
}

fn checked_u24_len(len: usize, label: &str) -> Result<u32> {
    if len <= 0x00ff_ffff {
        Ok(len as u32)
    } else {
        bail!("{label} exceeds u24 length")
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, value: u32) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_chrome_like_client_hello() -> Result<()> {
        let built = build_client_hello(ClientHelloParams::new(
            "example.com",
            UtlsFingerprint::Chrome,
        ))?;
        assert_eq!(built.record[0], TLS_CONTENT_TYPE_HANDSHAKE);
        assert_eq!(built.handshake[0], TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
        assert_eq!(built.session_id_len, 32);
        assert!(built.ja3.starts_with("771,4865-4866-4867"));
        Ok(())
    }

    #[test]
    fn randomized_no_alpn_omits_alpn_extension() -> Result<()> {
        let built = build_client_hello(ClientHelloParams::new(
            "example.com",
            UtlsFingerprint::RandomizedNoAlpn,
        ))?;
        assert!(
            !built
                .ja3
                .split(',')
                .nth(2)
                .unwrap_or_default()
                .contains("16")
        );
        Ok(())
    }
}
