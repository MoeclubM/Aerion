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
