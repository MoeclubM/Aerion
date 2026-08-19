use super::*;

#[tokio::test]
async fn udp_packet_roundtrip() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 443);
    let encoded = encode_trojan_udp_packet(&target, b"abc")?;
    let decoded = read_trojan_udp_packet(&mut encoded.as_slice())
        .await?
        .expect("packet");
    assert_eq!(decoded.target, target);
    assert_eq!(decoded.payload, b"abc");
    Ok(())
}

#[test]
fn password_hash_uses_raw_bytes_and_accepts_hex_case() {
    let core = ProxyCore::from_credentials(" secret", &[]);
    let lower = trojan_auth_hex(" secret");
    let mut upper = lower;
    for byte in &mut upper {
        *byte = byte.to_ascii_uppercase();
    }
    assert_eq!(
        lookup_trojan_credential(&core, &lower).as_deref(),
        Some(" secret")
    );
    assert_eq!(
        lookup_trojan_credential(&core, &upper).as_deref(),
        Some(" secret")
    );
    assert!(lookup_trojan_credential(&core, &trojan_auth_hex("secret")).is_none());
}

#[test]
fn default_fallback_is_localhost_http() {
    assert_eq!(
        TrojanServerConfig::default_fallback(),
        "127.0.0.1:80".parse().unwrap()
    );
}
