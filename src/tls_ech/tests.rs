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
fn rejects_truncated_ech_private_key_without_panicking() {
    let error = parse_xray_ech_keys(&[0xff, 0xff, 0, 0]).unwrap_err();
    assert!(error.to_string().contains("truncated ECH server key"));
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
