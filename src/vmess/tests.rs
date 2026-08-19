use super::*;

const UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

#[test]
fn auth_id_roundtrip() -> Result<()> {
    let uuid = parse_uuid(UUID)?;
    let key = vmess_cmd_key(&uuid);
    let auth_id = create_auth_id(&key, 1_700_000_000)?;
    assert_eq!(decode_auth_id(&key, &auth_id)?, 1_700_000_000);
    Ok(())
}

#[tokio::test]
async fn request_header_roundtrip() -> Result<()> {
    let uuid = parse_uuid(UUID)?;
    let target = ProxyTarget::Domain("example.com".to_string(), 443);
    let mut bytes = Vec::new();
    let keys = write_vmess_request(
        &mut bytes,
        &uuid,
        CMD_TCP,
        &target,
        SecurityType::None,
        RequestOptions::new(0),
    )
    .await?;
    let users = HashMap::from([(uuid, UUID.to_string())]);
    let (request, _) = read_vmess_request(&mut bytes.as_slice(), &users, None).await?;
    assert_eq!(request.command, CMD_TCP);
    assert_eq!(request.target, target);
    assert_eq!(request.security, SecurityType::None);
    assert_eq!(request.options.bits(), 0);
    let response = encode_vmess_response_header(&keys)?;
    read_vmess_response_header(&mut response.as_slice(), &keys).await?;
    Ok(())
}

#[tokio::test]
async fn mux_request_omits_address() -> Result<()> {
    let uuid = parse_uuid(UUID)?;
    let mut bytes = Vec::new();
    write_vmess_request(
        &mut bytes,
        &uuid,
        CMD_MUX,
        &vless_xudp::mux_target(),
        SecurityType::Aes128Gcm,
        RequestOptions::new(0x01),
    )
    .await?;
    let users = HashMap::from([(uuid, UUID.to_string())]);
    let (request, _) = read_vmess_request(&mut bytes.as_slice(), &users, None).await?;
    assert_eq!(request.command, CMD_MUX);
    assert!(vless_xudp::is_mux_target(&request.target));
    Ok(())
}

#[test]
fn auth_id_replay_is_rejected() -> Result<()> {
    let filter = VmessReplayFilter::new();
    let auth_id = [9u8; 16];
    filter.check_auth_id(auth_id)?;
    let error = filter
        .check_auth_id(auth_id)
        .expect_err("duplicate AuthID must fail");
    assert!(error.to_string().contains("AuthID replay"));
    Ok(())
}
