use super::*;

const UUID: &str = "a3482e88-686a-4a58-8126-99c9df64b7bf";

#[tokio::test]
async fn request_roundtrip() -> Result<()> {
    let target = ProxyTarget::Domain("example.com".to_string(), 443);
    let mut bytes = Vec::new();
    write_vless_request(&mut bytes, &parse_uuid(UUID)?, CMD_TCP, &target, "").await?;
    let request = read_vless_request(&mut bytes.as_slice()).await?;
    assert_eq!(request.user, parse_uuid(UUID)?);
    assert_eq!(request.command, CMD_TCP);
    assert_eq!(request.target, target);
    Ok(())
}
