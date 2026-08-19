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
