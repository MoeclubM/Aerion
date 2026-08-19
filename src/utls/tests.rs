use super::*;

#[test]
fn parses_mihomo_and_utls_names() -> Result<()> {
    assert_eq!(
        "chrome".parse::<UtlsFingerprint>()?,
        UtlsFingerprint::Chrome
    );
    assert_eq!(
        "HelloFirefox_Auto".parse::<UtlsFingerprint>()?,
        UtlsFingerprint::Firefox
    );
    assert_eq!(
        "HelloChrome_106_Shuffle".parse::<UtlsFingerprint>()?,
        UtlsFingerprint::Chrome
    );
    assert_eq!(
        "chrome_psk_shuffle".parse::<UtlsFingerprint>()?,
        UtlsFingerprint::Chrome
    );
    assert_eq!(
        "randomized_no_alpn".parse::<UtlsFingerprint>()?,
        UtlsFingerprint::RandomizedNoAlpn
    );
    assert_eq!(UtlsFingerprint::from_mihomo_name("unsafe")?, None);
    assert_eq!(
        UtlsFingerprint::Android.as_utls_client_hello_id(),
        "HelloAndroid_11_OkHttp"
    );
    assert_eq!(
        UtlsFingerprint::Chrome.as_utls_client_hello_id(),
        "HelloChrome_133"
    );
    assert_eq!(
        UtlsFingerprint::Firefox.as_utls_client_hello_id(),
        "HelloFirefox_148"
    );
    assert_eq!(
        UtlsFingerprint::Chrome.rustls_alpn_protocols(),
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert!(
        UtlsFingerprint::RandomizedNoAlpn
            .rustls_alpn_protocols()
            .is_empty()
    );
    Ok(())
}
