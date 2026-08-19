use super::*;

#[test]
fn parses_default_scheme() {
    let scheme = PaddingScheme::default();
    assert_eq!(scheme.preface_padding_len().unwrap(), 30);
    assert!(!scheme.md5().is_empty());
}

#[test]
fn rejects_missing_stop() {
    let error = PaddingScheme::from_text("1=100-200").unwrap_err();
    assert!(error.to_string().contains("missing stop"));
}

#[test]
fn rejects_invalid_rule() {
    let error = PaddingScheme::from_text("stop=8\n1=bad").unwrap_err();
    assert!(error.to_string().contains("invalid padding range"));
}

#[test]
fn samples_padding_range_half_open() {
    let scheme = PaddingScheme::from_text("stop=8\n1=10-11").unwrap();
    for _ in 0..32 {
        let sizes = scheme.record_payload_sizes(1).unwrap();
        assert_eq!(sizes, vec![10]);
    }
}
