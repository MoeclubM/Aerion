use super::*;

#[test]
fn parses_padding_pattern() -> Result<()> {
    let pattern = MieruTrafficPattern::parse_pair(Some("KgQIAxAE"), None)?
        .context("missing traffic pattern")?;
    assert_eq!(
        pattern.padding,
        Some(MieruPaddingPattern {
            max_middle_padding_len: Some(3),
            max_end_padding_len: Some(4),
        })
    );
    Ok(())
}

#[test]
fn rejects_nonzero_low_entropy_pattern() {
    let error = MieruTrafficPattern::parse_pair(Some("MgIIAQ=="), None).unwrap_err();
    assert!(error.to_string().contains("low-entropy"));
}
