use super::*;

#[test]
fn accepts_naive_quic_congestion_controls() -> Result<()> {
    for value in ["", "bbr", "cubic", "reno", "newreno", "new_reno"] {
        naive_quic_transport_config(value)
            .with_context(|| format!("accept Naive QUIC congestion control {value:?}"))?;
    }
    let error = naive_quic_transport_config("bbr2").expect_err("bbr2 is not wired in quinn");
    assert!(
        error
            .to_string()
            .contains("unsupported Naive quic_congestion_control bbr2")
    );
    Ok(())
}

#[test]
fn padding_header_lengths_match_naiveproxy_ranges() {
    for _ in 0..32 {
        let request = naive_padding_header().unwrap();
        assert!(request.len() >= 16 && request.len() < 32);
        let response = naive_response_padding_header().unwrap();
        assert!(response.len() >= 30 && response.len() < 62);
    }
}
