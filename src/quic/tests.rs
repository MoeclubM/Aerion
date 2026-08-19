use super::*;

#[test]
fn applies_only_protocol_supported_congestion_controls() -> Result<()> {
    let mut transport = quinn::TransportConfig::default();
    apply_congestion_controller(
        &mut transport,
        "",
        QuicCongestion::Bbr,
        BBR_RENO_CONGESTION_CONTROLS,
        "Hysteria2",
        "congestion_control",
    )?;

    let error = apply_congestion_controller(
        &mut transport,
        "new_reno",
        QuicCongestion::Bbr,
        BBR_RENO_CONGESTION_CONTROLS,
        "Hysteria2",
        "congestion_control",
    )
    .expect_err("Hysteria2 does not accept the new_reno alias");
    assert!(
        error
            .to_string()
            .contains("unsupported Hysteria2 congestion_control new_reno")
    );
    Ok(())
}
