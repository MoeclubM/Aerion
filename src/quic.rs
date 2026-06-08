use anyhow::{Context, Result, bail};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuicCongestion {
    Bbr,
    Cubic,
    NewReno,
}

pub(crate) const BBR_RENO_CONGESTION_CONTROLS: &[(&str, QuicCongestion)] = &[
    ("bbr", QuicCongestion::Bbr),
    ("reno", QuicCongestion::NewReno),
    ("newreno", QuicCongestion::NewReno),
];

pub(crate) const BBR_CUBIC_RENO_CONGESTION_CONTROLS: &[(&str, QuicCongestion)] = &[
    ("bbr", QuicCongestion::Bbr),
    ("cubic", QuicCongestion::Cubic),
    ("reno", QuicCongestion::NewReno),
    ("newreno", QuicCongestion::NewReno),
    ("new_reno", QuicCongestion::NewReno),
];

pub(crate) fn transport_config_with_idle_timeout(
    timeout: Duration,
    context: &str,
) -> Result<quinn::TransportConfig> {
    let idle_timeout = quinn::IdleTimeout::try_from(timeout).context(context.to_string())?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(idle_timeout));
    Ok(transport)
}

pub(crate) fn apply_congestion_controller(
    transport: &mut quinn::TransportConfig,
    value: &str,
    default: QuicCongestion,
    supported: &[(&str, QuicCongestion)],
    protocol: &str,
    field: &str,
) -> Result<()> {
    let normalized = value.trim().to_ascii_lowercase();
    let selected = if normalized.is_empty() {
        default
    } else if let Some((_, selected)) = supported.iter().find(|(name, _)| *name == normalized) {
        *selected
    } else {
        bail!("unsupported {protocol} {field} {normalized}");
    };

    transport.congestion_controller_factory(match selected {
        QuicCongestion::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
        QuicCongestion::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
        QuicCongestion::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
