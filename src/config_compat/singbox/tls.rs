//! Auto-extracted from the singbox compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

impl SingBoxTlsOptions {
    pub(super) fn ensure_supported_client_options(
        &self,
        protocol: &str,
        name: &str,
        allow_certificate_path: bool,
    ) -> Result<()> {
        self.reject_unsupported_fields(protocol, name, "outbound")?;
        ensure!(
            (allow_certificate_path || !json_value_non_empty_option(self.certificate.as_ref()))
                && !self.key.as_ref().map(json_value_non_empty).unwrap_or(false)
                && !self
                    .key_path
                    .as_ref()
                    .map(json_value_non_empty)
                    .unwrap_or(false),
            "sing-box {protocol} outbound {name} sets unsupported TLS private key material"
        );
        ensure!(
            allow_certificate_path
                || !self
                    .certificate_path
                    .as_ref()
                    .map(json_value_non_empty)
                    .unwrap_or(false),
            "sing-box {protocol} outbound {name} sets custom TLS certificate roots; Aerion client expects certificate_path support to be wired explicitly"
        );
        ensure!(
            !singbox_enabled_option(protocol, name, "tls.ech", self.ech.as_ref())?,
            "sing-box {protocol} outbound {name} enables ECH; Aerion client does not implement ECH"
        );
        Ok(())
    }

    pub(super) fn ensure_supported_server_options(
        &self,
        protocol: &str,
        name: &str,
        tls_disabled: bool,
    ) -> Result<()> {
        self.reject_unsupported_fields(protocol, name, "inbound")?;
        ensure_disabled_utls(name, self)?;
        ensure_disabled_reality(name, self)?;
        if tls_disabled {
            ensure!(
                !json_value_non_empty_option(self.certificate_path.as_ref())
                    && !json_value_non_empty_option(self.key_path.as_ref())
                    && !json_value_non_empty_option(self.certificate.as_ref())
                    && !json_value_non_empty_option(self.key.as_ref()),
                "sing-box {protocol} inbound {name} sets TLS certificate fields while TLS is disabled"
            );
        }
        Ok(())
    }

    pub(super) fn reject_unsupported_fields(&self, protocol: &str, name: &str, direction: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "sing-box {protocol} {direction} {name} tls has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        for (field, value, reason) in [
            (
                "engine",
                self.engine.as_ref(),
                "TLS engine/backend selection",
            ),
            (
                "min_version",
                self.min_version.as_ref(),
                "TLS version policy override",
            ),
            (
                "max_version",
                self.max_version.as_ref(),
                "TLS version policy override",
            ),
            (
                "cipher_suites",
                self.cipher_suites.as_ref(),
                "TLS cipher suite policy",
            ),
            (
                "curve_preferences",
                self.curve_preferences.as_ref(),
                "TLS curve preference policy",
            ),
            (
                "certificate_public_key_sha256",
                self.certificate_public_key_sha256.as_ref(),
                "certificate public key pinning",
            ),
            (
                "client_certificate",
                self.client_certificate.as_ref(),
                "mutual TLS client certificate support",
            ),
            (
                "client_certificate_path",
                self.client_certificate_path.as_ref(),
                "mutual TLS client certificate support",
            ),
            (
                "client_key",
                self.client_key.as_ref(),
                "mutual TLS client key support",
            ),
            (
                "client_key_path",
                self.client_key_path.as_ref(),
                "mutual TLS client key support",
            ),
            (
                "client_certificate_public_key_sha256",
                self.client_certificate_public_key_sha256.as_ref(),
                "client certificate public key pinning",
            ),
            (
                "kernel_tx",
                self.kernel_tx.as_ref(),
                "kernel TLS transmit offload",
            ),
            (
                "kernel_rx",
                self.kernel_rx.as_ref(),
                "kernel TLS receive offload",
            ),
            (
                "handshake_timeout",
                self.handshake_timeout.as_ref(),
                "TLS handshake timeout policy",
            ),
            (
                "certificate_provider",
                self.certificate_provider.as_ref(),
                "certificate provider integration",
            ),
            (
                "fragment",
                self.fragment.as_ref(),
                "TLS fragmentation policy",
            ),
            (
                "fragment_fallback_delay",
                self.fragment_fallback_delay.as_ref(),
                "TLS fragmentation fallback timing",
            ),
            (
                "record_fragment",
                self.record_fragment.as_ref(),
                "TLS record fragmentation policy",
            ),
            ("spoof", self.spoof.as_ref(), "TLS ClientHello spoofing"),
            (
                "spoof_method",
                self.spoof_method.as_ref(),
                "TLS ClientHello spoofing",
            ),
            ("acme", self.acme.as_ref(), "ACME certificate automation"),
        ] {
            ensure!(
                !value.is_some_and(value_has_data),
                "sing-box {protocol} {direction} {name} tls.{field} requires {reason}"
            );
        }
        if let Some(client_authentication) = &self.client_authentication {
            let no_client_authentication = client_authentication
                .as_str()
                .map(str::trim)
                .is_some_and(|value| value.is_empty() || value.eq_ignore_ascii_case("no"));
            ensure!(
                no_client_authentication || !value_has_data(client_authentication),
                "sing-box {protocol} {direction} {name} tls.client_authentication requires mutual TLS client authentication policy"
            );
        }
        ensure!(
            !self.disable_sni.unwrap_or(false),
            "sing-box {protocol} {direction} {name} tls.disable_sni requires TLS SNI suppression support"
        );
        if let Some(utls) = &self.utls {
            utls.reject_unsupported_fields(&format!(
                "sing-box {protocol} {direction} {name} tls.utls"
            ))?;
        }
        if let Some(reality) = &self.reality {
            reality.reject_unsupported_fields(&format!(
                "sing-box {protocol} {direction} {name} tls.reality"
            ))?;
        }
        Ok(())
    }

    pub(super) fn utls_fingerprint(&self, name: &str) -> Result<Option<UtlsFingerprint>> {
        let Some(utls) = &self.utls else {
            return Ok(None);
        };
        if utls.enabled {
            return Ok(Some(utls.fingerprint.unwrap_or(UtlsFingerprint::Chrome)));
        }
        ensure!(
            utls.fingerprint.is_none(),
            "sing-box outbound {name} sets uTLS fingerprint while utls.enabled is false"
        );
        Ok(None)
    }

    pub(super) fn reality_client_config(&self, name: &str) -> Result<Option<RealityClientConfig>> {
        let Some(reality) = &self.reality else {
            return Ok(None);
        };
        if !reality.enabled {
            ensure!(
                reality.public_key.is_none()
                    && reality.short_id.is_none()
                    && reality.handshake.is_none()
                    && reality.private_key.is_none(),
                "sing-box outbound {name} sets REALITY fields while reality.enabled is false"
            );
            return Ok(None);
        }
        ensure!(
            reality.handshake.is_none() && reality.private_key.is_none(),
            "sing-box outbound {name} sets REALITY server-only fields"
        );
        let short_id = reality
            .short_id
            .as_ref()
            .and_then(|short_id| short_id.to_vec().into_iter().next())
            .unwrap_or_default();
        Ok(Some(RealityClientConfig::from_strings(
            reality.public_key.as_deref().with_context(|| {
                format!("sing-box REALITY outbound {name} is missing public_key")
            })?,
            &short_id,
        )?))
    }
}

impl SingBoxUtlsOptions {
    pub(super) fn reject_unsupported_fields(&self, owner: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "{owner} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        Ok(())
    }
}

impl SingBoxRealityOptions {
    pub(super) fn reject_unsupported_fields(&self, owner: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "{owner} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        if let Some(handshake) = &self.handshake {
            handshake.reject_unsupported_fields(&format!("{owner}.handshake"))?;
        }
        Ok(())
    }
}

impl SingBoxRealityHandshake {
    pub(super) fn reject_unsupported_fields(&self, owner: &str) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "{owner} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        Ok(())
    }
}

