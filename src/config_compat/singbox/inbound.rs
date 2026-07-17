//! Auto-extracted from the singbox compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

impl SingBoxInbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.kind)
    }

    pub fn to_server_config(&self) -> Result<SingBoxServerConfig> {
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "naive" => Ok(SingBoxServerConfig::Naive(
                self.decode::<SingBoxNaiveInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "anytls" => Ok(SingBoxServerConfig::AnyTls(
                self.decode::<SingBoxAnyTlsInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "hysteria2" | "hy2" => Ok(SingBoxServerConfig::Hysteria2(
                self.decode::<SingBoxHysteria2Inbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "mieru" => Ok(SingBoxServerConfig::Mieru(
                self.decode::<SingBoxMieruInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "shadowsocks" | "ss" => Ok(SingBoxServerConfig::Shadowsocks(
                self.decode::<SingBoxShadowsocksInbound>()?
                    .to_server_config(self.name(), self.listen.as_deref(), self.listen_port)?,
            )),
            "trojan" => Ok(SingBoxServerConfig::Trojan(
                self.decode::<SingBoxTrojanInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "tuic" => Ok(SingBoxServerConfig::Tuic(
                self.decode::<SingBoxTuicInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "vless" => Ok(SingBoxServerConfig::Vless(
                self.decode::<SingBoxVlessInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            "vmess" => Ok(SingBoxServerConfig::Vmess(
                self.decode::<SingBoxVmessInbound>()?.to_server_config(
                    self.name(),
                    self.listen.as_deref(),
                    self.listen_port,
                )?,
            )),
            other => bail!(
                "unsupported sing-box inbound {} type {}; Aerion cannot run this inbound protocol as a server",
                self.name(),
                other
            ),
        }
    }

    pub(super) fn decode<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(Value::Object(self.fields.clone()))
            .with_context(|| format!("parse sing-box inbound {}", self.name()))
    }
}

impl SingBoxNaiveInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<NaiveServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Naive inbound {name}"), &self.extra)?;
        ensure!(
            self.tls.enabled,
            "sing-box Naive inbound {name} disables TLS; Naive requires HTTPS/TLS"
        );
        ensure_disabled_utls(name, &self.tls)?;
        ensure_disabled_reality(name, &self.tls)?;
        let (tcp, quic) = naive_inbound_network(name, self.network.as_deref())?;
        ensure_naive_inbound_alpn(name, self.tls.alpn.as_ref(), tcp, quic)?;
        ensure!(
            !json_value_non_empty_option(self.tls.ech.as_ref()),
            "sing-box Naive inbound {name} sets ECH; Aerion Naive server does not expose ECH"
        );
        let (username, password, users) = self.credentials();
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "Naive", name)?;
        Ok(NaiveServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Naive inbound {name} is missing listen_port")
                })?,
            ),
            username,
            password,
            users,
            cert_path,
            key_path,
            certificates,
            key,
            udp_over_tcp: false,
            tcp,
            quic,
            quic_congestion_control: self
                .quic_congestion_control
                .clone()
                .unwrap_or_else(default_naive_quic_congestion_control),
        })
    }

    fn credentials(&self) -> (String, String, Vec<String>) {
        if let Some(primary) = self.users.first() {
            return (
                primary.username.clone(),
                primary.password.clone(),
                self.users
                    .iter()
                    .skip(1)
                    .map(|user| format!("{}:{}", user.username, user.password))
                    .collect(),
            );
        }
        (
            self.username.clone().unwrap_or_default(),
            self.password.clone().unwrap_or_default(),
            Vec::new(),
        )
    }
}

impl SingBoxVlessInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<VlessServerConfig> {
        ensure_no_extra_fields(&format!("sing-box VLESS inbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box VLESS inbound", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        let tls = self.tls.as_ref();
        let tls_enabled = tls.map(|tls| tls.enabled).unwrap_or(false);
        if let Some(tls) = tls {
            tls.reject_unsupported_fields("VLESS", name, "inbound")?;
        }
        let reality = tls
            .and_then(|tls| tls.reality.as_ref())
            .filter(|reality| reality.enabled);
        ensure!(
            reality.is_none() || tls_enabled,
            "sing-box VLESS inbound {name} enables REALITY while TLS is disabled"
        );
        if tls_enabled || reality.is_some() {
            ensure_vless_alpn(
                "sing-box",
                name,
                &transport,
                tls.and_then(|tls| tls.alpn.as_ref()),
            )?;
        } else if let Some(tls) = tls {
            ensure_disabled_utls(name, tls)?;
            ensure_disabled_reality(name, tls)?;
            ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
        }
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box VLESS inbound {name} is missing users"))?;
        let flow = primary.flow.clone();
        let users = self
            .users
            .iter()
            .skip(1)
            .map(|user| {
                ensure!(
                    user.flow == flow,
                    "sing-box VLESS inbound {name} uses per-user flow; Aerion VLESS server expects one flow for the inbound"
                );
                Ok(user.uuid.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let reality = if let Some(reality) = reality {
            let handshake = reality.handshake.as_ref().with_context(|| {
                format!("sing-box VLESS inbound {name} REALITY is missing handshake")
            })?;
            ensure!(
                reality.public_key.is_none(),
                "sing-box VLESS inbound {name} REALITY sets client-side public_key; Aerion server expects private_key"
            );
            Some(RealityServerConfig::from_strings(
                handshake.server.clone(),
                handshake.server_port,
                Vec::new(),
                reality.private_key.as_deref().with_context(|| {
                    format!("sing-box VLESS inbound {name} REALITY is missing private_key")
                })?,
                &reality_short_ids(reality.short_id.as_ref()),
                transport.alpn_protocols(),
            )?)
        } else {
            None
        };
        let (cert_path, key_path, certificates, key) = if tls_enabled && reality.is_none() {
            let tls =
                tls.with_context(|| format!("sing-box VLESS inbound {name} is missing tls"))?;
            tls.ensure_supported_server_options("VLESS", name, false)?;
            singbox_tls_server_identity(tls, "VLESS", name)?
        } else {
            if let Some(tls) = tls {
                ensure_disabled_utls(name, tls)?;
                ensure!(
                    !json_value_non_empty_option(tls.certificate.as_ref())
                        && !json_value_non_empty_option(tls.key.as_ref())
                        && !json_value_non_empty_option(tls.certificate_path.as_ref())
                        && !json_value_non_empty_option(tls.key_path.as_ref()),
                    "sing-box VLESS inbound {name} sets TLS certificate fields while TLS certificate mode is disabled"
                );
            }
            (PathBuf::new(), PathBuf::new(), Vec::new(), None)
        };
        let ech = if tls_enabled && reality.is_none() {
            tls.and_then(|settings| settings.ech.as_ref())
                .map(tls_ech_from_singbox_value)
                .transpose()?
                .flatten()
        } else {
            None
        };
        Ok(VlessServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box VLESS inbound {name} is missing listen_port")
                })?,
            ),
            user_id: primary.uuid.clone(),
            users,
            tls: tls_enabled && reality.is_none(),
            cert_path,
            key_path,
            certificates,
            key,
            flow,
            reality,
            transport,
            ech,
        })
    }
}

impl SingBoxAnyTlsInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<ServerConfig> {
        ensure_no_extra_fields(&format!("sing-box AnyTLS inbound {name}"), &self.extra)?;
        ensure!(
            self.tls.enabled,
            "sing-box AnyTLS inbound {name} disables TLS; AnyTLS requires TLS"
        );
        self.tls
            .ensure_supported_server_options("AnyTLS", name, false)?;
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box AnyTLS inbound {name} is missing users"))?;
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "AnyTLS", name)?;
        let ech = self
            .tls
            .ech
            .as_ref()
            .map(tls_ech_from_singbox_value)
            .transpose()?
            .flatten();
        Ok(ServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box AnyTLS inbound {name} is missing listen_port")
                })?,
            ),
            password: primary.password.clone(),
            users: self
                .users
                .iter()
                .skip(1)
                .map(|user| user.password.clone())
                .collect(),
            cert_path,
            key_path,
            certificates,
            key,
            padding_scheme: if self.padding_scheme.is_empty() {
                PaddingScheme::default_lines()
            } else {
                self.padding_scheme.clone()
            },
            heartbeat_interval_secs: 30,
            ech,
        })
    }
}

impl SingBoxMieruInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<MieruServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Mieru inbound {name}"), &self.extra)?;
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box Mieru inbound {name} is missing users"))?;
        let users = self
            .users
            .iter()
            .skip(1)
            .map(|user| {
                MieruUser::password(
                    user.username
                        .as_deref()
                        .unwrap_or(&user.password)
                        .to_string(),
                    user.password.clone(),
                )
            })
            .collect();
        Ok(MieruServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Mieru inbound {name} is missing listen_port")
                })?,
            ),
            username: primary
                .username
                .clone()
                .unwrap_or_else(|| primary.password.clone()),
            password: primary.password.clone(),
            users,
            mtu: self.mtu,
            user_hint_mandatory: self.user_hint_mandatory,
            transport: MieruTransport::parse(&self.transport)?,
            traffic_pattern: MieruTrafficPattern::parse_pair(
                self.traffic_pattern.as_deref(),
                self.nonce_pattern.as_deref(),
            )
            .with_context(|| format!("parse sing-box Mieru inbound {name} traffic pattern"))?,
        })
    }
}

impl SingBoxHysteria2Inbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<Hysteria2ServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Hysteria2 inbound {name}"), &self.extra)?;
        ensure!(
            self.tls.enabled,
            "sing-box Hysteria2 inbound {name} disables TLS; Hysteria2 requires TLS"
        );
        self.tls
            .ensure_supported_server_options("Hysteria2", name, false)?;
        ensure_supported_network("sing-box Hysteria2", name, self.network.as_deref())?;
        ensure_hy2_alpn("sing-box", name, self.tls.alpn.as_ref())?;
        ensure!(
            !json_value_non_empty_option(self.masquerade.as_ref()),
            "sing-box Hysteria2 inbound {name} sets masquerade; Aerion Hysteria2 server does not expose HTTP masquerade"
        );
        ensure!(
            self.bbr_profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
            "sing-box Hysteria2 inbound {name} sets bbr_profile {:?}; Aerion Hysteria2 uses the default BBR profile",
            self.bbr_profile
        );
        ensure!(
            !self.brutal_debug,
            "sing-box Hysteria2 inbound {name} enables brutal_debug; Aerion Hysteria2 server does not expose brutal debug"
        );
        let password = self
            .users
            .first()
            .map(|user| user.password.clone())
            .or_else(|| self.password.clone())
            .with_context(|| format!("sing-box Hysteria2 inbound {name} is missing password"))?;
        let users = if self.users.is_empty() {
            Vec::new()
        } else {
            self.users
                .iter()
                .skip(1)
                .map(|user| user.password.clone())
                .collect()
        };
        let obfs = match &self.obfs {
            Some(obfs) => {
                ensure_no_extra_fields(
                    &format!("sing-box Hysteria2 inbound {name} obfs"),
                    &obfs.extra,
                )?;
                ensure!(
                    obfs.kind.eq_ignore_ascii_case("salamander"),
                    "sing-box Hysteria2 inbound {name} uses obfs {}; Aerion supports salamander",
                    obfs.kind
                );
                (Some(obfs.kind.clone()), Some(obfs.password.clone()))
            }
            None => (None, None),
        };
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "Hysteria2", name)?;
        Ok(Hysteria2ServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Hysteria2 inbound {name} is missing listen_port")
                })?,
            ),
            password,
            users,
            cert_path,
            key_path,
            certificates,
            key,
            obfs: obfs.0,
            obfs_password: obfs.1,
            upload_bandwidth: self.up_mbps,
            udp: network_allows_udp(self.network.as_deref()),
            cc_rx: self
                .down_mbps
                .or(self.down)
                .map(|mbps| mbps.saturating_mul(125_000).to_string())
                .unwrap_or_else(|| "0".to_string()),
            congestion_control: "bbr".to_string(),
            auth_timeout: crate::hysteria2::DEFAULT_AUTH_TIMEOUT,
        })
    }
}

impl SingBoxTuicInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<TuicServerConfig> {
        ensure_no_extra_fields(&format!("sing-box TUIC inbound {name}"), &self.extra)?;
        ensure!(
            self.tls.enabled,
            "sing-box TUIC inbound {name} disables TLS; TUIC requires TLS"
        );
        self.tls
            .ensure_supported_server_options("TUIC", name, false)?;
        ensure_supported_network("sing-box TUIC", name, self.network.as_deref())?;
        ensure_tuic_alpn("sing-box", name, self.tls.alpn.as_ref())?;
        ensure!(
            !self.zero_rtt_handshake,
            "sing-box TUIC inbound {name} enables zero_rtt_handshake; Aerion TUIC server does not expose 0-RTT handshakes"
        );
        if let Some(mode) = self.udp_relay_mode.as_deref().map(str::trim) {
            ensure!(
                mode.is_empty()
                    || mode.eq_ignore_ascii_case("native")
                    || mode.eq_ignore_ascii_case("quic"),
                "sing-box TUIC inbound {name} sets udp_relay_mode {mode}; Aerion supports native and quic TUIC UDP relay commands"
            );
        }
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box TUIC inbound {name} is missing users"))?;
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "TUIC", name)?;
        Ok(TuicServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box TUIC inbound {name} is missing listen_port")
                })?,
            ),
            uuid: primary.uuid.clone(),
            password: primary.password.clone(),
            users: self
                .users
                .iter()
                .skip(1)
                .map(|user| format!("{}:{}", user.uuid, user.password))
                .collect(),
            cert_path,
            key_path,
            certificates,
            key,
            udp: network_allows_udp(self.network.as_deref()),
            congestion_control: self
                .congestion_control
                .clone()
                .unwrap_or_else(|| "cubic".to_string()),
            alpn_protocols: alpn_values(self.tls.alpn.as_ref()),
            heartbeat_interval_secs: self
                .heartbeat
                .as_deref()
                .map(parse_duration_secs)
                .transpose()?
                .unwrap_or(10),
        })
    }
}

impl SingBoxShadowsocksInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<ShadowsocksServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Shadowsocks inbound {name}"), &self.extra)?;
        ensure!(
            !self.managed,
            "sing-box Shadowsocks inbound {name} enables managed users; Aerion does not implement the SSM API"
        );
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure!(
            !json_value_non_empty_option(self.destinations.as_ref()),
            "sing-box Shadowsocks inbound {name} sets relay destinations; Aerion Shadowsocks server does not implement relay mode"
        );
        let (tcp, udp) = tcp_udp_network(
            "sing-box Shadowsocks inbound",
            name,
            self.network.as_deref(),
        )?;
        Ok(ShadowsocksServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Shadowsocks inbound {name} is missing listen_port")
                })?,
            ),
            method: self.method.clone(),
            password: self.password.clone(),
            users: self
                .users
                .iter()
                .map(|user| format!("{}:{}", user.name, user.password))
                .collect(),
            tcp,
            udp,
            udp_over_tcp: false,
        })
    }
}

impl SingBoxTrojanInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<TrojanServerConfig> {
        ensure_no_extra_fields(&format!("sing-box Trojan inbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure!(
            !json_value_non_empty_option(self.fallback.as_ref())
                && self.fallback_for_alpn.is_empty(),
            "sing-box Trojan inbound {name} sets fallback; Aerion Trojan server does not expose fallback routing"
        );
        ensure!(
            self.tls.enabled,
            "sing-box Trojan inbound {name} disables TLS; Trojan requires TLS in Aerion"
        );
        self.tls
            .ensure_supported_server_options("Trojan", name, false)?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        ensure_vless_alpn("sing-box", name, &transport, self.tls.alpn.as_ref())?;
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box Trojan inbound {name} is missing users"))?;
        let (cert_path, key_path, certificates, key) =
            singbox_tls_server_identity(&self.tls, "Trojan", name)?;
        let ech = self
            .tls
            .ech
            .as_ref()
            .map(tls_ech_from_singbox_value)
            .transpose()?
            .flatten();
        Ok(TrojanServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                listen_port.with_context(|| {
                    format!("sing-box Trojan inbound {name} is missing listen_port")
                })?,
            ),
            password: primary.password.clone(),
            users: self
                .users
                .iter()
                .skip(1)
                .map(|user| user.password.clone())
                .collect(),
            cert_path,
            key_path,
            certificates,
            key,
            transport,
            ech,
        })
    }
}

impl SingBoxVmessInbound {
    pub fn to_server_config(
        &self,
        name: &str,
        listen: Option<&str>,
        listen_port: Option<u16>,
    ) -> Result<VmessServerConfig> {
        ensure_no_extra_fields(&format!("sing-box VMess inbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        let primary = self
            .users
            .first()
            .with_context(|| format!("sing-box VMess inbound {name} is missing users"))?;
        ensure!(
            primary.alter_id == 0,
            "sing-box VMess inbound {name} primary user uses legacy alterId {}; Aerion implements AEAD VMess only",
            primary.alter_id
        );
        let user_id = primary.uuid.clone().with_context(|| {
            format!("sing-box VMess inbound {name} primary user is missing uuid")
        })?;
        let users = self
            .users
            .iter()
            .skip(1)
            .map(|user| {
                ensure!(
                    user.alter_id == 0,
                    "sing-box VMess inbound {name} extra user uses legacy alterId {}; Aerion implements AEAD VMess only",
                    user.alter_id
                );
                user.uuid
                    .clone()
                    .with_context(|| format!("sing-box VMess inbound {name} extra user is missing uuid"))
            })
            .collect::<Result<Vec<_>>>()?;
        let tls_enabled = self.tls.as_ref().map(|tls| tls.enabled).unwrap_or(false);
        if tls_enabled {
            let tls = self
                .tls
                .as_ref()
                .with_context(|| format!("sing-box VMess inbound {name} is missing tls"))?;
            tls.ensure_supported_server_options("VMess", name, false)?;
            ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
            let (cert_path, key_path, certificates, key) =
                singbox_tls_server_identity(tls, "VMess", name)?;
            let ech = tls
                .ech
                .as_ref()
                .map(tls_ech_from_singbox_value)
                .transpose()?
                .flatten();
            Ok(VmessServerConfig {
                listen: SocketAddr::new(
                    parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                    listen_port.with_context(|| {
                        format!("sing-box VMess inbound {name} is missing listen_port")
                    })?,
                ),
                user_id,
                users,
                tls: true,
                cert_path: Some(cert_path),
                key_path: Some(key_path),
                certificates,
                key,
                transport,
                ech,
            })
        } else {
            if let Some(tls) = &self.tls {
                tls.ensure_supported_server_options("VMess", name, true)?;
                ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
            }
            Ok(VmessServerConfig {
                listen: SocketAddr::new(
                    parse_listen_ip("sing-box", listen.unwrap_or("0.0.0.0"))?,
                    listen_port.with_context(|| {
                        format!("sing-box VMess inbound {name} is missing listen_port")
                    })?,
                ),
                user_id,
                users,
                tls: false,
                cert_path: None,
                key_path: None,
                certificates: Vec::new(),
                key: None,
                transport,
                ech: None,
            })
        }
    }
}
