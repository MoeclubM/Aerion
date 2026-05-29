//! Auto-extracted from the xray compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

impl XrayInbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.protocol)
    }

    pub fn to_server_config(&self) -> Result<XrayServerConfig> {
        let owner = format!("xray {} inbound {}", self.protocol, self.name());
        ensure_no_extra_fields(&owner, &self.extra)?;
        self.settings.reject_unsupported_extra_fields(&owner)?;
        self.stream_settings.reject_unsupported_fields(&owner)?;
        match self.protocol.trim().to_ascii_lowercase().as_str() {
            "anytls" | "any-tls" => Ok(XrayServerConfig::AnyTls(
                self.to_anytls_server_config()
                    .with_context(|| format!("convert xray AnyTLS inbound {}", self.name()))?,
            )),
            "shadowsocks" | "ss" => Ok(XrayServerConfig::Shadowsocks(
                self.to_shadowsocks_server_config()
                    .with_context(|| format!("convert xray Shadowsocks inbound {}", self.name()))?,
            )),
            "hysteria" | "hysteria2" | "hy2" => Ok(XrayServerConfig::Hysteria2(
                self.to_hysteria2_server_config()
                    .with_context(|| format!("convert xray Hysteria2 inbound {}", self.name()))?,
            )),
            "mieru" => Ok(XrayServerConfig::Mieru(
                self.to_mieru_server_config()
                    .with_context(|| format!("convert xray Mieru inbound {}", self.name()))?,
            )),
            "trojan" => Ok(XrayServerConfig::Trojan(
                self.to_trojan_server_config()
                    .with_context(|| format!("convert xray Trojan inbound {}", self.name()))?,
            )),
            "vless" => Ok(XrayServerConfig::Vless(
                self.to_vless_server_config()
                    .with_context(|| format!("convert xray VLESS inbound {}", self.name()))?,
            )),
            "vmess" => Ok(XrayServerConfig::Vmess(
                self.to_vmess_server_config()
                    .with_context(|| format!("convert xray VMess inbound {}", self.name()))?,
            )),
            other => bail!(
                "unsupported xray inbound {} protocol {}; Aerion cannot run this inbound protocol as a server",
                self.name(),
                other
            ),
        }
    }

    fn to_shadowsocks_server_config(&self) -> Result<ShadowsocksServerConfig> {
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray Shadowsocks inbound {} uses stream security {}; Aerion Shadowsocks expects raw Shadowsocks transport",
            self.name(),
            stream_security
        );
        let primary = self.settings.clients.first();
        let method = primary
            .and_then(|user| user.method.clone().or(user.security.clone()))
            .or(self.settings.method.clone())
            .or(self.settings.security.clone())
            .with_context(|| {
                format!("xray Shadowsocks inbound {} is missing method", self.name())
            })?;
        let password = primary
            .and_then(|user| user.password.clone())
            .or(self.settings.password.clone())
            .with_context(|| {
                format!(
                    "xray Shadowsocks inbound {} is missing password",
                    self.name()
                )
            })?;
        let (tcp, udp) = xray_tcp_udp_network(self.settings.network.as_deref())?;
        Ok(ShadowsocksServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray Shadowsocks inbound {} is missing port", self.name())
                })?,
            ),
            method: method.clone(),
            password,
            users: self
                .settings
                .clients
                .iter()
                .skip(1)
                .map(|user| {
                    let user_method = user
                        .method
                        .as_deref()
                        .or(user.security.as_deref())
                        .unwrap_or_default();
                    ensure!(
                        user_method.trim().is_empty() || user_method.eq_ignore_ascii_case(&method),
                        "xray Shadowsocks inbound {} extra client uses method {}; Aerion Shadowsocks server expects one method per inbound",
                        self.name(),
                        user_method
                    );
                    user.password.clone().with_context(|| {
                        format!(
                            "xray Shadowsocks inbound {} extra client is missing password",
                            self.name()
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            tcp,
            udp,
            udp_over_tcp: false,
        })
    }

    fn to_anytls_server_config(&self) -> Result<ServerConfig> {
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("tls"),
            "xray AnyTLS inbound {} uses stream security {}; AnyTLS requires TLS",
            self.name(),
            stream_security
        );
        let certificate = xray_first_server_certificate(
            self.stream_settings.tls_settings.as_ref(),
            "AnyTLS",
            self.name(),
        )?;
        let (cert_path, key_path, certificates, key) =
            xray_tls_server_identity(certificate, "AnyTLS", self.name())?;
        let ech = xray_tls_ech_server_keys(self.stream_settings.tls_settings.as_ref())?;
        let password = self
            .settings
            .password
            .clone()
            .or_else(|| {
                self.settings
                    .clients
                    .first()
                    .and_then(|user| user.password.clone().or(user.id.clone()))
            })
            .with_context(|| format!("xray AnyTLS inbound {} is missing password", self.name()))?;
        let users = self
            .settings
            .clients
            .iter()
            .skip(1)
            .filter_map(|user| user.password.clone().or(user.id.clone()))
            .collect();
        Ok(ServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray AnyTLS inbound {} is missing port", self.name())
                })?,
            ),
            password,
            users,
            cert_path,
            key_path,
            certificates,
            key,
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
            ech,
        })
    }

    fn to_mieru_server_config(&self) -> Result<MieruServerConfig> {
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray Mieru inbound {} uses stream security {}; Mieru uses its own transport crypto",
            self.name(),
            stream_security
        );
        let primary = self
            .settings
            .clients
            .first()
            .cloned()
            .unwrap_or_else(|| XrayUser {
                id: self.settings.user.clone(),
                password: self.settings.password.clone(),
                auth: self.settings.auth.clone(),
                method: None,
                encryption: None,
                flow: None,
                packet_encoding: None,
                security: None,
                alter_id: None,
                extra: Map::new(),
            });
        let password = primary
            .password
            .or(primary.auth)
            .or(self.settings.password.clone())
            .with_context(|| format!("xray Mieru inbound {} is missing password", self.name()))?;
        let username = primary
            .id
            .or(self.settings.user.clone())
            .unwrap_or_else(|| password.clone());
        let users = self
            .settings
            .clients
            .iter()
            .skip(1)
            .map(|user| {
                let password = user
                    .password
                    .clone()
                    .or(user.auth.clone())
                    .with_context(|| {
                        format!(
                            "xray Mieru inbound {} user is missing password",
                            self.name()
                        )
                    })?;
                Ok(MieruUser::password(
                    user.id.clone().unwrap_or_else(|| password.clone()),
                    password,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(MieruServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray Mieru inbound {} is missing port", self.name())
                })?,
            ),
            username,
            password,
            users,
            mtu: 1500,
            user_hint_mandatory: false,
            transport: MieruTransport::parse(
                self.settings
                    .network
                    .as_deref()
                    .unwrap_or(&self.stream_settings.network),
            )?,
            traffic_pattern: None,
        })
    }

    fn to_hysteria2_server_config(&self) -> Result<Hysteria2ServerConfig> {
        let hysteria = self.stream_settings.hysteria_settings.as_ref();
        let version = self
            .settings
            .version
            .or_else(|| hysteria.and_then(|settings| settings.version));
        ensure!(
            !self.protocol.eq_ignore_ascii_case("hysteria") || version == Some(2),
            "xray Hysteria inbound {} uses version {:?}; Aerion supports Hysteria2 version 2",
            self.name(),
            version
        );
        if let Some(version) = version {
            ensure!(
                version == 2,
                "xray Hysteria inbound {} uses version {}; Aerion supports Hysteria2 version 2",
                self.name(),
                version
            );
        }
        let network = self.stream_settings.network.trim();
        ensure!(
            network.eq_ignore_ascii_case("hysteria"),
            "xray Hysteria inbound {} uses network {}; Aerion Hysteria2 expects hysteria transport",
            self.name(),
            network
        );
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty()
                || stream_security.eq_ignore_ascii_case("none")
                || stream_security.eq_ignore_ascii_case("tls"),
            "xray Hysteria inbound {} uses stream security {}; Aerion Hysteria2 expects TLS-backed hysteria transport",
            self.name(),
            stream_security
        );
        ensure!(
            !hysteria
                .and_then(|settings| settings.udp_hop.as_ref())
                .map(value_has_data)
                .unwrap_or(false),
            "xray Hysteria inbound {} enables UDP port hopping; Aerion Hysteria2 server expects one fixed port",
            self.name()
        );
        ensure!(
            !hysteria
                .and_then(|settings| settings.masquerade.as_ref())
                .map(value_has_data)
                .unwrap_or(false),
            "xray Hysteria inbound {} sets masquerade; Aerion Hysteria2 server does not expose HTTP masquerade",
            self.name()
        );
        let tls = self.stream_settings.tls_settings.as_ref();
        ensure_hysteria_alpn(
            "xray",
            self.name(),
            tls.and_then(|settings| settings.alpn.as_ref()),
        )?;
        let certificate = xray_first_server_certificate(tls, "Hysteria", self.name())?;
        let finalmask = self.stream_settings.finalmask.as_ref();
        if let Some(finalmask) = finalmask {
            ensure!(
                finalmask.tcp.is_empty(),
                "xray Hysteria inbound {} sets finalmask TCP masks; Aerion Hysteria2 only maps salamander UDP obfs",
                self.name()
            );
            ensure!(
                finalmask.udp.len() <= 1,
                "xray Hysteria inbound {} sets multiple finalmask UDP masks; Aerion Hysteria2 exposes one obfs layer",
                self.name()
            );
            ensure!(
                !finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.udp_hop.as_ref())
                    .map(value_has_data)
                    .unwrap_or(false),
                "xray Hysteria inbound {} enables finalmask UDP port hopping; Aerion Hysteria2 server expects one fixed port",
                self.name()
            );
            ensure!(
                finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.bbr_profile.as_deref())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
                "xray Hysteria inbound {} sets finalmask bbrProfile {:?}; Aerion Hysteria2 uses the default BBR profile",
                self.name(),
                finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.bbr_profile.as_ref())
            );
            ensure!(
                !finalmask
                    .quic_params
                    .as_ref()
                    .map(|params| params.debug)
                    .unwrap_or(false),
                "xray Hysteria inbound {} enables finalmask quicParams debug; Aerion Hysteria2 server does not expose QUIC debug toggles",
                self.name()
            );
        }
        let (obfs, obfs_password) = match finalmask.and_then(|finalmask| finalmask.udp.first()) {
            Some(mask) => {
                ensure!(
                    mask.kind.eq_ignore_ascii_case("salamander"),
                    "xray Hysteria inbound {} uses finalmask UDP mask {}; Aerion supports salamander",
                    self.name(),
                    mask.kind
                );
                let password = mask
                    .settings
                    .as_ref()
                    .and_then(|settings| settings.get("password"))
                    .and_then(Value::as_str)
                    .with_context(|| {
                        format!(
                            "xray Hysteria inbound {} salamander mask is missing password",
                            self.name()
                        )
                    })?
                    .to_string();
                (Some("salamander".to_string()), Some(password))
            }
            None => (None, None),
        };
        let congestion_control = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.congestion.clone())
            .or_else(|| hysteria.and_then(|settings| settings.congestion.clone()))
            .unwrap_or_else(|| "bbr".to_string());
        ensure!(
            congestion_control.trim().is_empty()
                || congestion_control.eq_ignore_ascii_case("bbr")
                || congestion_control.eq_ignore_ascii_case("reno"),
            "xray Hysteria inbound {} uses congestion {}; Aerion Hysteria2 supports bbr or reno",
            self.name(),
            congestion_control
        );
        let password = self
            .settings
            .clients
            .first()
            .and_then(|user| user.auth.clone().or(user.password.clone()))
            .or_else(|| hysteria.and_then(|settings| settings.auth.clone()))
            .or(self.settings.auth.clone())
            .or(self.settings.password.clone())
            .with_context(|| format!("xray Hysteria inbound {} is missing auth", self.name()))?;
        let users = self
            .settings
            .clients
            .iter()
            .skip(1)
            .map(|user| {
                user.auth
                    .clone()
                    .or(user.password.clone())
                    .with_context(|| {
                        format!(
                            "xray Hysteria inbound {} extra client is missing auth",
                            self.name()
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let cc_rx = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.brutal_down)
            .or_else(|| hysteria.and_then(|settings| settings.down))
            .map(|mbps| mbps.saturating_mul(125_000).to_string())
            .unwrap_or_else(|| "0".to_string());
        let (cert_path, key_path, certificates, key) =
            xray_tls_server_identity(certificate, "Hysteria", self.name())?;
        let upload_bandwidth = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.brutal_up)
            .or_else(|| hysteria.and_then(|settings| settings.up));
        Ok(Hysteria2ServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray Hysteria inbound {} is missing port", self.name())
                })?,
            ),
            password,
            users,
            cert_path,
            key_path,
            certificates,
            key,
            obfs,
            obfs_password,
            upload_bandwidth,
            udp: true,
            cc_rx,
            congestion_control,
        })
    }

    fn to_trojan_server_config(&self) -> Result<TrojanServerConfig> {
        ensure!(
            self.settings.fallbacks.is_empty(),
            "xray Trojan inbound {} sets fallbacks; Aerion Trojan server does not expose fallback routing",
            self.name()
        );
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.eq_ignore_ascii_case("tls"),
            "xray Trojan inbound {} uses stream security {}; Aerion Trojan server requires TLS",
            self.name(),
            stream_security
        );
        let transport = XrayOutbound {
            tag: self.tag.clone(),
            protocol: self.protocol.clone(),
            settings: XrayOutboundSettings::default(),
            stream_settings: self.stream_settings.clone(),
            mux: None,
            decode_error: None,
            extra: Map::new(),
        }
        .vless_transport_config()?;
        ensure_vless_alpn(
            "xray",
            self.name(),
            &transport,
            self.stream_settings
                .tls_settings
                .as_ref()
                .and_then(|tls| tls.alpn.as_ref()),
        )?;
        let certificate = xray_first_server_certificate(
            self.stream_settings.tls_settings.as_ref(),
            "Trojan",
            self.name(),
        )?;
        let primary = self
            .settings
            .clients
            .first()
            .context("xray Trojan inbound is missing settings.clients")?;
        let (cert_path, key_path, certificates, key) =
            xray_tls_server_identity(certificate, "Trojan", self.name())?;
        let ech = xray_tls_ech_server_keys(self.stream_settings.tls_settings.as_ref())?;
        Ok(TrojanServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray Trojan inbound {} is missing port", self.name())
                })?,
            ),
            password: primary
                .password
                .clone()
                .context("xray Trojan inbound primary client is missing password")?,
            users: self
                .settings
                .clients
                .iter()
                .skip(1)
                .map(|user| {
                    user.password
                        .clone()
                        .context("xray Trojan inbound extra client is missing password")
                })
                .collect::<Result<Vec<_>>>()?,
            cert_path,
            key_path,
            certificates,
            key,
            transport,
            ech,
        })
    }

    fn to_vless_server_config(&self) -> Result<VlessServerConfig> {
        let decryption = self.settings.decryption.as_deref().unwrap_or("none");
        ensure!(
            decryption.trim().is_empty() || decryption.eq_ignore_ascii_case("none"),
            "xray VLESS inbound {} uses decryption {}; Aerion supports VLESS decryption none",
            self.name(),
            decryption
        );
        ensure!(
            self.settings.fallbacks.is_empty(),
            "xray VLESS inbound {} sets fallbacks; Aerion VLESS server does not expose fallback routing",
            self.name()
        );
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty()
                || stream_security.eq_ignore_ascii_case("none")
                || stream_security.eq_ignore_ascii_case("tls")
                || stream_security.eq_ignore_ascii_case("reality"),
            "xray VLESS inbound {} uses stream security {}; Aerion maps raw TCP, TLS, or REALITY VLESS server configs",
            self.name(),
            stream_security
        );
        let tls = self.stream_settings.tls_settings.as_ref();
        let reality_settings = self.stream_settings.reality_settings.as_ref();
        let transport = XrayOutbound {
            tag: self.tag.clone(),
            protocol: self.protocol.clone(),
            settings: XrayOutboundSettings::default(),
            stream_settings: self.stream_settings.clone(),
            mux: None,
            decode_error: None,
            extra: Map::new(),
        }
        .vless_transport_config()?;
        if stream_security.eq_ignore_ascii_case("tls")
            || stream_security.eq_ignore_ascii_case("reality")
        {
            ensure_vless_alpn(
                "xray",
                self.name(),
                &transport,
                if stream_security.eq_ignore_ascii_case("reality") {
                    reality_settings.and_then(|settings| settings.alpn.as_ref())
                } else {
                    tls.and_then(|settings| settings.alpn.as_ref())
                },
            )?;
        } else {
            ensure_no_alpn("xray", self.name(), tls.and_then(|tls| tls.alpn.as_ref()))?;
        }
        let primary = self
            .settings
            .clients
            .first()
            .context("xray VLESS inbound is missing settings.clients")?;
        let user_id = primary
            .id
            .clone()
            .context("xray VLESS inbound primary client is missing id")?;
        let flow = primary
            .flow
            .clone()
            .or(self.settings.flow.clone())
            .unwrap_or_default();
        let users = self
            .settings
            .clients
            .iter()
            .skip(1)
            .map(|user| {
                let id = user
                    .id
                    .clone()
                    .context("xray VLESS inbound extra client is missing id")?;
                let user_flow = user
                    .flow
                    .clone()
                    .or(self.settings.flow.clone())
                    .unwrap_or_default();
                ensure!(
                    user_flow == flow,
                    "xray VLESS inbound {} uses per-client flow; Aerion VLESS server expects one flow for the inbound",
                    self.name()
                );
                Ok(id)
            })
            .collect::<Result<Vec<_>>>()?;
        let (cert_path, key_path, certificates, key) =
            if stream_security.eq_ignore_ascii_case("tls") {
                let certificate = xray_first_server_certificate(tls, "VLESS", self.name())?;
                xray_tls_server_identity(certificate, "VLESS", self.name())?
            } else {
                (PathBuf::new(), PathBuf::new(), Vec::new(), None)
            };
        let ech = if stream_security.eq_ignore_ascii_case("tls") {
            xray_tls_ech_server_keys(tls)?
        } else {
            None
        };
        let reality = if stream_security.eq_ignore_ascii_case("reality") {
            let settings = reality_settings.with_context(|| {
                format!(
                    "xray VLESS inbound {} is missing realitySettings",
                    self.name()
                )
            })?;
            Some(xray_reality_server_config(
                self.name(),
                settings,
                &transport,
            )?)
        } else {
            None
        };
        Ok(VlessServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray VLESS inbound {} is missing port", self.name())
                })?,
            ),
            user_id,
            users,
            tls: stream_security.eq_ignore_ascii_case("tls"),
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

    fn to_vmess_server_config(&self) -> Result<VmessServerConfig> {
        ensure_raw_or_tls_stream_security(
            "xray VMess",
            self.name(),
            &self.stream_settings.security,
        )?;
        let transport = XrayOutbound {
            tag: self.tag.clone(),
            protocol: self.protocol.clone(),
            settings: XrayOutboundSettings::default(),
            stream_settings: self.stream_settings.clone(),
            mux: None,
            decode_error: None,
            extra: Map::new(),
        }
        .vless_transport_config()?;
        let tls_enabled = self
            .stream_settings
            .security
            .trim()
            .eq_ignore_ascii_case("tls");
        if tls_enabled {
            ensure_vless_alpn(
                "xray",
                self.name(),
                &transport,
                self.stream_settings
                    .tls_settings
                    .as_ref()
                    .and_then(|tls| tls.alpn.as_ref()),
            )?;
        } else {
            ensure_no_alpn(
                "xray",
                self.name(),
                self.stream_settings
                    .tls_settings
                    .as_ref()
                    .and_then(|tls| tls.alpn.as_ref()),
            )?;
        }
        let primary = self
            .settings
            .clients
            .first()
            .context("xray VMess inbound is missing settings.clients")?;
        let alter_id = primary.alter_id.or(self.settings.alter_id).unwrap_or(0);
        ensure!(
            alter_id == 0,
            "xray VMess inbound {} primary client uses legacy alterId {}; Aerion implements AEAD VMess only",
            self.name(),
            alter_id
        );
        let user_id = primary
            .id
            .clone()
            .context("xray VMess inbound primary client is missing id")?;
        let users = self
            .settings
            .clients
            .iter()
            .skip(1)
            .map(|user| {
                let alter_id = user.alter_id.or(self.settings.alter_id).unwrap_or(0);
                ensure!(
                    alter_id == 0,
                    "xray VMess inbound {} extra client uses legacy alterId {}; Aerion implements AEAD VMess only",
                    self.name(),
                    alter_id
                );
                user.id
                    .clone()
                    .context("xray VMess inbound extra client is missing id")
            })
            .collect::<Result<Vec<_>>>()?;
        let (cert_path, key_path, certificates, key) = if tls_enabled {
            let certificate = xray_first_server_certificate(
                self.stream_settings.tls_settings.as_ref(),
                "VMess",
                self.name(),
            )?;
            let (cert_path, key_path, certificates, key) =
                xray_tls_server_identity(certificate, "VMess", self.name())?;
            (Some(cert_path), Some(key_path), certificates, key)
        } else {
            (None, None, Vec::new(), None)
        };
        let ech = if tls_enabled {
            xray_tls_ech_server_keys(self.stream_settings.tls_settings.as_ref())?
        } else {
            None
        };
        Ok(VmessServerConfig {
            listen: SocketAddr::new(
                parse_listen_ip("xray", self.listen.as_deref().unwrap_or("0.0.0.0"))?,
                self.port.with_context(|| {
                    format!("xray VMess inbound {} is missing port", self.name())
                })?,
            ),
            user_id,
            users,
            tls: tls_enabled,
            cert_path,
            key_path,
            certificates,
            key,
            transport,
            ech,
        })
    }
}

