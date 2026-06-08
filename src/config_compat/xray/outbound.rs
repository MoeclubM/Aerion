//! Auto-extracted from the xray compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

impl XrayOutbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.protocol)
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<XrayClientConfig> {
        ensure!(
            self.decode_error.is_none(),
            "parse xray outbound {} failed: {}",
            self.name(),
            self.decode_error.as_deref().unwrap_or_default()
        );
        let owner = format!("xray {} outbound {}", self.protocol, self.name());
        ensure_no_extra_fields(&owner, &self.extra)?;
        self.settings.reject_unsupported_extra_fields(&owner)?;
        self.stream_settings.reject_unsupported_fields(&owner)?;
        match self.protocol.trim().to_ascii_lowercase().as_str() {
            "anytls" | "any-tls" => Ok(XrayClientConfig::AnyTls(
                self.to_anytls_client_config(listen)?,
            )),
            "freedom" => Ok(XrayClientConfig::Route(
                self.to_route_client_config(listen, RouteDecision::Direct)?,
            )),
            "blackhole" => Ok(XrayClientConfig::Route(
                self.to_route_client_config(listen, RouteDecision::Block)?,
            )),
            "shadowsocks" | "ss" => Ok(XrayClientConfig::Shadowsocks(
                self.to_shadowsocks_client_config(listen)?,
            )),
            "socks" | "socks5" => Ok(XrayClientConfig::SocksProxy(
                self.to_socks_client_config(listen)?,
            )),
            "http" => Ok(XrayClientConfig::HttpProxy(
                self.to_http_client_config(listen)?,
            )),
            "vless" => Ok(XrayClientConfig::Vless(
                self.to_vless_client_config(listen)?,
            )),
            "vmess" => Ok(XrayClientConfig::Vmess(
                self.to_vmess_client_config(listen)?,
            )),
            "trojan" => Ok(XrayClientConfig::Trojan(
                self.to_trojan_client_config(listen)?,
            )),
            "hysteria" | "hysteria2" | "hy2" => Ok(XrayClientConfig::Hysteria2(
                self.to_hysteria2_client_config(listen)?,
            )),
            "mieru" => Ok(XrayClientConfig::Mieru(
                self.to_mieru_client_config(listen)?,
            )),
            other => bail!("unsupported xray outbound protocol {other}"),
        }
    }

    fn to_route_client_config(
        &self,
        listen: SocketAddr,
        default: RouteDecision,
    ) -> Result<RouteClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray {} outbound {}", self.protocol, self.name()),
            self.mux.as_ref(),
            "Aerion route client does not use Xray mux",
        )?;
        ensure_tcp_network("xray route", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray {} outbound {} uses stream security {}; Aerion route client does not use Xray stream security",
            self.protocol,
            self.name(),
            stream_security
        );
        ensure!(
            self.stream_settings.hysteria_settings.is_none()
                && self.stream_settings.finalmask.is_none()
                && self.stream_settings.tls_settings.is_none()
                && self.stream_settings.reality_settings.is_none()
                && self.stream_settings.ws_settings.is_none()
                && self.stream_settings.http_upgrade_settings.is_none()
                && self.stream_settings.grpc_settings.is_none()
                && self.stream_settings.http_settings.is_none()
                && self.stream_settings.xhttp_settings.is_none()
                && self.stream_settings.split_http_settings.is_none(),
            "xray {} outbound {} sets stream transport options; Aerion route client handles plain direct/block routing",
            self.protocol,
            self.name()
        );
        ensure_empty_route_settings(&self.settings, &self.protocol, self.name())?;
        Ok(RouteClientConfig { listen, default })
    }

    fn to_anytls_client_config(&self, listen: SocketAddr) -> Result<ClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray AnyTLS outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion AnyTLS client does not use Xray mux",
        )?;
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("tls"),
            "xray AnyTLS outbound {} uses stream security {}; AnyTLS requires TLS",
            self.name(),
            stream_security
        );
        let server = self.first_trojan_server()?;
        let tls = self.stream_settings.tls_settings.as_ref();
        let (ca_cert_paths, ca_certificates) = xray_tls_client_roots(tls)?;
        Ok(ClientConfig {
            listen,
            server_host: server.address.clone(),
            server_port: server.port,
            password: server
                .password
                .or(self.settings.password.clone())
                .with_context(|| {
                    format!("xray AnyTLS outbound {} is missing password", self.name())
                })?,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server.address,
                self.name(),
            ),
            insecure: tls.map(|settings| settings.allow_insecure).unwrap_or(false),
            client_fingerprint: tls.and_then(|settings| settings.fingerprint),
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, true),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, true),
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
        })
    }

    fn to_mieru_client_config(&self, listen: SocketAddr) -> Result<MieruClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray Mieru outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion Mieru client does not use Xray mux",
        )?;
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray Mieru outbound {} uses stream security {}; Mieru uses its own transport crypto",
            self.name(),
            stream_security
        );
        let server = self.first_trojan_server()?;
        let password = server
            .password
            .or(self.settings.password.clone())
            .with_context(|| format!("xray Mieru outbound {} is missing password", self.name()))?;
        Ok(MieruClientConfig {
            listen,
            server_host: server.address,
            server_port: server.port,
            username: self
                .settings
                .user
                .clone()
                .unwrap_or_else(|| password.clone()),
            password,
            hashed_password: None,
            mtu: 1500,
            transport: MieruTransport::parse(
                self.settings
                    .network
                    .as_deref()
                    .unwrap_or(&self.stream_settings.network),
            )?,
            traffic_pattern: None,
        })
    }

    fn to_http_client_config(&self, listen: SocketAddr) -> Result<HttpProxyClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray HTTP outbound {}", self.name()),
            self.mux.as_ref(),
            "HTTP CONNECT proxying does not use Xray mux",
        )?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty()
                || stream_security.eq_ignore_ascii_case("none")
                || stream_security.eq_ignore_ascii_case("tls"),
            "xray HTTP outbound {} uses stream security {}; Aerion HTTP proxy supports raw TCP or TLS",
            self.name(),
            stream_security
        );
        let tls_enabled = stream_security.eq_ignore_ascii_case("tls");
        if tls_enabled {
            ensure_http_alpn("xray", self.name(), self.stream_alpn())?;
        } else {
            ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
        }
        let tls = self.stream_settings.tls_settings.as_ref();
        if !tls_enabled {
            ensure!(
                tls.is_none_or(|settings| {
                    !settings.allow_insecure
                        && settings.fingerprint.is_none()
                        && settings
                            .server_name
                            .as_deref()
                            .map(str::trim)
                            .unwrap_or_default()
                            .is_empty()
                        && !settings.disable_system_root
                        && settings.pinned_peer_cert_sha256.is_none()
                        && settings.certificates.is_empty()
                }),
                "xray HTTP outbound {} sets TLS-only options while stream security is not tls",
                self.name()
            );
        }
        let (ca_cert_paths, ca_certificates) = if tls_enabled {
            xray_tls_client_roots(tls)?
        } else {
            (Vec::new(), Vec::new())
        };
        let server = self.first_trojan_server()?;
        let server_user = server.users.first();
        let server_host = server.address.clone();
        Ok(HttpProxyClientConfig {
            listen,
            server_host: server_host.clone(),
            server_port: server.port,
            username: self
                .settings
                .user
                .clone()
                .or_else(|| server_user.and_then(|user| user.user.clone()))
                .unwrap_or_default(),
            password: self
                .settings
                .pass
                .clone()
                .or_else(|| server_user.and_then(|user| user.pass.clone()))
                .unwrap_or_default(),
            tls: tls_enabled,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server_host,
                self.name(),
            ),
            insecure: if tls_enabled {
                tls.map(|settings| settings.allow_insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, tls_enabled),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, tls_enabled),
            client_fingerprint: if tls_enabled {
                tls.and_then(|settings| settings.fingerprint)
            } else {
                None
            },
            extra_headers: self.settings.headers.clone().into_iter().collect(),
        })
    }

    fn to_socks_client_config(&self, listen: SocketAddr) -> Result<SocksProxyClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray SOCKS outbound {}", self.name()),
            self.mux.as_ref(),
            "SOCKS proxying does not use Xray mux",
        )?;
        ensure_tcp_network("xray SOCKS", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray SOCKS outbound {} uses stream security {}; Aerion SOCKS outbound is plain SOCKS5",
            self.name(),
            stream_security
        );
        ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
        let tls = self.stream_settings.tls_settings.as_ref();
        ensure!(
            tls.is_none_or(|settings| {
                !settings.allow_insecure
                    && settings.fingerprint.is_none()
                    && settings
                        .server_name
                        .as_deref()
                        .map(str::trim)
                        .unwrap_or_default()
                        .is_empty()
                    && !settings.disable_system_root
                    && settings.pinned_peer_cert_sha256.is_none()
                    && settings.certificates.is_empty()
            }),
            "xray SOCKS outbound {} sets TLS-only options",
            self.name()
        );
        ensure!(
            self.settings.headers.is_empty(),
            "xray SOCKS outbound {} sets HTTP headers; SOCKS does not use headers",
            self.name()
        );
        let (tcp, udp) = xray_tcp_udp_outbound_network(self.settings.network.as_deref())?;
        ensure!(
            tcp,
            "xray SOCKS outbound {} uses udp-only network; Aerion SOCKS outbound requires TCP control channel",
            self.name()
        );
        let server = self.first_trojan_server()?;
        let server_user = server.users.first();
        Ok(SocksProxyClientConfig {
            listen,
            server_host: server.address.clone(),
            server_port: server.port,
            username: self
                .settings
                .user
                .clone()
                .or_else(|| server_user.and_then(|user| user.user.clone()))
                .unwrap_or_default(),
            password: self
                .settings
                .pass
                .clone()
                .or_else(|| server_user.and_then(|user| user.pass.clone()))
                .unwrap_or_default(),
            udp,
        })
    }

    fn to_vless_client_config(&self, listen: SocketAddr) -> Result<VlessClientConfig> {
        let peer = self.first_vless_or_vmess_peer()?;
        let mux = xray_mux_enabled(
            &format!("xray VLESS outbound {}", self.name()),
            self.mux.as_ref(),
        )?;
        ensure!(
            peer.user
                .encryption
                .as_deref()
                .unwrap_or("none")
                .eq_ignore_ascii_case("none"),
            "xray VLESS outbound {} uses encryption {:?}; Aerion supports VLESS encryption none",
            self.name(),
            peer.user.encryption
        );
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty()
                || stream_security.eq_ignore_ascii_case("none")
                || stream_security.eq_ignore_ascii_case("tls")
                || stream_security.eq_ignore_ascii_case("reality"),
            "xray VLESS outbound {} uses stream security {}; Aerion VLESS supports raw TCP, TLS, or REALITY",
            self.name(),
            stream_security
        );
        let transport = self.vless_transport_config()?;
        let tls_enabled = stream_security.eq_ignore_ascii_case("tls");
        let reality = if self.is_reality() {
            Some(self.reality_client_config()?)
        } else {
            None
        };
        if tls_enabled || reality.is_some() {
            ensure_vless_alpn("xray", self.name(), &transport, self.stream_alpn())?;
        } else {
            ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
        }
        let tls = self.stream_settings.tls_settings.as_ref();
        let reality_settings = self.stream_settings.reality_settings.as_ref();
        let tls_server_name = if reality.is_some() {
            reality_settings.and_then(|settings| settings.server_name.as_deref())
        } else if tls_enabled {
            tls.and_then(|settings| settings.server_name.as_deref())
        } else {
            None
        };
        let client_fingerprint = if reality.is_some() {
            reality_settings.and_then(|settings| settings.fingerprint)
        } else if tls_enabled {
            tls.and_then(|settings| settings.fingerprint)
        } else {
            None
        };
        let (ca_cert_paths, ca_certificates) = if tls_enabled {
            xray_tls_client_roots(tls)?
        } else {
            (Vec::new(), Vec::new())
        };
        let server_host = peer.address.clone();
        Ok(VlessClientConfig {
            listen,
            server_host: server_host.clone(),
            server_port: peer.port,
            user_id: peer.user.id.with_context(|| {
                format!("xray VLESS outbound {} is missing user id", self.name())
            })?,
            tls: tls_enabled,
            sni: sni_or_server(tls_server_name, &server_host, self.name()),
            insecure: if tls_enabled {
                tls.map(|settings| settings.allow_insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, tls_enabled),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, tls_enabled),
            flow: peer
                .user
                .flow
                .or(self.settings.flow.clone())
                .unwrap_or_default(),
            packet_encoding: peer
                .user
                .packet_encoding
                .or(self.settings.packet_encoding.clone())
                .unwrap_or_default(),
            mux,
            udp: true,
            client_fingerprint,
            reality,
            transport,
        })
    }

    fn to_shadowsocks_client_config(&self, listen: SocketAddr) -> Result<ShadowsocksClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray Shadowsocks outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion Shadowsocks client does not use Xray mux",
        )?;
        let server = self.first_trojan_server()?;
        ensure_tcp_network("xray", self.name(), &self.stream_settings.network)?;
        let stream_security = self.stream_settings.security.trim();
        ensure!(
            stream_security.is_empty() || stream_security.eq_ignore_ascii_case("none"),
            "xray Shadowsocks outbound {} uses stream security {}; Aerion Shadowsocks expects raw Shadowsocks transport",
            self.name(),
            stream_security
        );
        Ok(ShadowsocksClientConfig {
            listen,
            server_host: server.address.clone(),
            server_port: server.port,
            method: server
                .method
                .or(self.settings.method.clone())
                .or(self.settings.security.clone())
                .with_context(|| {
                    format!(
                        "xray Shadowsocks outbound {} is missing method",
                        self.name()
                    )
                })?,
            password: server.password.with_context(|| {
                format!(
                    "xray Shadowsocks outbound {} is missing password",
                    self.name()
                )
            })?,
            udp: true,
            udp_over_tcp: false,
        })
    }

    fn to_vmess_client_config(&self, listen: SocketAddr) -> Result<VmessClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray VMess outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion VMess client does not use Xray mux",
        )?;
        let peer = self.first_vless_or_vmess_peer()?;
        ensure_raw_or_tls_stream_security(
            "xray VMess",
            self.name(),
            &self.stream_settings.security,
        )?;
        let transport = self.vless_transport_config()?;
        let alter_id = peer.user.alter_id.or(self.settings.alter_id).unwrap_or(0);
        ensure!(
            alter_id == 0,
            "xray VMess outbound {} uses legacy alterId {}; Aerion implements AEAD VMess only",
            self.name(),
            alter_id
        );
        let packet_encoding = peer
            .user
            .packet_encoding
            .clone()
            .or(self.settings.packet_encoding.clone())
            .unwrap_or_default();
        ensure_vmess_packet_encoding(&packet_encoding)
            .with_context(|| format!("xray VMess outbound {} packetEncoding", self.name()))?;
        let tls = self.stream_settings.tls_settings.as_ref();
        let tls_enabled = self
            .stream_settings
            .security
            .trim()
            .eq_ignore_ascii_case("tls");
        if tls_enabled {
            ensure_vless_alpn("xray", self.name(), &transport, self.stream_alpn())?;
        } else {
            ensure_no_alpn("xray", self.name(), self.stream_alpn())?;
        }
        let (ca_cert_paths, ca_certificates) = if tls_enabled {
            xray_tls_client_roots(tls)?
        } else {
            (Vec::new(), Vec::new())
        };
        let server_host = peer.address.clone();
        Ok(VmessClientConfig {
            listen,
            server_host: server_host.clone(),
            server_port: peer.port,
            user_id: peer.user.id.with_context(|| {
                format!("xray VMess outbound {} is missing user id", self.name())
            })?,
            security: peer
                .user
                .security
                .or(self.settings.security.clone())
                .unwrap_or_else(|| "auto".to_string()),
            packet_encoding,
            udp: true,
            tls: tls_enabled,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server_host,
                self.name(),
            ),
            insecure: if tls_enabled {
                tls.map(|settings| settings.allow_insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, tls_enabled),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, tls_enabled),
            client_fingerprint: if tls_enabled {
                tls.and_then(|settings| settings.fingerprint)
            } else {
                None
            },
            transport,
        })
    }

    fn to_trojan_client_config(&self, listen: SocketAddr) -> Result<TrojanClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray Trojan outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion Trojan client does not use Xray mux",
        )?;
        let server = self.first_trojan_server()?;
        let transport = self.vless_transport_config()?;
        ensure_tls_or_reality("xray Trojan", self.name(), &self.stream_settings.security)?;
        ensure!(
            !self.is_reality(),
            "xray Trojan outbound {} uses REALITY; Aerion only wires REALITY on VLESS",
            self.name()
        );
        ensure_vless_alpn("xray", self.name(), &transport, self.stream_alpn())?;
        let tls = self.stream_settings.tls_settings.as_ref();
        let (ca_cert_paths, ca_certificates) = xray_tls_client_roots(tls)?;
        let server_host = server.address.clone();
        Ok(TrojanClientConfig {
            listen,
            server_host: server_host.clone(),
            server_port: server.port,
            password: server.password.with_context(|| {
                format!("xray Trojan outbound {} is missing password", self.name())
            })?,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server_host,
                self.name(),
            ),
            insecure: tls.map(|settings| settings.allow_insecure).unwrap_or(false),
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, true),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, true),
            udp: true,
            client_fingerprint: tls.and_then(|settings| settings.fingerprint),
            transport,
        })
    }

    fn to_hysteria2_client_config(&self, listen: SocketAddr) -> Result<Hysteria2ClientConfig> {
        ensure_xray_mux_disabled(
            &format!("xray Hysteria outbound {}", self.name()),
            self.mux.as_ref(),
            "Aerion Hysteria2 client does not use Xray mux",
        )?;
        let server = self.first_trojan_server()?;
        let hysteria = self.stream_settings.hysteria_settings.as_ref();
        let version = self
            .settings
            .version
            .or_else(|| hysteria.and_then(|settings| settings.version));
        ensure!(
            !self.protocol.eq_ignore_ascii_case("hysteria") || version == Some(2),
            "xray Hysteria outbound {} uses version {:?}; Aerion supports Hysteria2 version 2",
            self.name(),
            version
        );
        if let Some(version) = version {
            ensure!(
                version == 2,
                "xray Hysteria outbound {} uses version {}; Aerion supports Hysteria2 version 2",
                self.name(),
                version
            );
        }
        let network = self.stream_settings.network.trim();
        if self.protocol.eq_ignore_ascii_case("hysteria") {
            ensure!(
                network.eq_ignore_ascii_case("hysteria"),
                "xray Hysteria outbound {} uses network {}; Xray Hysteria profiles use hysteria transport",
                self.name(),
                network
            );
        } else {
            ensure!(
                network.is_empty()
                    || network.eq_ignore_ascii_case("tcp")
                    || network.eq_ignore_ascii_case("hysteria"),
                "xray Hysteria2 outbound {} uses network {}; Aerion Hysteria2 expects hysteria transport",
                self.name(),
                network
            );
        }
        let tls = self.stream_settings.tls_settings.as_ref();
        ensure_hysteria_alpn(
            "xray",
            self.name(),
            tls.and_then(|settings| settings.alpn.as_ref()),
        )?;
        ensure!(
            !hysteria
                .and_then(|settings| settings.udp_hop.as_ref())
                .map(value_has_data)
                .unwrap_or(false),
            "xray Hysteria outbound {} enables UDP port hopping; Aerion Hysteria2 client expects one fixed port",
            self.name()
        );
        ensure!(
            !hysteria
                .and_then(|settings| settings.masquerade.as_ref())
                .map(value_has_data)
                .unwrap_or(false),
            "xray Hysteria outbound {} sets masquerade; Aerion Hysteria2 client binding does not expose masquerade",
            self.name()
        );
        let finalmask = self.stream_settings.finalmask.as_ref();
        if let Some(finalmask) = finalmask {
            ensure!(
                finalmask.tcp.is_empty(),
                "xray Hysteria outbound {} sets finalmask TCP masks; Aerion Hysteria2 only maps salamander UDP obfs",
                self.name()
            );
            ensure!(
                finalmask.udp.len() <= 1,
                "xray Hysteria outbound {} sets multiple finalmask UDP masks; Aerion Hysteria2 exposes one obfs layer",
                self.name()
            );
            ensure!(
                !finalmask
                    .quic_params
                    .as_ref()
                    .and_then(|params| params.udp_hop.as_ref())
                    .map(value_has_data)
                    .unwrap_or(false),
                "xray Hysteria outbound {} enables finalmask UDP port hopping; Aerion Hysteria2 client expects one fixed port",
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
                "xray Hysteria outbound {} sets finalmask bbrProfile {:?}; Aerion Hysteria2 uses the default BBR profile",
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
                "xray Hysteria outbound {} enables finalmask quicParams debug; Aerion Hysteria2 client does not expose QUIC debug toggles",
                self.name()
            );
        }
        let (obfs, obfs_password) = match finalmask.and_then(|finalmask| finalmask.udp.first()) {
            Some(mask) => {
                ensure!(
                    mask.kind.eq_ignore_ascii_case("salamander"),
                    "xray Hysteria outbound {} uses finalmask UDP mask {}; Aerion supports salamander",
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
                            "xray Hysteria outbound {} salamander mask is missing password",
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
            "xray Hysteria outbound {} uses congestion {}; Aerion Hysteria2 supports bbr or reno",
            self.name(),
            congestion_control
        );
        let download_bandwidth = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.brutal_down)
            .or_else(|| hysteria.and_then(|settings| settings.down));
        let upload_bandwidth = finalmask
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .and_then(|params| params.brutal_up)
            .or_else(|| hysteria.and_then(|settings| settings.up));
        let (ca_cert_paths, ca_certificates) = xray_tls_client_roots(tls)?;
        Ok(Hysteria2ClientConfig {
            listen,
            server_host: server.address.clone(),
            server_port: server.port,
            password: hysteria
                .and_then(|settings| settings.auth.clone())
                .or(server.password)
                .with_context(|| {
                    format!(
                        "xray Hysteria2 outbound {} is missing password",
                        self.name()
                    )
                })?,
            sni: sni_or_server(
                tls.and_then(|settings| settings.server_name.as_deref()),
                &server.address,
                self.name(),
            ),
            insecure: tls.map(|settings| settings.allow_insecure).unwrap_or(false),
            certificate_fingerprint: None,
            ca_cert_paths,
            ca_certificates,
            disable_system_roots: xray_disable_system_roots(tls, true),
            pinned_cert_sha256: xray_pinned_cert_sha256(tls, true),
            obfs,
            obfs_password,
            upload_bandwidth,
            download_bandwidth,
            udp: true,
            congestion_control,
        })
    }

    fn first_vless_or_vmess_peer(&self) -> Result<XrayServerUser> {
        if let Some(vnext) = self.settings.vnext.first() {
            let user = vnext
                .users
                .first()
                .cloned()
                .with_context(|| format!("xray outbound {} has no users", self.name()))?;
            return Ok(XrayServerUser {
                address: vnext.address.clone(),
                port: vnext.port,
                user,
            });
        }
        Ok(XrayServerUser {
            address: self
                .settings
                .address
                .clone()
                .with_context(|| format!("xray outbound {} is missing address", self.name()))?,
            port: self
                .settings
                .port
                .with_context(|| format!("xray outbound {} is missing port", self.name()))?,
            user: XrayUser {
                id: self.settings.id.clone(),
                password: self.settings.password.clone(),
                auth: self.settings.auth.clone(),
                method: self.settings.method.clone(),
                encryption: None,
                flow: self.settings.flow.clone(),
                packet_encoding: self.settings.packet_encoding.clone(),
                security: self.settings.security.clone(),
                alter_id: self.settings.alter_id,
                extra: Map::new(),
            },
        })
    }

    fn first_trojan_server(&self) -> Result<XrayServer> {
        if let Some(server) = self.settings.servers.first() {
            return Ok(server.clone());
        }
        Ok(XrayServer {
            address: self
                .settings
                .address
                .clone()
                .with_context(|| format!("xray outbound {} is missing address", self.name()))?,
            port: self
                .settings
                .port
                .with_context(|| format!("xray outbound {} is missing port", self.name()))?,
            password: self.settings.password.clone(),
            method: self.settings.method.clone(),
            users: Vec::new(),
            extra: Map::new(),
        })
    }

    fn is_reality(&self) -> bool {
        self.stream_settings
            .security
            .trim()
            .eq_ignore_ascii_case("reality")
    }

    fn reality_client_config(&self) -> Result<RealityClientConfig> {
        let settings = self
            .stream_settings
            .reality_settings
            .as_ref()
            .with_context(|| {
                format!(
                    "xray REALITY outbound {} is missing realitySettings",
                    self.name()
                )
            })?;
        RealityClientConfig::from_strings(
            settings.public_key.as_deref().with_context(|| {
                format!("xray REALITY outbound {} is missing publicKey", self.name())
            })?,
            settings.short_id.as_deref().unwrap_or_default(),
        )
    }

    fn stream_alpn(&self) -> Option<&OneOrManyStrings> {
        if self.is_reality() {
            self.stream_settings
                .reality_settings
                .as_ref()
                .and_then(|settings| settings.alpn.as_ref())
        } else {
            self.stream_settings
                .tls_settings
                .as_ref()
                .and_then(|settings| settings.alpn.as_ref())
        }
    }

    pub(super) fn vless_transport_config(&self) -> Result<VlessTransportConfig> {
        if self.stream_settings.network.eq_ignore_ascii_case("ws")
            || self
                .stream_settings
                .network
                .eq_ignore_ascii_case("websocket")
        {
            return VlessTransportConfig::from_headers(
                &self.stream_settings.network,
                self.stream_settings
                    .ws_settings
                    .as_ref()
                    .and_then(|settings| settings.path.clone()),
                self.stream_settings
                    .ws_settings
                    .as_ref()
                    .map(|settings| settings.headers.clone())
                    .unwrap_or_default(),
            );
        }
        if self
            .stream_settings
            .network
            .trim()
            .eq_ignore_ascii_case("httpupgrade")
        {
            let settings = self.stream_settings.http_upgrade_settings.as_ref();
            return VlessTransportConfig::from_network(
                &self.stream_settings.network,
                settings.and_then(|settings| settings.path.clone()),
                settings.and_then(|settings| settings.host.clone()),
                settings
                    .map(|settings| settings.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
            );
        }
        if self
            .stream_settings
            .network
            .trim()
            .eq_ignore_ascii_case("grpc")
        {
            let settings = self.stream_settings.grpc_settings.as_ref();
            return VlessTransportConfig::from_network(
                &self.stream_settings.network,
                settings.and_then(|settings| settings.service_name.clone()),
                settings.and_then(|settings| settings.authority.clone()),
                settings
                    .map(|settings| settings.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
            );
        }
        if self
            .stream_settings
            .network
            .trim()
            .eq_ignore_ascii_case("h2")
            || self
                .stream_settings
                .network
                .trim()
                .eq_ignore_ascii_case("http2")
        {
            let settings = self.stream_settings.http_settings.as_ref();
            return VlessTransportConfig::from_network(
                &self.stream_settings.network,
                settings.and_then(|settings| settings.path.clone()),
                settings.and_then(|settings| {
                    settings
                        .host
                        .as_ref()
                        .and_then(|host| host.to_vec().into_iter().next())
                }),
                settings
                    .map(|settings| settings.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
            );
        }
        if self
            .stream_settings
            .network
            .trim()
            .eq_ignore_ascii_case("xhttp")
            || self
                .stream_settings
                .network
                .trim()
                .eq_ignore_ascii_case("splithttp")
        {
            let settings = self
                .stream_settings
                .xhttp_settings
                .as_ref()
                .or(self.stream_settings.split_http_settings.as_ref());
            return VlessTransportConfig::xhttp(
                settings.and_then(|settings| settings.path.clone()),
                settings.and_then(|settings| {
                    settings
                        .host
                        .as_ref()
                        .and_then(|host| host.to_vec().into_iter().next())
                }),
                settings
                    .map(|settings| settings.headers.clone().into_iter().collect())
                    .unwrap_or_default(),
                settings.and_then(|settings| settings.mode.clone()),
            );
        }
        VlessTransportConfig::from_network(&self.stream_settings.network, None, None, Vec::new())
    }
}
