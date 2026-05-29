//! Auto-extracted from the singbox compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

impl SingBoxOutbound {
    pub fn name(&self) -> &str {
        self.tag.as_deref().unwrap_or(&self.kind)
    }

    pub(super) fn static_policy_target(&self) -> Result<Option<String>> {
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "selector" => Ok(Some(
                self.decode::<SingBoxSelectorOutbound>()?
                    .selected_target(self.name())?,
            )),
            "urltest" => Ok(Some(
                self.decode::<SingBoxUrlTestOutbound>()?
                    .static_target(self.name())?,
            )),
            _ => Ok(None),
        }
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<SingBoxClientConfig> {
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "direct" => {
                ensure!(
                    self.fields.is_empty(),
                    "sing-box direct outbound {} has unsupported fields {:?}",
                    self.name(),
                    self.fields.keys().collect::<Vec<_>>()
                );
                Ok(SingBoxClientConfig::Route(RouteClientConfig {
                    listen,
                    default: RouteDecision::Direct,
                }))
            }
            "block" => {
                ensure!(
                    self.fields.is_empty(),
                    "sing-box block outbound {} has unsupported fields {:?}",
                    self.name(),
                    self.fields.keys().collect::<Vec<_>>()
                );
                Ok(SingBoxClientConfig::Route(RouteClientConfig {
                    listen,
                    default: RouteDecision::Block,
                }))
            }
            "shadowsocks" | "ss" => Ok(SingBoxClientConfig::Shadowsocks(
                self.decode::<SingBoxShadowsocksOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "socks" | "socks5" => Ok(SingBoxClientConfig::SocksProxy(
                self.decode::<SingBoxSocksOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "http" => Ok(SingBoxClientConfig::HttpProxy(
                self.decode::<SingBoxHttpOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "vless" => Ok(SingBoxClientConfig::Vless(
                self.decode::<SingBoxVlessOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "vmess" => Ok(SingBoxClientConfig::Vmess(
                self.decode::<SingBoxVmessOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "trojan" => Ok(SingBoxClientConfig::Trojan(
                self.decode::<SingBoxTrojanOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "hysteria2" | "hy2" => Ok(SingBoxClientConfig::Hysteria2(
                self.decode::<SingBoxHysteria2Outbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "mieru" => Ok(SingBoxClientConfig::Mieru(
                self.decode::<SingBoxMieruOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "anytls" => Ok(SingBoxClientConfig::AnyTls(
                self.decode::<SingBoxAnyTlsOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "naive" => Ok(SingBoxClientConfig::Naive(
                self.decode::<SingBoxNaiveOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "tuic" => Ok(SingBoxClientConfig::Tuic(
                self.decode::<SingBoxTuicOutbound>()?
                    .to_client_config(self.name(), listen)?,
            )),
            "selector" => bail!(
                "sing-box selector outbound {} must be resolved through its selected outbound before conversion",
                self.name()
            ),
            "urltest" => bail!(
                "sing-box urltest outbound {} must be resolved through its statically selected outbound before conversion",
                self.name()
            ),
            other => bail!("unsupported sing-box outbound type {other}"),
        }
    }

    pub(super) fn decode<T>(&self) -> Result<T>
    where
        T: DeserializeOwned,
    {
        serde_json::from_value(Value::Object(self.fields.clone()))
            .with_context(|| format!("parse sing-box outbound {}", self.name()))
    }
}

impl SingBoxSelectorOutbound {
    fn selected_target(&self, name: &str) -> Result<String> {
        ensure!(
            !self.outbounds.is_empty(),
            "sing-box selector outbound {name} has no outbounds"
        );
        ensure!(
            self.extra.is_empty(),
            "sing-box selector outbound {name} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            self.interrupt_exist_connections.is_none(),
            "sing-box selector outbound {name} interrupt_exist_connections requires runtime selector state"
        );
        let target = self
            .default
            .as_deref()
            .map(str::trim)
            .filter(|default| !default.is_empty())
            .unwrap_or(&self.outbounds[0]);
        ensure!(
            self.outbounds.iter().any(|outbound| outbound == target),
            "sing-box selector outbound {name} default {target} is not listed in outbounds"
        );
        Ok(target.to_string())
    }
}

impl SingBoxUrlTestOutbound {
    fn static_target(&self, name: &str) -> Result<String> {
        ensure!(
            self.extra.is_empty(),
            "sing-box urltest outbound {name} has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        for (field, value) in [
            ("url", &self.url),
            ("interval", &self.interval),
            ("tolerance", &self.tolerance),
            ("idle_timeout", &self.idle_timeout),
        ] {
            ensure!(
                !value.as_ref().map(value_has_data).unwrap_or(false),
                "sing-box urltest outbound {name} {field} requires active latency testing"
            );
        }
        ensure!(
            self.interrupt_exist_connections.is_none(),
            "sing-box urltest outbound {name} interrupt_exist_connections requires runtime policy state"
        );
        let outbounds = self
            .outbounds
            .iter()
            .map(|outbound| outbound.trim())
            .filter(|outbound| !outbound.is_empty())
            .collect::<Vec<_>>();
        match outbounds.as_slice() {
            [target] => Ok((*target).to_string()),
            [] => bail!("sing-box urltest outbound {name} has no outbounds"),
            _ => bail!(
                "sing-box urltest outbound {name} requires active latency selection; Aerion only resolves single-outbound urltest policies statically"
            ),
        }
    }
}

impl SingBoxShadowsocksOutbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<ShadowsocksClientConfig> {
        ensure_no_extra_fields(
            &format!("sing-box Shadowsocks outbound {name}"),
            &self.extra,
        )?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        ensure!(
            self.plugin.is_none() && self.plugin_opts.is_none(),
            "sing-box Shadowsocks outbound {name} sets SIP003 plugin; Aerion Shadowsocks does not implement plugins"
        );
        let udp_over_tcp = singbox_uot_enabled("Shadowsocks", name, self.udp_over_tcp.as_ref())?;
        Ok(ShadowsocksClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            method: self.method.clone(),
            password: self.password.clone(),
            udp: network_allows_udp(self.network.as_deref()) || udp_over_tcp,
            udp_over_tcp,
        })
    }
}

impl SingBoxSocksOutbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<SocksProxyClientConfig> {
        ensure_no_extra_fields(&format!("sing-box SOCKS outbound {name}"), &self.extra)?;
        let (tcp, udp) = tcp_udp_network("sing-box SOCKS outbound", name, self.network.as_deref())?;
        ensure!(
            tcp,
            "sing-box SOCKS outbound {name} uses udp-only network; Aerion SOCKS outbound requires TCP control channel"
        );
        Ok(SocksProxyClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            udp,
        })
    }
}

impl SingBoxHttpOutbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<HttpProxyClientConfig> {
        ensure_no_extra_fields(&format!("sing-box HTTP outbound {name}"), &self.extra)?;
        let tls_enabled = self.tls.as_ref().map(|tls| tls.enabled).unwrap_or(false);
        if let Some(tls) = &self.tls {
            tls.ensure_supported_client_options("HTTP", name, true)?;
            if tls_enabled {
                ensure_http_alpn("sing-box", name, tls.alpn.as_ref())?;
            } else {
                ensure_disabled_utls(name, tls)?;
                ensure_disabled_reality(name, tls)?;
                ensure!(
                    alpn_values(tls.alpn.as_ref()).is_empty()
                        && !tls.insecure
                        && !tls.disable_system_root
                        && !json_value_non_empty_option(tls.certificate.as_ref())
                        && !json_value_non_empty_option(tls.certificate_path.as_ref()),
                    "sing-box HTTP outbound {name} sets TLS-only options while tls.enabled is false"
                );
            }
        }
        Ok(HttpProxyClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            tls: tls_enabled,
            sni: sni_or_server(
                self.tls.as_ref().and_then(|tls| tls.server_name.as_deref()),
                &self.server,
            ),
            insecure: self.tls.as_ref().map(|tls| tls.insecure).unwrap_or(false),
            ca_cert_paths: value_paths(
                self.tls
                    .as_ref()
                    .and_then(|tls| tls.certificate_path.as_ref()),
            )?,
            ca_certificates: Vec::new(),
            disable_system_roots: self
                .tls
                .as_ref()
                .map(|tls| tls.disable_system_root)
                .unwrap_or(false),
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: self
                .tls
                .as_ref()
                .map(|tls| tls.utls_fingerprint(name))
                .transpose()?
                .flatten(),
            extra_headers: self.headers.clone().into_iter().collect(),
        })
    }
}

impl SingBoxVlessOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<VlessClientConfig> {
        ensure_no_extra_fields(&format!("sing-box VLESS outbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        let tls_enabled = self.tls.as_ref().map(|tls| tls.enabled).unwrap_or(false);
        let reality = if tls_enabled {
            self.tls
                .as_ref()
                .map(|tls| tls.reality_client_config(name))
                .transpose()?
                .flatten()
        } else {
            None
        };
        if let Some(tls) = &self.tls {
            tls.ensure_supported_client_options("VLESS", name, true)?;
            if tls_enabled || reality.is_some() {
                ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
            } else {
                ensure_disabled_utls(name, tls)?;
                ensure_disabled_reality(name, tls)?;
                ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
            }
        }
        Ok(VlessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            user_id: self.uuid.clone(),
            tls: tls_enabled && reality.is_none(),
            sni: sni_or_server(
                self.tls.as_ref().and_then(|tls| tls.server_name.as_deref()),
                &self.server,
            ),
            insecure: if tls_enabled {
                self.tls.as_ref().map(|tls| tls.insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths: value_paths(
                self.tls
                    .as_ref()
                    .and_then(|tls| tls.certificate_path.as_ref()),
            )?,
            ca_certificates: value_strings(
                self.tls.as_ref().and_then(|tls| tls.certificate.as_ref()),
            )?,
            disable_system_roots: tls_enabled
                && self
                    .tls
                    .as_ref()
                    .map(|tls| tls.disable_system_root)
                    .unwrap_or(false),
            pinned_cert_sha256: Vec::new(),
            flow: self.flow.clone(),
            packet_encoding: self
                .packet_encoding
                .clone()
                .unwrap_or_else(|| "xudp".to_string()),
            mux: false,
            udp: network_allows_udp(self.network.as_deref()),
            client_fingerprint: self
                .tls
                .as_ref()
                .map(|tls| tls.utls_fingerprint(name))
                .transpose()?
                .flatten(),
            reality,
            transport,
        })
    }
}

impl SingBoxVmessOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<VmessClientConfig> {
        ensure_no_extra_fields(&format!("sing-box VMess outbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        ensure!(
            self.alter_id == 0,
            "sing-box VMess outbound {name} uses legacy alter_id {}; Aerion implements AEAD VMess only",
            self.alter_id
        );
        let packet_encoding = self.packet_encoding.clone().unwrap_or_default();
        ensure_vmess_packet_encoding(&packet_encoding)
            .with_context(|| format!("sing-box VMess outbound {name} packet_encoding"))?;
        if let Some(tls) = &self.tls {
            tls.ensure_supported_client_options("VMess", name, true)?;
            if tls.enabled {
                ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
            } else {
                ensure_disabled_utls(name, tls)?;
                ensure_no_alpn("sing-box", name, tls.alpn.as_ref())?;
            }
        }
        let tls_enabled = self.tls.as_ref().map(|tls| tls.enabled).unwrap_or(false);
        let server_name = self.tls.as_ref().and_then(|tls| tls.server_name.as_deref());
        Ok(VmessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            user_id: self.uuid.clone(),
            security: self.security.clone(),
            packet_encoding,
            udp: network_allows_udp(self.network.as_deref()),
            tls: tls_enabled,
            sni: sni_or_server(server_name, &self.server),
            insecure: if tls_enabled {
                self.tls.as_ref().map(|tls| tls.insecure).unwrap_or(false)
            } else {
                false
            },
            ca_cert_paths: value_paths(
                self.tls
                    .as_ref()
                    .and_then(|tls| tls.certificate_path.as_ref()),
            )?,
            ca_certificates: value_strings(
                self.tls.as_ref().and_then(|tls| tls.certificate.as_ref()),
            )?,
            disable_system_roots: tls_enabled
                && self
                    .tls
                    .as_ref()
                    .map(|tls| tls.disable_system_root)
                    .unwrap_or(false),
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: if tls_enabled {
                self.tls
                    .as_ref()
                    .map(|tls| tls.utls_fingerprint(name))
                    .transpose()?
                    .flatten()
            } else {
                None
            },
            transport,
        })
    }
}

impl SingBoxTrojanOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<TrojanClientConfig> {
        ensure_no_extra_fields(&format!("sing-box Trojan outbound {name}"), &self.extra)?;
        ensure_multiplex_disabled("sing-box", name, self.multiplex.as_ref())?;
        let transport = vless_transport_config(
            "sing-box",
            name,
            self.network.as_deref(),
            self.transport.as_ref(),
        )?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box Trojan outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box Trojan outbound {name} disables TLS; Trojan requires TLS in Aerion"
        );
        tls.ensure_supported_client_options("Trojan", name, true)?;
        ensure_vless_alpn("sing-box", name, &transport, tls.alpn.as_ref())?;
        Ok(TrojanClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            udp: network_allows_udp(self.network.as_deref()),
            client_fingerprint: tls.utls_fingerprint(name)?,
            transport,
        })
    }
}

impl SingBoxHysteria2Outbound {
    pub fn to_client_config(
        &self,
        name: &str,
        listen: SocketAddr,
    ) -> Result<Hysteria2ClientConfig> {
        ensure_no_extra_fields(&format!("sing-box Hysteria2 outbound {name}"), &self.extra)?;
        ensure_supported_network("sing-box", name, self.network.as_deref())?;
        ensure!(
            !self
                .server_ports
                .as_ref()
                .map(value_has_data)
                .unwrap_or(false)
                && self.hop_interval.is_none()
                && self.hop_interval_max.is_none(),
            "sing-box Hysteria2 outbound {name} enables port hopping; Aerion Hysteria2 client expects one fixed port"
        );
        ensure!(
            !self.realm.as_ref().map(value_has_data).unwrap_or(false),
            "sing-box Hysteria2 outbound {name} sets realm; Aerion Hysteria2 client does not expose realm override"
        );
        ensure!(
            self.bbr_profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
            "sing-box Hysteria2 outbound {name} sets bbr_profile {:?}; Aerion Hysteria2 uses the default BBR profile",
            self.bbr_profile
        );
        ensure!(
            !self.brutal_debug,
            "sing-box Hysteria2 outbound {name} enables brutal_debug; Aerion Hysteria2 client does not expose brutal debug"
        );
        let server_port = self.server_port.with_context(|| {
            format!("sing-box Hysteria2 outbound {name} is missing server_port")
        })?;
        let server = self
            .server
            .as_ref()
            .with_context(|| format!("sing-box Hysteria2 outbound {name} is missing server"))?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box Hysteria2 outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box Hysteria2 outbound {name} disables TLS; Hysteria2 requires TLS in Aerion"
        );
        tls.ensure_supported_client_options("Hysteria2", name, true)?;
        ensure_hy2_alpn("sing-box", name, tls.alpn.as_ref())?;
        let (obfs, obfs_password) = match &self.obfs {
            Some(obfs) => {
                ensure_no_extra_fields(
                    &format!("sing-box Hysteria2 outbound {name} obfs"),
                    &obfs.extra,
                )?;
                ensure!(
                    obfs.kind.eq_ignore_ascii_case("salamander"),
                    "sing-box Hysteria2 outbound {name} uses obfs {}; Aerion supports salamander",
                    obfs.kind
                );
                (Some(obfs.kind.clone()), Some(obfs.password.clone()))
            }
            None => (None, None),
        };
        Ok(Hysteria2ClientConfig {
            listen,
            server_host: server.clone(),
            server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), server),
            insecure: tls.insecure,
            certificate_fingerprint: None,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            obfs,
            obfs_password,
            upload_bandwidth: self.up_mbps,
            download_bandwidth: self.down_mbps.or(self.down),
            udp: network_allows_udp(self.network.as_deref()),
            congestion_control: "bbr".to_string(),
        })
    }
}

impl SingBoxAnyTlsOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<ClientConfig> {
        ensure_no_extra_fields(&format!("sing-box AnyTLS outbound {name}"), &self.extra)?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box AnyTLS outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box AnyTLS outbound {name} disables TLS; AnyTLS requires TLS"
        );
        tls.ensure_supported_client_options("AnyTLS", name, true)?;
        Ok(ClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            client_fingerprint: tls.utls_fingerprint(name)?,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            padding_scheme: PaddingScheme::default_lines(),
            heartbeat_interval_secs: 30,
        })
    }
}

impl SingBoxMieruOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<MieruClientConfig> {
        ensure_no_extra_fields(&format!("sing-box Mieru outbound {name}"), &self.extra)?;
        Ok(MieruClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self
                .username
                .clone()
                .unwrap_or_else(|| self.password.clone()),
            password: self.password.clone(),
            hashed_password: None,
            mtu: self.mtu,
            transport: MieruTransport::parse(&self.transport)?,
            traffic_pattern: MieruTrafficPattern::parse_pair(
                self.traffic_pattern.as_deref(),
                self.nonce_pattern.as_deref(),
            )
            .with_context(|| format!("parse sing-box Mieru outbound {name} traffic pattern"))?,
        })
    }
}

impl SingBoxNaiveOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<NaiveClientConfig> {
        ensure_no_extra_fields(&format!("sing-box Naive outbound {name}"), &self.extra)?;
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box Naive outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box Naive outbound {name} disables TLS; Naive requires HTTPS/TLS"
        );
        tls.ensure_supported_client_options("Naive", name, true)?;
        ensure!(
            self.insecure_concurrency.unwrap_or(0) == 0,
            "sing-box Naive outbound {name} sets insecure_concurrency; Aerion Naive client does not implement speculative parallel connections"
        );
        let udp_over_tcp = singbox_uot_enabled("Naive", name, self.udp_over_tcp.as_ref())?;
        Ok(NaiveClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            extra_headers: self.extra_headers.clone().into_iter().collect(),
            udp_over_tcp,
            quic: self.quic
                || self
                    .network
                    .as_deref()
                    .map(|network| {
                        matches!(
                            network.to_ascii_lowercase().as_str(),
                            "quic" | "h3" | "http3"
                        )
                    })
                    .unwrap_or(false),
            quic_congestion_control: self
                .quic_congestion_control
                .clone()
                .unwrap_or_else(default_naive_quic_congestion_control),
        })
    }
}

impl SingBoxTuicOutbound {
    pub fn to_client_config(&self, name: &str, listen: SocketAddr) -> Result<TuicClientConfig> {
        ensure_no_extra_fields(&format!("sing-box TUIC outbound {name}"), &self.extra)?;
        ensure_supported_network("sing-box", name, self.network.as_deref())?;
        ensure!(
            !self.zero_rtt_handshake,
            "sing-box TUIC outbound {name} enables zero_rtt_handshake; Aerion TUIC client does not expose 0-RTT handshakes"
        );
        ensure!(
            !singbox_enabled_option(
                "TUIC",
                name,
                "udp_over_stream",
                self.udp_over_stream.as_ref()
            )?,
            "sing-box TUIC outbound {name} enables udp_over_stream; Aerion TUIC client does not implement UDP-over-stream"
        );
        let tls = self
            .tls
            .as_ref()
            .with_context(|| format!("sing-box TUIC outbound {name} is missing tls"))?;
        ensure!(
            tls.enabled,
            "sing-box TUIC outbound {name} disables TLS; TUIC requires QUIC TLS"
        );
        tls.ensure_supported_client_options("TUIC", name, true)?;
        ensure_tuic_alpn("sing-box", name, tls.alpn.as_ref())?;
        Ok(TuicClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.server_port,
            uuid: self.uuid.clone(),
            password: self.password.clone(),
            sni: sni_or_server(tls.server_name.as_deref(), &self.server),
            insecure: tls.insecure,
            ca_cert_paths: value_paths(tls.certificate_path.as_ref())?,
            ca_certificates: value_strings(tls.certificate.as_ref())?,
            disable_system_roots: tls.disable_system_root,
            pinned_cert_sha256: Vec::new(),
            udp: network_allows_udp(self.network.as_deref()),
            udp_relay_mode: self
                .udp_relay_mode
                .clone()
                .unwrap_or_else(|| "native".to_string()),
            congestion_control: self
                .congestion_control
                .clone()
                .unwrap_or_else(|| "cubic".to_string()),
            alpn_protocols: alpn_values(tls.alpn.as_ref()),
            heartbeat_interval_secs: self
                .heartbeat
                .as_deref()
                .map(parse_duration_secs)
                .transpose()?
                .unwrap_or(10),
        })
    }
}

