//! Auto-extracted from the mihomo compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

impl MihomoProxy {
    pub fn name(&self) -> &str {
        match self {
            Self::Shadowsocks(proxy) => &proxy.name,
            Self::Socks(proxy) => &proxy.name,
            Self::Http(proxy) => &proxy.name,
            Self::Vless(proxy) => &proxy.name,
            Self::Vmess(proxy) => &proxy.name,
            Self::Trojan(proxy) => &proxy.name,
            Self::Hysteria2(proxy) => &proxy.name,
            Self::AnyTls(proxy) => &proxy.name,
            Self::NodeExpand(proxy) => &proxy.name,
            Self::Mieru(proxy) => &proxy.name,
            Self::Naive(proxy) => &proxy.name,
            Self::Tuic(proxy) => &proxy.name,
            Self::Unsupported(proxy) => &proxy.name,
        }
    }

    pub fn to_client_config(&self, listen: SocketAddr) -> Result<MihomoClientConfig> {
        Ok(match self {
            Self::Shadowsocks(proxy) => {
                MihomoClientConfig::Shadowsocks(proxy.to_client_config(listen)?)
            }
            Self::Socks(proxy) => MihomoClientConfig::SocksProxy(proxy.to_client_config(listen)?),
            Self::Http(proxy) => MihomoClientConfig::HttpProxy(proxy.to_client_config(listen)?),
            Self::Vless(proxy) => MihomoClientConfig::Vless(proxy.to_client_config(listen)?),
            Self::Vmess(proxy) => MihomoClientConfig::Vmess(proxy.to_client_config(listen)?),
            Self::Trojan(proxy) => MihomoClientConfig::Trojan(proxy.to_client_config(listen)?),
            Self::Hysteria2(proxy) => {
                MihomoClientConfig::Hysteria2(proxy.to_client_config(listen)?)
            }
            Self::AnyTls(proxy) => MihomoClientConfig::AnyTls(proxy.to_client_config(listen)?),
            Self::NodeExpand(proxy) => {
                MihomoClientConfig::NodeExpand(proxy.to_client_config(listen)?)
            }
            Self::Mieru(proxy) => MihomoClientConfig::Mieru(proxy.to_client_config(listen)?),
            Self::Naive(proxy) => MihomoClientConfig::Naive(proxy.to_client_config(listen)?),
            Self::Tuic(proxy) => MihomoClientConfig::Tuic(proxy.to_client_config(listen)?),
            Self::Unsupported(proxy) => proxy.to_client_config(listen)?,
        })
    }
}

impl MihomoProxyGroup {
    pub(super) fn static_target(&self) -> Result<String> {
        let kind = self.kind.trim().to_ascii_lowercase();
        match kind.as_str() {
            "select" => {
                self.ensure_static_group_supported("select")?;
                let target = self
                    .proxies
                    .first()
                    .map(|proxy| proxy.trim())
                    .filter(|proxy| !proxy.is_empty())
                    .with_context(|| {
                        format!("mihomo select proxy-group {} has no proxies", self.name)
                    })?;
                Ok(target.to_string())
            }
            "url-test" | "fallback" | "load-balance" | "relay" => {
                self.ensure_static_group_supported(&kind)?;
                let targets = self
                    .proxies
                    .iter()
                    .map(|proxy| proxy.trim())
                    .filter(|proxy| !proxy.is_empty())
                    .collect::<Vec<_>>();
                match targets.as_slice() {
                    [target] => Ok((*target).to_string()),
                    [] => bail!("mihomo {kind} proxy-group {} has no proxies", self.name),
                    _ if kind == "url-test" => bail!(
                        "mihomo url-test proxy-group {} requires active latency selection; Aerion only resolves single-proxy url-test groups statically",
                        self.name
                    ),
                    _ if kind == "fallback" => bail!(
                        "mihomo fallback proxy-group {} requires active health-check selection; Aerion only resolves single-proxy fallback groups statically",
                        self.name
                    ),
                    _ if kind == "load-balance" => bail!(
                        "mihomo load-balance proxy-group {} requires per-connection policy selection; Aerion only resolves single-proxy load-balance groups statically",
                        self.name
                    ),
                    _ => bail!(
                        "mihomo relay proxy-group {} requires proxy chaining; Aerion only resolves single-proxy relay groups statically",
                        self.name
                    ),
                }
            }
            other => bail!("unsupported mihomo proxy-group {} type {other}", self.name),
        }
    }

    fn ensure_static_group_supported(&self, kind: &str) -> Result<()> {
        ensure!(
            !self.disable_udp,
            "mihomo {kind} proxy-group {} disables UDP; Aerion route clients expose TCP and UDP together",
            self.name
        );
        let mut unsupported = Vec::new();
        if !self.use_providers.is_empty() {
            unsupported.push("use".to_string());
        }
        if self.include_all {
            unsupported.push("include-all".to_string());
        }
        if self.include_all_proxies {
            unsupported.push("include-all-proxies".to_string());
        }
        if self.include_all_providers {
            unsupported.push("include-all-providers".to_string());
        }
        if self.filter.is_some() {
            unsupported.push("filter".to_string());
        }
        if self.exclude_filter.is_some() {
            unsupported.push("exclude-filter".to_string());
        }
        if self.exclude_type.is_some() {
            unsupported.push("exclude-type".to_string());
        }
        if self.interface_name.is_some() {
            unsupported.push("interface-name".to_string());
        }
        if self.routing_mark.is_some() {
            unsupported.push("routing-mark".to_string());
        }
        unsupported.extend(self.fields.keys().cloned());
        ensure!(
            unsupported.is_empty(),
            "mihomo {kind} proxy-group {} has unsupported fields {:?}",
            self.name,
            unsupported
        );
        Ok(())
    }
}

impl MihomoRuleProvider {
    pub(super) fn to_route_rules(
        &self,
        name: &str,
        source_dir: Option<&Path>,
        action: RouteDecision,
    ) -> Result<Vec<RouteRule>> {
        ensure_no_extra_fields(&format!("mihomo rule-provider {name}"), &self.extra)?;
        let lines = self.rule_lines(name, source_dir)?;
        let behavior = self.behavior.trim().to_ascii_lowercase();
        match behavior.as_str() {
            "domain" => {
                let mut rule = RouteRule::new(action);
                for line in lines {
                    rule.domains.push(mihomo_rule_provider_domain(&line)?);
                }
                ensure!(
                    !rule.domains.is_empty(),
                    "mihomo rule-provider {name} domain payload is empty"
                );
                Ok(vec![rule])
            }
            "ipcidr" | "ip-cidr" => {
                let mut rule = RouteRule::new(action);
                for line in lines {
                    rule.ip_cidrs.push(IpCidr::parse(&line)?);
                }
                ensure!(
                    !rule.ip_cidrs.is_empty(),
                    "mihomo rule-provider {name} ipcidr payload is empty"
                );
                Ok(vec![rule])
            }
            "classical" => {
                let mut rules = Vec::new();
                for (index, line) in lines.iter().enumerate() {
                    let location = format!("mihomo rule-provider {name} payload[{index}]");
                    rules.extend(parse_mihomo_route_expr_with_action(
                        line,
                        &location,
                        action.clone(),
                    )?);
                }
                ensure!(
                    !rules.is_empty(),
                    "mihomo rule-provider {name} classical payload is empty"
                );
                Ok(rules)
            }
            other => bail!("unsupported mihomo rule-provider {name} behavior {other}"),
        }
    }

    fn rule_lines(&self, name: &str, source_dir: Option<&Path>) -> Result<Vec<String>> {
        let kind = self.kind.trim().to_ascii_lowercase();
        match kind.as_str() {
            "inline" => {
                ensure!(
                    self.path.is_none(),
                    "mihomo inline rule-provider {name} sets path"
                );
                ensure!(
                    !option_text_has_data(self.url.as_ref()),
                    "mihomo inline rule-provider {name} sets url"
                );
                ensure!(
                    !option_text_has_data(self.format.as_ref()),
                    "mihomo inline rule-provider {name} sets format"
                );
                Ok(clean_mihomo_rule_provider_lines(&self.payload))
            }
            "file" => {
                ensure!(
                    self.payload.is_empty(),
                    "mihomo file rule-provider {name} embeds inline payload"
                );
                ensure!(
                    !option_text_has_data(self.url.as_ref()),
                    "mihomo file rule-provider {name} sets url"
                );
                let path = self
                    .path
                    .as_ref()
                    .with_context(|| format!("mihomo file rule-provider {name} is missing path"))?;
                let path = match (path.is_absolute(), source_dir) {
                    (true, _) | (false, None) => path.clone(),
                    (false, Some(source_dir)) => source_dir.join(path),
                };
                self.load_rule_file(name, &path)
            }
            "http" => bail!("mihomo http rule-provider {name} requires downloading rule-set data"),
            other => bail!("unsupported mihomo rule-provider {name} type {other}"),
        }
    }

    fn load_rule_file(&self, name: &str, path: &Path) -> Result<Vec<String>> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read mihomo rule-provider {name} file {}", path.display()))?;
        match self
            .format
            .as_deref()
            .map(str::trim)
            .filter(|format| !format.is_empty())
            .unwrap_or("yaml")
            .to_ascii_lowercase()
            .as_str()
        {
            "yaml" | "yml" => {
                #[derive(Deserialize)]
                struct RuleProviderFile {
                    payload: Vec<String>,
                    #[serde(flatten)]
                    extra: BTreeMap<String, Value>,
                }
                let file: RuleProviderFile = serde_yaml::from_str(&text).with_context(|| {
                    format!(
                        "parse mihomo rule-provider {name} YAML file {}",
                        path.display()
                    )
                })?;
                ensure_no_extra_fields(
                    &format!("mihomo rule-provider {name} YAML file"),
                    &file.extra,
                )?;
                Ok(clean_mihomo_rule_provider_lines(&file.payload))
            }
            "text" => Ok(text
                .lines()
                .filter_map(mihomo_text_rule_provider_line)
                .map(str::to_string)
                .collect()),
            "mrs" => bail!("mihomo rule-provider {name} MRS format is not supported"),
            other => bail!("unsupported mihomo rule-provider {name} format {other}"),
        }
    }
}

impl MihomoUnsupportedProxy {
    fn to_client_config(&self, listen: SocketAddr) -> Result<MihomoClientConfig> {
        let value = self.value();
        Ok(match self.kind.trim().to_ascii_lowercase().as_str() {
            "direct" => {
                self.ensure_route_fields()?;
                MihomoClientConfig::Route(RouteClientConfig {
                    listen,
                    default: RouteDecision::Direct,
                })
            }
            "reject" | "block" => {
                self.ensure_route_fields()?;
                MihomoClientConfig::Route(RouteClientConfig {
                    listen,
                    default: RouteDecision::Block,
                })
            }
            "ss" | "shadowsocks" => MihomoClientConfig::Shadowsocks(
                serde_yaml::from_value::<MihomoShadowsocksProxy>(value)
                    .with_context(|| format!("parse mihomo Shadowsocks proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "socks" | "socks5" | "socks5h" => MihomoClientConfig::SocksProxy(
                serde_yaml::from_value::<MihomoSocksProxy>(value)
                    .with_context(|| format!("parse mihomo SOCKS proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "http" => MihomoClientConfig::HttpProxy(
                serde_yaml::from_value::<MihomoHttpProxy>(value)
                    .with_context(|| format!("parse mihomo HTTP proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "vless" => MihomoClientConfig::Vless(
                serde_yaml::from_value::<MihomoVlessProxy>(value)
                    .with_context(|| format!("parse mihomo VLESS proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "vmess" => MihomoClientConfig::Vmess(
                serde_yaml::from_value::<MihomoVmessProxy>(value)
                    .with_context(|| format!("parse mihomo VMess proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "trojan" => MihomoClientConfig::Trojan(
                serde_yaml::from_value::<MihomoTrojanProxy>(value)
                    .with_context(|| format!("parse mihomo Trojan proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "hysteria2" | "hy2" => MihomoClientConfig::Hysteria2(
                serde_yaml::from_value::<MihomoHysteria2Proxy>(value)
                    .with_context(|| format!("parse mihomo Hysteria2 proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "anytls" | "any-tls" => MihomoClientConfig::AnyTls(
                serde_yaml::from_value::<MihomoAnyTlsProxy>(value)
                    .with_context(|| format!("parse mihomo AnyTLS proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "nodeexpand" | "node-expand" | "node_expand" | "aerion-mp" => {
                MihomoClientConfig::NodeExpand(
                    serde_yaml::from_value::<MihomoNodeExpandProxy>(value)
                        .with_context(|| format!("parse mihomo NodeExpand proxy {}", self.name))?
                        .to_client_config(listen)?,
                )
            }
            "mieru" => MihomoClientConfig::Mieru(
                serde_yaml::from_value::<MihomoMieruProxy>(value)
                    .with_context(|| format!("parse mihomo Mieru proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "naive" | "naive+https" | "naive+quic" => MihomoClientConfig::Naive(
                serde_yaml::from_value::<MihomoNaiveProxy>(value)
                    .with_context(|| format!("parse mihomo Naive proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            "tuic" => MihomoClientConfig::Tuic(
                serde_yaml::from_value::<MihomoTuicProxy>(value)
                    .with_context(|| format!("parse mihomo TUIC proxy {}", self.name))?
                    .to_client_config(listen)?,
            ),
            _ => bail!(
                "unsupported mihomo proxy {} type {}; Aerion cannot run this proxy protocol",
                self.name,
                self.kind
            ),
        })
    }

    fn ensure_route_fields(&self) -> Result<()> {
        let unsupported = self
            .fields
            .keys()
            .filter(|key| {
                !key.eq_ignore_ascii_case("name")
                    && !key.eq_ignore_ascii_case("type")
                    && !key.eq_ignore_ascii_case("udp")
            })
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            unsupported.is_empty(),
            "mihomo proxy {} type {} sets unsupported fields {:?}",
            self.name,
            self.kind,
            unsupported
        );
        ensure!(
            !matches!(self.fields.get("udp"), Some(Value::Bool(false))),
            "mihomo proxy {} type {} disables UDP; Aerion route client exposes TCP and UDP together",
            self.name,
            self.kind
        );
        Ok(())
    }

    fn value(&self) -> Value {
        let mut mapping = Mapping::new();
        for (key, value) in &self.fields {
            mapping.insert(Value::String(key.clone()), value.clone());
        }
        Value::Mapping(mapping)
    }
}

impl MihomoShadowsocksProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<ShadowsocksClientConfig> {
        ensure_no_proxy_extra_fields(
            &format!("mihomo Shadowsocks proxy {}", self.name),
            &self.fields,
        )?;
        ensure!(
            self.plugin
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
                && self.plugin_opts.as_ref().is_none_or(BTreeMap::is_empty),
            "mihomo Shadowsocks proxy {} uses SIP003 plugin; Aerion Shadowsocks does not implement plugins",
            self.name
        );
        let udp_over_tcp = self
            .udp_over_tcp
            .as_ref()
            .map(|opts| opts.enabled_for("Shadowsocks", &self.name))
            .transpose()?
            .unwrap_or(false);
        Ok(ShadowsocksClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            method: self.cipher.clone(),
            password: self.password.clone(),
            udp: self.udp,
            udp_over_tcp,
        })
    }
}

impl MihomoSocksProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<SocksProxyClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo SOCKS proxy {}", self.name), &self.fields)?;
        ensure!(
            !self.tls && !self.skip_cert_verify && alpn_values(self.alpn.as_ref()).is_empty(),
            "mihomo SOCKS proxy {} sets TLS options; Aerion SOCKS outbound is plain SOCKS5",
            self.name
        );
        Ok(SocksProxyClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            udp: self.udp,
        })
    }
}

impl MihomoHttpProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<HttpProxyClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo HTTP proxy {}", self.name), &self.fields)?;
        if self.tls {
            ensure_http_alpn(&self.name, self.alpn.as_ref())?;
        } else {
            ensure!(
                alpn_values(self.alpn.as_ref()).is_empty()
                    && !self.skip_cert_verify
                    && self.client_fingerprint.is_none(),
                "mihomo HTTP proxy {} sets TLS-only options while tls is disabled",
                self.name
            );
        }
        Ok(HttpProxyClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            tls: self.tls,
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: self.client_fingerprint,
            extra_headers: self.headers.clone().into_iter().collect(),
        })
    }
}

impl MihomoVlessProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<VlessClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo VLESS proxy {}", self.name), &self.fields)?;
        if let Some(encryption) = self.encryption.as_deref().map(str::trim) {
            ensure!(
                encryption.is_empty() || encryption.eq_ignore_ascii_case("none"),
                "mihomo VLESS proxy {} uses encryption {}; Aerion VLESS supports none/empty encryption",
                self.name,
                encryption
            );
        }
        let reality = self
            .reality_opts
            .as_ref()
            .map(MihomoRealityOpts::to_client_config)
            .transpose()?;
        let network = self.network.trim();
        let transport = mihomo_transport_config(
            "VLESS",
            &self.name,
            network,
            self.ws_opts.as_ref(),
            self.grpc_opts.as_ref(),
            self.xhttp_opts.as_ref(),
        )?;
        if self.tls || reality.is_some() {
            ensure_vless_alpn(&self.name, &transport, self.alpn.as_ref())?;
        } else {
            ensure!(
                self.client_fingerprint.is_none(),
                "mihomo VLESS proxy {} sets client-fingerprint while TLS is disabled",
                self.name
            );
            ensure_no_alpn(&self.name, self.alpn.as_ref())?;
        }
        ensure_no_smux(&self.name, self.smux.as_ref())?;
        Ok(VlessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            user_id: self.uuid.clone(),
            tls: self.tls && reality.is_none(),
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: if self.tls || reality.is_some() {
                self.skip_cert_verify
            } else {
                false
            },
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            flow: self.flow.clone(),
            packet_encoding: self.packet_encoding.clone(),
            mux: self.mux,
            udp: self.udp,
            client_fingerprint: self.client_fingerprint,
            reality,
            transport,
        })
    }
}

impl MihomoVmessProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<VmessClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo VMess proxy {}", self.name), &self.fields)?;
        ensure!(
            self.alter_id == 0,
            "mihomo VMess proxy {} uses legacy alterId {}; Aerion implements AEAD VMess only",
            self.name,
            self.alter_id
        );
        ensure!(
            self.tls || self.client_fingerprint.is_none(),
            "mihomo VMess proxy {} sets client-fingerprint while TLS is disabled",
            self.name
        );
        ensure_vmess_packet_encoding(&self.packet_encoding)
            .with_context(|| format!("mihomo VMess proxy {} packet-encoding", self.name))?;
        let network = self.network.trim();
        let transport = mihomo_transport_config(
            "VMess",
            &self.name,
            network,
            self.ws_opts.as_ref(),
            self.grpc_opts.as_ref(),
            None,
        )?;
        if self.tls {
            ensure_vless_alpn(&self.name, &transport, self.alpn.as_ref())?;
        } else {
            ensure_no_alpn(&self.name, self.alpn.as_ref())?;
        }
        Ok(VmessClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            user_id: self.uuid.clone(),
            security: self.cipher.clone(),
            packet_encoding: self.packet_encoding.clone(),
            udp: self.udp,
            tls: self.tls,
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: if self.tls {
                self.skip_cert_verify
            } else {
                false
            },
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            client_fingerprint: if self.tls {
                self.client_fingerprint
            } else {
                None
            },
            transport,
        })
    }
}

impl MihomoTrojanProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<TrojanClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo Trojan proxy {}", self.name), &self.fields)?;
        ensure!(
            self.tls,
            "mihomo Trojan proxy {} disables TLS; Trojan requires TLS in Aerion",
            self.name
        );
        let network = self.network.trim();
        let transport = mihomo_transport_config(
            "Trojan",
            &self.name,
            network,
            self.ws_opts.as_ref(),
            self.grpc_opts.as_ref(),
            None,
        )?;
        ensure_vless_alpn(&self.name, &transport, self.alpn.as_ref())?;
        Ok(TrojanClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            password: self.password.clone(),
            sni: sni_or_server(self.sni.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            udp: self.udp,
            client_fingerprint: self.client_fingerprint,
            transport,
        })
    }
}

impl MihomoHysteria2Proxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<Hysteria2ClientConfig> {
        ensure_no_proxy_extra_fields(
            &format!("mihomo Hysteria2 proxy {}", self.name),
            &self.fields,
        )?;
        ensure!(
            self.ports.is_none(),
            "mihomo Hysteria2 proxy {} uses port hopping; Aerion Hysteria2 client expects one fixed port",
            self.name
        );
        ensure!(
            !self
                .hop_interval
                .as_ref()
                .map(value_has_data)
                .unwrap_or(false),
            "mihomo Hysteria2 proxy {} sets hop-interval; Aerion Hysteria2 client expects one fixed port",
            self.name
        );
        ensure!(
            self.bbr_profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
            "mihomo Hysteria2 proxy {} sets bbr-profile {:?}; Aerion Hysteria2 uses the default BBR profile",
            self.name,
            self.bbr_profile
        );
        ensure!(
            !self
                .realm_opts
                .as_ref()
                .map(value_has_data)
                .unwrap_or(false),
            "mihomo Hysteria2 proxy {} sets realm-opts; Aerion Hysteria2 client does not expose realm override",
            self.name
        );
        for (field, value) in [
            (
                "initial-stream-receive-window",
                self.initial_stream_receive_window.as_ref(),
            ),
            (
                "max-stream-receive-window",
                self.max_stream_receive_window.as_ref(),
            ),
            (
                "initial-connection-receive-window",
                self.initial_connection_receive_window.as_ref(),
            ),
            (
                "max-connection-receive-window",
                self.max_connection_receive_window.as_ref(),
            ),
        ] {
            ensure!(
                !value.map(value_has_data).unwrap_or(false),
                "mihomo Hysteria2 proxy {} sets {field}; Aerion Hysteria2 client does not expose QUIC receive window override",
                self.name
            );
        }
        if let Some(obfs) = self
            .obfs
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            ensure!(
                obfs.eq_ignore_ascii_case("salamander"),
                "mihomo Hysteria2 proxy {} uses obfs {}; Aerion supports salamander",
                self.name,
                obfs
            );
        }
        let port = self
            .port
            .with_context(|| format!("mihomo Hysteria2 proxy {} is missing port", self.name))?;
        ensure_hy2_alpn(&self.name, self.alpn.as_ref())?;
        Ok(Hysteria2ClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: port,
            password: self.password.clone(),
            sni: sni_or_server(self.sni.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            certificate_fingerprint: self.fingerprint.clone(),
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            obfs: self.obfs.clone(),
            obfs_password: self.obfs_password.clone(),
            upload_bandwidth: self.up,
            download_bandwidth: self.down,
            udp: self.udp,
            congestion_control: self.congestion_control.clone(),
        })
    }
}

impl MihomoAnyTlsProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<ClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo AnyTLS proxy {}", self.name), &self.fields)?;
        Ok(ClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            password: self.password.clone(),
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            client_fingerprint: self.client_fingerprint,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            padding_scheme: if self.padding_scheme.is_empty() {
                PaddingScheme::default_lines()
            } else {
                self.padding_scheme.clone()
            },
            heartbeat_interval_secs: 30,
        })
    }
}

impl MihomoNodeExpandProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<NodeExpandClientConfig> {
        ensure_no_proxy_extra_fields(
            &format!("mihomo NodeExpand proxy {}", self.name),
            &self.fields,
        )?;
        let password = self
            .password
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                self.uuid
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
            .with_context(|| {
                format!(
                    "mihomo NodeExpand proxy {} is missing password or uuid",
                    self.name
                )
            })?;
        let endpoints = if self.endpoints.is_empty() {
            let server_host = self
                .server
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .with_context(|| {
                    format!(
                        "mihomo NodeExpand proxy {} is missing endpoints or server",
                        self.name
                    )
                })?;
            let server_port = self.port.with_context(|| {
                format!(
                    "mihomo NodeExpand proxy {} is missing endpoints or port",
                    self.name
                )
            })?;
            vec![NodeExpandEndpoint {
                server_host: server_host.to_string(),
                server_port,
            }]
        } else {
            self.endpoints
                .iter()
                .enumerate()
                .map(|(index, endpoint)| endpoint.to_endpoint(&self.name, index))
                .collect::<Result<Vec<_>>>()?
        };
        Ok(NodeExpandClientConfig {
            listen,
            endpoints,
            password: password.to_string(),
            padding_scheme: if self.padding_scheme.is_empty() {
                PaddingScheme::default_lines()
            } else {
                self.padding_scheme.clone()
            },
            heartbeat_interval_secs: self.heartbeat_interval_secs.unwrap_or(30),
        })
    }
}

impl MihomoNodeExpandEndpoint {
    fn to_endpoint(&self, name: &str, index: usize) -> Result<NodeExpandEndpoint> {
        ensure_no_proxy_extra_fields(
            &format!("mihomo NodeExpand proxy {name} endpoint #{}", index + 1),
            &self.fields,
        )?;
        let host = self
            .server_host
            .as_deref()
            .or(self.host.as_deref())
            .or(self.server.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .with_context(|| {
                format!(
                    "mihomo NodeExpand proxy {name} endpoint #{} is missing host",
                    index + 1
                )
            })?;
        let port = self.port.or(self.server_port).with_context(|| {
            format!(
                "mihomo NodeExpand proxy {name} endpoint #{} is missing port",
                index + 1
            )
        })?;
        Ok(NodeExpandEndpoint {
            server_host: host.to_string(),
            server_port: port,
        })
    }
}

impl MihomoMieruProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<MieruClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo Mieru proxy {}", self.name), &self.fields)?;
        Ok(MieruClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port,
            username: self
                .username
                .clone()
                .unwrap_or_else(|| self.password.clone()),
            password: self.password.clone(),
            hashed_password: None,
            mtu: 1500,
            transport: MieruTransport::parse(&self.transport)?,
            traffic_pattern: MieruTrafficPattern::parse_pair(
                self.traffic_pattern.as_deref(),
                self.nonce_pattern.as_deref(),
            )
            .with_context(|| format!("parse mihomo Mieru proxy {} traffic pattern", self.name))?,
        })
    }
}

impl MihomoNaiveProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<NaiveClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo Naive proxy {}", self.name), &self.fields)?;
        Ok(NaiveClientConfig {
            listen,
            server_host: self.server.clone(),
            server_port: self.port.unwrap_or(443),
            username: self.username.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            extra_headers: self.extra_headers.clone().into_iter().collect(),
            udp_over_tcp: self
                .udp_over_tcp
                .as_ref()
                .map(|options| options.enabled_for("Naive", &self.name))
                .transpose()?
                .unwrap_or(false),
            quic: self.quic,
            quic_congestion_control: default_naive_quic_congestion_control(),
        })
    }
}

impl MihomoTuicProxy {
    pub fn to_client_config(&self, listen: SocketAddr) -> Result<TuicClientConfig> {
        ensure_no_proxy_extra_fields(&format!("mihomo TUIC proxy {}", self.name), &self.fields)?;
        ensure!(
            self.token.as_deref().unwrap_or_default().trim().is_empty(),
            "mihomo TUIC proxy {} uses TUIC v4 token; Aerion implements TUIC v5 UUID/password auth",
            self.name
        );
        ensure!(
            !self.reduce_rtt,
            "mihomo TUIC proxy {} enables reduce-rtt; Aerion TUIC client does not expose 0-RTT handshakes",
            self.name
        );
        ensure!(
            !self.disable_sni,
            "mihomo TUIC proxy {} disables SNI; Aerion TUIC client requires a TLS server name",
            self.name
        );
        ensure!(
            !self.fast_open,
            "mihomo TUIC proxy {} enables fast-open; Aerion TUIC client does not expose TCP fast open",
            self.name
        );
        ensure!(
            self.bbr_profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none_or(|value| value.eq_ignore_ascii_case("standard")),
            "mihomo TUIC proxy {} sets bbr-profile {:?}; Aerion TUIC uses the default BBR profile",
            self.name,
            self.bbr_profile
        );
        for (field, value) in [
            ("max-open-streams", self.max_open_streams.as_ref()),
            (
                "max-udp-relay-packet-size",
                self.max_udp_relay_packet_size.as_ref(),
            ),
            ("request-timeout", self.request_timeout.as_ref()),
        ] {
            ensure!(
                !value.map(value_has_data).unwrap_or(false),
                "mihomo TUIC proxy {} sets {field}; Aerion TUIC client does not expose this option",
                self.name
            );
        }
        ensure_tuic_alpn(&self.name, self.alpn.as_ref())?;
        let server_host = self
            .ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.server);
        Ok(TuicClientConfig {
            listen,
            server_host: server_host.to_string(),
            server_port: self.port,
            uuid: self
                .uuid
                .clone()
                .with_context(|| format!("mihomo TUIC proxy {} is missing uuid", self.name))?,
            password: self
                .password
                .clone()
                .with_context(|| format!("mihomo TUIC proxy {} is missing password", self.name))?,
            sni: sni_or_server(self.servername.as_deref(), &self.server),
            insecure: self.skip_cert_verify,
            ca_cert_paths: Vec::new(),
            ca_certificates: Vec::new(),
            disable_system_roots: false,
            pinned_cert_sha256: Vec::new(),
            udp: self.udp,
            udp_relay_mode: self.udp_relay_mode.clone(),
            congestion_control: self.congestion_control.clone(),
            alpn_protocols: alpn_values(self.alpn.as_ref()),
            heartbeat_interval_secs: self
                .heartbeat_interval
                .map(|millis| millis.saturating_add(999) / 1000)
                .unwrap_or(10),
        })
    }
}

impl MihomoRealityOpts {
    pub fn to_client_config(&self) -> Result<RealityClientConfig> {
        ensure_no_extra_fields("mihomo reality-opts", &self.fields)?;
        RealityClientConfig::from_strings(&self.public_key, &self.short_id)
    }
}

impl MihomoSmuxOptions {
    pub(super) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(super) fn has_settings(&self) -> bool {
        self.enabled
            || self
                .protocol
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || self.max_connections.is_some()
            || self.min_streams.is_some()
            || self.max_streams.is_some()
            || !self.fields.is_empty()
    }

    pub(super) fn ensure_supported(&self, name: &str) -> Result<()> {
        ensure_no_extra_fields(&format!("mihomo proxy {name} smux"), &self.fields)?;
        ensure!(
            !self.has_settings(),
            "mihomo proxy {name} sets smux options; Aerion VLESS mux.cool is not wire-compatible with mihomo smux"
        );
        Ok(())
    }
}

impl MihomoWsOptions {
    pub(super) fn ensure_supported(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(owner, &self.fields)
    }

    pub(super) fn has_settings(&self) -> bool {
        self.path
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || !self.headers.is_empty()
            || !self.fields.is_empty()
    }
}

impl MihomoGrpcOptions {
    pub(super) fn ensure_supported(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(owner, &self.fields)
    }

    pub(super) fn has_settings(&self) -> bool {
        self.grpc_service_name
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || !self.fields.is_empty()
    }
}

impl MihomoXhttpOptions {
    pub(super) fn ensure_supported(&self, owner: &str) -> Result<()> {
        ensure_no_extra_fields(owner, &self.fields)
    }

    pub(super) fn has_settings(&self) -> bool {
        self.path
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || self
                .host
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || self
                .mode
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || !self.headers.is_empty()
            || !self.fields.is_empty()
    }
}

impl OneOrManyStrings {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}
