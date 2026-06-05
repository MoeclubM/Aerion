//! Auto-extracted from the singbox compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

impl SingBoxRouteConfig {
    pub fn to_route_table(
        &self,
        source_dir: Option<&Path>,
        outbounds: &[SingBoxOutbound],
    ) -> Result<RouteTable> {
        self.reject_unsupported_route_options()?;
        let rule_sets = self.static_rule_sets(source_dir)?;
        let default = match self
            .final_outbound
            .as_deref()
            .map(RouteDecision::from_outbound)
            .transpose()?
        {
            Some(default) => default,
            None => singbox_default_route_decision(outbounds)?,
        };
        let mut table = RouteTable {
            rules: Vec::new(),
            default,
            ..RouteTable::default()
        };
        for (index, rule) in self.rules.iter().enumerate() {
            table.rules.extend(rule.to_route_rules(index, &rule_sets)?);
        }
        Ok(table)
    }

    fn reject_unsupported_route_options(&self) -> Result<()> {
        ensure!(
            self.extra.is_empty(),
            "sing-box route has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        for (field, value, reason) in [
            (
                "auto_detect_interface",
                &self.auto_detect_interface,
                "active platform interface detection",
            ),
            (
                "override_android_vpn",
                &self.override_android_vpn,
                "Android VPN route ownership",
            ),
            (
                "default_interface",
                &self.default_interface,
                "platform interface binding",
            ),
            (
                "default_mark",
                &self.default_mark,
                "platform socket mark support",
            ),
            (
                "default_domain_resolver",
                &self.default_domain_resolver,
                "DNS resolver integration during routing",
            ),
            (
                "default_network_strategy",
                &self.default_network_strategy,
                "DNS network strategy integration",
            ),
            (
                "default_network_type",
                &self.default_network_type,
                "platform network metadata",
            ),
            (
                "default_fallback_network_type",
                &self.default_fallback_network_type,
                "platform network fallback metadata",
            ),
            (
                "default_fallback_delay",
                &self.default_fallback_delay,
                "platform network fallback timers",
            ),
            (
                "find_process",
                &self.find_process,
                "process metadata lookup",
            ),
            (
                "find_neighbor",
                &self.find_neighbor,
                "LAN neighbor metadata lookup",
            ),
            (
                "dhcp_lease_files",
                &self.dhcp_lease_files,
                "DHCP lease metadata lookup",
            ),
            (
                "default_http_client",
                &self.default_http_client,
                "remote rule-set HTTP client integration",
            ),
            (
                "default_transport",
                &self.default_transport,
                "global dialer transport policy",
            ),
            (
                "default_udp_timeout",
                &self.default_udp_timeout,
                "global UDP session timeout policy",
            ),
            (
                "geoip",
                &self.geoip,
                "loading sing-box legacy geoip databases",
            ),
            (
                "geosite",
                &self.geosite,
                "loading sing-box legacy geosite databases",
            ),
        ] {
            ensure!(
                !value.as_ref().map(value_has_data).unwrap_or(false),
                "sing-box route {field} requires {reason}"
            );
        }
        Ok(())
    }

    fn static_rule_sets(
        &self,
        source_dir: Option<&Path>,
    ) -> Result<BTreeMap<String, Vec<SingBoxRouteRule>>> {
        let mut rule_sets = BTreeMap::new();
        for rule_set in &self.rule_sets {
            let tag = rule_set.tag.trim();
            ensure!(!tag.is_empty(), "sing-box route.rule_set tag is empty");
            ensure!(
                rule_sets
                    .insert(tag.to_string(), rule_set.static_rules(source_dir)?)
                    .is_none(),
                "sing-box route.rule_set {tag} is duplicated"
            );
        }
        Ok(rule_sets)
    }
}

impl SingBoxRuleSet {
    fn static_rules(&self, source_dir: Option<&Path>) -> Result<Vec<SingBoxRouteRule>> {
        ensure!(
            self.extra.is_empty(),
            "sing-box route.rule_set {} has unsupported fields {:?}",
            self.tag,
            self.extra.keys().collect::<Vec<_>>()
        );
        let kind = self
            .kind
            .as_deref()
            .map(str::trim)
            .filter(|kind| !kind.is_empty())
            .unwrap_or("inline")
            .to_ascii_lowercase();
        match kind.as_str() {
            "inline" => {
                ensure!(
                    self.format.is_none()
                        && self.path.is_none()
                        && self.url.is_none()
                        && self.http_client.is_none()
                        && self.update_interval.is_none()
                        && self.download_detour.is_none(),
                    "sing-box inline route.rule_set {} sets local/remote rule-set fields",
                    self.tag
                );
                ensure!(
                    !self.rules.is_empty(),
                    "sing-box inline route.rule_set {} has no rules",
                    self.tag
                );
                Ok(self.rules.clone())
            }
            "local" => self.local_source_rules(source_dir),
            "remote" => bail!(
                "sing-box remote route.rule_set {} requires downloading rule-set data",
                self.tag
            ),
            other => bail!(
                "unsupported sing-box route.rule_set {} type {other}",
                self.tag
            ),
        }
    }

    fn local_source_rules(&self, source_dir: Option<&Path>) -> Result<Vec<SingBoxRouteRule>> {
        ensure!(
            self.rules.is_empty()
                && self.url.is_none()
                && self.http_client.is_none()
                && self.update_interval.is_none()
                && self.download_detour.is_none(),
            "sing-box local route.rule_set {} sets inline/remote rule-set fields",
            self.tag
        );
        let path = value_path(self.path.as_ref()).with_context(|| {
            format!("sing-box local route.rule_set {} is missing path", self.tag)
        })?;
        let format = self.rule_set_format(Some(&path))?;
        ensure!(
            format == "source",
            "sing-box local route.rule_set {} format {format} is not supported",
            self.tag
        );
        let path = match (path.is_absolute(), source_dir) {
            (true, _) | (false, None) => path,
            (false, Some(source_dir)) => source_dir.join(path),
        };
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "read sing-box local route.rule_set {} file {}",
                self.tag,
                path.display()
            )
        })?;
        let source: SingBoxSourceRuleSet = serde_json::from_str(&text).with_context(|| {
            format!(
                "parse sing-box local route.rule_set {} source file {}",
                self.tag,
                path.display()
            )
        })?;
        ensure!(
            source.extra.is_empty(),
            "sing-box local route.rule_set {} source has unsupported fields {:?}",
            self.tag,
            source.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            source.version > 0,
            "sing-box local route.rule_set {} source version is invalid",
            self.tag
        );
        ensure!(
            !source.rules.is_empty(),
            "sing-box local route.rule_set {} source has no rules",
            self.tag
        );
        Ok(source.rules)
    }

    fn rule_set_format(&self, path: Option<&Path>) -> Result<String> {
        if let Some(value) = &self.format {
            return value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .with_context(|| {
                    format!(
                        "sing-box route.rule_set {} format must be a string",
                        self.tag
                    )
                });
        }
        let extension = path
            .and_then(Path::extension)
            .and_then(|value| value.to_str())
            .map(str::trim)
            .unwrap_or_default();
        if extension.eq_ignore_ascii_case("json") {
            return Ok("source".to_string());
        }
        if extension.eq_ignore_ascii_case("srs") {
            return Ok("binary".to_string());
        }
        bail!("sing-box route.rule_set {} is missing format", self.tag)
    }
}

fn singbox_default_route_decision(outbounds: &[SingBoxOutbound]) -> Result<RouteDecision> {
    let Some(outbound) = outbounds.first() else {
        return Ok(RouteDecision::Direct);
    };
    if let Some(tag) = outbound
        .tag
        .as_deref()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
    {
        return RouteDecision::from_outbound(tag);
    }
    match outbound.kind.trim().to_ascii_lowercase().as_str() {
        "direct" => Ok(RouteDecision::Direct),
        "block" => Ok(RouteDecision::Block),
        kind => bail!(
            "sing-box route default uses first outbound type {kind} without tag; Aerion route proxy requires a tag"
        ),
    }
}

impl SingBoxRouteRule {
    fn to_route_rules(
        &self,
        index: usize,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            self.extra.is_empty(),
            "sing-box route.rules[{index}] has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        let kind = self
            .kind
            .as_deref()
            .map(str::trim)
            .filter(|kind| !kind.is_empty());
        if matches!(kind, Some(kind) if kind.eq_ignore_ascii_case("logical")) {
            return self.to_logical_route_rules(index, None, rule_sets);
        }
        if let Some(kind) = kind {
            ensure!(
                kind.eq_ignore_ascii_case("default"),
                "unsupported sing-box route.rules[{index}] type {kind}"
            );
        }
        self.to_default_route_rules(index, None, rule_sets)
    }

    fn to_default_route_rules(
        &self,
        index: usize,
        action_override: Option<&RouteDecision>,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            !self.rule_set_ip_cidr_match_source,
            "sing-box route.rules[{index}] rule_set_ip_cidr_match_source requires source IP matching"
        );
        let rule_set_refs = route_value_strings(self.rule_set.as_ref())?;
        ensure!(
            action_override.is_none() || rule_set_refs.is_empty(),
            "sing-box route.rules[{index}] inherited-action rule uses nested rule_set"
        );
        let base = self.to_default_route_rule(index, action_override)?;
        if rule_set_refs.is_empty() {
            return Ok(vec![base]);
        }
        let action = base.action.clone();
        let mut rules = Vec::new();
        for tag in rule_set_refs {
            let set_rules = rule_sets.get(&tag).with_context(|| {
                format!("sing-box route.rules[{index}] rule_set {tag} is missing")
            })?;
            for set_rule in set_rules {
                for branch in set_rule.to_child_route_rules(index, &action, rule_sets)? {
                    let mut merged = base.clone();
                    merge_singbox_and_route_rule(&mut merged, branch, index)?;
                    rules.push(merged);
                }
            }
        }
        ensure!(
            !rules.is_empty(),
            "sing-box route.rules[{index}] rule_set expanded to no rules"
        );
        Ok(rules)
    }

    fn to_default_route_rule(
        &self,
        index: usize,
        action_override: Option<&RouteDecision>,
    ) -> Result<RouteRule> {
        ensure!(
            self.extra.is_empty(),
            "sing-box route.rules[{index}] has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            !self.invert,
            "sing-box route.rules[{index}] invert requires negative route matching"
        );
        ensure!(
            self.mode.is_none() && self.rules.is_empty(),
            "sing-box route.rules[{index}] sets logical fields on a default rule"
        );
        self.reject_unsupported_metadata_matchers(index)?;
        let mut rule = RouteRule::new(match action_override {
            Some(action) => action.clone(),
            None => self.route_decision(index)?,
        });
        for value in route_value_strings(self.network.as_ref())? {
            ensure!(
                !value.eq_ignore_ascii_case("icmp"),
                "sing-box route.rules[{index}] network icmp requires ICMP routing support"
            );
            rule.networks.push(RouteNetwork::parse(&value)?);
        }
        for value in route_value_strings(self.domain.as_ref())? {
            rule.domains.push(DomainMatcher::exact(&value));
        }
        for value in route_value_strings(self.domain_suffix.as_ref())? {
            rule.domains.push(DomainMatcher::suffix(&value));
        }
        for value in route_value_strings(self.domain_keyword.as_ref())? {
            rule.domains.push(DomainMatcher::keyword(&value));
        }
        for value in route_value_strings(self.domain_regex.as_ref())? {
            rule.domains.push(DomainMatcher::regex(&value)?);
        }
        for value in route_value_strings(self.geosite.as_ref())? {
            bail!("sing-box route.rules[{index}] geosite {value} requires geosite rule-set data");
        }
        for value in route_value_strings(self.ip_cidr.as_ref())? {
            rule.ip_cidrs.push(IpCidr::parse(&value)?);
        }
        for value in route_value_strings(self.geoip.as_ref())? {
            if value.eq_ignore_ascii_case("private") {
                rule.ip_is_private = true;
            } else {
                bail!("sing-box route.rules[{index}] geoip {value} requires geoip rule-set data");
            }
        }
        rule.ip_is_private |= self.ip_is_private;
        for value in route_value_strings(self.port.as_ref())? {
            rule.ports.push(PortRange::parse(&value)?);
        }
        for value in route_value_strings(self.port_range.as_ref())? {
            rule.ports.push(PortRange::parse(&value)?);
        }
        Ok(rule)
    }

    fn reject_unsupported_metadata_matchers(&self, index: usize) -> Result<()> {
        for (field, value, reason) in [
            ("inbound", &self.inbound, "inbound tag metadata"),
            ("ip_version", &self.ip_version, "IP-version route metadata"),
            (
                "auth_user",
                &self.auth_user,
                "authenticated inbound user metadata",
            ),
            ("protocol", &self.protocol, "sniffed protocol metadata"),
            ("client", &self.client, "sniffed client metadata"),
            ("source_geoip", &self.source_geoip, "source IP metadata"),
            ("source_ip_cidr", &self.source_ip_cidr, "source IP metadata"),
            (
                "source_ip_is_private",
                &self.source_ip_is_private,
                "source IP metadata",
            ),
            ("source_port", &self.source_port, "source port metadata"),
            (
                "source_port_range",
                &self.source_port_range,
                "source port metadata",
            ),
            ("process_name", &self.process_name, "process metadata"),
            ("process_path", &self.process_path, "process metadata"),
            (
                "process_path_regex",
                &self.process_path_regex,
                "process metadata",
            ),
            ("package_name", &self.package_name, "process metadata"),
            (
                "package_name_regex",
                &self.package_name_regex,
                "process metadata",
            ),
            ("user", &self.user, "process owner metadata"),
            ("user_id", &self.user_id, "process owner metadata"),
            ("clash_mode", &self.clash_mode, "Clash mode state"),
            (
                "network_type",
                &self.network_type,
                "platform network metadata",
            ),
            (
                "network_is_expensive",
                &self.network_is_expensive,
                "platform network metadata",
            ),
            (
                "network_is_constrained",
                &self.network_is_constrained,
                "platform network metadata",
            ),
            (
                "interface_address",
                &self.interface_address,
                "platform interface metadata",
            ),
            (
                "network_interface_address",
                &self.network_interface_address,
                "platform interface metadata",
            ),
            (
                "default_interface_address",
                &self.default_interface_address,
                "platform interface metadata",
            ),
            ("wifi_ssid", &self.wifi_ssid, "platform Wi-Fi metadata"),
            ("wifi_bssid", &self.wifi_bssid, "platform Wi-Fi metadata"),
            (
                "preferred_by",
                &self.preferred_by,
                "platform route ownership metadata",
            ),
            (
                "source_mac_address",
                &self.source_mac_address,
                "source device metadata",
            ),
            (
                "source_hostname",
                &self.source_hostname,
                "source device metadata",
            ),
        ] {
            ensure!(
                value.is_none(),
                "sing-box route.rules[{index}] {field} requires {reason}"
            );
        }
        Ok(())
    }

    fn to_logical_route_rules(
        &self,
        index: usize,
        action_override: Option<&RouteDecision>,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            !self.invert,
            "sing-box route.rules[{index}] logical invert requires negative route matching"
        );
        let mode = self
            .mode
            .as_deref()
            .map(str::trim)
            .filter(|mode| !mode.is_empty())
            .with_context(|| format!("sing-box route.rules[{index}] logical rule is missing mode"))?
            .to_ascii_lowercase();
        ensure!(
            !self.rules.is_empty(),
            "sing-box route.rules[{index}] logical rule has no child rules"
        );
        ensure!(
            !self.has_match_fields(),
            "sing-box route.rules[{index}] logical rule sets parent match fields"
        );
        let action = match action_override {
            Some(action) => {
                ensure!(
                    self.outbound.is_none() && self.action.is_none(),
                    "sing-box route.rules[{index}] inherited logical child sets its own action"
                );
                action.clone()
            }
            None => self.route_decision(index)?,
        };
        match mode.as_str() {
            "or" => {
                let mut rules = Vec::new();
                for rule in &self.rules {
                    rules.extend(rule.to_child_route_rules(index, &action, rule_sets)?);
                }
                Ok(rules)
            }
            "and" => self
                .to_logical_and_route_rule(index, &action, rule_sets)
                .map(|rule| vec![rule]),
            other => bail!("unsupported sing-box route.rules[{index}] logical mode {other}"),
        }
    }

    fn to_child_route_rules(
        &self,
        index: usize,
        action: &RouteDecision,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<Vec<RouteRule>> {
        ensure!(
            self.outbound.is_none() && self.action.is_none(),
            "sing-box route.rules[{index}] logical child sets its own action"
        );
        let kind = self
            .kind
            .as_deref()
            .map(str::trim)
            .filter(|kind| !kind.is_empty());
        if matches!(kind, Some(kind) if kind.eq_ignore_ascii_case("logical")) {
            return self.to_logical_route_rules(index, Some(action), rule_sets);
        }
        if let Some(kind) = kind {
            ensure!(
                kind.eq_ignore_ascii_case("default"),
                "unsupported sing-box route.rules[{index}] logical child type {kind}"
            );
        }
        self.to_default_route_rules(index, Some(action), rule_sets)
    }

    fn to_logical_and_route_rule(
        &self,
        index: usize,
        action: &RouteDecision,
        rule_sets: &BTreeMap<String, Vec<SingBoxRouteRule>>,
    ) -> Result<RouteRule> {
        let mut merged = RouteRule::new(action.clone());
        for child in &self.rules {
            let mut rules = child.to_child_route_rules(index, action, rule_sets)?;
            ensure!(
                rules.len() == 1,
                "sing-box route.rules[{index}] logical and child expands to multiple branches"
            );
            merge_singbox_and_route_rule(&mut merged, rules.remove(0), index)?;
        }
        Ok(merged)
    }

    fn route_decision(&self, index: usize) -> Result<RouteDecision> {
        let outbound = self
            .outbound
            .as_deref()
            .map(str::trim)
            .filter(|outbound| !outbound.is_empty());
        let action = self
            .action
            .as_deref()
            .map(str::trim)
            .filter(|action| !action.is_empty());
        let Some(action) = action else {
            let outbound = outbound
                .with_context(|| format!("sing-box route.rules[{index}] is missing outbound"))?;
            return RouteDecision::from_outbound(outbound);
        };
        match action.to_ascii_lowercase().as_str() {
            "route" => {
                let outbound = outbound.with_context(|| {
                    format!("sing-box route.rules[{index}] route action is missing outbound")
                })?;
                RouteDecision::from_outbound(outbound)
            }
            "direct" => {
                ensure!(
                    outbound.is_none(),
                    "sing-box route.rules[{index}] direct action must not set outbound"
                );
                Ok(RouteDecision::Direct)
            }
            "reject" | "block" => {
                ensure!(
                    outbound.is_none(),
                    "sing-box route.rules[{index}] reject action must not set outbound"
                );
                Ok(RouteDecision::Block)
            }
            other => bail!("unsupported sing-box route.rules[{index}] action {other}"),
        }
    }

    fn has_match_fields(&self) -> bool {
        self.network.is_some()
            || self.domain.is_some()
            || self.domain_suffix.is_some()
            || self.domain_keyword.is_some()
            || self.domain_regex.is_some()
            || self.geosite.is_some()
            || self.inbound.is_some()
            || self.ip_version.is_some()
            || self.auth_user.is_some()
            || self.protocol.is_some()
            || self.client.is_some()
            || self.ip_cidr.is_some()
            || self.geoip.is_some()
            || self.ip_is_private
            || self.source_geoip.is_some()
            || self.source_ip_cidr.is_some()
            || self.source_ip_is_private.is_some()
            || self.port.is_some()
            || self.port_range.is_some()
            || self.source_port.is_some()
            || self.source_port_range.is_some()
            || self.process_name.is_some()
            || self.process_path.is_some()
            || self.process_path_regex.is_some()
            || self.package_name.is_some()
            || self.package_name_regex.is_some()
            || self.user.is_some()
            || self.user_id.is_some()
            || self.clash_mode.is_some()
            || self.network_type.is_some()
            || self.network_is_expensive.is_some()
            || self.network_is_constrained.is_some()
            || self.interface_address.is_some()
            || self.network_interface_address.is_some()
            || self.default_interface_address.is_some()
            || self.wifi_ssid.is_some()
            || self.wifi_bssid.is_some()
            || self.preferred_by.is_some()
            || self.source_mac_address.is_some()
            || self.source_hostname.is_some()
            || self.rule_set.is_some()
            || self.rule_set_ip_cidr_match_source
    }
}

fn merge_singbox_and_route_rule(
    target: &mut RouteRule,
    rule: RouteRule,
    index: usize,
) -> Result<()> {
    ensure!(
        target.networks.is_empty() || rule.networks.is_empty(),
        "sing-box route.rules[{index}] logical and combines multiple network matchers"
    );
    let target_has_domain = !target.domains.is_empty() || !target.geosite_sets.is_empty();
    let rule_has_domain = !rule.domains.is_empty() || !rule.geosite_sets.is_empty();
    ensure!(
        !target_has_domain || !rule_has_domain,
        "sing-box route.rules[{index}] logical and combines multiple domain matchers"
    );
    ensure!(
        target.ip_cidrs.is_empty() || rule.ip_cidrs.is_empty(),
        "sing-box route.rules[{index}] logical and combines multiple IP CIDR matchers"
    );
    ensure!(
        target.geoip_sets.is_empty() || rule.geoip_sets.is_empty(),
        "sing-box route.rules[{index}] logical and combines multiple geoip matchers"
    );
    ensure!(
        target.ports.is_empty() || rule.ports.is_empty(),
        "sing-box route.rules[{index}] logical and combines multiple port matchers"
    );
    target.networks.extend(rule.networks);
    target.domains.extend(rule.domains);
    target.geosite_sets.extend(rule.geosite_sets);
    target.ip_cidrs.extend(rule.ip_cidrs);
    target.geoip_sets.extend(rule.geoip_sets);
    target.ip_is_private |= rule.ip_is_private;
    target.ports.extend(rule.ports);
    Ok(())
}
