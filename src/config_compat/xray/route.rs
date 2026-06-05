//! Auto-extracted from the xray compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

impl XrayRoutingConfig {
    pub fn to_route_table(&self, outbounds: &[XrayOutbound]) -> Result<RouteTable> {
        ensure!(
            self.extra.is_empty(),
            "xray routing has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        if let Some(matcher) = self.domain_matcher.as_deref().map(str::trim) {
            ensure!(
                matcher.is_empty()
                    || matcher.eq_ignore_ascii_case("linear")
                    || matcher.eq_ignore_ascii_case("hybrid")
                    || matcher.eq_ignore_ascii_case("mph"),
                "unsupported xray routing.domainMatcher {matcher}"
            );
        }
        if let Some(strategy) = self.domain_strategy.as_deref().map(str::trim) {
            ensure!(
                strategy.is_empty() || strategy.eq_ignore_ascii_case("AsIs"),
                "xray routing.domainStrategy {strategy} requires DNS resolution during routing"
            );
        }
        let mut table = RouteTable {
            default: xray_default_route_decision(outbounds)?,
            ..RouteTable::default()
        };
        for (index, rule) in self.rules.iter().enumerate() {
            table
                .rules
                .push(rule.to_route_rule(index, &self.balancers, outbounds)?);
        }
        Ok(table)
    }
}

impl XrayRoutingRule {
    fn to_route_rule(
        &self,
        index: usize,
        balancers: &[XrayBalancer],
        outbounds: &[XrayOutbound],
    ) -> Result<RouteRule> {
        ensure!(
            self.extra.is_empty(),
            "xray routing.rules[{index}] has unsupported fields {:?}",
            self.extra.keys().collect::<Vec<_>>()
        );
        self.reject_unsupported_match_metadata(index)?;
        if let Some(rule_tag) = &self.rule_tag {
            ensure!(
                rule_tag.as_str().is_some(),
                "xray routing.rules[{index}] ruleTag must be a string"
            );
        }
        ensure!(
            self.kind.trim().is_empty() || self.kind.eq_ignore_ascii_case("field"),
            "unsupported xray routing.rules[{index}] type {}",
            self.kind
        );
        let action = if !self.outbound_tag.trim().is_empty() {
            RouteDecision::from_outbound(&self.outbound_tag)?
        } else if !self.balancer_tag.trim().is_empty() {
            let balancer = balancers
                .iter()
                .find(|balancer| balancer.tag == self.balancer_tag)
                .with_context(|| {
                    format!(
                        "xray routing.rules[{index}] balancerTag {} was not found",
                        self.balancer_tag
                    )
                })?;
            RouteDecision::Proxy(balancer.static_target(outbounds)?)
        } else {
            bail!("xray routing.rules[{index}] is missing outboundTag or balancerTag");
        };
        let mut rule = RouteRule::new(action);
        for domain in &self.domain {
            if let Some(name) = DomainMatcher::geosite_name(domain) {
                bail!("xray routing.rules[{index}] geosite {name} requires geosite rule-set data");
            } else if let Some(matcher) = DomainMatcher::xray(domain)? {
                rule.domains.push(matcher);
            }
        }
        for ip in &self.ip {
            let ip = ip.trim();
            if let Some(value) = ip.strip_prefix('!') {
                ensure!(
                    !value.trim().is_empty(),
                    "xray routing.rules[{index}] inverse IP matcher is empty"
                );
                bail!(
                    "xray routing.rules[{index}] inverse IP matcher {value} requires negative route matching"
                );
            } else if ip
                .get(..4)
                .map(|prefix| prefix.eq_ignore_ascii_case("ext:"))
                .unwrap_or(false)
            {
                bail!(
                    "xray routing.rules[{index}] external IP matcher {ip} requires geoip rule-set data"
                );
            } else if ip.eq_ignore_ascii_case("geoip:private") {
                rule.ip_is_private = true;
            } else if let Some(name) = IpCidr::geoip_name(ip) {
                bail!("xray routing.rules[{index}] geoip {name} requires geoip rule-set data");
            } else {
                rule.ip_cidrs.push(IpCidr::parse(ip)?);
            }
        }
        if let Some(network) = &self.network {
            for value in network
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                rule.networks.push(RouteNetwork::parse(value)?);
            }
        }
        for value in xray_route_value_strings(self.port.as_ref())? {
            rule.ports.push(PortRange::parse(&value)?);
        }
        Ok(rule)
    }

    fn reject_unsupported_match_metadata(&self, index: usize) -> Result<()> {
        for (field, value, reason) in [
            (
                "sourcePort",
                &self.source_port,
                "source port matching metadata",
            ),
            ("localPort", &self.local_port, "local inbound port metadata"),
            (
                "sourceIP/source",
                &self.source_ip,
                "source IP matching metadata",
            ),
            ("localIP", &self.local_ip, "local inbound IP metadata"),
            ("user", &self.user, "authenticated inbound user metadata"),
            (
                "vlessRoute",
                &self.vless_route,
                "VLESS inbound route metadata",
            ),
            ("inboundTag", &self.inbound_tag, "inbound tag metadata"),
            ("protocol", &self.protocol, "sniffed protocol metadata"),
            ("attrs", &self.attrs, "sniffed HTTP attribute metadata"),
            ("process", &self.process, "process metadata"),
            ("webhook", &self.webhook, "route-hit webhook side effects"),
        ] {
            ensure!(
                value.is_none(),
                "xray routing.rules[{index}] {field} requires {reason}"
            );
        }
        Ok(())
    }
}

fn xray_default_route_decision(outbounds: &[XrayOutbound]) -> Result<RouteDecision> {
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
    match outbound.protocol.trim().to_ascii_lowercase().as_str() {
        "freedom" => Ok(RouteDecision::Direct),
        "blackhole" => Ok(RouteDecision::Block),
        protocol => bail!(
            "xray routing default uses first outbound protocol {protocol} without tag; Aerion route proxy requires a tag"
        ),
    }
}

impl XrayBalancer {
    fn static_target(&self, outbounds: &[XrayOutbound]) -> Result<String> {
        ensure!(
            self.extra.is_empty(),
            "xray routing.balancers {} has unsupported fields {:?}",
            self.tag,
            self.extra.keys().collect::<Vec<_>>()
        );
        ensure!(
            self.fallback_tag.trim().is_empty(),
            "xray routing.balancers {} fallbackTag requires active observatory state",
            self.tag
        );
        ensure!(
            self.strategy
                .as_ref()
                .map(value_is_empty_object)
                .unwrap_or(true),
            "xray routing.balancers {} strategy requires active load balancing policy",
            self.tag
        );
        let selectors = self
            .selector
            .iter()
            .map(|selector| selector.trim())
            .filter(|selector| !selector.is_empty())
            .collect::<Vec<_>>();
        ensure!(
            !selectors.is_empty(),
            "xray routing.balancers {} has no selector",
            self.tag
        );
        let mut matches = Vec::new();
        for outbound in outbounds {
            let tag = outbound.tag.as_deref().unwrap_or_default();
            if !tag.is_empty()
                && selectors.iter().any(|selector| tag.starts_with(selector))
                && !matches.iter().any(|matched| matched == tag)
            {
                matches.push(tag.to_string());
            }
        }
        ensure!(
            matches.len() == 1,
            "xray routing.balancers {} matches {} outbounds [{}]; Aerion only supports statically equivalent single-outbound balancers",
            self.tag,
            matches.len(),
            matches.join(", ")
        );
        Ok(matches.remove(0))
    }
}
