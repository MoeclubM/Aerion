//! Auto-extracted from the mihomo compatibility module. See `mod.rs` for shared
//! types, imports, and helper functions (brought in via `use super::*`).

use super::*;

pub(super) fn split_mihomo_rule(raw: &str) -> Vec<&str> {
    raw.split(',').map(str::trim).collect()
}

pub(super) fn split_mihomo_logical_rule<'a>(
    raw: &'a str,
    location: &str,
    action: Option<RouteDecision>,
) -> Result<(String, &'a str, RouteDecision)> {
    let (kind, rest) = raw
        .split_once(',')
        .with_context(|| format!("{location} logical rule is missing payload"))?;
    let kind = kind.trim().to_ascii_uppercase();
    let rest = rest.trim();
    ensure!(
        rest.starts_with('('),
        "{location} {kind} rule is missing payload"
    );
    let mut depth = 0usize;
    let mut payload_end = None;
    for (index, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                ensure!(depth > 0, "{location} {kind} rule has unmatched ')'");
                depth -= 1;
                if depth == 0 {
                    payload_end = Some(index + ch.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }
    let payload_end =
        payload_end.with_context(|| format!("{location} {kind} rule has unclosed payload"))?;
    let payload = &rest[..payload_end];
    let trailing = rest[payload_end..].trim();
    let action = match action {
        Some(action) => {
            ensure!(
                trailing.is_empty(),
                "{location} {kind} child rule sets its own action"
            );
            action
        }
        None => {
            let trailing = trailing
                .strip_prefix(',')
                .map(str::trim)
                .with_context(|| format!("{location} {kind} rule is missing outbound"))?;
            let values = trailing
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            ensure!(
                !values.is_empty(),
                "{location} {kind} rule is missing outbound"
            );
            ensure!(
                values.len() == 1,
                "{location} {kind} rule has unsupported trailing fields {:?}",
                &values[1..]
            );
            RouteDecision::from_outbound(values[0])?
        }
    };
    Ok((kind, payload, action))
}

pub(super) fn mihomo_logical_children<'a>(
    payload: &'a str,
    location: &str,
) -> Result<Vec<&'a str>> {
    let payload = payload.trim();
    ensure!(
        payload.starts_with('(') && payload.ends_with(')'),
        "{location} logical payload must be enclosed in parentheses"
    );
    let inner = payload[1..payload.len() - 1].trim();
    let mut children = Vec::new();
    let mut cursor = 0usize;
    while cursor < inner.len() {
        let tail = inner[cursor..].trim_start();
        cursor = inner.len() - tail.len();
        if tail.starts_with(',') {
            cursor += 1;
            continue;
        }
        ensure!(
            tail.starts_with('('),
            "{location} logical payload has non-rule text {}",
            tail
        );
        let start = cursor;
        let mut depth = 0usize;
        let mut end = None;
        for (offset, ch) in inner[start..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    ensure!(depth > 0, "{location} logical payload has unmatched ')'");
                    depth -= 1;
                    if depth == 0 {
                        end = Some(start + offset + ch.len_utf8());
                        break;
                    }
                }
                _ => {}
            }
        }
        let end =
            end.with_context(|| format!("{location} logical payload has unclosed child rule"))?;
        children.push(inner[start + 1..end - 1].trim());
        cursor = end;
    }
    Ok(children)
}

pub(super) fn parse_mihomo_logical_rules<F>(
    kind: &str,
    payload: &str,
    location: &str,
    action: RouteDecision,
    mut parse_child: F,
) -> Result<Vec<RouteRule>>
where
    F: FnMut(&str, &str, RouteDecision) -> Result<Vec<RouteRule>>,
{
    if kind == "NOT" {
        bail!("{location} NOT requires negative route matching");
    }
    let children = mihomo_logical_children(payload, location)?;
    ensure!(
        !children.is_empty(),
        "{location} {kind} rule has no child rules"
    );
    if kind == "OR" {
        let mut rules = Vec::new();
        for (child_index, child) in children.iter().enumerate() {
            let child_location = format!("{location} {kind}[{child_index}]");
            rules.extend(parse_child(child, &child_location, action.clone())?);
        }
        return Ok(rules);
    }

    let mut branches = vec![RouteRule::new(action.clone())];
    for (child_index, child) in children.iter().enumerate() {
        let child_location = format!("{location} {kind}[{child_index}]");
        let child_rules = parse_child(child, &child_location, action.clone())?;
        ensure!(
            !child_rules.is_empty(),
            "{child_location} expands to no route rules"
        );
        let mut next = Vec::new();
        for branch in &branches {
            for child_rule in &child_rules {
                let mut merged = branch.clone();
                merge_mihomo_and_route_rule(&mut merged, child_rule.clone(), &child_location)?;
                next.push(merged);
            }
        }
        branches = next;
    }
    Ok(branches)
}

pub(super) fn parse_mihomo_route_expr_with_action(
    raw: &str,
    location: &str,
    action: RouteDecision,
) -> Result<Vec<RouteRule>> {
    let parts = split_mihomo_rule(raw);
    ensure!(
        !parts.is_empty() && !parts[0].is_empty(),
        "{location} is empty"
    );
    let kind = parts[0].to_ascii_uppercase();
    match kind.as_str() {
        "RULE-SET" => bail!("{location} nested RULE-SET requires rule-set expansion"),
        "OR" | "AND" | "NOT" => {
            let (kind, payload, action) = split_mihomo_logical_rule(raw, location, Some(action))?;
            parse_mihomo_logical_rules(
                &kind,
                payload,
                location,
                action,
                |child, location, action| {
                    parse_mihomo_route_expr_with_action(child, location, action)
                },
            )
        }
        _ => Ok(vec![parse_mihomo_route_rule_parts(
            &parts,
            location,
            Some(action),
        )?]),
    }
}

pub(super) fn parse_mihomo_route_rule_parts(
    parts: &[&str],
    location: &str,
    action: Option<RouteDecision>,
) -> Result<RouteRule> {
    ensure!(
        !parts.is_empty() && !parts[0].is_empty(),
        "{location} is empty"
    );
    let kind = parts[0].to_ascii_uppercase();
    let action_index = if matches!(kind.as_str(), "MATCH" | "FINAL") {
        1
    } else {
        2
    };
    let inherited_action = action.is_some();
    let action = match action {
        Some(action) => action,
        None => {
            ensure!(parts.len() > action_index, "{location} is missing outbound");
            RouteDecision::from_outbound(parts[action_index])?
        }
    };
    if !matches!(kind.as_str(), "MATCH" | "FINAL") {
        ensure!(
            parts.len() > 1 && !parts[1].is_empty(),
            "{location} is missing rule value"
        );
    }
    let param_start = if inherited_action {
        if matches!(kind.as_str(), "MATCH" | "FINAL") {
            1
        } else {
            2
        }
    } else {
        action_index + 1
    };
    let params = parts.get(param_start..).unwrap_or(&[]);
    if params.iter().any(|param| param.eq_ignore_ascii_case("src")) {
        bail!("{location} src route parameter requires source IP metadata");
    }
    for param in params.iter().filter(|param| !param.is_empty()) {
        ensure!(
            param.eq_ignore_ascii_case("no-resolve"),
            "{location} unsupported mihomo route parameter {param}"
        );
    }
    let mut rule = RouteRule::new(action);
    match kind.as_str() {
        "DOMAIN" => rule.domains.push(DomainMatcher::exact(parts[1])),
        "DOMAIN-SUFFIX" => rule.domains.push(DomainMatcher::suffix(parts[1])),
        "DOMAIN-KEYWORD" => rule.domains.push(DomainMatcher::keyword(parts[1])),
        "DOMAIN-WILDCARD" => rule.domains.push(DomainMatcher::wildcard(parts[1])?),
        "DOMAIN-REGEX" => rule.domains.push(DomainMatcher::regex(parts[1])?),
        "GEOSITE" => rule.add_geosite_set(parts[1]),
        "IP-CIDR" | "IP-CIDR6" => rule.ip_cidrs.push(IpCidr::parse(parts[1])?),
        "GEOIP" if parts[1].eq_ignore_ascii_case("private") => rule.ip_is_private = true,
        "GEOIP" => rule.add_geoip_set(parts[1]),
        "DST-PORT" => rule.ports.push(PortRange::parse(parts[1])?),
        "NETWORK" => rule.networks.push(RouteNetwork::parse(parts[1])?),
        "MATCH" | "FINAL" => {}
        "RULE-SET" => bail!("{location} nested RULE-SET requires rule-set expansion"),
        "SRC-IP-CIDR" | "SRC-PORT" => bail!("{location} source rules require source metadata"),
        "PROCESS-NAME" | "PROCESS-PATH" => {
            bail!("{location} process rules require process metadata")
        }
        other => bail!("{location} unsupported mihomo route rule type {other}"),
    }
    Ok(rule)
}

pub(super) fn merge_mihomo_and_route_rule(
    target: &mut RouteRule,
    rule: RouteRule,
    location: &str,
) -> Result<()> {
    ensure!(
        target.networks.is_empty() || rule.networks.is_empty(),
        "{location} AND combines multiple network matchers"
    );
    let target_has_domain = !target.domains.is_empty() || !target.geosite_sets.is_empty();
    let rule_has_domain = !rule.domains.is_empty() || !rule.geosite_sets.is_empty();
    ensure!(
        !target_has_domain || !rule_has_domain,
        "{location} AND combines multiple domain matchers"
    );
    let target_has_ip =
        target.ip_is_private || !target.ip_cidrs.is_empty() || !target.geoip_sets.is_empty();
    let rule_has_ip =
        rule.ip_is_private || !rule.ip_cidrs.is_empty() || !rule.geoip_sets.is_empty();
    ensure!(
        !target_has_domain || !rule_has_ip,
        "{location} AND combines destination domain and IP matchers, which requires DNS resolution"
    );
    ensure!(
        !target_has_ip || !rule_has_domain,
        "{location} AND combines destination IP and domain matchers, which requires DNS resolution"
    );
    ensure!(
        target.ip_cidrs.is_empty() || rule.ip_cidrs.is_empty(),
        "{location} AND combines multiple IP CIDR matchers"
    );
    ensure!(
        target.geoip_sets.is_empty() || rule.geoip_sets.is_empty(),
        "{location} AND combines multiple geoip matchers"
    );
    ensure!(
        target.ports.is_empty() || rule.ports.is_empty(),
        "{location} AND combines multiple port matchers"
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

pub(super) fn mihomo_rule_provider_domain(value: &str) -> Result<DomainMatcher> {
    DomainMatcher::clash_wildcard(value)
}

pub(super) fn clean_mihomo_rule_provider_lines(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

pub(super) fn mihomo_text_rule_provider_line(line: &str) -> Option<&str> {
    let line = line.split('#').next().unwrap_or_default().trim();
    (!line.is_empty()).then_some(line)
}

pub(super) fn collect_mihomo_route_asset_sets(
    table: &RouteTable,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut geoip = BTreeSet::new();
    let mut geosite = BTreeSet::new();
    for rule in &table.rules {
        geoip.extend(rule.geoip_sets.iter().cloned());
        geosite.extend(rule.geosite_sets.iter().cloned());
    }
    (geoip, geosite)
}

pub fn load_mihomo_route_assets(table: &mut RouteTable, dir: &Path) -> Result<()> {
    let (geoip, geosite) = collect_mihomo_route_asset_sets(table);
    for name in geoip {
        if table.geoip_sets.contains_key(&name) {
            continue;
        }
        let path = mihomo_route_asset_path(dir, &name, "geoip");
        table.load_geoip_set_file(&name, path)?;
    }
    for name in geosite {
        if table.geosite_sets.contains_key(&name) {
            continue;
        }
        let path = mihomo_route_asset_path(dir, &name, "geosite");
        table.load_geosite_set_file(&name, path)?;
    }
    ensure_mihomo_route_assets(table, Some(dir))
}

pub(super) fn ensure_mihomo_route_assets(table: &RouteTable, dir: Option<&Path>) -> Result<()> {
    let (geoip, geosite) = collect_mihomo_route_asset_sets(table);
    for name in geoip {
        ensure!(
            table.geoip_sets.contains_key(&name),
            "mihomo route rule references geoip set {name}{}",
            mihomo_route_asset_hint(dir, &name, "geoip")
        );
    }
    for name in geosite {
        ensure!(
            table.geosite_sets.contains_key(&name),
            "mihomo route rule references geosite set {name}{}",
            mihomo_route_asset_hint(dir, &name, "geosite")
        );
    }
    Ok(())
}

pub(super) fn mihomo_route_asset_path(dir: &Path, name: &str, kind: &str) -> PathBuf {
    let normalized = route_set_name(name);
    for candidate in [
        dir.join(format!("{normalized}.txt")),
        dir.join(format!("{normalized}.list")),
        dir.join(kind).join(format!("{normalized}.txt")),
        dir.join(kind).join(format!("{normalized}.list")),
    ] {
        if candidate.is_file() {
            return candidate;
        }
    }
    dir.join(format!("{normalized}.txt"))
}

pub(super) fn mihomo_route_asset_hint(dir: Option<&Path>, name: &str, kind: &str) -> String {
    let normalized = route_set_name(name);
    match dir {
        Some(dir) => format!(
            "; place CIDR/domain lines in {}/{normalized}.txt or {}/{kind}/{normalized}.txt",
            dir.display(),
            dir.display()
        ),
        None => format!("; provide route {kind} data for {normalized} via route_table_with_assets"),
    }
}
