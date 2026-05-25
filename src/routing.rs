use crate::protocol::ProxyTarget;
use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    Proxy(String),
    Direct,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteNetwork {
    Tcp,
    Udp,
    Dns,
}

#[derive(Clone, Debug)]
pub struct RouteTable {
    pub rules: Vec<RouteRule>,
    pub default: RouteDecision,
    pub geoip_sets: BTreeMap<String, Vec<IpCidr>>,
    pub geosite_sets: BTreeMap<String, Vec<DomainMatcher>>,
}

#[derive(Clone, Debug)]
pub struct SharedRouteTable {
    inner: Arc<RwLock<RouteTable>>,
}

#[derive(Clone, Debug)]
pub struct RouteRule {
    pub action: RouteDecision,
    pub networks: Vec<RouteNetwork>,
    pub domains: Vec<DomainMatcher>,
    pub ip_cidrs: Vec<IpCidr>,
    pub geoip_sets: Vec<String>,
    pub geosite_sets: Vec<String>,
    pub ip_is_private: bool,
    pub ports: Vec<PortRange>,
}

#[derive(Clone, Debug)]
pub enum DomainMatcher {
    Exact(String),
    Suffix(String),
    Keyword(String),
    Dotless(String),
    Regex(Regex),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default: RouteDecision::Direct,
            geoip_sets: BTreeMap::new(),
            geosite_sets: BTreeMap::new(),
        }
    }
}

impl RouteTable {
    pub fn decide(&self, target: &ProxyTarget, network: RouteNetwork) -> RouteDecision {
        self.try_decide(target, network)
            .expect("route table decision failed")
    }

    pub fn try_decide(&self, target: &ProxyTarget, network: RouteNetwork) -> Result<RouteDecision> {
        self.rules
            .iter()
            .find_map(|rule| match rule.try_matches(self, target, network) {
                Ok(true) => Some(Ok(rule.action.clone())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .unwrap_or_else(|| Ok(self.default.clone()))
    }

    pub fn add_geoip_set(&mut self, name: impl AsRef<str>, cidrs: Vec<IpCidr>) {
        self.geoip_sets.insert(route_set_name(name.as_ref()), cidrs);
    }

    pub fn add_geosite_set(&mut self, name: impl AsRef<str>, domains: Vec<DomainMatcher>) {
        self.geosite_sets
            .insert(route_set_name(name.as_ref()), domains);
    }

    pub fn add_geoip_lines<I, S>(&mut self, name: impl AsRef<str>, lines: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut cidrs = Vec::new();
        for line in lines {
            if let Some(line) = route_set_line(line.as_ref()) {
                cidrs.push(IpCidr::parse(line)?);
            }
        }
        self.add_geoip_set(name, cidrs);
        Ok(())
    }

    pub fn add_geosite_lines<I, S>(&mut self, name: impl AsRef<str>, lines: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut domains = Vec::new();
        for line in lines {
            if let Some(line) = route_set_line(line.as_ref()) {
                if let Some(matcher) = DomainMatcher::from_prefixed(line)? {
                    domains.push(matcher);
                }
            }
        }
        self.add_geosite_set(name, domains);
        Ok(())
    }

    pub fn load_geoip_set_file(
        &mut self,
        name: impl AsRef<str>,
        path: impl AsRef<Path>,
    ) -> Result<()> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read geoip route set {}", path.as_ref().display()))?;
        self.add_geoip_lines(name, text.lines())
    }

    pub fn load_geosite_set_file(
        &mut self,
        name: impl AsRef<str>,
        path: impl AsRef<Path>,
    ) -> Result<()> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read geosite route set {}", path.as_ref().display()))?;
        self.add_geosite_lines(name, text.lines())
    }
}

impl SharedRouteTable {
    pub fn new(routes: RouteTable) -> Self {
        Self {
            inner: Arc::new(RwLock::new(routes)),
        }
    }

    pub fn replace(&self, routes: RouteTable) {
        *self.inner.write().expect("route table lock poisoned") = routes;
    }

    pub fn snapshot(&self) -> RouteTable {
        self.inner
            .read()
            .expect("route table lock poisoned")
            .clone()
    }

    pub fn decide(&self, target: &ProxyTarget, network: RouteNetwork) -> RouteDecision {
        self.try_decide(target, network)
            .expect("route table decision failed")
    }

    pub fn try_decide(&self, target: &ProxyTarget, network: RouteNetwork) -> Result<RouteDecision> {
        self.inner
            .read()
            .expect("route table lock poisoned")
            .try_decide(target, network)
    }
}

impl RouteRule {
    pub fn new(action: RouteDecision) -> Self {
        Self {
            action,
            networks: Vec::new(),
            domains: Vec::new(),
            ip_cidrs: Vec::new(),
            geoip_sets: Vec::new(),
            geosite_sets: Vec::new(),
            ip_is_private: false,
            ports: Vec::new(),
        }
    }

    pub fn matches(&self, target: &ProxyTarget, network: RouteNetwork) -> bool {
        self.try_matches(&RouteTable::default(), target, network)
            .expect("route rule match failed")
    }

    fn try_matches(
        &self,
        table: &RouteTable,
        target: &ProxyTarget,
        network: RouteNetwork,
    ) -> Result<bool> {
        if !self.networks.is_empty() && !self.networks.contains(&network) {
            return Ok(false);
        }

        if !self.ports.is_empty()
            && !self
                .ports
                .iter()
                .any(|range| range.contains(target_port(target)))
        {
            return Ok(false);
        }

        if !self.domains.is_empty() || !self.geosite_sets.is_empty() {
            let ProxyTarget::Domain(host, _) = target else {
                return Ok(false);
            };
            let host = normalize_domain(host);
            let mut matched = self.domains.iter().any(|matcher| matcher.matches(&host));
            for name in &self.geosite_sets {
                let domains = table
                    .geosite_sets
                    .get(name)
                    .with_context(|| format!("route geosite set {name} is missing"))?;
                matched |= domains.iter().any(|matcher| matcher.matches(&host));
            }
            if !matched {
                return Ok(false);
            }
        }

        if self.ip_is_private || !self.ip_cidrs.is_empty() || !self.geoip_sets.is_empty() {
            let ProxyTarget::Ip(addr) = target else {
                return Ok(false);
            };
            let ip = addr.ip();
            if self.ip_is_private && !is_private_ip(ip) {
                return Ok(false);
            }
            if !self.ip_cidrs.is_empty() && !self.ip_cidrs.iter().any(|cidr| cidr.contains(ip)) {
                return Ok(false);
            }
            if !self.geoip_sets.is_empty() {
                let mut matched = false;
                for name in &self.geoip_sets {
                    let cidrs = table
                        .geoip_sets
                        .get(name)
                        .with_context(|| format!("route geoip set {name} is missing"))?;
                    matched |= cidrs.iter().any(|cidr| cidr.contains(ip));
                }
                if !matched {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    pub fn add_geoip_set(&mut self, name: impl AsRef<str>) {
        self.geoip_sets.push(route_set_name(name.as_ref()));
    }

    pub fn add_geosite_set(&mut self, name: impl AsRef<str>) {
        self.geosite_sets.push(route_set_name(name.as_ref()));
    }
}

impl RouteDecision {
    pub fn from_outbound(value: &str) -> Result<Self> {
        let value = value.trim();
        ensure!(!value.is_empty(), "route outbound is empty");
        if value.eq_ignore_ascii_case("direct") {
            return Ok(Self::Direct);
        }
        if matches_ignore_ascii_case(value, &["reject", "block"]) {
            return Ok(Self::Block);
        }
        Ok(Self::Proxy(value.to_string()))
    }
}

impl RouteNetwork {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "dns" => Ok(Self::Dns),
            other => bail!("unsupported route network {other}"),
        }
    }
}

impl DomainMatcher {
    pub fn exact(domain: &str) -> Self {
        Self::Exact(normalize_domain(domain))
    }

    pub fn suffix(domain: &str) -> Self {
        Self::Suffix(normalize_domain(domain))
    }

    pub fn keyword(keyword: &str) -> Self {
        Self::Keyword(keyword.trim().to_ascii_lowercase())
    }

    pub fn dotless(keyword: &str) -> Self {
        Self::Dotless(keyword.trim().to_ascii_lowercase())
    }

    pub fn regex(pattern: &str) -> Result<Self> {
        Ok(Self::Regex(Regex::new(pattern)?))
    }

    pub fn wildcard(pattern: &str) -> Result<Self> {
        let pattern = normalize_domain(pattern);
        ensure!(!pattern.is_empty(), "empty route domain wildcard");
        let mut regex = String::from("^");
        for ch in pattern.chars() {
            match ch {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                _ => regex.push_str(&regex::escape(&ch.to_string())),
            }
        }
        regex.push('$');
        Self::regex(&regex)
    }

    pub fn clash_wildcard(pattern: &str) -> Result<Self> {
        let pattern = normalize_domain(pattern);
        ensure!(!pattern.is_empty(), "empty clash domain wildcard");
        if let Some(domain) = pattern.strip_prefix("+.") {
            ensure!(!domain.is_empty(), "empty clash + domain wildcard");
            return Ok(Self::suffix(domain));
        }
        if let Some(domain) = pattern.strip_prefix('.') {
            ensure!(!domain.is_empty(), "empty clash . domain wildcard");
            return Self::regex(&format!(r"^.+\.{}$", regex::escape(domain)));
        }
        if pattern.contains('*') {
            let mut regex = String::from("^");
            for ch in pattern.chars() {
                match ch {
                    '*' => regex.push_str("[^.]+"),
                    _ => regex.push_str(&regex::escape(&ch.to_string())),
                }
            }
            regex.push('$');
            return Self::regex(&regex);
        }
        Ok(Self::exact(&pattern))
    }

    pub fn from_prefixed(value: &str) -> Result<Option<Self>> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        if let Some(pattern) = value
            .strip_prefix("regexp:")
            .or_else(|| value.strip_prefix("regex:"))
        {
            return Self::regex(pattern).map(Some);
        }
        if let Some(domain) = value
            .strip_prefix("full:")
            .or_else(|| value.strip_prefix("domain_full:"))
        {
            return Ok(Some(Self::exact(domain)));
        }
        if let Some(domain) = value
            .strip_prefix("domain:")
            .or_else(|| value.strip_prefix("suffix:"))
        {
            return Ok(Some(Self::suffix(domain)));
        }
        if let Some(keyword) = value.strip_prefix("keyword:") {
            return Ok(Some(Self::keyword(keyword)));
        }
        if let Some(keyword) = value.strip_prefix("dotless:") {
            return Ok(Some(Self::dotless(keyword)));
        }
        if let Some(domain) = value.strip_prefix("*.") {
            return Ok(Some(Self::suffix(domain)));
        }
        if Self::geosite_name(value).is_some() {
            bail!("geosite route rules require rule-set data");
        }
        if value
            .get(..4)
            .map(|prefix| prefix.eq_ignore_ascii_case("ext:"))
            .unwrap_or(false)
        {
            bail!("external domain route rules require rule-set data");
        }
        Ok(Some(Self::exact(value)))
    }

    pub fn xray(value: &str) -> Result<Option<Self>> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        if let Some(name) = Self::geosite_name(value) {
            bail!("xray geosite {name} must be represented as a route set");
        }
        if let Some(matcher) = Self::from_prefixed(value)? {
            let prefixed = matches!(
                value.split_once(':').map(|(prefix, _)| prefix.to_ascii_lowercase()),
                Some(prefix)
                    if matches!(
                        prefix.as_str(),
                        "regexp"
                            | "regex"
                            | "full"
                            | "domain_full"
                            | "domain"
                            | "suffix"
                            | "keyword"
                            | "dotless"
                    )
            );
            if prefixed || value.strip_prefix("*.").is_some() {
                return Ok(Some(matcher));
            }
        }
        Ok(Some(Self::keyword(value)))
    }

    pub fn geosite_name(value: &str) -> Option<String> {
        let value = value.trim();
        value
            .get(..8)
            .filter(|prefix| prefix.eq_ignore_ascii_case("geosite:"))
            .map(|_| route_set_name(&value[8..]))
    }

    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Exact(expected) => domain == expected,
            Self::Suffix(suffix) => domain == suffix || domain.ends_with(&format!(".{suffix}")),
            Self::Keyword(keyword) => domain.contains(keyword),
            Self::Dotless(keyword) => !domain.contains('.') && domain.contains(keyword),
            Self::Regex(regex) => regex.is_match(domain),
        }
    }
}

impl IpCidr {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        ensure!(!value.is_empty(), "empty route CIDR");
        if value.eq_ignore_ascii_case("geoip:private") {
            bail!("geoip:private must be represented as ip_is_private");
        }
        if Self::geoip_name(value).is_some() {
            bail!("geoip route rules require geoip data");
        }
        let (network, prefix) = match value.split_once('/') {
            Some((network, prefix)) => (network.parse::<IpAddr>()?, prefix.parse::<u8>()?),
            None => {
                let network = value.parse::<IpAddr>()?;
                let prefix = match network {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                (network, prefix)
            }
        };
        match network {
            IpAddr::V4(_) => ensure!(prefix <= 32, "invalid IPv4 prefix length {prefix}"),
            IpAddr::V6(_) => ensure!(prefix <= 128, "invalid IPv6 prefix length {prefix}"),
        }
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = prefix_to_mask_v4(self.prefix);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = prefix_to_mask_v6(self.prefix);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    pub fn geoip_name(value: &str) -> Option<String> {
        let value = value.trim();
        value
            .get(..6)
            .filter(|prefix| prefix.eq_ignore_ascii_case("geoip:"))
            .map(|_| route_set_name(&value[6..]))
    }
}

impl PortRange {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        ensure!(!value.is_empty(), "empty route port range");
        if let Ok(port) = value.parse::<u16>() {
            return Ok(Self {
                start: port,
                end: port,
            });
        }
        let (start, end) = value
            .split_once(':')
            .or_else(|| value.split_once('-'))
            .ok_or_else(|| anyhow::anyhow!("invalid route port range {value}"))?;
        let start = start.parse::<u16>()?;
        let end = end.parse::<u16>()?;
        ensure!(start <= end, "invalid route port range {value}");
        Ok(Self { start, end })
    }

    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

pub fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn route_set_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn route_set_line(line: &str) -> Option<&str> {
    let line = line.split('#').next().unwrap_or_default().trim();
    (!line.is_empty()).then_some(line)
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local(),
    }
}

fn target_port(target: &ProxyTarget) -> u16 {
    match target {
        ProxyTarget::Ip(addr) => addr.port(),
        ProxyTarget::Domain(_, port) => *port,
    }
}

fn prefix_to_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_to_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn matches_ignore_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn routes_by_domain_suffix_and_keyword() {
        let mut suffix = RouteRule::new(RouteDecision::Direct);
        suffix.domains.push(DomainMatcher::suffix("example.com"));
        let mut keyword = RouteRule::new(RouteDecision::Proxy("proxy".to_string()));
        keyword.domains.push(DomainMatcher::keyword("video"));
        let table = RouteTable {
            rules: vec![suffix, keyword],
            default: RouteDecision::Block,
            ..RouteTable::default()
        };
        assert_eq!(
            table.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );
        assert_eq!(
            table.decide(
                &ProxyTarget::Domain("video.cdn.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy".to_string())
        );
        assert_eq!(
            table.decide(
                &ProxyTarget::Domain("other.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Block
        );
    }

    #[test]
    fn routes_by_cidr_private_ip_port_and_network() -> Result<()> {
        let mut rule = RouteRule::new(RouteDecision::Direct);
        rule.networks.push(RouteNetwork::Udp);
        rule.ip_cidrs.push(IpCidr::parse("10.0.0.0/8")?);
        rule.ports.push(PortRange::parse("53")?);
        let table = RouteTable {
            rules: vec![rule],
            default: RouteDecision::Proxy("proxy".to_string()),
            ..RouteTable::default()
        };
        assert_eq!(
            table.decide(
                &ProxyTarget::Ip("10.1.2.3:53".parse::<SocketAddr>()?),
                RouteNetwork::Udp
            ),
            RouteDecision::Direct
        );
        assert_eq!(
            table.decide(
                &ProxyTarget::Ip("10.1.2.3:53".parse::<SocketAddr>()?),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy".to_string())
        );
        Ok(())
    }

    #[test]
    fn prefixed_domain_matchers_follow_xray_style() -> Result<()> {
        let exact = DomainMatcher::from_prefixed("full:api.example.com")?.unwrap();
        let suffix = DomainMatcher::from_prefixed("domain:example.org")?.unwrap();
        let regex = DomainMatcher::from_prefixed(r"regexp:^cdn\d+\.example\.net$")?.unwrap();
        let dotless = DomainMatcher::from_prefixed("dotless:local")?.unwrap();
        assert!(exact.matches("api.example.com"));
        assert!(!exact.matches("www.api.example.com"));
        assert!(suffix.matches("static.example.org"));
        assert!(regex.matches("cdn12.example.net"));
        assert!(dotless.matches("my-local-host"));
        assert!(!dotless.matches("my-local-host.example.com"));
        Ok(())
    }

    #[test]
    fn xray_plain_domain_matchers_are_substrings() -> Result<()> {
        let plain = DomainMatcher::xray("cdn")?.unwrap();
        let full = DomainMatcher::xray("full:cdn.example.com")?.unwrap();
        assert!(plain.matches("video-cdn.example.com"));
        assert!(!plain.matches("video.example.com"));
        assert!(full.matches("cdn.example.com"));
        assert!(!full.matches("video-cdn.example.com"));
        Ok(())
    }

    #[test]
    fn wildcard_domain_matchers_follow_glob_style() -> Result<()> {
        let wildcard = DomainMatcher::wildcard("*.cdn?.example.com")?;
        assert!(wildcard.matches("img.cdn1.example.com"));
        assert!(wildcard.matches("static.cdn2.example.com"));
        assert!(!wildcard.matches("cdn1.example.com"));
        assert!(!wildcard.matches("img.cdn12.example.com"));
        Ok(())
    }

    #[test]
    fn clash_domain_wildcards_follow_mihomo_style() -> Result<()> {
        let plus = DomainMatcher::clash_wildcard("+.baidu.com")?;
        assert!(plus.matches("baidu.com"));
        assert!(plus.matches("tieba.baidu.com"));
        assert!(plus.matches("123.tieba.baidu.com"));

        let dot = DomainMatcher::clash_wildcard(".baidu.com")?;
        assert!(!dot.matches("baidu.com"));
        assert!(dot.matches("tieba.baidu.com"));
        assert!(dot.matches("123.tieba.baidu.com"));

        let star = DomainMatcher::clash_wildcard("*.baidu.com")?;
        assert!(!star.matches("baidu.com"));
        assert!(star.matches("tieba.baidu.com"));
        assert!(!star.matches("123.tieba.baidu.com"));
        Ok(())
    }

    #[test]
    fn routes_by_geoip_and_geosite_sets() -> Result<()> {
        let mut domain_rule = RouteRule::new(RouteDecision::Proxy("site".to_string()));
        domain_rule.add_geosite_set("category-test");
        let mut ip_rule = RouteRule::new(RouteDecision::Proxy("ip".to_string()));
        ip_rule.add_geoip_set("test");
        let mut table = RouteTable {
            rules: vec![domain_rule, ip_rule],
            default: RouteDecision::Direct,
            ..RouteTable::default()
        };
        table.add_geosite_set("category-test", vec![DomainMatcher::suffix("example.com")]);
        table.add_geoip_set("test", vec![IpCidr::parse("203.0.113.0/24")?]);

        assert_eq!(
            table.try_decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            )?,
            RouteDecision::Proxy("site".to_string())
        );
        assert_eq!(
            table.try_decide(
                &ProxyTarget::Ip("203.0.113.10:443".parse::<SocketAddr>()?),
                RouteNetwork::Tcp
            )?,
            RouteDecision::Proxy("ip".to_string())
        );
        Ok(())
    }

    #[test]
    fn loads_geo_sets_from_text_lines() -> Result<()> {
        let mut table = RouteTable::default();
        table.add_geosite_lines(
            "ads",
            [
                "# comment",
                "domain:example.com",
                "full:api.example.net # inline comment",
                "keyword:tracker",
            ],
        )?;
        table.add_geoip_lines("lab", ["203.0.113.0/24", "", "2001:db8::/32"])?;

        assert!(
            table
                .geosite_sets
                .get("ads")
                .expect("geosite set")
                .iter()
                .any(|matcher| matcher.matches("cdn.example.com"))
        );
        let ipv6_sample = "2001:db8::1".parse()?;
        assert!(
            table
                .geoip_sets
                .get("lab")
                .expect("geoip set")
                .iter()
                .any(|cidr| cidr.contains(ipv6_sample))
        );
        Ok(())
    }

    #[test]
    fn missing_geo_set_is_explicit_error() {
        let mut rule = RouteRule::new(RouteDecision::Direct);
        rule.add_geosite_set("missing");
        let table = RouteTable {
            rules: vec![rule],
            default: RouteDecision::Block,
            ..RouteTable::default()
        };
        let error = table
            .try_decide(
                &ProxyTarget::Domain("example.com".to_string(), 443),
                RouteNetwork::Tcp,
            )
            .expect_err("missing geosite set must fail explicitly");
        assert!(error.to_string().contains("geosite set missing"));
    }

    #[test]
    fn shared_route_table_reflects_replacement() {
        let target = ProxyTarget::Domain("example.com".to_string(), 443);
        let shared = SharedRouteTable::new(RouteTable {
            rules: Vec::new(),
            default: RouteDecision::Direct,
            ..RouteTable::default()
        });
        assert_eq!(
            shared.decide(&target, RouteNetwork::Tcp),
            RouteDecision::Direct
        );

        shared.replace(RouteTable {
            rules: Vec::new(),
            default: RouteDecision::Block,
            ..RouteTable::default()
        });
        assert_eq!(
            shared.decide(&target, RouteNetwork::Tcp),
            RouteDecision::Block
        );
    }
}
