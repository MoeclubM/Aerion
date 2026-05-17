use crate::protocol::ProxyTarget;
use anyhow::{Result, bail, ensure};
use regex::Regex;
use std::net::IpAddr;

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
}

#[derive(Clone, Debug)]
pub struct RouteRule {
    pub action: RouteDecision,
    pub networks: Vec<RouteNetwork>,
    pub domains: Vec<DomainMatcher>,
    pub ip_cidrs: Vec<IpCidr>,
    pub ip_is_private: bool,
    pub ports: Vec<PortRange>,
}

#[derive(Clone, Debug)]
pub enum DomainMatcher {
    Exact(String),
    Suffix(String),
    Keyword(String),
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
        }
    }
}

impl RouteTable {
    pub fn decide(&self, target: &ProxyTarget, network: RouteNetwork) -> RouteDecision {
        self.rules
            .iter()
            .find(|rule| rule.matches(target, network))
            .map(|rule| rule.action.clone())
            .unwrap_or_else(|| self.default.clone())
    }
}

impl RouteRule {
    pub fn new(action: RouteDecision) -> Self {
        Self {
            action,
            networks: Vec::new(),
            domains: Vec::new(),
            ip_cidrs: Vec::new(),
            ip_is_private: false,
            ports: Vec::new(),
        }
    }

    pub fn matches(&self, target: &ProxyTarget, network: RouteNetwork) -> bool {
        if !self.networks.is_empty() && !self.networks.contains(&network) {
            return false;
        }

        if !self.ports.is_empty()
            && !self
                .ports
                .iter()
                .any(|range| range.contains(target_port(target)))
        {
            return false;
        }

        if !self.domains.is_empty() {
            let ProxyTarget::Domain(host, _) = target else {
                return false;
            };
            let host = normalize_domain(host);
            if !self.domains.iter().any(|matcher| matcher.matches(&host)) {
                return false;
            }
        }

        if self.ip_is_private || !self.ip_cidrs.is_empty() {
            let ProxyTarget::Ip(addr) = target else {
                return false;
            };
            let ip = addr.ip();
            if self.ip_is_private && !is_private_ip(ip) {
                return false;
            }
            if !self.ip_cidrs.is_empty() && !self.ip_cidrs.iter().any(|cidr| cidr.contains(ip)) {
                return false;
            }
        }

        true
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

    pub fn regex(pattern: &str) -> Result<Self> {
        Ok(Self::Regex(Regex::new(pattern)?))
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
        if let Some(domain) = value.strip_prefix("*.") {
            return Ok(Some(Self::suffix(domain)));
        }
        if value.starts_with("geosite:") {
            bail!("geosite route rules require rule-set data");
        }
        Ok(Some(Self::exact(value)))
    }

    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Exact(expected) => domain == expected,
            Self::Suffix(suffix) => domain == suffix || domain.ends_with(&format!(".{suffix}")),
            Self::Keyword(keyword) => domain.contains(keyword),
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
        if value.to_ascii_lowercase().starts_with("geoip:") {
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
        assert!(exact.matches("api.example.com"));
        assert!(!exact.matches("www.api.example.com"));
        assert!(suffix.matches("static.example.org"));
        assert!(regex.matches("cdn12.example.net"));
        Ok(())
    }
}
