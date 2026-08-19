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
