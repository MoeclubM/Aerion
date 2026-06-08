//! Tests for the mihomo configuration-compatibility module.

use anyhow::bail;
use std::fs;

use super::*;
use crate::protocol::ProxyTarget;

#[test]
fn parses_unsupported_proxy_entries_without_breaking_selected_proxy() -> Result<()> {
    let yaml = r#"
proxies:
  - name: direct-out
    type: direct
    udp: true
  - name: wireguard-out
    type: wireguard
    ip: 172.16.0.2
    ipv6: "fd00::2"
    private-key: ignored-by-aerion
    peers:
      - server: wg.example.com
        port: 51820
        public-key: ignored
  - name: naive-h3
    type: naive+quic
    server: naive.example.com
    username: user
    password: pass
    quic: true
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    assert_eq!(
        config.proxy("direct-out").context("direct proxy")?.name(),
        "direct-out"
    );
    let MihomoClientConfig::Route(direct) = config
        .proxy("direct-out")
        .context("direct proxy")?
        .to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected route client")
    };
    assert_eq!(direct.default, RouteDecision::Direct);
    let error = config
        .proxy("wireguard-out")
        .context("wireguard proxy")?
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unsupported proxy must fail explicitly when selected");
    assert!(error.to_string().contains("unsupported mihomo proxy"));

    let MihomoClientConfig::Naive(naive) = config
        .proxy("naive-h3")
        .context("naive proxy")?
        .to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Naive")
    };
    assert!(naive.quic);
    Ok(())
}

#[test]
fn resolves_select_proxy_group_to_first_proxy() -> Result<()> {
    let yaml = r#"
proxy-groups:
  - name: auto
    type: select
    proxies:
      - http-a
      - DIRECT
proxies:
  - name: http-a
    type: http
    server: proxy.example.com
    port: 8080
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    assert_eq!(config.profile_names(), vec!["http-a", "auto"]);
    let MihomoClientConfig::HttpProxy(http) =
        config.resolved_proxy_config("auto", "127.0.0.1:1080".parse()?)?
    else {
        bail!("expected selected HTTP proxy")
    };
    assert_eq!(http.server_host, "proxy.example.com");
    assert_eq!(http.server_port, 8080);
    Ok(())
}

#[test]
fn resolves_select_proxy_group_to_builtin_route() -> Result<()> {
    let yaml = r#"
proxy-groups:
  - name: direct-group
    type: select
    proxies:
      - DIRECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Route(route) =
        config.resolved_proxy_config("direct-group", "127.0.0.1:1080".parse()?)?
    else {
        bail!("expected direct route client")
    };
    assert_eq!(route.default, RouteDecision::Direct);
    Ok(())
}

#[test]
fn rejects_mihomo_proxy_group_cycles() -> Result<()> {
    let yaml = r#"
proxy-groups:
  - name: a
    type: select
    proxies: [b]
  - name: b
    type: select
    proxies: [a]
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let error = config
        .resolved_proxy_config("a", "127.0.0.1:1080".parse()?)
        .expect_err("proxy-group cycles must fail");
    assert!(error.to_string().contains("cycle"));
    Ok(())
}

#[test]
fn resolves_single_mihomo_policy_group_to_target() -> Result<()> {
    let yaml = r#"
proxy-groups:
  - name: auto
    type: url-test
    proxies: [DIRECT]
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Route(route) =
        config.resolved_proxy_config("auto", "127.0.0.1:1080".parse()?)?
    else {
        bail!("expected static url-test direct route client")
    };
    assert_eq!(route.default, RouteDecision::Direct);
    Ok(())
}

#[test]
fn rejects_mihomo_policy_proxy_groups_without_static_equivalence() -> Result<()> {
    let yaml = r#"
proxy-groups:
  - name: auto
    type: url-test
    proxies: [DIRECT, REJECT]
    url: https://www.gstatic.com/generate_204
    interval: 300
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let error = config
        .resolved_proxy_config("auto", "127.0.0.1:1080".parse()?)
        .expect_err("url-test requires active selection");
    assert!(error.to_string().contains("single-proxy"));
    Ok(())
}

#[test]
fn compiles_mihomo_route_rules() -> Result<()> {
    let yaml = r#"
proxies: []
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - DOMAIN-KEYWORD,video,proxy-a
  - DOMAIN-WILDCARD,*.cdn?.example.org,proxy-c
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - DST-PORT,53,DIRECT
  - MATCH,proxy-b
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let routes = config.route_table()?;
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("api.example.com".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Direct
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("video.test".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("img.cdn1.example.org".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-c".to_string())
    );
    assert_eq!(
        routes.decide(&ProxyTarget::Ip("10.1.2.3:443".parse()?), RouteNetwork::Tcp),
        RouteDecision::Direct
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("unmatched.test".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-b".to_string())
    );
    Ok(())
}

#[test]
fn compiles_mihomo_logical_route_rules() -> Result<()> {
    let yaml = r#"
proxies: []
rules:
  - OR,((DOMAIN-SUFFIX,video.example),(DOMAIN-KEYWORD,stream)),proxy-a
  - AND,((DOMAIN-SUFFIX,api.example),(NETWORK,tcp)),proxy-b
  - AND,((OR,((DOMAIN-SUFFIX,cdn.example),(DOMAIN-SUFFIX,asset.example))),(DST-PORT,443)),proxy-c
  - MATCH,DIRECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let routes = config.route_table()?;
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("img.video.example".to_string(), 80),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("live.stream.test".to_string(), 80),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("www.api.example".to_string(), 80),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-b".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("www.api.example".to_string(), 80),
            RouteNetwork::Udp
        ),
        RouteDecision::Direct
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("edge.asset.example".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-c".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("edge.asset.example".to_string(), 80),
            RouteNetwork::Tcp
        ),
        RouteDecision::Direct
    );
    Ok(())
}

#[test]
fn rejects_mihomo_logical_not_and_unrepresentable_and_rules() -> Result<()> {
    let not_yaml = r#"
proxies: []
rules:
  - NOT,((DOMAIN-SUFFIX,example.com)),DIRECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(not_yaml)?;
    let error = config
        .route_table()
        .expect_err("NOT needs negative matching");
    assert!(error.to_string().contains("negative route matching"));

    let and_yaml = r#"
proxies: []
rules:
  - AND,((DOMAIN-SUFFIX,example.com),(DOMAIN-KEYWORD,video)),DIRECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(and_yaml)?;
    let error = config
        .route_table()
        .expect_err("AND of multiple domain matchers must fail explicitly");
    assert!(error.to_string().contains("multiple domain matchers"));

    let src_yaml = r#"
proxies: []
rules:
  - IP-CIDR,10.0.0.0/8,DIRECT,src
"#;
    let config: MihomoConfig = serde_yaml::from_str(src_yaml)?;
    let error = config
        .route_table()
        .expect_err("src route parameter requires source metadata");
    assert!(error.to_string().contains("source IP metadata"));

    let geo_yaml = r#"
proxies: []
rules:
  - GEOSITE,category-ads-all,REJECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(geo_yaml)?;
    let error = config
        .route_table()
        .expect_err("GEOSITE requires geosite route-set data");
    assert!(error.to_string().contains("geosite set category-ads-all"));

    let geoip_yaml = r#"
proxies: []
rules:
  - GEOIP,CN,DIRECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(geoip_yaml)?;
    let error = config
        .route_table()
        .expect_err("GEOIP requires geoip route-set data");
    assert!(error.to_string().contains("geoip set cn"));
    Ok(())
}

#[test]
fn compiles_mihomo_inline_rule_providers() -> Result<()> {
    let yaml = r#"
rule-providers:
  ads:
    type: inline
    behavior: domain
    payload:
      - .example.com
      - +.cdn.test
      - '*.media.example.net'
  lan:
    type: inline
    behavior: ipcidr
    payload:
      - 10.0.0.0/8
  mixed:
    type: inline
    behavior: classical
    payload:
      - DOMAIN-KEYWORD,video
      - DST-PORT,53
      - OR,((DOMAIN-SUFFIX,or-a.test),(DOMAIN-SUFFIX,or-b.test))
      - AND,((DOMAIN-SUFFIX,and.test),(DST-PORT,8443))
rules:
  - RULE-SET,ads,REJECT
  - RULE-SET,lan,DIRECT
  - RULE-SET,mixed,proxy-a
  - MATCH,proxy-b
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let routes = config.route_table()?;
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("api.example.com".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Block
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("cdn.test".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Block
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("sub.media.example.net".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Block
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("deep.sub.media.example.net".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-b".to_string())
    );
    assert_eq!(
        routes.decide(&ProxyTarget::Ip("10.1.2.3:443".parse()?), RouteNetwork::Tcp),
        RouteDecision::Direct
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("video.example.net".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("dns.example.net".to_string(), 53),
            RouteNetwork::Udp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("cdn.or-b.test".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("api.and.test".to_string(), 8443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("api.and.test".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-b".to_string())
    );
    Ok(())
}

#[test]
fn compiles_mihomo_file_rule_providers_relative_to_config() -> Result<()> {
    let dir = tempfile::tempdir()?;
    fs::write(
        dir.path().join("ads.yaml"),
        r#"
payload:
  - +.example.com
"#,
    )?;
    let yaml = r#"
rule-providers:
  ads:
    type: file
    behavior: domain
    path: ads.yaml
rules:
  - RULE-SET,ads,REJECT
  - MATCH,DIRECT
"#;
    let mut config: MihomoConfig = serde_yaml::from_str(yaml)?;
    config.source_dir = Some(dir.path().to_path_buf());
    let routes = config.route_table()?;
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("api.example.com".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Block
    );
    Ok(())
}

#[test]
fn rejects_mihomo_unsupported_rule_provider_fields() -> Result<()> {
    let yaml = r#"
rule-providers:
  ads:
    type: inline
    behavior: domain
    interval: 3600
    payload:
      - +.example.com
rules:
  - RULE-SET,ads,REJECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let error = config
        .route_table()
        .expect_err("unsupported rule-provider fields must not be ignored");
    assert!(error.to_string().contains("rule-provider ads"));
    assert!(error.to_string().contains("interval"));
    Ok(())
}

#[test]
fn rejects_mihomo_misplaced_rule_provider_fields() -> Result<()> {
    let yaml = r#"
rule-providers:
  ads:
    type: inline
    behavior: domain
    path: ads.yaml
    payload:
      - +.example.com
rules:
  - RULE-SET,ads,REJECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let inline_error = config
        .route_table()
        .expect_err("inline rule-provider path must not be ignored");
    assert!(
        inline_error
            .to_string()
            .contains("inline rule-provider ads")
    );
    assert!(inline_error.to_string().contains("path"));

    let yaml = r#"
rule-providers:
  ads:
    type: file
    behavior: domain
    path: ads.yaml
    url: https://rules.example.test/ads.yaml
rules:
  - RULE-SET,ads,REJECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let file_error = config
        .route_table()
        .expect_err("file rule-provider url must not be ignored");
    assert!(file_error.to_string().contains("file rule-provider ads"));
    assert!(file_error.to_string().contains("url"));
    Ok(())
}

#[test]
fn rejects_mihomo_unsupported_rule_provider_file_fields() -> Result<()> {
    let dir = tempfile::tempdir()?;
    fs::write(
        dir.path().join("ads.yaml"),
        r#"
payload:
  - +.example.com
metadata:
  source: generated
"#,
    )?;
    let yaml = r#"
rule-providers:
  ads:
    type: file
    behavior: domain
    path: ads.yaml
rules:
  - RULE-SET,ads,REJECT
"#;
    let mut config: MihomoConfig = serde_yaml::from_str(yaml)?;
    config.source_dir = Some(dir.path().to_path_buf());
    let error = config
        .route_table()
        .expect_err("unsupported rule-provider file fields must not be ignored");
    assert!(error.to_string().contains("YAML file"));
    assert!(error.to_string().contains("metadata"));
    Ok(())
}

#[test]
fn rejects_mihomo_http_rule_provider_without_remote_loader() -> Result<()> {
    let yaml = r#"
rule-providers:
  remote:
    type: http
    behavior: domain
    url: https://rules.example.test/ads.yaml
    path: ./ads.yaml
rules:
  - RULE-SET,remote,REJECT
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let error = config
        .route_table()
        .expect_err("http rule-provider must fail explicitly");
    assert!(error.to_string().contains("requires downloading"));
    Ok(())
}

#[test]
fn compiles_mihomo_tun_config() -> Result<()> {
    let yaml = r#"
mixed-port: 7890
ipv6: true
dns:
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
tun:
  enable: true
  device: utun9
  auto-route: true
  mtu: 9000
  dns-hijack:
    - any:53
  route-exclude-address:
    - 10.0.0.0/8
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    assert!(config.tun_enabled());
    let tun = config
        .tun_config("127.0.0.1:7890".parse()?)?
        .context("tun config")?;
    assert_eq!(tun.proxy_url, "socks5://127.0.0.1:7890");
    assert_eq!(tun.tun_name.as_deref(), Some("utun9"));
    assert_eq!(tun.mtu, 9000);
    assert_eq!(tun.dns, TunDnsStrategy::Virtual);
    assert_eq!(tun.virtual_dns_pool, "198.18.0.0/15");
    assert_eq!(tun.bypass, vec!["10.0.0.0/8"]);
    assert!(tun.ipv6);
    Ok(())
}

#[test]
fn rejects_mihomo_unsupported_local_listener_options() -> Result<()> {
    let yaml = r#"
socks-port: 7890
authentication:
  - user:pass
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let auth_error = config
        .local_socks_listen()
        .expect_err("local listener authentication must not be ignored");
    assert!(auth_error.to_string().contains("authentication"));

    let yaml = r#"
port: 8080
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let port_error = config
        .local_socks_listen()
        .expect_err("HTTP-only port must not be exposed as SOCKS");
    assert!(port_error.to_string().contains("HTTP proxy listener"));

    let yaml = r#"
socks-port: 7890
redir-port: 7892
lan-allowed-ips:
  - 192.168.0.0/16
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let redir_error = config
        .local_socks_listen()
        .expect_err("transparent proxy listeners must not be ignored");
    assert!(redir_error.to_string().contains("redir-port"));
    Ok(())
}

#[test]
fn rejects_mihomo_unsupported_top_level_options() -> Result<()> {
    let yaml = r#"
log-level: debug
mixed-port: 7890
proxies:
  - name: direct-out
    type: direct
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let error = config
        .local_socks_listen()
        .expect_err("unsupported mihomo top-level options must not be ignored");
    assert!(error.to_string().contains("mihomo config"));
    assert!(error.to_string().contains("log-level"));
    Ok(())
}

#[test]
fn rejects_mihomo_unsupported_dns_and_tun_fields() -> Result<()> {
    let yaml = r#"
mixed-port: 7890
dns:
  enhanced-mode: fake-ip
  nameserver:
    - 1.1.1.1
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let dns_error = config
        .local_socks_listen()
        .expect_err("unsupported mihomo dns fields must not be ignored");
    assert!(dns_error.to_string().contains("mihomo dns"));
    assert!(dns_error.to_string().contains("nameserver"));

    let yaml = r#"
mixed-port: 7890
tun:
  enable: true
  stack: system
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let tun_error = config
        .tun_config("127.0.0.1:7890".parse()?)
        .expect_err("unsupported mihomo tun fields must not be ignored");
    assert!(tun_error.to_string().contains("mihomo tun"));
    assert!(tun_error.to_string().contains("stack"));
    Ok(())
}

#[test]
fn defers_known_proxy_parse_errors_until_selected() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vless-newer-fingerprint
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    client-fingerprint: 123
  - name: naive-h3
    type: naive
    server: naive.example.com
    username: user
    password: pass
    quic: true
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Naive(naive) = config
        .proxy("naive-h3")
        .context("naive proxy")?
        .to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Naive")
    };
    assert!(naive.quic);

    let error = config
        .proxy("vless-newer-fingerprint")
        .context("vless proxy")?
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("known proxy parse error must be deferred");
    assert!(error.to_string().contains("parse mihomo VLESS proxy"));
    Ok(())
}

#[test]
fn parses_shadowsocks_udp_over_tcp_profile() -> Result<()> {
    let yaml = r#"
proxies:
  - name: ss-uot
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp: true
    udp-over-tcp: true
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Shadowsocks(shadowsocks) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Shadowsocks")
    };
    assert!(shadowsocks.udp);
    assert!(shadowsocks.udp_over_tcp);
    Ok(())
}

#[test]
fn parses_anytls_client_fingerprint() -> Result<()> {
    let yaml = r#"
proxies:
  - name: anytls-chrome
    type: anytls
    server: anytls.example.com
    port: 443
    password: secret
    servername: edge.example.com
    client-fingerprint: chrome
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::AnyTls(anytls) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected AnyTLS")
    };
    assert_eq!(anytls.sni, "edge.example.com");
    assert_eq!(anytls.client_fingerprint, Some(UtlsFingerprint::Chrome));
    Ok(())
}

#[test]
fn rejects_unsupported_udp_over_tcp_version() -> Result<()> {
    let yaml = r#"
proxies:
  - name: ss-uot-v1
    type: ss
    server: example.com
    port: 8388
    cipher: aes-128-gcm
    password: secret
    udp-over-tcp:
      enabled: true
      version: 1
  - name: naive-uot-v1
    type: naive
    server: naive.example.com
    udp-over-tcp:
      enabled: true
      version: "1"
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let ss_error = config.proxies[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("Shadowsocks UOT v1 must be explicit");
    assert!(ss_error.to_string().contains("version 2"));
    let naive_error = config.proxies[1]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("Naive UOT v1 must be explicit");
    assert!(naive_error.to_string().contains("version 2"));
    Ok(())
}

#[test]
fn parses_vless_reality_profile() -> Result<()> {
    let yaml = r#"
mixed-port: 7890
proxies:
  - name: vless-reality
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.com
    client-fingerprint: chrome
    packet-encoding: xudp
    reality-opts:
      public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
      short-id: a1b2
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    assert_eq!(
        config.local_socks_listen()?,
        Some("127.0.0.1:7890".parse()?)
    );
    let proxy = config.proxy("vless-reality").context("proxy exists")?;
    let MihomoClientConfig::Vless(vless) = proxy.to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert_eq!(vless.server_host, "example.com");
    assert_eq!(vless.sni, "www.example.com");
    assert_eq!(vless.client_fingerprint, Some(UtlsFingerprint::Chrome));
    assert!(vless.reality.is_some());
    assert_eq!(vless.packet_encoding, "xudp");
    Ok(())
}

#[test]
fn parses_vless_raw_profile() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vless-raw
    type: vless
    server: example.com
    port: 80
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    tls: false
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Vless(vless) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert!(!vless.tls);
    assert!(vless.reality.is_none());
    assert_eq!(vless.server_port, 80);
    Ok(())
}

#[test]
fn rejects_non_equivalent_smux_mapping() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vless-smux
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    smux:
      enabled: true
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let error = config.proxies[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("smux must be explicit");
    assert!(error.to_string().contains("not wire-compatible"));
    Ok(())
}

#[test]
fn parses_vless_websocket_transport() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vless-ws
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: edge.example.com
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Vless(vless) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert_eq!(
        vless.transport.kind,
        crate::vless_transport::VlessTransportKind::WebSocket
    );
    assert_eq!(vless.transport.path, "/vless");
    assert_eq!(
        vless.transport.request_host("example.com"),
        "edge.example.com"
    );
    Ok(())
}

#[test]
fn parses_trojan_websocket_transport() -> Result<()> {
    let yaml = r#"
proxies:
  - name: trojan-ws
    type: trojan
    server: example.com
    port: 443
    password: secret
    network: ws
    ws-opts:
      path: /trojan
      headers:
        Host: edge.example.com
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Trojan(trojan) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Trojan")
    };
    assert_eq!(trojan.transport.kind, VlessTransportKind::WebSocket);
    assert_eq!(trojan.transport.path, "/trojan");
    assert_eq!(
        trojan.transport.request_host("example.com"),
        "edge.example.com"
    );
    Ok(())
}

#[test]
fn parses_vmess_websocket_transport() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vmess-ws
    type: vmess
    server: example.com
    port: 80
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    alterId: 0
    packet-encoding: packetaddr
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: edge.example.com
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Vmess(vmess) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VMess")
    };
    assert!(!vmess.tls);
    assert_eq!(
        vmess.transport.kind,
        crate::vless_transport::VlessTransportKind::WebSocket
    );
    assert_eq!(vmess.transport.path, "/vmess");
    assert_eq!(vmess.packet_encoding, "packetaddr");
    assert_eq!(
        vmess.transport.request_host("example.com"),
        "edge.example.com"
    );
    Ok(())
}

#[test]
fn parses_vmess_xudp_packet_encoding() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vmess-xudp
    type: vmess
    server: example.com
    port: 80
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    alterId: 0
    packet-encoding: xudp
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Vmess(vmess) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VMess")
    };
    assert_eq!(vmess.packet_encoding, "xudp");
    Ok(())
}

#[test]
fn parses_vless_grpc_transport() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vless-grpc
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: grpc
    alpn: h2
    grpc-opts:
      grpc-service-name: TunService
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Vless(vless) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert_eq!(vless.transport.kind, VlessTransportKind::Grpc);
    assert_eq!(vless.transport.path, "/TunService/Tun");
    Ok(())
}

#[test]
fn parses_vless_xhttp_transport() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vless-xhttp
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: xhttp
    alpn: http/1.1
    xhttp-opts:
      path: /xhttp
      host: edge.example.com
      mode: stream-one
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Vless(vless) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert_eq!(vless.transport.kind, VlessTransportKind::Xhttp);
    assert_eq!(vless.transport.path, "/xhttp");
    assert_eq!(
        vless.transport.request_host("example.com"),
        "edge.example.com"
    );
    assert_eq!(vless.transport.mode, "stream-one");
    Ok(())
}

#[test]
fn rejects_mihomo_unsupported_proxy_and_transport_fields() -> Result<()> {
    let yaml = r#"
proxies:
  - name: vless-dialer
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    dialer-proxy: bootstrap
  - name: vless-ws-early
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: ws
    ws-opts:
      path: /vless
      max-early-data: 2048
  - name: vless-unused-ws
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: tcp
    ws-opts:
      path: /ignored
  - name: vless-xhttp-extra
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    network: xhttp
    alpn: http/1.1
    xhttp-opts:
      path: /xhttp
      no-grpc-header: true
  - name: vless-reality-extra
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    tls: true
    reality-opts:
      public-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
      short-id: a1b2
      server-name: www.example.com
  - name: vless-smux-disabled-fields
    type: vless
    server: example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    smux:
      enabled: false
      protocol: h2mux
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let dialer_error = config.proxies[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unsupported proxy fields must not be ignored");
    assert!(dialer_error.to_string().contains("dialer-proxy"));

    let ws_error = config.proxies[1]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unsupported ws-opts fields must not be ignored");
    assert!(ws_error.to_string().contains("ws-opts"));
    assert!(ws_error.to_string().contains("max-early-data"));

    let unused_ws_error = config.proxies[2]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unused ws-opts must not be ignored");
    assert!(
        unused_ws_error
            .to_string()
            .contains("network is not WebSocket")
    );

    let xhttp_error = config.proxies[3]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unsupported xhttp-opts fields must not be ignored");
    assert!(xhttp_error.to_string().contains("xhttp-opts"));
    assert!(xhttp_error.to_string().contains("no-grpc-header"));

    let reality_error = config.proxies[4]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unsupported reality-opts fields must not be ignored");
    assert!(reality_error.to_string().contains("reality-opts"));
    assert!(reality_error.to_string().contains("server-name"));

    let smux_error = config.proxies[5]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("disabled smux fields must not be ignored");
    assert!(smux_error.to_string().contains("smux"));
    Ok(())
}

#[test]
fn parses_hysteria2_profile() -> Result<()> {
    let yaml = r#"
proxies:
  - name: hy2
    type: hysteria2
    server: example.com
    port: 443
    password: secret
    servername: hy2.example.com
    skip-cert-verify: true
    fingerprint: sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
    obfs: salamander
    obfs-password: obfs-pass
    up: 10 Mbps
    down: 80 Mbps
    congestion-control: reno
    udp: true
    alpn:
      - h3
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Hysteria2(hysteria2) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Hysteria2")
    };
    assert_eq!(hysteria2.server_host, "example.com");
    assert_eq!(hysteria2.server_port, 443);
    assert_eq!(hysteria2.password, "secret");
    assert_eq!(hysteria2.sni, "hy2.example.com");
    assert!(hysteria2.insecure);
    assert_eq!(
        hysteria2.certificate_fingerprint.as_deref(),
        Some("sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    );
    assert_eq!(hysteria2.obfs.as_deref(), Some("salamander"));
    assert_eq!(hysteria2.obfs_password.as_deref(), Some("obfs-pass"));
    assert_eq!(hysteria2.upload_bandwidth, Some(10));
    assert_eq!(hysteria2.download_bandwidth, Some(80));
    assert_eq!(hysteria2.congestion_control, "reno");
    Ok(())
}

#[test]
fn rejects_hysteria2_unsupported_fields() -> Result<()> {
    let yaml = r#"
proxies:
  - name: hy2-hop
    type: hysteria2
    server: example.com
    ports: 443,8443
    hop-interval: 30s
    password: secret
  - name: hy2-realm
    type: hysteria2
    server: example.com
    port: 443
    password: secret
    realm-opts:
      name: test
  - name: hy2-window
    type: hysteria2
    server: example.com
    port: 443
    password: secret
    max-stream-receive-window: 8388608
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let hop_error = config.proxies[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("port hopping must be explicit");
    assert!(hop_error.to_string().contains("port hopping"));
    let realm_error = config.proxies[1]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("realm opts must be explicit");
    assert!(realm_error.to_string().contains("realm-opts"));
    let window_error = config.proxies[2]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("receive window override must be explicit");
    assert!(window_error.to_string().contains("receive window"));
    Ok(())
}

#[test]
fn parses_naive_and_tuic_profiles() -> Result<()> {
    let yaml = r#"
proxies:
  - name: naive-h3
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    quic: true
    udp-over-tcp:
      enabled: true
      version: 2
    servername: front.example.com
    skip-cert-verify: true
    extra-headers:
      X-Test: value
  - name: tuic-v5
    type: tuic
    server: tuic.example.com
    ip: 203.0.113.10
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    udp: true
    udp-relay-mode: quic
    congestion-controller: bbr
    heartbeat-interval: 1500
    alpn:
      - h3
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Naive(naive) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Naive")
    };
    assert_eq!(naive.server_host, "naive.example.com");
    assert_eq!(naive.sni, "front.example.com");
    assert!(naive.insecure);
    assert!(naive.quic);
    assert!(naive.udp_over_tcp);
    assert_eq!(
        naive.extra_headers,
        vec![("X-Test".to_string(), "value".to_string())]
    );

    let MihomoClientConfig::Tuic(tuic) =
        config.proxies[1].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected TUIC")
    };
    assert_eq!(tuic.server_host, "203.0.113.10");
    assert_eq!(tuic.sni, "tuic.example.com");
    assert_eq!(tuic.udp_relay_mode, "quic");
    assert_eq!(tuic.congestion_control, "bbr");
    assert_eq!(tuic.alpn_protocols, vec!["h3".to_string()]);
    assert_eq!(tuic.heartbeat_interval_secs, 2);
    Ok(())
}

#[test]
fn rejects_tuic_unsupported_fields() -> Result<()> {
    let yaml = r#"
proxies:
  - name: tuic-reduce-rtt
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    reduce-rtt: true
  - name: tuic-disable-sni
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    disable-sni: true
  - name: tuic-open-streams
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    password: secret
    max-open-streams: 64
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let reduce_rtt_error = config.proxies[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("reduce-rtt must be explicit");
    assert!(reduce_rtt_error.to_string().contains("reduce-rtt"));
    let disable_sni_error = config.proxies[1]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("disable-sni must be explicit");
    assert!(disable_sni_error.to_string().contains("SNI"));
    let stream_error = config.proxies[2]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("max-open-streams must be explicit");
    assert!(stream_error.to_string().contains("max-open-streams"));
    Ok(())
}

#[test]
fn converts_http_proxy_to_client_config() -> Result<()> {
    let yaml = r#"
proxies:
  - name: http-proxy
    type: http
    server: proxy.example.com
    port: 8080
    username: user
    password: pass
    tls: true
    servername: front.example.com
    skip-cert-verify: true
    alpn:
      - http/1.1
    headers:
      X-Test: value
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::HttpProxy(http) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected HTTP proxy")
    };
    assert_eq!(http.server_host, "proxy.example.com");
    assert_eq!(http.server_port, 8080);
    assert_eq!(http.username, "user");
    assert_eq!(http.password, "pass");
    assert!(http.tls);
    assert_eq!(http.sni, "front.example.com");
    assert!(http.insecure);
    assert_eq!(
        http.extra_headers,
        vec![("X-Test".to_string(), "value".to_string())]
    );
    Ok(())
}

#[test]
fn converts_socks_proxy_to_client_config() -> Result<()> {
    let yaml = r#"
proxies:
  - name: socks-proxy
    type: socks5
    server: proxy.example.com
    port: 1080
    username: user
    password: pass
    udp: true
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::SocksProxy(socks) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected SOCKS proxy")
    };
    assert_eq!(socks.server_host, "proxy.example.com");
    assert_eq!(socks.server_port, 1080);
    assert_eq!(socks.username, "user");
    assert_eq!(socks.password, "pass");
    assert!(socks.udp);
    Ok(())
}

#[test]
fn converts_mihomo_builtin_route_proxies() -> Result<()> {
    let yaml = r#"
proxies:
  - name: direct-out
    type: direct
  - name: reject-out
    type: reject
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let MihomoClientConfig::Route(direct) =
        config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected direct route client")
    };
    assert_eq!(direct.default, RouteDecision::Direct);
    let MihomoClientConfig::Route(reject) =
        config.proxies[1].to_client_config("127.0.0.1:1081".parse()?)?
    else {
        bail!("expected reject route client")
    };
    assert_eq!(reject.default, RouteDecision::Block);
    Ok(())
}

#[test]
fn rejects_invalid_mieru_traffic_pattern_without_silent_degrade() -> Result<()> {
    let yaml = r#"
proxies:
  - name: mieru-shaped
    type: mieru
    server: mieru.example.com
    port: 2999
    username: user
    password: pass
    traffic-pattern: abc
"#;
    let config: MihomoConfig = serde_yaml::from_str(yaml)?;
    let error = config.proxies[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("Mieru shaping must not be silently ignored");
    assert!(error.to_string().contains("traffic pattern"));
    Ok(())
}
