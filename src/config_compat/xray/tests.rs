//! Tests for the xray configuration-compatibility module.

use super::*;
use crate::protocol::ProxyTarget;

#[test]
fn parses_vless_reality_outbound() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "settings": { "auth": "noauth" }
  }],
  "outbounds": [{
    "tag": "proxy",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{
          "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
          "encryption": "none",
          "flow": "xtls-rprx-vision",
          "packetEncoding": "xudp"
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "serverName": "www.example.com",
        "fingerprint": "chrome",
        "publicKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "shortId": "a1b2"
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    assert_eq!(
        config.local_socks_listen()?,
        Some("127.0.0.1:1080".parse()?)
    );
    let XrayClientConfig::Vless(vless) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert_eq!(vless.server_host, "example.com");
    assert_eq!(vless.sni, "www.example.com");
    assert_eq!(vless.client_fingerprint, Some(UtlsFingerprint::Chrome));
    assert!(vless.reality.is_some());
    Ok(())
}

#[test]
fn compiles_xray_tun_inbound() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "protocol": "tun",
    "tag": "tun-in",
    "settings": {
      "interfaceName": "utun9",
      "mtu": 9000,
      "autoRoute": true,
      "routeExcludeAddress": ["10.0.0.0/8"],
      "addresses": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
    }
  }],
  "outbounds": [{
    "tag": "direct",
    "protocol": "freedom"
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    assert!(config.tun_enabled());
    let tun = config
        .tun_config("127.0.0.1:7890".parse()?)?
        .context("tun config")?;
    assert_eq!(tun.proxy_url, "socks5://127.0.0.1:7890");
    assert_eq!(tun.tun_name.as_deref(), Some("utun9"));
    assert_eq!(tun.mtu, 9000);
    assert_eq!(tun.bypass, vec!["10.0.0.0/8"]);
    assert!(tun.setup);
    assert!(tun.ipv6);
    Ok(())
}

#[test]
fn rejects_xray_unsupported_local_socks_inbound_fields() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "settings": { "auth": "password" }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let auth_error = config
        .local_socks_listen()
        .expect_err("local SOCKS auth must not be ignored");
    assert!(auth_error.to_string().contains("settings.auth"));

    let json = r#"
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "streamSettings": {
      "network": "ws",
      "wsSettings": { "path": "/socks" }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let transport_error = config
        .local_socks_listen()
        .expect_err("local SOCKS transport must not be ignored");
    assert!(transport_error.to_string().contains("local SOCKS listener"));
    assert!(transport_error.to_string().contains("network ws"));

    let json = r#"
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "sniffing": { "enabled": true }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let sniff_error = config
        .local_socks_listen()
        .expect_err("local SOCKS sniffing must not be ignored");
    assert!(sniff_error.to_string().contains("sniffing"));

    let json = r#"
{
  "inbounds": [{
    "tag": "http-in",
    "protocol": "http",
    "listen": "127.0.0.1",
    "port": 8080
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let http_error = config
        .local_socks_listen()
        .expect_err("local HTTP inbound must not be ignored");
    assert!(http_error.to_string().contains("local SOCKS/TUN listener"));
    assert!(http_error.to_string().contains("http"));
    Ok(())
}

#[test]
fn compiles_xray_routing_rules() -> Result<()> {
    let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "outboundTag": "direct" },
      { "type": "field", "domain": ["keyword:video"], "outboundTag": "proxy-a" },
      { "type": "field", "domain": ["cdn"], "outboundTag": "proxy-c" },
      { "type": "field", "ip": ["10.0.0.0/8"], "port": "53", "network": "udp", "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
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
            &ProxyTarget::Domain("static-cdn.test".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-c".to_string())
    );
    assert_eq!(
        routes.decide(&ProxyTarget::Ip("10.1.2.3:53".parse()?), RouteNetwork::Udp),
        RouteDecision::Direct
    );
    Ok(())
}

#[test]
fn xray_route_default_uses_first_outbound() -> Result<()> {
    let json = r#"
{
  "outbounds": [
    { "tag": "proxy-a", "protocol": "socks" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
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
            &ProxyTarget::Domain("unmatched.test".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );

    let json = r#"
{
  "outbounds": [
    { "protocol": "socks" }
  ],
  "routing": {
    "rules": []
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("tagless default proxy outbound cannot be spawned");
    assert!(error.to_string().contains("requires a tag"));
    Ok(())
}

#[test]
fn handles_xray_routing_top_level_options_explicitly() -> Result<()> {
    let json = r#"
{
  "routing": {
    "domainMatcher": "hybrid",
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let routes = config.route_table()?;
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("api.example.com".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Direct
    );

    let json = r#"
{
  "routing": {
    "domainMatcher": "unknown",
    "rules": []
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("unknown domain matcher must not be ignored");
    assert!(error.to_string().contains("domainMatcher"));

    let json = r#"
{
  "routing": {
    "observatory": {},
    "rules": []
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("unknown routing fields must not be ignored");
    assert!(error.to_string().contains("unsupported fields"));
    Ok(())
}

#[test]
fn rejects_xray_unsupported_top_level_options() -> Result<()> {
    let json = r#"
{
  "log": { "loglevel": "debug" },
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("unsupported xray top-level options must not be ignored");
    assert!(error.to_string().contains("xray config"));
    assert!(error.to_string().contains("log"));
    Ok(())
}

#[test]
fn handles_xray_route_rule_tags_and_action_precedence() -> Result<()> {
    let json = r#"
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": ["domain:example.com"],
        "outboundTag": "direct",
        "balancerTag": "missing-balancer",
        "ruleTag": "debug-label"
      }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let routes = config.route_table()?;
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("api.example.com".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Direct
    );

    let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "ruleTag": 7, "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("non-string ruleTag must be rejected");
    assert!(error.to_string().contains("ruleTag"));
    Ok(())
}

#[test]
fn rejects_xray_geo_route_rules_without_data() -> Result<()> {
    let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("geosite needs explicit route-set data");
    assert!(error.to_string().contains("geosite rule-set data"));

    let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("geoip needs explicit route-set data");
    assert!(error.to_string().contains("geoip rule-set data"));

    let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "ip": ["ext:geoip.dat:cn"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("external geoip needs explicit route-set data");
    assert!(error.to_string().contains("external IP matcher"));
    assert!(error.to_string().contains("geoip rule-set data"));

    let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "ip": ["!geoip:cn"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("inverse IP matcher needs negative matching");
    assert!(error.to_string().contains("inverse IP matcher"));
    assert!(error.to_string().contains("negative route matching"));
    Ok(())
}

#[test]
fn rejects_xray_metadata_route_matchers() -> Result<()> {
    let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "source": ["10.0.0.0/8"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("source route matcher requires metadata");
    assert!(error.to_string().contains("source IP matching metadata"));

    let json = r#"
{
  "routing": {
    "rules": [
      { "type": "field", "process": ["curl"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("process route matcher requires metadata");
    assert!(error.to_string().contains("process metadata"));
    Ok(())
}

#[test]
fn rejects_xray_routing_domain_strategy_that_requires_dns() -> Result<()> {
    let json = r#"
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "ip": ["10.0.0.0/8"], "outboundTag": "direct" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("xray domainStrategy must not be ignored");
    assert!(error.to_string().contains("domainStrategy"));
    Ok(())
}

#[test]
fn resolves_static_xray_balancer_rule() -> Result<()> {
    let json = r#"
{
  "outbounds": [
    { "tag": "proxy-a", "protocol": "freedom" },
    { "tag": "direct-out", "protocol": "freedom" }
  ],
  "routing": {
    "balancers": [
      { "tag": "single", "selector": ["proxy-a"], "strategy": {} }
    ],
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "balancerTag": "single" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let routes = config.route_table()?;
    assert_eq!(
        routes.decide(
            &ProxyTarget::Domain("api.example.com".to_string(), 443),
            RouteNetwork::Tcp
        ),
        RouteDecision::Proxy("proxy-a".to_string())
    );
    Ok(())
}

#[test]
fn rejects_dynamic_xray_balancer_rule() -> Result<()> {
    let json = r#"
{
  "outbounds": [
    { "tag": "proxy-a", "protocol": "freedom" },
    { "tag": "proxy-b", "protocol": "freedom" }
  ],
  "routing": {
    "balancers": [
      { "tag": "multi", "selector": ["proxy-"] }
    ],
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "balancerTag": "multi" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("multi-outbound balancer needs a real policy");
    assert!(error.to_string().contains("single-outbound"));
    Ok(())
}

#[test]
fn rejects_xray_balancer_runtime_policy_fields() -> Result<()> {
    let json = r#"
{
  "outbounds": [
    { "tag": "proxy-a", "protocol": "freedom" }
  ],
  "routing": {
    "balancers": [
      { "tag": "runtime", "selector": ["proxy-a"], "fallbackTag": "direct", "strategy": { "type": "leastPing" } }
    ],
    "rules": [
      { "type": "field", "domain": ["domain:example.com"], "balancerTag": "runtime" }
    ]
  }
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config
        .route_table()
        .expect_err("fallbackTag requires observatory state");
    assert!(error.to_string().contains("fallbackTag"));
    Ok(())
}

#[test]
fn defers_xray_outbound_decode_errors_until_selected() -> Result<()> {
    let json = r#"
{
  "outbounds": [
    {
      "tag": "broken-vless",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" }]
        }]
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": { "fingerprint": 123 }
      }
    },
    {
      "tag": "ss-ok",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{
          "address": "ss.example.com",
          "port": 8388,
          "method": "aes-128-gcm",
          "password": "secret"
        }]
      }
    }
  ]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Shadowsocks(shadowsocks) = config
        .outbound("ss-ok")
        .context("ss outbound")?
        .to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Shadowsocks")
    };
    assert_eq!(shadowsocks.server_host, "ss.example.com");

    let error = config
        .outbound("broken-vless")
        .context("broken outbound")?
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("broken outbound parse must be deferred");
    assert!(
        error
            .to_string()
            .contains("parse xray outbound broken-vless failed")
    );
    Ok(())
}

#[test]
fn parses_xray_local_socks_string_port() -> Result<()> {
    let json = r#"
{
  "inbounds": [
    { "tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": "1080" }
  ],
  "outbounds": []
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    assert_eq!(config.inbounds[0].port, Some(1080));
    assert_eq!(
        config.local_socks_listen()?,
        Some("127.0.0.1:1080".parse()?)
    );
    Ok(())
}

#[test]
fn converts_vless_tls_inbound_to_server_config() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "tag": "vless-server",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": 8443,
    "settings": {
      "decryption": "none",
      "clients": [
        { "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" },
        { "id": "e4d909c2-0a31-4ebf-8a8e-582c8f1f6e5a" }
      ]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "server.crt",
          "keyFile": "server.key"
        }]
      },
      "wsSettings": {
        "path": "/vless",
        "headers": { "Host": "edge.example.com" }
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
        bail!("expected VLESS")
    };
    assert_eq!(vless.listen, "127.0.0.1:8443".parse()?);
    assert_eq!(vless.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
    assert_eq!(
        vless.users,
        vec!["e4d909c2-0a31-4ebf-8a8e-582c8f1f6e5a".to_string()]
    );
    assert!(vless.tls);
    assert_eq!(vless.cert_path, PathBuf::from("server.crt"));
    assert_eq!(vless.key_path, PathBuf::from("server.key"));
    assert_eq!(vless.flow, "");
    assert_eq!(vless.transport.kind, VlessTransportKind::WebSocket);
    assert_eq!(vless.transport.path, "/vless");
    assert_eq!(
        vless.transport.request_host("example.com"),
        "edge.example.com"
    );
    Ok(())
}

#[test]
fn converts_vless_inline_tls_inbound_to_server_config() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "tag": "vless-inline-server",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": 8443,
    "settings": {
      "decryption": "none",
      "clients": [
        { "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" }
      ]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificate": ["cert-line-1", "cert-line-2"],
          "key": ["key-line-1", "key-line-2"]
        }]
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
        bail!("expected VLESS")
    };
    assert_eq!(vless.cert_path, PathBuf::new());
    assert_eq!(vless.key_path, PathBuf::new());
    assert_eq!(vless.certificates, vec!["cert-line-1\ncert-line-2"]);
    assert_eq!(vless.key.as_deref(), Some("key-line-1\nkey-line-2"));
    Ok(())
}

#[test]
fn converts_vless_reality_inbound_to_server_config() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "tag": "vless-reality",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": 8443,
    "settings": {
      "decryption": "none",
      "clients": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" }]
    },
    "streamSettings": {
      "network": "grpc",
      "security": "reality",
      "realitySettings": {
        "dest": "www.example.com:443",
        "serverNames": ["front.example.com"],
        "privateKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "shortIds": ["a1b2"],
        "alpn": ["h2"]
      },
      "grpcSettings": {
        "serviceName": "TunService"
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
        bail!("expected VLESS")
    };
    let reality = vless.reality.context("REALITY config")?;
    assert!(!vless.tls);
    assert_eq!(reality.server_name, "www.example.com");
    assert_eq!(reality.server_port, 443);
    assert_eq!(reality.server_names, vec!["front.example.com".to_string()]);
    assert_eq!(reality.short_ids[0], [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);
    assert_eq!(reality.alpn_protocols, vec![b"h2".to_vec()]);
    assert_eq!(vless.transport.kind, VlessTransportKind::Grpc);
    assert_eq!(vless.transport.path, "/TunService/Tun");
    Ok(())
}

#[test]
fn converts_vmess_tls_inbound_to_server_config() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "tag": "vmess-tls",
    "protocol": "vmess",
    "listen": "127.0.0.1",
    "port": 9443,
    "settings": {
      "clients": [
        { "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "alterId": 0 },
        { "id": "433722e1-0f8c-4724-9089-d5bc6d0c51ef" }
      ]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{ "certificateFile": "server.crt", "keyFile": "server.key" }],
        "echServerKeys": "ech-vmess.keys"
      },
      "wsSettings": { "path": "/vmess" }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayServerConfig::Vmess(vmess) = config.inbounds[0].to_server_config()? else {
        bail!("expected VMess")
    };
    assert_eq!(vmess.listen, "127.0.0.1:9443".parse()?);
    assert!(vmess.tls);
    assert_eq!(vmess.cert_path, Some(PathBuf::from("server.crt")));
    assert_eq!(vmess.key_path, Some(PathBuf::from("server.key")));
    assert_eq!(vmess.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
    assert_eq!(
        vmess.users,
        vec!["433722e1-0f8c-4724-9089-d5bc6d0c51ef".to_string()]
    );
    assert_eq!(vmess.transport.kind, VlessTransportKind::WebSocket);
    assert_eq!(vmess.transport.path, "/vmess");
    assert!(vmess.ech.is_some());
    Ok(())
}

#[test]
fn converts_trojan_tls_inbound_to_server_config() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "tag": "trojan-tls",
    "protocol": "trojan",
    "listen": "127.0.0.1",
    "port": 9444,
    "settings": {
      "clients": [
        { "password": "primary-pass" },
        { "password": "alice-pass" }
      ]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{ "certificateFile": "server.crt", "keyFile": "server.key" }],
        "echServerKeys": "ech-trojan.keys"
      },
      "wsSettings": { "path": "/trojan" }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayServerConfig::Trojan(trojan) = config.inbounds[0].to_server_config()? else {
        bail!("expected Trojan")
    };
    assert_eq!(trojan.listen, "127.0.0.1:9444".parse()?);
    assert_eq!(trojan.password, "primary-pass");
    assert_eq!(trojan.users, vec!["alice-pass".to_string()]);
    assert_eq!(trojan.cert_path, PathBuf::from("server.crt"));
    assert_eq!(trojan.key_path, PathBuf::from("server.key"));
    assert_eq!(trojan.transport.kind, VlessTransportKind::WebSocket);
    assert_eq!(trojan.transport.path, "/trojan");
    assert!(trojan.ech.is_some());
    Ok(())
}

#[test]
fn converts_shadowsocks_inbound_to_server_config() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "tag": "ss",
    "protocol": "shadowsocks",
    "listen": "127.0.0.1",
    "port": 8388,
    "settings": {
      "method": "aes-128-gcm",
      "password": "secret",
      "network": "tcp,udp"
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayServerConfig::Shadowsocks(shadowsocks) = config.inbounds[0].to_server_config()? else {
        bail!("expected Shadowsocks")
    };
    assert_eq!(shadowsocks.listen, "127.0.0.1:8388".parse()?);
    assert_eq!(shadowsocks.method, "aes-128-gcm");
    assert_eq!(shadowsocks.password, "secret");
    assert!(shadowsocks.tcp);
    assert!(shadowsocks.udp);
    Ok(())
}

#[test]
fn converts_hysteria2_inbound_to_server_config() -> Result<()> {
    let json = r#"
{
  "inbounds": [{
    "tag": "hy2",
    "protocol": "hysteria",
    "listen": "127.0.0.1",
    "port": 8445,
    "settings": {
      "version": 2,
      "users": [
        { "auth": "primary-pass" },
        { "auth": "alice-pass" }
      ]
    },
    "streamSettings": {
      "network": "hysteria",
      "security": "tls",
      "tlsSettings": {
        "alpn": ["h3"],
        "certificates": [{ "certificateFile": "server.crt", "keyFile": "server.key" }]
      },
      "hysteriaSettings": {
        "version": 2
      },
      "finalmask": {
        "udp": [{
          "type": "salamander",
          "settings": { "password": "obfs-pass" }
        }],
        "quicParams": {
          "congestion": "reno",
          "brutalUp": "20mbps",
          "brutalDown": "80mbps"
        }
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayServerConfig::Hysteria2(hy2) = config.inbounds[0].to_server_config()? else {
        bail!("expected Hysteria2")
    };
    assert_eq!(hy2.listen, "127.0.0.1:8445".parse()?);
    assert_eq!(hy2.password, "primary-pass");
    assert_eq!(hy2.users, vec!["alice-pass".to_string()]);
    assert_eq!(hy2.cert_path, PathBuf::from("server.crt"));
    assert_eq!(hy2.key_path, PathBuf::from("server.key"));
    assert_eq!(hy2.obfs.as_deref(), Some("salamander"));
    assert_eq!(hy2.obfs_password.as_deref(), Some("obfs-pass"));
    assert_eq!(hy2.upload_bandwidth, Some(20));
    assert_eq!(hy2.cc_rx, "10000000");
    assert_eq!(hy2.congestion_control, "reno");
    assert!(hy2.udp);
    Ok(())
}

#[test]
fn parses_vless_raw_outbound() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "vless-raw",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 80,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": { "network": "tcp", "security": "none" }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Vless(vless) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert!(!vless.tls);
    assert!(vless.reality.is_none());
    assert_eq!(vless.server_port, 80);
    Ok(())
}

#[test]
fn parses_vmess_tls_transport() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "vmess-tls",
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{
          "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
          "alterId": 0,
          "packetEncoding": "packetaddr"
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "vmess.example.com",
        "disableSystemRoot": true,
        "pinnedPeerCertSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "certificates": [
          { "usage": "verify", "certificateFile": "vmess-ca.pem" },
          { "usage": "verify", "certificate": ["vmess-inline-ca"] },
          { "usage": "encipherment", "certificateFile": "ignored-ca.pem" }
        ]
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Vmess(vmess) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VMess")
    };
    assert!(vmess.tls);
    assert_eq!(vmess.sni, "vmess.example.com");
    assert_eq!(vmess.ca_cert_paths, vec![PathBuf::from("vmess-ca.pem")]);
    assert_eq!(vmess.ca_certificates, vec!["vmess-inline-ca"]);
    assert!(vmess.disable_system_roots);
    assert_eq!(
        vmess.pinned_cert_sha256,
        vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    );
    Ok(())
}

#[test]
fn parses_vmess_websocket_transport() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "vmess-ws",
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 80,
        "users": [{
          "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
          "alterId": 0,
          "packetEncoding": "packetaddr"
        }]
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "none",
      "wsSettings": {
        "path": "/vmess",
        "headers": { "Host": "edge.example.com" }
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Vmess(vmess) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
    let json = r#"
{
  "outbounds": [{
    "tag": "vmess-xudp",
    "protocol": "vmess",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 80,
        "users": [{
          "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
          "alterId": 0,
          "packetEncoding": "xudp"
        }]
      }]
    },
    "streamSettings": { "network": "tcp", "security": "none" }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Vmess(vmess) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VMess")
    };
    assert_eq!(vmess.packet_encoding, "xudp");
    Ok(())
}

#[test]
fn parses_hysteria2_transport_profile() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "hy2",
    "protocol": "hysteria",
    "settings": {
      "version": 2,
      "address": "example.com",
      "port": 443
    },
    "streamSettings": {
      "network": "hysteria",
      "security": "tls",
      "tlsSettings": {
        "serverName": "hy2.example.com",
        "allowInsecure": true,
        "disableSystemRoot": true,
        "alpn": ["h3"],
        "certificates": [
          { "usage": "verify", "certificateFile": "hy2-ca.pem" },
          { "usage": "verify", "certificate": ["hy2-inline-ca"] }
        ]
      },
      "hysteriaSettings": {
        "version": 2,
        "auth": "secret"
      },
      "finalmask": {
        "udp": [{
          "type": "salamander",
          "settings": { "password": "obfs-pass" }
        }],
        "quicParams": {
          "congestion": "reno",
          "brutalUp": "10mbps",
          "brutalDown": "80mbps"
        }
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Hysteria2(hysteria2) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Hysteria2")
    };
    assert_eq!(hysteria2.server_host, "example.com");
    assert_eq!(hysteria2.server_port, 443);
    assert_eq!(hysteria2.password, "secret");
    assert_eq!(hysteria2.sni, "hy2.example.com");
    assert!(hysteria2.insecure);
    assert_eq!(hysteria2.ca_cert_paths, vec![PathBuf::from("hy2-ca.pem")]);
    assert_eq!(hysteria2.ca_certificates, vec!["hy2-inline-ca"]);
    assert!(hysteria2.disable_system_roots);
    assert_eq!(hysteria2.obfs.as_deref(), Some("salamander"));
    assert_eq!(hysteria2.obfs_password.as_deref(), Some("obfs-pass"));
    assert_eq!(hysteria2.upload_bandwidth, Some(10));
    assert_eq!(hysteria2.download_bandwidth, Some(80));
    assert_eq!(hysteria2.congestion_control, "reno");
    Ok(())
}

#[test]
fn parses_hysteria2_upload_bandwidth_and_rejects_unmapped_quic_options() -> Result<()> {
    let json = r#"
{
  "outbounds": [
    {
      "tag": "hy2-up",
      "protocol": "hysteria",
      "settings": {
        "version": 2,
        "address": "example.com",
        "port": 443
      },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "hysteriaSettings": {
          "version": 2,
          "auth": "secret",
          "up": "10mbps"
        }
      }
    },
    {
      "tag": "hy2-brutal-up",
      "protocol": "hysteria",
      "settings": {
        "version": 2,
        "address": "example.com",
        "port": 443
      },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "hysteriaSettings": {
          "version": 2,
          "auth": "secret"
        },
        "finalmask": {
          "quicParams": {
            "brutalUp": "10mbps"
          }
        }
      }
    },
    {
      "tag": "hy2-bbr-profile",
      "protocol": "hysteria",
      "settings": {
        "version": 2,
        "address": "example.com",
        "port": 443
      },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "hysteriaSettings": {
          "version": 2,
          "auth": "secret"
        },
        "finalmask": {
          "quicParams": {
            "bbrProfile": "aggressive"
          }
        }
      }
    }
  ]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Hysteria2(up) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Hysteria2")
    };
    assert_eq!(up.upload_bandwidth, Some(10));
    let XrayClientConfig::Hysteria2(brutal_up) =
        config.outbounds[1].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected Hysteria2")
    };
    assert_eq!(brutal_up.upload_bandwidth, Some(10));
    let bbr_profile_error = config.outbounds[2]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("bbrProfile must be explicit");
    assert!(bbr_profile_error.to_string().contains("bbrProfile"));
    Ok(())
}

#[test]
fn parses_trojan_websocket_transport() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "trojan-ws",
    "protocol": "trojan",
    "settings": {
      "servers": [{ "address": "example.com", "port": 443, "password": "secret" }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {
        "path": "/trojan",
        "headers": { "Host": "edge.example.com" }
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Trojan(trojan) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
fn parses_vless_websocket_transport() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "vless-ws",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": {
        "path": "/vless",
        "headers": { "Host": "edge.example.com" }
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Vless(vless) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
fn parses_vless_http2_transport() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "vless-h2",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "h2",
      "security": "tls",
      "tlsSettings": { "alpn": ["h2"] },
      "httpSettings": {
        "path": "/h2",
        "host": ["edge.example.com"]
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Vless(vless) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert_eq!(vless.transport.kind, VlessTransportKind::Http2);
    assert_eq!(vless.transport.path, "/h2");
    assert_eq!(
        vless.transport.request_host("example.com"),
        "edge.example.com"
    );
    Ok(())
}

#[test]
fn parses_vless_grpc_transport() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "vless-grpc",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "grpc",
      "security": "tls",
      "tlsSettings": { "alpn": ["h2"] },
      "grpcSettings": {
        "serviceName": "TunService",
        "authority": "edge.example.com"
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Vless(vless) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected VLESS")
    };
    assert_eq!(vless.transport.kind, VlessTransportKind::Grpc);
    assert_eq!(vless.transport.path, "/TunService/Tun");
    assert_eq!(
        vless.transport.request_host("example.com"),
        "edge.example.com"
    );
    Ok(())
}

#[test]
fn parses_vless_xhttp_transport() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "vless-xhttp",
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "example.com",
        "port": 443,
        "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
      }]
    },
    "streamSettings": {
      "network": "xhttp",
      "security": "tls",
      "tlsSettings": { "alpn": ["http/1.1"] },
      "xhttpSettings": {
        "path": "/xhttp",
        "host": ["edge.example.com"],
        "mode": "stream-one"
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Vless(vless) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
fn rejects_xray_unsupported_stream_settings() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "direct-out",
    "protocol": "freedom",
    "streamSettings": {
      "network": "tcp",
      "tcpSettings": {
        "acceptProxyProtocol": false,
        "header": { "type": "none" }
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Route(route) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected route client")
    };
    assert_eq!(route.default, RouteDecision::Direct);

    let json = r#"
{
  "outbounds": [{
    "tag": "http-proxy",
    "protocol": "http",
    "settings": {
      "address": "proxy.example.com",
      "port": 8443
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tcpSettings": {
        "header": { "type": "http" }
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config.outbounds[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("raw TCP header options must not be ignored");
    assert!(error.to_string().contains("streamSettings"));
    assert!(error.to_string().contains("tcpSettings"));

    let json = r#"
{
  "outbounds": [{
    "tag": "direct-out",
    "protocol": "freedom",
    "streamSettings": {
      "sockopt": { "interface": "eth0" }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config.outbounds[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("socket options must not be ignored");
    assert!(error.to_string().contains("sockopt"));
    assert!(error.to_string().contains("socket option"));

    let json = r#"
{
  "outbounds": [{
    "tag": "direct-out",
    "protocol": "freedom",
    "streamSettings": {
      "unknownStreamField": true
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config.outbounds[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unknown streamSettings fields must not be ignored");
    assert!(error.to_string().contains("unsupported fields"));
    assert!(error.to_string().contains("unknownStreamField"));
    Ok(())
}

#[test]
fn rejects_xray_unsupported_profile_fields() -> Result<()> {
    let json = r#"
{
  "outbounds": [
    {
      "tag": "vless-send-through",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
        }]
      },
      "streamSettings": { "network": "tcp", "security": "none" },
      "sendThrough": "192.0.2.1"
    },
    {
      "tag": "vless-user-email",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{
            "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
            "encryption": "none",
            "email": "user@example.com"
          }]
        }]
      },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    {
      "tag": "vless-ws-extra",
      "protocol": "vless",
      "settings": {
        "vnext": [{
          "address": "example.com",
          "port": 443,
          "users": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "encryption": "none" }]
        }]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/ws",
          "maxEarlyData": 2048
        }
      }
    },
    {
      "tag": "ss-mux-fields",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{
          "address": "ss.example.com",
          "port": 8388,
          "method": "aes-128-gcm",
          "password": "secret"
        }]
      },
      "mux": {
        "enabled": false,
        "concurrency": 8
      }
    }
  ],
  "inbounds": [
    {
      "tag": "trojan-sniffing",
      "protocol": "trojan",
      "sniffing": { "enabled": true }
    },
    {
      "tag": "hy2-mask-extra",
      "protocol": "hysteria2",
      "streamSettings": {
        "network": "hysteria",
        "finalmask": {
          "udp": [{
            "type": "salamander",
            "settings": {
              "password": "obfs-pass",
              "padding": true
            }
          }]
        }
      }
    }
  ]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let top_level_error = config.outbounds[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unsupported xray outbound fields must not be ignored");
    assert!(top_level_error.to_string().contains("sendThrough"));

    let user_error = config.outbounds[1]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unsupported xray user fields must not be ignored");
    assert!(user_error.to_string().contains("users[0]"));
    assert!(user_error.to_string().contains("email"));

    let ws_error = config.outbounds[2]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unsupported xray wsSettings fields must not be ignored");
    assert!(ws_error.to_string().contains("wsSettings"));
    assert!(ws_error.to_string().contains("maxEarlyData"));

    let mux_error = config.outbounds[3]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("disabled mux settings must not be ignored");
    assert!(mux_error.to_string().contains("mux"));
    assert!(mux_error.to_string().contains("concurrency"));

    let inbound_error = config.inbounds[0]
        .to_server_config()
        .err()
        .context("unsupported xray inbound fields must not be ignored")?;
    assert!(inbound_error.to_string().contains("sniffing"));

    let mask_error = config.inbounds[1]
        .to_server_config()
        .err()
        .context("unsupported xray finalmask settings must not be ignored")?;
    assert!(mask_error.to_string().contains("finalmask"));
    assert!(mask_error.to_string().contains("padding"));
    Ok(())
}

#[test]
fn rejects_xray_unsupported_tls_settings() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "http-proxy",
    "protocol": "http",
    "settings": {
      "address": "proxy.example.com",
      "port": 8443
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "minVersion": "1.2"
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config.outbounds[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("TLS version policy must not be ignored");
    assert!(error.to_string().contains("tlsSettings"));
    assert!(error.to_string().contains("minVersion"));
    assert!(error.to_string().contains("TLS version policy"));

    let json = r#"
{
  "outbounds": [{
    "tag": "http-proxy",
    "protocol": "http",
    "settings": {
      "address": "proxy.example.com",
      "port": 8443
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "disableSystemRoot": true,
        "certificates": [{
          "usage": "verify",
          "certificate": ["ca-line"],
          "oneTimeLoading": true
        }]
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config.outbounds[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("certificate loading policy must not be ignored");
    assert!(error.to_string().contains("certificates[0]"));
    assert!(error.to_string().contains("oneTimeLoading"));

    let json = r#"
{
  "inbounds": [{
    "tag": "vless-server",
    "protocol": "vless",
    "listen": "127.0.0.1",
    "port": 8443,
    "settings": {
      "decryption": "none",
      "clients": [{ "id": "a3482e88-686a-4a58-8126-99c9df64b7bf" }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "rejectUnknownSni": true
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config.inbounds[0]
        .to_server_config()
        .err()
        .context("SNI rejection policy must not be ignored")?;
    assert!(error.to_string().contains("rejectUnknownSni"));
    assert!(error.to_string().contains("SNI-based server rejection"));

    let json = r#"
{
  "outbounds": [{
    "tag": "direct-out",
    "protocol": "freedom",
    "streamSettings": {
      "tlsSettings": {
        "unknownTlsOption": true
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let error = config.outbounds[0]
        .to_client_config("127.0.0.1:1080".parse()?)
        .expect_err("unknown tlsSettings fields must not be ignored");
    assert!(error.to_string().contains("unsupported fields"));
    assert!(error.to_string().contains("unknownTlsOption"));
    Ok(())
}

#[test]
fn converts_http_outbound_to_client_config() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "http-proxy",
    "protocol": "http",
    "settings": {
      "address": "proxy.example.com",
      "port": 8443,
      "user": "user",
      "pass": "pass",
      "headers": {
        "X-Test": "value"
      }
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "front.example.com",
        "allowInsecure": true,
        "fingerprint": "chrome",
        "alpn": ["http/1.1"]
      }
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::HttpProxy(http) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected HTTP proxy")
    };
    assert_eq!(http.server_host, "proxy.example.com");
    assert_eq!(http.server_port, 8443);
    assert_eq!(http.username, "user");
    assert_eq!(http.password, "pass");
    assert!(http.tls);
    assert_eq!(http.sni, "front.example.com");
    assert!(http.insecure);
    assert_eq!(http.client_fingerprint, Some(UtlsFingerprint::Chrome));
    assert_eq!(
        http.extra_headers,
        vec![("X-Test".to_string(), "value".to_string())]
    );
    Ok(())
}

#[test]
fn converts_socks_outbound_to_client_config() -> Result<()> {
    let json = r#"
{
  "outbounds": [{
    "tag": "socks-proxy",
    "protocol": "socks",
    "settings": {
      "servers": [{
        "address": "proxy.example.com",
        "port": 1080,
        "users": [{
          "user": "user",
          "pass": "pass"
        }]
      }],
      "network": "tcp+udp"
    }
  }]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::SocksProxy(socks) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
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
fn converts_builtin_route_outbounds_to_client_config() -> Result<()> {
    let json = r#"
{
  "outbounds": [
    {
      "tag": "direct-out",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "blackhole-out",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}
"#;
    let config: XrayConfig = serde_json::from_str(json)?;
    let XrayClientConfig::Route(direct) =
        config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
    else {
        bail!("expected direct route client")
    };
    assert_eq!(direct.default, RouteDecision::Direct);
    let XrayClientConfig::Route(blackhole) =
        config.outbounds[1].to_client_config("127.0.0.1:1081".parse()?)?
    else {
        bail!("expected blackhole route client")
    };
    assert_eq!(blackhole.default, RouteDecision::Block);
    Ok(())
}
