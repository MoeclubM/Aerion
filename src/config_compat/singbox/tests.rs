//! Tests for the singbox configuration-compatibility module.

    use std::fs;

    use super::*;
    use crate::protocol::ProxyTarget;

    #[test]
    fn parses_singbox_inbound_string_ports() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    { "type": "mixed", "listen": "127.0.0.1", "listen_port": "7890" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(config.inbounds[0].listen_port, Some(7890));
        assert_eq!(
            config.local_socks_listen()?,
            Some("127.0.0.1:7890".parse()?)
        );
        Ok(())
    }

    #[test]
    fn rejects_singbox_unsupported_local_socks_inbound_fields() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 7890,
      "sniff": true
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .local_socks_listen()
            .expect_err("local mixed inbound sniffing must not be ignored");
        assert!(error.to_string().contains("sniff"));

        let json = r#"
{
  "inbounds": [
    {
      "type": "http",
      "tag": "http-in",
      "listen": "127.0.0.1",
      "listen_port": 8080
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .local_socks_listen()
            .expect_err("local HTTP inbound must not be ignored");
        assert!(error.to_string().contains("local SOCKS/mixed/TUN listener"));
        assert!(error.to_string().contains("http"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_unsupported_top_level_options() -> Result<()> {
        let json = r#"
{
  "log": { "level": "debug" },
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "domain_suffix": "example.com", "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("unsupported sing-box top-level options must not be ignored");
        assert!(error.to_string().contains("sing-box config"));
        assert!(error.to_string().contains("log"));
        Ok(())
    }

    #[test]
    fn compiles_singbox_route_rules() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "domain_suffix": ["example.com"], "outbound": "direct" },
      { "domain_keyword": "video", "outbound": "proxy-a" },
      { "ip_cidr": ["10.0.0.0/8"], "port": [53], "network": "udp", "outbound": "direct" }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
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
            routes.decide(&ProxyTarget::Ip("10.1.2.3:53".parse()?), RouteNetwork::Udp),
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
    fn singbox_route_default_uses_first_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    { "type": "vless", "tag": "proxy-a" }
  ],
  "route": {
    "rules": [
      { "domain_suffix": ["example.com"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
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
    { "type": "vless" }
  ],
  "route": {
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("tagless default proxy outbound cannot be spawned");
        assert!(error.to_string().contains("requires a tag"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_route_top_level_runtime_options() -> Result<()> {
        let json = r#"
{
  "route": {
    "auto_detect_interface": true,
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("platform interface detection must not be ignored");
        assert!(error.to_string().contains("auto_detect_interface"));

        let json = r#"
{
  "route": {
    "default_domain_resolver": "local",
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("default resolver must not be ignored");
        assert!(error.to_string().contains("default_domain_resolver"));

        let json = r#"
{
  "route": {
    "dhcp_lease_files": ["/var/lib/misc/dnsmasq.leases"],
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("DHCP lease lookup must not be ignored");
        assert!(error.to_string().contains("dhcp_lease_files"));

        let json = r#"
{
  "route": {
    "default_http_client": "rule-set-fetcher",
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("remote rule-set HTTP client must not be ignored");
        assert!(error.to_string().contains("default_http_client"));

        let json = r#"
{
  "route": {
    "unknown_route_option": true,
    "rules": []
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("unknown route options must not be ignored");
        assert!(error.to_string().contains("unsupported fields"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_icmp_route_network() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "network": "icmp", "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("ICMP route rules require ICMP routing support");
        assert!(error.to_string().contains("network icmp"));
        Ok(())
    }

    #[test]
    fn compiles_singbox_route_actions() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "domain_suffix": ["example.com"], "action": "route", "outbound": "direct" },
      { "domain_suffix": ["blocked.test"], "action": "reject" }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
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
                &ProxyTarget::Domain("www.blocked.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Block
        );
        Ok(())
    }

    #[test]
    fn compiles_singbox_logical_or_route_rules() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      {
        "type": "logical",
        "mode": "or",
        "action": "route",
        "outbound": "direct",
        "rules": [
          { "domain_suffix": ["example.com"] },
          { "ip_cidr": ["10.0.0.0/8"] }
        ]
      }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let routes = config.route_table()?;
        assert_eq!(routes.rules.len(), 2);
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
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
    fn compiles_singbox_logical_and_route_rules() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      {
        "type": "logical",
        "mode": "and",
        "outbound": "direct",
        "rules": [
          { "domain_suffix": ["example.com"] },
          { "port": [443] },
          { "network": "tcp" }
        ]
      }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
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
                &ProxyTarget::Domain("api.example.com".to_string(), 80),
                RouteNetwork::Tcp
            ),
            RouteDecision::Proxy("proxy-b".to_string())
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Udp
            ),
            RouteDecision::Proxy("proxy-b".to_string())
        );
        Ok(())
    }

    #[test]
    fn compiles_singbox_inline_route_rule_set() -> Result<()> {
        let json = r#"
{
  "route": {
    "rule_set": [
      {
        "type": "inline",
        "tag": "static-set",
        "rules": [
          { "domain_suffix": ["example.com"] },
          {
            "type": "logical",
            "mode": "or",
            "rules": [
              { "ip_cidr": ["10.0.0.0/8"] },
              { "domain_keyword": "video" }
            ]
          }
        ]
      }
    ],
    "rules": [
      { "rule_set": ["static-set"], "action": "route", "outbound": "direct" }
    ],
    "final": "proxy-b"
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let routes = config.route_table()?;
        assert_eq!(routes.rules.len(), 3);
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(&ProxyTarget::Ip("10.1.2.3:443".parse()?), RouteNetwork::Tcp),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("video.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
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
    fn rejects_singbox_geo_route_rules_without_data() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "geosite": ["category-ads-all"], "outbound": "block" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("geosite needs explicit route-set data");
        assert!(error.to_string().contains("geosite rule-set data"));

        let json = r#"
{
  "route": {
    "rules": [
      { "geoip": ["cn"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("geoip needs explicit route-set data");
        assert!(error.to_string().contains("geoip rule-set data"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_metadata_route_matchers() -> Result<()> {
        let json = r#"
{
  "route": {
    "rules": [
      { "source_ip_cidr": ["10.0.0.0/8"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("source route matcher requires metadata");
        assert!(error.to_string().contains("source IP metadata"));

        let json = r#"
{
  "route": {
    "rules": [
      { "process_name": ["curl"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("process route matcher requires metadata");
        assert!(error.to_string().contains("process metadata"));

        let json = r#"
{
  "route": {
    "rules": [
      { "inbound": ["mixed-in"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("inbound route matcher requires metadata");
        assert!(error.to_string().contains("inbound tag metadata"));
        Ok(())
    }

    #[test]
    fn compiles_singbox_local_source_route_rule_set() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(
            dir.path().join("geo.json"),
            r#"
{
  "version": 3,
  "rules": [
    { "domain_suffix": ["example.com"] },
    {
      "type": "logical",
      "mode": "or",
      "rules": [
        { "ip_cidr": ["10.0.0.0/8"] },
        { "domain_keyword": "video" }
      ]
    }
  ]
}
"#,
        )?;
        let json = r#"
{
  "route": {
    "rule_set": [
      {
        "type": "local",
        "tag": "geo",
        "format": "source",
        "path": "geo.json"
      }
    ],
    "rules": [
      { "rule_set": ["geo"], "action": "route", "outbound": "direct" }
    ],
    "final": "proxy-b"
  }
}
"#;
        let mut config: SingBoxConfig = serde_json::from_str(json)?;
        config.source_dir = Some(dir.path().to_path_buf());
        let routes = config.route_table()?;
        assert_eq!(routes.rules.len(), 3);
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("api.example.com".to_string(), 443),
                RouteNetwork::Tcp
            ),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(&ProxyTarget::Ip("10.1.2.3:443".parse()?), RouteNetwork::Tcp),
            RouteDecision::Direct
        );
        assert_eq!(
            routes.decide(
                &ProxyTarget::Domain("video.test".to_string(), 443),
                RouteNetwork::Tcp
            ),
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
    fn rejects_singbox_binary_route_rule_set() -> Result<()> {
        let json = r#"
{
  "route": {
    "rule_set": [
      {
        "type": "local",
        "tag": "geo",
        "path": "geo.srs"
      }
    ],
    "rules": [
      { "rule_set": ["geo"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("binary rule-set loading must fail explicitly");
        assert!(error.to_string().contains("format binary"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_remote_route_rule_set() -> Result<()> {
        let json = r#"
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "geo",
        "format": "source",
        "url": "https://rules.example.test/geo.json"
      }
    ],
    "rules": [
      { "rule_set": ["geo"], "outbound": "direct" }
    ]
  }
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .route_table()
            .expect_err("remote rule-set loading must fail explicitly");
        assert!(error.to_string().contains("requires downloading"));
        Ok(())
    }

    #[test]
    fn compiles_singbox_tun_inbound() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "mtu": 9000,
      "auto_route": true,
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "route_exclude_address": ["10.0.0.0/8"]
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "proxy-a",
      "server": "example.com",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert!(config.tun_enabled());
        let tun = config
            .tun_config("127.0.0.1:7890".parse()?)?
            .context("tun config")?;
        assert_eq!(tun.proxy_url, "socks5://127.0.0.1:7890");
        assert_eq!(tun.tun_name.as_deref(), Some("tun0"));
        assert_eq!(tun.mtu, 9000);
        assert_eq!(tun.bypass, vec!["10.0.0.0/8"]);
        assert!(tun.ipv6);
        Ok(())
    }

    #[test]
    fn converts_naive_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "naive",
      "tag": "naive-h3",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "network": "udp",
      "users": [
        { "username": "user", "password": "pass" },
        { "username": "alice", "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key",
        "alpn": ["h3"]
      },
      "quic_congestion_control": "reno"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Naive(naive) = config.inbounds[0].to_server_config()? else {
            bail!("expected Naive")
        };
        assert_eq!(naive.listen, "127.0.0.1:8443".parse()?);
        assert_eq!(naive.username, "user");
        assert_eq!(naive.password, "pass");
        assert_eq!(naive.users, vec!["alice:alice-pass".to_string()]);
        assert_eq!(naive.cert_path, PathBuf::from("server.crt"));
        assert_eq!(naive.key_path, PathBuf::from("server.key"));
        assert!(!naive.tcp);
        assert!(naive.quic);
        assert_eq!(naive.quic_congestion_control, "reno");
        Ok(())
    }

    #[test]
    fn converts_vless_reality_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf" }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h2"],
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.example.com",
            "server_port": 443
          },
          "private_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
          "short_id": ["a1b2"]
        }
      },
      "transport": {
        "type": "grpc",
        "service_name": "TunService"
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        let reality = vless.reality.context("REALITY config")?;
        assert_eq!(vless.listen, "127.0.0.1:8443".parse()?);
        assert!(!vless.tls);
        assert_eq!(vless.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(reality.server_name, "www.example.com");
        assert_eq!(reality.server_port, 443);
        assert_eq!(reality.short_ids[0], [0xa1, 0xb2, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reality.alpn_protocols, vec![b"h2".to_vec()]);
        assert_eq!(vless.transport.kind, VlessTransportKind::Grpc);
        assert_eq!(vless.transport.path, "/TunService/Tun");
        Ok(())
    }

    #[test]
    fn converts_vless_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-tls",
      "listen": "127.0.0.1",
      "listen_port": 9443,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf", "flow": "xtls-rprx-vision" },
        { "uuid": "433722e1-0f8c-4724-9089-d5bc6d0c51ef", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key"
      },
      "transport": {
        "type": "ws",
        "path": "/ws",
        "headers": { "Host": "front.example.com" }
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.listen, "127.0.0.1:9443".parse()?);
        assert!(vless.tls);
        assert_eq!(vless.cert_path, PathBuf::from("server.crt"));
        assert_eq!(vless.key_path, PathBuf::from("server.key"));
        assert_eq!(vless.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(
            vless.users,
            vec!["433722e1-0f8c-4724-9089-d5bc6d0c51ef".to_string()]
        );
        assert_eq!(vless.flow, "xtls-rprx-vision");
        assert_eq!(vless.transport.kind, VlessTransportKind::WebSocket);
        assert_eq!(vless.transport.path, "/ws");
        assert_eq!(vless.transport.host, Some("front.example.com".to_string()));
        Ok(())
    }

    #[test]
    fn converts_vless_inline_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-inline-tls",
      "listen": "127.0.0.1",
      "listen_port": 9443,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf" }
      ],
      "tls": {
        "enabled": true,
        "certificate": ["cert-line-1", "cert-line-2"],
        "key": ["key-line-1", "key-line-2"]
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Vless(vless) = config.inbounds[0].to_server_config()? else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.cert_path, PathBuf::new());
        assert_eq!(vless.key_path, PathBuf::new());
        assert_eq!(vless.certificates, vec!["cert-line-1\ncert-line-2"]);
        assert_eq!(vless.key.as_deref(), Some("key-line-1\nkey-line-2"));
        Ok(())
    }

    #[test]
    fn converts_anytls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "anytls",
      "tag": "anytls",
      "listen": "127.0.0.1",
      "listen_port": 8444,
      "users": [
        { "password": "primary-pass" },
        { "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key"
      },
      "padding_scheme": ["stop=8"]
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::AnyTls(anytls) = config.inbounds[0].to_server_config()? else {
            bail!("expected AnyTLS")
        };
        assert_eq!(anytls.listen, "127.0.0.1:8444".parse()?);
        assert_eq!(anytls.password, "primary-pass");
        assert_eq!(anytls.users, vec!["alice-pass".to_string()]);
        assert_eq!(anytls.cert_path, PathBuf::from("server.crt"));
        assert_eq!(anytls.key_path, PathBuf::from("server.key"));
        assert_eq!(anytls.padding_scheme, vec!["stop=8".to_string()]);
        Ok(())
    }

    #[test]
    fn converts_mieru_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "mieru",
      "tag": "mieru",
      "listen": "127.0.0.1",
      "listen_port": 8964,
      "users": [
        { "username": "default", "password": "primary-pass" },
        { "username": "alice", "password": "alice-pass" }
      ],
      "transport": "udp",
      "mtu": 1400,
      "user_hint_mandatory": true
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Mieru(mieru) = config.inbounds[0].to_server_config()? else {
            bail!("expected Mieru")
        };
        assert_eq!(mieru.listen, "127.0.0.1:8964".parse()?);
        assert_eq!(mieru.username, "default");
        assert_eq!(mieru.password, "primary-pass");
        assert_eq!(mieru.users.len(), 1);
        assert_eq!(mieru.mtu, 1400);
        assert!(mieru.user_hint_mandatory);
        assert_eq!(mieru.transport, MieruTransport::Udp);
        Ok(())
    }

    #[test]
    fn converts_hysteria2_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "127.0.0.1",
      "listen_port": 8445,
      "users": [
        { "password": "primary-pass" },
        { "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key",
        "alpn": ["h3"]
      },
      "obfs": {
        "type": "salamander",
        "password": "obfs-pass"
      },
      "up_mbps": 5,
      "down_mbps": 10
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Hysteria2(hy2) = config.inbounds[0].to_server_config()? else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hy2.listen, "127.0.0.1:8445".parse()?);
        assert_eq!(hy2.password, "primary-pass");
        assert_eq!(hy2.users, vec!["alice-pass".to_string()]);
        assert_eq!(hy2.cert_path, PathBuf::from("server.crt"));
        assert_eq!(hy2.key_path, PathBuf::from("server.key"));
        assert_eq!(hy2.obfs, Some("salamander".to_string()));
        assert_eq!(hy2.obfs_password, Some("obfs-pass".to_string()));
        assert_eq!(hy2.upload_bandwidth, Some(5));
        assert_eq!(hy2.cc_rx, "1250000");
        assert!(hy2.udp);
        Ok(())
    }

    #[test]
    fn converts_tuic_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "127.0.0.1",
      "listen_port": 9445,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf", "password": "primary-pass" },
        { "uuid": "433722e1-0f8c-4724-9089-d5bc6d0c51ef", "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key",
        "alpn": ["h3"]
      },
      "congestion_control": "bbr",
      "heartbeat": "15s"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Tuic(tuic) = config.inbounds[0].to_server_config()? else {
            bail!("expected TUIC")
        };
        assert_eq!(tuic.listen, "127.0.0.1:9445".parse()?);
        assert_eq!(tuic.uuid, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(tuic.password, "primary-pass");
        assert_eq!(
            tuic.users,
            vec!["433722e1-0f8c-4724-9089-d5bc6d0c51ef:alice-pass".to_string()]
        );
        assert_eq!(tuic.cert_path, PathBuf::from("server.crt"));
        assert_eq!(tuic.key_path, PathBuf::from("server.key"));
        assert_eq!(tuic.congestion_control, "bbr");
        assert_eq!(tuic.alpn_protocols, vec!["h3".to_string()]);
        assert_eq!(tuic.heartbeat_interval_secs, 15);
        Ok(())
    }

    #[test]
    fn converts_shadowsocks_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-udp",
      "listen": "127.0.0.1",
      "listen_port": 8388,
      "network": "udp",
      "method": "aes-128-gcm",
      "password": "primary-pass",
      "users": [
        { "name": "alice", "password": "alice-pass" }
      ]
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Shadowsocks(shadowsocks) =
            config.inbounds[0].to_server_config()?
        else {
            bail!("expected Shadowsocks")
        };
        assert_eq!(shadowsocks.listen, "127.0.0.1:8388".parse()?);
        assert_eq!(shadowsocks.method, "aes-128-gcm");
        assert_eq!(shadowsocks.password, "primary-pass");
        assert_eq!(shadowsocks.users, vec!["alice:alice-pass".to_string()]);
        assert!(!shadowsocks.tcp);
        assert!(shadowsocks.udp);
        Ok(())
    }

    #[test]
    fn converts_trojan_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-ws",
      "listen": "127.0.0.1",
      "listen_port": 9443,
      "users": [
        { "password": "primary-pass" },
        { "password": "alice-pass" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": ["server.crt"],
        "key_path": "server.key",
        "ech": { "key_path": "trojan-ech.keys" }
      },
      "transport": {
        "type": "ws",
        "path": "/trojan"
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Trojan(trojan) = config.inbounds[0].to_server_config()? else {
            bail!("expected Trojan")
        };
        assert_eq!(trojan.listen, "127.0.0.1:9443".parse()?);
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
    fn converts_vmess_tls_inbound_to_server_config() -> Result<()> {
        let json = r#"
{
  "inbounds": [
    {
      "type": "vmess",
      "tag": "vmess-h2",
      "listen": "127.0.0.1",
      "listen_port": 9444,
      "users": [
        { "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf", "alterId": 0 },
        { "uuid": "433722e1-0f8c-4724-9089-d5bc6d0c51ef" }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "server.crt",
        "key_path": "server.key",
        "alpn": ["h2"],
        "ech": { "key_path": "vmess-ech.keys" }
      },
      "transport": {
        "type": "http",
        "path": "/vmess"
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxServerConfig::Vmess(vmess) = config.inbounds[0].to_server_config()? else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.listen, "127.0.0.1:9444".parse()?);
        assert!(vmess.tls);
        assert_eq!(vmess.cert_path, Some(PathBuf::from("server.crt")));
        assert_eq!(vmess.key_path, Some(PathBuf::from("server.key")));
        assert_eq!(vmess.user_id, "a3482e88-686a-4a58-8126-99c9df64b7bf");
        assert_eq!(
            vmess.users,
            vec!["433722e1-0f8c-4724-9089-d5bc6d0c51ef".to_string()]
        );
        assert_eq!(vmess.transport.kind, VlessTransportKind::Http2);
        assert_eq!(vmess.transport.path, "/vmess");
        assert!(vmess.ech.is_some());
        Ok(())
    }

    #[test]
    fn parses_shadowsocks_udp_over_tcp_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-uot",
      "server": "example.com",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret",
      "network": "tcp",
      "udp_over_tcp": { "enabled": true, "version": 2 }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-no-uot",
      "server": "example.com",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret",
      "network": "tcp",
      "udp_over_tcp": { "enabled": false, "version": 1 }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Shadowsocks(shadowsocks) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Shadowsocks")
        };
        assert!(shadowsocks.udp);
        assert!(shadowsocks.udp_over_tcp);
        let SingBoxClientConfig::Shadowsocks(disabled) =
            config.outbounds[1].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Shadowsocks")
        };
        assert!(!disabled.udp);
        assert!(!disabled.udp_over_tcp);
        Ok(())
    }

    #[test]
    fn parses_vless_reality_outbound() -> Result<()> {
        let json = r#"
{
  "inbounds": [{ "type": "mixed", "listen": "127.0.0.1", "listen_port": 7890 }],
  "outbounds": [{
    "type": "vless",
    "tag": "proxy",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "flow": "xtls-rprx-vision",
    "packet_encoding": "xudp",
    "tls": {
      "enabled": true,
      "server_name": "www.example.com",
      "utls": { "enabled": true, "fingerprint": "chrome" },
      "reality": {
        "enabled": true,
        "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "short_id": "a1b2"
      }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(
            config.local_socks_listen()?,
            Some("127.0.0.1:7890".parse()?)
        );
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.sni, "www.example.com");
        assert_eq!(vless.client_fingerprint, Some(UtlsFingerprint::Chrome));
        assert!(vless.reality.is_some());
        Ok(())
    }

    #[test]
    fn parses_vless_raw_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "vless-raw",
    "server": "example.com",
    "server_port": 80,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": false }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
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
    fn rejects_sing_box_multiplex() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "muxed",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true },
    "multiplex": { "enabled": true }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("multiplex must be explicit");
        assert!(error.to_string().contains("not wire-compatible"));
        Ok(())
    }

    #[test]
    fn parses_vless_websocket_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "vless-ws",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true },
    "transport": {
      "type": "ws",
      "path": "/vless",
      "headers": { "Host": "edge.example.com" }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
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
    fn parses_trojan_websocket_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "trojan",
    "tag": "trojan-ws",
    "server": "example.com",
    "server_port": 443,
    "password": "secret",
    "tls": { "enabled": true },
    "transport": {
      "type": "ws",
      "path": "/trojan",
      "headers": { "Host": "edge.example.com" }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Trojan(trojan) =
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
    fn parses_vmess_websocket_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vmess",
    "tag": "vmess-ws",
    "server": "example.com",
    "server_port": 80,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "alter_id": 0,
    "packet_encoding": "packetaddr",
    "transport": {
      "type": "ws",
      "path": "/vmess",
      "headers": { "Host": "edge.example.com" }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vmess(vmess) =
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
    "type": "vmess",
    "tag": "vmess-xudp",
    "server": "example.com",
    "server_port": 80,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "alter_id": 0,
    "packet_encoding": "xudp"
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vmess(vmess) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.packet_encoding, "xudp");
        Ok(())
    }

    #[test]
    fn parses_vless_http2_transport() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "vless",
    "tag": "vless-h2",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true, "alpn": "h2" },
    "transport": {
      "type": "http2",
      "path": "/h2",
      "host": "edge.example.com"
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
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
    "type": "vless",
    "tag": "vless-grpc",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true, "alpn": "h2" },
    "transport": {
      "type": "grpc",
      "service_name": "TunService",
      "headers": { "Host": "edge.example.com" }
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
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
    "type": "vless",
    "tag": "vless-xhttp",
    "server": "example.com",
    "server_port": 443,
    "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
    "tls": { "enabled": true, "alpn": "http/1.1" },
    "transport": {
      "type": "xhttp",
      "path": "/xhttp",
      "host": "edge.example.com",
      "mode": "stream-one"
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
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
    fn parses_hysteria2_udp_network() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "hysteria2",
    "tag": "hy2-udp",
    "server": "example.com",
    "server_port": 443,
    "password": "secret",
    "network": "udp",
    "up_mbps": 10,
    "down_mbps": 80,
    "tls": {
      "enabled": true,
      "server_name": "hy2.example.com",
      "insecure": true,
      "disable_system_root": true,
      "alpn": ["h3"],
      "certificate_path": ["ca.pem", "backup-ca.pem"],
      "certificate": ["hy2-inline-ca"]
    },
    "obfs": {
      "type": "salamander",
      "password": "obfs-pass"
    }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Hysteria2(hysteria2) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hysteria2.server_host, "example.com");
        assert_eq!(hysteria2.server_port, 443);
        assert_eq!(hysteria2.password, "secret");
        assert_eq!(hysteria2.sni, "hy2.example.com");
        assert!(hysteria2.insecure);
        assert!(hysteria2.disable_system_roots);
        assert_eq!(
            hysteria2.ca_cert_paths,
            vec![PathBuf::from("ca.pem"), PathBuf::from("backup-ca.pem")]
        );
        assert_eq!(hysteria2.ca_certificates, vec!["hy2-inline-ca"]);
        assert!(hysteria2.udp);
        assert_eq!(hysteria2.obfs.as_deref(), Some("salamander"));
        assert_eq!(hysteria2.obfs_password.as_deref(), Some("obfs-pass"));
        assert_eq!(hysteria2.upload_bandwidth, Some(10));
        assert_eq!(hysteria2.download_bandwidth, Some(80));
        Ok(())
    }

    #[test]
    fn parses_client_custom_tls_roots() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-tls",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "tls": {
        "enabled": true,
        "certificate_path": ["vless-ca.pem"],
        "certificate": ["vless-inline-ca"]
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-tls",
      "server": "vmess.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "alter_id": 0,
      "tls": {
        "enabled": true,
        "certificate_path": "vmess-ca.pem",
        "certificate": "vmess-inline-ca"
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-tls",
      "server": "trojan.example.com",
      "server_port": 443,
      "password": "secret",
      "tls": {
        "enabled": true,
        "certificate_path": "trojan-ca.pem",
        "certificate": "trojan-inline-ca"
      }
    },
    {
      "type": "anytls",
      "tag": "anytls",
      "server": "anytls.example.com",
      "server_port": 443,
      "password": "secret",
      "tls": {
        "enabled": true,
        "certificate_path": "anytls-ca.pem",
        "disable_system_root": true,
        "certificate": ["anytls-inline-ca"],
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-v5",
      "server": "tuic.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "password": "secret",
      "tls": {
        "enabled": true,
        "certificate_path": "tuic-ca.pem",
        "certificate": "tuic-inline-ca"
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Vless(vless) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VLESS")
        };
        assert_eq!(vless.ca_cert_paths, vec![PathBuf::from("vless-ca.pem")]);
        assert_eq!(vless.ca_certificates, vec!["vless-inline-ca"]);

        let SingBoxClientConfig::Vmess(vmess) =
            config.outbounds[1].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected VMess")
        };
        assert_eq!(vmess.ca_cert_paths, vec![PathBuf::from("vmess-ca.pem")]);
        assert_eq!(vmess.ca_certificates, vec!["vmess-inline-ca"]);

        let SingBoxClientConfig::Trojan(trojan) =
            config.outbounds[2].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Trojan")
        };
        assert_eq!(trojan.ca_cert_paths, vec![PathBuf::from("trojan-ca.pem")]);
        assert_eq!(trojan.ca_certificates, vec!["trojan-inline-ca"]);

        let SingBoxClientConfig::AnyTls(anytls) =
            config.outbounds[3].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected AnyTLS")
        };
        assert_eq!(anytls.ca_cert_paths, vec![PathBuf::from("anytls-ca.pem")]);
        assert_eq!(anytls.ca_certificates, vec!["anytls-inline-ca"]);
        assert!(anytls.disable_system_roots);
        assert_eq!(anytls.client_fingerprint, Some(UtlsFingerprint::Chrome));

        let SingBoxClientConfig::Tuic(tuic) =
            config.outbounds[4].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected TUIC")
        };
        assert_eq!(tuic.ca_cert_paths, vec![PathBuf::from("tuic-ca.pem")]);
        assert_eq!(tuic.ca_certificates, vec!["tuic-inline-ca"]);
        Ok(())
    }

    #[test]
    fn rejects_singbox_unsupported_tls_options() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-min-version",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "tls": {
        "enabled": true,
        "min_version": "1.3"
      }
    },
    {
      "type": "naive",
      "tag": "naive-disable-sni",
      "server": "naive.example.com",
      "server_port": 443,
      "tls": {
        "enabled": true,
        "disable_sni": true
      }
    },
    {
      "type": "http",
      "tag": "http-utls-extra",
      "server": "proxy.example.com",
      "server_port": 443,
      "tls": {
        "enabled": true,
        "utls": {
          "enabled": true,
          "fingerprint": "chrome",
          "randomized": true
        }
      }
    }
  ],
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-mtls",
      "listen_port": 8443,
      "users": [{ "password": "secret" }],
      "tls": {
        "enabled": true,
        "client_authentication": "require"
      }
    },
    {
      "type": "anytls",
      "tag": "anytls-unknown-tls",
      "listen_port": 8444,
      "users": [{ "password": "secret" }],
      "tls": {
        "enabled": true,
        "unexpected_tls_field": true
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let version_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("TLS min_version must not be ignored");
        assert!(version_error.to_string().contains("tls.min_version"));

        let disable_sni_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("TLS disable_sni must not be ignored");
        assert!(disable_sni_error.to_string().contains("tls.disable_sni"));

        let utls_error = config.outbounds[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unknown uTLS fields must not be ignored");
        assert!(utls_error.to_string().contains("tls.utls"));

        let mtls_error = config.inbounds[0]
            .to_server_config()
            .err()
            .context("TLS client_authentication must not be ignored")?;
        assert!(mtls_error.to_string().contains("tls.client_authentication"));

        let unknown_error = config.inbounds[1]
            .to_server_config()
            .err()
            .context("unknown TLS fields must not be ignored")?;
        assert!(unknown_error.to_string().contains("unsupported fields"));
        Ok(())
    }

    #[test]
    fn rejects_singbox_unsupported_profile_fields() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-dialer",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "tls": { "enabled": true },
      "dialer_proxy": "bootstrap"
    },
    {
      "type": "vless",
      "tag": "vless-ws-early",
      "server": "vless.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "tls": { "enabled": true },
      "transport": {
        "type": "ws",
        "path": "/vless",
        "max_early_data": 2048
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss-mux-fields",
      "server": "ss.example.com",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret",
      "multiplex": {
        "enabled": false,
        "protocol": "smux"
      }
    }
  ],
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-sniff",
      "listen_port": 8443,
      "users": [{ "password": "secret" }],
      "tls": { "enabled": true, "certificate_path": "server.crt", "key_path": "server.key" },
      "sniff": true
    },
    {
      "type": "hysteria2",
      "tag": "hy2-obfs-extra",
      "listen_port": 8444,
      "password": "secret",
      "tls": { "enabled": true, "certificate_path": "server.crt", "key_path": "server.key" },
      "obfs": {
        "type": "salamander",
        "password": "obfs-pass",
        "padding": true
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let dialer_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported outbound fields must not be ignored");
        assert!(dialer_error.to_string().contains("dialer_proxy"));

        let transport_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("unsupported transport fields must not be ignored");
        assert!(transport_error.to_string().contains("transport"));
        assert!(transport_error.to_string().contains("max_early_data"));

        let multiplex_error = config.outbounds[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("disabled multiplex settings must not be ignored");
        assert!(multiplex_error.to_string().contains("multiplex"));

        let inbound_error = config.inbounds[0]
            .to_server_config()
            .err()
            .context("unsupported inbound fields must not be ignored")?;
        assert!(inbound_error.to_string().contains("sniff"));

        let obfs_error = config.inbounds[1]
            .to_server_config()
            .err()
            .context("unsupported obfs fields must not be ignored")?;
        assert!(obfs_error.to_string().contains("obfs"));
        assert!(obfs_error.to_string().contains("padding"));
        Ok(())
    }

    #[test]
    fn rejects_hysteria2_port_hopping() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "hysteria2",
    "tag": "hy2-hop",
    "server": "example.com",
    "server_ports": [443, 8443],
    "hop_interval": "30s",
    "password": "secret",
    "tls": { "enabled": true }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("port hopping must be explicit");
        assert!(error.to_string().contains("port hopping"));
        Ok(())
    }

    #[test]
    fn parses_hysteria2_upload_bandwidth() -> Result<()> {
        let json = r#"
{
  "outbounds": [{
    "type": "hysteria2",
    "tag": "hy2-up",
    "server": "example.com",
    "server_port": 443,
    "password": "secret",
    "up_mbps": 10,
    "tls": { "enabled": true }
  }]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Hysteria2(hysteria2) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Hysteria2")
        };
        assert_eq!(hysteria2.upload_bandwidth, Some(10));
        Ok(())
    }

    #[test]
    fn parses_naive_and_tuic_outbounds() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "naive",
      "tag": "naive-h3",
      "server": "naive.example.com",
      "server_port": 443,
      "username": "user",
      "password": "pass",
      "quic": true,
      "quic_congestion_control": "reno",
      "udp_over_tcp": { "enabled": true, "version": 2 },
      "tls": {
        "enabled": true,
        "server_name": "front.example.com",
        "certificate_path": ["ca.pem", "backup-ca.pem"],
        "certificate": "naive-inline-ca"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic-v5",
      "server": "tuic.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "password": "secret",
      "network": "tcp",
      "udp_relay_mode": "quic",
      "congestion_control": "bbr",
      "heartbeat": "15s",
      "tls": {
        "enabled": true,
        "server_name": "front.example.com",
        "alpn": ["h3"],
        "certificate": ["tuic-inline-ca"]
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Naive(naive) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected Naive")
        };
        assert_eq!(naive.server_host, "naive.example.com");
        assert_eq!(naive.sni, "front.example.com");
        assert!(!naive.insecure);
        assert_eq!(
            naive.ca_cert_paths,
            vec![PathBuf::from("ca.pem"), PathBuf::from("backup-ca.pem")]
        );
        assert_eq!(naive.ca_certificates, vec!["naive-inline-ca"]);
        assert!(naive.quic);
        assert!(naive.udp_over_tcp);
        assert_eq!(naive.quic_congestion_control, "reno");

        let SingBoxClientConfig::Tuic(tuic) =
            config.outbounds[1].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected TUIC")
        };
        assert_eq!(tuic.server_host, "tuic.example.com");
        assert_eq!(tuic.sni, "front.example.com");
        assert!(!tuic.udp);
        assert_eq!(tuic.udp_relay_mode, "quic");
        assert_eq!(tuic.congestion_control, "bbr");
        assert_eq!(tuic.alpn_protocols, vec!["h3".to_string()]);
        assert_eq!(tuic.heartbeat_interval_secs, 15);
        assert_eq!(tuic.ca_certificates, vec!["tuic-inline-ca"]);
        Ok(())
    }

    #[test]
    fn rejects_unmapped_naive_options() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "naive",
      "tag": "naive-uot-v1",
      "server": "naive.example.com",
      "server_port": 443,
      "udp_over_tcp": { "enabled": true, "version": 1 },
      "tls": { "enabled": true }
    },
    {
      "type": "naive",
      "tag": "naive-concurrency",
      "server": "naive.example.com",
      "server_port": 443,
      "insecure_concurrency": 2,
      "tls": { "enabled": true }
    },
    {
      "type": "naive",
      "tag": "naive-ech",
      "server": "naive.example.com",
      "server_port": 443,
      "tls": {
        "enabled": true,
        "ech": { "enabled": true }
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let uot_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("UOT v1 must be explicit");
        assert!(uot_error.to_string().contains("version 2"));

        let concurrency_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("insecure_concurrency must be explicit");
        assert!(
            concurrency_error
                .to_string()
                .contains("insecure_concurrency")
        );

        let ech_error = config.outbounds[2]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("ECH must be explicit");
        assert!(ech_error.to_string().contains("ECH"));
        Ok(())
    }

    #[test]
    fn rejects_unmapped_tuic_options() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "tuic",
      "tag": "tuic-0rtt",
      "server": "tuic.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "password": "secret",
      "zero_rtt_handshake": true,
      "tls": { "enabled": true }
    },
    {
      "type": "tuic",
      "tag": "tuic-uos",
      "server": "tuic.example.com",
      "server_port": 443,
      "uuid": "a3482e88-686a-4a58-8126-99c9df64b7bf",
      "password": "secret",
      "udp_over_stream": true,
      "tls": { "enabled": true }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let zero_rtt_error = config.outbounds[0]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("0-RTT must be explicit");
        assert!(zero_rtt_error.to_string().contains("zero_rtt"));
        let udp_over_stream_error = config.outbounds[1]
            .to_client_config("127.0.0.1:1080".parse()?)
            .expect_err("udp_over_stream must be explicit");
        assert!(
            udp_over_stream_error
                .to_string()
                .contains("udp_over_stream")
        );
        Ok(())
    }

    #[test]
    fn converts_http_outbound_to_client_config() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "http",
      "tag": "http-proxy",
      "server": "proxy.example.com",
      "server_port": 8443,
      "username": "user",
      "password": "pass",
      "headers": {
        "X-Test": "value"
      },
      "tls": {
        "enabled": true,
        "server_name": "front.example.com",
        "insecure": true,
        "alpn": "http/1.1",
        "utls": { "enabled": true, "fingerprint": "chrome" }
      }
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::HttpProxy(http) =
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
  "outbounds": [
    {
      "type": "socks",
      "tag": "socks-proxy",
      "server": "proxy.example.com",
      "server_port": 1080,
      "username": "user",
      "password": "pass",
      "network": "tcp+udp"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::SocksProxy(socks) =
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
    { "type": "direct", "tag": "direct-out" },
    { "type": "block", "tag": "block-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let SingBoxClientConfig::Route(direct) =
            config.outbounds[0].to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected direct route client")
        };
        assert_eq!(direct.default, RouteDecision::Direct);
        let SingBoxClientConfig::Route(block) =
            config.outbounds[1].to_client_config("127.0.0.1:1081".parse()?)?
        else {
            bail!("expected block route client")
        };
        assert_eq!(block.default, RouteDecision::Block);
        Ok(())
    }

    #[test]
    fn resolves_selector_outbound_default() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "select",
      "outbounds": ["direct-out", "block-out"],
      "default": "block-out"
    },
    { "type": "direct", "tag": "direct-out" },
    { "type": "block", "tag": "block-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(config.resolved_outbound("select")?.name(), "block-out");
        let SingBoxClientConfig::Route(block) = config
            .resolved_outbound_profile("select")?
            .to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected selected block route client")
        };
        assert_eq!(block.default, RouteDecision::Block);
        Ok(())
    }

    #[test]
    fn resolves_selector_first_outbound_without_default() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "select",
      "outbounds": ["direct-out", "block-out"]
    },
    { "type": "direct", "tag": "direct-out" },
    { "type": "block", "tag": "block-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(config.resolved_outbound("select")?.name(), "direct-out");
        Ok(())
    }

    #[test]
    fn rejects_selector_cycle() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "a",
      "outbounds": ["b"],
      "default": "b"
    },
    {
      "type": "selector",
      "tag": "b",
      "outbounds": ["a"],
      "default": "a"
    }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .resolved_outbound("a")
            .expect_err("selector cycles must fail");
        assert!(error.to_string().contains("cycle"));
        Ok(())
    }

    #[test]
    fn resolves_single_urltest_policy_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["direct-out"]
    },
    { "type": "direct", "tag": "direct-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        assert_eq!(config.resolved_outbound("auto")?.name(), "direct-out");
        let SingBoxClientConfig::Route(route) = config
            .resolved_outbound_profile("auto")?
            .to_client_config("127.0.0.1:1080".parse()?)?
        else {
            bail!("expected static urltest direct route client")
        };
        assert_eq!(route.default, RouteDecision::Direct);
        Ok(())
    }

    #[test]
    fn rejects_selector_runtime_policy_fields() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "select",
      "outbounds": ["direct-out"],
      "interrupt_exist_connections": false
    },
    { "type": "direct", "tag": "direct-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .resolved_outbound("select")
            .expect_err("selector runtime policy must not be ignored");
        assert!(error.to_string().contains("interrupt_exist_connections"));
        Ok(())
    }

    #[test]
    fn rejects_urltest_runtime_policy_fields() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["direct-out"],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "3m"
    },
    { "type": "direct", "tag": "direct-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .resolved_outbound("auto")
            .expect_err("urltest runtime policy must not be ignored");
        assert!(error.to_string().contains("active latency testing"));
        assert!(error.to_string().contains("url"));
        Ok(())
    }

    #[test]
    fn rejects_urltest_policy_outbound() -> Result<()> {
        let json = r#"
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["direct-out", "block-out"]
    },
    { "type": "direct", "tag": "direct-out" },
    { "type": "block", "tag": "block-out" }
  ]
}
"#;
        let config: SingBoxConfig = serde_json::from_str(json)?;
        let error = config
            .resolved_outbound("auto")
            .expect_err("urltest requires active latency selection");
        assert!(error.to_string().contains("single-outbound"));
        Ok(())
    }
