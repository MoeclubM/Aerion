use super::*;

#[test]
fn parses_client_example() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.client.example.toml");
    assert!(matches!(
        load_config(&path).expect("client config"),
        FileConfig::Aerion(config) if config.clients.len() == 12 && config.servers.is_empty()
    ));
}

#[test]
fn parses_server_example() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.server.example.toml");
    assert!(matches!(
        load_config(&path).expect("server config"),
        FileConfig::Aerion(config) if config.clients.is_empty() && config.servers.len() == 9
    ));
}

#[test]
fn parses_mihomo_yaml() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.mihomo.example.yaml");
    assert!(matches!(
        load_config(&path).expect("mihomo config"),
        FileConfig::Mihomo(config) if config.proxies.len() == 13
    ));
}

#[test]
fn parses_xray_json() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.xray.example.json");
    assert!(matches!(
        load_config(&path).expect("xray config"),
        FileConfig::Xray(config) if config.outbounds.len() == 11
    ));
}

#[test]
fn parses_singbox_json() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.singbox.example.json");
    assert!(matches!(
        load_config(&path).expect("sing-box config"),
        FileConfig::SingBox(config) if config.outbounds.len() == 13
    ));
}

#[test]
fn detects_json_proxy_format_from_inbounds() -> Result<()> {
    let sing_box = load_jsonc_value(
        r#"{ "inbounds": [{ "type": "naive", "listen": "127.0.0.1", "listen_port": 443 }] }"#,
    )?;
    assert!(matches!(
        detect_json_proxy_format(&sing_box)?,
        JsonProxyFormat::SingBox
    ));

    let xray = load_jsonc_value(
        r#"{ "inbounds": [{ "protocol": "vless", "listen": "127.0.0.1", "port": 443 }] }"#,
    )?;
    assert!(matches!(
        detect_json_proxy_format(&xray)?,
        JsonProxyFormat::Xray
    ));
    Ok(())
}

#[test]
fn compat_examples_convert_all_profiles() -> Result<()> {
    let listen = "127.0.0.1:1080".parse()?;

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.mihomo.example.yaml");
    let FileConfig::Mihomo(config) = load_config(&path)? else {
        bail!("expected mihomo config")
    };
    for proxy in &config.proxies {
        proxy
            .to_client_config(listen)
            .with_context(|| format!("convert mihomo proxy {}", proxy.name()))?;
    }

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.xray.example.json");
    let FileConfig::Xray(config) = load_config(&path)? else {
        bail!("expected xray config")
    };
    for outbound in &config.outbounds {
        outbound
            .to_client_config(listen)
            .with_context(|| format!("convert xray outbound {}", outbound.name()))?;
    }

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.singbox.example.json");
    let FileConfig::SingBox(config) = load_config(&path)? else {
        bail!("expected sing-box config")
    };
    for outbound in &config.outbounds {
        outbound
            .to_client_config(listen)
            .with_context(|| format!("convert sing-box outbound {}", outbound.name()))?;
    }

    Ok(())
}

#[test]
fn strips_json_comments_without_touching_strings() -> Result<()> {
    let value = load_jsonc_value(r#"{ "url": "https://example.com/a//b", /* c */ "n": 1 }"#)?;
    assert_eq!(value["url"], "https://example.com/a//b");
    assert_eq!(value["n"], 1);
    Ok(())
}
