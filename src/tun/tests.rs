use super::*;

#[test]
fn builds_tun2proxy_args() -> Result<()> {
    let mut config = TunConfig::new("socks5://127.0.0.1:1080");
    config.tun_name = Some("tun0".to_string());
    config.setup = true;
    config.dns = TunDnsStrategy::Virtual;
    config.dns_addr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    config.bypass = vec!["203.0.113.8/32".to_string()];
    config.ipv6 = true;
    let args = config.to_tun2proxy_args()?;
    assert_eq!(args.proxy.addr, "127.0.0.1:1080".parse::<SocketAddr>()?);
    assert_eq!(args.tun.as_deref(), Some("tun0"));
    assert!(args.setup);
    assert_eq!(args.dns, TunDnsStrategy::Virtual);
    assert_eq!(args.dns_addr, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    assert_eq!(args.bypass.len(), 1);
    assert!(args.ipv6_enabled);
    Ok(())
}

#[test]
fn rejects_tun_name_with_fd() {
    let mut config = TunConfig::new("socks5://127.0.0.1:1080");
    config.tun_name = Some("tun0".to_string());
    config.tun_fd = Some(3);
    let error = config
        .to_tun2proxy_args()
        .expect_err("tun name and fd must be exclusive");
    assert!(error.to_string().contains("mutually exclusive"));
}

#[test]
fn builds_ios_packet_flow_socket_fd_config() {
    let config = TunConfig::ios_packet_flow_socket_fd("socks5://127.0.0.1:1080", 7, false);
    assert_eq!(config.tun_fd, Some(7));
    assert!(!config.close_fd_on_drop);
    assert!(config.packet_information);
    assert!(!config.setup);
}
