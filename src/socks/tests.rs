use super::*;

#[test]
fn udp_associate_uses_upstream_ip_for_unspecified_bind() -> Result<()> {
    assert_eq!(
        normalize_udp_bind("0.0.0.0:5300".parse()?, "192.0.2.10:1080".parse()?),
        "192.0.2.10:5300".parse::<SocketAddr>()?
    );
    assert_eq!(
        normalize_udp_bind("[::]:5300".parse()?, "[2001:db8::1]:1080".parse()?),
        "[2001:db8::1]:5300".parse::<SocketAddr>()?
    );
    assert_eq!(
        normalize_udp_bind("198.51.100.5:5300".parse()?, "192.0.2.10:1080".parse()?),
        "198.51.100.5:5300".parse::<SocketAddr>()?
    );
    Ok(())
}
