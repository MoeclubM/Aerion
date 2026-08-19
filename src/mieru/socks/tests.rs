use super::*;

#[test]
fn parses_connect_request_with_shared_target_decoder() -> Result<()> {
    let request = vec![
        SOCKS_VERSION,
        SOCKS_CMD_CONNECT,
        0,
        SOCKS_ATYP_DOMAIN,
        11,
        b'e',
        b'x',
        b'a',
        b'm',
        b'p',
        b'l',
        b'e',
        b'.',
        b'c',
        b'o',
        b'm',
        0x01,
        0xbb,
    ];
    match parse_socks_request(request)? {
        SocksRequest::Connect(ProxyTarget::Domain(host, port)) => {
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
        }
        _ => panic!("unexpected SOCKS request"),
    }
    Ok(())
}
