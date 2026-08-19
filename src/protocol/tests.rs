use super::*;

#[test]
fn encodes_and_decodes_domain_target() {
    let target = ProxyTarget::Domain("example.com".to_string(), 443);
    let encoded = encode_target(&target).unwrap();
    let (decoded, tail) = decode_target(&encoded).unwrap();
    assert_eq!(decoded, target);
    assert!(tail.is_empty());
}

#[test]
fn encodes_and_decodes_ipv4_target() {
    let target = ProxyTarget::Ip("127.0.0.1:8080".parse().unwrap());
    let encoded = encode_target(&target).unwrap();
    let (decoded, tail) = decode_target(&encoded).unwrap();
    assert_eq!(decoded, target);
    assert!(tail.is_empty());
}

#[test]
fn encodes_ipv4_mapped_ipv6_as_ipv4() {
    let mapped: SocketAddr = "[::ffff:127.0.0.1]:8080".parse().unwrap();
    let encoded = encode_target(&ProxyTarget::Ip(mapped)).unwrap();
    assert_eq!(encoded[0], 0x01);
    let (decoded, tail) = decode_target(&encoded).unwrap();
    assert_eq!(decoded, ProxyTarget::Ip("127.0.0.1:8080".parse().unwrap()));
    assert!(tail.is_empty());
}
