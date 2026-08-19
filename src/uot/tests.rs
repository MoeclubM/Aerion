use super::*;

#[test]
fn roundtrips_associate_packet() {
    let target = ProxyTarget::Domain("example.com".to_string(), 53);
    let packet = encode_associate_packet(&target, b"abc").unwrap();
    let (decoded, payload) = decode_associate_packet(&packet).unwrap();
    assert_eq!(decoded, target);
    assert_eq!(payload, b"abc");
}

#[test]
fn parses_socks_udp_packet() {
    let target = ProxyTarget::Ip("1.2.3.4:53".parse().unwrap());
    let packet = encode_socks_udp_packet(&target, b"abc").unwrap();
    let (decoded, payload) = parse_socks_udp_packet(&packet).unwrap();
    assert_eq!(decoded, target);
    assert_eq!(payload, b"abc");
}

#[test]
fn legacy_request_preserves_initial_packet() {
    let target = ProxyTarget::Domain(LEGACY_MAGIC_ADDRESS.to_string(), 0);
    let (request, packet) = decode_request_for_target(&target, b"abc").unwrap();
    assert!(!request.is_connect);
    assert_eq!(packet, b"abc");
}

#[test]
fn v2_request_can_be_split_and_preserves_initial_packet() {
    let target = magic_target();
    let request = encode_v2_associate_request().unwrap();
    assert!(!v2_request_complete(&request[..3]).unwrap());
    assert!(v2_request_complete(&request).unwrap());

    let packet =
        encode_associate_packet(&ProxyTarget::Ip("1.2.3.4:53".parse().unwrap()), b"abc").unwrap();
    let mut payload = request;
    payload.extend_from_slice(&packet);
    let (decoded, initial_packet) = decode_request_for_target(&target, &payload).unwrap();
    assert!(!decoded.is_connect);
    assert_eq!(initial_packet, packet);
}

#[test]
fn reassembles_stream_packets_from_pending_buffer() {
    let target = ProxyTarget::Ip("1.2.3.4:53".parse().unwrap());
    let request = UotRequest {
        is_connect: false,
        destination: target.clone(),
    };
    let packet = encode_associate_packet(&target, b"hello").unwrap();
    let mut pending = packet[..3].to_vec();
    assert!(
        take_stream_packet(&request, &mut pending)
            .unwrap()
            .is_none()
    );
    pending.extend_from_slice(&packet[3..]);
    let (decoded, payload, _) = take_stream_packet(&request, &mut pending)
        .unwrap()
        .expect("complete packet");
    assert_eq!(decoded, target);
    assert_eq!(payload, b"hello");
    assert!(pending.is_empty());
}
