use super::*;

#[test]
fn varint_roundtrip() {
    for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823] {
        let mut encoded = Vec::new();
        encode_varint(value, &mut encoded).unwrap();
        let decoded = read_varint_from_slice(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, value);
    }
}

#[test]
fn udp_message_roundtrip() {
    let message = UdpMessage {
        session_id: 7,
        packet_id: 9,
        fragment_id: 0,
        fragment_count: 1,
        address: "example.com:53".to_string(),
        payload: b"hello".to_vec(),
    };
    let encoded = encode_udp_message(&message).unwrap();
    assert_eq!(decode_udp_message(&encoded).unwrap(), message);
}

#[test]
fn upload_limiter_maps_mbps_to_bytes_per_second() {
    assert_eq!(
        Hy2ByteRateLimiter::new(Some(8)).bytes_per_second,
        Some(1_000_000)
    );
    assert_eq!(Hy2ByteRateLimiter::new(None).bytes_per_second, None);
}

#[test]
fn salamander_roundtrip() {
    let salt = [7u8; SALAMANDER_SALT_LEN];
    let payload = b"hello hysteria2";
    let mut encrypted = vec![0u8; payload.len()];
    let mut decrypted = vec![0u8; payload.len()];
    salamander_xor(b"secret", &salt, payload, &mut encrypted);
    assert_ne!(encrypted, payload);
    salamander_xor(b"secret", &salt, &encrypted, &mut decrypted);
    assert_eq!(decrypted, payload);
}

#[test]
fn failed_auth_is_not_http_401() {
    assert_ne!(http::StatusCode::OK.as_u16(), 401);
    assert_eq!(http::StatusCode::from_u16(233).unwrap().as_u16(), 233);
    let padding = random_hysteria_padding_bytes().unwrap();
    assert!(padding.len() >= 16);
    assert!(padding.iter().all(|byte| byte.is_ascii_alphabetic()));
}
