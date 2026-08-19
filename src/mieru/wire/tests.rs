use super::*;
use crate::mieru::crypto::{current_mieru_key, hash_mieru_password};

#[test]
fn udp_payload_reuses_metadata_nonce() -> Result<()> {
    let key = current_mieru_key(&hash_mieru_password(b"secret", b"user"))?;
    let mut send = MieruCipher::new(key, false, "user".to_string(), None);
    let mut recv = MieruCipher::new(key, false, "user".to_string(), None);
    let segment = MieruSegment {
        metadata: MieruMetadata::Session(MieruSessionMetadata {
            protocol: OPEN_SESSION_REQUEST,
            session_id: 1,
            seq: 0,
            status_code: STATUS_OK,
            payload_len: 4,
            suffix_len: 0,
        }),
        payload: b"ping".to_vec(),
    };
    let packet = encode_mieru_packet_segment(&mut send, segment, 1500, None)?;
    let decoded = decode_mieru_packet_segment(&mut recv, &packet)?;
    assert_eq!(decoded.payload, b"ping");

    let nonce = &packet[..NONCE_LEN];
    let reused = send.encrypt_with_nonce(b"ping", nonce)?;
    let payload_offset = PACKET_METADATA_LEN;
    let encrypted_len = 4 + AEAD_OVERHEAD;
    assert_eq!(
        &packet[payload_offset..payload_offset + encrypted_len],
        reused.as_slice(),
        "UDP payload must reuse the metadata nonce"
    );
    Ok(())
}

#[test]
fn replay_cache_rejects_duplicate_first_segment() -> Result<()> {
    let cache = MieruReplayCache::new();
    cache.check_and_store(b"first-segment")?;
    let error = cache
        .check_and_store(b"first-segment")
        .expect_err("duplicate first segment must be rejected");
    assert!(error.to_string().contains("replay"));
    cache.check_and_store(b"other-segment")?;
    Ok(())
}
