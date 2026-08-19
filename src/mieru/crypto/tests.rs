use super::*;
use crate::mieru::{MieruNoncePattern, MieruNonceType, MieruTrafficPattern};

#[test]
fn password_hash_uses_username_separator() {
    let hash1 = hash_mieru_password(b"password", b"alice");
    let hash2 = hash_mieru_password(b"passwordalice", b"");
    assert_ne!(hash1, hash2);
}

#[test]
fn pbkdf2_vector_matches_rfc6070_shape() -> Result<()> {
    let key = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)?;
    assert_eq!(
        hex::encode(key),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    Ok(())
}

#[test]
fn implicit_cipher_roundtrip() -> Result<()> {
    let hashed = hash_mieru_password(b"secret", b"user");
    let key = current_mieru_key(&hashed)?;
    let mut send = MieruCipher::new(key, true, "user".to_string(), None);
    let mut recv = MieruCipher::new(key, true, "user".to_string(), None);
    for payload in [
        b"hello".as_slice(),
        b"world".as_slice(),
        b"mieru".as_slice(),
    ] {
        let encrypted = send.encrypt(payload)?;
        let decrypted = recv.decrypt(&encrypted)?;
        assert_eq!(decrypted, payload);
    }
    Ok(())
}

#[test]
fn fixed_nonce_pattern_rewrites_prefix() -> Result<()> {
    let pattern = MieruTrafficPattern {
        tcp_fragment: None,
        nonce: Some(MieruNoncePattern {
            kind: MieruNonceType::Fixed,
            apply_to_all_udp_packet: true,
            min_len: 0,
            max_len: 0,
            custom_prefixes: vec![vec![0x41, 0x42, 0x43]],
        }),
        padding: None,
    };
    let key = current_mieru_key(&hash_mieru_password(b"secret", b"user"))?;
    let mut cipher = MieruCipher::new(key, false, "user".to_string(), Some(&pattern));
    let encrypted = cipher.encrypt(b"payload")?;
    assert_eq!(&encrypted[..3], b"ABC");
    Ok(())
}

#[test]
fn user_hint_matches_nonce() -> Result<()> {
    let mut nonce = random_nonce()?;
    add_user_hint_to_nonce("alice", &mut nonce);
    assert!(check_user_from_hint(b"alice", &nonce));
    assert!(!check_user_from_hint(b"bob", &nonce));
    Ok(())
}

#[test]
fn increment_nonce_adds_one_from_the_end() -> Result<()> {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[NONCE_LEN - 1] = 0xff;
    nonce[NONCE_LEN - 2] = 0x01;
    let next = increment_nonce(&nonce)?;
    assert_eq!(next[NONCE_LEN - 1], 0);
    assert_eq!(next[NONCE_LEN - 2], 0x02);
    Ok(())
}
