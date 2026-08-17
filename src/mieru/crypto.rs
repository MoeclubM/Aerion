use super::pattern::{MieruNoncePattern, MieruTrafficPattern, apply_nonce_pattern};
use super::{KEY_ITER, KEY_LEN, KEY_REFRESH_SECS, NONCE_LEN};
use anyhow::{Context, Result, ensure};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const PBKDF2_CACHE_MAX: usize = 1024;
static PBKDF2_CACHE: Mutex<Option<HashMap<([u8; KEY_LEN], [u8; KEY_LEN]), [u8; KEY_LEN]>>> =
    Mutex::new(None);

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(super) struct MieruCipher {
    key: [u8; KEY_LEN],
    implicit_nonce: Option<[u8; NONCE_LEN]>,
    implicit: bool,
    username: String,
    nonce_pattern: Option<MieruNoncePattern>,
    nonce_pattern_applied: bool,
}

impl MieruCipher {
    pub(super) fn new(
        key: [u8; KEY_LEN],
        implicit: bool,
        username: String,
        traffic_pattern: Option<&MieruTrafficPattern>,
    ) -> Self {
        Self {
            key,
            implicit_nonce: None,
            implicit,
            username,
            nonce_pattern: traffic_pattern.and_then(|pattern| pattern.nonce.clone()),
            nonce_pattern_applied: false,
        }
    }

    pub(super) fn clone_reset_implicit(&self) -> Self {
        Self {
            key: self.key,
            implicit_nonce: None,
            implicit: true,
            username: self.username.clone(),
            nonce_pattern: self.nonce_pattern.clone(),
            nonce_pattern_applied: false,
        }
    }

    pub(super) fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, send_nonce) = if self.implicit {
            if self.implicit_nonce.is_none() {
                let mut nonce = self.random_nonce()?;
                add_user_hint_to_nonce(&self.username, &mut nonce);
                self.implicit_nonce = Some(nonce);
                (nonce, true)
            } else {
                self.increase_nonce();
                (self.implicit_nonce.expect("implicit nonce is set"), false)
            }
        } else {
            let mut nonce = self.random_nonce()?;
            add_user_hint_to_nonce(&self.username, &mut nonce);
            (nonce, true)
        };
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid Mieru XChaCha20-Poly1305 key"))?;
        let mut sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 encrypt failed"))?;
        if send_nonce {
            let mut out = nonce.to_vec();
            out.append(&mut sealed);
            Ok(out)
        } else {
            Ok(sealed)
        }
    }

    pub(super) fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, payload) = if self.implicit {
            if self.implicit_nonce.is_none() {
                ensure!(
                    ciphertext.len() >= NONCE_LEN,
                    "Mieru ciphertext is shorter than nonce"
                );
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&ciphertext[..NONCE_LEN]);
                self.implicit_nonce = Some(nonce);
                (nonce, &ciphertext[NONCE_LEN..])
            } else {
                self.increase_nonce();
                (
                    self.implicit_nonce.expect("implicit nonce is set"),
                    ciphertext,
                )
            }
        } else {
            ensure!(
                ciphertext.len() >= NONCE_LEN,
                "Mieru ciphertext is shorter than nonce"
            );
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&ciphertext[..NONCE_LEN]);
            (nonce, &ciphertext[NONCE_LEN..])
        };
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid Mieru XChaCha20-Poly1305 key"))?;
        cipher
            .decrypt(XNonce::from_slice(&nonce), payload)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 decrypt failed"))
    }

    pub(super) fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        ensure!(nonce.len() == NONCE_LEN, "invalid Mieru nonce length");
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid Mieru XChaCha20-Poly1305 key"))?;
        cipher
            .encrypt(XNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 encrypt failed"))
    }

    pub(super) fn decrypt_with_nonce(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        ensure!(nonce.len() == NONCE_LEN, "invalid Mieru nonce length");
        let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid Mieru XChaCha20-Poly1305 key"))?;
        cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 decrypt failed"))
    }

    fn increase_nonce(&mut self) {
        let nonce = self
            .implicit_nonce
            .as_mut()
            .expect("implicit nonce must exist before increment");
        *nonce = increment_nonce(nonce).expect("implicit nonce length is valid");
    }

    fn random_nonce(&mut self) -> Result<[u8; NONCE_LEN]> {
        let mut nonce = random_nonce()?;
        if let Some(pattern) = &self.nonce_pattern {
            if self.implicit || !self.nonce_pattern_applied || pattern.apply_to_all_udp_packet {
                apply_nonce_pattern(&mut nonce, pattern)?;
                self.nonce_pattern_applied = true;
            }
        }
        Ok(nonce)
    }
}

pub(super) fn hash_mieru_password(raw_password: &[u8], unique_value: &[u8]) -> [u8; KEY_LEN] {
    let mut input = Vec::with_capacity(raw_password.len() + 1 + unique_value.len());
    input.extend_from_slice(raw_password);
    input.push(0);
    input.extend_from_slice(unique_value);
    Sha256::digest(&input).into()
}

pub(super) fn current_mieru_key(hashed_password: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN]> {
    let keys = mieru_keys_for_password(hashed_password)?;
    Ok(keys[1])
}

pub(super) fn mieru_keys_for_password(
    hashed_password: &[u8; KEY_LEN],
) -> Result<Vec<[u8; KEY_LEN]>> {
    let mut keys = Vec::with_capacity(3);
    for salt in salt_from_time(SystemTime::now())? {
        keys.push(pbkdf2_cached(hashed_password, &salt)?);
    }
    Ok(keys)
}

pub(super) fn increment_nonce(nonce: &[u8]) -> Result<[u8; NONCE_LEN]> {
    ensure!(nonce.len() == NONCE_LEN, "invalid Mieru nonce length");
    let mut next = [0u8; NONCE_LEN];
    next.copy_from_slice(nonce);
    for byte in next.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    Ok(next)
}

fn pbkdf2_cached(password: &[u8; KEY_LEN], salt: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN]> {
    {
        let cache = PBKDF2_CACHE
            .lock()
            .expect("Mieru PBKDF2 cache lock poisoned");
        if let Some(cache) = cache.as_ref()
            && let Some(key) = cache.get(&(*password, *salt))
        {
            return Ok(*key);
        }
    }
    let derived = pbkdf2_hmac_sha256(password, salt, KEY_ITER, KEY_LEN)?;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&derived);
    let mut cache = PBKDF2_CACHE
        .lock()
        .expect("Mieru PBKDF2 cache lock poisoned");
    let cache = cache.get_or_insert_with(HashMap::new);
    if cache.len() >= PBKDF2_CACHE_MAX {
        cache.clear();
    }
    cache.insert((*password, *salt), key);
    Ok(key)
}

fn salt_from_time(time: SystemTime) -> Result<[[u8; KEY_LEN]; 3]> {
    let seconds = time.duration_since(UNIX_EPOCH)?.as_secs();
    let rounded = ((seconds + KEY_REFRESH_SECS / 2) / KEY_REFRESH_SECS) * KEY_REFRESH_SECS;
    let times = [
        rounded.saturating_sub(KEY_REFRESH_SECS),
        rounded,
        rounded + KEY_REFRESH_SECS,
    ];
    let mut salts = [[0u8; KEY_LEN]; 3];
    for (salt, unix) in salts.iter_mut().zip(times) {
        let digest = Sha256::digest(unix.to_be_bytes());
        salt.copy_from_slice(&digest);
    }
    Ok(salts)
}

fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    key_len: usize,
) -> Result<Vec<u8>> {
    ensure!(!password.is_empty(), "Mieru password is empty");
    let blocks = key_len.div_ceil(KEY_LEN);
    let mut derived = Vec::with_capacity(blocks * KEY_LEN);
    for block_index in 1..=blocks {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(password)?;
        mac.update(salt);
        mac.update(&(block_index as u32).to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(password)?;
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (left, right) in t.iter_mut().zip(&u) {
                *left ^= *right;
            }
        }
        derived.extend_from_slice(&t);
    }
    derived.truncate(key_len);
    Ok(derived)
}

fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).context("generate Mieru nonce")?;
    Ok(nonce)
}

fn add_user_hint_to_nonce(username: &str, nonce: &mut [u8; NONCE_LEN]) {
    if username.is_empty() {
        return;
    }
    let mut input = Vec::with_capacity(username.len() + 16);
    input.extend_from_slice(username.as_bytes());
    input.extend_from_slice(&nonce[..16]);
    let digest = Sha256::digest(&input);
    nonce[20..24].copy_from_slice(&digest[..4]);
}

pub(super) fn check_user_from_hint(username: &[u8], nonce: &[u8]) -> bool {
    if username.is_empty() || nonce.len() < 20 {
        return false;
    }
    let mut input = Vec::with_capacity(username.len() + 16);
    input.extend_from_slice(username);
    input.extend_from_slice(&nonce[..16]);
    let digest = Sha256::digest(&input);
    digest[..4].eq(&nonce[nonce.len() - 4..])
}

#[cfg(test)]
mod tests {
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
}
