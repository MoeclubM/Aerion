use super::pattern::{MieruNoncePattern, MieruTrafficPattern, apply_nonce_pattern};
use super::{AEAD_OVERHEAD, KEY_ITER, KEY_LEN, KEY_REFRESH_SECS, NONCE_LEN};
use anyhow::{Context, Result, ensure};
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// Bound users, not individual time keys. A full authentication scan must not
// flush the keys used by every other connection in the process.
const PBKDF2_CACHE_MAX: usize = 4096;
static PBKDF2_CACHE: Mutex<Option<KeyCache>> = Mutex::new(None);

#[derive(Clone, Copy)]
struct TimeKeys {
    epoch: u64,
    keys: [[u8; KEY_LEN]; 3],
}

fn key_epochs(epoch: u64) -> [u64; 3] {
    [epoch.saturating_sub(1), epoch, epoch.saturating_add(1)]
}

#[derive(Default)]
struct KeyCache {
    entries: HashMap<[u8; KEY_LEN], TimeKeys>,
    order: VecDeque<[u8; KEY_LEN]>,
    salts: Option<(u64, [[u8; KEY_LEN]; 3])>,
}

impl KeyCache {
    fn insert(&mut self, password: [u8; KEY_LEN], keys: TimeKeys) {
        if !self.entries.contains_key(&password) {
            if self.entries.len() == PBKDF2_CACHE_MAX {
                let oldest = self.order.pop_front().expect("key cache eviction order");
                self.entries.remove(&oldest);
            }
            self.order.push_back(password);
        }
        self.entries.insert(password, keys);
    }
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(super) struct MieruCipher {
    cipher: XChaCha20Poly1305,
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
            cipher: XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key)),
            implicit_nonce: None,
            implicit,
            username,
            nonce_pattern: traffic_pattern.and_then(|pattern| pattern.nonce.clone()),
            nonce_pattern_applied: false,
        }
    }

    pub(super) fn clone_reset_implicit(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            implicit_nonce: None,
            implicit: true,
            username: self.username.clone(),
            nonce_pattern: self.nonce_pattern.clone(),
            nonce_pattern_applied: false,
        }
    }

    pub(super) fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut sealed = Vec::with_capacity(NONCE_LEN + plaintext.len() + AEAD_OVERHEAD);
        self.encrypt_into(plaintext, &mut sealed)?;
        Ok(sealed)
    }

    pub(super) fn encrypt_into(&mut self, plaintext: &[u8], output: &mut Vec<u8>) -> Result<()> {
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
        output.reserve(if send_nonce { NONCE_LEN } else { 0 } + plaintext.len() + AEAD_OVERHEAD);
        if send_nonce {
            output.extend_from_slice(&nonce);
        }
        let start = output.len();
        output.extend_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &[], &mut output[start..])
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 encrypt failed"))?;
        output.extend_from_slice(&tag);
        Ok(())
    }

    pub(super) fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = ciphertext.to_vec();
        self.decrypt_in_place(&mut plaintext)?;
        Ok(plaintext)
    }

    pub(super) fn decrypt_in_place(&mut self, ciphertext: &mut Vec<u8>) -> Result<()> {
        let (nonce, prefix_len) = if self.implicit {
            if self.implicit_nonce.is_none() {
                ensure!(
                    ciphertext.len() >= NONCE_LEN,
                    "Mieru ciphertext is shorter than nonce"
                );
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&ciphertext[..NONCE_LEN]);
                self.implicit_nonce = Some(nonce);
                (nonce, NONCE_LEN)
            } else {
                self.increase_nonce();
                (self.implicit_nonce.expect("implicit nonce is set"), 0)
            }
        } else {
            ensure!(
                ciphertext.len() >= NONCE_LEN,
                "Mieru ciphertext is shorter than nonce"
            );
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&ciphertext[..NONCE_LEN]);
            (nonce, NONCE_LEN)
        };
        ensure!(
            ciphertext.len() >= prefix_len + AEAD_OVERHEAD,
            "Mieru ciphertext is shorter than authentication tag"
        );
        let tag_offset = ciphertext.len() - AEAD_OVERHEAD;
        let tag = *chacha20poly1305::Tag::from_slice(&ciphertext[tag_offset..]);
        self.cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &[],
                &mut ciphertext[prefix_len..tag_offset],
                &tag,
            )
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 decrypt failed"))?;
        if prefix_len > 0 {
            ciphertext.copy_within(prefix_len..tag_offset, 0);
        }
        ciphertext.truncate(tag_offset - prefix_len);
        Ok(())
    }

    pub(super) fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        ensure!(nonce.len() == NONCE_LEN, "invalid Mieru nonce length");
        self.cipher
            .encrypt(XNonce::from_slice(nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("Mieru XChaCha20-Poly1305 encrypt failed"))
    }

    pub(super) fn decrypt_with_nonce(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        ensure!(nonce.len() == NONCE_LEN, "invalid Mieru nonce length");
        self.cipher
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

pub(super) fn mieru_key_epoch() -> Result<u64> {
    Ok(
        (SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + KEY_REFRESH_SECS / 2)
            / KEY_REFRESH_SECS,
    )
}

pub(super) fn mieru_keys_for_password(
    hashed_password: &[u8; KEY_LEN],
) -> Result<[[u8; KEY_LEN]; 3]> {
    let epoch = mieru_key_epoch()?;
    let (salts, previous) = {
        let mut cache = PBKDF2_CACHE
            .lock()
            .expect("Mieru PBKDF2 cache lock poisoned");
        let cache = cache.get_or_insert_with(KeyCache::default);
        let previous = cache.entries.get(hashed_password).copied();
        if let Some(previous) = previous
            && previous.epoch == epoch
        {
            return Ok(previous.keys);
        }
        if cache
            .salts
            .as_ref()
            .is_none_or(|(cached, _)| *cached != epoch)
        {
            cache.salts = Some((epoch, salt_from_epoch(epoch)));
        }
        (cache.salts.as_ref().unwrap().1, previous)
    };
    let keys = derive_time_keys(hashed_password, epoch, salts, previous)?;
    PBKDF2_CACHE
        .lock()
        .expect("Mieru PBKDF2 cache lock poisoned")
        .as_mut()
        .unwrap()
        .insert(*hashed_password, TimeKeys { epoch, keys });
    Ok(keys)
}

fn derive_time_keys(
    hashed_password: &[u8; KEY_LEN],
    epoch: u64,
    salts: [[u8; KEY_LEN]; 3],
    previous: Option<TimeKeys>,
) -> Result<[[u8; KEY_LEN]; 3]> {
    // Key rotation overlaps two of the three accepted epochs. Reuse those
    // keys, and keep the expensive derivation outside the process-wide lock.
    let epochs = key_epochs(epoch);
    let mut keys = [[0; KEY_LEN]; 3];
    for (index, salt) in salts.iter().enumerate() {
        if let Some((previous, old_index)) = previous.and_then(|old| {
            key_epochs(old.epoch)
                .iter()
                .position(|e| *e == epochs[index])
                .map(|i| (old, i))
        }) {
            keys[index] = previous.keys[old_index];
        } else {
            keys[index].copy_from_slice(&pbkdf2_hmac_sha256(
                hashed_password,
                salt,
                KEY_ITER,
                KEY_LEN,
            )?);
        }
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

fn salt_from_epoch(epoch: u64) -> [[u8; KEY_LEN]; 3] {
    let mut salts = [[0u8; KEY_LEN]; 3];
    for (salt, epoch) in salts.iter_mut().zip(key_epochs(epoch)) {
        let unix = epoch.saturating_mul(KEY_REFRESH_SECS);
        let digest = Sha256::digest(unix.to_be_bytes());
        salt.copy_from_slice(&digest);
    }
    salts
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
    let base = <HmacSha256 as Mac>::new_from_slice(password)?;
    for block_index in 1..=blocks {
        let mut mac = base.clone();
        mac.update(salt);
        mac.update(&(block_index as u32).to_be_bytes());
        let mut u: [u8; KEY_LEN] = mac.finalize().into_bytes().into();
        let mut t = u;
        for _ in 1..iterations {
            let mut mac = base.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes().into();
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
    let mut hash = Sha256::new();
    hash.update(username.as_bytes());
    hash.update(&nonce[..16]);
    let digest = hash.finalize();
    nonce[20..24].copy_from_slice(&digest[..4]);
}

pub(super) fn check_user_from_hint(username: &[u8], nonce: &[u8]) -> bool {
    if username.is_empty() || nonce.len() < 20 {
        return false;
    }
    let mut hash = Sha256::new();
    hash.update(username);
    hash.update(&nonce[..16]);
    let digest = hash.finalize();
    digest[..4].eq(&nonce[nonce.len() - 4..])
}

#[cfg(test)]
mod tests;
