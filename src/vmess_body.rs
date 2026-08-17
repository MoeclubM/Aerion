use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use md5::Md5;
use sha2::{Digest, Sha256};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const AEAD_TAG_LEN: usize = 16;
const MAX_CHUNK_PLAIN_LEN: usize = 16 * 1024;
const HMAC_BLOCK_SIZE: usize = 64;
const CHACHA_KEY_LEN: usize = 32;
const AUTHENTICATED_LENGTH_SALT: &str = "auth_len";
const VMESS_AEAD_KDF_SALT: &[u8] = b"VMess AEAD KDF";
const MAX_PADDING_LEN: usize = 64;
const SECURITY_TYPE_AES128_GCM: u8 = 0x03;
const SECURITY_TYPE_CHACHA20_POLY1305: u8 = 0x04;
const SECURITY_TYPE_NONE: u8 = 0x05;
const SECURITY_TYPE_ZERO: u8 = 0x06;
const REQUEST_OPTION_CHUNK_STREAM: u8 = 0x01;
const REQUEST_OPTION_CONNECTION_REUSE: u8 = 0x02;
const REQUEST_OPTION_CHUNK_MASKING: u8 = 0x04;
const REQUEST_OPTION_GLOBAL_PADDING: u8 = 0x08;
const REQUEST_OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;
const SUPPORTED_OPTION_BITS: u8 = REQUEST_OPTION_CHUNK_STREAM
    | REQUEST_OPTION_CONNECTION_REUSE
    | REQUEST_OPTION_CHUNK_MASKING
    | REQUEST_OPTION_GLOBAL_PADDING
    | REQUEST_OPTION_AUTHENTICATED_LENGTH;
const KECCAKF_ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];
const KECCAKF_ROTATION: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const KECCAKF_PERMUTATION: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityType {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
    Zero,
}

impl SecurityType {
    pub fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            SECURITY_TYPE_AES128_GCM => Ok(Self::Aes128Gcm),
            SECURITY_TYPE_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            SECURITY_TYPE_NONE => Ok(Self::None),
            SECURITY_TYPE_ZERO => Ok(Self::Zero),
            0x01 => bail!("VMess legacy security is not supported"),
            0x02 => bail!("VMess auto security must not appear on the wire"),
            other => bail!("unsupported VMess security type: {other:#x}"),
        }
    }

    pub fn from_name(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "none" => Ok(Self::None),
            "zero" => Ok(Self::Zero),
            "auto" => Ok(Self::auto_for_platform()),
            "aes-128-gcm" | "aes128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            other => bail!("unsupported VMess security setting: {other}"),
        }
    }

    pub fn auto_for_platform() -> Self {
        match std::env::consts::ARCH {
            "x86_64" | "aarch64" | "s390x" => Self::Aes128Gcm,
            _ => Self::ChaCha20Poly1305,
        }
    }

    pub fn normalized(self) -> Self {
        match self {
            Self::Zero => Self::None,
            other => other,
        }
    }

    pub fn raw_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => SECURITY_TYPE_AES128_GCM,
            Self::ChaCha20Poly1305 => SECURITY_TYPE_CHACHA20_POLY1305,
            Self::None => SECURITY_TYPE_NONE,
            Self::Zero => SECURITY_TYPE_ZERO,
        }
    }

    fn payload_overhead(self) -> usize {
        match self.normalized() {
            Self::None => 0,
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => AEAD_TAG_LEN,
            Self::Zero => 0,
        }
    }
}

impl fmt::Display for SecurityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "aes-128-gcm"),
            Self::ChaCha20Poly1305 => write!(f, "chacha20-poly1305"),
            Self::None => write!(f, "none"),
            Self::Zero => write!(f, "zero"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RequestOptions(u8);

impl RequestOptions {
    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn supported_mask() -> u8 {
        SUPPORTED_OPTION_BITS
    }

    pub const fn chunk_stream(self) -> bool {
        self.0 & REQUEST_OPTION_CHUNK_STREAM != 0
    }

    const fn chunk_masking(self) -> bool {
        self.0 & REQUEST_OPTION_CHUNK_MASKING != 0
    }

    const fn global_padding(self) -> bool {
        self.0 & REQUEST_OPTION_GLOBAL_PADDING != 0
    }

    const fn authenticated_length(self) -> bool {
        self.0 & REQUEST_OPTION_AUTHENTICATED_LENGTH != 0
    }

    pub const fn has_unknown_bits(self) -> bool {
        self.0 & !SUPPORTED_OPTION_BITS != 0
    }

    pub fn enable_chunk_stream(&mut self) {
        self.0 |= REQUEST_OPTION_CHUNK_STREAM;
    }

    pub fn clear_chunk_stream(&mut self) {
        self.0 &= !REQUEST_OPTION_CHUNK_STREAM;
    }

    pub fn clear_chunk_masking(&mut self) {
        self.0 &= !REQUEST_OPTION_CHUNK_MASKING;
    }

    pub fn clear_authenticated_length(&mut self) {
        self.0 &= !REQUEST_OPTION_AUTHENTICATED_LENGTH;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyConfig {
    security: SecurityType,
    options: RequestOptions,
    payload_key: [u8; 16],
    payload_iv: [u8; 16],
    length_key: [u8; 16],
    length_iv: [u8; 16],
}

impl BodyConfig {
    pub fn new_request(
        security: SecurityType,
        options: RequestOptions,
        key: [u8; 16],
        iv: [u8; 16],
    ) -> Result<Self> {
        Self::new(security, options, key, iv, key, iv)
    }

    pub fn new_response(
        security: SecurityType,
        options: RequestOptions,
        request_key: [u8; 16],
        request_iv: [u8; 16],
    ) -> Result<Self> {
        Self::new(
            security,
            options,
            response_body_key(&request_key),
            response_body_iv(&request_iv),
            request_key,
            request_iv,
        )
    }

    fn new(
        security: SecurityType,
        mut options: RequestOptions,
        payload_key: [u8; 16],
        payload_iv: [u8; 16],
        length_key: [u8; 16],
        length_iv: [u8; 16],
    ) -> Result<Self> {
        let security = security.normalized();
        if security == SecurityType::None {
            options.clear_authenticated_length();
        }
        ensure!(
            !options.has_unknown_bits(),
            "unsupported VMess request option bits: 0x{:02x}",
            options.bits() & !RequestOptions::supported_mask()
        );
        if !options.chunk_stream() {
            ensure!(
                !options.chunk_masking()
                    && !options.global_padding()
                    && !options.authenticated_length(),
                "VMess non-chunked body cannot enable chunk masking, global padding, or authenticated length"
            );
            ensure!(
                security == SecurityType::None,
                "encrypted VMess security {security} requires chunk stream"
            );
        }
        if options.global_padding() {
            ensure!(
                options.chunk_masking(),
                "VMess global padding requires chunk masking"
            );
        }
        if options.chunk_masking() {
            ensure!(
                options.chunk_stream(),
                "VMess chunk masking requires chunk stream"
            );
        }
        if options.authenticated_length() {
            ensure!(
                options.chunk_stream(),
                "VMess authenticated length requires chunk stream"
            );
        }
        Ok(Self {
            security,
            options,
            payload_key,
            payload_iv,
            length_key,
            length_iv,
        })
    }

    fn raw_mode(self) -> bool {
        self.security == SecurityType::None && !self.options.chunk_stream()
    }
}

pub struct BodyReader<R> {
    inner: R,
    state: ChunkState,
    pending: Vec<u8>,
    pending_pos: usize,
    finished: bool,
}

impl<R: AsyncRead + Unpin> BodyReader<R> {
    pub fn new(inner: R, config: BodyConfig) -> Self {
        Self {
            inner,
            state: ChunkState::new(config),
            pending: Vec::new(),
            pending_pos: 0,
            finished: false,
        }
    }

    pub async fn read_plain(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.state.raw_mode() {
            return self.inner.read(buffer).await.context("read raw VMess body");
        }
        if self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
            if self.finished {
                return Ok(0);
            }
            self.read_next_chunk().await?;
            if self.pending.is_empty() {
                return Ok(0);
            }
        }
        let to_copy = buffer.len().min(self.pending.len() - self.pending_pos);
        buffer[..to_copy]
            .copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + to_copy]);
        self.pending_pos += to_copy;
        if self.pending_pos >= self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        Ok(to_copy)
    }

    pub async fn read_packet(&mut self) -> Result<Option<Vec<u8>>> {
        ensure!(
            !self.state.raw_mode(),
            "VMess packet transfer requires chunk stream"
        );
        ensure!(
            self.pending_pos >= self.pending.len(),
            "VMess packet transfer cannot continue after partial stream reads"
        );
        if self.finished {
            return Ok(None);
        }
        self.pending.clear();
        self.pending_pos = 0;
        self.read_next_chunk().await?;
        if self.finished {
            return Ok(None);
        }
        Ok(Some(std::mem::take(&mut self.pending)))
    }

    async fn read_next_chunk(&mut self) -> Result<()> {
        let mut size_bytes = vec![0u8; self.state.size_field_len()];
        self.inner
            .read_exact(&mut size_bytes)
            .await
            .context("read VMess chunk size")?;
        let padding_len = if self.state.padding_before_size_decode() {
            self.state.next_padding_len()
        } else {
            0
        };
        let encoded_size = self.state.decode_size(&size_bytes)? as usize;
        let padding_len = if self.state.padding_before_size_decode() {
            padding_len
        } else {
            self.state.next_padding_len()
        };
        ensure!(
            encoded_size >= padding_len,
            "invalid VMess chunk size {encoded_size} smaller than padding {padding_len}"
        );
        let payload_len = encoded_size - padding_len;
        ensure!(
            payload_len >= self.state.payload_overhead(),
            "invalid VMess chunk payload size {payload_len} below overhead {}",
            self.state.payload_overhead()
        );
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            self.inner
                .read_exact(&mut payload)
                .await
                .context("read VMess chunk payload")?;
        }
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            self.inner
                .read_exact(&mut padding)
                .await
                .context("read VMess chunk padding")?;
        }
        let plaintext = self.state.decrypt_payload(&payload)?;
        if payload_len == self.state.payload_overhead() && plaintext.is_empty() {
            self.finished = true;
            self.pending.clear();
            self.pending_pos = 0;
            return Ok(());
        }
        self.pending = plaintext;
        self.pending_pos = 0;
        Ok(())
    }
}

pub struct BodyWriter<W> {
    inner: W,
    state: ChunkState,
    finished: bool,
}

impl<W: AsyncWrite + Unpin> BodyWriter<W> {
    pub fn new(inner: W, config: BodyConfig) -> Self {
        Self {
            inner,
            state: ChunkState::new(config),
            finished: false,
        }
    }

    pub async fn write_all_plain(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        ensure!(!self.finished, "VMess body writer already finished");
        if self.state.raw_mode() {
            return self
                .inner
                .write_all(data)
                .await
                .context("write raw VMess body");
        }
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + MAX_CHUNK_PLAIN_LEN).min(data.len());
            self.write_chunk(&data[offset..end]).await?;
            offset = end;
        }
        Ok(())
    }

    pub async fn write_packet_plain(&mut self, data: &[u8]) -> Result<()> {
        ensure!(!self.finished, "VMess body writer already finished");
        ensure!(
            !self.state.raw_mode(),
            "VMess packet transfer requires chunk stream"
        );
        self.write_chunk(data).await
    }

    pub async fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        if !self.state.raw_mode() {
            self.write_chunk(&[]).await?;
        }
        self.inner.shutdown().await.context("shutdown VMess body")?;
        self.finished = true;
        Ok(())
    }

    async fn write_chunk(&mut self, plaintext: &[u8]) -> Result<()> {
        let padding_len = self.state.next_padding_len();
        let ciphertext = self.state.encrypt_payload(plaintext)?;
        let total_len = ciphertext.len() + padding_len;
        ensure!(
            total_len <= u16::MAX as usize,
            "VMess chunk too large: {total_len}"
        );
        let size_bytes = self.state.encode_size(total_len as u16)?;
        self.inner
            .write_all(&size_bytes)
            .await
            .context("write VMess chunk size")?;
        if !ciphertext.is_empty() {
            self.inner
                .write_all(&ciphertext)
                .await
                .context("write VMess chunk payload")?;
        }
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            getrandom::fill(&mut padding).context("generate VMess chunk padding")?;
            self.inner
                .write_all(&padding)
                .await
                .context("write VMess chunk padding")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ChunkState {
    config: BodyConfig,
    size_shake: Option<Shake128>,
    padding_shake: Option<Shake128>,
    padding_from_size_shake: bool,
    size_counter: u16,
    payload_counter: u16,
}

impl ChunkState {
    fn new(config: BodyConfig) -> Self {
        let mut size_shake = None;
        let mut padding_shake = None;
        let mut padding_from_size_shake = false;
        if config.options.chunk_stream() {
            if config.options.authenticated_length() {
                if config.options.global_padding() {
                    let mut shake = Shake128::default();
                    shake.absorb(&config.payload_iv);
                    shake.finalize();
                    padding_shake = Some(shake);
                }
            } else if config.options.chunk_masking() {
                let mut shake = Shake128::default();
                shake.absorb(&config.payload_iv);
                shake.finalize();
                if config.options.global_padding() {
                    padding_from_size_shake = true;
                }
                size_shake = Some(shake);
            }
        }
        Self {
            config,
            size_shake,
            padding_shake,
            padding_from_size_shake,
            size_counter: 0,
            payload_counter: 0,
        }
    }

    fn raw_mode(&self) -> bool {
        self.config.raw_mode()
    }

    fn size_field_len(&self) -> usize {
        if self.config.options.authenticated_length() {
            2 + AEAD_TAG_LEN
        } else {
            2
        }
    }

    fn payload_overhead(&self) -> usize {
        self.config.security.payload_overhead()
    }

    fn padding_before_size_decode(&self) -> bool {
        self.padding_from_size_shake
    }

    fn next_padding_len(&mut self) -> usize {
        if self.padding_from_size_shake {
            self.size_shake
                .as_mut()
                .map(Shake128::next_padding_len)
                .unwrap_or(0)
        } else {
            self.padding_shake
                .as_mut()
                .map(Shake128::next_padding_len)
                .unwrap_or(0)
        }
    }

    fn decode_size(&mut self, encoded: &[u8]) -> Result<u16> {
        ensure!(
            encoded.len() == self.size_field_len(),
            "invalid VMess encoded chunk size length: {}",
            encoded.len()
        );
        if self.config.options.authenticated_length() {
            let plain = self.open_length_chunk(encoded)?;
            ensure!(plain.len() == 2, "invalid VMess AEAD length payload size");
            return Ok(u16::from_be_bytes([plain[0], plain[1]]).wrapping_add(AEAD_TAG_LEN as u16));
        }
        if let Some(shake) = self.size_shake.as_mut() {
            return Ok(shake.next_u16() ^ u16::from_be_bytes([encoded[0], encoded[1]]));
        }
        Ok(u16::from_be_bytes([encoded[0], encoded[1]]))
    }

    fn encode_size(&mut self, size: u16) -> Result<Vec<u8>> {
        if self.config.options.authenticated_length() {
            return self.seal_length_chunk(&size.wrapping_sub(AEAD_TAG_LEN as u16).to_be_bytes());
        }
        if let Some(shake) = self.size_shake.as_mut() {
            return Ok((shake.next_u16() ^ size).to_be_bytes().to_vec());
        }
        Ok(size.to_be_bytes().to_vec())
    }

    fn decrypt_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        match self.config.security {
            SecurityType::None => Ok(payload.to_vec()),
            SecurityType::Aes128Gcm => {
                let nonce = generate_chunk_nonce(&self.config.payload_iv, self.payload_counter);
                self.payload_counter = self.payload_counter.wrapping_add(1);
                decrypt_aes_gcm(&self.config.payload_key, &nonce, payload, &[])
            }
            SecurityType::ChaCha20Poly1305 => {
                let nonce = generate_chunk_nonce(&self.config.payload_iv, self.payload_counter);
                self.payload_counter = self.payload_counter.wrapping_add(1);
                decrypt_chacha20_poly1305(
                    &generate_chacha20_poly1305_key(&self.config.payload_key),
                    &nonce,
                    payload,
                    &[],
                )
            }
            SecurityType::Zero => unreachable!("normalized security never keeps zero"),
        }
    }

    fn encrypt_payload(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self.config.security {
            SecurityType::None => Ok(plaintext.to_vec()),
            SecurityType::Aes128Gcm => {
                let nonce = generate_chunk_nonce(&self.config.payload_iv, self.payload_counter);
                self.payload_counter = self.payload_counter.wrapping_add(1);
                encrypt_aes_gcm(&self.config.payload_key, &nonce, plaintext, &[])
            }
            SecurityType::ChaCha20Poly1305 => {
                let nonce = generate_chunk_nonce(&self.config.payload_iv, self.payload_counter);
                self.payload_counter = self.payload_counter.wrapping_add(1);
                encrypt_chacha20_poly1305(
                    &generate_chacha20_poly1305_key(&self.config.payload_key),
                    &nonce,
                    plaintext,
                    &[],
                )
            }
            SecurityType::Zero => unreachable!("normalized security never keeps zero"),
        }
    }

    fn open_length_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = kdf16(&self.config.length_key, AUTHENTICATED_LENGTH_SALT, &[]);
        let nonce = generate_chunk_nonce(&self.config.length_iv, self.size_counter);
        self.size_counter = self.size_counter.wrapping_add(1);
        match self.config.security {
            SecurityType::ChaCha20Poly1305 => decrypt_chacha20_poly1305(
                &generate_chacha20_poly1305_key(&key),
                &nonce,
                ciphertext,
                &[],
            ),
            SecurityType::Aes128Gcm | SecurityType::None => {
                decrypt_aes_gcm(&key, &nonce, ciphertext, &[])
            }
            SecurityType::Zero => unreachable!("normalized security never keeps zero"),
        }
    }

    fn seal_length_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = kdf16(&self.config.length_key, AUTHENTICATED_LENGTH_SALT, &[]);
        let nonce = generate_chunk_nonce(&self.config.length_iv, self.size_counter);
        self.size_counter = self.size_counter.wrapping_add(1);
        match self.config.security {
            SecurityType::ChaCha20Poly1305 => encrypt_chacha20_poly1305(
                &generate_chacha20_poly1305_key(&key),
                &nonce,
                plaintext,
                &[],
            ),
            SecurityType::Aes128Gcm | SecurityType::None => {
                encrypt_aes_gcm(&key, &nonce, plaintext, &[])
            }
            SecurityType::Zero => unreachable!("normalized security never keeps zero"),
        }
    }
}

#[derive(Debug, Clone)]
struct Shake128 {
    state: [u64; 25],
    absorb_pos: usize,
    squeeze_pos: usize,
    finalized: bool,
}

impl Default for Shake128 {
    fn default() -> Self {
        Self {
            state: [0u64; 25],
            absorb_pos: 0,
            squeeze_pos: 0,
            finalized: false,
        }
    }
}

impl Shake128 {
    const RATE: usize = 168;

    fn absorb(&mut self, data: &[u8]) {
        assert!(!self.finalized, "cannot absorb after SHAKE128 finalization");
        for &byte in data {
            self.xor_byte(self.absorb_pos, byte);
            self.absorb_pos += 1;
            if self.absorb_pos == Self::RATE {
                keccakf(&mut self.state);
                self.absorb_pos = 0;
            }
        }
    }

    fn finalize(&mut self) {
        if self.finalized {
            return;
        }
        self.xor_byte(self.absorb_pos, 0x1f);
        self.xor_byte(Self::RATE - 1, 0x80);
        keccakf(&mut self.state);
        self.squeeze_pos = 0;
        self.finalized = true;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        if !self.finalized {
            self.finalize();
        }
        for byte in out {
            if self.squeeze_pos == Self::RATE {
                keccakf(&mut self.state);
                self.squeeze_pos = 0;
            }
            *byte = self.byte_at(self.squeeze_pos);
            self.squeeze_pos += 1;
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.squeeze(&mut buf);
        u16::from_be_bytes(buf)
    }

    fn next_padding_len(&mut self) -> usize {
        (self.next_u16() as usize) % MAX_PADDING_LEN
    }

    fn xor_byte(&mut self, pos: usize, byte: u8) {
        let lane = pos / 8;
        let shift = (pos % 8) * 8;
        self.state[lane] ^= (byte as u64) << shift;
    }

    fn byte_at(&self, pos: usize) -> u8 {
        let lane = pos / 8;
        let shift = (pos % 8) * 8;
        ((self.state[lane] >> shift) & 0xff) as u8
    }
}

fn keccakf(state: &mut [u64; 25]) {
    for round_constant in KECCAKF_ROUND_CONSTANTS {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        let mut current = state[1];
        for index in 0..24 {
            let target = KECCAKF_PERMUTATION[index];
            let tmp = state[target];
            state[target] = current.rotate_left(KECCAKF_ROTATION[index]);
            current = tmp;
        }

        for y in 0..5 {
            let row = [
                state[5 * y],
                state[5 * y + 1],
                state[5 * y + 2],
                state[5 * y + 3],
                state[5 * y + 4],
            ];
            for x in 0..5 {
                state[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }

        state[0] ^= round_constant;
    }
}

fn response_body_key(request_body_key: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(request_body_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn response_body_iv(request_body_iv: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::digest(request_body_iv);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn generate_chunk_nonce(base: &[u8], counter: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&base[..12]);
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn generate_chacha20_poly1305_key(value: &[u8]) -> [u8; CHACHA_KEY_LEN] {
    let first = Md5::digest(value);
    let second = Md5::digest(first);
    let mut out = [0u8; CHACHA_KEY_LEN];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

fn kdf16(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, salt, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 32] {
    let mut levels = Vec::with_capacity(2 + path.len());
    levels.push(VMESS_AEAD_KDF_SALT);
    levels.push(salt.as_bytes());
    levels.extend_from_slice(path);
    nested_hmac_hash(&levels, key)
}

fn nested_hmac_hash(levels: &[&[u8]], data: &[u8]) -> [u8; 32] {
    if let Some((last, rest)) = levels.split_last() {
        hmac_with_custom_hash(last, data, |input| {
            if rest.is_empty() {
                sha256_hash(input)
            } else {
                nested_hmac_hash(rest, input)
            }
        })
    } else {
        sha256_hash(data)
    }
}

fn hmac_with_custom_hash<F>(key: &[u8], data: &[u8], hash_fn: F) -> [u8; 32]
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut key_block = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        key_block[..32].copy_from_slice(&hash_fn(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];
    for index in 0..HMAC_BLOCK_SIZE {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Vec::with_capacity(HMAC_BLOCK_SIZE + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = hash_fn(&inner);
    let mut outer = Vec::with_capacity(HMAC_BLOCK_SIZE + inner_hash.len());
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    hash_fn(&outer)
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encrypt_aes_gcm(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .context("init VMess AES-128-GCM body")?
        .encrypt(
            AesNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt VMess AES-128-GCM body"))
}

fn decrypt_aes_gcm(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        ciphertext.len() >= AEAD_TAG_LEN,
        "VMess AES-GCM ciphertext too short"
    );
    Aes128Gcm::new_from_slice(key)
        .context("init VMess AES-128-GCM body")?
        .decrypt(
            AesNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("decrypt VMess AES-128-GCM body"))
}

fn encrypt_chacha20_poly1305(
    key: &[u8; CHACHA_KEY_LEN],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(key)
        .context("init VMess ChaCha20-Poly1305 body")?
        .encrypt(
            ChaChaNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt VMess ChaCha20-Poly1305 body"))
}

fn decrypt_chacha20_poly1305(
    key: &[u8; CHACHA_KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        ciphertext.len() >= AEAD_TAG_LEN,
        "VMess ChaCha20-Poly1305 ciphertext too short"
    );
    ChaCha20Poly1305::new_from_slice(key)
        .context("init VMess ChaCha20-Poly1305 body")?
        .decrypt(
            ChaChaNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("decrypt VMess ChaCha20-Poly1305 body"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn chacha_key_matches_reference() {
        let key = generate_chacha20_poly1305_key(b"0123456789abcdef");
        assert_eq!(
            hex::encode(key),
            "4032af8d61035123906e58e067140cc567304ba676a616064c4340059e1b6370"
        );
    }

    #[test]
    fn shake128_matches_known_vector_prefix() {
        let mut shake = Shake128::default();
        shake.finalize();
        let mut out = [0u8; 16];
        shake.squeeze(&mut out);
        assert_eq!(hex::encode(out), "7f9c2ba4e88f827d616045507605853e");
    }

    #[tokio::test]
    async fn packet_chunk_roundtrip_none() -> Result<()> {
        let mut options = RequestOptions::new(0);
        options.enable_chunk_stream();
        let config = BodyConfig::new_request(SecurityType::None, options, [0x11; 16], [0x22; 16])?;
        let (client, server) = duplex(4096);
        let write = tokio::spawn(async move {
            let mut writer = BodyWriter::new(client, config);
            writer.write_packet_plain(b"one").await?;
            writer.write_packet_plain(b"two").await?;
            writer.finish().await
        });
        let mut reader = BodyReader::new(server, config);
        assert_eq!(reader.read_packet().await?, Some(b"one".to_vec()));
        assert_eq!(reader.read_packet().await?, Some(b"two".to_vec()));
        assert_eq!(reader.read_packet().await?, None);
        write.await??;
        Ok(())
    }

    #[tokio::test]
    async fn stream_chunk_roundtrip_aes_gcm() -> Result<()> {
        let mut options = RequestOptions::new(0);
        options.enable_chunk_stream();
        let config =
            BodyConfig::new_request(SecurityType::Aes128Gcm, options, [0x11; 16], [0x22; 16])?;
        let (client, server) = duplex(4096);
        let write = tokio::spawn(async move {
            let mut writer = BodyWriter::new(client, config);
            writer.write_all_plain(b"encrypted-body").await?;
            writer.finish().await
        });
        let mut reader = BodyReader::new(server, config);
        let mut output = Vec::new();
        let mut buffer = [0u8; 16];
        loop {
            let read = reader.read_plain(&mut buffer).await?;
            if read == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..read]);
        }
        write.await??;
        assert_eq!(output, b"encrypted-body");
        Ok(())
    }
}
