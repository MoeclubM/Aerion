use super::table::{Decoder, Table, encode};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use anyhow::{Context, Result, ensure};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) fn bases(
    seed: &str,
    shared: Option<&[u8; 32]>,
    nonce: &[u8],
) -> Result<([u8; 32], [u8; 32])> {
    let hash = Sha256::digest(seed.as_bytes());
    let hk = if let Some(shared) = shared {
        Hkdf::<Sha256>::new(Some(&hash), &[shared.as_slice(), nonce].concat())
    } else {
        Hkdf::<Sha256>::from_prk(&hash).map_err(|_| anyhow::anyhow!("invalid Sudoku PSK"))?
    };
    let prefix = if shared.is_some() {
        "sudoku-session-"
    } else {
        "sudoku-psk-"
    };
    let mut up = [0; 32];
    let mut down = [0; 32];
    hk.expand(format!("{prefix}c2s").as_bytes(), &mut up)
        .map_err(|_| anyhow::anyhow!("Sudoku HKDF"))?;
    hk.expand(format!("{prefix}s2c").as_bytes(), &mut down)
        .map_err(|_| anyhow::anyhow!("Sudoku HKDF"))?;
    Ok((up, down))
}

fn crypt(
    method: &str,
    base: &[u8; 32],
    header: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(base).unwrap();
    mac.update(b"sudoku-record:");
    mac.update(method.as_bytes());
    mac.update(&header[..4]);
    let key = mac.finalize().into_bytes();
    let payload = Payload {
        msg: input,
        aad: header,
    };
    let result = match method {
        "aes-128-gcm" => {
            let cipher = Aes128Gcm::new_from_slice(&key[..16]).unwrap();
            if encrypt {
                cipher.encrypt(header.into(), payload)
            } else {
                cipher.decrypt(header.into(), payload)
            }
        }
        "chacha20-poly1305" => {
            let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
            if encrypt {
                cipher.encrypt(header.into(), payload)
            } else {
                cipher.decrypt(header.into(), payload)
            }
        }
        _ => anyhow::bail!("unsupported Sudoku AEAD {method}"),
    };
    result.map_err(|_| anyhow::anyhow!("Sudoku record authentication failed"))
}

pub(super) struct Receiver {
    pub decoder: Decoder,
    pub decoded: Vec<u8>,
    plain: Vec<u8>,
    base: [u8; 32],
    method: String,
    counter: Option<(u32, u64)>,
}
impl Receiver {
    pub fn new(table: Table, down: bool, packed: bool, base: [u8; 32], method: &str) -> Self {
        Self {
            decoder: Decoder::new(table, down, packed),
            decoded: Vec::new(),
            plain: Vec::new(),
            base,
            method: method.into(),
            counter: None,
        }
    }
    pub fn rekey(&mut self, base: [u8; 32]) {
        self.base = base;
        self.counter = None;
    }
    pub fn take_record(&mut self) -> Result<Option<Vec<u8>>> {
        if self.method == "none" {
            return Ok((!self.decoded.is_empty()).then(|| std::mem::take(&mut self.decoded)));
        }
        if self.decoded.len() < 2 {
            return Ok(None);
        }
        let length = u16::from_be_bytes(self.decoded[..2].try_into()?) as usize;
        ensure!(length >= 28, "short Sudoku record");
        if self.decoded.len() < length + 2 {
            return Ok(None);
        }
        let header = &self.decoded[2..14];
        let epoch = u32::from_be_bytes(header[..4].try_into()?);
        let seq = u64::from_be_bytes(header[4..].try_into()?);
        if let Some((old, next)) = self.counter {
            ensure!(
                (epoch == old && seq == next) || (epoch > old && epoch - old <= 8),
                "replayed or out-of-order Sudoku record"
            );
        }
        let plain = crypt(
            &self.method,
            &self.base,
            header,
            &self.decoded[14..length + 2],
            false,
        )?;
        self.counter = Some((
            epoch,
            seq.checked_add(1).context("Sudoku sequence exhausted")?,
        ));
        self.decoded.drain(..length + 2);
        Ok(Some(plain))
    }
    pub async fn read<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        if !self.plain.is_empty() {
            return Ok(std::mem::take(&mut self.plain));
        }
        loop {
            if let Some(plain) = self.take_record()? {
                if !plain.is_empty() {
                    return Ok(plain);
                }
            }
            let mut wire = [0; 8192];
            let n = reader.read(&mut wire).await?;
            if n == 0 {
                ensure!(self.decoded.is_empty(), "truncated Sudoku record");
                return Ok(Vec::new());
            }
            self.decoded.extend(self.decoder.feed(&wire[..n])?);
        }
    }
    pub async fn exact<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        length: usize,
    ) -> Result<Vec<u8>> {
        while self.plain.len() < length {
            let pending = std::mem::take(&mut self.plain);
            let next = self.read(reader).await?;
            self.plain = pending;
            ensure!(!next.is_empty(), "truncated Sudoku control message");
            self.plain.extend(next);
        }
        Ok(self.plain.drain(..length).collect())
    }
    pub fn prepend(&mut self, plain: Vec<u8>) {
        self.plain.splice(..0, plain);
    }
    pub async fn kip<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<(u8, Vec<u8>)> {
        let header = self.exact(reader, 6).await?;
        ensure!(&header[..3] == b"kip", "invalid Sudoku KIP magic");
        let n = u16::from_be_bytes(header[4..6].try_into()?) as usize;
        Ok((header[3], self.exact(reader, n).await?))
    }
}

pub(super) struct Sender {
    table: Table,
    down: bool,
    packed: bool,
    base: [u8; 32],
    method: String,
    epoch: u32,
    seq: u64,
    bytes: u64,
    padding: u8,
}
impl Sender {
    pub fn new(
        table: Table,
        down: bool,
        packed: bool,
        base: [u8; 32],
        method: &str,
        padding: u8,
    ) -> Result<Self> {
        let mut value = Self {
            table,
            down,
            packed,
            base,
            method: method.into(),
            epoch: 0,
            seq: 0,
            bytes: 0,
            padding,
        };
        value.rekey(base)?;
        Ok(value)
    }
    pub fn rekey(&mut self, base: [u8; 32]) -> Result<()> {
        let mut random = [0; 12];
        getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("Sudoku counters: {e}"))?;
        self.base = base;
        self.epoch = u32::from_be_bytes(random[..4].try_into()?).clamp(1, u32::MAX - 1);
        self.seq = u64::from_be_bytes(random[4..].try_into()?).clamp(1, u64::MAX - 1);
        self.bytes = 0;
        Ok(())
    }
    pub async fn write<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        input: &[u8],
    ) -> Result<()> {
        for chunk in input.chunks(65507) {
            let frame = if self.method == "none" {
                chunk.to_vec()
            } else {
                let mut header = self.epoch.to_be_bytes().to_vec();
                header.extend(self.seq.to_be_bytes());
                let ciphertext = crypt(&self.method, &self.base, &header, chunk, true)?;
                let mut frame = ((12 + ciphertext.len()) as u16).to_be_bytes().to_vec();
                frame.extend(header);
                frame.extend(ciphertext);
                self.seq = self
                    .seq
                    .checked_add(1)
                    .context("Sudoku sequence exhausted")?;
                frame
            };
            writer
                .write_all(&encode(
                    &self.table,
                    self.down,
                    self.packed,
                    &frame,
                    self.padding,
                )?)
                .await?;
            self.bytes += chunk.len() as u64;
            if self.bytes >= 32 << 20 {
                self.epoch = self
                    .epoch
                    .checked_add(1)
                    .context("Sudoku epoch exhausted")?;
                self.seq = 1;
                self.bytes = 0;
            }
        }
        writer.flush().await?;
        Ok(())
    }
    pub async fn kip<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        kind: u8,
        payload: &[u8],
    ) -> Result<()> {
        ensure!(payload.len() <= 65535, "Sudoku control payload too large");
        let mut message = b"kip".to_vec();
        message.push(kind);
        message.extend((payload.len() as u16).to_be_bytes());
        message.extend(payload);
        self.write(writer, &message).await
    }
}
