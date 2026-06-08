use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

use super::NONCE_LEN;

const COMMON_64_SET: &[u8; 64] =
    b"!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz<>";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MieruTrafficPattern {
    pub tcp_fragment: Option<MieruTcpFragment>,
    pub nonce: Option<MieruNoncePattern>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MieruTcpFragment {
    pub enable: bool,
    pub max_sleep_ms: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MieruNonceType {
    Random,
    Printable,
    PrintableSubset,
    Fixed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MieruNoncePattern {
    pub kind: MieruNonceType,
    pub apply_to_all_udp_packet: bool,
    pub min_len: usize,
    pub max_len: usize,
    pub custom_prefixes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
struct RawTrafficPattern {
    seed: Option<i32>,
    unlock_all: Option<bool>,
    tcp_fragment: Option<RawTcpFragment>,
    nonce: Option<RawNoncePattern>,
}

#[derive(Clone, Debug, Default)]
struct RawTcpFragment {
    enable: Option<bool>,
    max_sleep_ms: Option<u8>,
}

#[derive(Clone, Debug, Default)]
struct RawNoncePattern {
    kind: Option<MieruNonceType>,
    apply_to_all_udp_packet: Option<bool>,
    min_len: Option<usize>,
    max_len: Option<usize>,
    custom_prefixes: Vec<Vec<u8>>,
}

impl MieruTrafficPattern {
    pub fn parse_pair(
        traffic_pattern: Option<&str>,
        nonce_pattern: Option<&str>,
    ) -> Result<Option<Self>> {
        let traffic_pattern = traffic_pattern
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let nonce_pattern = nonce_pattern
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let mut pattern = match traffic_pattern {
            Some(value) => Some(decode_traffic_pattern(value)?.into_effective()?),
            None => None,
        };
        if let Some(value) = nonce_pattern {
            let nonce = decode_nonce_pattern(value)?.into_effective(random_seed()?, false)?;
            match &mut pattern {
                Some(pattern) => pattern.nonce = Some(nonce),
                None => {
                    pattern = Some(Self {
                        tcp_fragment: None,
                        nonce: Some(nonce),
                    });
                }
            }
        }
        Ok(pattern)
    }
}

impl RawTrafficPattern {
    fn into_effective(self) -> Result<MieruTrafficPattern> {
        let seed = match self.seed {
            Some(seed) => seed,
            None => random_seed()?,
        };
        let unlock_all = self.unlock_all.unwrap_or(false);
        Ok(MieruTrafficPattern {
            tcp_fragment: Some(self.effective_tcp_fragment(seed, unlock_all)?),
            nonce: Some(
                self.nonce
                    .unwrap_or_default()
                    .into_effective(seed, unlock_all)?,
            ),
        })
    }

    fn effective_tcp_fragment(&self, seed: i32, unlock_all: bool) -> Result<MieruTcpFragment> {
        let raw = self.tcp_fragment.clone().unwrap_or_default();
        let enable = raw.enable.unwrap_or_else(|| {
            unlock_all && fixed_int(2, &format!("{seed}:tcpFragment.enable")) == 1
        });
        let max_sleep_ms = raw.max_sleep_ms.unwrap_or_else(|| {
            if unlock_all {
                fixed_int(100, &format!("{seed}:tcpFragment.maxSleepMs")) as u8 + 1
            } else {
                0
            }
        });
        ensure!(
            max_sleep_ms <= 100,
            "Mieru TCP fragment maxSleepMs exceeds 100"
        );
        Ok(MieruTcpFragment {
            enable,
            max_sleep_ms,
        })
    }
}

impl RawNoncePattern {
    fn into_effective(self, seed: i32, unlock_all: bool) -> Result<MieruNoncePattern> {
        let kind = self.kind.unwrap_or_else(|| {
            if unlock_all {
                match fixed_int(3, &format!("{seed}:nonce.type")) {
                    0 => MieruNonceType::Random,
                    1 => MieruNonceType::Printable,
                    _ => MieruNonceType::PrintableSubset,
                }
            } else {
                match fixed_int(2, &format!("{seed}:nonce.type")) {
                    0 => MieruNonceType::Printable,
                    _ => MieruNonceType::PrintableSubset,
                }
            }
        });
        let apply_to_all_udp_packet = self
            .apply_to_all_udp_packet
            .unwrap_or_else(|| fixed_int(2, &format!("{seed}:nonce.applyToAllUDPPacket")) == 1);
        let min_len = self.min_len.unwrap_or_else(|| {
            if unlock_all {
                fixed_int(13, &format!("{seed}:nonce.minLen"))
            } else {
                fixed_int(7, &format!("{seed}:nonce.minLen")) + 6
            }
        });
        ensure!(min_len <= 12, "Mieru nonce minLen exceeds 12");
        let max_len = self
            .max_len
            .unwrap_or_else(|| min_len + fixed_int(13 - min_len, &format!("{seed}:nonce.maxLen")));
        ensure!(max_len <= 12, "Mieru nonce maxLen exceeds 12");
        ensure!(
            min_len <= max_len,
            "Mieru nonce minLen is greater than maxLen"
        );
        for prefix in &self.custom_prefixes {
            ensure!(
                prefix.len() <= 12,
                "Mieru fixed nonce custom prefix exceeds 12 bytes"
            );
        }
        Ok(MieruNoncePattern {
            kind,
            apply_to_all_udp_packet,
            min_len,
            max_len,
            custom_prefixes: self.custom_prefixes,
        })
    }
}

impl MieruNonceType {
    fn from_u64(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Random),
            1 => Ok(Self::Printable),
            2 => Ok(Self::PrintableSubset),
            3 => Ok(Self::Fixed),
            other => bail!("unsupported Mieru nonce type {other}"),
        }
    }
}

fn decode_traffic_pattern(value: &str) -> Result<RawTrafficPattern> {
    let bytes = BASE64_STANDARD
        .decode(value.trim())
        .context("decode Mieru traffic-pattern base64 protobuf")?;
    let mut input = bytes.as_slice();
    let mut pattern = RawTrafficPattern::default();
    while !input.is_empty() {
        let key = read_protobuf_varint(&mut input)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 0) => pattern.seed = Some(read_protobuf_varint(&mut input)? as u32 as i32),
            (2, 0) => pattern.unlock_all = Some(read_protobuf_varint(&mut input)? != 0),
            (3, 2) => {
                pattern.tcp_fragment = Some(decode_tcp_fragment(read_protobuf_len(&mut input)?)?)
            }
            (4, 2) => {
                pattern.nonce = Some(decode_nonce_pattern_bytes(read_protobuf_len(&mut input)?)?)
            }
            _ => skip_protobuf_field(wire, &mut input)?,
        }
    }
    Ok(pattern)
}

fn decode_tcp_fragment(mut input: &[u8]) -> Result<RawTcpFragment> {
    let mut fragment = RawTcpFragment::default();
    while !input.is_empty() {
        let key = read_protobuf_varint(&mut input)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 0) => fragment.enable = Some(read_protobuf_varint(&mut input)? != 0),
            (2, 0) => {
                let value = read_protobuf_varint(&mut input)?;
                ensure!(value <= 100, "Mieru TCP fragment maxSleepMs exceeds 100");
                fragment.max_sleep_ms = Some(value as u8);
            }
            _ => skip_protobuf_field(wire, &mut input)?,
        }
    }
    Ok(fragment)
}

fn decode_nonce_pattern(value: &str) -> Result<RawNoncePattern> {
    let bytes = BASE64_STANDARD
        .decode(value.trim())
        .context("decode Mieru nonce-pattern base64 protobuf")?;
    decode_nonce_pattern_bytes(&bytes)
}

fn decode_nonce_pattern_bytes(mut input: &[u8]) -> Result<RawNoncePattern> {
    let mut pattern = RawNoncePattern::default();
    while !input.is_empty() {
        let key = read_protobuf_varint(&mut input)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 0) => {
                pattern.kind = Some(MieruNonceType::from_u64(read_protobuf_varint(&mut input)?)?)
            }
            (2, 0) => {
                pattern.apply_to_all_udp_packet = Some(read_protobuf_varint(&mut input)? != 0)
            }
            (3, 0) => {
                let value = read_protobuf_varint(&mut input)? as usize;
                ensure!(value <= 12, "Mieru nonce minLen exceeds 12");
                pattern.min_len = Some(value);
            }
            (4, 0) => {
                let value = read_protobuf_varint(&mut input)? as usize;
                ensure!(value <= 12, "Mieru nonce maxLen exceeds 12");
                pattern.max_len = Some(value);
            }
            (5, 2) => {
                let text = String::from_utf8(read_protobuf_len(&mut input)?.to_vec())
                    .context("decode Mieru fixed nonce hex prefix")?;
                let prefix =
                    hex::decode(text.trim()).context("decode Mieru fixed nonce hex prefix")?;
                ensure!(
                    prefix.len() <= 12,
                    "Mieru fixed nonce custom prefix exceeds 12 bytes"
                );
                pattern.custom_prefixes.push(prefix);
            }
            _ => skip_protobuf_field(wire, &mut input)?,
        }
    }
    if let (Some(min_len), Some(max_len)) = (pattern.min_len, pattern.max_len) {
        ensure!(
            min_len <= max_len,
            "Mieru nonce minLen is greater than maxLen"
        );
    }
    Ok(pattern)
}

fn read_protobuf_varint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        ensure!(!input.is_empty(), "truncated Mieru protobuf varint");
        let byte = input[0];
        *input = &input[1..];
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("Mieru protobuf varint is too long")
}

fn read_protobuf_len<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = read_protobuf_varint(input)? as usize;
    ensure!(
        input.len() >= len,
        "truncated Mieru protobuf length-delimited field"
    );
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

fn skip_protobuf_field(wire: u64, input: &mut &[u8]) -> Result<()> {
    match wire {
        0 => {
            read_protobuf_varint(input)?;
        }
        1 => {
            ensure!(input.len() >= 8, "truncated Mieru protobuf fixed64");
            *input = &input[8..];
        }
        2 => {
            read_protobuf_len(input)?;
        }
        5 => {
            ensure!(input.len() >= 4, "truncated Mieru protobuf fixed32");
            *input = &input[4..];
        }
        other => bail!("unsupported Mieru protobuf wire type {other}"),
    }
    Ok(())
}

fn fixed_int(n: usize, hint: &str) -> usize {
    if n == 0 {
        return 0;
    }
    let digest = Sha256::digest(hint.as_bytes());
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&digest[..4]);
    bytes[0] &= 0x7f;
    u32::from_be_bytes(bytes) as usize % n
}

fn random_seed() -> Result<i32> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).context("generate Mieru traffic-pattern seed")?;
    bytes[0] &= 0x7f;
    Ok(i32::from_be_bytes(bytes))
}

pub(super) async fn write_with_possible_fragment(
    writer: &mut OwnedWriteHalf,
    data: &[u8],
    traffic_pattern: &Option<MieruTrafficPattern>,
) -> Result<()> {
    let Some(fragment) = traffic_pattern
        .as_ref()
        .and_then(|pattern| pattern.tcp_fragment.as_ref())
    else {
        writer.write_all(data).await?;
        return Ok(());
    };
    if !fragment.enable {
        writer.write_all(data).await?;
        return Ok(());
    }
    let min_len = (data.len() as f64).sqrt() as usize + 1;
    let max_len = min_len.max(data.len() / 2);
    let mut remaining = data;
    while !remaining.is_empty() {
        let mut len = min_len + random_usize_below(max_len - min_len + 1)?;
        if len > remaining.len() {
            len = remaining.len();
        }
        writer.write_all(&remaining[..len]).await?;
        remaining = &remaining[len..];
        if fragment.max_sleep_ms > 0 && !remaining.is_empty() {
            let sleep_ms = random_usize_below(fragment.max_sleep_ms as usize + 1)? as u64;
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        }
    }
    Ok(())
}

pub(super) fn apply_nonce_pattern(
    nonce: &mut [u8; NONCE_LEN],
    pattern: &MieruNoncePattern,
) -> Result<()> {
    match pattern.kind {
        MieruNonceType::Random => {}
        MieruNonceType::Printable => {
            let rewrite_len = nonce_rewrite_len(pattern)?;
            for byte in &mut nonce[..rewrite_len] {
                if *byte < 0x20 || *byte > 0x7e {
                    let low_bits = *byte & 0x7f;
                    if (0x20..=0x7e).contains(&low_bits) {
                        *byte = low_bits;
                    } else {
                        *byte = 0x20 + random_usize_below(0x7f - 0x20)? as u8;
                    }
                }
            }
        }
        MieruNonceType::PrintableSubset => {
            let rewrite_len = nonce_rewrite_len(pattern)?;
            for byte in &mut nonce[..rewrite_len] {
                *byte = COMMON_64_SET[(*byte & 0x3f) as usize];
            }
        }
        MieruNonceType::Fixed => {
            if !pattern.custom_prefixes.is_empty() {
                let prefix =
                    &pattern.custom_prefixes[random_usize_below(pattern.custom_prefixes.len())?];
                nonce[..prefix.len()].copy_from_slice(prefix);
            }
        }
    }
    Ok(())
}

fn nonce_rewrite_len(pattern: &MieruNoncePattern) -> Result<usize> {
    let min_len = pattern.min_len.min(NONCE_LEN);
    let max_len = pattern.max_len.min(NONCE_LEN);
    if min_len >= max_len {
        return Ok(min_len);
    }
    Ok(min_len + random_usize_below(max_len - min_len + 1)?)
}

fn random_usize_below(n: usize) -> Result<usize> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).context("generate Mieru traffic-pattern randomness")?;
    Ok((u64::from_be_bytes(bytes) as usize) % n)
}
