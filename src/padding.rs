use anyhow::{Context, Result, ensure};
use md5::{Digest as Md5Digest, Md5};

pub const PADDING_CHECKPOINT: isize = -1;

const DEFAULT_SCHEME: &[&str] = &[
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000",
];

#[derive(Clone, Debug)]
pub struct PaddingScheme {
    raw: Vec<String>,
    md5: String,
    stop: u32,
    rules: Vec<(u32, Vec<PaddingRule>)>,
}

#[derive(Clone, Debug)]
enum PaddingRule {
    Range(usize, usize),
    Checkpoint,
}

impl Default for PaddingScheme {
    fn default() -> Self {
        Self::from_lines(Self::default_lines()).expect("default padding scheme must be valid")
    }
}

impl PaddingScheme {
    pub fn default_lines() -> Vec<String> {
        DEFAULT_SCHEME.iter().map(|line| line.to_string()).collect()
    }

    pub fn from_lines(lines: Vec<String>) -> Result<Self> {
        let raw = lines
            .into_iter()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        Self::from_text(&raw.join("\n"))
    }

    pub fn from_text(raw: &str) -> Result<Self> {
        let raw_lines = raw
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        let raw_text = raw_lines.join("\n");
        let mut stop = None;
        let mut rules = Vec::new();
        for line in &raw_lines {
            let (key, value) = line
                .split_once('=')
                .with_context(|| format!("invalid padding line: {line}"))?;
            if key == "stop" {
                let parsed = value.parse::<u32>().context("parse padding stop")?;
                ensure!(parsed > 0, "padding stop must be positive");
                stop = Some(parsed);
                continue;
            }
            let packet = key
                .parse::<u32>()
                .with_context(|| format!("parse padding packet index: {key}"))?;
            let mut packet_rules = Vec::new();
            for rule in value.split(',') {
                if rule == "c" {
                    packet_rules.push(PaddingRule::Checkpoint);
                    continue;
                }
                let (min, max) = rule
                    .split_once('-')
                    .with_context(|| format!("invalid padding range: {rule}"))?;
                let mut min = min
                    .parse::<usize>()
                    .with_context(|| format!("parse padding range minimum: {rule}"))?;
                let mut max = max
                    .parse::<usize>()
                    .with_context(|| format!("parse padding range maximum: {rule}"))?;
                if min > max {
                    std::mem::swap(&mut min, &mut max);
                }
                ensure!(min > 0 && max > 0, "padding range must be positive");
                packet_rules.push(PaddingRule::Range(min, max));
            }
            rules.push((packet, packet_rules));
        }
        let stop = stop.context("padding scheme missing stop")?;
        Ok(Self {
            raw: raw_lines,
            md5: hex::encode(Md5::digest(raw_text.as_bytes())),
            stop,
            rules,
        })
    }

    pub fn md5(&self) -> &str {
        &self.md5
    }

    pub fn raw_text(&self) -> String {
        self.raw.join("\n")
    }

    pub fn stop(&self) -> u32 {
        self.stop
    }

    pub fn preface_padding_len(&self) -> Result<usize> {
        let size = self
            .record_payload_sizes(0)?
            .into_iter()
            .find(|size| *size >= 0)
            .unwrap_or(0);
        ensure!(
            size <= u16::MAX as isize,
            "preface padding length out of range"
        );
        Ok(size as usize)
    }

    pub fn record_payload_sizes(&self, packet: u32) -> Result<Vec<isize>> {
        let Some((_, rules)) = self.rules.iter().find(|(index, _)| *index == packet) else {
            return Ok(Vec::new());
        };
        let mut sizes = Vec::with_capacity(rules.len());
        for rule in rules {
            match rule {
                PaddingRule::Checkpoint => sizes.push(PADDING_CHECKPOINT),
                PaddingRule::Range(min, max) if min == max => sizes.push(*min as isize),
                PaddingRule::Range(min, max) => {
                    let mut bytes = [0u8; 8];
                    getrandom::fill(&mut bytes)
                        .map_err(|error| anyhow::anyhow!("generate padding randomness: {error}"))?;
                    let span = (*max - *min) as u64;
                    sizes.push((*min + (u64::from_ne_bytes(bytes) % span) as usize) as isize);
                }
            }
        }
        Ok(sizes)
    }
}

#[cfg(test)]
mod tests;
