//! Wire-compatible 4x4 Sudoku appearance codec. The grid numbering and seeded
//! shuffle are protocol constants, shared by the official Go implementation.
use anyhow::{Result, bail, ensure};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

mod go_rand;

struct Grids {
    values: Vec<[u8; 16]>,
    clues: Vec<u16>,
    encodings: Vec<Vec<[u8; 4]>>,
}

fn grids() -> &'static Grids {
    static GRIDS: OnceLock<Grids> = OnceLock::new();
    GRIDS.get_or_init(|| {
        fn fill(values: &mut Vec<[u8; 16]>, grid: &mut [u8; 16], pos: usize) {
            if pos == 16 {
                values.push(*grid);
                return;
            }
            let (row, col) = (pos / 4, pos % 4);
            for value in 1..=4 {
                if (0..pos).any(|i| {
                    grid[i] == value
                        && (i / 4 == row
                            || i % 4 == col
                            || (i / 8 == row / 2 && i % 4 / 2 == col / 2))
                }) {
                    continue;
                }
                grid[pos] = value;
                fill(values, grid, pos + 1);
                grid[pos] = 0;
            }
        }
        let mut values = Vec::new();
        fill(&mut values, &mut [0; 16], 0);
        let mut clues = HashMap::new();
        for (index, grid) in values.iter().enumerate() {
            for a in 0..13 {
                for b in a + 1..14 {
                    for c in b + 1..15 {
                        for d in c + 1..16 {
                            let hints = [a, b, c, d].map(|p| ((grid[p] - 1) << 4) | p as u8);
                            let key = clue_key(hints);
                            clues
                                .entry(key)
                                .and_modify(|v| *v = usize::MAX)
                                .or_insert(index);
                        }
                    }
                }
            }
        }
        clues.retain(|_, v| *v != usize::MAX);
        let mut encodings = vec![Vec::new(); values.len()];
        for (&key, &index) in &clues {
            encodings[index].push(key.to_be_bytes());
        }
        for entries in &mut encodings {
            entries.sort_unstable();
        }
        // Rank sorted four-clue sets into C(64, 4) slots. The bounded 1.2 MiB
        // lookup replaces a hash and pointer chase for every plaintext byte.
        let mut lookup = vec![u16::MAX; 635_376];
        for (key, index) in clues {
            lookup[clue_index(key.to_be_bytes()).unwrap()] = index as u16;
        }
        Grids {
            values,
            clues: lookup,
            encodings,
        }
    })
}

fn sorted_hints([a, b, c, d]: [u8; 4]) -> [u8; 4] {
    // A fixed sorting network avoids unpredictable comparisons when every
    // received byte uses a newly shuffled set of four clues.
    let (a, b) = (a.min(b), a.max(b));
    let (c, d) = (c.min(d), c.max(d));
    let (a, c) = (a.min(c), a.max(c));
    let (b, d) = (b.min(d), b.max(d));
    let (b, c) = (b.min(c), b.max(c));
    [a, b, c, d]
}

fn clue_key(hints: [u8; 4]) -> u32 {
    u32::from_be_bytes(sorted_hints(hints))
}

const CLUE_RANK: [[usize; 4]; 64] = {
    let mut ranks = [[0; 4]; 64];
    let mut n = 0;
    while n < 64 {
        let mut k = 1;
        let mut value = 1;
        while k <= 4 {
            if n >= k {
                value = value * (n + 1 - k) / k;
                ranks[n][k - 1] = value;
            }
            k += 1;
        }
        n += 1;
    }
    ranks
};

fn clue_index(hints: [u8; 4]) -> Option<usize> {
    let [a, b, c, d] = sorted_hints(hints).map(usize::from);
    if a == b || b == c || c == d {
        return None;
    }
    Some(CLUE_RANK[a][0] + CLUE_RANK[b][1] + CLUE_RANK[c][2] + CLUE_RANK[d][3])
}

#[derive(Clone, Debug)]
pub(super) struct Layout {
    encode: [u8; 64],
    decode: [u8; 256],
    padding: Vec<u8>,
    packed_padding: Vec<u8>,
    marker: u8,
}

impl Layout {
    fn new(ascii: bool, pattern: &str) -> Result<Self> {
        let mut out = Self {
            encode: [0; 64],
            decode: [255; 256],
            padding: Vec::new(),
            packed_padding: Vec::new(),
            marker: 0,
        };
        if ascii {
            out.marker = 0x3f;
            out.padding = (0x20..=0x3f).collect();
            for group in 0..64 {
                let b = if group == 63 {
                    b'\n'
                } else {
                    0x40 | group as u8
                };
                out.encode[group] = b;
                out.decode[b as usize] = group as u8;
            }
        } else if pattern.is_empty() {
            out.marker = 0x80;
            for i in 0..8 {
                out.padding.extend_from_slice(&[0x80 + i, 0x10 + i]);
            }
            for group in 0..64 {
                let b = ((group as u8 & 0x30) << 1) | (group as u8 & 15);
                out.encode[group] = b;
                out.decode[b as usize] = group as u8;
            }
        } else {
            let pattern = pattern.trim().to_ascii_lowercase().replace(' ', "");
            ensure!(
                pattern.len() == 8,
                "Sudoku custom table needs eight symbols"
            );
            let positions = |symbol| {
                pattern
                    .bytes()
                    .enumerate()
                    .filter_map(|(i, b)| (b == symbol).then_some(7 - i))
                    .collect::<Vec<_>>()
            };
            let (x, p, v) = (positions(b'x'), positions(b'p'), positions(b'v'));
            ensure!(
                x.len() == 2 && p.len() == 2 && v.len() == 4,
                "Sudoku custom table needs 2 x, 2 p and 4 v"
            );
            let mask = (1 << x[0]) | (1 << x[1]);
            for group in 0..64u8 {
                let mut b = mask;
                for (i, bit) in p.iter().chain(v.iter()).enumerate() {
                    b |= ((group >> (5 - i)) & 1) << bit;
                }
                out.encode[group as usize] = b;
                out.decode[b as usize] = group;
                for bit in &x {
                    let pad = b & !(1 << bit);
                    if pad.count_ones() >= 5 {
                        out.padding.push(pad);
                    }
                }
            }
            out.padding.sort_unstable();
            out.padding.dedup();
            out.marker = out.padding[0];
        }
        out.packed_padding = out
            .padding
            .iter()
            .copied()
            .filter(|b| *b != out.marker)
            .collect();
        Ok(out)
    }
}

#[derive(Clone)]
pub(super) struct Table {
    order: Arc<Vec<usize>>,
    inverse: Arc<Vec<u16>>,
    pub up: Arc<Layout>,
    pub down: Arc<Layout>,
    pub hint: u32,
}

impl Table {
    pub fn new(seed: &str, mode: &str, pattern: &str) -> Result<Self> {
        let (up, down, canonical) = match mode {
            "" | "entropy" | "prefer_entropy" => (false, false, "prefer_entropy"),
            "ascii" | "prefer_ascii" => (true, true, "prefer_ascii"),
            "up_ascii_down_entropy" => (true, false, "up_ascii_down_entropy"),
            "up_entropy_down_ascii" => (false, true, "up_entropy_down_ascii"),
            _ => bail!("invalid Sudoku table type {mode}"),
        };
        let hash = Sha256::digest(seed.as_bytes());
        let mut order = (0..grids().values.len()).collect::<Vec<_>>();
        go_rand::shuffle(&mut order, i64::from_be_bytes(hash[..8].try_into()?));
        let mut inverse = vec![256; order.len()];
        for (byte, &grid) in order.iter().take(256).enumerate() {
            inverse[grid] = byte as u16;
        }
        let pattern = pattern.trim().to_ascii_lowercase();
        let up_pattern = if up { "" } else { &pattern };
        let down_pattern = if down { "" } else { &pattern };
        let fingerprint = [
            "sudoku-table-hint",
            seed,
            canonical,
            up_pattern,
            down_pattern,
        ]
        .join("\0");
        let hint = u32::from_be_bytes(Sha256::digest(fingerprint.as_bytes())[..4].try_into()?);
        Ok(Self {
            order: Arc::new(order),
            inverse: Arc::new(inverse),
            up: Arc::new(Layout::new(up, up_pattern)?),
            down: Arc::new(Layout::new(down, down_pattern)?),
            hint,
        })
    }
    fn decode(&self, hints: [u8; 4]) -> Result<u8> {
        let slot = clue_index(hints).ok_or_else(|| anyhow::anyhow!("invalid Sudoku puzzle"))?;
        let index = grids().clues[slot];
        ensure!(index != u16::MAX, "invalid Sudoku puzzle");
        let value = self.inverse[index as usize];
        ensure!(value < 256, "Sudoku puzzle is outside byte mapping");
        Ok(value as u8)
    }
}

pub(super) struct Decoder {
    table: Table,
    layout: Arc<Layout>,
    packed: bool,
    hints: [u8; 4],
    bits: u32,
    count: u8,
}
impl Decoder {
    pub fn new(table: Table, down: bool, packed: bool) -> Self {
        let layout = if down {
            table.down.clone()
        } else {
            table.up.clone()
        };
        Self {
            table,
            layout,
            packed,
            hints: [0; 4],
            bits: 0,
            count: 0,
        }
    }
    #[cfg(test)]
    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(if self.packed {
            input.len() * 3 / 4 + 1
        } else {
            input.len() / 4 + 1
        });
        self.feed_into(input, &mut output)?;
        Ok(output)
    }
    pub fn feed_into(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<()> {
        if self.packed {
            self.feed_packed(input, output);
            return Ok(());
        }
        for &byte in input {
            let group = self.layout.decode[byte as usize];
            if group == 255 {
                continue;
            }
            self.hints[self.count as usize] = group;
            self.count += 1;
            if self.count == 4 {
                output.push(self.table.decode(self.hints)?);
                self.count = 0;
            }
        }
        Ok(())
    }
    fn feed_packed(&mut self, input: &[u8], output: &mut Vec<u8>) {
        let mut pos = 0;
        while pos < input.len() {
            // Four aligned six-bit symbols yield three bytes, including when
            // a record spans reads. Padding/markers use the scalar path.
            if self.count == 0 && pos + 4 <= input.len() {
                let [a, b, c, d] =
                    std::array::from_fn(|i| self.layout.decode[input[pos + i] as usize]);
                if a != 255 && b != 255 && c != 255 && d != 255 {
                    output.extend_from_slice(&[
                        (a << 2) | (b >> 4),
                        (b << 4) | (c >> 2),
                        (c << 6) | d,
                    ]);
                    pos += 4;
                    continue;
                }
            }
            let byte = input[pos];
            pos += 1;
            let group = self.layout.decode[byte as usize];
            if group == 255 {
                if byte == self.layout.marker {
                    self.bits = 0;
                    self.count = 0;
                }
                continue;
            }
            self.bits = (self.bits << 6) | group as u32;
            self.count += 6;
            if self.count >= 8 {
                self.count -= 8;
                output.push((self.bits >> self.count) as u8);
                self.bits &= (1 << self.count) - 1;
            }
        }
    }
}

pub(super) struct Encoder {
    rng: StdRng,
    random: Vec<u8>,
    output: Vec<u8>,
}
impl Encoder {
    pub fn new() -> Result<Self> {
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("Sudoku appearance seed: {e}"))?;
        Ok(Self {
            rng: StdRng::from_seed(seed),
            random: Vec::new(),
            output: Vec::new(),
        })
    }
    // Appearance randomness is independent of AEAD keys/counters. Seed a
    // standard CSPRNG once per direction instead of asking the OS for up to
    // twelve random bytes for every plaintext byte. Keep padding unchanged.
    pub fn encode(
        &mut self,
        table: &Table,
        down: bool,
        packed: bool,
        input: &[u8],
        padding: u8,
    ) -> &[u8] {
        let layout = if down { &table.down } else { &table.up };
        let groups = if packed {
            (input.len() * 8).div_ceil(6)
        } else {
            input.len() * 4
        };
        let draw_len = if padding == 0 { 0 } else { groups * 2 };
        let puzzle_len = if packed { 0 } else { input.len() * 4 };
        self.random.resize(draw_len + puzzle_len, 0);
        self.rng.fill_bytes(&mut self.random);
        let (padding_random, puzzle_random) = self.random.split_at(draw_len);
        let mut draw = padding_random.iter().copied();
        let pool = if packed {
            &layout.packed_padding
        } else {
            &layout.padding
        };
        self.output.clear();
        self.output
            .reserve(groups * if padding == 0 { 1 } else { 2 } + usize::from(packed));
        let output = &mut self.output;
        let mut emit = |group: u8| {
            if padding != 0 && draw.next().unwrap() as u16 * 100 < padding as u16 * 256 {
                output.push(pool[draw.next().unwrap() as usize % pool.len()]);
            }
            output.push(layout.encode[group as usize]);
        };
        if packed {
            let mut triples = input.chunks_exact(3);
            for chunk in &mut triples {
                let (a, b, c) = (chunk[0], chunk[1], chunk[2]);
                emit(a >> 2);
                emit(((a & 3) << 4) | (b >> 4));
                emit(((b & 15) << 2) | (c >> 6));
                emit(c & 63);
            }
            let (mut bits, mut count) = (0u32, 0u8);
            for &byte in triples.remainder() {
                bits = (bits << 8) | byte as u32;
                count += 8;
                while count >= 6 {
                    count -= 6;
                    emit(((bits >> count) & 63) as u8);
                }
                bits &= (1 << count) - 1;
            }
            if count > 0 {
                emit((bits << (6 - count)) as u8);
                output.push(layout.marker);
            }
        } else {
            for (index, &byte) in input.iter().enumerate() {
                let choices = &grids().encodings[table.order[byte as usize]];
                let random = &puzzle_random[index * 4..index * 4 + 4];
                let mut hints =
                    choices[u16::from_be_bytes([random[0], random[1]]) as usize % choices.len()];
                // Clue order has no meaning on the wire.
                for i in (1..4).rev() {
                    hints.swap(i, random[i] as usize % (i + 1));
                }
                for group in hints {
                    emit(group);
                }
            }
        }
        &self.output
    }
}

#[cfg(test)]
pub(super) fn encode(
    table: &Table,
    down: bool,
    packed: bool,
    input: &[u8],
    padding: u8,
) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new()?;
    encoder.encode(table, down, packed, input, padding);
    Ok(encoder.output)
}
