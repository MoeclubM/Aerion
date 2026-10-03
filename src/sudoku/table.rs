//! Wire-compatible 4x4 Sudoku appearance codec. The grid numbering and seeded
//! shuffle are protocol constants, shared by the official Go implementation.
use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

mod go_rand;

struct Grids {
    values: Vec<[u8; 16]>,
    clues: HashMap<u32, usize>,
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
        Grids {
            values,
            clues,
            encodings,
        }
    })
}

fn clue_key(mut hints: [u8; 4]) -> u32 {
    hints.sort_unstable();
    u32::from_be_bytes(hints)
}

#[derive(Clone, Debug)]
pub(super) struct Layout {
    encode: [u8; 64],
    decode: [u8; 256],
    padding: Vec<u8>,
    marker: u8,
}

impl Layout {
    fn new(ascii: bool, pattern: &str) -> Result<Self> {
        let mut out = Self {
            encode: [0; 64],
            decode: [255; 256],
            padding: Vec::new(),
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
        Ok(out)
    }
}

#[derive(Clone)]
pub(super) struct Table {
    order: Arc<Vec<usize>>,
    inverse: Arc<Vec<u16>>,
    pub up: Layout,
    pub down: Layout,
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
            up: Layout::new(up, up_pattern)?,
            down: Layout::new(down, down_pattern)?,
            hint,
        })
    }
    fn decode(&self, hints: [u8; 4]) -> Result<u8> {
        let index = grids()
            .clues
            .get(&clue_key(hints))
            .ok_or_else(|| anyhow::anyhow!("invalid Sudoku puzzle"))?;
        let value = self.inverse[*index];
        ensure!(value < 256, "Sudoku puzzle is outside byte mapping");
        Ok(value as u8)
    }
}

pub(super) struct Decoder {
    table: Table,
    layout: Layout,
    packed: bool,
    hints: Vec<u8>,
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
            hints: Vec::new(),
            bits: 0,
            count: 0,
        }
    }
    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for &byte in input {
            let group = self.layout.decode[byte as usize];
            if group == 255 {
                if self.packed && byte == self.layout.marker {
                    self.bits = 0;
                    self.count = 0;
                }
                continue;
            }
            if self.packed {
                self.bits = (self.bits << 6) | group as u32;
                self.count += 6;
                if self.count >= 8 {
                    self.count -= 8;
                    output.push((self.bits >> self.count) as u8);
                    self.bits &= (1 << self.count) - 1;
                }
            } else {
                self.hints.push(group);
                if self.hints.len() == 4 {
                    output.push(self.table.decode(self.hints.as_slice().try_into()?)?);
                    self.hints.clear();
                }
            }
        }
        Ok(output)
    }
}

pub(super) fn encode(
    table: &Table,
    down: bool,
    packed: bool,
    input: &[u8],
    padding: u8,
) -> Result<Vec<u8>> {
    let layout = if down { &table.down } else { &table.up };
    let mut random = vec![0; input.len() * 6 + 32];
    getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("Sudoku random source: {e}"))?;
    let mut draw = random.into_iter().cycle();
    let mut output = Vec::new();
    let mut emit = |group: u8| {
        if draw.next().unwrap() as u16 * 100 < padding as u16 * 256 {
            let pool = layout
                .padding
                .iter()
                .copied()
                .filter(|b| !packed || *b != layout.marker)
                .collect::<Vec<_>>();
            output.push(pool[draw.next().unwrap() as usize % pool.len()]);
        }
        output.push(layout.encode[group as usize]);
    };
    if packed {
        let (mut bits, mut count) = (0u32, 0u8);
        for &byte in input {
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
        for &byte in input {
            let choices = &grids().encodings[table.order[byte as usize]];
            let mut hints = choices[(byte as usize + input.len()) % choices.len()];
            // Clue order has no meaning on the wire.
            hints.rotate_left(byte as usize % 4);
            for group in hints {
                emit(group);
            }
        }
    }
    Ok(output)
}
