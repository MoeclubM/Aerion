use anyhow::{Result, ensure};

pub(crate) const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;
pub(crate) const MAX_PENDING_PACKETS: usize = 64;

pub(crate) struct FragmentPayload {
    chunks: Vec<Option<Vec<u8>>>,
    remaining: usize,
    length: usize,
}

impl FragmentPayload {
    pub(crate) fn new(count: u8) -> Self {
        Self {
            chunks: vec![None; usize::from(count)],
            remaining: usize::from(count),
            length: 0,
        }
    }

    pub(crate) fn count(&self) -> usize {
        self.chunks.len()
    }

    pub(crate) fn insert(&mut self, index: u8, payload: Vec<u8>) -> Result<Option<Vec<u8>>> {
        ensure!(self.remaining > 0, "UDP packet already reassembled");
        let slot = self
            .chunks
            .get_mut(usize::from(index))
            .ok_or_else(|| anyhow::anyhow!("UDP fragment index out of range"))?;
        ensure!(slot.is_none(), "duplicate UDP fragment");
        ensure!(
            payload.len() <= MAX_UDP_PAYLOAD - self.length,
            "reassembled UDP payload too large"
        );
        self.length += payload.len();
        self.remaining -= 1;
        *slot = Some(payload);
        if self.remaining != 0 {
            return Ok(None);
        }
        let mut payload = Vec::with_capacity(self.length);
        for chunk in &mut self.chunks {
            payload.extend(chunk.take().expect("all UDP fragments received"));
        }
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests;
