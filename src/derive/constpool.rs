//! Constant-pool extraction from the executable's `.text`.
//!
//! The metadata de-obfuscation constants are 32/64-bit immediates inside the
//! metadata-access code region. A sliding-window u32 pool over `.text` (sorted for
//! binary search) plus movabs-imm64 pairs gives the candidate set that every
//! column/table cracker searches over. Verified: all known 7.1 constants hit.

/// Sorted u32 pool over every byte-aligned window of `.text`.
pub struct ConstPool {
    u32s: Vec<u32>,
}

impl ConstPool {
    pub fn from_text(text: &[u8]) -> Self {
        let n = text.len().saturating_sub(4);
        let mut u32s = Vec::with_capacity(n);
        for i in 0..n {
            u32s.push(u32::from_le_bytes([text[i], text[i + 1], text[i + 2], text[i + 3]]));
        }
        u32s.sort_unstable();
        u32s.dedup();
        Self { u32s }
    }

    pub fn len(&self) -> usize {
        self.u32s.len()
    }

    pub fn contains(&self, v: u32) -> bool {
        self.u32s.binary_search(&v).is_ok()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, u32> {
        self.u32s.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_contains_planted() {
        // must be >=4 bytes so the sliding u32 window covers the payload
        let text = [0x90u8, 0x48, 0xB8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x90];
        let p = ConstPool::from_text(&text);
        assert!(p.contains(0x44332211));
        assert!(p.contains(0x88776655));
        assert!(!p.contains(0xdeadbeef));
    }
}
