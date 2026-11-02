//! GI 7.1 metadata-usage + string-literal tables.
//!
//! Both are reachable from the runtime metadata resolver disassembled at `0x140524250`
//! (the eight-way jump-table resolver) and its only string branch, which calls the
//! decryption routine at `0x140526BD0` (single call site `0x14052460F`):
//!
//!   usage index table : body + (i32(hdr[0x19C]) ^ 0x159FBC84)   (u32 range starts)
//!   usage pair table  : body + (i32(hdr[0x14C]) ^ 0x2F249C2F)   (8B rows)
//!   literal offsets   : body + (hdr[0x88] + 0xF3C0B2FE)         (u32 cumulative offsets)
//!   literal data      : body + (hdr[0x13C] ^ 0x28B1D785)
//!
//! Row masks and the literal cipher were recovered instruction-by-instruction; the
//! Python counterpart is `tools/inspect_usage_tables.py` (validates 86,108 literals
//! against `literals.json` and 311,730 usages / 788,057 pairs).
//!
//! Note on version handling: like every other per-build constant in this crate these
//! belong to the 7.1 layout; when a new build rotates them this module must be
//! re-derived (see docs/re/71-usage-tables.md for the exact sites to watch).

use crate::mem::{Buffer, Memory};

/// Header slot / transform for the usage index table.
const H_USAGE_LISTS: usize = 0x19C;
const X_USAGE_LISTS: u32 = 0x159F_BC84;
/// Header slot / transform for the usage pair table.
const H_USAGE_PAIRS: usize = 0x14C;
const X_USAGE_PAIRS: u32 = 0x2F24_9C2F;
/// Header slot / transform for the literal offset table (add).
const H_LIT_OFFS: usize = 0x88;
const A_LIT_OFFS: u32 = 0xF3C0_B2FE;
/// Header slot / transform for the literal data blob (xor).
const H_LIT_DATA: usize = 0x13C;
const X_LIT_DATA: u32 = 0x28B1_D785;

/// Additive bias shared by both literal columns.
const LIT_BIAS: u32 = 0x8155_5D04;
/// Additive bias shared by both usage-range columns.
const USAGE_BIAS: u32 = 0xE649_5E3D;
/// Raw usage-index column is xor-obfuscated before the mask is applied.
const USAGE_RAW_XOR: u32 = 0x15A6_F604;
/// Usage pair handle: `raw @ +4 ^ mask(j) ^ 0x5CD30101`.
const PAIR_XOR_MASK: u32 = 0x615E_B706;
const PAIR_ADD: u32 = 0x63D4_6A21;
const PAIR_XOR_HANDLE: u32 = 0x5CD3_0101;

/// Literal cipher (decrypt_to_string 0x140526BD0):
/// `key = ((((seed*m1) ^ x1) * m2) ^ x2) * m3`, then `key += step` per 8-byte qword.
const LC_M1: u64 = 0x3404_4C3B_94B4_0C;
const LC_X1: u64 = 0x2C16_5A1E_0D09_C29E;
const LC_M2: u64 = 0x4D61_3E55_75A1_2594;
const LC_X2: u64 = 0x1B34_FA77_3FEE_107E;
const LC_M3: u64 = 0x2914_0A61_56B9_041E;
const LC_STEP: u64 = 0x70BA_8080_760A_C800;

/// Reference count of literals recovered for 7.1 (kept for validators).
pub const LITERAL_COUNT: usize = 86_108;
/// Reference count of usage groups / pair entries recovered for 7.1.
pub const USAGE_COUNT: usize = 311_730;
pub const PAIR_COUNT: usize = 788_057;

pub struct UsageTables<'a> {
    header: &'a [u8],
    body: Buffer<'a>,
}

impl<'a> UsageTables<'a> {
    pub fn new(header: &'a [u8], body: Buffer<'a>) -> Self {
        Self { header, body }
    }

    fn hdr_u32(&self, off: usize) -> Option<u32> {
        let b = self.header.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn literal_offsets_base(&self) -> usize {
        (self.hdr_u32(H_LIT_OFFS).unwrap_or(0).wrapping_add(A_LIT_OFFS)) as usize
    }

    pub fn literal_data_base(&self) -> usize {
        (self.hdr_u32(H_LIT_DATA).unwrap_or(0) ^ X_LIT_DATA) as usize
    }

    pub fn usage_lists_base(&self) -> usize {
        (self.hdr_u32(H_USAGE_LISTS).unwrap_or(0) ^ X_USAGE_LISTS) as usize
    }

    pub fn usage_pairs_base(&self) -> usize {
        (self.hdr_u32(H_USAGE_PAIRS).unwrap_or(0) ^ X_USAGE_PAIRS) as usize
    }

    /// Literal `i` byte range within the data blob.
    pub fn literal_bounds(&self, i: u32) -> Option<(u32, u32)> {
        let base = self.literal_offsets_base();
        let a = self.body.read_u32_opt(base + 4 * i as usize)?;
        let b = self.body.read_u32_opt(base + 4 * (i as usize + 1))?;
        let start = mask_literal(i).wrapping_add(a).wrapping_add(LIT_BIAS);
        let end = mask_literal(i.wrapping_add(1)).wrapping_add(b).wrapping_add(LIT_BIAS);
        Some((start, end))
    }

    /// Decrypted UTF-8 literal `i` (embedded NULs preserved, like the reference artifact).
    pub fn literal(&self, i: u32) -> Option<String> {
        let (start, end) = self.literal_bounds(i)?;
        if end < start || end - start > 0x2000 {
            return None;
        }
        let len = (end - start) as usize;
        let src = self.literal_data_base() + start as usize;
        if src > self.body.size() || src + len > self.body.size() {
            return None;
        }
        let mut key = ((i as u64).wrapping_mul(LC_M1) ^ LC_X1).wrapping_mul(LC_M2);
        key = (key ^ LC_X2).wrapping_mul(LC_M3);
        let mut out = Vec::with_capacity(len);
        let mut off = 0usize;
        while off < len {
            let q = self.body.read_u64_opt(src + off)?;
            out.extend_from_slice(&(q ^ key).to_le_bytes());
            key = key.wrapping_add(LC_STEP);
            off += 8;
        }
        out.truncate(len);
        Some(String::from_utf8_lossy(&out).into_owned())
    }

    /// Usage `i` pair range `[start, end)`.
    pub fn usage_range(&self, i: u32) -> Option<(u32, u32)> {
        let base = self.usage_lists_base();
        let a = self.body.read_u32_opt(base + 4 * i as usize)?;
        let b = self.body.read_u32_opt(base + 4 * (i as usize + 1))?;
        let start = mask_usage_index(i)
            .wrapping_add(a ^ USAGE_RAW_XOR)
            .wrapping_add(USAGE_BIAS);
        let end = mask_usage_index(i.wrapping_add(1))
            .wrapping_add(b ^ USAGE_RAW_XOR)
            .wrapping_add(USAGE_BIAS);
        Some((start, end))
    }

    /// Decoded handle of pair `j`; `handle >> 29` is the usage kind.
    pub fn usage_pair_handle(&self, j: u32) -> Option<u32> {
        let raw = self.body.read_u32_opt(self.usage_pairs_base() + 8 * j as usize + 4)?;
        Some(raw ^ mask_pair(j) ^ PAIR_XOR_HANDLE)
    }

    /// Visit every usage group; returns `(groups, pairs, kind histogram)`.
    pub fn scan_usages(&self, mut f: impl FnMut(u32, u32)) -> (usize, usize, [u64; 8]) {
        let mut kinds = [0u64; 8];
        let mut groups = 0usize;
        let mut last = 0u32;
        while groups < 400_000 {
            let Some((start, end)) = self.usage_range(groups as u32) else { break };
            if start > end || end - start > 200_000 || end > 1_000_000 {
                break;
            }
            last = end;
            for j in start..end {
                let Some(h) = self.usage_pair_handle(j) else { break };
                kinds[(h >> 29) as usize] += 1;
                f(h >> 29, h & 0x1FFF_FFFF);
            }
            groups += 1;
        }
        (groups, last as usize, kinds)
    }
}

#[inline]
fn mask_literal(i: u32) -> u32 {
    let mut r = (i as u64).wrapping_mul(0x9825);
    r ^= 0x2506_21A3;
    r = r.wrapping_mul(0x76C8_023D);
    r >>= 0xC;
    r = r.wrapping_mul(0x5E62_6528);
    r >>= 0xF;
    r = r.wrapping_add(0x3483_F478);
    (r as u32) ^ 0xA0D4_507F
}

#[inline]
fn mask_usage_index(i: u32) -> u32 {
    let mut r = (i as u64).wrapping_mul(0x6536);
    r ^= 0x138D_67F3;
    r = r.wrapping_mul(0x44B1_AAD4);
    r = r.wrapping_add(0x1F9E_A55A_D057_D0);
    (((r >> 0x15) as u32).wrapping_mul(0xD0DC_29D5)) & 0xFFFF_FFFF
}

#[inline]
fn mask_pair(j: u32) -> u32 {
    let mut r = (j as u64).wrapping_mul(0x3C5F_6DC3_F5D0);
    r >>= 0x14;
    ((r as u32) ^ PAIR_XOR_MASK).wrapping_add(PAIR_ADD)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_sample() -> Option<(Vec<u8>, Vec<u8>)> {
        let exe = std::fs::read(std::env::var("MHY_SAMPLE_EXE").ok()?).ok()?;
        let dat = std::fs::read(std::env::var("MHY_SAMPLE_DAT").ok()?).ok()?;
        let pe = crate::pe::Image::parse(&exe).ok()?;
        let off = pe.va_to_file(0x1427_D5CB0)? as usize;
        Some((exe[off..off + 0x210].to_vec(), dat[0x210..].to_vec()))
    }

    #[test]
    fn mask_chains_match_python_probe() {
        assert_eq!(mask_usage_index(0), 0xAC0D_DBDB);
        assert_eq!(mask_pair(0), 0xC533_2127);
        assert_eq!(mask_literal(0), 0xBA06_8D75);
    }

    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE / MHY_SAMPLE_DAT"]
    fn sample_literals_and_usages() {
        let Some((hdr, body)) = load_sample() else { return };
        let ut = UsageTables::new(&hdr, Buffer::new(&body));
        assert_eq!(ut.literal(0).as_deref(), Some("i"));
        assert_eq!(ut.literal(1).as_deref(), Some("m"));
        assert_eq!(ut.literal(6).as_deref(), Some(""));
        let mut n5 = 0u64;
        let mut first = true;
        let (groups, pairs, kinds) = ut.scan_usages(|k, _i| {
            if first { assert_eq!(k, 1); first = false; }
            if k == 5 { n5 += 1; }
        });
        eprintln!("groups={groups} pairs={pairs} kinds={kinds:?} kind5={n5}");
        assert_eq!(groups, USAGE_COUNT);
        assert_eq!(pairs, PAIR_COUNT);
        assert_eq!(kinds[5], 137_466);
    }
}
