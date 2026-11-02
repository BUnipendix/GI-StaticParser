//! TypeDefinition table walk for the current-generation layout (stride 0x46).
//!
//! Per-build constants below are re-derived for a new build by decompiling the
//! in-game class-lookup routine (the table base expression and the two index
//! transforms) — see the repo notes.
//!
//! Layout: each 0x46-byte record carries a sanity tag at +0x1C (mismatch =
//! hidden entry), the name index at +0x14 (`idx = u32 + C_NAME`, sentinel
//! stored value = NAME_SENTINEL means idx -1) and the namespace index at +0x18
//! (`idx = u32 ^ C_NS`). Index packing: offset in low 24 bits, length in the
//! next 8. The identifier heap is packed without terminators.

use anyhow::Result;
use std::io::Write;

use crate::decrypt::Metadata;
use crate::decode_str::decode_str;
use crate::mem::Buffer;

pub const TD_HDR_FIELD: usize = 0xDC;
pub const TD_HDR_XOR: u32 = 0x5278_CA3B;
pub const TD_STRIDE: usize = 0x46;
pub const REC_MAGIC: i32 = -0x2145_AFB7;
pub const C_NAME: u32 = 0xE811_F779;
pub const C_NS: u32 = 0x6667_69B5;
pub const NAME_SENTINEL: u32 = 0x17EE_0886;
/// `strsec = i32(header+0x150) - STRSEC_BIAS` (keep in sync with decrypt/file.rs)
const STRSEC_BIAS: i64 = 0x37AB_D22E as i64;

/// Walk the TypeDefinition table and write `tdi<TAB>Namespace.Name` lines.
/// Returns (visible types, hidden-marker records skipped).
pub fn dump_types(md: &Metadata, w: &mut dyn Write) -> Result<(usize, usize)> {
    let body = Buffer::new(&md.body);
    let td_base = (u32_le(&md.header, TD_HDR_FIELD) ^ TD_HDR_XOR) as usize;
    let strsec = strsec_of(md);
    let mut visible = 0usize;
    let mut hidden = 0usize;
    let mut run_bad = 0usize;
    let n_rec = (md.body.len().saturating_sub(td_base)) / TD_STRIDE;
    for i in 0..n_rec.min(300_000) {
        let rec = td_base + i * TD_STRIDE;
        let Some(magic) = body.read_u32_opt(rec + 0x1C) else { break };
        if (magic as i32) != REC_MAGIC {
            hidden += 1;
            run_bad += 1;
            if run_bad > 5000 { break; }
            // hidden records still occupy a TypeDefIndex slot — keep indices aligned
            writeln!(w, "{i}\t<hidden_{}>", hidden)?;
            continue;
        }
        run_bad = 0;
        let raw_name = body.read_u32_opt(rec + 0x14).unwrap_or(0);
        let idx = if raw_name == NAME_SENTINEL { 0xFFFF_FFFF } else { raw_name.wrapping_add(C_NAME) };
        let name = decode_str(&body, strsec, idx);
        let ns_idx = body.read_u32_opt(rec + 0x18).unwrap_or(0) ^ C_NS;
        let ns = decode_str(&body, strsec, ns_idx);
        let full = if ns.is_empty() { name } else { format!("{ns}.{name}") };
        writeln!(w, "{i}\t{full}")?;
        visible += 1;
    }
    Ok((visible, hidden))
}

/// `strsec = i32(header+0x150) - STRSEC_BIAS` (must match decrypt/file.rs).
fn strsec_of(md: &Metadata) -> usize {
    let v = i32_le(&md.header, 0x150) as i64;
    (v - STRSEC_BIAS) as usize
}

fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn i32_le(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
