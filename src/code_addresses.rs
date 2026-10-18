//! The reference `Addresses` array: every code pointer Il2CppDumper merges for v>=24.2.
//!
//! Il2CppDumper/Outputs/StructGenerator.cs::WriteScript builds `Addresses` from
//! (a) per-module method pointers, (b) genericMethodPointers, (c) invokerPointers,
//! then sorts/dedups and drops 0. GI 7.1 keeps those pointer arrays in `.rdata`,
//! reachable from the static code-registration blob at `0x1422DF450`:
//!
//!   +0x08 -> invokerPointers array      (indexed by the per-method table at hdr[0x200])
//!   +0x78 -> genericMethodPointers array (indexed by the 0x74 table u16 column)
//!
//! Counts are derived, not guessed:
//!   generic = (hdr[0x110] ^ 0x1AB6109A) / 6          = 12,827 rows (u16 max = 12,826)
//!   invoker = max(hdr[0x200] table value, < 1e6) + 1 = 25,651
//!
//! Both arrays were verified to hold exactly that many in-image pointers before the
//! first non-image qword. reversePInvokeWrappers / unresolvedVirtualCallPointers are
//! part of the reference merge too, but their 7.1 arrays are not located yet; omitting
//! them is reported by the caller instead of being silent.

use crate::derive::engine::Meta;
use crate::mem::Memory;

/// Static `Il2CppCodeRegistration` blob (7.1.0, .rdata).
const CODE_REG_VA: u64 = 0x1422_DF450;
const FIELD_INVOKERS: u64 = 0x08;
const FIELD_GENERIC: u64 = 0x78;

#[derive(Debug)]
pub struct AddressStats {
    pub method_ptrs: usize,
    pub generic_ptrs: usize,
    pub invoker_ptrs: usize,
    pub unique: usize,
}

/// Read one little-endian qword at an image VA (raw-backed sections only).
fn read_va(m: &Meta, va: u64) -> Option<u64> {
    let rva = va.checked_sub(m.image_base)?;
    if rva >= m.image.len() as u64 {
        return None;
    }
    let rva32 = rva as u32;
    for &(sva, vsz, rp, rsz) in &m.sections {
        if rva32 >= sva && rva32 < sva.saturating_add(rsz.max(vsz)) {
            let rel = rva32 - sva;
            if rel >= rsz {
                return None;
            }
            let off = rp as usize + rel as usize;
            let bytes = m.image.get(off..off.checked_add(8)?)?;
            return Some(u64::from_le_bytes(bytes.try_into().ok()?));
        }
    }
    None
}

fn header_u32(m: &Meta, off: usize) -> Option<u32> {
    let b = m.header.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Generic method pointer count: rows of the 0x74 table `{i32 method, u16 generic}`.
fn generic_method_count(m: &Meta) -> Option<usize> {
    let size = (header_u32(m, 0x110)? ^ 0x1AB6_109A) as usize;
    let base = (header_u32(m, 0x74)? ^ 0x2451_77E0) as usize;
    if base >= m.body.size() {
        return None;
    }
    // The recorded size is 3 bytes past the last full row (0x12CA5 / 6 = 12,827 r 3); the
    // authoritative count is the u16 column's max + 1, cross-checked against the row count.
    let rows = size / 6;
    // The u16 column must index this array; use it as a consistency check, not a guess.
    let mut max = 0u32;
    let mut seen = 0usize;
    for i in 0..rows {
        let off = base + 6 * i + 4;
        if !m.body.readable(off, 2) {
            break;
        }
        let g = m.body.read_u16(off);
        if g != 0xFFFF {
            max = max.max(g as u32);
            seen += 1;
        }
    }
    let count = max as usize + 1;
    if rows >= 1000 && seen > 0 && count <= rows + 1 {
        Some(count)
    } else {
        None
    }
}

/// Invoker pointer count: highest invoker index in the per-method table (hdr[0x200]) + 1.
fn invoker_count(m: &Meta) -> Option<usize> {
    let base = (header_u32(m, 0x200)? as i32 as u32).wrapping_add(0xB43E_0EB1) as usize;
    if base >= m.body.size() {
        return None;
    }
    let mut max = 0u32;
    let rows = 733_442usize.min((m.body.size() - base) / 4);
    for i in 0..rows {
        let Some(v) = m.body.read_u32_opt(base + 4 * i) else { break };
        if v != 0xFFFF_FFFF && v < 1_000_000 {
            max = max.max(v);
        }
    }
    if max == 0 {
        None
    } else {
        Some(max as usize + 1)
    }
}

fn push_array(m: &Meta, out: &mut Vec<u64>, array_va: u64, count: usize) -> usize {
    let mut n = 0usize;
    for i in 0..count {
        let Some(p) = read_va(m, array_va + 8 * i as u64) else { break };
        if p == 0 {
            continue;
        }
        let Some(rva) = p.checked_sub(m.image_base) else { continue };
        if rva as usize >= m.image.len() {
            continue;
        }
        out.push(rva);
        n += 1;
    }
    n
}

/// Collect the reference `Addresses` array (sorted, deduped, no zeros).
pub fn collect(m: &Meta) -> (Vec<u64>, AddressStats) {
    let method_ptrs = m.methodptrs_len;
    let mut out: Vec<u64> = (0..m.methodptrs_len)
        .map(|i| m.method_rva(i) as u64)
        .filter(|r| *r != 0)
        .collect();

    let mut generic_ptrs = 0usize;
    let mut invoker_ptrs = 0usize;
    if let Some(array) = read_va(m, CODE_REG_VA + FIELD_GENERIC) {
        if let Some(count) = generic_method_count(m) {
            generic_ptrs = push_array(m, &mut out, array, count);
        }
    }
    if let Some(array) = read_va(m, CODE_REG_VA + FIELD_INVOKERS) {
        if let Some(count) = invoker_count(m) {
            invoker_ptrs = push_array(m, &mut out, array, count);
        }
    }
    out.sort_unstable();
    out.dedup();
    let unique = out.len();
    (
        out,
        AddressStats { method_ptrs, generic_ptrs, invoker_ptrs, unique },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::engine::Meta;

    fn sample_meta() -> Option<(Vec<u8>, Vec<u8>)> {
        let exe = std::fs::read(std::env::var("MHY_SAMPLE_EXE").ok()?).ok()?;
        let dat = std::fs::read(std::env::var("MHY_SAMPLE_DAT").ok()?).ok()?;
        Some((exe, dat))
    }

    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE / MHY_SAMPLE_DAT"]
    fn counts_match_reference_arrays() {
        let Some((exe, dat)) = sample_meta() else { return };
        let m = Meta::load(&exe, &dat, crate::derive::layout71::gen71()).expect("load");
        let (addrs, st) = collect(&m);
        eprintln!("addresses: {st:?} (merged {})", addrs.len());
        assert_eq!(st.generic_ptrs, 12_827);
        assert_eq!(st.invoker_ptrs, 25_651);
        assert!(addrs.len() > st.method_ptrs);
        assert!(addrs.windows(2).all(|w| w[0] < w[1]));
    }
}
