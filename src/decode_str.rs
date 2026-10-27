//! String decryption (see `RECIPE.md` §2).
//!
//! `idx` packs offset (low 24 bits) + length (next 8 bits). The keystream is 8-byte blocks XOR'd
//! with an evolving key seeded from the string's offset.

use serde::{Deserialize, Serialize};

use crate::mem::Memory;

const M1: u64 = 0xB33E_4042_7D56_68C0;
const X1: u64 = 0x6D8C_4AAB_00FE_8E27;
const X2: u64 = 0x30EE_5B43_130F_E0CD;
const M4: u64 = 0x0889_EEEA_326A_FB36;

/// Decode a string at `strsec` (offset of the string section within the body buffer) for packed
/// index `idx`. Generic over the backing store.
pub fn decode_str<M: Memory>(mem: &M, strsec: usize, idx: u32) -> String {
    if idx == 0xFFFF_FFFF {
        return String::new();
    }
    let off = (idx & 0xFF_FFFF) as usize;
    let len = ((idx >> 24) & 0xFF) as usize;
    if len == 0 {
        return String::new();
    }
    let nq = (len + 7) >> 3;
    let src = strsec.wrapping_add(off);
    if !mem.readable(src, nq * 8 + 8) {
        return String::new();
    }
    let mut key = (off as u64)
        .wrapping_mul(M1)
        .wrapping_add(X1)
        ^ X2;
    let mut buf = Vec::with_capacity(nq * 8);
    for k in 0..nq {
        let enc = mem.read_u64(src + 8 * k);
        buf.extend_from_slice(&(enc ^ key).to_le_bytes());
        key = key.wrapping_add(M4);
    }
    buf.truncate(len);
    if let Some(z) = buf.iter().position(|&b| b == 0) {
        buf.truncate(z);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Convenience: decode against a raw byte slice (the common case — the body buffer). Returns `None`
/// for an empty result so callers can distinguish "no string" from `""`.
pub fn decode_at(body: &[u8], strsec: usize, idx: u32) -> Option<String> {
    let mem = crate::mem::Buffer::new(body);
    let s = decode_str(&mem, strsec, idx);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_anchor_strings() {
        let Ok(gm) = std::fs::read("Original/global-metadata.dat") else {
            eprintln!("[skip] global-metadata.dat not present");
            return;
        };
        let Ok(ga) = std::fs::read("Original/GenshinImpact.exe") else {
            eprintln!("[skip] GenshinImpact.exe not present");
            return;
        };
        let md = crate::decrypt::file::load(&ga, &gm).expect("load");
        let f272 = i32::from_le_bytes([md.header[272], md.header[273], md.header[274], md.header[275]]);
        let strsec = (f272 as i64 - 1426623823) as usize;
        // Exact-offset anchors confirmed during RE.
        assert_eq!(decode_at(&md.body, strsec, (8 << 24) | 0).as_deref(), Some("mscorlib"));
        assert_eq!(decode_at(&md.body, strsec, (8 << 24) | 0x3D4).as_deref(), Some("hidden_3"));
        assert_eq!(decode_at(&md.body, strsec, (9 << 24) | 0x40D).as_deref(), Some("hidden_12"));
        assert_eq!(decode_at(&md.body, strsec, (8 << 24) | 0x487).as_deref(), Some("hash_alg"));
    }
}

/// Profile-parameterized variant: key0 = (off*m1 + x1) ^ x2, per qword key += m4.
pub fn decode_str_masked<M: Memory>(
    mem: &M,
    strsec: usize,
    idx: u32,
    m1: u64,
    x1: u64,
    x2: u64,
    m4: u64,
) -> String {
    if idx == 0xFFFF_FFFF {
        return String::new();
    }
    let off = (idx & 0xFF_FFFF) as usize;
    let len = ((idx >> 24) & 0xFF) as usize;
    if len == 0 {
        return String::new();
    }
    let nq = (len + 7) >> 3;
    let src = strsec.wrapping_add(off);
    if !mem.readable(src, nq * 8) {
        return String::new();
    }
    let mut key = (off as u64).wrapping_mul(m1).wrapping_add(x1) ^ x2;
    let mut buf = Vec::with_capacity(nq * 8);
    for k in 0..nq {
        let enc = mem.read_u64(src + 8 * k);
        buf.extend_from_slice(&(enc ^ key).to_le_bytes());
        key = key.wrapping_add(m4);
    }
    buf.truncate(len);
    if let Some(z) = buf.iter().position(|&b| b == 0) {
        buf.truncate(z);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

// ---------------------------------------------------------------------------
// Schedule-driven variants
//
// `decode_str_masked` above hard-codes the 3-constant one-stage schedule. The
// generations differ (7.0.0 / 6.4.0 are two-stage, 5 constants), so everything
// that must work without a code change takes a `CipherSchedule` -- a serialized
// op list that the derivation produces and a profile stores.
// ---------------------------------------------------------------------------

use crate::derive::cipher::CipherSchedule;

/// Decode a string by packed index under an arbitrary key schedule.
pub fn decode_str_sched<M: Memory>(mem: &M, strsec: usize, idx: u32, sched: &CipherSchedule) -> String {
    if idx == 0xFFFF_FFFF {
        return String::new();
    }
    let off = (idx & 0xFF_FFFF) as usize;
    let len = ((idx >> 24) & 0xFF) as usize;
    if len == 0 {
        return String::new();
    }
    let nq = (len + 7) >> 3;
    let src = strsec.wrapping_add(off);
    if !mem.readable(src, nq * 8) {
        return String::new();
    }
    let mut key = sched.key(off as u64);
    let mut buf = Vec::with_capacity(nq * 8);
    for k in 0..nq {
        let enc = mem.read_u64(src + 8 * k);
        buf.extend_from_slice(&(enc ^ key).to_le_bytes());
        key = key.wrapping_add(sched.step);
    }
    buf.truncate(len);
    if let Some(z) = buf.iter().position(|&b| b == 0) {
        buf.truncate(z);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

// ---------------------------------------------------------------------------
// String heap: what the layout actually is (measured, 7.1.0)
//
// The heap is a **dense concatenation of unterminated strings**: entry `i+1`
// starts exactly at `off_i + len_i`, with no NUL and no padding. Verified on the
// 7.1.0 heap: `mono_runtime_install_handlers` at 0x5B (29 bytes) -> 0x78,
// `InstallSignalHandlers` at 0x78 (21) -> 0x8D, `GetDisplayName` at 0xBE (14) -> 0xCC,
// `RemoveSignalHandlers` at 0xAA (20) -> 0xBE -- all exact, and the byte AT each
// boundary decrypts to the next string, not to 0x00.
//
// The length is carried in the *index* (bits 24..31), which comes from the
// metadata tables. So a byte offset can be decoded exactly even though the heap
// cannot be segmented from the ciphertext alone. What the ciphertext does give is
// a decisive *predicate*: for the correct schedule, an offset `o` that starts a
// string of length >= 8 decrypts its first qword to eight printable bytes, and no
// other offset does (the key depends on the absolute offset, so a string shifted
// by one byte decrypts to noise). Measured hit rate on 7.1.0: ~15,163 per 256 KiB
// against a ~100 random floor.
// ---------------------------------------------------------------------------

/// One decrypted entry of the string heap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeapString {
    /// Byte offset of the string inside the heap (== the low 24 bits of its index).
    pub off: u32,
    /// Decoded text. This is the exact string followed by the maximal further run
    /// of printable bytes -- see [`string_starts`]. Exact lengths come from the
    /// metadata table that holds the index, not from the ciphertext.
    pub text: String,
}

/// `true` when the 8 bytes at heap offset `off` decrypt to printable ASCII under
/// the schedule. This is the predicate the derivation is scored on.
#[inline]
pub fn is_printable_qword(body: &[u8], strsec: usize, off: usize, sched: &CipherSchedule) -> bool {
    printable_prefix_len(body, strsec, off, sched) >= 8
}

/// Number of leading printable bytes at a heap offset (0..=8).
pub fn printable_prefix_len(body: &[u8], strsec: usize, off: usize, sched: &CipherSchedule) -> usize {
    let src = match strsec.checked_add(off) {
        Some(s) if s + 8 <= body.len() => s,
        _ => return 0,
    };
    let enc = u64::from_le_bytes(body[src..src + 8].try_into().unwrap());
    (enc ^ sched.key(off as u64))
        .to_le_bytes()
        .iter()
        .take_while(|&b| (0x20..=0x7E).contains(b))
        .count()
}

/// Enumerate every heap offset that starts a string of length >= 8, plus the ~0.04%
/// of offsets where random ciphertext happens to satisfy the predicate.
///
/// `text` is the exact string followed by the further printable bytes that follow
/// it before the first non-printable byte, so it *starts with* the true string;
/// truncating it needs the real length, which lives in the metadata index. Callers
/// that need exact strings must use [`decode_str_sched`] with a real index.
pub fn string_starts(body: &[u8], strsec: usize, sched: &CipherSchedule, limit: usize) -> Vec<HeapString> {
    string_starts_min(body, strsec, sched, limit, 8)
}

/// Same enumeration with a configurable minimum run length. Short strings
/// (parameter names like `msg`/`fmt` sit in 3-byte runs bounded by
/// non-printable gaps) need `min_len < 8` to be visible to the solvers;
/// the noise share rises as the threshold falls (measured ~0.04% at 8).
pub fn string_starts_min(
    body: &[u8],
    strsec: usize,
    sched: &CipherSchedule,
    limit: usize,
    min_len: usize,
) -> Vec<HeapString> {
    let mut out = Vec::new();
    let end = body.len().saturating_sub(8);
    let mut off = 0usize;
    while off < body.len().saturating_sub(strsec) && off < limit {
        if printable_prefix_len(body, strsec, off, sched) < min_len {
            off += 1;
            continue;
        }
        // Exact string first, then however far the printable run continues.
        let mut key = sched.key(off as u64);
        let mut buf: Vec<u8> = Vec::with_capacity(32);
        let mut p = strsec + off;
        while p + 8 <= end && buf.len() < 255 {
            let enc = u64::from_le_bytes(body[p..p + 8].try_into().unwrap());
            let dec = (enc ^ key).to_le_bytes();
            let stop = dec.iter().position(|&b| !(0x20..=0x7E).contains(&b));
            match stop {
                Some(z) => {
                    buf.extend_from_slice(&dec[..z]);
                    break;
                }
                None => buf.extend_from_slice(&dec),
            }
            key = key.wrapping_add(sched.step);
            p += 8;
        }
        out.push(HeapString { off: off as u32, text: String::from_utf8_lossy(&buf).into_owned() });
        off += 1;
    }
    out
}