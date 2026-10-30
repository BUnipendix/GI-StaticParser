//! Mechanical event-definition solve (R95) — invariants only, no version
//! constants in code.
//!
//! Input: the event accessor's emu/symwalk chains (from the shape-transfer
//! report), the build's own anchors, the typeDef solve and the metadata body.
//! Output: every Profile event field, or None when the invariants don't bite.
//!
//! The five boards (each uniquely picked the true answer on 6.2.0):
//! 1. **td tiling** — eventStart/eventCount pairs whose spans cover [0, total)
//!    exactly, no hole and no overlap, count column a u8 with a small total.
//! 2. **table base** — the confirmed anchor inside the accessor function,
//!    tried raw and −8 (the runtime-copy shift, R91/R92: accessors that read a
//!    +8-shifted runtime copy resolve 8 past the file rows).
//! 3. **name** — the u32 column whose xor-C (C from the accessor's own
//!    immediates) decodes ≥90% of sampled rows to identifiers through the
//!    build's own cipher schedule.
//! 4. **type** — the other u32 column; C by group consistency: every row of a
//!    typeDef must decode to the SAME typearr index.
//! 5. **add/remove/raise** — the three u16 columns: raise by 0xFFFF-sentinel
//!    majority; add (xor-shape) and remove (add-shape) by immediates + the
//!    |add−remove| median adjacency (C# emits the pair adjacently; measured
//!    median 1 for the truth vs 352 for the runner-up).
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0.

use crate::derive::cipher::BuildDerivation;
use crate::derive::profile::{Column, ColKind};
use crate::expr::Expr;
use crate::mem::Buffer;
use crate::pe::Image;
use crate::profile_splice::TdSolve;
use crate::rowtable::is_identifier;

/// One solved event section, ready for [`crate::profile_splice::splice_events`].
pub struct EventSolve {
    /// Header-slot form of the table base (the −8 shift folded into `add`
    /// for Add anchors; other ops fall back to a direct offset).
    pub defs: crate::derive::profile::TableBase,
    pub stride: u32,
    pub td_start: Column,
    pub td_count: Column,
    /// The mask chain, as data (engine evaluates it per row).
    pub mask_expr: Expr,
    pub name_off: u32,
    /// false: (raw ^ mask) ^ name_xor (6.2/7.1); true: (raw + name_xor) ^ mask (6.6).
    pub name_add: bool,
    pub name_xor: u32,
    pub type_off: u32,
    /// XorC form (raw ^ mask) ^ type_xor; None when the add-form is used or
    /// the column is absent.
    pub type_xor: Option<u32>,
    /// AddC form (raw + type_add) ^ mask (the 7.1 shape).
    pub type_add: u32,
    /// True when the row has no typearr column (6.6 packs name+add+remove only).
    pub type_absent: bool,
    pub add_off: u32,
    pub add_xor: u16,
    pub remove_off: u32,
    pub remove_add: u16,
    pub raise_off: u32,
    pub raise_xor: u16,
    /// True when the row has no raise column (6.6: name+add+remove only).
    pub raise_absent: bool,
    /// Rows in the event table (== Σ eventCount).
    pub total_events: u32,
    /// Diagnostics for the splice manifest.
    pub name_rate: f64,
    pub base_shift: i64,
}

/// All 8/16/32-bit immediates in [va, va+len), deduplicated (the accessor's
/// column constants all sit in its own instruction stream).
fn scan_immediates(img: &Image, exe: &[u8], va: u64, len: u64) -> (Vec<u32>, Vec<u16>) {
    use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};
    fn imm_of(ins: &Instruction, i: usize) -> Option<u64> {
        Some(match ins.op_kind(i as u32) {
            OpKind::Immediate8 => u64::from(ins.immediate8()),
            OpKind::Immediate16 => u64::from(ins.immediate16()),
            OpKind::Immediate32 => u64::from(ins.immediate32()),
            OpKind::Immediate64 => ins.immediate64(),
            OpKind::Immediate8to16 => ins.immediate8to16() as i64 as u64,
            OpKind::Immediate8to32 => ins.immediate8to32() as i64 as u64,
            OpKind::Immediate8to64 => ins.immediate8to64() as i64 as u64,
            OpKind::Immediate32to64 => ins.immediate32to64() as i64 as u64,
            _ => return None,
        })
    }
    let mut i32s = std::collections::BTreeSet::new();
    let mut i16s = std::collections::BTreeSet::new();
    if let Some(fo) = img.va_to_file(va) {
        let fo = fo as usize;
        if fo + len as usize <= exe.len() {
            let mut dec = Decoder::with_ip(64, &exe[fo..fo + len as usize], va, DecoderOptions::NONE);
            while dec.can_decode() {
                let ins = dec.decode();
                for op in 0..4 {
                    if let Some(v) = imm_of(&ins, op) {
                        if v == 0 {
                            continue;
                        }
                        if v > 0xFFFF {
                            i32s.insert((v & 0xFFFF_FFFF) as u32);
                        }
                        i16s.insert((v & 0xFFFF) as u16);
                    }
                }
            }
        }
    }
    i16s.remove(&0);
    (i32s.into_iter().collect(), i16s.into_iter().collect())
}

/// td eventStart/eventCount solve by exact tiling. Returns EVERY (start,
/// count, total, per-typeDef spans) candidate whose spans tile [0, total)
/// exactly — tiling alone is not unique (6.6 has a coincidental 613-event
/// tiling on the wrong columns), so the name board downstream picks the true
/// one. The start column is searched in all four forms the accessors use
/// (u16/u32 × add/xor — 6.2 packs a u16 add, 6.6 a u32 add); count is u8
/// add/xor.
type Tiling = (Column, Column, u32, Vec<(usize, u32, u32)>);
/// `max_total`/`max_count` bound the tiling search: events are hundreds of
/// rows (6.2: 565), property tables tens of thousands (6.2: 93,543).
fn solve_td_tiling(body: &[u8], td: &TdSolve, max_total: u32, max_count: u32) -> Vec<Tiling> {
    let mut tilings: Vec<Tiling> = Vec::new();
    let stride = td.stride as usize;
    let rows = td.rows;
    let rd8 = |off: usize| -> u32 { body.get(off).copied().unwrap_or(0) as u32 };
    let rd16 = |off: usize| -> u32 {
        match body.get(off..off + 2) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]) as u32,
            None => 0,
        }
    };
    // count-column candidates by histogram (total + max derivable in 256 ops)
    let mut count_cands: Vec<(usize, bool, u32, u32, Vec<u32>)> = Vec::new(); // (off, xor, c, total, counts)
    for off in 0..stride {
        let mut hist = [0u32; 256];
        let mut raws = Vec::with_capacity(rows);
        for r in 0..rows {
            let v = rd8(td.base + r * stride + off);
            hist[v as usize] += 1;
            raws.push(v);
        }
        // The padding rows dominate every td column (types without events/
        // properties have count 0), so the constant must map the histogram
        // MODE to 0 — one or two candidates per (offset, form) instead of 256.
        let (mode, _mode_n) = (0..256u32)
            .max_by_key(|&v| hist[v as usize])
            .map(|v| (v, hist[v as usize]))
            .unwrap_or((0, 0));
        for &xor in &[false, true] {
            let cs: Vec<u32> = if xor {
                vec![mode]
            } else {
                vec![mode.wrapping_neg() & 0xFF, (mode.wrapping_neg() & 0xFF).wrapping_add(0x100 & 0xFF)]
            };
            for c in cs {
                let (mut total, mut max) = (0u32, 0u32);
                for v in 0..256u32 {
                    let n = hist[v as usize];
                    if n == 0 {
                        continue;
                    }
                    let cnt = if xor { v ^ c } else { v.wrapping_add(c) & 0xFF };
                    total = total.wrapping_add(n.wrapping_mul(cnt));
                    max = max.max(cnt);
                }
                if total == 0 || total > max_total || max > max_count {
                    continue;
                }
                let counts: Vec<u32> = raws
                    .iter()
                    .map(|&v| if xor { v ^ c } else { v.wrapping_add(c) & 0xFF })
                    .collect();
                count_cands.push((off, xor, c, total, counts));
            }
        }
    }
    // start-column reads: (offset, width 2|4, xor) — the accessors use u16 add
    // (6.2) and u32 add (6.6); xor forms cost little to cover too.
    let mut start_reads: Vec<(usize, u32, bool)> = Vec::new();
    for off in 0..stride.saturating_sub(1) {
        start_reads.push((off, 2, false));
        start_reads.push((off, 2, true));
    }
    for off in 0..stride.saturating_sub(3) {
        start_reads.push((off, 4, false));
        start_reads.push((off, 4, true));
    }
    // start-column raw values, hoisted: each (offset, width) is read once for
    // all rows instead of once per count candidate
    let mut start_raws: Vec<Vec<u32>> = Vec::with_capacity(start_reads.len());
    for &(soff, swidth, _) in &start_reads {
        let mut v = Vec::with_capacity(rows);
        for r in 0..rows {
            v.push(if swidth == 2 {
                rd16(td.base + r * stride + soff)
            } else {
                match body.get(td.base + r * stride + soff..td.base + r * stride + soff + 4) {
                    Some(b) => u32::from_le_bytes(b.try_into().unwrap()),
                    None => 0,
                }
            });
        }
        start_raws.push(v);
    }
    for (coff, cxor, cc, total, counts) in &count_cands {
        // first 8 count>0 rows for the cheap prefilter
        let mut first8: Vec<usize> = Vec::with_capacity(8);
        for r in 0..rows {
            if counts[r] > 0 {
                first8.push(r);
                if first8.len() == 8 {
                    break;
                }
            }
        }
        if first8.len() < 2 {
            continue;
        }
        for (sidx, &(soff, swidth, sxor)) in start_reads.iter().enumerate() {
            let sraw = &start_raws[sidx];
            // Monotonicity prefilter: the decoded starts of count>0 rows are
            // row-ordered (the table is written in index order), so the RAW
            // column is non-decreasing over count>0 rows with at most one
            // 2^w wrap. Sample 24 rows; >1 descent kills the column.
            {
                let mut sampled = 0usize;
                let mut descents = 0usize;
                let mut prev: u32 = 0;
                for r in (0..rows).step_by(7) {
                    if counts[r] == 0 {
                        continue;
                    }
                    let raw = sraw[r];
                    if sampled > 0 && raw < prev {
                        descents += 1;
                        if descents > 1 {
                            break;
                        }
                    }
                    prev = raw;
                    sampled += 1;
                    if sampled >= 24 {
                        break;
                    }
                }
                if sampled < 8 || descents > 1 {
                    continue;
                }
            }
            // the zero-start row is the one with the MINIMUM raw (add form);
            // for xor form try the mode raw too — at most 2 candidates
            let nz_min = (0..rows)
                .filter(|&r| counts[r] > 0)
                .map(|r| sraw[r])
                .min()
                .unwrap_or(0);
            let cs: Vec<u32> = if sxor {
                // min start = 0 → sc = the raw AT that row; find it
                let mut sc0 = 0u32;
                for r in 0..rows {
                    if counts[r] > 0 && sraw[r] == nz_min {
                        sc0 = sraw[r];
                        break;
                    }
                }
                vec![sc0]
            } else {
                vec![nz_min.wrapping_neg()]
            };
            for sc in &cs {
                let mut spans: Vec<(u32, u32)> = Vec::new();
                let mut ok = true;
                for r in 0..rows {
                    if counts[r] == 0 {
                        continue;
                    }
                    let raw = sraw[r];
                    let st = if sxor { raw ^ sc } else { raw.wrapping_add(*sc) };
                    // u16 starts wrap at 16 bits (no negative starts measured
                    // on any build — movsx semantics coincide with u16 there)
                    let st = if swidth == 2 { st & 0xFFFF } else { st };
                    if st as u64 + counts[r] as u64 > *total as u64 {
                        ok = false;
                        break;
                    }
                    spans.push((st, counts[r]));
                }
                if !ok || spans.is_empty() {
                    continue;
                }
                spans.sort_unstable();
                let mut cursor = 0u32;
                for (st, cnt) in &spans {
                    if *st != cursor {
                        ok = false;
                        break;
                    }
                    cursor += cnt;
                }
                if ok && cursor == *total {
                    let groups: Vec<(usize, u32, u32)> = (0..rows)
                        .filter(|&r| counts[r] > 0)
                        .map(|r| {
                            let raw = sraw[r];
                            let st = if sxor { raw ^ sc } else { raw.wrapping_add(*sc) };
                            let st = if swidth == 2 { st & 0xFFFF } else { st };
                            (r, st, counts[r])
                        })
                        .collect();
                    tilings.push((
                        Column {
                            offset: soff as u32,
                            kind: if sxor { ColKind::XorC } else { ColKind::AddC },
                            c: *sc,
                            row_shift: 0,
                        },
                        Column {
                            offset: *coff as u32,
                            kind: if *cxor { ColKind::XorC } else { ColKind::AddC },
                            c: *cc,
                            row_shift: 0,
                        },
                        *total,
                        groups,
                    ));
                    if tilings.len() >= 16 {
                        return tilings;
                    }
                }
            }
        }
    }
    tilings
}

/// Score helper: decode packed index `idx` through the build's own schedule and
/// judge identifier-ness.
fn dec_ident(body: &[u8], strsec: usize, sched: &crate::derive::cipher::CipherSchedule, idx: u32) -> bool {
    if idx == 0xFFFF_FFFF {
        return false;
    }
    let s = crate::decode_str::decode_str_sched(&Buffer::new(body), strsec, idx, sched);
    s.len() >= 2 && is_identifier(&s)
}

/// Run the full solve. `ev_fn` is the event accessor VA (matched_fn of the
/// `event` semantic); `chains` are its symwalk+emu chains.
#[allow(clippy::too_many_arguments)]
pub fn solve_events(
    img: &Image,
    exe: &[u8],
    dat: &[u8],
    derived: &BuildDerivation,
    ev_fn: u64,
    chains: &[Expr],
    td: Option<&TdSolve>,
) -> Result<Option<EventSolve>, String> {
    let body = match dat.get(0x210..) {
        Some(b) if !b.is_empty() => b,
        _ => return Err("metadata body missing".into()),
    };
    let cipher = match &derived.cipher {
        Some(c) => c,
        None => return Err("no derived string cipher; event solve impossible".into()),
    };
    let hdr = &derived.header;
    let strsec = cipher.strsec as usize;
    let sched = &cipher.schedule;
    let td = match td {
        Some(t) => t,
        None => return Ok(None),
    };
    let tilings = solve_td_tiling(body, td, 8192, 128);
    if tilings.is_empty() {
        #[cfg(feature = "ev_debug")]
        eprintln!("[ev] td tiling failed");
        return Ok(None);
    }
    // sample EVENLY across the table — the first rows decode systematically
    // worse on some builds (6.2 props: 73% head vs 100% spread)
    let sample_of = |total: u32| -> Vec<u32> {
        let st = (total / 240).max(1) as usize;
        (0..total as usize).step_by(st).take(240).map(|i| i as u32).collect()
    };

    // base candidates: confirmed anchors inside the accessor, ± the runtime-copy shift
    let mut base_cands: Vec<usize> = Vec::new();
    for a in &derived.anchors {
        if a.confirmed && a.site >= ev_fn && a.site < ev_fn + 0x600 {
            if let Some(v) = a.resolve(hdr) {
                for sh in [0i64, -8] {
                    let b = (v as i64 + sh) as usize;
                    if !base_cands.contains(&b) {
                        base_cands.push(b);
                    }
                }
            }
        }
    }
    if base_cands.is_empty() {
        return Ok(None);
    }
    let (imm32s, imm16s) = scan_immediates(img, exe, ev_fn, 0x600);
    if imm32s.is_empty() || imm16s.is_empty() {
        return Ok(None);
    }
    let stride = td.stride as usize; // event rows use their own stride (14); read via b14
    let _ = stride;

    let rd32 = |off: usize| -> Option<u32> {
        let b = body.get(off..off + 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    };
    let rd16 = |off: usize| -> Option<u32> {
        let b = body.get(off..off + 2)?;
        Some(u16::from_le_bytes(b.try_into().ok()?) as u32)
    };

    let mut best: Option<(f64, usize, EventSolve)> = None;
    let mut dedupe_chains: Vec<&Expr> = Vec::new();
    for ch in chains {
        if !dedupe_chains.iter().any(|e| format!("{e:?}") == format!("{ch:?}")) {
            dedupe_chains.push(ch);
        }
    }
    for til in &tilings {
    let (td_start, td_count, total, groups) = (&til.0, &til.1, til.2, &til.3);
    // Flatten: per event index -> owner row
    let mut owner = vec![0usize; total as usize];
    for (r, st, cnt) in groups {
        for j in 0..*cnt {
            let i = st + j;
            if (i as usize) < owner.len() {
                owner[i as usize] = *r;
            }
        }
    }
    let sample = sample_of(total);
    for &ev_stride in &[14usize, 10] {
    for &base in &base_cands {
        for chain in &dedupe_chains {
            let mask = |i: u32| -> u32 { chain.eval(i as u64, hdr, &|_, _| 0).unwrap_or(0) as u32 };
            // --- name column: (col, shape, C) with the best decode rate.
            // Both accessor shapes occur: (raw ^ mask) ^ C (6.2) and
            // (raw + C) ^ mask (6.6). ---
            let mut name: Option<(usize, bool, u32, f64)> = None;
            for col in [0usize, 4] {
                if col + 4 > ev_stride {
                    continue;
                }
                for add_form in [false, true] {
                    for &c in &imm32s {
                        let tested = sample.len();
                        let mut good = 0usize;
                        for &i in &sample {
                            let Some(raw) = rd32(base + i as usize * ev_stride + col) else { continue };
                            let idx = if add_form {
                                (raw.wrapping_add(c) ^ mask(i)) & 0xFFFF_FFFF
                            } else {
                                (raw ^ mask(i) ^ c) & 0xFFFF_FFFF
                            };
                            if dec_ident(body, strsec, sched, idx) {
                                good += 1;
                            }
                        }
                        let rate = good as f64 / tested.max(1) as f64;
                        if rate >= 0.9 && name.map(|(_, _, _, r)| rate > r).unwrap_or(true) {
                            name = Some((col, add_form, c, rate));
                        }
                    }
                }
            }
            let Some((ncol, n_add, nxor, nrate)) = name else {
                #[cfg(feature = "ev_debug")]
                eprintln!("[ev] base {base:#x} chain: no name col");
                continue;
            };
            let tcol = if ncol == 0 { 4 } else { 0 };
            // --- type column: C by group consistency (same typearr index for
            // every row of a typeDef). Absent on narrow strides. ---
            let mut type_hit: Option<(bool, u32)> = None;
            let mut type_best = 0.0;
            if tcol + 4 <= ev_stride {
                for t_add in [false, true] {
                    for &c in &imm32s {
                        use std::collections::HashMap;
                        let mut per_group: HashMap<usize, HashMap<u32, u32>> = HashMap::new();
                        for &i in &sample {
                            if let Some(raw) = rd32(base + i as usize * ev_stride + tcol) {
                                let v = if t_add {
                                    (raw.wrapping_add(c) ^ mask(i)) & 0xFFFF_FFFF
                                } else {
                                    (raw ^ mask(i) ^ c) & 0xFFFF_FFFF
                                };
                                *per_group.entry(owner[i as usize]).or_default().entry(v).or_insert(0) += 1;
                            }
                        }
                        let mut agree = 0usize;
                        let mut seen = 0usize;
                        for (_r, hist) in &per_group {
                            if let Some((_v, n)) = hist.iter().max_by_key(|(_, n)| **n) {
                                agree += *n as usize;
                                seen += hist.len();
                            }
                        }
                        // few distinct values per group AND plausible magnitude
                        let cons = agree as f64 / sample.len().max(1) as f64;
                        if cons > type_best && seen <= per_group.len() * 2 {
                            let v0 = rd32(base + sample[0] as usize * ev_stride + tcol)
                                .map(|raw| {
                                    if t_add {
                                        (raw.wrapping_add(c) ^ mask(sample[0])) & 0xFFFF_FFFF
                                    } else {
                                        (raw ^ mask(sample[0]) ^ c) & 0xFFFF_FFFF
                                    }
                                })
                                .unwrap_or(u32::MAX);
                            if v0 < 4_000_000 {
                                type_best = cons;
                                type_hit = Some((t_add, c));
                            }
                        }
                    }
                }
            }
            let Some((t_add, tconst)) = type_hit else { continue };
            // --- raise: u16 col with the strongest 0xFFFF sentinel majority.
            // Optional: 6.6's 10-byte rows carry no raise column. ---
            let u16cols: Vec<usize> = if ev_stride >= 14 { vec![8, 10, 12] } else { vec![4, 6] };
            let mut raise: Option<(usize, u16, f64)> = None;
            for ucol in &u16cols {
                let ucol = *ucol;
                for shape in 0..2 {
                    for &c in &imm16s {
                        let (mut sent, mut n) = (0usize, 0usize);
                        for &i in &sample {
                            let Some(raw) = rd16(base + i as usize * ev_stride + ucol) else { continue };
                            let m16 = (mask(i) & 0xFFFF) as u32;
                            let v = if shape == 0 {
                                ((raw & 0xFFFF) ^ m16 ^ c as u32) & 0xFFFF
                            } else {
                                (((raw & 0xFFFF) + c as u32) ^ m16) & 0xFFFF
                            };
                            n += 1;
                            if v == 0xFFFF {
                                sent += 1;
                            }
                        }
                        let rate = sent as f64 / n.max(1) as f64;
                        if rate >= 0.3 && raise.map(|(_, _, r)| rate > r).unwrap_or(true) {
                            raise = Some((ucol, c, rate));
                        }
                    }
                }
            }
            let (rcol, rconst, _rrate, raise_absent) = match raise {
                Some((rcol, rconst, rrate)) => (rcol, rconst, rrate, false),
                None if ev_stride < 14 => (0, 0, 0.0, true),
                None => continue,
            };
            // --- add (xor-shape) / remove (add-shape) on the remaining cols ---
            let rest: Vec<usize> = if raise_absent {
                u16cols.clone()
            } else {
                u16cols.iter().copied().filter(|c| *c != rcol).collect()
            };
            let mut ar: Option<(usize, u16, usize, u16, u32)> = None;
            for &acol in &rest {
                for &ca in &imm16s {
                    // add values
                    let mut av = Vec::with_capacity(sample.len());
                    let mut a_ok = true;
                    for &i in &sample {
                        let Some(raw) = rd16(base + i as usize * ev_stride + acol) else { continue };
                        let m16 = (mask(i) & 0xFFFF) as u32;
                        let v = ((raw & 0xFFFF) ^ m16 ^ ca as u32) & 0xFFFF;
                        if v != 0xFFFF && v >= 16384 {
                            a_ok = false;
                        }
                        av.push(v);
                    }
                    if !a_ok {
                        continue;
                    }
                    for &bcol in &rest {
                        if bcol == acol {
                            continue;
                        }
                        for &cb in &imm16s {
                            let mut bv = Vec::with_capacity(sample.len());
                            let mut b_ok = true;
                            for &i in &sample {
                                let Some(raw) = rd16(base + i as usize * ev_stride + bcol) else { continue };
                                let m16 = (mask(i) & 0xFFFF) as u32;
                                let v = (((raw & 0xFFFF) + cb as u32) ^ m16) & 0xFFFF;
                                if v != 0xFFFF && v >= 16384 {
                                    b_ok = false;
                                }
                                bv.push(v);
                            }
                            if !b_ok {
                                continue;
                            }
                            let mut diffs: Vec<u32> = av
                                .iter()
                                .zip(&bv)
                                .filter(|(a, b)| **a != 0xFFFF && **b != 0xFFFF)
                                .map(|(a, b)| a.abs_diff(*b))
                                .collect();
                            if diffs.len() < sample.len() / 2 {
                                continue;
                            }
                            diffs.sort_unstable();
                            let med = diffs[diffs.len() / 2];
                            if ar.map(|(_, _, _, _, m)| med < m).unwrap_or(true) {
                                ar = Some((acol, ca, bcol, cb, med));
                            }
                        }
                    }
                }
            }
            let Some((acol, ca, bcol, cb, med)) = ar else { continue };
            if med > 32 {
                continue; // adjacency board failed
            }
            let sol = EventSolve {
                defs: crate::derive::profile::TableBase {
                    hdr_off: 0,
                    sub: None,
                    xor: None,
                    add: None,
                    direct: None,
                },
                stride: ev_stride as u32,
                td_start: td_start.clone(),
                td_count: td_count.clone(),
                mask_expr: (*chain).clone(),
                name_off: ncol as u32,
                name_add: n_add,
                name_xor: nxor,
                type_off: tcol as u32,
                type_xor: if t_add { None } else { Some(tconst) },
                type_add: if t_add { tconst } else { 0 },
                type_absent: false,
                add_off: acol as u32,
                add_xor: ca,
                remove_off: bcol as u32,
                remove_add: cb,
                raise_off: rcol as u32,
                raise_xor: rconst,
                raise_absent,
                total_events: total,
                name_rate: nrate,
                base_shift: 0,
            };
            if best.as_ref().map(|(r, _, _)| nrate > *r).unwrap_or(true) {
                best = Some((nrate, base, sol));
            }
        }
        }
    }
    }
    let Some((_, win_base, mut sol)) = best else { return Ok(None) };
    // Anchor the base back to its header slot: the shift is decided by the
    // BOARD-winning base (the ±8 runtime-copy ambiguity is resolved by the
    // decode-rate board, not re-guessed here). No anchor within ±8 → direct.
    let mut anchor = None;
    for a in &derived.anchors {
        if a.confirmed && a.site >= ev_fn && a.site < ev_fn + 0x600 {
            if let Some(v) = a.resolve(hdr) {
                let shift = win_base as i64 - v as i64;
                if shift.abs() <= 8 {
                    anchor = Some((a, shift, v as usize));
                    break;
                }
            }
        }
    }
    if let Some((a, shift, v)) = anchor {
        sol.base_shift = shift;
        sol.defs = match a.op {
            crate::derive::anchor::AnchorOp::Add => crate::derive::profile::TableBase {
                hdr_off: a.hdr_off,
                sub: None,
                xor: None,
                add: Some(a.imm.wrapping_add(shift as u32)),
                direct: None,
            },
            _ => crate::derive::profile::TableBase {
                hdr_off: a.hdr_off,
                sub: None,
                xor: None,
                add: None,
                direct: Some((v as i64 + shift) as u32),
            },
        };
    } else {
        return Ok(None);
    }
    Ok(Some(sol))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solves_62_td_tiling() {
        let Ok(gm) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat") else {
            eprintln!("[skip] 6.2 dat not present");
            return;
        };
        let Ok(exe) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen.exe") else {
            eprintln!("[skip] 6.2 exe not present");
            return;
        };
        let derived = crate::derive::cipher::derive_build(&exe, &gm).expect("derive");
        let dv = derived.as_ref().expect("no derivation");
        let img = crate::pe::Image::parse(&exe).expect("pe");
        let _ = &img;
        // td solve first
        let td = crate::profile_splice::solve_typedef(&exe, &gm, dv).expect("td solve").expect("td");
        let body = &gm[0x210..];
        let r = solve_td_tiling(body, &td, 250_000, 512);
        let tl = solve_td_tiling(body, &td, 8192, 128);
        let Some((s, c, total, groups)) = tl.iter().find(|(_, _, t, g)| *t == 565 && g.len() == 195) else {
            panic!("td tiling failed: td base {:#x} stride {} rows {} candidates {}", td.base, td.stride, td.rows, tl.len());
        };
        println!("start col {s:?} count col {c:?} total {total} types {}", groups.len());
        assert_eq!(s.offset, 44);
        assert_eq!(c.offset, 59);
    }
}

#[cfg(test)]
mod tests2 {
    use super::*;
    #[test]
    fn solves_62_events_full() {
        let Ok(gm) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat") else { eprintln!("[skip] dat"); return; };
        let Ok(exe) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen.exe") else { eprintln!("[skip] exe"); return; };
        let Ok(rep) = std::fs::read_to_string("/tmp/62.auto2.json") else { eprintln!("[skip] auto json"); return; };
        let rep: serde_json::Value = serde_json::from_str(&rep).expect("report");
        let chains: Vec<crate::expr::Expr> = rep["semantics"]["event"]["chains"]
            .as_array()
            .map(|a| a.iter().filter_map(|c| serde_json::from_value(c.clone()).ok()).collect())
            .unwrap_or_default();
        println!("chains loaded: {}", chains.len());
        let derived = crate::derive::cipher::derive_build(&exe, &gm).expect("derive");
        let dv = derived.as_ref().expect("dv");
        let td = crate::profile_splice::solve_typedef(&exe, &gm, dv).expect("td").expect("td");
        let img = crate::pe::Image::parse(&exe).expect("pe");
        for a in &dv.anchors {
            if a.site >= 0x14044A7AF && a.site < 0x14044ADAF {
                println!("anchor site={:#x} hdr_off={} op={:?} imm={:#x} confirmed={} resolve={:?}",
                    a.site, a.hdr_off, a.op, a.imm, a.confirmed, a.resolve(&dv.header));
            }
        }
        let (i32s, i16s) = scan_immediates(&img, &exe, 0x14044A7AF, 0x600);
        println!("imm32 contains 0x2c9ff31d: {}", i32s.contains(&0x2c9ff31d));
        println!("imm16 contains 0xb3c2/0x37af/0x3185: {}/ {}/ {}", i16s.contains(&0xb3c2), i16s.contains(&0x37af), i16s.contains(&0x3185));
        let (i32s2, _) = scan_immediates(&img, &exe, 0x14044A7A0, 0x600);
        println!("alt start 0x14044A7A0 imm32 contains 0x2c9ff31d: {}", i32s2.contains(&0x2c9ff31d));
        let r = solve_events(&img, &exe, &gm, dv, 0x14044A7AF, &chains, Some(&td));
        match r {
            Ok(Some(s)) => println!("SOLVED: name@{} add={} ^{:#x} rate {:.2} type@{} xor {:?} addc {} absent={} add@{} ^{:#x} rem@{} +{:#x} raise@{} ^{:#x} absent={} shift {:+} defs hdr_off {} add {:?} direct {:?}",
                s.name_off, s.name_add, s.name_xor, s.name_rate, s.type_off, s.type_xor, s.type_add, s.type_absent, s.add_off, s.add_xor, s.remove_off, s.remove_add, s.raise_off, s.raise_xor, s.raise_absent, s.base_shift, s.defs.hdr_off, s.defs.add, s.defs.direct),
            Ok(None) => println!("SOLVED: none"),
            Err(e) => println!("SOLVED: err {e}"),
        }
    }
}

#[cfg(test)]
mod tests3 {
    use super::*;
    #[test]
    fn diagnoses_66_events() {
        let Ok(gm) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.6.0/YuanShen_Data/Managed/Metadata/global-metadata.dat") else { eprintln!("[skip] dat"); return; };
        let Ok(exe) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.6.0/YuanShen.exe") else { eprintln!("[skip] exe"); return; };
        let derived = crate::derive::cipher::derive_build(&exe, &gm).expect("derive");
        let dv = derived.as_ref().expect("dv");
        let td = crate::profile_splice::solve_typedef(&exe, &gm, dv).expect("td").expect("td");
        let body = &gm[0x210..];
        let tl = solve_td_tiling(body, &td, 8192, 128);
println!("td tilings: {}", tl.len());
        for (s_, c_, t_, g_) in tl.iter().take(4) {
            println!("  start@{} count@{} total {} types {}", s_.offset, c_.offset, t_, g_.len());
        }
        // anchors near the accessor region (true accessor code ~0x1404AD0A1)
        for a in &dv.anchors {
            if a.site >= 0x1404ACC00 && a.site < 0x1404AD300 {
                println!("anchor site={:#x} hdr_off={} imm={:#x} confirmed={} resolve={:?}", a.site, a.hdr_off, a.imm, a.confirmed, a.resolve(&dv.header));
            }
        }
        let img = crate::pe::Image::parse(&exe).expect("pe");
        let (i32s, i16s) = scan_immediates(&img, &exe, 0x1404ACC4F, 0x600);
        println!("imm32 has 0xae502577: {}  imm16 has 0xc5ab/0x32dd/0x71: {}/{}/{}",
            i32s.contains(&0xae502577), i16s.contains(&0xc5ab), i16s.contains(&0x32dd), i16s.contains(&0x71));
    }
}

/// One solved property section (mirror of [`EventSolve`]; see the module docs
/// for the boards — props use the same five, with get/set adjacency replacing
/// the raise sentinel and the typearr column excluded by the adjacency pick).
pub struct PropSolve {
    pub defs: crate::derive::profile::TableBase,
    pub stride: u32,
    pub td_start: Column,
    pub td_count: Column,
    pub mask_expr: Expr,
    pub name_xor: u32,
    pub get_xor: u16,
    pub set_xorsub: u16,
    pub total_props: u32,
    pub name_rate: f64,
    pub base_shift: i64,
}

/// Solve the property-definition table (6.2 family: rows of
/// {name u32 -> (raw ^ C) − mask -> decode_str, get u16, type u16, set u16},
/// all XorCSubMask). `prop_fn` is the matched accessor VA; `chains` its
/// symwalk+emu chains.
pub fn solve_props(
    img: &Image,
    exe: &[u8],
    dat: &[u8],
    derived: &BuildDerivation,
    prop_fn: u64,
    chains: &[Expr],
    td: Option<&TdSolve>,
) -> Result<Option<PropSolve>, String> {
    let body = match dat.get(0x210..) {
        Some(b) if !b.is_empty() => b,
        _ => return Err("metadata body missing".into()),
    };
    let cipher = match &derived.cipher {
        Some(c) => c,
        None => return Err("no derived string cipher; prop solve impossible".into()),
    };
    let hdr = &derived.header;
    let strsec = cipher.strsec as usize;
    let sched = &cipher.schedule;
    let td = match td {
        Some(t) => t,
        None => return Ok(None),
    };
    let t0 = std::time::Instant::now();
    let tilings = solve_td_tiling(body, td, 250_000, 512);
    #[cfg(feature = "ev_debug")]
    for (i, t) in tilings.iter().enumerate() {
        eprintln!(
            "[prop] tiling {i}: start@{} {:?} {:#x} count@{} {:?} {:#x} total {} types {}",
            t.0.offset, t.0.kind, t.0.c, t.1.offset, t.1.kind, t.1.c, t.2, t.3.len()
        );
    }
    #[cfg(feature = "ev_debug")]
    eprintln!("[prop] tilings {} in {:?}", tilings.len(), t0.elapsed());
    if tilings.is_empty() {
        return Ok(None);
    }
    // base candidates: confirmed anchors inside the accessor window, ±8
    let mut base_cands: Vec<usize> = Vec::new();
    for a in &derived.anchors {
        if a.confirmed && a.site >= prop_fn && a.site < prop_fn + 0x700 {
            if let Some(v) = a.resolve(hdr) {
                for sh in [0i64, -8] {
                    let b = (v as i64 + sh) as usize;
                    if !base_cands.contains(&b) {
                        base_cands.push(b);
                    }
                }
            }
        }
    }
    if base_cands.is_empty() {
        return Ok(None);
    }
    let (imm32s, imm16s) = scan_immediates(img, exe, prop_fn, 0x700);
    if imm32s.is_empty() || imm16s.is_empty() {
        return Ok(None);
    }
    let rd32 = |off: usize| -> Option<u32> {
        let b = body.get(off..off + 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    };
    let rd16 = |off: usize| -> Option<u32> {
        let b = body.get(off..off + 2)?;
        Some(u16::from_le_bytes(b.try_into().ok()?) as u32)
    };
    let mut dedupe: Vec<&Expr> = Vec::new();
    for ch in chains {
        if !dedupe.iter().any(|e| format!("{e:?}") == format!("{ch:?}")) {
            dedupe.push(ch);
        }
    }
    let mut best: Option<(f64, usize, PropSolve)> = None;
    for (til_i, til) in tilings.iter().enumerate() {
        let (td_start, td_count, total, groups) = (&til.0, &til.1, til.2, &til.3);
        let mut owner = vec![0usize; total as usize];
        for (r, st, cnt) in groups {
            for j in 0..*cnt {
                let i = st + j;
                if (i as usize) < owner.len() {
                    owner[i as usize] = *r;
                }
            }
        }
        // even spread — the head rows decode systematically worse (6.2 props)
        let stp = (total / 240).max(1) as usize;
        let sample: Vec<u32> = (0..total as usize).step_by(stp).take(240).map(|i| i as u32).collect();
        for &base in &base_cands {
            for (ch_i, chain) in dedupe.iter().enumerate() {
                let t1 = std::time::Instant::now();
                let mask = |i: u32| -> u32 { chain.eval(i as u64, hdr, &|_, _| 0).unwrap_or(0) as u32 };
                // name board: (raw ^ C) − mask decodes (the 6.2 shape; the
                // xor/add mask shapes are kept for other generations)
                let mut name: Option<(u32, f64)> = None;
                for &c in &imm32s {
                    let tested = sample.len();
                    let mut good = 0usize;
                    for &i in &sample {
                        let Some(raw) = rd32(base + i as usize * 10) else { continue };
                        let idx = ((raw ^ c).wrapping_sub(mask(i))) & 0xFFFF_FFFF;
                        if dec_ident(body, strsec, sched, idx) {
                            good += 1;
                        }
                    }
                    let rate = good as f64 / tested.max(1) as f64;
                    if rate >= 0.9 && name.map(|(_, r)| rate > r).unwrap_or(true) {
                        name = Some((c, rate));
                    }
                }
                let Some((nxor, nrate)) = name else {
                    #[cfg(feature = "ev_debug")]
                    eprintln!("[prop] t{} base {base:#x} chain#{}: no name col", til_i, ch_i);
                    continue;
                };
                // get/set board: the two u16 columns whose XorCSubMask decodes
                // are adjacency-adjacent accessor indices; the third is the
                // typearr column.
                let mut ar: Option<(usize, u16, usize, u16, u32)> = None;
                for &acol in &[4usize, 6, 8] {
                    for &ca in &imm16s {
                        let mut av = Vec::with_capacity(sample.len());
                        let mut a_ok = true;
                        for &i in &sample {
                            let Some(raw) = rd16(base + i as usize * 10 + acol) else { continue };
                            let v = ((raw ^ ca as u32).wrapping_sub(mask(i))) & 0xFFFF;
                            if v != 0xFFFF && v >= 16384 {
                                a_ok = false;
                            }
                            av.push(v);
                        }
                        if !a_ok {
                            continue;
                        }
                        for &bcol in &[4usize, 6, 8] {
                            if bcol == acol {
                                continue;
                            }
                            for &cb in &imm16s {
                                let mut bv = Vec::with_capacity(sample.len());
                                let mut b_ok = true;
                                for &i in &sample {
                                    let Some(raw) = rd16(base + i as usize * 10 + bcol) else { continue };
                                    let v = ((raw ^ cb as u32).wrapping_sub(mask(i))) & 0xFFFF;
                                    if v != 0xFFFF && v >= 16384 {
                                        b_ok = false;
                                    }
                                    bv.push(v);
                                }
                                if !b_ok {
                                    continue;
                                }
                                let mut diffs: Vec<u32> = av
                                    .iter()
                                    .zip(&bv)
                                    .filter(|(a, b)| **a != 0xFFFF && **b != 0xFFFF)
                                    .map(|(a, b)| a.abs_diff(*b))
                                    .collect();
                                // setters are often absent (6.2: ~85%
                                // sentinel) — the pair only needs a handful
                                // of co-non-sentinel rows
                                if diffs.len() < sample.len() / 8 || diffs.len() < 12 {
                                    continue;
                                }
                                diffs.sort_unstable();
                                let med = diffs[diffs.len() / 2];
                                if ar.map(|(_, _, _, _, m)| med < m).unwrap_or(true) {
                                    ar = Some((acol, ca, bcol, cb, med));
                                }
                            }
                        }
                    }
                }
                let Some((acol, ca, bcol, cb, med)) = ar else {
                    #[cfg(feature = "ev_debug")]
                    eprintln!("[prop] t{} base {base:#x} chain#{}: name ok rate {:.2} but no accessor pair ({:?})", til_i, ch_i, nrate, t1.elapsed());
                    continue;
                };
                if med > 32 {
                    #[cfg(feature = "ev_debug")]
                    eprintln!("[prop] t{} base {base:#x} chain#{}: pair med {} too big", til_i, ch_i, med);
                    continue;
                }
                let sol = PropSolve {
                    defs: crate::derive::profile::TableBase { hdr_off: 0, sub: None, xor: None, add: None, direct: None },
                    stride: 10,
                    td_start: td_start.clone(),
                    td_count: td_count.clone(),
                    mask_expr: (*chain).clone(),
                    name_xor: nxor,
                    get_xor: ca,
                    set_xorsub: cb,
                    total_props: total,
                    name_rate: nrate,
                    base_shift: 0,
                };
                let _ = owner.len();
                if best.as_ref().map(|(r, _, _)| nrate > *r).unwrap_or(true) {
                    best = Some((nrate, base, sol));
                }
            }
        }
    }
    let Some((_, win_base, mut sol)) = best else { return Ok(None) };
    let mut anchor = None;
    for a in &derived.anchors {
        if a.confirmed && a.site >= prop_fn && a.site < prop_fn + 0x700 {
            if let Some(v) = a.resolve(hdr) {
                let shift = win_base as i64 - v as i64;
                if shift.abs() <= 8 {
                    anchor = Some((a, shift, v as usize));
                    break;
                }
            }
        }
    }
    if let Some((a, shift, v)) = anchor {
        sol.base_shift = shift;
        sol.defs = match a.op {
            crate::derive::anchor::AnchorOp::Add => crate::derive::profile::TableBase {
                hdr_off: a.hdr_off,
                sub: None,
                xor: None,
                add: Some(a.imm.wrapping_add(shift as u32)),
                direct: None,
            },
            _ => crate::derive::profile::TableBase {
                hdr_off: a.hdr_off,
                sub: None,
                xor: None,
                add: None,
                direct: Some((v as i64 + shift) as u32),
            },
        };
    } else {
        return Ok(None);
    }
    Ok(Some(sol))
}

#[cfg(test)]
mod tests4 {
    use super::*;
    #[test]
    fn diagnoses_62_props() {
        let Ok(gm) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat") else { eprintln!("[skip] dat"); return; };
        let Ok(exe) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen.exe") else { eprintln!("[skip] exe"); return; };
        let derived = crate::derive::cipher::derive_build(&exe, &gm).expect("derive");
        let dv = derived.as_ref().expect("dv");
        let td = crate::profile_splice::solve_typedef(&exe, &gm, dv).expect("td").expect("td");
        let img = crate::pe::Image::parse(&exe).expect("pe");
        let chains: Vec<crate::expr::Expr> = serde_json::from_str(&std::fs::read_to_string("/tmp/62.auto3.json").expect("auto")) // dummy to fail gracefully
            .unwrap_or_else(|_| {
                let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("/tmp/62.auto3.json").unwrap()).unwrap();
                v["semantics"]["prop"]["chains"].as_array().map(|a| a.iter().filter_map(|c| serde_json::from_value(c.clone()).ok()).collect()).unwrap_or_default()
            });
        println!("prop chains: {}", chains.len());
        let r = std::panic::catch_unwind(|| solve_props(&img, &exe, &gm, dv, 0x14044AF56, &chains, Some(&td)));
        match r {
            Ok(Ok(Some(s))) => println!("PROPS: name ^{:#x} rate {:.2} get@{} ^{:#x} set@{} ^{:#x} total {} shift {:+} defs hdr_off {} add {:?}",
                s.name_xor, s.name_rate, 4, s.get_xor, 8, s.set_xorsub, s.total_props, s.base_shift, s.defs.hdr_off, s.defs.add),
            Ok(Ok(None)) => println!("PROPS: none"),
            Ok(Err(e)) => println!("PROPS: err {e}"),
            Err(_) => println!("PROPS: PANICKED"),
        }
    }
}

#[cfg(test)]
mod tests5 {
    use super::*;
    #[test]
    fn probes_62_prop_chains() {
        let Ok(gm) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat") else { eprintln!("[skip] dat"); return; };
        let Ok(exe) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen.exe") else { eprintln!("[skip] exe"); return; };
        let derived = crate::derive::cipher::derive_build(&exe, &gm).expect("derive");
        let dv = derived.as_ref().expect("dv");
        let img = crate::pe::Image::parse(&exe).expect("pe");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("/tmp/62.auto3.json").unwrap()).unwrap();
        let chains: Vec<crate::expr::Expr> = v["semantics"]["prop"]["chains"].as_array().map(|a| a.iter().filter_map(|c| serde_json::from_value(c.clone()).ok()).collect()).unwrap_or_default();
        let cipher = dv.cipher.as_ref().unwrap();
        let body = &gm[0x210..];
        let strsec = cipher.strsec as usize;
        let base = 0x18012E4usize;
        let rd32 = |off: usize| u32::from_le_bytes(body[off..off+4].try_into().unwrap());
        for (ci, chain) in chains.iter().enumerate() {
            let mask = |i: u32| -> u32 { chain.eval(i as u64, &dv.header, &|_, _| 0).unwrap_or(0) as u32 };
            let mut good = 0usize; let n = 61usize;
            for i in (0..60000u32).step_by(997) {
                let raw = rd32(base + i as usize * 10);
                let idx = ((raw ^ 0x1844A562).wrapping_sub(mask(i))) & 0xFFFF_FFFF;
                if dec_ident(body, strsec, &cipher.schedule, idx) { good += 1; }
            }
            if good > n / 4 {
                println!("chain {ci}: name rate {good}/{n}");
            }
        }
        println!("probe done");
    }
}

#[cfg(test)]
mod tests6 {
    use super::*;
    #[test]
    fn probes_62_method_frame() {
        let Ok(gm) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat") else { eprintln!("[skip] dat"); return; };
        let Ok(exe) = std::fs::read("/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen.exe") else { eprintln!("[skip] exe"); return; };
        let Ok(pj) = std::fs::read_to_string("/tmp/62.profile.sol8.json") else { eprintln!("[skip] profile"); return; };
        let profile: crate::derive::profile::Profile = serde_json::from_str(&pj).expect("profile parse");
        let m = crate::derive::engine::Meta::load_with_startup(&exe, &gm, None, profile);
        let m = match m { Ok(m) => m, Err(e) => { println!("load err {e}"); return; } };
        println!("td74: start={} count={:?}", m.td_method_start(74), m.td_method_count(74));
        println!("td75: start={} count={:?}", m.td_method_start(75), m.td_method_count(75));
        println!("td0: start={} count={:?}", m.td_method_start(0), m.td_method_count(0));
    }
}
