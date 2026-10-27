//! Splice a solved auto-tables report into a seed [`Profile`] (R78).
//!
//! The zero-touch pipeline (shape transfer → symwalk/emu chains → rowtable
//! column solve) recovers SOME of a target build's constants; everything it
//! did not recover keeps the seed profile's value. This module performs that
//! merge and records, field-group by field-group, what is *solved* (machine
//! set and validated for the target), *partial* (table base transferred, but
//! column constants still seed data), and *inherited* (seed value untouched),
//! so nobody mistakes a spliced profile for a fully solved one.
//!
//! Everything here is data plumbing; no version constant lives in this file.
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0.

use crate::derive::cipher::BuildDerivation;
use crate::derive::profile::{ColKind, Column, Profile, TableBase};
use crate::rowtable::{is_identifier, TableReport};
use crate::shape_transfer::{parse_op, AnchorOp, TransferRec, TransferReport};
use serde::Serialize;

/// Field-group level provenance of a spliced profile.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct SpliceManifest {
    /// Machine-set AND validated against the target (cipher, strsec, method slice).
    pub solved: Vec<String>,
    /// Table BASE transferred from the seed semantics; column constants inside
    /// the table are still seed data and may be wrong for the target.
    pub partial: Vec<String>,
    /// Seed values kept as-is (never validated for the target).
    pub inherited: Vec<String>,
    /// Anomalies worth a human look (weak matches, cross-check failures).
    pub notes: Vec<String>,
}


/// Field-name decode rate over the first `n` rows of a candidate field-table
/// base, using the profile's own field mask + name xor: the share of decodable
/// rows whose name is a plausible identifier. A WRONG base (e.g. the typeDef
/// table, which the transfer can pick on a weak match) decodes to noise.
fn field_name_rate(body: &[u8], base: usize, p: &Profile, n: usize) -> f64 {
    let sched = p.schedule();
    let (mut ok, mut good) = (0usize, 0usize);
    for i in 0..n {
        let at = base + i * p.field_stride as usize;
        let Some(b) = body.get(at..at + 4) else { break };
        let raw = u32::from_le_bytes(b.try_into().unwrap());
        let m = p.field_mask.eval(i as u32);
        let idx = raw ^ m ^ p.field_name_xor;
        let s = crate::decode_str::decode_str_sched(
            &crate::mem::Buffer::new(body),
            p.strsec_direct.map(|v| v as usize).unwrap_or(0),
            idx,
            &sched,
        );
        if s.is_empty() {
            continue;
        }
        ok += 1;
        if is_identifier(&s) {
            good += 1;
        }
    }
    good as f64 / ok.max(1) as f64
}

fn table_base(rec: &TransferRec) -> TableBase {
    // rec.op carries EITHER the seed word ("add") or, after a successful
    // transfer, the anchor symbol ("+") — parse_op accepts both.
    let imm = rec.imm as u32;
    let op = parse_op(&rec.op);
    TableBase {
        hdr_off: rec.slot,
        sub: (op == AnchorOp::Sub).then_some(imm),
        xor: (op == AnchorOp::Xor).then_some(imm),
        add: (op == AnchorOp::Add).then_some(imm),
    }
}

/// Seed semantics that transfer cleanly but have no Profile field yet —
/// the engine reads them from hardcoded constants (R78 gap, see notes).
const NO_FIELD: &[&str] = &[
    "generic_params",
    "generic_containers",
    "usage_index",
    "usage_pairs",
    "literal_offsets",
    "literal_data",
];

/// Splice transfer results + method solve + build derivation into `seed`.
///
/// `derived` is the TARGET build's own derivation (`derive_build`); its cipher
/// and strsec are authoritative over any transfer (they come from the decoder
/// code itself), which is why `strsec_direct` always wins over slot formulas.
pub fn splice_profile(
    mut p: Profile,
    report: &TransferReport,
    method: Option<&TableReport>,
    td: Option<&TdSolve>,
    derived: Option<&BuildDerivation>,
    body: &[u8],
) -> (Profile, SpliceManifest) {
    let mut m = SpliceManifest::default();

    // ---- cipher + string section: always the target's own derivation ----
    if let Some(b) = derived {
        if let Some(c) = &b.cipher {
            p.cipher = Some(c.schedule.clone());
            p.strsec_direct = Some(c.strsec);
            m.solved.push("cipher (derived from decoder code)".into());
            m.solved.push("strsec (strsec_direct)".into());
        } else {
            m.notes.push("no string cipher derived from this image; seed cipher kept".into());
        }
    }

    // ---- table bases from the shape transfer ----
    let mut transferred = std::collections::HashSet::new();
    for (name, rec) in &report.semantics {
        if rec.resolved.is_none() {
            if rec.matched_fn == 0 {
                m.notes.push(format!("{name}: transfer unmatched (score {:.3})", rec.score));
            } else {
                m.notes.push(format!("{name}: transfer unresolved (score {:.3})", rec.score));
            }
            continue;
        }
        if rec.score < 0.3 && rec.matched_fn != 0 {
            // L5 gate: a WEAK fingerprint match proves nothing about the
            // ordinal pick. Accept it only when the target's own derive
            // anchors contain the exact (slot, op, imm) — code-level
            // confirmation independent of the transfer. Verified on 6.6
            // field_names: the weak pick (slot 0x4 ^ 0x46E79FE3) has no
            // derive anchor, the correct one (0xDC + 0x9623F4C7) does.
            let op = parse_op(&rec.op);
            let confirmed = derived
                .map(|dv| {
                    dv.anchors.iter().any(|a| {
                        a.hdr_off == rec.slot
                            && a.imm as u64 == rec.imm
                            && matches!(
                                (a.op, op),
                                (crate::derive::anchor::AnchorOp::Add, AnchorOp::Add)
                                    | (crate::derive::anchor::AnchorOp::Sub, AnchorOp::Sub)
                                    | (crate::derive::anchor::AnchorOp::Xor, AnchorOp::Xor)
                            )
                    })
                })
                .unwrap_or(false);
            if confirmed {
                m.notes.push(format!(
                    "{name}: WEAK match score {:.3} but CONFIRMED by a target derive anchor",
                    rec.score
                ));
            } else {
                m.notes.push(format!(
                    "{name}: WEAK match score {:.3} with NO derive anchor for slot {:#x} {} {:#X} — base REJECTED, seed value kept",
                    rec.score, rec.slot, op.name(), rec.imm
                ));
                continue;
            }
        }
        let tb = table_base(rec);
        let partial = format!("{name}.base");
        match name.as_str() {
            "type_defs" => p.type_defs = tb,
            "td_size" => p.td_size = Some(tb),
            "method_defs" => p.method_defs = tb,
            "md_size" => p.md_size = Some(tb),
            "fields" => p.fields = tb,
            "params" => p.params = tb,
            "nested_types" => p.nested_types = Some(tb),
            "event_defs" => p.event_defs = Some(tb),
            "field_names" => {
                // L6 decode gate: the base must yield identifier-looking
                // field names under the profile's own field mask. L5 alone
                // accepted the TYPE-DEF anchor here on 7.1 (a real anchor,
                // wrong table). On failure, sweep the derive anchors for a
                // base that does decode.
                let cand = rec.resolved.map(|r| (r & 0xFFFF_FFFF) as usize);
                let mut chosen: Option<(TableBase, usize, f64)> = None;
                let mut cands: Vec<(usize, TableBase)> = vec![];
                if let Some(b) = cand {
                    cands.push((b, tb.clone()));
                }
                if let Some(dv) = derived {
                    for a in &dv.anchors {
                        if let Some(r) = a.resolve(&dv.header) {
                            cands.push((r as usize, anchor_table_base(a)));
                        }
                    }
                }
                for (b, tbx) in cands {
                    if body.len().saturating_sub(b) < 4096 {
                        continue;
                    }
                    let rate = field_name_rate(body, b, &p, 256);
                    if rate >= 0.98 {
                        chosen = Some((tbx, b, rate));
                        break;
                    }
                }
                match chosen {
                    Some((tbx, b, rate)) => {
                        if cand != Some(b) {
                            m.notes.push(format!(
                                "field_names: transfer base {:#x} failed the decode gate; anchor base {:#x} passes (rate {:.2})",
                                cand.unwrap_or(0), b, rate
                            ));
                        }
                        p.field_names = tbx;
                        m.partial.push(partial);
                        transferred.insert(name.clone());
                    }
                    None => {
                        m.notes.push(
                            "field_names: no candidate base decodes as field names; seed base kept".into(),
                        );
                    }
                }
                continue;
            }
            "field_defaults" => p.field_defaults = Some(tb),
            "field_defaults_size" => p.field_defaults_size = Some(tb),
            "default_value_data" => p.default_value_data = Some(tb),
            "param_defs" => p.param_defs = Some(tb),
            "param_defaults_size" => p.param_defaults_size = Some(tb),
            "iface_table" => p.iface_table = tb,
            "str" => {
                // engine formula: strsec = i32(hdr[hdr_off]) - str_sub (mod 2^32);
                // the anchor formula is hdr[slot] ± imm, so add -> sub = -imm.
                let op = parse_op(&rec.op);
                let want = match (op, derived.and_then(|b| b.cipher.as_ref())) {
                    (AnchorOp::Add, Some(c)) | (AnchorOp::Sub, Some(c)) => Some(c.strsec),
                    _ => None,
                };
                if let (Some(want), Some(hdr)) = (want, derived.map(|b| &b.header)) {
                    let raw = u32::from_le_bytes(
                        hdr[rec.slot as usize..rec.slot as usize + 4].try_into().unwrap_or([0; 4]),
                    );
                    let got = match op {
                        AnchorOp::Add => raw.wrapping_add(rec.imm as u32),
                        AnchorOp::Sub => raw.wrapping_sub(rec.imm as u32),
                        AnchorOp::Xor => raw ^ rec.imm as u32,
                    };
                    if got != want {
                        m.notes.push(format!(
                            "str: slot {:#x} resolves {:#x} but derived strsec is {:#x}; keeping strsec_direct",
                            rec.slot, got, want
                        ));
                        continue;
                    }
                }
                match op {
                    AnchorOp::Add => {
                        p.str_hdr_off = rec.slot;
                        p.str_sub = rec.imm.wrapping_neg() as u32;
                    }
                    AnchorOp::Sub => {
                        p.str_hdr_off = rec.slot;
                        p.str_sub = rec.imm as u32;
                    }
                    AnchorOp::Xor => {
                        m.notes.push("str: xor op has no profile formula; strsec_direct covers it".into());
                        continue;
                    }
                }
                m.solved.push("str_hdr_off/str_sub (cross-checked)".into());
                continue;
            }
            "startup_images" => match &mut p.startup_images {
                Some(s) => s.table = tb,
                None => {
                    m.notes.push("startup_images: seed profile has no startup table to splice into".into());
                    continue;
                }
            },
            "startup_assemblies" => match &mut p.startup_assemblies {
                Some(s) => s.table = tb,
                None => {
                    m.notes.push("startup_assemblies: seed profile has no startup table to splice into".into());
                    continue;
                }
            },
            other if NO_FIELD.contains(&other) => {
                m.notes.push(format!("{other}: transferred but no Profile field yet (engine hardcode)"));
                continue;
            }
            other => {
                m.notes.push(format!("{other}: no splice mapping (unknown semantic)"));
                continue;
            }
        }
        m.partial.push(partial);
        transferred.insert(name.clone());
    }

    // ---- method-table slice (the only fully machine-solved table today) ----
    match method.and_then(|r| r.name.as_ref().map(|n| (r, n))) {
        Some((rep, name)) if !rep.counts.is_empty() && !rep.starts.is_empty() => {
            let cnt = &rep.counts[0];
            let st = &rep.starts[0];
            let Some(count_kind) = ColKind::from_count_op(&cnt.op) else {
                m.notes.push(format!("method slice: unknown count op {:?}", cnt.op));
                return (p, m);
            };
            p.md_stride = rep.stride as u32;
            p.md_mask_expr = Some(rep.chain.clone());
            // the method slice is target data; a seed md_size would resolve
            // against the target header to garbage, and the engine prefers it
            // over everything — drop it when the transfer did not carry one.
            if !transferred.contains("md_size") {
                p.md_size = None;
                // structural size probe: an anchor resolving to a byte count
                // that divides by the stride into [lower bound, +512) rows.
                // Lower bound = the typeDef tiling's max methodStart+1 (the
                // exact row count minus at most trailing padding).
                if let Some(dv) = derived {
                    let lo = td
                        .map(|t| t.max_method_index.wrapping_add(1) as usize)
                        .unwrap_or(st.sum_counts as usize)
                        .max(1);
                    for a in &dv.anchors {
                        let Some(off) = a.resolve(&dv.header) else { continue };
                        let off = off as usize;
                        if off % rep.stride != 0 || off / rep.stride < lo {
                            continue;
                        }
                        if off / rep.stride < lo + 512 {
                            p.md_size = Some(anchor_table_base(a));
                            break;
                        }
                    }
                }
            }
            p.md_name = Column {
                offset: name.off as u32,
                kind: ColKind::from_fam(name.family),
                c: name.c as u32,
            };
            p.md_param_start = Column {
                offset: st.off as u32,
                kind: ColKind::from_fam(st.family),
                c: st.c as u32,
            };
            p.md_param_count = Column {
                offset: cnt.off as u32,
                kind: count_kind,
                c: cnt.c as u32,
            };
            m.solved.push(
                "method_defs.slice (stride + mask chain + name/param_start/param_count)".into(),
            );
            if st.chain_bad > 0 {
                m.notes.push(format!(
                    "method slice: param_start chain has {} violations (accepted by solver gates)",
                    st.chain_bad
                ));
            }
        }
        // name-only splice: the name column + chain alone put correct method
        // names in the dump; params stay seed-decoded (6.2's count/start use
        // a second-stage mask the u8/u32 solvers do not model yet)
        Some((rep, name)) if crate::rowtable::name_column_ok(name, 4000) => {
            p.md_stride = rep.stride as u32;
            p.md_mask_expr = Some(rep.chain.clone());
            if !transferred.contains("md_size") {
                p.md_size = None;
                // structural size probe (same as the full-slice branch, but no
                // start column exists here to bound rows from below)
                if let Some(dv) = derived {
                    let lo = td
                        .map(|t| t.max_method_index.wrapping_add(1) as usize)
                        .unwrap_or(1)
                        .max(1);
                    for a in &dv.anchors {
                        let Some(off) = a.resolve(&dv.header) else { continue };
                        let off = off as usize;
                        if off % rep.stride != 0 || off / rep.stride < lo {
                            continue;
                        }
                        if off / rep.stride < lo + 512 {
                            p.md_size = Some(anchor_table_base(a));
                            break;
                        }
                    }
                }
            }
            p.md_name = Column {
                offset: name.off as u32,
                kind: ColKind::from_fam(name.family),
                c: name.c as u32,
            };
            m.solved
                .push("method_defs.slice (PARTIAL: stride + mask chain + name only)".into());
            m.notes.push(
                "method slice: count/start columns unsolved (likely a mask2 variant); \
                 param columns stay seed data"
                    .into(),
            );
        }
        _ => m.notes.push("method table not solved; md_* columns stay seed data".into()),
    }

    // ---- typeDef slice (structural solve; no seed semantics needed) ----
    if let Some(td) = td {
        splice_td(&mut p, td, &mut m);
    }

    m.inherited.extend([
        "td columns (td_name/td_ns/td_method_start/td_field_start/td_field_count/...)".into(),
        "md other columns (md_ret_type/md_decl/md_slot/md_flags)".into(),
        "fields table columns + fd_pmask".into(),
        "param_defs column xors + param_def_mask".into(),
        "property/event column constants + masks".into(),
        "startup name-table masks".into(),
        "generic-params engine hardcodes (gp/gc chains)".into(),
        "strides other than md_stride (td_stride etc.)".into(),
    ]);
    (p, m)
}

/// Convenience: deserialize a seed profile written by `dump-gen --profile-out`.
pub fn load_seed_profile(path: &str) -> Result<Profile, String> {
    serde_json::from_str(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

// ===========================================================================
// typeDef table: solved entirely from structure (no seed, no transfer)
// ===========================================================================

/// The typeDef table as recovered by the constant-free structural scan:
/// `tables::find` gives the two (start, count) pairs, the string-column finder
/// gives the name column, and the build's own anchors turn the body offsets
/// back into Profile `TableBase` slot forms.
#[derive(Clone, Serialize)]
pub struct TdSolve {
    pub base: usize,
    pub stride: u32,
    /// Rows in the tiling run, INCLUDING trailing all-sentinel padding.
    pub rows: usize,
    pub name: Column,
    /// Namespace column (the OTHER string-index column), when a second one
    /// survives the printable-run finder.
    pub ns: Option<Column>,
    pub method_start: Column,
    pub field_start: Column,
    pub field_count: Column,
    /// Raw fieldStart value that decodes to "no fields" (None = none seen).
    pub fs_sentinel_raw: Option<u32>,
    /// Highest methodStart seen + 1 — a lower bound/cross-check on method rows.
    pub max_method_index: u32,
    /// Header-slot form of the table base, when an anchor resolves to it.
    pub type_defs: Option<TableBase>,
    /// Header-slot form of the table byte size, when an anchor resolves to a
    /// plausible multiple of the stride just past the run.
    pub td_size: Option<TableBase>,
    pub notes: Vec<String>,
}

fn anchor_table_base(a: &crate::derive::anchor::Anchor) -> TableBase {
    use crate::derive::anchor::AnchorOp;
    TableBase {
        hdr_off: a.hdr_off,
        sub: (a.op == AnchorOp::Sub).then_some(a.imm),
        xor: (a.op == AnchorOp::Xor).then_some(a.imm),
        add: (a.op == AnchorOp::Add).then_some(a.imm),
    }
}

fn pair_column(t: &crate::derive::tables::IndexTable, idx: bool) -> Column {
    use crate::derive::tables::IndexTransform;
    // IndexTable decodes `plain = raw - c` (Add) or `raw ^ c` (Xor); the
    // profile's static kinds are `raw + c`, so Add carries the negated c.
    let (tr, c) = if idx {
        (t.transform, t.idx_c)
    } else {
        (t.cnt_transform, t.cnt_c as u32)
    };
    let off = if idx { t.idx_off } else { t.cnt_off };
    match tr {
        IndexTransform::Xor => Column { offset: off, kind: ColKind::XorC, c },
        IndexTransform::Add => Column {
            offset: off,
            kind: ColKind::AddC,
            c: c.wrapping_neg(),
        },
    }
}

/// Solve the typeDef table for one build, structurally:
/// 1. candidate bases from the code's own table sites,
/// 2. `tables::find` (start/count tiling predicate),
/// 3. pick the group that also has a string-index name column,
/// 4. map both pairs + name back onto Profile columns and anchor the bases.
pub fn solve_typedef(
    exe: &[u8],
    dat: &[u8],
    derived: &BuildDerivation,
) -> Result<Option<TdSolve>, String> {
    use crate::derive::tables::{self, IndexTable, StringTransform};
    let body = dat.get(0x210..).unwrap_or(&[]);
    let (bases, src) = tables::candidate_bases(exe, Some(derived));
    if bases.is_empty() {
        return Err("no candidate table bases (neither code sites nor anchors)".into());
    }
    let found = tables::find(body, &bases);
    if found.is_empty() {
        return Ok(None);
    }
    // group by (base, stride); the typeDef table is the group with >= 2
    // start/count pairs (methods + fields) AND a valid name column.
    let mut groups: std::collections::BTreeMap<(usize, u32), Vec<&IndexTable>> =
        std::collections::BTreeMap::new();
    for t in &found {
        groups.entry((t.base, t.stride)).or_default().push(t);
    }
    let Some(cipher) = &derived.cipher else {
        return Err("no derived string cipher; name column cannot be verified".into());
    };
    let strsec = cipher.strsec as usize;
    let mut notes = Vec::new();
    let mut best: Option<(Vec<&IndexTable>, tables::StringColumn, Option<tables::StringColumn>)> = None;
    for ((base, stride), entries) in &groups {
        if entries.len() < 2 {
            continue;
        }
        let rows = entries[0].rows;
        if !(20_000..=400_000).contains(&rows) {
            continue;
        }
        let sample = rows.min(4096);
        let mut cols = tables::find_additive_string_columns(
            body, strsec, &cipher.schedule, *base, *stride, sample,
        );
        cols.extend(tables::find_xor_string_columns(
            body, strsec, &cipher.schedule, *base, *stride, sample,
        ));
        let Some(name) = cols
            .iter()
            .filter(|c| c.rows_tested > 0 && c.rows_ok as f64 / c.rows_tested as f64 >= 0.9)
            .max_by_key(|c| c.rows_ok)
        else {
            continue;
        };
        // namespace = the best OTHER accepted string column (the td row has
        // exactly two: name and namespace)
        let ns = cols
            .iter()
            .filter(|c| {
                c.off != name.off && c.rows_tested > 0 && c.rows_ok as f64 / c.rows_tested as f64 >= 0.9
            })
            .max_by_key(|c| c.rows_ok)
            .cloned();
        let better = best
            .as_ref()
            .map(|(e, _, _)| entries[0].real_rows > e[0].real_rows)
            .unwrap_or(true);
        if better {
            if best.is_some() {
                notes.push(format!(
                    "multiple typeDef candidates; kept base {base:#x} (most real rows)"
                ));
            }
            best = Some((entries.clone(), name.clone(), ns));
        }
    }
    let Some((entries, name_col, ns_col)) = best else {
        return Ok(None);
    };
    let mut entries: Vec<&IndexTable> = entries;
    // methods outnumber fields by ~1.5x in every build measured; the pair with
    // the larger max index is the methodStart/methodCount pair.
    entries.sort_by_key(|t| t.max_index);
    let field_pair = entries[entries.len() - 2];
    let method_pair = entries[entries.len() - 1];
    if method_pair.max_index < 100_000 {
        notes.push(format!(
            "methodStart max index only {} — expected several hundred thousand",
            method_pair.max_index
        ));
    }
    let mk_col = |c: &tables::StringColumn| Column {
        offset: c.off,
        kind: match c.transform {
            StringTransform::Add => ColKind::AddC,
            StringTransform::Xor => ColKind::XorC,
        },
        c: c.c,
    };
    let name = mk_col(&name_col);
    let ns = ns_col.as_ref().map(&mk_col);
    // anchor the base and the byte size back to header slots
    let hdr = &derived.header;
    let mut type_defs = None;
    let mut td_size = None;
    let stride = entries[0].stride;
    let rows = entries[0].rows;
    for a in &derived.anchors {
        let Some(off) = a.resolve(hdr) else { continue };
        let off = off as usize;
        if off == entries[0].base && type_defs.is_none() {
            type_defs = Some(anchor_table_base(a));
        }
        if td_size.is_none() && off % stride as usize == 0 {
            let r = off / stride as usize;
            if (rows..rows + 512).contains(&r) {
                td_size = Some(anchor_table_base(a));
            }
        }
    }
    if type_defs.is_none() {
        notes.push(format!(
            "typeDef base {:#x} has no matching header anchor — cannot express as TableBase",
            entries[0].base
        ));
    }
    if td_size.is_none() {
        notes.push("no td_size anchor: row count carried as td_rows_direct (structural walk)".into());
    }
    Ok(Some(TdSolve {
        base: entries[0].base,
        stride,
        rows,
        name,
        ns,
        method_start: pair_column(method_pair, true),
        field_start: pair_column(field_pair, true),
        field_count: pair_column(field_pair, false),
        fs_sentinel_raw: field_pair.sentinel_raw,
        max_method_index: method_pair.max_index,
        type_defs,
        td_size,
        notes,
    }))
}

/// Splice a solved typeDef table into the profile (solved-grade fields only;
/// td_ns / parent / flags columns stay seed data and are reported as such).
pub fn splice_td(p: &mut Profile, td: &TdSolve, m: &mut SpliceManifest) {
    let Some(tb) = td.type_defs.clone() else {
        m.notes.push("typeDef solve dropped: base has no header anchor".into());
        for n in &td.notes {
            m.notes.push(format!("td: {n}"));
        }
        return;
    };
    p.type_defs = tb;
    if let Some(sz) = &td.td_size {
        p.td_size = Some(sz.clone());
    } else {
        // no size anchor: the SEED's td_size must go — it resolves against the
        // target header to garbage (the 144714-row live-run lesson). Carry the
        // walk row count directly instead (td_count trims trailing padding).
        p.td_size = None;
        p.td_rows_direct = Some(td.rows as u32);
    }
    p.td_stride = td.stride;
    p.td_name = td.name.clone();
    if let Some(ns) = &td.ns {
        p.td_ns = ns.clone();
        m.solved.push("td_ns (second string column)".into());
    }
    p.td_method_start = td.method_start.clone();
    p.td_field_start = td.field_start.clone();
    if let Some(s) = td.fs_sentinel_raw {
        p.td_fs_sentinel_raw = s;
    }
    p.td_field_count = td.field_count.clone();
    // the typeDef tiling gives the method-row count for free (highest
    // methodStart + 1). Used only when no md_size survived the splice: the
    // size slot is exact, this is a lower bound that still beats mptrs.
    if p.md_size.is_none() {
        p.md_rows_direct = Some(td.max_method_index.wrapping_add(1));
    }
    m.solved.push(format!(
        "type_defs.slice (stride {} + name/method_start/field_start/field_count{}, rows≥{})",
        td.stride,
        if td.td_size.is_some() { " + td_size" } else { " + walk rows" },
        td.rows
    ));
    for n in &td.notes {
        m.notes.push(format!("td: {n}"));
    }
    m.inherited.retain(|s| !s.contains("td_name/td_ns"));
    m.inherited.push("td_ns / td_parent / td_flags / td_bitfield columns (seed data)".into());
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::{BinOp, Expr};
    use crate::rowtable::{CountCol, NameCol, StartCol};
    use crate::shape_transfer::TransferRec;

    fn rec(slot: u32, op: &str, imm: u64, resolved: u64, score: f64) -> TransferRec {
        TransferRec {
            score,
            matched_fn: 0x1400_1000,
            slot,
            op: op.into(),
            imm,
            resolved: Some(resolved),
            stride_expected: None,
            chains: vec![],
            note: None,
        }
    }

    fn seed_profile() -> Profile {
        crate::derive::layout71::gen71()
    }

    /// The str semantic inversion: 7.1 seed str {slot 0x150, add, 0xC8542DD2}
    /// must land on layout71's own str_hdr_off/str_sub — the profile and the
    /// semantic describe the same loader idiom in two notations.
    #[test]
    fn str_semantic_matches_layout71() {
        let mut report = TransferReport {
            target_exe: String::new(),
            semantics: Default::default(),
        };
        report.semantics.insert(
            "str".into(),
            rec(0x150, "add", 0xC854_2DD2, 0xDEAD_BEEF, 1.0),
        );
        let (p, m) = splice_profile(seed_profile(), &report, None, None, None, &[]);
        assert_eq!(p.str_hdr_off, 0x150);
        assert_eq!(p.str_sub, 0x37AB_D22E);
        assert!(m.solved.iter().any(|s| s.contains("str_hdr_off")));
        // seed profile baseline: layout71 says the same thing
        assert_eq!(seed_profile().str_sub, 0x37AB_D22E);
    }

    /// Method slice round trip: the spliced columns must reproduce
    /// fam_value/count_decode exactly through gen_col_value.
    #[test]
    fn method_slice_matches_solver_families() {
        let chain = Expr::Lo(
            32,
            Box::new(Expr::Op2(
                BinOp::Add,
                Box::new(Expr::Op2(
                    BinOp::Mul,
                    Box::new(Expr::Sym("i".into())),
                    Box::new(Expr::Imm(0x9E37_79B1)),
                )),
                Box::new(Expr::Imm(0x1234_5678)),
            )),
        );
        let rep = TableReport {
            base: 0x1000,
            stride: 26,
            rows: 100,
            chain,
            name: Some(NameCol {
                off: 8,
                family: crate::expr::Fam::XorCSubMask,
                c: 0x06BB_F48D,
                pinned_row: 1,
                ok_rows: 3000,
                idrate: 0.99,
            }),
            counts: vec![CountCol { off: 24, op: "sub".into(), c: 88, mean: 0.4 }],
            starts: vec![StartCol {
                off: 0,
                family: crate::expr::Fam::XorCSubMask,
                c: 0x0D62_B555,
                chain_bad: 0,
                sentinel_ok: 900,
                sentinel_total: 900,
                sum_counts: 4096,
            }],
        };
        let mut report = TransferReport {
            target_exe: String::new(),
            semantics: Default::default(),
        };
        report
            .semantics
            .insert("method_defs".into(), rec(0x1E0, "xor", 0x2EEC_3A0B, 0x1000, 1.0));
        let (p, m) = splice_profile(seed_profile(), &report, Some(&rep), None, None, &[]);

        assert_eq!(p.md_stride, 26);
        assert!(p.md_mask_expr.is_some());
        assert_eq!(p.md_name.offset, 8);
        assert_eq!(p.md_name.c, 0x06BB_F48D);
        assert_eq!(p.md_param_count.offset, 24);
        assert_eq!(p.md_param_count.c, 88);

        // decode equivalence: profile kinds vs the solver's own math
        let mask = 0xE4A8_05CDu32;
        for raw in [0xED13_F17Au32, 0x0BAD_C0DE, 0x1234_5678] {
            let v_name = crate::derive::profile::gen_col_value(
                p.md_name.kind,
                raw,
                mask,
                p.md_name.c,
            );
            assert_eq!(
                v_name,
                crate::expr::fam_value(
                    crate::expr::Fam::XorCSubMask,
                    raw as u64,
                    mask as u64,
                    0x06BB_F48D,
                    u32::MAX as u64
                ) as u32
            );
        }
        // count: rowtable "sub" C=88 == raw - mask8 - 88
        for raw in [0u32, 17, 200, 255] {
            let v = crate::derive::profile::gen_col_value(
                p.md_param_count.kind,
                raw,
                mask,
                p.md_param_count.c,
            );
            assert_eq!(
                v as u8,
                (raw as u8).wrapping_sub(mask as u8).wrapping_sub(88)
            );
        }
        assert!(m.solved.iter().any(|s| s.contains("method_defs.slice")));
        assert!(m.partial.iter().any(|s| s == "method_defs.base"));
    }

    /// Transferred base lands in the right field and is marked partial.
    #[test]
    fn table_bases_land() {
        let mut report = TransferReport {
            target_exe: String::new(),
            semantics: Default::default(),
        };
        report
            .semantics
            .insert("field_names".into(), rec(0xDC, "add", 0xE5D3_E43F, 0x2000, 0.9));
        report
            .semantics
            .insert("generic_params".into(), rec(0x174, "add", 1, 0x3000, 0.9));
        report
            .semantics
            .insert("type_defs".into(), rec(0xDC, "xor", 0x5266_9FF5, 0x4000, 0.05));
        // op in SYMBOL form ("+"), the way a successful transfer reports it
        report
            .semantics
            .insert("params".into(), rec(0x1D0, "+", 0x08F4_E5DB, 0x5000, 0.9));
        let (p, m) = splice_profile(seed_profile(), &report, None, None, None, &[]);
        // L6 gate: with no decodable body the transfer pick cannot be
        // validated, so the SEED base stays and the failure is noted.
        assert_eq!(p.field_names.hdr_off, seed_profile().field_names.hdr_off);
        assert!(m.notes.iter().any(|n| n.contains("field_names: no candidate base decodes")));
        assert!(!m.partial.iter().any(|s| s == "field_names.base"));
        assert!(m.notes.iter().any(|n| n.contains("generic_params")));
        // weak type_defs match: still spliced, but flagged
        assert!(m.notes.iter().any(|n| n.contains("type_defs") && n.contains("WEAK")));
        // symbol-form op must keep its imm (the 6.6 live-run regression)
        assert_eq!(p.params.hdr_off, 0x1D0);
        assert_eq!(p.params.add, Some(0x08F4_E5DB));
        assert!(m.partial.iter().any(|s| s == "params.base"));
    }
}
