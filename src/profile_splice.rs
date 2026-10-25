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
use crate::rowtable::TableReport;
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
    derived: Option<&BuildDerivation>,
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
            m.notes.push(format!("{name}: WEAK match score {:.3} — treat base as unverified", rec.score));
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
            "field_names" => p.field_names = tb,
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
        _ => m.notes.push("method table not solved; md_* columns stay seed data".into()),
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
        let (p, m) = splice_profile(seed_profile(), &report, None, None);
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
        let (p, m) = splice_profile(seed_profile(), &report, Some(&rep), None);

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
        let (p, m) = splice_profile(seed_profile(), &report, None, None);
        assert_eq!(p.field_names.hdr_off, 0xDC);
        assert_eq!(p.field_names.add, Some(0xE5D3_E43F));
        assert!(m.partial.iter().any(|s| s == "field_names.base"));
        assert!(m.notes.iter().any(|n| n.contains("generic_params")));
        // weak type_defs match: still spliced, but flagged
        assert!(m.notes.iter().any(|n| n.contains("type_defs") && n.contains("WEAK")));
        // symbol-form op must keep its imm (the 6.6 live-run regression)
        assert_eq!(p.params.hdr_off, 0x1D0);
        assert_eq!(p.params.add, Some(0x08F4_E5DB));
        assert!(m.partial.iter().any(|s| s == "params.base"));
    }
}
