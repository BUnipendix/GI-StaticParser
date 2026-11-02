//! Shape-transfer solver — Rust port of `tools/version-triage/shape_transfer.py`
//! (R39 final piece). Carries semantic table seeds (slot/op/imm + stride)
//! from a SOLVED seed version onto a target build by matching
//! constant-stripped instruction-shape fingerprints of the functions that
//! load the header pointer (loadsites.py caches), then re-reading the slot
//! idiom at the same ordinal in the matched target function.
//!
//! All inputs are DATA artifacts (sites JSON / derive JSON / seed JSON);
//! nothing here knows a version. Acceptance stays downstream (rowtable).
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0.

use crate::expr::Expr;
use crate::pe::Image;
use crate::symwalk::reg_canon_bits;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

// ------------------------------------------------------------ input formats
#[derive(Deserialize)]
pub struct SitesFile {
    pub exe: String,
    pub blob_va: u64,
    pub hdr_global: u64,
    pub sites: Vec<SiteFp>,
}

#[derive(Deserialize)]
pub struct SiteFp {
    pub site: u64,
    pub fp: Vec<String>,
}

#[derive(Deserialize)]
pub struct SeedFile {
    pub semantics: BTreeMap<String, SeedSem>,
}

#[derive(Deserialize, Clone)]
pub struct SeedSem {
    pub slot: u32,
    pub op: String,
    pub imm: u64,
    #[serde(default)]
    pub stride: Option<u32>,
}

#[derive(Deserialize)]
pub struct DeriveFile {
    pub anchors: Vec<DeriveAnchor>,
}

#[derive(Deserialize, Clone)]
pub struct DeriveAnchor {
    pub hdr_off: u32,
    pub op: String,
    pub imm: u64,
    pub site: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorOp {
    Add,
    Xor,
    Sub,
}

impl AnchorOp {
    pub fn apply(self, raw: u64, imm: u64) -> u64 {
        match self {
            AnchorOp::Add => raw.wrapping_add(imm),
            AnchorOp::Xor => raw ^ imm,
            AnchorOp::Sub => raw.wrapping_sub(imm),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            AnchorOp::Add => "+",
            AnchorOp::Xor => "^",
            AnchorOp::Sub => "-",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Anchor {
    pub slot: u32,
    pub op: AnchorOp,
    pub imm: u64,
    pub addr: u64,
}

// ------------------------------------------------------------- fingerprint
fn trigrams(fp: &[String]) -> HashSet<(String, String, String)> {
    fp.windows(3)
        .map(|w| (w[0].clone(), w[1].clone(), w[2].clone()))
        .collect()
}

/// Jaccard over trigram sets (Python `match()`).
pub fn jaccard(a: &[String], b: &[String]) -> f64 {
    let ta = trigrams(a);
    let tb = trigrams(b);
    if ta.is_empty() && tb.is_empty() {
        return 0.0;
    }
    let inter = ta.intersection(&tb).count();
    let union = ta.union(&tb).count();
    inter as f64 / union as f64
}

/// Best-matching target site for a seed fingerprint (top-n with scores).
pub fn match_site<'a>(qfp: &[String], sites: &'a [SiteFp], topn: usize) -> Vec<(f64, &'a SiteFp)> {
    let mut best: Vec<(f64, &'a SiteFp)> = sites
        .iter()
        .map(|s| (jaccard(qfp, &s.fp), s))
        .filter(|(j, _)| *j > 0.0)
        .collect();
    best.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.site.cmp(&b.1.site)));
    best.truncate(topn);
    best
}

// ------------------------------------------------------------ anchor scan
/// Recover (slot, op, imm, addr) for the slot idiom inside one load-site
/// window (Python `scan_anchors`): track the header-pointer register from a
/// rip load of hdr_global, then `[hdrptr+disp]` loads become pending slots,
/// combined with add/xor/sub of an immediate (direct or via register).
pub fn scan_anchors(
    img: &Image,
    d: &[u8],
    fn_site: u64,
    hg: u64,
    window: usize,
) -> Vec<Anchor> {
    let mut out = Vec::new();
    let Some(fo) = img.va_to_file(fn_site) else { return out };
    let fo = fo as usize;
    let Some(code) = d.get(fo..(fo + window).min(d.len())) else { return out };
    let mut dec = Decoder::with_ip(64, code, fn_site, DecoderOptions::NONE);
    let mut hregs: HashSet<String> = HashSet::new();
    let mut pending: HashMap<String, (u32, u64)> = HashMap::new();
    let mut immreg: HashMap<String, u64> = HashMap::new();
    while dec.can_decode() {
        let ins = dec.decode();
        let m = ins.mnemonic();
        if matches!(m, Mnemonic::Mov | Mnemonic::Movsxd | Mnemonic::Movzx) && ins.op_count() == 2 {
            if ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Memory {
                let dst = reg_cb(ins.op_register(0));
                let base = ins.memory_base();
                if base == iced_x86::Register::RIP {
                    // iced exposes RIP-relative displacement64 as the
                    // ABSOLUTE target address already
                    let tgt = ins.memory_displacement64();
                    if tgt == hg {
                        hregs.insert(dst);
                    }
                } else if base != iced_x86::Register::None {
                    let bn = reg_cb(base);
                    if hregs.contains(&bn) {
                        let disp = ins.memory_displacement64() as u32;
                        pending.insert(dst, (disp, ins.ip()));
                    }
                }
            } else if ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Register {
                let a = reg_cb(ins.op_register(0));
                let b = reg_cb(ins.op_register(1));
                if a != b {
                    if hregs.contains(&b) {
                        hregs.insert(a.clone());
                    }
                    if let Some(v) = pending.get(&b).cloned() {
                        pending.insert(a.clone(), v);
                    }
                    if let Some(v) = immreg.get(&b).cloned() {
                        immreg.insert(a.clone(), v);
                    }
                }
            } else if ins.op_kind(0) == OpKind::Register && ins.op_kind(1) != OpKind::Memory {
                if let Some(imm) = imm_of(&ins, 1) {
                    immreg.insert(reg_cb(ins.op_register(0)), imm & 0xFFFF_FFFF);
                }
            }
            continue;
        }
        if matches!(m, Mnemonic::Add | Mnemonic::Xor | Mnemonic::Sub) && ins.op_count() == 2 {
            if ins.op_kind(0) != OpKind::Register {
                continue;
            }
            let an = reg_cb(ins.op_register(0));
            let op = match m {
                Mnemonic::Add => AnchorOp::Add,
                Mnemonic::Xor => AnchorOp::Xor,
                _ => AnchorOp::Sub,
            };
            if ins.op_kind(1) == OpKind::Register {
                let bn = reg_cb(ins.op_register(1));
                if let (Some(&(slot, saddr)), Some(&imm)) = (pending.get(&an), immreg.get(&bn)) {
                    if ins.ip() - saddr <= 0x40 {
                        out.push(Anchor { slot, op, imm, addr: ins.ip() });
                    }
                }
            } else if let Some(imm) = imm_of(&ins, 1) {
                if let Some(&(slot, saddr)) = pending.get(&an) {
                    if ins.ip() - saddr <= 0x40 {
                        out.push(Anchor { slot, op, imm: imm & 0xFFFF_FFFF, addr: ins.ip() });
                    }
                    pending.remove(&an);
                }
            }
        }
    }
    out
}

pub fn parse_op(s: &str) -> AnchorOp {
    match s.to_ascii_lowercase().as_str() {
        "add" | "+" => AnchorOp::Add,
        "xor" | "^" => AnchorOp::Xor,
        _ => AnchorOp::Sub,
    }
}

fn reg_cb(r: iced_x86::Register) -> String {
    let n = format!("{:?}", r).to_ascii_lowercase();
    reg_canon_bits(&n).map(|(c, _)| c).unwrap_or(n)
}

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

// --------------------------------------------------------------- transfer
#[derive(Serialize, Clone)]
pub struct TransferRec {
    pub score: f64,
    pub matched_fn: u64,
    pub slot: u32,
    pub op: String,
    pub imm: u64,
    pub resolved: Option<u64>,
    pub stride_expected: Option<u32>,
    pub chains: Vec<Expr>,
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct TransferReport {
    pub target_exe: String,
    pub semantics: BTreeMap<String, TransferRec>,
}

/// Full transfer for one semantic (Python `main()` loop body): locate the
/// seed anchor's function, fingerprint-match into the target, rescan the
/// matched function's slot idiom, pick by size-stride divisibility when the
/// semantic declares one, else by ordinal.
#[allow(clippy::too_many_arguments)]
pub fn transfer_semantic(
    seed_img: &Image,
    seed_d: &[u8],
    tgt_img: &Image,
    tgt_d: &[u8],
    seed: &SeedFile,
    seed_sites: &SitesFile,
    seed_derive: &DeriveFile,
    target_sites: &SitesFile,
    name: &str,
    sem: &SeedSem,
) -> TransferRec {
    // 1) seed anchor from derive (site may be the confirmation site; match by
    //    slot/op/imm like the Python code)
    let anch = seed_derive
        .anchors
        .iter()
        .find(|a| a.hdr_off == sem.slot && a.op.eq_ignore_ascii_case(&sem.op) && a.imm == sem.imm);
    let Some(anch) = anch else {
        return TransferRec {
            score: 0.0,
            matched_fn: 0,
            slot: sem.slot,
            op: sem.op.clone(),
            imm: sem.imm,
            resolved: None,
            stride_expected: sem.stride,
            chains: vec![],
            note: Some("seed anchor not found in derive artifact".into()),
        };
    };
    let a_site = u64::from_str_radix(anch.site.trim_start_matches("0x"), 16).unwrap_or(0);
    let mut seed_fns: Vec<u64> = seed_sites.sites.iter().map(|s| s.site).collect();
    seed_fns.sort_unstable();
    // containing function = greatest load-site <= anchor site
    let fn_idx = seed_fns.partition_point(|&s| s <= a_site).saturating_sub(1);
    let seed_fn = seed_fns[fn_idx];
    let seq = scan_anchors(seed_img, seed_d, seed_fn, seed_sites.hdr_global, 0x700);
    let sem_op = parse_op(&sem.op);
    let ai = seq.iter().position(|a| {
        a.slot == sem.slot && a.op == sem_op && a.imm == sem.imm
    });
    let qfp = seed_sites
        .sites
        .iter()
        .find(|s| s.site == seed_fn)
        .map(|s| s.fp.clone())
        .unwrap_or_default();
    let mut rec = TransferRec {
        score: 0.0,
        matched_fn: 0,
        slot: sem.slot,
        op: sem.op.clone(),
        imm: sem.imm,
        resolved: None,
        stride_expected: sem.stride,
        chains: vec![],
        note: None,
    };
    // 2) match into the target
    let cands = match_site(&qfp, &target_sites.sites, 3);
    let Some(&(score, tfn_site)) = cands.first() else {
        rec.note = Some("no function match".into());
        return rec;
    };
    rec.score = (score * 10000.0).round() / 10000.0;
    rec.matched_fn = tfn_site.site;
    let tseq = scan_anchors(tgt_img, tgt_d, tfn_site.site, target_sites.hdr_global, 0x700);
    // 3) pick: divisibility gate when a size semantic; else same ordinal
    let hdr_slice = tgt_img
        .va_to_file(target_sites.blob_va)
        .and_then(|fo| tgt_d.get(fo as usize..fo as usize + 0x210))
        .unwrap_or(&[]);
    let mut picked: Option<Anchor> = None;
    if let Some(stride) = sem.stride {
        let mut passing: Vec<Anchor> = tseq
            .iter()
            .cloned()
            .filter(|a| {
                if (a.slot as usize) + 4 > hdr_slice.len() {
                    return false;
                }
                let raw = u32::from_le_bytes(
                    hdr_slice[a.slot as usize..a.slot as usize + 4].try_into().unwrap(),
                ) as u64;
                let v = a.op.apply(raw, a.imm) & 0xFFFF_FFFF;
                v != 0 && v % stride as u64 == 0
            })
            .collect();
        passing.sort_by_key(|a| a.addr);
        if passing.len() == 1 {
            picked = Some(passing.remove(0));
        }
    }
    if picked.is_none() {
        if let Some(ai) = ai {
            if ai < tseq.len() {
                picked = Some(tseq[ai]);
            }
        }
    }
    let Some(a) = picked else {
        rec.note = Some("no candidate anchor in the matched function".into());
        return rec;
    };
    rec.slot = a.slot;
    rec.op = a.op.name().to_string();
    rec.imm = a.imm;
    if (a.slot as usize) + 4 <= hdr_slice.len() {
        let raw = u32::from_le_bytes(hdr_slice[a.slot as usize..a.slot as usize + 4].try_into().unwrap()) as u64;
        rec.resolved = Some(a.op.apply(raw, a.imm) & 0xFFFF_FFFF);
    }
    rec
}
