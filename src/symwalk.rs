//! Symbolic dataflow walker over metadata builder functions — Rust port of
//! `tools/version-triage/symwalk.py` (R39, step 3; iced-x86 decoder, Expr
//! interchange from `expr.rs`).
//!
//! Given a `hdr[slot] op imm` anchor site inside a function that reads a
//! metadata row table, walk a window of instructions symbolically and emit:
//!
//! * anchors  — every (slot, op, imm) applied to a header-pointer load
//! * chains   — pure single-unknown expressions (per-row mask chains and
//!   derivations like mask2 = mask * K)
//! * columns  — row-relative loads combined with constants/chains
//!
//! Constants are data: nothing here knows a version. Acceptance is decided
//! downstream (rowtable/heap validators). Behavior parity with the Python
//! prototype is gated by `symwalk_regression` (11 known anchor sites).
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0.

use crate::expr::{expr_has, expr_size, expr_syms_set, fold, lin_terms, BinOp, Expr};
use crate::pe::Image;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Serialize, Debug, Clone)]
pub struct AnchorRec {
    pub slot: u32,
    pub op: String,
    pub imm: u64,
    pub addr: u64,
    pub resolved: Option<u64>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ChainRec {
    pub addr: u64,
    pub expr: Expr,
}

#[derive(Serialize, Debug, Clone)]
pub struct ColRec {
    pub off: u32,
    pub width: u32,
    pub addr: u64,
    pub sink: Option<String>,
    pub expr: Expr,
}

#[derive(Serialize)]
pub struct SymwalkReport {
    pub exe: String,
    pub site: u64,
    pub back: usize,
    pub anchors: Vec<AnchorRec>,
    pub chains: Vec<ChainRec>,
    pub columns: Vec<ColRec>,
}

// ------------------------------------------------------------- register map
pub fn reg_canon_bits(name: &str) -> Option<(String, u32)> {
    reg_info(name)
}

fn reg_name(r: Register) -> String {
    format!("{:?}", r)
}

fn reg_info(name: &str) -> Option<(String, u32)> {
    // returns (canonical 64-bit lowercase, bit width)
    let n = name.to_ascii_lowercase();
    let canon64 = |b: &str| Some((b.to_string(), 64u32));
    let s = n.as_str();
    Some(match s {
        "rax" | "eax" | "ax" | "al" => canon64("rax")?,
        "rcx" | "ecx" | "cx" | "cl" => canon64("rcx")?,
        "rdx" | "edx" | "dx" | "dl" => canon64("rdx")?,
        "rbx" | "ebx" | "bx" | "bl" => canon64("rbx")?,
        "rsp" | "esp" | "sp" | "spl" => canon64("rsp")?,
        "rbp" | "ebp" | "bp" | "bpl" => canon64("rbp")?,
        "rsi" | "esi" | "si" | "sil" => canon64("rsi")?,
        "rdi" | "edi" | "di" | "dil" => canon64("rdi")?,
        "rip" | "eip" => ("rip".to_string(), 64),
        _ => {
            if let Some(rest) = s.strip_prefix('r') {
                // optional width suffix; a bare rN (N in 8..=15) is 64-bit
                let (digits, bits) = match rest.chars().last() {
                    Some('d') if rest.len() > 1 => (&rest[..rest.len() - 1], 32u32),
                    Some('w') if rest.len() > 1 => (&rest[..rest.len() - 1], 16),
                    Some('b') if rest.len() > 1 => (&rest[..rest.len() - 1], 8),
                    _ => (rest, 64),
                };
                if let Ok(idx) = digits.parse::<u32>() {
                    if (8..=15).contains(&idx) {
                        return Some((format!("r{}", idx), bits));
                    }
                }
            }
            return None;
        }
    });
    // adjust widths for the low-register spellings above
    let bits = match s {
        "eax" | "ecx" | "edx" | "ebx" | "esp" | "ebp" | "esi" | "edi" | "eip" => 32,
        "ax" | "cx" | "dx" | "bx" | "sp" | "bp" | "si" | "di" => 16,
        "al" | "cl" | "dl" | "bl" | "sil" | "dil" | "spl" | "bpl" => 8,
        _ => return Some((n, 64)),
    };
    let (c, _) = reg_info(
        match s {
            "eax" => "rax", "ecx" => "rcx", "edx" => "rdx", "ebx" => "rbx",
            "esp" => "rsp", "ebp" => "rbp", "esi" => "rsi", "edi" => "rdi",
            "eip" => "rip",
            "ax" => "rax", "cx" => "rcx", "dx" => "rdx", "bx" => "rbx",
            "sp" => "rsp", "bp" => "rbp", "si" => "rsi", "di" => "rdi",
            "al" => "rax", "cl" => "rcx", "dl" => "rdx", "bl" => "rbx",
            "sil" => "rsi", "dil" => "rdi", "spl" => "rsp", "bpl" => "rbp",
            _ => s,
        },
    )?;
    Some((c, bits))
}

// ------------------------------------------------------------------- values
#[derive(Debug, Clone, Default)]
pub struct RowMark {
    pub coeffs: BTreeMap<String, u64>,
    pub cst: u64,
}

#[derive(Debug, Clone)]
pub struct Val {
    pub e: Expr,
    pub row: Option<RowMark>,
}

impl Val {
    fn new(e: Expr) -> Self {
        Val { e, row: None }
    }
}

/// Windows x64 ABI: only rax/rcx/rdx/r8-r11 are caller-saved (rsi/rdi are
/// CALLEE-saved here, unlike SysV — clearing them after calls loses row markers).
const CALLER_SAVED: [&str; 7] = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

fn bad_sym(n: &str) -> bool {
    n == "mem"
        || n == "post_call"
        || n.starts_with("glob@")
        || n.starts_with("mulhi@")
        || n.starts_with("ripdata")
}

fn has_bigmul(e: &Expr) -> bool {
    if let Expr::Op2(BinOp::Mul, _, b) = e {
        if let Expr::Imm(v) = b.as_ref() {
            if *v > 0xFFFF {
                return true;
            }
        }
    }
    match e {
        Expr::Op2(_, a, b) => has_bigmul(a) || has_bigmul(b),
        Expr::Lo(_, a) | Expr::Ext(_, a, _) => has_bigmul(a),
        _ => false,
    }
}

// ------------------------------------------------------------------- walker
pub struct Walker<'a> {
    img: &'a Image<'a>,
    d: &'a [u8],
    pub blob_va: u64,
    hdr_global: Option<u64>,
    hdr_copy: Vec<u8>,

    regs: HashMap<String, Val>,
    stack: HashMap<u64, Val>,
    hdr_ptrs: HashSet<String>,
    pub anchors: Vec<AnchorRec>,
    pub chains: BTreeMap<String, ChainRec>,
    pub columns: BTreeMap<(u32, String), ColRec>,
    sym_last: HashMap<String, Expr>,
}

impl<'a> Walker<'a> {
    pub fn new(img: &'a Image<'a>, d: &'a [u8], blob_va: u64, hdr_global: Option<u64>) -> Self {
        let hdr_copy = img
            .va_to_file(blob_va)
            .and_then(|fo| {
                let fo = fo as usize;
                d.get(fo..fo + 0x210).map(|s| s.to_vec())
            })
            .unwrap_or_default();
        Walker {
            img,
            d,
            blob_va,
            hdr_global,
            hdr_copy,
            regs: HashMap::new(),
            stack: HashMap::new(),
            hdr_ptrs: HashSet::new(),
            anchors: Vec::new(),
            chains: BTreeMap::new(),
            columns: BTreeMap::new(),
            sym_last: HashMap::new(),
        }
    }

    fn get(&mut self, canon: &str) -> Val {
        if !self.regs.contains_key(canon) {
            self.regs.insert(canon.to_string(), Val::new(Expr::Sym(canon.to_string())));
        }
        self.regs.get(canon).cloned().unwrap()
    }

    /// Read by written name: sub-register reads wrap lo(bits).
    fn get_named(&mut self, name: &str) -> Val {
        let (canon, bits) = reg_info(name).unwrap_or((name.to_string(), 64));
        let v = self.get(&canon);
        if bits < 64 {
            Val::new(fold(&Expr::Lo(bits, Box::new(v.e))))
        } else {
            v
        }
    }

    fn set(&mut self, canon: &str, val: Val) {
        // Runaway guard: symbolic propagation through long register lifetimes
        // grows expression trees without bound (a chain-hunt walk allocated
        // gigabytes before this cap). Past the cap the value becomes an
        // opaque symbol — the register is untrackable, which is fine for the
        // hunt (real mask chains never grow that large).
        let val = if expr_size(&val.e) > 4096 {
            Val { e: Expr::Sym(format!("RUNAWAY_{canon}")), row: val.row }
        } else {
            val
        };
        let e = val.e.clone();
        let mut syms = BTreeSet::new();
        crate::expr::expr_syms(&e, &mut syms);
        if syms.len() == 1
            && !expr_has(&e, false)
            && !expr_has(&e, true)
            && expr_size(&e) >= 3
            && syms.iter().all(|s| !bad_sym(s))
        {
            self.sym_last.insert(canon.to_string(), e.clone());
        }
        self.regs.insert(canon.to_string(), val);
    }

    fn record_chain(&mut self, addr: u64, e: &Expr) {
        let mut cand = e.clone();
        if expr_syms_set(&cand).len() == 2 {
            // base+counter row index: collapse the single Add(Sym, Sym) node
            // into `i` so the chain becomes pure for the row solver
            if let Some(c) = crate::expr::collapse_index_sum(&cand) {
                cand = c;
            }
        }
        let syms = expr_syms_set(&cand);
        if syms.len() == 1
            && !expr_has(&cand, false)
            && !expr_has(&cand, true)
            && expr_size(&cand) >= 3
            && syms.iter().all(|s| !bad_sym(s))
        {
            let key = format!("{}", cand);
            self.chains.entry(key).or_insert(ChainRec { addr, expr: cand });
        }
    }

    fn record_column(&mut self, addr: u64, e: &Expr, sink: Option<String>) {
        if !expr_has(e, false) {
            return;
        }
        let mut raws = Vec::new();
        collect_raws(e, &mut raws);
        if raws.len() > 2 || raws.first().map(|r| r.0).unwrap_or(0x1000) >= 0x100 {
            return;
        }
        let key = (raws[0].0, format!("{}", e));
        let width = raws[0].1 / 8;
        match self.columns.get(&key) {
            Some(existing) if existing.sink.is_some() || sink.is_none() => {}
            _ => {
                self.columns.insert(
                    key,
                    ColRec {
                        off: raws[0].0,
                        width,
                        addr,
                        sink,
                        expr: e.clone(),
                    },
                );
            }
        }
    }

    // ------------------------------------------------------------- memory
    fn try_row(&self, a: &Val, b: &Val, sign: i64) -> Option<Val> {
        // existing marker + linear addend -> merged
        for (x, y) in [(a, b), (b, a)] {
            if let Some(row) = &x.row {
                if let Some((ly, lc)) = lin_terms(&y.e) {
                    if !ly.is_empty() || lc != 0 {
                        let mut coeffs = row.coeffs.clone();
                        for (s, c) in &ly {
                            let nc = coeffs
                                .get(s)
                                .copied()
                                .unwrap_or(0)
                                .wrapping_add(((*c as i64) * sign) as u64);
                            coeffs.insert(s.clone(), nc);
                        }
                        let cst = row
                            .cst
                            .wrapping_add(((lc as i64) * sign) as u64);
                        let op = if sign > 0 { BinOp::Add } else { BinOp::Sub };
                        let e = fold(&Expr::Op2(
                            op,
                            Box::new(x.e.clone()),
                            Box::new(y.e.clone()),
                        ));
                        return Some(Val { e, row: Some(RowMark { coeffs, cst }) });
                    }
                }
            }
        }
        // base (contains hdr, no raw) + linear addend with symbols
        for (x, y) in [(a, b), (b, a)] {
            if expr_has(&x.e, true) && !expr_has(&x.e, false) {
                if let Some((ly, lc)) = lin_terms(&y.e) {
                    if ly.is_empty() {
                        continue;
                    }
                    let lx = lin_terms(&x.e);
                    let mut coeffs: BTreeMap<String, u64> = BTreeMap::new();
                    let mut cst = 0u64;
                    if let Some((lxm, lxc)) = &lx {
                        for (s, c) in lxm {
                            coeffs.insert(s.clone(), *c);
                        }
                        cst = *lxc;
                        for (s, c) in &ly {
                            let nc = coeffs
                                .get(s)
                                .copied()
                                .unwrap_or(0)
                                .wrapping_add(((*c as i64) * sign) as u64);
                            coeffs.insert(s.clone(), nc);
                        }
                        cst = cst.wrapping_add(((lc as i64) * sign) as u64);
                    } else {
                        for (s, c) in &ly {
                            coeffs.insert(s.clone(), ((*c as i64) * sign) as u64);
                        }
                        cst = ((lc as i64) * sign) as u64;
                    }
                    if coeffs.is_empty() {
                        continue;
                    }
                    let op = if sign > 0 { BinOp::Add } else { BinOp::Sub };
                    let e = fold(&Expr::Op2(
                        op,
                        Box::new(x.e.clone()),
                        Box::new(y.e.clone()),
                    ));
                    return Some(Val { e, row: Some(RowMark { coeffs, cst }) });
                }
            }
        }
        None
    }

    fn add_addr(a: &Val, b: &Val) -> Val {
        // row marker + const, or plain fold
        if let Some(row) = &a.row {
            if let Expr::Imm(k) = &b.e {
                let mut r = row.clone();
                r.cst = r.cst.wrapping_add(*k);
                let e = fold(&Expr::Op2(
                    BinOp::Add,
                    Box::new(a.e.clone()),
                    Box::new(b.e.clone()),
                ));
                return Val { e, row: Some(r) };
            }
        }
        if let Some(row) = &b.row {
            if let Expr::Imm(k) = &a.e {
                let mut r = row.clone();
                r.cst = r.cst.wrapping_add(*k);
                let e = fold(&Expr::Op2(
                    BinOp::Add,
                    Box::new(a.e.clone()),
                    Box::new(b.e.clone()),
                ));
                return Val { e, row: Some(r) };
            }
        }
        let e = fold(&Expr::Op2(
            BinOp::Add,
            Box::new(a.e.clone()),
            Box::new(b.e.clone()),
        ));
        Val {
            e,
            row: a.row.clone().or(b.row.clone()),
        }
    }

    fn mem_operand_val(&mut self, ins: &Instruction) -> Val {
        let base = ins.memory_base();
        let index = ins.memory_index();
        let scale = ins.memory_index_scale() as u64;
        let disp = ins.memory_displacement64() as u64;
        let mut acc: Option<Val> = None;
        if base != Register::None {
            let bn = reg_name(base);
            let (canon, _) = reg_info(&bn).unwrap_or((bn.to_lowercase(), 64));
            acc = Some(self.get(&canon));
        }
        if index != Register::None {
            let iname = reg_name(index);
            let (canon, _) = reg_info(&iname).unwrap_or((iname.to_lowercase(), 64));
            let iv = self.get(&canon);
            let scaled = Val::new(fold(&Expr::Op2(
                BinOp::Mul,
                Box::new(iv.e),
                Box::new(Expr::Imm(scale)),
            )));
            acc = Some(match acc {
                None => scaled,
                Some(a) => self
                    .try_row(&a, &scaled, 1)
                    .unwrap_or_else(|| Self::add_addr(&a, &scaled)),
            });
        }
        let dv = Val::new(Expr::Imm(disp));
        match acc {
            None => dv,
            Some(a) => self.try_row(&a, &dv, 1).unwrap_or_else(|| Self::add_addr(&a, &dv)),
        }
    }

    /// rip-relative operand: pointer loads from known globals resolve to the
    /// HDRPTR symbol; smaller reads become immediates.
    fn rip_val(&self, ins: &Instruction) -> Option<Val> {
        if ins.memory_base() != Register::RIP {
            return None;
        }
        let target = ins.next_ip() + ins.memory_displacement64() as u64;
        let fo = self.img.va_to_file(target)? as usize;
        let size = (ins.memory_size().size()) as usize;
        if size == 8 {
            if fo + 8 <= self.d.len() {
                let q = u64::from_le_bytes(self.d[fo..fo + 8].try_into().ok()?);
                if Some(q) == self.hdr_global || q == self.blob_va {
                    return Some(Val::new(Expr::Sym("HDRPTR".into())));
                }
                return Some(Val::new(Expr::Sym(format!("glob@{:x}", q))));
            }
            return Some(Val::new(Expr::Sym("ripdata".into())));
        }
        if fo + size <= self.d.len() {
            let mut b = [0u8; 8];
            b[..size].copy_from_slice(&self.d[fo..fo + size]);
            return Some(Val::new(Expr::Imm(u64::from_le_bytes(b))));
        }
        Some(Val::new(Expr::Sym("ripdata".into())))
    }

    fn hdr_slot_in(&mut self, e: &Expr) -> Option<u32> {
        match e {
            Expr::Sym(n) if n == "HDRPTR" || self.hdr_ptrs.contains(n) => Some(0),
            Expr::Op2(BinOp::Add, a, b) => {
                for (x, y) in [(a, b), (b, a)] {
                    if let Expr::Sym(n) = x.as_ref() {
                        if (n == "HDRPTR" || self.hdr_ptrs.contains(n))
                            && matches!(y.as_ref(), Expr::Imm(_))
                        {
                            if let Expr::Imm(v) = y.as_ref() {
                                if *v < 0x210 {
                                    self.hdr_ptrs.insert(n.clone());
                                    return Some(*v as u32);
                                }
                            }
                        }
                    }
                    // lazy promotion (Python parity): lone non-stack sym +
                    // small aligned disp is provisionally the header pointer;
                    // misidentifications are rejected by downstream validators
                    if let Expr::Sym(n) = x.as_ref() {
                        if n != "rsp" && n != "post_call" && n != "mem" {
                            if let Expr::Imm(v) = y.as_ref() {
                                if *v < 0x210 && *v % 4 == 0 {
                                    self.hdr_ptrs.insert(n.clone());
                                    return Some(*v as u32);
                                }
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn read_mem(&mut self, addr: &Val, width: u32, signed: bool) -> Option<Val> {
        if let Some(slot) = self.hdr_slot_in(&addr.e) {
            let mut v = Expr::Hdr(slot, 4);
            if signed && width < 8 {
                v = fold(&Expr::Ext(width * 8, Box::new(v), true));
            }
            return Some(Val::new(v));
        }
        if let Some(row) = &addr.row {
            let off = (row.cst & 0xFFFF_FFFF) as u32;
            let mut raw = Expr::Raw(off, width * 8);
            if signed && width < 8 {
                raw = fold(&Expr::Ext(width * 8, Box::new(raw), true));
            }
            return Some(Val::new(raw));
        }
        // stack slot?
        if let Expr::Op2(BinOp::Add, a, b) = &addr.e {
            if let (Expr::Sym(n), Expr::Imm(disp)) = (a.as_ref(), b.as_ref()) {
                if n == "rsp" {
                    return self.stack.get(disp).cloned();
                }
            }
        }
        None
    }

    // ------------------------------------------------------------ stepping
    fn apply_op2(&mut self, addr: u64, canon: &str, a: &Val, op: BinOp, b: &Val, width: u32) {
        // anchor: hdr op imm
        if let (Some(slot), Expr::Imm(imm)) = (unwrap_hdr(&a.e), &b.e) {
            if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Xor) {
                let resolved = self
                    .hdr_copy
                    .get(slot as usize..slot as usize + 4)
                    .map(|s| {
                        let raw = u32::from_le_bytes(s.try_into().unwrap()) as u64;
                        match op {
                            BinOp::Add => raw.wrapping_add(*imm),
                            BinOp::Sub => raw.wrapping_sub(*imm),
                            _ => raw ^ *imm,
                        }
                    });
                self.anchors.push(AnchorRec {
                    slot,
                    op: binop_str(op).to_string(),
                    imm: *imm,
                    addr,
                    resolved,
                });
            }
        }
        let mut e = fold(&Expr::Op2(op, Box::new(a.e.clone()), Box::new(b.e.clone())));
        if width < 64 {
            e = fold(&Expr::Lo(width, Box::new(e)));
        }
        let v = Val { e: e.clone(), row: None };
        self.set(canon, v);
        if expr_has(&e, false) {
            self.record_column(addr, &e, None);
        } else {
            self.record_chain(addr, &e);
        }
    }

    fn write_reg(&mut self, addr: u64, name: &str, val: Val) {
        let Some((canon, bits)) = reg_info(name) else { return };
        let mut e = val.e;
        if bits < 64 {
            e = fold(&Expr::Lo(bits, Box::new(e)));
        }
        let v = Val { e: e.clone(), row: val.row };
        self.set(&canon, v);
        if expr_has(&e, false) {
            self.record_column(addr, &e, None);
        } else {
            self.record_chain(addr, &e);
        }
    }

    fn write_mem(&mut self, addr: u64, addr_val: &Val, val: &Val) {
        if let Expr::Op2(BinOp::Add, a, b) = &addr_val.e {
            if let (Expr::Sym(n), Expr::Imm(disp)) = (a.as_ref(), b.as_ref()) {
                if n == "rsp" {
                    self.stack.insert(*disp, val.clone());
                    return;
                }
            }
        }
        // non-stack stores are not tracked further (columns recorded on use)
        let _ = addr;
    }

    pub fn step(&mut self, ins: &Instruction) {
        let addr = ins.ip();
        let m = ins.mnemonic();
        match m {
            Mnemonic::Mov => {
                if ins.op_count() != 2 {
                    return;
                }
                let dst_name = reg_name(ins.op_register(0));
                match ins.op_kind(1) {
                    OpKind::Register => {
                        let src = self.get_named(&reg_name(ins.op_register(1)));
                        self.write_reg(addr, &dst_name, src);
                    }
                    OpKind::Memory => {
                        if let Some(v) = self.rip_val(ins) {
                            self.write_reg(addr, &dst_name, v);
                            return;
                        }
                        let av = self.mem_operand_val(ins);
                        let (_, bits) = reg_info(&dst_name).unwrap_or((dst_name.clone(), 64));
                        let width = bits / 8;
                        match self.read_mem(&av, width, false) {
                            Some(v) => self.write_reg(addr, &dst_name, v),
                            None => {
                                self.write_reg(addr, &dst_name, Val::new(Expr::Sym("mem".into())))
                            }
                        }
                    }
                    _ => {
                        if let Some(imm) = imm_of(ins, 1) {
                            self.write_reg(addr, &dst_name, Val::new(Expr::Imm(imm)));
                        }
                    }
                }
            }
            Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
                if ins.op_count() != 2 {
                    return;
                }
                let dst_name = reg_name(ins.op_register(0));
                let srcbits: u32 = match ins.op_kind(1) {
                    OpKind::Register => reg_info(&reg_name(ins.op_register(1)))
                        .map(|(_, b)| b)
                        .unwrap_or(64),
                    OpKind::Memory => ins.memory_size().size() as u32 * 8,
                    _ => return,
                };
                let sv = match ins.op_kind(1) {
                    OpKind::Register => self.get_named(&reg_name(ins.op_register(1))),
                    OpKind::Memory => {
                        if let Some(v) = self.rip_val(ins) {
                            v
                        } else {
                            let av = self.mem_operand_val(ins);
                            self.read_mem(&av, srcbits / 8, false)
                                .unwrap_or_else(|| Val::new(Expr::Sym("mem".into())))
                        }
                    }
                    _ => return,
                };
                let e = if m == Mnemonic::Movzx {
                    fold(&Expr::Lo(srcbits, Box::new(sv.e)))
                } else {
                    fold(&Expr::Ext(srcbits, Box::new(sv.e), true))
                };
                self.write_reg(addr, &dst_name, Val::new(e));
            }
            Mnemonic::Lea => {
                if ins.op_count() != 2 || ins.op_kind(1) != OpKind::Memory {
                    return;
                }
                let dst_name = reg_name(ins.op_register(0));
                let v = self
                    .rip_val(ins)
                    .unwrap_or_else(|| self.mem_operand_val(ins));
                self.write_reg(addr, &dst_name, v);
            }
            Mnemonic::Add | Mnemonic::Sub | Mnemonic::Xor | Mnemonic::And | Mnemonic::Or
            | Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar => {
                if ins.op_count() != 2 || ins.op_kind(0) != OpKind::Register {
                    return;
                }
                let dname = reg_name(ins.op_register(0));
                let (canon, bits) = reg_info(&dname).unwrap_or((dname.clone(), 64));
                let a = self.get_named(&dname);
                let op = match m {
                    Mnemonic::Add => BinOp::Add,
                    Mnemonic::Sub => BinOp::Sub,
                    Mnemonic::Xor => BinOp::Xor,
                    Mnemonic::And => BinOp::And,
                    Mnemonic::Or => BinOp::Or,
                    Mnemonic::Shl => BinOp::Shl,
                    _ => BinOp::Shr, // sar approximated as shr (flagged in docs)
                };
                let b = match ins.op_kind(1) {
                    OpKind::Register => self.get_named(&reg_name(ins.op_register(1))),
                    _ => match imm_of(ins, 1) {
                        Some(i) => Val::new(Expr::Imm(i)),
                        None => return,
                    },
                };
                if matches!(m, Mnemonic::Add | Mnemonic::Sub) {
                    let sign = if m == Mnemonic::Add { 1i64 } else { -1i64 };
                    if sign > 0 {
                        if let Some(mk) = self.try_row(&a, &b, 1) {
                            let mut e = mk.e.clone();
                            if bits < 64 {
                                e = fold(&Expr::Lo(bits, Box::new(e)));
                            }
                            let v = Val { e: e.clone(), row: mk.row };
                            self.set(&canon, v);
                            self.record_chain(addr, &e);
                            return;
                        }
                    } else if let Some(row) = &a.row {
                        if let Expr::Imm(k) = &b.e {
                            let mut r = row.clone();
                            r.cst = r.cst.wrapping_sub(*k);
                            let mut e = fold(&Expr::Op2(
                                BinOp::Sub,
                                Box::new(a.e.clone()),
                                Box::new(b.e.clone()),
                            ));
                            if bits < 64 {
                                e = fold(&Expr::Lo(bits, Box::new(e)));
                            }
                            let v = Val { e: e.clone(), row: Some(r) };
                            self.set(&canon, v);
                            return;
                        }
                    }
                }
                self.apply_op2(addr, &canon, &a, op, &b, bits);
            }
            Mnemonic::Imul => {
                if ins.op_count() == 3 {
                    let dst = reg_name(ins.op_register(0));
                    let (canon, bits) = reg_info(&dst).unwrap_or((dst.clone(), 64));
                    let a = operand_val(self, ins, 1);
                    let b = match ins.op_kind(2) {
                        OpKind::Register => operand_val(self, ins, 2),
                        _ => match imm_of(ins, 2) {
                            Some(i) => Val::new(Expr::Imm(i)),
                            None => return,
                        },
                    };
                    self.apply_op2(addr, &canon, &a, BinOp::Mul, &b, bits);
                } else if ins.op_count() == 2 {
                    let dst = reg_name(ins.op_register(0));
                    let (canon, bits) = reg_info(&dst).unwrap_or((dst.clone(), 64));
                    let a = self.get_named(&dst);
                    let b = operand_val(self, ins, 1);
                    self.apply_op2(addr, &canon, &a, BinOp::Mul, &b, bits);
                }
            }
            Mnemonic::Mul => {
                let a = self.get("rax");
                let b = operand_val(self, ins, 0);
                let prod = fold(&Expr::Op2(
                    BinOp::Mul,
                    Box::new(a.e),
                    Box::new(b.e),
                ));
                self.set("rax", Val::new(prod));
                self.set(
                    "rdx",
                    Val::new(Expr::Sym(format!("mulhi@{:x}", addr))),
                );
            }
            Mnemonic::Neg => {
                let d = reg_name(ins.op_register(0));
                let (canon, bits) = reg_info(&d).unwrap_or((d.clone(), 64));
                let a = self.get_named(&d);
                let z = Val::new(Expr::Imm(0));
                self.apply_op2(addr, &canon, &z, BinOp::Sub, &a, bits);
            }
            Mnemonic::Not => {
                let d = reg_name(ins.op_register(0));
                let (canon, bits) = reg_info(&d).unwrap_or((d.clone(), 64));
                let a = self.get_named(&d);
                let all = Val::new(Expr::Imm(!0u64));
                self.apply_op2(addr, &canon, &a, BinOp::Xor, &all, bits);
            }
            Mnemonic::Cdq | Mnemonic::Cqo => {}
            Mnemonic::Cdqe => {
                let a = self.get_named("eax");
                let e = fold(&Expr::Ext(32, Box::new(a.e), true));
                self.write_reg(addr, "rax", Val::new(e));
            }
            Mnemonic::Push => {
                if ins.op_count() >= 1 && ins.op_kind(0) == OpKind::Register {
                    let v = self.get_named(&reg_name(ins.op_register(0)));
                    self.stack.insert(u64::MAX - self.stack.len() as u64, v);
                }
            }
            Mnemonic::Pop => {}
            Mnemonic::Call => {
                let tgt = match ins.op_kind(0) {
                    OpKind::NearBranch64 => Some(ins.near_branch_target()),
                    _ => None,
                };
                // record column exprs passed as args
                for r in ["rcx", "rdx", "r8", "r9"] {
                    if let Some(v) = self.regs.get(r).cloned() {
                        if expr_has(&v.e, false) {
                            self.record_column(
                                addr,
                                &v.e,
                                Some(format!("call:{:x}", tgt.unwrap_or(0))),
                            );
                            self.record_chain(addr, &v.e);
                        }
                    }
                }
                for r in CALLER_SAVED {
                    self.regs.remove(r);
                    self.sym_last.remove(r);
                }
            }
            _ => {}
        }
    }

    /// Back-substitute bare register syms by their last chain value in column
    /// formulas (Python `finalize`).
    pub fn finalize(&mut self) {
        let keys: Vec<(u32, String)> = self.columns.keys().cloned().collect();
        for key in keys {
            let Some(rec) = self.columns.get(&key).cloned() else { continue };
            let sub = substitute(&rec.expr, &self.sym_last, 0);
            if format!("{}", &sub) != format!("{}", &rec.expr) {
                let e = fold(&sub);
                let mut raws = Vec::new();
                collect_raws(&e, &mut raws);
                if raws.len() <= 2 && raws.first().map(|r| r.0).unwrap_or(0x1000) < 0x100 {
                    let nkey = (raws[0].0, format!("{}", e));
                    self.columns.remove(&key);
                    self.columns.entry(nkey).or_insert(ColRec {
                        off: raws[0].0,
                        width: raws[0].1 / 8,
                        addr: rec.addr,
                        sink: rec.sink,
                        expr: e,
                    });
                } else {
                    self.columns.remove(&key);
                }
            }
        }
    }

    fn quality(&self) -> i64 {
        let good = self
            .anchors
            .iter()
            .filter(|a| a.resolved.map(|r| r & 0xFFFF_FFFF < (1 << 26)).unwrap_or(false))
            .count() as i64;
        let big = self
            .chains
            .values()
            .filter(|c| has_bigmul(&c.expr))
            .count() as i64;
        2 * self.columns.len() as i64 + good + 2 * big
    }
}

fn operand_val(w: &mut Walker, ins: &Instruction, i: usize) -> Val {
    match ins.op_kind(i as u32) {
        OpKind::Register => w.get_named(&reg_name(ins.op_register(i as u32))),
        OpKind::Memory => {
            if let Some(v) = w.rip_val_public(ins) {
                return v;
            }
            let av = w.mem_operand_val_public(ins);
            let width = ins.memory_size().size() as u32;
            w.read_mem_public(&av, width, false)
                .unwrap_or_else(|| Val::new(Expr::Sym("mem".into())))
        }
        _ => match imm_of(ins, i as usize) {
            Some(i) => Val::new(Expr::Imm(i)),
            None => Val::new(Expr::Sym("mem".into())),
        },
    }
}

impl<'a> Walker<'a> {
    pub fn rip_val_public(&self, ins: &Instruction) -> Option<Val> {
        self.rip_val(ins)
    }
    pub fn mem_operand_val_public(&mut self, ins: &Instruction) -> Val {
        self.mem_operand_val(ins)
    }
    pub fn read_mem_public(&mut self, addr: &Val, width: u32, signed: bool) -> Option<Val> {
        self.read_mem(addr, width, signed)
    }
}

fn substitute(e: &Expr, last: &HashMap<String, Expr>, depth: u32) -> Expr {
    if depth > 2 {
        return e.clone();
    }
    match e {
        Expr::Sym(n) => last.get(n).cloned().unwrap_or_else(|| e.clone()),
        Expr::Op2(op, a, b) => Expr::Op2(
            *op,
            Box::new(substitute(a, last, depth + 1)),
            Box::new(substitute(b, last, depth + 1)),
        ),
        Expr::Lo(n, a) => Expr::Lo(*n, Box::new(substitute(a, last, depth + 1))),
        Expr::Ext(n, a, s) => Expr::Ext(*n, Box::new(substitute(a, last, depth + 1)), *s),
        _ => e.clone(),
    }
}

fn collect_raws(e: &Expr, out: &mut Vec<(u32, u32)>) {
    match e {
        Expr::Raw(off, w) => out.push((*off, *w)),
        Expr::Op2(_, a, b) => {
            collect_raws(a, out);
            collect_raws(b, out);
        }
        Expr::Lo(_, a) | Expr::Ext(_, a, _) => collect_raws(a, out),
        _ => {}
    }
}

fn unwrap_hdr(e: &Expr) -> Option<u32> {
    let mut e = e;
    loop {
        match e {
            Expr::Hdr(s, _) => return Some(*s),
            Expr::Lo(_, a) | Expr::Ext(_, a, _) => e = a,
            _ => return None,
        }
    }
}

fn binop_str(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Xor => "^",
        BinOp::And => "&",
        BinOp::Or => "|",
        BinOp::Shr => ">>",
        BinOp::Shl => "<<",
    }
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

/// Walk one window (stops at int3). Returns instruction count.
pub fn walk_window(w: &mut Walker, start: u64, win: usize, cap: usize) -> usize {
    let Some(fo) = w.img.va_to_file(start) else { return 0 };
    let fo = fo as usize;
    let Some(bytes) = w.d.get(fo..(fo + win).min(w.d.len())) else { return 0 };
    let mut dec = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut n = 0;
    while dec.can_decode() && n < cap {
        let ins = dec.decode();
        if ins.mnemonic() == Mnemonic::Int3 {
            break;
        }
        w.step(&ins);
        n += 1;
    }
    n
}

/// Multi-start back-scan, merge top-3 by quality (Python parity).
pub fn symwalk(
    img: &Image,
    d: &[u8],
    blob_va: u64,
    hdr_global: Option<u64>,
    site: u64,
    back: usize,
    win: usize,
) -> (SymwalkReport, usize) {
    let mut walks: Vec<(usize, Walker)> = Vec::new();
    for b in 0..=back {
        let mut w = Walker::new(img, d, blob_va, hdr_global);
        let n = walk_window(&mut w, site - b as u64, win, 20_000);
        if n >= 8 {
            walks.push((b, w));
        }
    }
    walks.sort_by_key(|(b, w)| {
        let big = w
            .chains
            .values()
            .filter(|c| has_bigmul(&c.expr))
            .count() as i64;
        std::cmp::Reverse((w.quality(), big, *b as i64))
    });
    // candidates from ALL aligned walks are merged; misaligned garbage is
    // rejected downstream by the data validators (heap/tiling), not here
    let mut chosen: Vec<(usize, Walker)> = walks.into_iter().collect();
    let mut m = Walker::new(img, d, blob_va, hdr_global);
    let used = chosen.len();
    for (_, w) in chosen.drain(..) {
        m.anchors.extend(w.anchors);
        for (k, v) in w.chains {
            m.chains.entry(k).or_insert(v);
        }
        for (k, v) in w.columns {
            match m.columns.get(&k) {
                Some(e) if e.sink.is_some() || v.sink.is_none() => {}
                _ => {
                    m.columns.insert(k, v);
                }
            }
        }
        for (k, v) in w.sym_last {
            m.sym_last.entry(k).or_insert(v);
        }
    }
    // dedupe anchors
    let mut seen = HashSet::new();
    m.anchors.retain(|a| seen.insert((a.slot, a.op.clone(), a.imm, a.addr)));
    m.finalize();
    let mut chains: Vec<ChainRec> = m.chains.values().cloned().collect();
    chains.sort_by_key(|c| std::cmp::Reverse(expr_size(&c.expr)));
    chains.truncate(400);
    let mut columns: Vec<ColRec> = m.columns.values().cloned().collect();
    columns.sort_by_key(|c| c.addr);
    let report = SymwalkReport {
        exe: String::new(),
        site,
        back: used,
        anchors: m.anchors,
        chains,
        columns,
    };
    (report, used)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bit-exact regression against the hand-extracted constant sets (the
    /// 11/12 anchor-site group from the Python prototype; the 12th — 7.1
    /// 0x613ace3 — lives at a sibling site and is intentionally excluded).
    /// Run with:
    ///   MHY_SAMPLE_ROOT=~/gire/sample/gi cargo test symwalk_regression -- --ignored --nocapture
    #[test]
    #[ignore]
    fn symwalk_regression() {
        let root = std::env::var("MHY_SAMPLE_ROOT")
            .unwrap_or_else(|_| "/home/yangsanyi/gire/sample/gi".into());
        struct Case {
            ver: &'static str,
            blob: u64,
            hg: u64,
            site: u64,
            expect: &'static [&'static str],
        }
        let cases = [
            Case { ver: "7.1.0", blob: 0x1427D5CB0, hg: 0x145AD62B8, site: 0x140515603,
                expect: &["4e94","62d8b7b8","7572748a","1f4d9eea","6e8931d6","39036375","1e2a"] },
            Case { ver: "7.1.0", blob: 0x1427D5CB0, hg: 0x145AD62B8, site: 0x140516303,
                expect: &["a593","3ca3ffa0","5cd0b62e","63a341e6","2411ed71","ee8895ea","ffffdc71"] },
            Case { ver: "7.1.0", blob: 0x1427D5CB0, hg: 0x145AD62B8, site: 0x140515EA6,
                expect: &["9c54","1f0da79f","1bf89d8b64959bb7","295ee0eba6cafaea","979c7da9","38eb"] },
            Case { ver: "7.0.0", blob: 0x142720328, hg: 0x145898158, site: 0x1404E5C42,
                expect: &["3639b538f896","cc49cf2e948f28f","3209b9a2","66e3ee5eebb7b78","997e86cd","13"] },
            Case { ver: "7.0.0", blob: 0x142720328, hg: 0x145898158, site: 0x1404F9A7B,
                expect: &["2f64c993dffe","ab42c68e0d4a","272e941c","705880a8","da14eda6","8fe5701b"] },
            Case { ver: "7.0.0", blob: 0x142720328, hg: 0x145898158, site: 0x1404E6463,
                expect: &["e0f8","22f6da00","3aa8ee62","49880e3c","3e17e98e","7ec31f32","5dc2119e","ffff945b","ffffc45a"] },
            Case { ver: "6.7.0", blob: 0x142418C00, hg: 0x14536F4D8, site: 0x1404BFB48,
                expect: &["cb87","1d9a1a7a","38036d18","7964c76c","324caf19"] },
            Case { ver: "6.7.0", blob: 0x142418C00, hg: 0x14536F4D8, site: 0x1404D3C1D,
                expect: &["2a2e98a6","59887b45","3cbe0533","5a301fb"] },
            Case { ver: "6.7.0", blob: 0x142418C00, hg: 0x14536F4D8, site: 0x1404BDF2B,
                expect: &["1bb4f2a67161","251ba412d3bc6","70f1d209","2c7618b2","14bda7a6"] },
            Case { ver: "6.7.0", blob: 0x142418C00, hg: 0x14536F4D8, site: 0x1404C084A,
                expect: &["137d","70b05cb7","42639239","525521b3","5f17108d","2bfbe794","5d18"] },
            Case { ver: "6.7.0", blob: 0x142418C00, hg: 0x14536F4D8, site: 0x1404C03E6,
                expect: &["fda4fdc7922e20a0","52ed0039dcb14f2e","e2cc29ca","a16dd35b","5b99"] },
        ];
        let mut fails = 0usize;
        for c in &cases {
            let path = format!("{}/{}/YuanShen.exe", root, c.ver);
            let Ok(d) = std::fs::read(&path) else {
                println!("SKIP {} (no exe)", c.ver);
                continue;
            };
            let img = Image::parse(&d).expect("pe");
            let (rep, used) = symwalk(&img, &d, c.blob, Some(c.hg), c.site, 0x120, 0x700);
            let mut hay = String::new();
            for ch in &rep.chains {
                hay.push_str(&format!("{}", ch.expr));
                hay.push(' ');
            }
            for col in &rep.columns {
                hay.push_str(&format!("{}", col.expr));
                hay.push(' ');
            }
            let missing: Vec<&str> = c
                .expect
                .iter()
                .filter(|x| !contains_const(&hay, x))
                .copied()
                .collect();
            if missing.is_empty() {
                println!(
                    "PASS {} site {:#x} (back-merges {}, chains {}, cols {})",
                    c.ver,
                    c.site,
                    used,
                    rep.chains.len(),
                    rep.columns.len()
                );
            } else {
                fails += 1;
                println!(
                    "MISS {} site {:#x}: {:?} (chains {} cols {})",
                    c.ver,
                    c.site,
                    missing,
                    rep.chains.len(),
                    rep.columns.len()
                );
            }
        }
        assert_eq!(fails, 0, "{} regression sites missing constants", fails);
    }

    #[test]
    fn imul3_chain_recorded() {
        // mov eax, edi ; imul rcx, rax, 0x4e94 ; xor rcx, 0x62d8b7b8
        // use exact encodings instead:
        let code: Vec<u8> = vec![
            0x8B, 0xC7,
            0x48, 0x69, 0xC8, 0x94, 0x4E, 0x00, 0x00,
            0x48, 0x81, 0xF1, 0xB8, 0xB7, 0xD8, 0x62,
            0xC3,
        ];
        let _ = code.len();
        // build a minimal PE-less image: use Image::parse on a tiny stub is
        // heavy; instead exercise Walker via a raw decoder loop with a
        // borrowed Image from the real 7.1 sample if present, else skip.
        let root = std::env::var("MHY_SAMPLE_ROOT")
            .unwrap_or_else(|_| "/home/yangsanyi/gire/sample/gi".into());
        let p = format!("{}/7.1.0/YuanShen.exe", root);
        let Ok(d) = std::fs::read(&p) else { return };
        let img = Image::parse(&d).unwrap();
        let mut w = Walker::new(&img, &d, 0x1427D5CB0, Some(0x145AD62B8));
        let mut dec = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.mnemonic() == Mnemonic::Ret { break; }
            w.step(&ins);
            println!(
                "step {:?} {} -> rax={:?} rcx={:?} chains={}",
                ins.mnemonic(),
                ins.ip(),
                w.regs.get("rax").map(|v| format!("{}", v.e)),
                w.regs.get("rcx").map(|v| format!("{}", v.e)),
                w.chains.len()
            );
        }
        let hay: String = w.chains.keys().cloned().collect::<Vec<_>>().join(" | ");
        println!("chains: {}", hay);
        assert!(hay.contains("4e94"), "imul chain missing");
        assert!(hay.contains("62d8b7b8"), "xor chain missing");
    }

    #[test]
    fn rowmarker_column_recorded() {
        // rdx = 14*rcx (shl/sub idiom); rax = sym r13; rdx += rax;
        // eax = [rdx+rax+4]; eax += 0x979c7da9; eax ^= esi
        let code: Vec<u8> = vec![
            0x48, 0x89, 0xCE,             // mov rsi, rcx   (mask holder)
            0x48, 0x89, 0xCA,             // mov rdx, rcx
            0x48, 0xC1, 0xE2, 0x04,       // shl rdx, 4
            0x48, 0x29, 0xCA,             // sub rdx, rcx
            0x48, 0x29, 0xCA,             // sub rdx, rcx
            0x41, 0x8B, 0x45, 0x64,       // mov eax, [r13+0x64]  (hdr read)
            0x48, 0x98,                   // cdqe -> rax = eax (sext32 hdr)
            0x48, 0x01, 0xC2,             // add rdx, rax
            0x8B, 0x44, 0x02, 0x04,       // mov eax, [rdx+rax+4]
            0x81, 0xC0, 0xA9, 0x7D, 0x9C, 0x97, // add eax, 0x979c7da9
            0x31, 0xF0,                   // xor eax, esi
            0xC3,
        ];
        let root = std::env::var("MHY_SAMPLE_ROOT")
            .unwrap_or_else(|_| "/home/yangsanyi/gire/sample/gi".into());
        let p = format!("{}/7.1.0/YuanShen.exe", root);
        let Ok(d) = std::fs::read(&p) else { return };
        let img = Image::parse(&d).unwrap();
        let mut w = Walker::new(&img, &d, 0x1427D5CB0, Some(0x145AD62B8));
        let mut dec = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.mnemonic() == Mnemonic::Ret { break; }
            w.step(&ins);
        }
        let cols: Vec<String> = w.columns.values().map(|c| format!("{}", c.expr)).collect();
        println!("cols: {:?}", cols);
        let hay = cols.join(" | ");
        assert!(hay.contains("979c7da9"), "type column missing: {}", hay);
    }

    #[test]
    fn disp8_column_recorded() {
        // rsi = hdr-ish; r9 = 5*edi; eax = movzx word [rsi + r9*2 + 4]; +imm
        let code: Vec<u8> = vec![
            0x41, 0x8B, 0x45, 0x58,       // mov eax, [r13+0x158]
            0x48, 0x98,                   // cdqe
            0x48, 0x89, 0xC6,             // mov rsi, rax
            0x44, 0x8B, 0xC7,             // mov r8d, edi
            0x4D, 0x8D, 0x4C, 0x88, 0x00, // lea r9, [r8+r8*4]
            0x0F, 0xB7, 0x44, 0x4E, 0x04, // movzx eax, word [rsi+r9*2+4]
            0x81, 0xC0, 0x71, 0xDC, 0xFF, 0xFF, // add eax, 0xffffdc71
            0xC3,
        ];
        let root = std::env::var("MHY_SAMPLE_ROOT")
            .unwrap_or_else(|_| "/home/yangsanyi/gire/sample/gi".into());
        let p = format!("{}/7.1.0/YuanShen.exe", root);
        let Ok(d) = std::fs::read(&p) else { return };
        let img = Image::parse(&d).unwrap();
        let mut w = Walker::new(&img, &d, 0x1427D5CB0, Some(0x145AD62B8));
        let mut dec = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.mnemonic() == Mnemonic::Ret { break; }
            w.step(&ins);
        }
        let cols: Vec<String> = w.columns.values().map(|c| format!("{}", c.expr)).collect();
        println!("cols: {:?}", cols);
        let hay = cols.join(" | ");
        assert!(hay.contains("ffffdc71"), "disp column missing: {}", hay);
        assert!(hay.contains("raw16@0x4"), "off-4 raw missing: {}", hay);
    }

    #[test]
    fn movabs_imul2_chain() {
        // movabs rax, imm64 ; imul rdi, rax  (7.0 method chain head form)
        let code: Vec<u8> = vec![
            0x48, 0xB8, 0x96, 0xF8, 0x39, 0xB5, 0x39, 0x36, 0x00, 0x00,
            0x48, 0x0F, 0xAF, 0xF8,
            0xC3,
        ];
        let root = std::env::var("MHY_SAMPLE_ROOT")
            .unwrap_or_else(|_| "/home/yangsanyi/gire/sample/gi".into());
        let p = format!("{}/7.1.0/YuanShen.exe", root);
        let Ok(d) = std::fs::read(&p) else { return };
        let img = Image::parse(&d).unwrap();
        let mut w = Walker::new(&img, &d, 0x1427D5CB0, Some(0x145AD62B8));
        let mut dec = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.mnemonic() == Mnemonic::Ret { break; }
            w.step(&ins);
        }
        let hay: String = w.chains.keys().cloned().collect::<Vec<_>>().join(" | ");
        assert!(hay.contains("3639b539f896"), "movabs imul2 chain missing: {}", hay);
    }

    /// find "0x<hex>" with a non-hex char after it (so 0x13 != 0x137d)
    fn contains_const(hay: &str, hex: &str) -> bool {
        let needle = format!("0x{}", hex);
        let mut from = 0usize;
        while let Some(pos) = hay[from..].find(&needle) {
            let end = from + pos + needle.len();
            let ok = hay
                .as_bytes()
                .get(end)
                .map(|b| !b.is_ascii_hexdigit())
                .unwrap_or(true);
            if ok {
                return true;
            }
            from = from + pos + needle.len() - 1;
        }
        false
    }
}

// ---------------------------------------------------------------- chain hunt

/// One chain found by the whole-image shape hunt.
#[derive(Serialize, Debug, Clone)]
pub struct HuntChain {
    /// VA of the chain-defining instruction (provenance).
    pub addr: u64,
    /// VA of the cluster window the walk started at.
    pub site: u64,
    /// The anchor immediate that seeded the cluster.
    pub imm: u64,
    pub expr: Expr,
}

/// Random-looking immediate filter (the obfuscator's chain constants are
/// never small, never powers of two, never the SWAR/divisor idioms).
fn hunt_imm32_ok(imm: u32) -> bool {
    imm > 0xFFFF && imm < 0xFE00_0000 && (imm & (imm - 1)) != 0
}

fn hunt_imm64_ok(imm: u64) -> bool {
    let lo = (imm & 0xFFFF_FFFF) as u32;
    imm > 0xFFFF_FFFF && lo != 0 && (imm & (imm - 1)) != 0
}

/// Whole-image shape-driven chain hunt (Rust port of
/// tools/version-triage/chain_hunt.py, R89d) with one fix the python
/// scanner lacked: the movabs-imul reg,reg form is scanned TOO — the
/// 6.6/6.2 method chains compile to `movabs r,imm64; imul r,r` which the
/// python `0x69` byte scan cannot see, which is why it never finished
/// productively. Every executable section is scanned for cluster anchors
/// (both forms), clusters are walked with a shared-image Walker, and every
/// single-symbol chain carrying a big multiplier is emitted. Which chain
/// belongs to which table is decided downstream by data validators (the
/// differential locator + heap gates), never here.
pub fn chain_hunt(
    img: &Image,
    d: &[u8],
    blob_va: u64,
    hdr_global: Option<u64>,
    win: usize,
    max_clusters: usize,
) -> Vec<HuntChain> {
    let ib = img.image_base();
    // ---- 1. anchor scan over every executable section
    let mut anchors: Vec<(usize, u64)> = Vec::new(); // (file off, imm)
    for s in img.sections() {
        if !s.is_executable() {
            continue;
        }
        let start = s.raw_pointer as usize;
        // The metadata accessors live in the first megabytes of .text (the
        // whole-image scan the python tool attempted OOMed on the 250MB
        // il2cpp section, whose movabs density is data-driven, not code
        // structure). 32MB per exec section is a hard cap that covers every
        // accessor found so far with a wide margin.
        let end = (start + s.raw_size as usize).min(d.len()).min(start + 0x200_0000);
        let base_va = ib + s.virtual_address as u64 - s.raw_pointer as u64;
        let mut i = start;
        while i + 12 <= end {
            // direct form: [48] 69 /r with mod=11 and random imm32. The
            // anchor ONLY counts when the 69 opcode is actually present —
            // a stray-else variant of this block once treated every byte
            // with mod=11 as an anchor (7.9M anchors vs the true ~12k).
            let j69 = if d[i] == 0x48 && d.get(i + 1) == Some(&0x69) {
                Some(i + 2)
            } else if d[i] == 0x69 {
                Some(i + 1)
            } else {
                None
            };
            if let Some(j) = j69 {
                if j + 5 <= end && d[j] >> 6 == 3 {
                    let imm = u32::from_le_bytes(d[j + 1..j + 5].try_into().unwrap());
                    if hunt_imm32_ok(imm) {
                        anchors.push((i, imm as u64));
                        i = j + 5;
                        continue;
                    }
                }
            }
            // movabs form: 48 B8+r imm64 (rarely with REX extensions — the
            // B8 opcode byte's low 3 bits select the register, REX.B can't
            // appear for B8-BF without a second REX, which the compiler
            // never emits for movabs)
            if d[i] == 0x48 && (0xB8..=0xBF).contains(&d[i + 1]) && i + 10 <= end {
                let imm = u64::from_le_bytes(d[i + 2..i + 10].try_into().unwrap());
                if hunt_imm64_ok(imm) {
                    anchors.push((i, imm));
                    i += 10;
                    continue;
                }
            }
            i += 1;
        }
    }
    // ---- 2. cluster (96-byte gap, >= 2 anchors), file offsets are
    // monotonically increasing across sections already
    let mut clusters: Vec<(usize, usize, u64)> = Vec::new(); // (first, last, imm)
    let mut cur: Vec<usize> = Vec::new();
    for &(off, imm) in &anchors {
        if let Some(&last) = cur.last() {
            if off - last > 96 {
                if cur.len() >= 2 {
                    clusters.push((cur[0], *cur.last().unwrap(), imm));
                }
                cur.clear();
            }
        }
        cur.push(off);
    }
    if cur.len() >= 2 {
        clusters.push((cur[0], *cur.last().unwrap(), 0));
    }
    clusters.truncate(max_clusters);

    // ---- 3. walk each cluster from its ANCHOR points — a movabs/imul
    // anchor is an instruction boundary by construction, so the walk starts
    // aligned (fixed back-offsets land mid-instruction and the decoder
    // derails at the next int3, which is why the first cut collected only
    // division-magic chains from unrelated code).
    let mut pool: std::collections::HashMap<String, HuntChain> = Default::default();
    for (first, last, _imm) in &clusters {
        for anchor in [*first, *last] {
            let start = base_va_of(img, anchor);
            if start == 0 {
                continue;
            }
            let mut w = Walker::new(img, d, blob_va, hdr_global);
            let n = walk_window(&mut w, start, win, 20_000);
            if n < 12 {
                continue;
            }
            for rec in w.chains.values() {
                let mut syms = std::collections::BTreeSet::new();
                crate::expr::expr_syms(&rec.expr, &mut syms);
                if syms.len() != 1 || crate::expr::expr_has(&rec.expr, false) {
                    continue;
                }
                if syms.iter().any(|s| bad_sym(s)) {
                    continue;
                }
                if !has_bigmul(&rec.expr) {
                    continue;
                }
                let key = format!("{}", rec.expr);
                pool.entry(key).or_insert_with(|| HuntChain {
                    addr: rec.addr,
                    site: start,
                    imm: 0,
                    expr: rec.expr.clone(),
                });
            }
        }
    }
    let mut out: Vec<HuntChain> = pool.into_values().collect();
    out.sort_by_key(|c| c.addr);
    out
}

fn base_va_of(img: &Image, file_off: usize) -> u64 {
    for s in img.sections() {
        let start = s.raw_pointer as usize;
        let end = start + s.raw_size as usize;
        if file_off >= start && file_off < end {
            return img.image_base() + s.virtual_address as u64 + (file_off - start) as u64;
        }
    }
    0
}
