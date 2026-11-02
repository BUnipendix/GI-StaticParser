//! Static-emulation mask-chain extractor — Rust port of
//! `tools/version-triage/emu_chain.py` (R39 step 4; unicorn-engine + iced
//! decode, Expr interchange from `expr.rs`).
//!
//! Why this exists: some builders compute their per-row chains through
//! real control flow a window walker cannot follow — the chain head can sit
//! before the anchor window (6.6: 0x22A before site), or behind an indirect
//! call. Emulation maps the REAL exe + metadata, plants the header/body
//! globals, seeds registers two ways (zero / ret-forest), runs forward, and
//! a mini tracker rebuilds chain expressions from the executed arithmetic.
//! Bad indirect calls are survived either by the ret-forest (calls through
//! forest pointers return immediately) or by stack-return recovery.
//!
//! Constants are data; acceptance is downstream. Ground truths: the Python
//! emu runs (7.1 method builder incl. the mask2 derivation; 6.1-6.6 method
//! chains) — gated by `emu_chain_regression`.
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0.

use crate::expr::{expr_has, expr_size, expr_syms_set, fold, BinOp, Expr};
use crate::pe::Image;
use crate::symwalk::reg_canon_bits;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use unicorn_engine::RegisterX86 as Reg;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Prot};
use unicorn_engine::Unicorn;

pub const META_BASE: u64 = 0x4000_0000;
pub const SCRATCH: u64 = 0x5000_0000;
pub const STACK_TOP: u64 = 0x7FF1_0000_0000;

#[derive(Serialize, Debug, Clone)]
pub struct ChainRec {
    pub addr: u64,
    pub expr: Expr,
}

#[derive(Serialize, Debug, Clone)]
pub struct AnchorRec {
    pub addr: u64,
    pub slot: u32,
}

#[derive(Serialize)]
pub struct EmuReport {
    pub exe: String,
    pub start: u64,
    pub modes_run: Vec<String>,
    pub anchors: Vec<AnchorRec>,
    pub chains: Vec<ChainRec>,
    pub stops: Vec<String>,
}

const WIN64_CALLER_SAVED: [&str; 7] = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

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

fn bad_sym(n: &str) -> bool {
    n == "mem" || n.starts_with("glob@") || n.starts_with("ripdata")
}

/// Mini symbolic tracker over executed instructions (Python `track()`):
/// arithmetic with immediates, imul forms, register copies; call clears the
/// Win64 caller-saved set.
#[derive(Clone, Default)]
struct Tracker {
    regs: HashMap<String, Expr>,
    chains: BTreeMap<String, ChainRec>,
    anchors: Vec<AnchorRec>,
}

impl Tracker {
    fn get(&self, canon: &str) -> Expr {
        self.regs.get(canon).cloned().unwrap_or(Expr::Sym(canon.to_string()))
    }

    fn set(&mut self, canon: &str, e: Expr, addr: u64) {
        let mut cand = e.clone();
        if expr_syms_set(&cand).len() == 2 {
            // base+counter row index (e.g. the 7.1 field builder's
            // `lea edx,[r14+r13]`): collapse the single Add(Sym,Sym) node
            // into `i` so the mask chain becomes pure
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
        self.regs.insert(canon.to_string(), e);
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

    /// One executed instruction. `hdr_ptr_regs` = concrete register values
    /// that currently equal blob_va (for anchor detection).
    fn step(&mut self, ins: &Instruction, blob_va: u64, uc: &mut Unicorn<'_, ()>) {
        let addr = ins.ip();
        match ins.mnemonic() {
            Mnemonic::Mov => {
                if ins.op_count() != 2 || ins.op_kind(0) != OpKind::Register {
                    return;
                }
                let dst = reg_cb(ins.op_register(0));
                if ins.op_kind(1) == OpKind::Register {
                    let src = self.get(&reg_cb(ins.op_register(1)).0);
                    self.set(&dst.0, src, addr);
                } else if let Some(imm) = Self::imm_of(ins, 1) {
                    self.set(&dst.0, Expr::Imm(imm), addr);
                } else if ins.op_kind(1) == OpKind::Memory {
                    // anchor: [reg + disp] with the concrete base == blob header
                    if let Some((slot, _)) = hdr_slot(ins, blob_va, uc) {
                        self.anchors.push(AnchorRec { addr, slot });
                    }
                }
            }
            Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
                if ins.op_kind(0) != OpKind::Register {
                    return;
                }
                let dst = reg_cb(ins.op_register(0));
                if ins.op_kind(1) == OpKind::Memory {
                    if let Some((slot, _)) = hdr_slot(ins, blob_va, uc) {
                        self.anchors.push(AnchorRec { addr, slot });
                    }
                }
                // register-source extends/copy: keep symbolic as-is (width
                // nuance does not affect chain constants)
                if ins.op_kind(1) == OpKind::Register {
                    let src = self.get(&reg_cb(ins.op_register(1)).0);
                    self.set(&dst.0, src, addr);
                }
            }
            Mnemonic::Lea => {
                // `lea reg, [base + index*scale + disp]` — the row-address
                // idiom every table loop uses (`lea edx, [r14 + r13]`); without
                // symbolic evaluation the destination keeps a stale value and
                // the whole mask chain built on it is lost
                if ins.op_count() != 2 || ins.op_kind(0) != OpKind::Register {
                    return;
                }
                let dst = reg_cb(ins.op_register(0)).0;
                let mut e: Option<Expr> = None;
                let base = ins.memory_base();
                if base != iced_x86::Register::None {
                    e = Some(self.get(&reg_cb(base).0));
                }
                let index = ins.memory_index();
                if index != iced_x86::Register::None {
                    let idx = self.get(&reg_cb(index).0);
                    let scale = ins.memory_index_scale() as u64;
                    let scaled = if scale == 1 {
                        idx
                    } else {
                        Expr::Op2(BinOp::Mul, Box::new(idx), Box::new(Expr::Imm(scale)))
                    };
                    e = Some(match e {
                        Some(b) => Expr::Op2(BinOp::Add, Box::new(b), Box::new(scaled)),
                        None => scaled,
                    });
                }
                let disp = ins.memory_displacement64();
                if disp != 0 {
                    e = Some(match e {
                        Some(b) => Expr::Op2(BinOp::Add, Box::new(b), Box::new(Expr::Imm(disp))),
                        None => Expr::Imm(disp),
                    });
                }
                if let Some(e) = e {
                    let e = fold(&e);
                    self.set(&dst, e, addr);
                }
            }
            Mnemonic::Imul => {
                if ins.op_count() == 3 && ins.op_kind(0) == OpKind::Register {
                    let dst = reg_cb(ins.op_register(0));
                    let a = if ins.op_kind(1) == OpKind::Register {
                        self.get(&reg_cb(ins.op_register(1)).0)
                    } else {
                        Expr::Sym("mem".into())
                    };
                    let b = match ins.op_kind(2) {
                        OpKind::Register => self.get(&reg_cb(ins.op_register(2)).0),
                        _ => match Self::imm_of(ins, 2) {
                            Some(v) => Expr::Imm(v),
                            None => return,
                        },
                    };
                    let e = fold(&Expr::Op2(BinOp::Mul, Box::new(a), Box::new(b)));
                    self.set(&dst.0, e, addr);
                } else if ins.op_count() == 2 && ins.op_kind(0) == OpKind::Register {
                    // imul dst, src  ->  dst = dst * src (movabs idiom)
                    let dst = reg_cb(ins.op_register(0));
                    let a = self.get(&dst.0);
                    let b = self.get(&reg_cb(ins.op_register(1)).0);
                    let e = fold(&Expr::Op2(BinOp::Mul, Box::new(a), Box::new(b)));
                    self.set(&dst.0, e, addr);
                }
            }
            Mnemonic::Add | Mnemonic::Sub | Mnemonic::Xor | Mnemonic::And | Mnemonic::Or
            | Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar => {
                if ins.op_kind(0) != OpKind::Register {
                    return;
                }
                let dst = reg_cb(ins.op_register(0));
                let op = match ins.mnemonic() {
                    Mnemonic::Add => BinOp::Add,
                    Mnemonic::Sub => BinOp::Sub,
                    Mnemonic::Xor => BinOp::Xor,
                    Mnemonic::And => BinOp::And,
                    Mnemonic::Or => BinOp::Or,
                    Mnemonic::Shl => BinOp::Shl,
                    _ => BinOp::Shr,
                };
                let a = self.get(&dst.0);
                let b = match ins.op_kind(1) {
                    OpKind::Register => self.get(&reg_cb(ins.op_register(1)).0),
                    _ => match Self::imm_of(ins, 1) {
                        Some(v) => Expr::Imm(v),
                        None => return,
                    },
                };
                let e = fold(&Expr::Op2(op, Box::new(a), Box::new(b)));
                self.set(&dst.0, e, addr);
            }
            Mnemonic::Call => {
                for r in WIN64_CALLER_SAVED {
                    self.regs.remove(r);
                }
            }
            _ => {}
        }
    }
}

fn reg_cb(r: iced_x86::Register) -> (String, u32) {
    let n = format!("{:?}", r).to_ascii_lowercase();
    reg_canon_bits(&n).unwrap_or((n, 64))
}

/// If the memory operand is [reg+disp] with the concrete reg == header
/// pointer, return (slot, reg) for anchor recording.
fn hdr_slot(
    ins: &Instruction,
    blob_va: u64,
    uc: &mut Unicorn<'_, ()>,
) -> Option<(u32, iced_x86::Register)> {
    let base = ins.memory_base();
    if base == iced_x86::Register::None || base == iced_x86::Register::RIP {
        return None;
    }
    let disp = ins.memory_displacement64();
    if !(0..0x210).contains(&disp) {
        return None;
    }
    let val = match base {
        iced_x86::Register::RAX => uc.reg_read(Reg::RAX),
        iced_x86::Register::RBX => uc.reg_read(Reg::RBX),
        iced_x86::Register::RCX => uc.reg_read(Reg::RCX),
        iced_x86::Register::RDX => uc.reg_read(Reg::RDX),
        iced_x86::Register::RSI => uc.reg_read(Reg::RSI),
        iced_x86::Register::RDI => uc.reg_read(Reg::RDI),
        iced_x86::Register::RBP => uc.reg_read(Reg::RBP),
        iced_x86::Register::R13 => uc.reg_read(Reg::R13),
        _ => return None,
    };
    if val == Ok(blob_va) {
        Some((disp as u32, base))
    } else {
        None
    }
}

fn decode_at(img: &Image, d: &[u8], addr: u64) -> Option<Instruction> {
    let fo = img.va_to_file(addr)? as usize;
    if fo + 16 > d.len() {
        return None;
    }
    let mut dec = Decoder::with_ip(64, &d[fo..fo + 16], addr, DecoderOptions::NONE);
    if dec.can_decode() {
        Some(dec.decode())
    } else {
        None
    }
}

#[derive(Clone, Default)]
struct Shared {
    tracker: Tracker,
    insns: u64,
    max_insns: u64,
    stop_reason: Option<String>,
}

/// One emulation run (single seed mode). Returns (chains, anchors, stop).
#[allow(clippy::too_many_arguments)]
fn run_one(
    img: &Image,
    d: &[u8],
    metadata: &[u8],
    blob_va: u64,
    hdr_global: u64,
    start: u64,
    mode: &str,
    max_insns: u64,
) -> (BTreeMap<String, ChainRec>, Vec<AnchorRec>, String) {
    let mut uc = match Unicorn::new(Arch::X86, Mode::MODE_64) {
        Ok(u) => u,
        Err(e) => return (BTreeMap::new(), Vec::new(), format!("init: {:?}", e)),
    };
    // map image (RWX for simplicity), metadata, scratch w/ ret-forest, stack
    let lo = img.image_base();
    let hi = {
        let mut m = lo;
        for s in img.sections() {
            let end = img.image_base() + s.virtual_address as u64 + s.virtual_size as u64;
            m = m.max(end);
        }
        (m + 0xFFF) & !0xFFF
    };
    let _ = uc.mem_map(lo, hi - lo, Prot::ALL);
    for s in img.sections() {
        if let (Some(fo), true) = (img.va_to_file(img.image_base() + s.virtual_address as u64), s.raw_pointer > 0) {
            let fo = fo as usize;
            let raw = std::cmp::min(s.raw_size as usize, d.len().saturating_sub(fo));
            if raw > 0 {
                let _ = uc.mem_write(img.image_base() + s.virtual_address as u64, &d[fo..fo + raw]);
            }
        }
    }
    let _ = uc.mem_map(META_BASE, ((metadata.len() + 0xFFF) & !0xFFF) as u64, Prot::ALL);
    let _ = uc.mem_write(META_BASE, metadata);
    let _ = uc.mem_map(SCRATCH, 0x500_000, Prot::ALL);
    let ret_stub = SCRATCH + 0x4FF_000;
    let _ = uc.mem_write(ret_stub, &[0xC3]);
    let forest = SCRATCH + 0x300_000;
    let q = (ret_stub as u64).to_le_bytes();
    for off in (0..0x100_000usize).step_by(8) {
        let _ = uc.mem_write(forest + off as u64, &q);
    }
    let _ = uc.mem_map(STACK_TOP - 0x200_000, 0x200_000, Prot::ALL);
    // plant header/body globals
    let _ = uc.mem_write(hdr_global, &blob_va.to_le_bytes());
    let _ = uc.mem_write(hdr_global + 8, &(META_BASE + 0x210).to_le_bytes());
    // seed registers
    let _ = uc.reg_write(Reg::RSP, STACK_TOP - 0x10_000);
    let _ = uc.reg_write(Reg::RBP, SCRATCH + 0x1000);
    let _ = uc.reg_write(Reg::RAX, 64);
    let gpr = [
        (Reg::RBX, "rbx"),
        (Reg::RCX, "rcx"),
        (Reg::RDX, "rdx"),
        (Reg::RSI, "rsi"),
        (Reg::RDI, "rdi"),
        (Reg::R8, "r8"),
        (Reg::R9, "r9"),
        (Reg::R10, "r10"),
        (Reg::R11, "r11"),
        (Reg::R12, "r12"),
        (Reg::R13, "r13"),
        (Reg::R14, "r14"),
        (Reg::R15, "r15"),
    ];
    for (i, (reg, _)) in gpr.iter().enumerate() {
        let v = if mode == "forest" {
            forest + ((i as u64) * 0x800) & 0xFFF_F8
        } else {
            SCRATCH + 0x2000 + (i as u64) * 0x40
        };
        let _ = uc.reg_write(*reg, v);
    }

    let shared = std::rc::Rc::new(RefCell::new(Shared {
        tracker: Tracker::default(),
        insns: 0,
        max_insns,
        stop_reason: None,
    }));

    let sh_code = shared.clone();
    let _ = uc.add_code_hook(1, 0, move |uc, addr, _size| {
        let mut sh = sh_code.borrow_mut();
        sh.insns += 1;
        if sh.insns > sh.max_insns {
            sh.stop_reason = Some("insn limit".into());
            uc.emu_stop();
            return;
        }
        if let Some(ins) = decode_at(img, d, addr) {
            sh.tracker.step(&ins, blob_va, uc);
        }
    });

    let sh_mem = shared.clone();
    let img_range = (lo, hi);
    let _ = uc.add_mem_hook(HookType::MEM_INVALID, 1, 0, move |uc, mt, address, _s, _v| {
        if mt == MemType::FETCH_UNMAPPED || mt == MemType::FETCH_PROT {
            // stack-return recovery: [rsp] pointing into the image = ret
            let rsp = uc.reg_read(Reg::RSP).unwrap_or(0);
            let mut b = [0u8; 8];
            if uc.mem_read(rsp, &mut b).is_ok() {
                let rv = u64::from_le_bytes(b);
                if rv >= img_range.0 && rv < img_range.1 {
                    let _ = uc.reg_write(Reg::RSP, rsp + 8);
                    let _ = uc.reg_write(Reg::RIP, rv);
                    return true;
                }
            }
            sh_mem.borrow_mut().stop_reason = Some(format!("fetch unmapped @{:x}", address));
            return false;
        }
        // data access: map a zero page on demand
        let page = address & !0xFFF;
        if uc.mem_map(page, 0x1000, Prot::ALL).is_ok() {
            let z = [0u8; 0x1000];
            let _ = uc.mem_write(page, &z);
        }
        true
    });

    let _ = uc.emu_start(start, 0, 0, max_insns as usize);
    // hooks were unregistered when `uc` goes out of scope; clone then drop
    let sh = match Rc::try_unwrap(shared) {
        Ok(cell) => cell.into_inner(),
        Err(rc) => {
            let mut taken = Shared::default();
            let mut b = rc.borrow_mut();
            std::mem::swap(&mut *b, &mut taken);
            taken
        }
    };
    (sh.tracker.chains, sh.tracker.anchors, sh.stop_reason.unwrap_or_else(|| "clean".into()))
}

/// Public entry: run zero+forest strategies, merge chains/anchors.
pub fn emu_chain(
    img: &Image,
    d: &[u8],
    metadata: &[u8],
    blob_va: u64,
    hdr_global: u64,
    start: u64,
    max_insns: u64,
) -> EmuReport {
    let mut chains: BTreeMap<String, ChainRec> = BTreeMap::new();
    let mut anchors: Vec<AnchorRec> = Vec::new();
    let mut modes = Vec::new();
    let mut stops = Vec::new();
    let mut seen: HashSet<(u64, u32)> = HashSet::new();
    for mode in ["zero", "forest"] {
        let (ch, an, stop) = run_one(img, d, metadata, blob_va, hdr_global, start, mode, max_insns);
        modes.push(mode.to_string());
        stops.push(format!("[{}] {}", mode, stop));
        for (k, v) in ch {
            chains.entry(k).or_insert(v);
        }
        for a in an {
            if seen.insert((a.addr, a.slot)) {
                anchors.push(a);
            }
        }
    }
    let mut ch: Vec<ChainRec> = chains.into_values().collect();
    ch.sort_by_key(|c| std::cmp::Reverse(expr_size(&c.expr)));
    EmuReport {
        exe: String::new(),
        start,
        modes_run: modes,
        anchors,
        chains: ch,
        stops,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground truths = the Python emu runs (R71/R72): each builder's chain
    /// constants must be reproduced bit-exactly by the Rust port.
    /// Run with:
    ///   MHY_SAMPLE_ROOT=~/gire/sample/gi cargo test emu_chain_regression -- --ignored --nocapture
    #[test]
    #[ignore]
    fn emu_chain_regression() {
        let root = std::env::var("MHY_SAMPLE_ROOT")
            .unwrap_or_else(|_| "/home/yangsanyi/gire/sample/gi".into());
        struct Case {
            ver: &'static str,
            blob: u64,
            hg: u64,
            start: u64,
            expect: &'static [&'static str],
        }
        let cases = [
            Case { ver: "7.1.0", blob: 0x1427D5CB0, hg: 0x145AD62B8, start: 0x1405155AD,
                expect: &["4e94", "62d8b7b8", "7572748a", "1f4d9eea", "6e8931d6", "39036375"] },
            Case { ver: "6.6.0", blob: 0x1423AB198, hg: 0x14521F418, start: 0x1404AC3C3,
                expect: &["190f9299014a", "534f6131", "62c58385"] },
            Case { ver: "6.5.0", blob: 0x142341298, hg: 0x1450BB198, start: 0x140498087,
                expect: &["cf56", "56f42251", "7094e2d9", "379c9083", "114557b6", "7daebb56"] },
            Case { ver: "6.3.0", blob: 0x1422A3300, hg: 0x144E1AB18, start: 0x140467BC8,
                expect: &["3770bdb16890", "43b7ca2c", "2e937253"] },
            Case { ver: "6.2.0", blob: 0x142251328, hg: 0x144C7B5D8, start: 0x14044A255,
                expect: &["1a70e038e08a", "700a03c7", "4455dc19"] },
            Case { ver: "6.1.0", blob: 0x142210940, hg: 0x144BAFBD8, start: 0x14043EFA9,
                expect: &["966c", "1be8f3a9", "2042a445", "6843a01c", "11fd46e1", "281146b2"] },
        ];
        let mut fails = 0usize;
        for c in &cases {
            let exe = format!("{}/{}/YuanShen.exe", root, c.ver);
            let meta = format!("{}/{}/YuanShen_Data/Managed/Metadata/global-metadata.dat", root, c.ver);
            let (Ok(d), Ok(md)) = (std::fs::read(&exe), std::fs::read(&meta)) else {
                println!("SKIP {} (sample missing)", c.ver);
                continue;
            };
            let img = Image::parse(&d).expect("pe");
            let rep = emu_chain(&img, &d, &md, c.blob, c.hg, c.start, 60_000);
            let hay: String = rep
                .chains
                .iter()
                .map(|ch| format!("{}", ch.expr))
                .collect::<Vec<_>>()
                .join(" | ");
            let missing: Vec<&str> = c
                .expect
                .iter()
                .filter(|x| !contains_const(&hay, x))
                .copied()
                .collect();
            if missing.is_empty() {
                println!(
                    "PASS {} start {:#x} (chains {}, anchors {}, stops {:?})",
                    c.ver, c.start, rep.chains.len(), rep.anchors.len(), rep.stops
                );
            } else {
                fails += 1;
                println!(
                    "MISS {} start {:#x}: {:?} (chains {}, stops {:?})",
                    c.ver, c.start, missing, rep.chains.len(), rep.stops
                );
            }
        }
        assert_eq!(fails, 0, "{} emu sites missing constants", fails);
    }

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
