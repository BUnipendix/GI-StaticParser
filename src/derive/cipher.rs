//! Constant-free derivation of the MHY string cipher.
//!
//! The packed string index is `(image << 24) | offset`, so the decoder always
//! masks the offset with the literal `0xFFFFFF` -- a format constant that does not
//! rotate per build. Around that mask sits the key schedule:
//!
//! ```text
//! and  r32, 0xFFFFFF
//! movabs/mov  M1        ; may also be loaded from .rdata
//! imul  r64, r32
//! movabs/mov  X1
//! add   r64, r64
//! movabs/mov  X2
//! xor   r64, r64        ; key(off) = ((off * M1 + X1) ^ X2)
//! ```
//!
//! Two checks, neither of which needs a supplied constant:
//!
//!  * **known plaintext** — the heap starts at offset 0 with `mscorlib`
//!    (IL2CPP layout), so `u64(body, s) ^ (X1^X2) == "mscorlib"` locates `strsec`;
//!  * **printable-window density** — with the right triple *and* `strsec`, every
//!    string start decrypts to >=8 printable bytes, so over a 256 KiB window the
//!    hit count is ~15000; a wrong triple or a wrong `strsec` collapses to ~100.
//!    (Measured: 15,163 vs a 99-hit noise floor on 7.1.0.)
//!
//! The score is what makes this decidable rather than a guess: it is a 150x
//! separation, not a threshold judgement on a 77%-vs-76% statistic.

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::pe::Image;

/// `"mscorlib"` little-endian: the first string of every IL2CPP string heap.
pub const MSCORLIB: u64 = u64::from_le_bytes(*b"mscorlib");
/// Printable-window width used by the density score.
pub const SCORE_WINDOW: usize = 1 << 18;
/// Minimum density score accepted as a derivation. The noise floor measured on
/// 4.8.0 .. 7.1.0 is 20..100; a real hit scores 15,000+.
pub const SCORE_ACCEPT: usize = 3000;
/// How far past the mask the key schedule may extend.
const SCHEDULE_WINDOW: usize = 0x100;
/// At most this many `mscorlib` placement candidates are scored per triple.
const MAX_STRSEC_HITS: usize = 4;

/// A derived string cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringCipher {
    pub m1: u64,
    pub x1: u64,
    pub x2: u64,
    /// Offset of the string section, relative to the metadata body.
    pub strsec: u32,
    pub score: usize,
    /// VA of the decoder's `and r32, 0xFFFFFF`.
    pub site: u64,
}

/// `and r32, imm32` sites whose immediate is the 24-bit index mask.
fn mask_sites(img: &Image<'_>, exe: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    for s in img.sections() {
        if !s.is_executable() {
            continue;
        }
        let start = s.raw_pointer as usize;
        let end = (start + s.raw_size as usize).min(exe.len());
        let Some(blob) = exe.get(start..end) else { continue };
        let base = img.image_base() + s.virtual_address as u64;
        let mut i = 0usize;
        while i + 6 <= blob.len() {
            if blob[i] == 0x81
                && (blob[i + 1] & 0xF8) == 0xE0 // mod=11, reg=100 (/4) => AND
                && blob[i + 2..i + 6] == [0xFF, 0xFF, 0xFF, 0x00]
            {
                out.push(base + i as u64);
            }
            i += 1;
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    Imm(u64),
    Imul,
    Arith,
}

/// Decode the key schedule after a mask site into a token stream.
fn schedule_tokens(img: &Image<'_>, exe: &[u8], site: u64) -> Vec<Tok> {
    let Some(fo) = img.va_to_file(site) else { return Vec::new() };
    let fo = fo as usize;
    let end = (fo + SCHEDULE_WINDOW).min(exe.len());
    let mut dec = Decoder::with_ip(64, &exe[fo..end], site, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    let mut out = Vec::new();
    while dec.can_decode() {
        dec.decode_out(&mut ins);
        if ins.mnemonic() == Mnemonic::Mov {
            if ins.op_count() == 2 && ins.op_kind(0) == OpKind::Register {
                if ins.op_kind(1) == OpKind::Immediate64 {
                    out.push(Tok::Imm(ins.immediate64()));
                } else if ins.op_kind(1) == OpKind::Memory && ins.is_ip_rel_memory_operand() {
                    if let Some(o) = img.va_to_file(ins.ip_rel_memory_address()) {
                        let o = o as usize;
                        if o + 8 <= exe.len() {
                            out.push(Tok::Imm(u64::from_le_bytes(
                                exe[o..o + 8].try_into().unwrap(),
                            )));
                        }
                    }
                }
            }
        } else if ins.mnemonic() == Mnemonic::Imul {
            out.push(Tok::Imul);
        } else if matches!(ins.mnemonic(), Mnemonic::Add | Mnemonic::Xor | Mnemonic::Sub) {
            out.push(Tok::Arith);
        }
    }
    out
}

/// `const, imul, const, arith, const, arith` — the schedule order observed on every
/// build that carries it inline.
fn schedule_triples(toks: &[Tok]) -> Vec<(u64, u64, u64)> {
    let mut out = Vec::new();
    let n = toks.len();
    let imm = |i: usize| match toks.get(i) {
        Some(Tok::Imm(v)) => Some(*v),
        _ => None,
    };
    for a in 0..n {
        let Some(v0) = imm(a) else { continue };
        for b in a + 1..n {
            if toks[b] != Tok::Imul {
                continue;
            }
            for c in b + 1..n {
                let Some(v1) = imm(c) else { continue };
                for d in c + 1..n {
                    if toks[d] != Tok::Arith {
                        continue;
                    }
                    for e in d + 1..n {
                        let Some(v2) = imm(e) else { continue };
                        for f in e + 1..n {
                            if toks[f] == Tok::Arith {
                                out.push((v0, v1, v2));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Printable-window density over the first `SCORE_WINDOW` bytes of the heap.
pub fn density_score(body: &[u8], strsec: usize, m1: u64, x1: u64, x2: u64) -> usize {
    let Some(avail) = body.len().checked_sub(strsec + 8) else { return 0 };
    let n = SCORE_WINDOW.min(avail);
    if n < 4096 {
        return 0;
    }
    let mut hits = 0usize;
    for o in 0..n {
        let c = u64::from_le_bytes(body[strsec + o..strsec + o + 8].try_into().unwrap());
        let k = (o as u64).wrapping_mul(m1).wrapping_add(x1) ^ x2;
        if (c ^ k).to_le_bytes().iter().all(|&b| (0x20..=0x7E).contains(&b)) {
            hits += 1;
        }
    }
    hits
}

/// A per-build key-step table: six consecutive qwords `[0, k, 2k, 2k, 4k, 4k]`.
///
/// This is the .rdata table the SIMD path of the decoder adds to the running key
/// (`paddq xmm, [table]`). Its *shape* is constant across builds, so it yields
/// `k = M4` without knowing any constant. Verified on 4.8.0 (returns exactly the
/// M4 that the instruction-shape matcher found independently) and on 7.1.0
/// (returns M4 = 0x0889_EEEA_326A_FB36 at VA 0x1439_095E0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStepTable {
    /// VA of the table.
    pub va: u64,
    /// The step `M4`.
    pub m4: u64,
}

/// Find every `[0, k, 2k, 2k, 4k, 4k]` window in the image.
pub fn find_key_step_tables(exe: &[u8]) -> Result<Vec<KeyStepTable>> {
    let img = Image::parse(exe)?;
    let mut out = Vec::new();
    for s in img.sections() {
        let start = s.raw_pointer as usize;
        let end = (start + s.raw_size as usize).min(exe.len());
        let Some(blob) = exe.get(start..end) else { continue };
        let base = img.image_base() + s.virtual_address as u64;
        let n = blob.len() / 8;
        if n < 6 {
            continue;
        }
        let q = |i: usize| u64::from_le_bytes(blob[i * 8..i * 8 + 8].try_into().unwrap());
        for i in 0..n - 6 {
            if q(i) != 0 {
                continue;
            }
            let k = q(i + 1);
            if k == 0 {
                continue;
            }
            let k2 = k.wrapping_mul(2);
            let k4 = k.wrapping_mul(4);
            if q(i + 2) == k2 && q(i + 3) == k2 && q(i + 4) == k4 && q(i + 5) == k4 {
                out.push(KeyStepTable { va: base + (i * 8) as u64, m4: k });
            }
        }
    }
    Ok(out)
}

/// Every body offset whose qword XOR `x1 ^ x2` spells `mscorlib`.
fn mscorlib_offsets(body: &[u8], x1: u64, x2: u64) -> Vec<usize> {
    let pat = (x1 ^ x2 ^ MSCORLIB).to_le_bytes();
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(rel) = body[pos..].windows(8).position(|w| w == pat) {
        let at = pos + rel;
        out.push(at);
        pos = at + 1;
        if out.len() >= MAX_STRSEC_HITS {
            break;
        }
    }
    out
}

/// Derive every string cipher the image carries, best score first.
pub fn derive(exe: &[u8], body: &[u8]) -> Result<Vec<StringCipher>> {
    let img = Image::parse(exe)?;
    let mut out: Vec<StringCipher> = Vec::new();
    for site in mask_sites(&img, exe) {
        for (m1, x1, x2) in schedule_triples(&schedule_tokens(&img, exe, site)) {
            for strsec in mscorlib_offsets(body, x1, x2) {
                if strsec == 0 || strsec + 0x1000 >= body.len() {
                    continue;
                }
                let score = density_score(body, strsec, m1, x1, x2);
                if score >= SCORE_ACCEPT {
                    out.push(StringCipher { m1, x1, x2, strsec: strsec as u32, score, site });
                }
            }
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score));
    out.dedup_by_key(|c| (c.m1, c.x1, c.x2, c.strsec));
    Ok(out)
}


// ---------------------------------------------------------------------------
// Generic (schedule-agnostic) derivation
//
// The 3-constant schedule of 7.1 is one generation; 7.0.0 / 6.4.0 use a
// two-stage, 5-constant schedule:
//     key = (((off*M1 + X1) ^ X2) * M5) ^ X3      (7.0.0)
//     key = (((off*M1 + X1) ^ X2) * M5) + X3      (6.4.0)
// so no fixed constant count or op order may be assumed. What IS stable is the
// key-step table, and that the decoder references it. This section finds the
// decoder that way and then simply EXECUTES the straight-line schedule with a
// tiny register simulator -- no shape guessing at all.
// ---------------------------------------------------------------------------

/// A string decoder located through the key-step table it references.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderSite {
    /// VA of the instruction that references the key-step table.
    pub site: u64,
    /// VA of the preceding mask instruction.
    pub mask_site: u64,
    /// The masked register, i.e. the one holding the string offset.
    pub off_reg: Register,
}

/// One step of the string-key schedule. The schedule is *data* on purpose: the
/// algorithm changed between generations (7.1 uses a 3-constant one-stage chain,
/// 7.0.0/6.4.0 a 5-constant two-stage one), so a profile that hard-codes a
/// constant count cannot describe a future build. A serialized op list can.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "v")]
pub enum CipherOp {
    And(u64),
    Mul(u64),
    Add(u64),
    Xor(u64),
    Sub(u64),
}

impl CipherOp {
    #[inline]
    pub fn apply(self, v: u64) -> u64 {
        match self {
            CipherOp::And(k) => v & k,
            CipherOp::Mul(k) => v.wrapping_mul(k),
            CipherOp::Add(k) => v.wrapping_add(k),
            CipherOp::Xor(k) => v ^ k,
            CipherOp::Sub(k) => v.wrapping_sub(k),
        }
    }
    /// Same operation, with its constant replaced.
    fn with(self, v: u64) -> Self {
        match self {
            CipherOp::And(_) => CipherOp::And(v),
            CipherOp::Mul(_) => CipherOp::Mul(v),
            CipherOp::Add(_) => CipherOp::Add(v),
            CipherOp::Xor(_) => CipherOp::Xor(v),
            CipherOp::Sub(_) => CipherOp::Sub(v),
        }
    }
    pub fn sym(&self) -> &'static str {
        match self {
            CipherOp::And(_) => "&",
            CipherOp::Mul(_) => "*",
            CipherOp::Add(_) => "+",
            CipherOp::Xor(_) => "^",
            CipherOp::Sub(_) => "-",
        }
    }
    pub fn value(&self) -> u64 {
        match self {
            CipherOp::And(v) | CipherOp::Mul(v) | CipherOp::Add(v)
            | CipherOp::Xor(v) | CipherOp::Sub(v) => *v,
        }
    }
}

/// FIRST-QWORD KEY: `key(off) = ops.iter().fold(off & 0xFFFF_FFFF, apply)`. Inside one
/// string the key then advances by `step` for every further qword.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherSchedule {
    pub ops: Vec<CipherOp>,
    pub step: u64,
}

impl CipherSchedule {
    #[inline]
    pub fn key(&self, off: u64) -> u64 {
        let mut v = off & 0xFFFF_FFFF;
        for op in &self.ops {
            v = op.apply(v);
        }
        v
    }
    /// C expression of the first-qword key, for reports.
    pub fn formula(&self) -> String {
        let mut s = String::from("off");
        for op in &self.ops {
            s = format!("({} {} 0x{:X})", s, op.sym(), op.value());
        }
        s
    }
}

/// A schedule-agnostic derivation result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleCipher {
    pub site: u64,
    pub mask_site: u64,
    pub strsec: u32,
    pub score: usize,
    /// The key schedule itself, as data.
    pub schedule: CipherSchedule,
    /// VA of the key-step table the decoder references (where `schedule.step` came from).
    pub step_table: u64,
}

fn is_imm32_any(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate8
    )
}

fn imm_any(ins: &Instruction) -> u64 {
    match ins.op_kind(1) {
        OpKind::Immediate32 => ins.immediate32() as u64,
        OpKind::Immediate32to64 => ins.immediate32to64() as u64,
        OpKind::Immediate8to32 => ins.immediate8to32() as u64,
        OpKind::Immediate8to64 => ins.immediate8to64() as u64,
        OpKind::Immediate8 => ins.immediate8() as u64,
        _ => 0,
    }
}

fn gpr32(i: u8) -> Register {
    const R: [Register; 16] = [
        Register::EAX, Register::ECX, Register::EDX, Register::EBX,
        Register::ESP, Register::EBP, Register::ESI, Register::EDI,
        Register::R8D, Register::R9D, Register::R10D, Register::R11D,
        Register::R12D, Register::R13D, Register::R14D, Register::R15D,
    ];
    R[(i & 15) as usize]
}

/// Every RIP-relative memory operand in the executable sections that resolves to
/// one of the targets, as (site_va, target_va).
fn rip_refs_to(img: &Image<'_>, exe: &[u8], targets: &[u64]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for s in img.sections() {
        if !s.is_executable() {
            continue;
        }
        let start = s.raw_pointer as usize;
        let end = (start + s.raw_size as usize).min(exe.len());
        let Some(blob) = exe.get(start..end) else { continue };
        let base = img.image_base() + s.virtual_address as u64;
        let n = blob.len();
        let mut i = 0usize;
        while i + 8 <= n {
            let chk = |len: usize, disp_at: usize| -> Option<u64> {
                if i + len > n {
                    return None;
                }
                let disp = i32::from_le_bytes(blob[disp_at..disp_at + 4].try_into().unwrap());
                let t = (base + i as u64 + len as u64).wrapping_add(disp as i64 as u64);
                targets.contains(&t).then_some(t)
            };
            if matches!(blob[i], 0x66 | 0xF3 | 0xF2) && blob[i + 1] == 0x0F && (blob[i + 3] & 0xC7) == 0x05 {
                if let Some(t) = chk(8, i + 4) {
                    out.push((base + i as u64, t));
                }
            }
            if matches!(blob[i], 0x48 | 0x4C | 0x4D | 0x49)
                && matches!(blob[i + 1], 0x8B | 0x8D | 0x89)
                && (blob[i + 2] & 0xC7) == 0x05
            {
                if let Some(t) = chk(7, i + 3) {
                    out.push((base + i as u64, t));
                }
            }
            if matches!(blob[i], 0x48 | 0x49 | 0x4C | 0x4D) && blob[i + 1] == 0x0F && (blob[i + 3] & 0xC7) == 0x05 {
                if let Some(t) = chk(8, i + 4) {
                    out.push((base + i as u64, t));
                }
            }
            i += 1;
        }
    }
    out
}

/// Find the `and r32, 0xFFFFFF` that precedes the site, returning (va, dest register).
fn find_mask_before(img: &Image<'_>, exe: &[u8], site: u64, back: usize) -> Option<(u64, Register)> {
    let fo = img.va_to_file(site)? as usize;
    let lo = fo.saturating_sub(back);
    let blob = exe.get(lo..fo)?;
    let base_va = site - (fo - lo) as u64;
    let mut i = blob.len().saturating_sub(6);
    loop {
        if blob[i] == 0x81
            && (blob[i + 1] & 0xF8) == 0xE0
            && blob[i + 2..i + 6] == [0xFF, 0xFF, 0xFF, 0x00]
        {
            let rex = i >= 1 && matches!(blob[i - 1], 0x41 | 0x49);
            let hi = if rex { 8 } else { 0 };
            // start at the REX prefix so the address is instruction-aligned
            let start = if rex { i - 1 } else { i };
            return Some((base_va + start as u64, gpr32(hi | (blob[i + 1] & 7))));
        }
        if blob[i] == 0x25 && blob[i + 1..i + 5] == [0xFF, 0xFF, 0xFF, 0x00] {
            let rex = i >= 1 && matches!(blob[i - 1], 0x41 | 0x49);
            let hi = if rex { 8 } else { 0 };
            let start = if rex { i - 1 } else { i };
            return Some((base_va + start as u64, gpr32(hi)));
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

/// A traced value: either a known constant, or a chain of schedule ops applied to
/// the string offset.
#[derive(Clone)]
enum Sym {
    Const(u64),
    Chain(Vec<CipherOp>),
}

impl Sym {
    fn copy_of(&self) -> Sym {
        self.clone()
    }
}

fn apply_bin(op: CipherOp, a: &Sym, b: &Sym) -> Option<Sym> {
    match (a, b) {
        (Sym::Const(x), Sym::Const(y)) => Some(Sym::Const(op.with(*y).apply(*x))),
        (Sym::Chain(_), Sym::Const(y)) => {
            let mut c = a.copy_of();
            if let Sym::Chain(v) = &mut c {
                v.push(op.with(*y));
                return Some(c);
            }
            None
        }
        (Sym::Const(x), Sym::Chain(_)) => match op {
            // Only commutative ops may move the chain to the left operand.
            CipherOp::Add(_) | CipherOp::Xor(_) | CipherOp::Mul(_) => {
                let mut c = b.copy_of();
                if let Sym::Chain(v) = &mut c {
                    v.push(op.with(*x));
                    return Some(c);
                }
                None
            }
            _ => None,
        },
        (Sym::Chain(_), Sym::Chain(_)) => None,
    }
}

/// Trace the straight-line key schedule from the mask site up to (not including)
/// the key-step-table reference, symbolically. Returns the op chain applied to
/// the string offset, so the very same derivation can be serialized into a
/// profile instead of being re-read from the image on every run.
///
/// Control flow mirrors `eval_schedule` exactly (same stop conditions, same
/// "last arithmetic write wins"), so `trace.key(off) == eval_schedule(off)` is a
/// property enforced by a test rather than an assumption.
pub fn trace_schedule(
    img: &Image<'_>,
    exe: &[u8],
    mask_site: u64,
    off_reg: Register,
    end: u64,
) -> Option<Vec<CipherOp>> {
    let fo = img.va_to_file(mask_site)? as usize;
    let end_fo = img.va_to_file(end)? as usize;
    if end_fo <= fo {
        return None;
    }
    let blob = exe.get(fo..end_fo.min(exe.len()))?;
    let mut dec = Decoder::with_ip(64, blob, mask_site, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    let mut regs: Vec<(Register, Sym)> = vec![(off_reg.full_register(), Sym::Chain(Vec::new()))];
    fn get(regs: &[(Register, Sym)], r: Register) -> Option<Sym> {
        let f = r.full_register();
        regs.iter().rev().find(|(k, _)| *k == f).map(|(_, v)| v.clone())
    }
    let mut steps = 0usize;
    let mut last_arith: Option<Register> = None;
    while dec.can_decode() && steps < 64 {
        dec.decode_out(&mut ins);
        if steps > 0 && ins.ip() >= end {
            break;
        }
        steps += 1;
        let m = ins.mnemonic();
        if ins.op_count() == 0 || ins.op_kind(0) != OpKind::Register {
            break;
        }
        let a = ins.op_register(0).full_register();
        if m == Mnemonic::And && ins.op_count() == 2 && is_imm32_any(ins.op_kind(1)) {
            // NOTE: the second operand here is an immediate, not a register, so it
            // cannot go through apply_bin (which takes the constant from the operand).
            let k = imm_any(&ins);
            let v = get(&regs, ins.op_register(0))?;
            let out = match v {
                Sym::Const(x) => Sym::Const(x & k),
                Sym::Chain(mut ops) => {
                    ops.push(CipherOp::And(k));
                    Sym::Chain(ops)
                }
            };
            regs.push((a, out));
        } else if m == Mnemonic::Mov && ins.op_count() == 2 {
            if is_imm32_any(ins.op_kind(1)) {
                regs.push((a, Sym::Const(imm_any(&ins))));
            } else if ins.op_kind(1) == OpKind::Immediate64 {
                regs.push((a, Sym::Const(ins.immediate64())));
            } else if ins.op_kind(1) == OpKind::Register {
                let v = get(&regs, ins.op_register(1))?;
                regs.push((a, v));
            } else {
                break; // schedule over
            }
        } else if ins.op_count() == 2 && matches!(m, Mnemonic::Imul | Mnemonic::Add | Mnemonic::Xor | Mnemonic::Sub) {
            let av = get(&regs, ins.op_register(0))?;
            let bv = if ins.op_kind(1) == OpKind::Register {
                get(&regs, ins.op_register(1))?
            } else if is_imm32_any(ins.op_kind(1)) {
                Sym::Const(imm_any(&ins))
            } else {
                break;
            };
            let op = match m {
                Mnemonic::Imul => CipherOp::Mul(0),
                Mnemonic::Add => CipherOp::Add(0),
                Mnemonic::Xor => CipherOp::Xor(0),
                _ => CipherOp::Sub(0),
            };
            regs.push((a, apply_bin(op, &av, &bv)?));
            last_arith = Some(a);
        } else {
            break; // schedule over: anything else (memory refs, calls, ...)
        }
    }
    let r = last_arith?;
    match get(&regs, r)? {
        Sym::Chain(v) => Some(v),
        Sym::Const(_) => None,
    }
}

/// Evaluate the straight-line schedule from the mask site up to (not including)
/// the table reference, for one string offset.
pub fn eval_schedule(
    img: &Image<'_>,
    exe: &[u8],
    mask_site: u64,
    off_reg: Register,
    end: u64,
    off: u64,
) -> Option<u64> {
    let ops = trace_schedule(img, exe, mask_site, off_reg, end)?;
    let mut v = off & 0xFFFF_FFFF;
    for op in &ops {
        v = op.apply(v);
    }
    Some(v)
}

/// Density with an arbitrary key function.
pub fn density_fn<F: Fn(u64) -> u64>(body: &[u8], strsec: usize, key: F) -> usize {
    let Some(avail) = body.len().checked_sub(strsec + 8) else { return 0 };
    let n = SCORE_WINDOW.min(avail);
    if n < 4096 {
        return 0;
    }
    let mut hits = 0usize;
    for o in 0..n {
        let c = u64::from_le_bytes(body[strsec + o..strsec + o + 8].try_into().unwrap());
        if (c ^ key(o as u64)).to_le_bytes().iter().all(|&b| (0x20..=0x7E).contains(&b)) {
            hits += 1;
        }
    }
    hits
}

/// Derive the cipher by locating the decoder through its key-step table and
/// executing its schedule, for each candidate string-section offset.
/// Schedule-agnostic: no constant count or op order is assumed.
pub fn derive_by_decoder(
    exe: &[u8],
    body: &[u8],
    strsec_candidates: &[u32],
) -> Result<Vec<ScheduleCipher>> {
    let img = Image::parse(exe)?;
    let tables = find_key_step_tables(exe)?;
    let table_vas: Vec<u64> = tables.iter().map(|t| t.va).collect();
    if table_vas.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let dbg = std::env::var("MHY_DEBUG").is_ok();
    let refs = rip_refs_to(&img, exe, &table_vas);
    if dbg {
        eprintln!("[dbg] tables={} refs={} cands={}", table_vas.len(), refs.len(), strsec_candidates.len());
    }
    for (site, table_va) in refs {
        let Some((mask_site, off_reg)) = find_mask_before(&img, exe, site, 0x200) else {
            if dbg { eprintln!("[dbg] site 0x{site:X}: no mask"); }
            continue;
        };
        // Trace the schedule ONCE; everything downstream folds the op list.
        let Some(ops) = trace_schedule(&img, exe, mask_site, off_reg, site) else {
            if dbg { eprintln!("[dbg] site 0x{site:X}: schedule not a straight-line chain"); }
            continue;
        };
        // The per-qword key step lives in the key-step table this decoder references.
        let step = tables.iter().find(|t| t.va == table_va).map(|t| t.m4).unwrap_or(0);
        let sched = CipherSchedule { ops, step };
        if dbg {
            eprintln!("[dbg] site 0x{site:X} mask 0x{mask_site:X} reg {off_reg:?} step=0x{step:X} key0=0x{:X} : {}",
                sched.key(0), sched.formula());
        }
        let k0 = sched.key(0);
        // The heap starts with "mscorlib" at heap offset 0, whose key is key(0).
        // That makes strsec directly searchable -- no candidate list needed.
        let pat = (k0 ^ MSCORLIB).to_le_bytes();
        let mut found: Vec<u32> = Vec::new();
        let mut pos = 0usize;
        while let Some(rel) = body[pos..].windows(8).position(|w| w == pat) {
            let at = pos + rel;
            if at > 0 && at < u32::MAX as usize {
                found.push(at as u32);
            }
            pos = at + 1;
            if found.len() >= 8 {
                break;
            }
        }
        let local: Vec<u32> = if found.is_empty() {
            strsec_candidates.to_vec()
        } else {
            found
        };
        // Precompute the key schedule ONCE for this site; every candidate strsec
        // reuses it. Then a cheap 512-byte pre-filter rejects the ~50k junk
        // candidates before the full 256 KiB window runs.
        let win = SCORE_WINDOW.min(body.len());
        let mut keys: Vec<u64> = Vec::with_capacity(win);
        for o in 0..win {
            keys.push(sched.key(o as u64));
        }
        let quick = |s: usize| -> usize {
            let n = 512.min(body.len().saturating_sub(s + 8));
            let mut hits = 0;
            for o in 0..n {
                let c = u64::from_le_bytes(body[s + o..s + o + 8].try_into().unwrap());
                if (c ^ keys[o]).to_le_bytes().iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    hits += 1;
                }
            }
            hits
        };
        for &strsec in &local {
            let s = strsec as usize;
            if s == 0 || s + 0x1000 >= body.len() {
                continue;
            }
            if quick(s) < 8 {
                continue;
            }
            let mut hits = 0usize;
            let n = SCORE_WINDOW.min(body.len() - s - 8);
            for o in 0..n {
                let c = u64::from_le_bytes(body[s + o..s + o + 8].try_into().unwrap());
                if (c ^ keys[o]).to_le_bytes().iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    hits += 1;
                }
            }
            if hits >= SCORE_ACCEPT {
                out.push(ScheduleCipher {
                    site,
                    mask_site,
                    strsec,
                    score: hits,
                    schedule: sched.clone(),
                    step_table: table_va,
                });
            }
        }
    }
    out.sort_by(|a, b| b.score.cmp(&a.score));
    out.dedup_by_key(|c| (c.site, c.strsec));
    Ok(out)
}


// ---------------------------------------------------------------------------
// Whole-build pipeline
// ---------------------------------------------------------------------------

/// Everything the constant-free pipeline recovers for one build, in one struct.
pub struct BuildDerivation {
    /// The embedded MHY header, as bytes (0x210 of them).
    pub header: Vec<u8>,
    /// VA of the header blob inside the image.
    pub blob_va: u64,
    /// Every header-slot -> body-offset transform read out of the code.
    pub anchors: Vec<super::anchor::Anchor>,
    /// The derived string cipher, `None` if the image carries no key-step table.
    pub cipher: Option<ScheduleCipher>,
}

impl BuildDerivation {
    /// Every anchor whose resolved body offset is in range, deduplicated by
    /// offset (two anchors may resolve to the same table).
    pub fn body_offsets(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .anchors
            .iter()
            .filter_map(|a| a.resolve(&self.header))
            .filter(|o| *o > 0x40)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Locate the header, read every header-slot anchor out of the code, and derive
/// the string cipher -- with no constant, address or field name supplied.
///
/// This is the single entry point every downstream step (string heap, table
/// discovery, dump) should go through, so a new build is attacked by the same
/// code path that was verified on the 20 sampled versions.
pub fn derive_build(exe: &[u8], dat: &[u8]) -> Result<Option<BuildDerivation>> {
    const BODY_OFF: usize = 0x210;
    if dat.len() <= BODY_OFF || &dat[..4] != b"MHY\0" {
        return Ok(None);
    }
    let body = &dat[BODY_OFF..];
    let Some(blob) = super::anchor::find_header_blobs(exe)?.into_iter().next() else {
        return Ok(None);
    };
    let hdr_global = super::anchor::find_hdr_global(exe, blob.va)?;
    let anchors = super::anchor::recover_anchors(exe, hdr_global)?;
    let header = exe
        .get(blob.file_off..blob.file_off + super::anchor::HEADER_LEN)
        .unwrap_or(&[])
        .to_vec();
    let cands: Vec<u32> = anchors
        .iter()
        .filter_map(|a| a.resolve(&header))
        .filter(|v| *v > 0x1000)
        .collect();
    let cipher = derive_by_decoder(exe, body, &cands)?
        .into_iter()
        .max_by_key(|c| c.score);
    Ok(Some(BuildDerivation { header, blob_va: blob.va, anchors, cipher }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schedule is data: the same code path must describe a 3-constant and a
    /// 5-constant generation, and both must agree with the values recovered by hand
    /// from the decompiled decoders.
    #[test]
    fn schedule_is_data_not_shape() {
        let s71 = CipherSchedule {
            ops: vec![
                CipherOp::And(0xFF_FFFF),
                CipherOp::Mul(0xB33E_4042_7D56_68C0),
                CipherOp::Add(0x6D8C_4AAB_00FE_8E27),
                CipherOp::Xor(0x30EE_5B43_130F_E0CD),
            ],
            step: 0x0889_EEEA_326A_FB36,
        };
        let s70 = CipherSchedule {
            ops: vec![
                CipherOp::And(0xFF_FFFF),
                CipherOp::Mul(0x4348_F5DA_A896_6D44),
                CipherOp::Add(0xF417_6615_F38C_2F5A),
                CipherOp::Xor(0x6814_C42E_4410_ABD4),
                CipherOp::Mul(0x1575_0134_7813_E1A5),
                CipherOp::Xor(0x5DF3_5195_58F2_F383),
            ],
            step: 0x26A1_8408_75C0_5436,
        };
        for o in [0u64, 1, 0x3D4, 0xFF_FFFF] {
            let want = (o & 0xFF_FFFF)
                .wrapping_mul(0xB33E_4042_7D56_68C0)
                .wrapping_add(0x6D8C_4AAB_00FE_8E27)
                ^ 0x30EE_5B43_130F_E0CD;
            assert_eq!(s71.key(o), want, "7.1 off {o:#X}");
        }
        let o = 0x1234u64;
        let mut v = o & 0xFF_FFFF;
        v = v.wrapping_mul(0x4348_F5DA_A896_6D44).wrapping_add(0xF417_6615_F38C_2F5A)
            ^ 0x6814_C42E_4410_ABD4;
        v = v.wrapping_mul(0x1575_0134_7813_E1A5) ^ 0x5DF3_5195_58F2_F383;
        assert_eq!(s70.key(o), v, "7.0.0 two-stage recipe");
        assert_ne!(s71.key(o), s70.key(o));
        assert_eq!(s71.formula(), "((((off & 0xFFFFFF) * 0xB33E40427D5668C0) + 0x6D8C4AAB00FE8E27) ^ 0x30EE5B43130FE0CD)");
    }

    /// End-to-end on a sample: derive everything with no constant supplied, then use
    /// the derived schedule to decode the heap's first string.
    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE / MHY_SAMPLE_DAT"]
    fn derives_schedule_for_sample() {
        let exe = std::fs::read(std::env::var("MHY_SAMPLE_EXE").expect("MHY_SAMPLE_EXE")).unwrap();
        let dat = std::fs::read(std::env::var("MHY_SAMPLE_DAT").expect("MHY_SAMPLE_DAT")).unwrap();
        let b = super::derive_build(&exe, &dat).expect("derive").expect("header");
        let c = b.cipher.expect("cipher");
        assert!(c.score > 10_000, "score {}", c.score);
        assert!(
            matches!(c.schedule.ops.first(), Some(CipherOp::And(0xFF_FFFF))),
            "ops {:?}",
            c.schedule.ops
        );
        let body = &dat[0x210..];
        let s = crate::decode_str::decode_str_sched(
            &crate::mem::Buffer::new(body),
            c.strsec as usize,
            8u32 << 24,
            &c.schedule,
        );
        assert_eq!(s, "mscorlib");
        eprintln!("schedule {} (step 0x{:X}) score {}", c.schedule.formula(), c.schedule.step, c.score);
    }

    /// The key-step table signature must find M4 with no constants supplied.
    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE"]
    fn finds_71_key_step_table() {
        let exe = std::fs::read(std::env::var("MHY_SAMPLE_EXE").expect("MHY_SAMPLE_EXE")).unwrap();
        let tabs = super::find_key_step_tables(&exe).expect("scan");
        assert!(
            tabs.iter().any(|t| t.m4 == 0x0889_EEEA_326A_FB36 && t.va == 0x1439_095E0),
            "tables: {tabs:?}"
        );
    }

    /// Needs a sample: `MHY_SAMPLE_EXE` / `MHY_SAMPLE_DAT` (7.1.0).
    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE / MHY_SAMPLE_DAT"]
    fn derives_71_cipher() {
        let exe = std::fs::read(std::env::var("MHY_SAMPLE_EXE").expect("MHY_SAMPLE_EXE")).unwrap();
        let dat = std::fs::read(std::env::var("MHY_SAMPLE_DAT").expect("MHY_SAMPLE_DAT")).unwrap();
        let body = &dat[0x210..];
        let got = super::derive(&exe, body).expect("derive");
        let top = got.first().expect("at least one cipher");
        assert_eq!(top.m1, 0xB33E_4042_7D56_68C0);
        assert_eq!(top.x1, 0x6D8C_4AAB_00FE_8E27);
        assert_eq!(top.x2, 0x30EE_5B43_130F_E0CD);
        assert_eq!(top.strsec, 0x3C58_E68);
        assert_eq!(top.site, 0x1405_10EC7);
        assert!(top.score > 10_000, "score {}", top.score);
    }
}
