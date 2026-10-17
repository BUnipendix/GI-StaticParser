//! Constant-free location of the embedded MHY header and of the per-build
//! header-slot anchors it is read through.
//!
//! Why this exists: `engine::find_header` used to *validate* a candidate header by
//! decrypting the string heap with the profile's cipher constants. On a build whose
//! constants have rotated there is no candidate to validate, so the whole run died
//! with "embedded MHY header not located" — a bootstrap paradox.
//!
//! This module breaks it with two facts that hold for the 4.8.0 .. 7.1.0 generation
//! (measured, see IMPLEMENTATION_LOG §12):
//!
//! 1. the header blob is the *only* `MHY\0` in `.rdata` (no constants needed);
//! 2. the game reaches it through one global pointer, initialised by a single
//!    `lea blob ; mov [rip+X], reg` pair, and every metadata accessor reads header
//!    slots out of that pointer with a fixed idiom:
//!
//!    ```text
//!    mov|movsxd rA, dword ptr [rH + slot]   ; slot = header field offset
//!    add|xor|sub rA, imm32                  ; imm = the per-build bias
//!    add rA, rBody                          ; body-relative table base (confirmed)
//!    ```
//!
//!    or, for the string section, `mov rA, imm32 ; add rA, dword ptr [rH + slot]`.
//!
//! Everything here is a *measurement*; nothing is a guess, and the caller is
//! expected to validate the resolved offsets against the body length and the
//! table walkers before trusting them.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::pe::Image;

/// The embedded MHY header blob is 0x210 bytes; the following bytes are a table of
/// image VAs, not header slots (measured on 4.8.0 .. 7.1.0).
pub const HEADER_LEN: usize = 0x210;
/// `MHY\0` — the blob magic.
pub const BLOB_MAGIC: [u8; 4] = [b'M', b'H', b'Y', 0x00];
/// How far past a header-pointer load a slot idiom is expected to appear.
const SCAN_WINDOW: usize = 0x1400;
/// How far back a slot read may sit from its `add rA, rBody` confirmation.
const CONFIRM_SPAN: u64 = 0x200;

/// A located `MHY\0` blob candidate.
#[derive(Clone, Copy, Debug)]
pub struct HeaderBlob {
    pub section_index: usize,
    pub file_off: usize,
    pub va: u64,
}

/// How the per-build bias is combined with the stored header slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnchorOp {
    Add,
    Sub,
    Xor,
}

/// One recovered `(header slot -> body offset)` transform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub hdr_off: u32,
    pub op: AnchorOp,
    pub imm: u32,
    /// VA of the instruction that applies `imm`.
    pub site: u64,
    /// True when the very same register was subsequently `add`ed to the body pointer.
    pub confirmed: bool,
}

impl Anchor {
    /// Apply the transform to a header blob, as the game code does (u32 arithmetic).
    pub fn resolve(&self, hdr: &[u8]) -> Option<u32> {
        let o = self.hdr_off as usize;
        let raw = u32::from_le_bytes(hdr.get(o..o + 4)?.try_into().ok()?);
        Some(match self.op {
            AnchorOp::Add => raw.wrapping_add(self.imm),
            AnchorOp::Sub => raw.wrapping_sub(self.imm),
            AnchorOp::Xor => raw ^ self.imm,
        })
    }
}

/// Everything recoverable from one image without knowing a single constant.
pub struct Recovered {
    pub blob: HeaderBlob,
    pub header: Vec<u8>,
    pub hdr_global: u64,
    pub anchors: Vec<Anchor>,
}

impl Recovered {
    /// Anchors whose resolved value lands inside `[1, body_len)`.
    pub fn in_range<'a>(&'a self, body_len: usize) -> Vec<(&'a Anchor, u32)> {
        self.anchors
            .iter()
            .filter_map(|a| {
                let v = a.resolve(&self.header)?;
                (v > 0 && (v as usize) < body_len).then_some((a, v))
            })
            .collect()
    }

    /// Deduplicated `(slot, op, imm)` view, most-confirmed first.
    pub fn unique(&self) -> Vec<Anchor> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for a in &self.anchors {
            if seen.insert((a.hdr_off, a.op, a.imm)) {
                out.push(a.clone());
            }
        }
        out.sort_by_key(|a| (!a.confirmed, a.hdr_off, a.imm));
        out
    }
}

/// Every `MHY\0` in the image, with its section, file offset, and VA.
pub fn find_header_blobs(exe: &[u8]) -> Result<Vec<HeaderBlob>> {
    let img = Image::parse(exe)?;
    let mut out = Vec::new();
    for (i, s) in img.sections().iter().enumerate() {
        let start = s.raw_pointer as usize;
        let end = (start + s.raw_size as usize).min(exe.len());
        let Some(region) = exe.get(start..end) else { continue };
        let mut pos = 0usize;
        while let Some(rel) = region[pos..]
            .windows(BLOB_MAGIC.len())
            .position(|w| w == BLOB_MAGIC)
        {
            let at = pos + rel;
            out.push(HeaderBlob {
                section_index: i,
                file_off: start + at,
                va: img.image_base() + s.virtual_address as u64 + at as u64,
            });
            pos = at + 1;
        }
    }
    Ok(out)
}

/// File offset of a VA, or `None` when it is in a BSS tail / not mapped.
fn va_to_file(img: &Image<'_>, va: u64) -> Option<usize> {
    img.va_to_file(va).map(|v| v as usize)
}

/// RIP-relative `[mem]` operands inside executable sections: `(site_va, opcode, target_va)`
/// for `REX.W 8B/8D/89 modrm(mod=00,rm=101)`.
fn rip_refs(img: &Image<'_>, exe: &[u8]) -> Vec<(u64, u8, u64)> {
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
        while i + 7 <= blob.len() {
            let b0 = blob[i];
            if matches!(b0, 0x48 | 0x4C | 0x4D | 0x49)
                && matches!(blob[i + 1], 0x8B | 0x8D | 0x89)
                && (blob[i + 2] & 0xC7) == 0x05
            {
                let disp = i32::from_le_bytes(blob[i + 3..i + 7].try_into().unwrap());
                let site = base + i as u64;
                let target = (site + 7).wrapping_add(disp as i64 as u64);
                out.push((site, blob[i + 1], target));
                i += 3;
                continue;
            }
            i += 1;
        }
    }
    out
}

/// The global pointer that holds the header blob address: the `mov [rip+X], reg`
/// that immediately follows the single `lea reg, [rip+blob]`.
pub fn find_hdr_global(exe: &[u8], blob_va: u64) -> Result<u64> {
    let img = Image::parse(exe)?;
    let refs = rip_refs(&img, exe);
    let lea_site = refs
        .iter()
        .find(|(_, op, t)| *op == 0x8D && *t == blob_va)
        .map(|(s, _, _)| *s)
        .ok_or_else(|| anyhow!("no lea to the MHY blob at 0x{blob_va:X}"))?;
    let fo = va_to_file(&img, lea_site).ok_or_else(|| anyhow!("lea site not in file"))?;
    let end = (fo + 0x40).min(exe.len());
    let mut dec = Decoder::with_ip(64, &exe[fo..end], lea_site, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    dec.decode_out(&mut ins);
    if dec.can_decode() {
        dec.decode_out(&mut ins);
        if ins.mnemonic() == Mnemonic::Mov
            && ins.op_count() == 2
            && ins.op_kind(0) == OpKind::Memory
            && ins.op_kind(1) == OpKind::Register
            && ins.is_ip_rel_memory_operand()
        {
            return Ok(ins.ip_rel_memory_address());
        }
    }
    Err(anyhow!("lea to blob at 0x{lea_site:X} is not followed by a global store"))
}

/// Is this operand kind an immediate of at most 32 significant bits?
///
/// iced reports `xor rsi, imm32` as `Immediate32to64` (the operand is a 64-bit
/// register), so the 32-bit-only kinds are not enough.
fn is_imm32(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate8
    )
}

fn imm_value(ins: &Instruction) -> Option<u32> {
    match ins.op_kind(1) {
        OpKind::Immediate32 => Some(ins.immediate32()),
        OpKind::Immediate32to64 => Some(ins.immediate32to64() as u32),
        OpKind::Immediate8to32 => Some(ins.immediate8to32() as u32),
        OpKind::Immediate8to64 => Some(ins.immediate8to64() as u32),
        OpKind::Immediate8 => Some(ins.immediate8() as u32),
        _ => None,
    }
}

/// 64-bit GPR for encoding index 0..=15.
fn gpr64(i: u8) -> Register {
    const R: [Register; 16] = [
        Register::RAX, Register::RCX, Register::RDX, Register::RBX,
        Register::RSP, Register::RBP, Register::RSI, Register::RDI,
        Register::R8, Register::R9, Register::R10, Register::R11,
        Register::R12, Register::R13, Register::R14, Register::R15,
    ];
    R[(i & 15) as usize]
}

/// Which registers hold `hg` / `bg` anywhere near `site`?
///
/// Necessary because the body-pointer load often *precedes* the header-pointer load,
/// so a forward-only scan starting at the header load would never learn the body
/// register and would lose every "confirmed" anchor.
fn seed_regs(img: &Image<'_>, exe: &[u8], site: u64, hg: u64, bg: u64) -> (HashSet<Register>, HashSet<Register>) {
    let mut hregs = HashSet::new();
    let mut bodys = HashSet::new();
    let Some(fo) = va_to_file(img, site) else { return (hregs, bodys) };
    let lo = fo.saturating_sub(0x800);
    let hi = (fo + 0x100).min(exe.len());
    let Some(blob) = exe.get(lo..hi) else { return (hregs, bodys) };
    let base = site - (fo - lo) as u64;
    let mut i = 0usize;
    while i + 7 <= blob.len() {
        let rex = blob[i];
        if matches!(rex, 0x48 | 0x4C | 0x4D | 0x49)
            && blob[i + 1] == 0x8B
            && (blob[i + 2] & 0xC7) == 0x05
        {
            let disp = i32::from_le_bytes(blob[i + 3..i + 7].try_into().unwrap());
            let site_va = base + i as u64;
            let target = (site_va + 7).wrapping_add(disp as i64 as u64);
            if target == hg || target == bg {
                let idx = (((rex >> 2) & 1) << 3) | ((blob[i + 2] >> 3) & 7);
                if target == hg {
                    hregs.insert(gpr64(idx));
                } else {
                    bodys.insert(gpr64(idx));
                }
            }
        }
        i += 1;
    }
    (hregs, bodys)
}

/// Decode forward from one header-pointer load and collect slot idioms.
fn scan_site(img: &Image<'_>, exe: &[u8], site: u64, hg: u64, bg: u64) -> Vec<Anchor> {
    let Some(fo) = va_to_file(img, site) else { return Vec::new() };
    let end = (fo + SCAN_WINDOW).min(exe.len());
    let mut dec = Decoder::with_ip(64, &exe[fo..end], site, DecoderOptions::NONE);
    let mut ins = Instruction::default();

    let (mut hregs, mut bodys) = seed_regs(img, exe, site, hg, bg);
    let mut imm_of: HashMap<Register, u32> = HashMap::new();
    let mut pend: HashMap<Register, (u32, u64)> = HashMap::new();
    let mut cand: HashMap<Register, (u32, AnchorOp, u32)> = HashMap::new();
    let mut out = Vec::new();

    while dec.can_decode() {
        dec.decode_out(&mut ins);
        let addr = ins.ip();
        let m = ins.mnemonic();
        let n = ins.op_count();

        if (m == Mnemonic::Mov || m == Mnemonic::Movsxd) && n == 2 {
            let k0 = ins.op_kind(0);
            let k1 = ins.op_kind(1);
            if k0 == OpKind::Register && k1 == OpKind::Memory {
                let ar = ins.op_register(0).full_register();
                let (target, disp) = if ins.is_ip_rel_memory_operand() {
                    (ins.ip_rel_memory_address(), 0u32)
                } else {
                    (0, ins.memory_displacement64() as u32)
                };
                if target == hg {
                    hregs.insert(ar);
                } else if target == bg {
                    bodys.insert(ar);
                } else if hregs.contains(&ins.memory_base().full_register()) {
                    hregs.remove(&ar);
                    pend.insert(ar, (disp, addr));
                    cand.remove(&ar);
                }
            } else if k0 == OpKind::Register && k1 == OpKind::Register {
                let ar = ins.op_register(0).full_register();
                let br = ins.op_register(1).full_register();
                if hregs.contains(&br) || bodys.contains(&br) {
                    // A copy of the header pointer keeps reading slots; a copy of the body
                    // pointer still confirms. Both roles are tracked.
                    if hregs.contains(&br) {
                        hregs.insert(ar);
                    }
                    if bodys.contains(&br) {
                        bodys.insert(ar);
                    }
                }
                if ar != br {
                    if let Some(v) = pend.get(&br).copied() {
                        hregs.remove(&ar);
                        pend.insert(ar, v);
                        cand.remove(&ar);
                    }
                    if let Some(v) = cand.get(&br).copied() {
                        cand.insert(ar, v);
                    }
                }
            } else if k0 == OpKind::Register && is_imm32(k1) {
                imm_of.insert(ins.op_register(0).full_register(), imm_value(&ins).unwrap_or(0));
            }
            continue;
        }

        if !matches!(m, Mnemonic::Add | Mnemonic::Xor | Mnemonic::Sub) || n != 2 {
            continue;
        }
        let k0 = ins.op_kind(0);
        if k0 != OpKind::Register {
            continue;
        }
        let ar = ins.op_register(0).full_register();
        let op = match m {
            Mnemonic::Add => AnchorOp::Add,
            Mnemonic::Xor => AnchorOp::Xor,
            _ => AnchorOp::Sub,
        };
        match ins.op_kind(1) {
            OpKind::Register => {
                let br = ins.op_register(1).full_register();
                // The immediate interpretation wins when the source register was just
                // loaded with a constant; a register that merely *also* looks like the body
                // pointer must not swallow the bias.
                let mut inserted = false;
                if let Some(&(slot, saddr)) = pend.get(&ar) {
                    if let Some(&k) = imm_of.get(&br) {
                        if addr - saddr <= 0x40 {
                            cand.insert(ar, (slot, op, k));
                            inserted = true;
                        }
                    }
                }
                if !inserted && bodys.contains(&br) {
                    if let Some((slot, cop, cimm)) = cand.remove(&ar) {
                        out.push(Anchor { hdr_off: slot, op: cop, imm: cimm, site: addr, confirmed: true });
                    }
                }
            }
            k if is_imm32(k) => {
                if let Some((slot, saddr)) = pend.remove(&ar) {
                    if addr - saddr <= 0x40 {
                        let imm = imm_value(&ins).unwrap_or(0);
                        // Recorded unconditionally; the confirmation pass only *promotes* it.
                        out.push(Anchor { hdr_off: slot, op, imm, site: addr, confirmed: false });
                        cand.insert(ar, (slot, op, imm));
                    }
                }
            }
            OpKind::Memory => {
                if hregs.contains(&ins.memory_base().full_register()) {
                    if let Some(&k) = imm_of.get(&ar) {
                        out.push(Anchor {
                            hdr_off: ins.memory_displacement64() as u32,
                            op,
                            imm: k,
                            site: addr,
                            confirmed: false,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Debug entry point: run the slot-idiom scanner over one header-pointer load.
pub fn scan_site_debug(img: &Image<'_>, exe: &[u8], site: u64, hg: u64, bg: u64) -> Vec<Anchor> {
    scan_site(img, exe, site, hg, bg)
}

/// Recover every header-slot anchor reachable from the header global.
pub fn recover_anchors(exe: &[u8], hdr_global: u64) -> Result<Vec<Anchor>> {
    let img = Image::parse(exe)?;
    let body_global = hdr_global + 8;
    let sites: Vec<u64> = rip_refs(&img, exe)
        .into_iter()
        .filter(|(_, op, t)| *op == 0x8B && *t == hdr_global)
        .map(|(s, _, _)| s)
        .collect();
    let mut anchors = Vec::new();
    for site in sites {
        anchors.extend(scan_site(&img, exe, site, hdr_global, body_global));
    }
    Ok(anchors)
}

// ---------------------------------------------------------------------------
// Table definitions: the code's own "base + index * stride" arithmetic
// ---------------------------------------------------------------------------
//
// Measured on 7.1.0 (IMPLEMENTATION_LOG §21). The loader does not merely read a
// header slot: it *computes a row address*. Three instruction sequences inside
// FUN_1405359e0 do it, and together they are the whole definition of a table:
//
//   0x14053A73F  mov    rcx, [rip+global]      ; rcx = the header pointer
//   0x14053A746  movsxd rcx, [rcx+0xdc]        ; rcx = hdr[0xdc]
//   0x14053A74D  xor    rcx, 0x5278CA3B        ; the per-build bias
//   0x14053A754  add    rcx, [rip+global+8]    ; rcx += the body base
//   0x14053A75D  imul   rdx, rax, 0x46         ; rdx  = index * stride
//   0x14053A761  add    rdx, rcx               ; row  = base + index * stride
//   0x14053A764  cmp    dword [rdx+0x1C], 0xDEBA5049   ; the table magic
//
// The joint feature -- a body-anchored header slot AND a stride, combined by one
// instruction -- is what separates a *table* from the hundreds of other header
// slot reads the game performs. It is far more specific than either half alone,
// and it is still constant-free: the stride is read out of the code, never assumed.

/// One row-table definition read out of the code:
/// base = (hdr[slot] OP imm) + body, and row(i) = base + i * stride.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDef {
    pub hdr_off: u32,
    pub op: AnchorOp,
    pub imm: u32,
    pub stride: u32,
    /// VA of the instruction that combines the base with the scaled index.
    pub site: u64,
}

impl TableDef {
    /// Apply the transform to a header blob, exactly as the game code does.
    pub fn resolve(&self, hdr: &[u8]) -> Option<u32> {
        let o = self.hdr_off as usize;
        let raw = u32::from_le_bytes(hdr.get(o..o + 4)?.try_into().ok()?);
        Some(match self.op {
            AnchorOp::Add => raw.wrapping_add(self.imm),
            AnchorOp::Sub => raw.wrapping_sub(self.imm),
            AnchorOp::Xor => raw ^ self.imm,
        })
    }
}

/// What a register is known to hold while walking forward from a header load.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sym {
    Unknown,
    /// A constant materialised in a register (mov r, imm).
    Imm(u32),
    /// The header-table pointer itself.
    Hg,
    /// The metadata body pointer.
    Body,
    /// A raw read of hdr[slot].
    Slot(u32),
    /// The expression hdr[slot] OP imm.
    SlotOp(u32, AnchorOp, u32),
    /// The table base, i.e. (hdr[slot] OP imm) + body.
    Base(u32, AnchorOp, u32),
    /// index * stride.
    Scaled(u32),
}

/// Index into the 16-entry GPR table, or None for a non-GPR register.
fn ridx(r: Register) -> Option<usize> {
    let f = r.full_register();
    (0..16u8).find(|&i| gpr64(i) == f).map(|i| i as usize)
}

/// Fold one more immediate operation into a value already known to be such an
/// expression. Mixed families are not representable and collapse to Unknown.
fn sym_op(s: Sym, op: AnchorOp, imm: u32) -> Sym {
    match s {
        Sym::Slot(slot) => Sym::SlotOp(slot, op, imm),
        Sym::SlotOp(slot, o0, k0) => {
            let (o, k) = match (o0, op) {
                (AnchorOp::Add, AnchorOp::Add) => (AnchorOp::Add, k0.wrapping_add(imm)),
                (AnchorOp::Sub, AnchorOp::Sub) => (AnchorOp::Sub, k0.wrapping_add(imm)),
                (AnchorOp::Xor, AnchorOp::Xor) => (AnchorOp::Xor, k0 ^ imm),
                (AnchorOp::Add, AnchorOp::Sub) => (AnchorOp::Add, k0.wrapping_sub(imm)),
                (AnchorOp::Sub, AnchorOp::Add) => (AnchorOp::Sub, k0.wrapping_sub(imm)),
                _ => return Sym::Unknown,
            };
            Sym::SlotOp(slot, o, k)
        }
        _ => Sym::Unknown,
    }
}

/// The conjunction that defines a table: a table base plus a scaled index.
fn table_of(a: Sym, b: Sym, addr: u64) -> Option<TableDef> {
    let ((slot, op, imm), stride) = match (a, b) {
        (Sym::Base(s, o, k), Sym::Scaled(st)) => ((s, o, k), st),
        (Sym::Scaled(st), Sym::Base(s, o, k)) => ((s, o, k), st),
        _ => return None,
    };
    // A sanity bound on the row size, not a hit-rate knob: a stride outside this
    // range is a coincidence of two unrelated registers, not a row.
    if !(2..=0x2000).contains(&stride) {
        return None;
    }
    Some(TableDef { hdr_off: slot, op, imm, stride, site: addr })
}

fn imm_at(ins: &Instruction, i: u32) -> Option<u32> {
    match ins.op_kind(i) {
        OpKind::Immediate32 => Some(ins.immediate32()),
        OpKind::Immediate32to64 => Some(ins.immediate32to64() as u32),
        OpKind::Immediate8to32 => Some(ins.immediate8to32() as u32),
        OpKind::Immediate8to64 => Some(ins.immediate8to64() as u32),
        OpKind::Immediate8 => Some(ins.immediate8() as u32),
        _ => None,
    }
}

/// What the memory operand of an instruction denotes, in terms of the symbols
/// above. Unknown when it is neither the header pointer, the body pointer, nor a
/// slot read out of the header pointer.
fn mem_sym(ins: &Instruction, regs: &[Sym; 16], stack: &HashMap<i32, Sym>, hg: u64, bg: u64) -> Sym {
    if ins.is_ip_rel_memory_operand() {
        let a = ins.ip_rel_memory_address();
        if a == hg {
            return Sym::Hg;
        }
        if a == bg {
            return Sym::Body;
        }
        return Sym::Unknown;
    }
    let base = ins.memory_base().full_register();
    let disp = ins.memory_displacement64() as i64 as i32;
    if base == Register::RBP || base == Register::RSP {
        return stack.get(&disp).copied().unwrap_or(Sym::Unknown);
    }
    match ridx(base).map(|i| regs[i]) {
        Some(Sym::Hg) => Sym::Slot(disp as u32),
        Some(Sym::SlotOp(slot, op, k)) => Sym::SlotOp(slot, op, k.wrapping_add(disp as u32)),
        _ => Sym::Unknown,
    }
}

/// Adding the body pointer onto a slot expression yields a table base.
fn with_body(s: Sym) -> Sym {
    match s {
        Sym::Slot(slot) => Sym::Base(slot, AnchorOp::Add, 0),
        Sym::SlotOp(slot, op, k) => Sym::Base(slot, op, k),
        _ => Sym::Unknown,
    }
}

/// Decode forward from one header-pointer load, tracking what each register and
/// stack slot holds, and report every base + index * stride that appears.
fn scan_tables_at(img: &Image<'_>, exe: &[u8], site: u64, hg: u64, bg: u64) -> Vec<TableDef> {
    let Some(fo) = va_to_file(img, site) else { return Vec::new() };
    let end = (fo + SCAN_WINDOW).min(exe.len());
    let mut dec = Decoder::with_ip(64, &exe[fo..end], site, DecoderOptions::NONE);
    let mut ins = Instruction::default();

    let (hregs, _) = seed_regs(img, exe, site, hg, bg);
    let mut regs = [Sym::Unknown; 16];
    for r in hregs {
        if let Some(i) = ridx(r) {
            regs[i] = Sym::Hg;
        }
    }
    let mut stack: HashMap<i32, Sym> = HashMap::new();
    let mut out: Vec<TableDef> = Vec::new();

    while dec.can_decode() {
        dec.decode_out(&mut ins);
        let addr = ins.ip();
        let m = ins.mnemonic();
        let n = ins.op_count();
        let mut next = regs;

        // A memory operand with both a base and an index register is the
        // [base + index*scale] form the loader uses for a row address.
        for i in 0..n {
            if ins.op_kind(i) != OpKind::Memory || ins.is_ip_rel_memory_operand() {
                continue;
            }
            if let (Some(b), Some(x)) = (ridx(ins.memory_base()), ridx(ins.memory_index())) {
                if let Some(t) = table_of(regs[b], regs[x], addr) {
                    out.push(t);
                }
            }
        }

        match m {
            Mnemonic::Mov | Mnemonic::Movsxd if n == 2 => {
                let k0 = ins.op_kind(0);
                let k1 = ins.op_kind(1);
                if k0 == OpKind::Register && k1 == OpKind::Memory {
                    if let Some(ar) = ridx(ins.op_register(0)) {
                        next[ar] = mem_sym(&ins, &regs, &stack, hg, bg);
                    }
                } else if k0 == OpKind::Register && k1 == OpKind::Register {
                    if let (Some(ar), Some(br)) = (ridx(ins.op_register(0)), ridx(ins.op_register(1))) {
                        if ar != br {
                            next[ar] = regs[br];
                        }
                    }
                } else if k0 == OpKind::Register && imm_at(&ins, 1).is_some() {
                    if let Some(ar) = ridx(ins.op_register(0)) {
                        next[ar] = Sym::Imm(imm_at(&ins, 1).unwrap_or(0));
                    }
                } else if k0 == OpKind::Memory && k1 == OpKind::Register && !ins.is_ip_rel_memory_operand() {
                    let base = ins.memory_base().full_register();
                    if base == Register::RBP || base == Register::RSP {
                        if let Some(br) = ridx(ins.op_register(1)) {
                            stack.insert(ins.memory_displacement64() as i64 as i32, regs[br]);
                        }
                    }
                }
            }
            Mnemonic::Lea if n == 2 && ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Memory => {
                if let Some(ar) = ridx(ins.op_register(0)) {
                    let mut v = Sym::Unknown;
                    match (ridx(ins.memory_base()), ridx(ins.memory_index())) {
                        (Some(b), Some(x)) => {
                            if let Some(t) = table_of(regs[b], regs[x], addr) {
                                out.push(t);
                            }
                        }
                        (Some(b), None) => v = regs[b],
                        _ => {}
                    }
                    next[ar] = v;
                }
            }
            Mnemonic::Imul => {
                if n == 3 && ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Register {
                    if let (Some(ar), Some(st)) = (ridx(ins.op_register(0)), imm_at(&ins, 2)) {
                        next[ar] = Sym::Scaled(st);
                    }
                } else if n == 2 && ins.op_kind(0) == OpKind::Register {
                    if let (Some(ar), Some(st)) = (ridx(ins.op_register(0)), imm_at(&ins, 1)) {
                        next[ar] = Sym::Scaled(st);
                    }
                }
            }
            Mnemonic::Add | Mnemonic::Xor | Mnemonic::Sub if n == 2 && ins.op_kind(0) == OpKind::Register => {
                let op = match m {
                    Mnemonic::Add => AnchorOp::Add,
                    Mnemonic::Xor => AnchorOp::Xor,
                    _ => AnchorOp::Sub,
                };
                let ar = ridx(ins.op_register(0));
                match ins.op_kind(1) {
                    OpKind::Memory => {
                        if let Some(ar) = ar {
                            let s = mem_sym(&ins, &regs, &stack, hg, bg);
                            next[ar] = match (regs[ar], s) {
                                (prev, Sym::Body) => with_body(prev),
                                // The bias is often materialised in a register
                                // (mov ecx, imm ; add eax, ecx) instead of being
                                // folded into the instruction as an immediate.
                                (Sym::Imm(k), s @ (Sym::Slot(_) | Sym::SlotOp(..)))
                                    if op != AnchorOp::Sub => sym_op(s, op, k),
                                (prev, s @ Sym::Base(..)) => {
                                    if let Some(t) = table_of(prev, s, addr) {
                                        out.push(t);
                                    }
                                    s
                                }
                                _ => Sym::Unknown,
                            };
                        }
                    }
                    OpKind::Register => {
                        if let (Some(ar), Some(br)) = (ar, ridx(ins.op_register(1))) {
                            let bv = regs[br];
                            if let Sym::Imm(k) = bv {
                                next[ar] = if matches!(regs[ar], Sym::Base(..)) {
                                    regs[ar]
                                } else if op == AnchorOp::Sub {
                                    Sym::Unknown
                                } else {
                                    sym_op(regs[ar], op, k)
                                };
                            } else {
                                if let Some(t) = table_of(regs[ar], bv, addr) {
                                    out.push(t);
                                }
                                next[ar] = match (regs[ar], bv) {
                                    (Sym::Base(..), _) => regs[ar],
                                    (_, Sym::Base(..)) => bv,
                                    (Sym::Scaled(st), _) | (_, Sym::Scaled(st)) => Sym::Scaled(st),
                                    _ => Sym::Unknown,
                                };
                            }
                        }
                    }
                    _ => {
                        if let (Some(ar), Some(k)) = (ar, imm_at(&ins, 1)) {
                            next[ar] = sym_op(regs[ar], op, k);
                        }
                    }
                }
            }
            _ => {}
        }
        regs = next;
    }
    out
}

/// Recover every base + index * stride table definition reachable from the header
/// global, deduplicated by (slot, op, imm, stride).
pub fn recover_tables(exe: &[u8], hdr_global: u64) -> Result<Vec<TableDef>> {
    let img = Image::parse(exe)?;
    let body_global = hdr_global + 8;
    let sites: Vec<u64> = rip_refs(&img, exe)
        .into_iter()
        .filter(|(_, op, t)| *op == 0x8B && *t == hdr_global)
        .map(|(s, _, _)| s)
        .collect();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for site in sites {
        for t in scan_tables_at(&img, exe, site, hdr_global, body_global) {
            if seen.insert((t.hdr_off, t.op, t.imm, t.stride)) {
                out.push(t);
            }
        }
    }
    out.sort_by_key(|t| (t.hdr_off, t.stride, t.site));
    Ok(out)
}

/// Full constant-free pass: blob -> header global -> anchors.
pub fn recover(exe: &[u8]) -> Result<Recovered> {
    let blobs = find_header_blobs(exe)?;
    if blobs.len() != 1 {
        return Err(anyhow!(
            "expected exactly one MHY\\0 blob in the image, found {}",
            blobs.len()
        ));
    }
    let blob = blobs[0];
    let header = exe
        .get(blob.file_off..blob.file_off + HEADER_LEN)
        .ok_or_else(|| anyhow!("MHY blob at 0x{:X} is truncated", blob.file_off))?
        .to_vec();
    let hdr_global = find_hdr_global(exe, blob.va)?;
    let anchors = recover_anchors(exe, hdr_global)?;
    Ok(Recovered { blob, header, hdr_global, anchors })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample path override: `MHY_SAMPLE_EXE` / `MHY_SAMPLE_DAT`.
    /// Ignored by default so a checkout without the 9.6 GB sample library stays green.
    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE / MHY_SAMPLE_DAT"]
    fn recovers_71_profile_exactly() {
        let a = super::tests::load_env();
        let rec = recover(&a.0).expect("recover");
        assert_eq!(rec.anchors.iter().filter(|x| x.hdr_off == 0x150).count(), 1);
        let anchors = rec.unique();
        let check = |slot: u32, op: AnchorOp, imm: u32| {
            assert!(
                anchors.iter().any(|x| x.hdr_off == slot && x.op == op && x.imm == imm),
                "missing hdr[{slot:#X}] {op:?} {imm:#010X}"
            );
        };
        check(0x150, AnchorOp::Add, 0xC854_2DD2);
        check(0x0DC, AnchorOp::Xor, 0x5278_CA3B);
        check(0x1E0, AnchorOp::Xor, 0x2EE4_80FB);
        check(0x158, AnchorOp::Add, 0xE2AB_A334);
        check(0x1D0, AnchorOp::Xor, 0x07D0_BBF9);
        check(0x04C, AnchorOp::Add, 0xE5D2_49BF);
        check(0x070, AnchorOp::Add, 0x915A_4C03);
    }

    /// Self-test for the code-driven locator (R8). The loader computes the
    /// typeDef row address at 0x14053A73F .. 0x14053A761 as
    ///   row = ((hdr[0xDC] ^ 0x5278CA3B) + body) + index * 0x46
    /// so the recovery must reproduce that quadruple from the code alone --
    /// no constant, no address, and no threshold.
    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE / MHY_SAMPLE_DAT"]
    fn recovers_71_type_def_table_from_code() {
        let (exe, _dat) = super::tests::load_env();
        let rec = recover(&exe).expect("recover");
        let defs = recover_tables(&exe, rec.hdr_global).expect("recover_tables");
        assert!(
            defs.iter().any(|t| t.hdr_off == 0xDC
                && t.op == AnchorOp::Xor
                && t.imm == 0x5278_CA3B
                && t.stride == 0x46),
            "missing (0xDC, xor, 0x5278CA3B, 0x46) in {defs:#?}"
        );
        let v = defs
            .iter()
            .find(|t| t.hdr_off == 0xDC && t.stride == 0x46)
            .and_then(|t| t.resolve(&rec.header));
        assert_eq!(v, Some(0x048F_3FD8), "code-derived typeDef base");
    }

    pub(super) fn load_env() -> (Vec<u8>, Vec<u8>) {
        let exe = std::env::var("MHY_SAMPLE_EXE").expect("MHY_SAMPLE_EXE");
        let dat = std::env::var("MHY_SAMPLE_DAT").expect("MHY_SAMPLE_DAT");
        (std::fs::read(exe).unwrap(), std::fs::read(dat).unwrap())
    }
}
