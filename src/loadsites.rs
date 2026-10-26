//! Loadsites — Rust port of `tools/version-triage/loadsites.py` (R79).
//!
//! Recovers every rip-relative load (`mov reg, [rip+d]`) of the MHY header
//! global and a constant-stripped instruction fingerprint of the function
//! that performs it. These fingerprints are the substrate the shape transfer
//! matches across versions, so the token format must be stable: mnemonic +
//! normalized operands, every numeric literal (0x.. / decimal) replaced by
//! `#`, disassembly stopped at the first `ret`.
//!
//! Output JSON schema (same as the Python original, so existing seed files
//! mix freely): `{exe, blob_va, hdr_global, body_global, sites:[{site, fp}]}`.
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0.

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use serde::Serialize;

#[derive(Serialize)]
pub struct LoadSites {
    pub exe: String,
    pub blob_va: u64,
    pub hdr_global: u64,
    pub body_global: u64,
    pub sites: Vec<SiteFp>,
}

#[derive(Serialize)]
pub struct SiteFp {
    pub site: u64,
    pub fp: Vec<String>,
}

struct ExecSection {
    va: u64,
    roff: usize,
    rsz: usize,
}

fn exec_sections(exe: &[u8]) -> anyhow::Result<(u64, Vec<ExecSection>)> {
    let img = crate::pe::Image::parse(exe)?;
    let ib = img.image_base();
    let mut out = Vec::new();
    for s in img.sections() {
        // IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE (the Python filter is
        // EXECUTE alone; some builds mark thunks code-only)
        if s.characteristics & 0x2000_0000 != 0 {
            let rsz = (s.raw_size as usize).min(exe.len().saturating_sub(s.raw_pointer as usize));
            out.push(ExecSection {
                va: ib + s.virtual_address as u64,
                roff: s.raw_pointer as usize,
                rsz,
            });
        }
    }
    Ok((ib, out))
}

/// One rip-relative memory instruction: opcode byte (0x8b load / 0x8d lea /
/// 0x89 store), instruction VA, resolved target VA.
struct RipRef {
    op: u8,
    site: u64,
    target: u64,
}

/// Byte-pattern scan for `(48|4c|4d|49) (8b|8d|89) modrm(r/m=101)` — every
/// rip-relative access with a REX prefix, exactly the Python numpy mask.
fn rip_refs(exe: &[u8], ib: u64, secs: &[ExecSection]) -> Vec<RipRef> {
    let mut out = Vec::new();
    for s in secs {
        let end = s.roff + s.rsz;
        let b = &exe[..end.min(exe.len())];
        let limit = b.len().saturating_sub(7);
        let mut i = s.roff;
        while i < limit {
            let rex = b[i];
            if rex != 0x48 && rex != 0x4c && rex != 0x4d && rex != 0x49 {
                i += 1;
                continue;
            }
            let op = b[i + 1];
            if op != 0x8b && op != 0x8d && op != 0x89 {
                i += 1;
                continue;
            }
            if b[i + 2] & 0xc7 != 0x05 {
                i += 1;
                continue;
            }
            let disp = i32::from_le_bytes([b[i + 3], b[i + 4], b[i + 5], b[i + 6]]);
            let site = s.va + (i - s.roff) as u64;
            out.push(RipRef {
                op,
                site,
                target: (site as i64 + 7 + disp as i64) as u64,
            });
            // advance by ONE byte like the numpy mask (overlapping byte
            // patterns inside displacement/immediate fields count as sites in
            // the Python artifact; they never fingerprint-match, but the site
            // list must stay identical for cross-tool compatibility)
            i += 1;
        }
    }
    out
}

fn find_blob(exe: &[u8]) -> Option<u64> {
    let img = crate::pe::Image::parse(exe).ok()?;
    for s in img.sections() {
        let start = s.raw_pointer as usize;
        let end = (start + s.raw_size as usize).min(exe.len());
        let hay = exe.get(start..end)?;
        if let Some(rel) = hay.windows(4).position(|w| w == b"MHY\0") {
            return Some(img.image_base() + s.virtual_address as u64 + rel as u64);
        }
    }
    None
}

/// The header global: the `lea reg, [rip+d]` that materializes the blob VA,
/// immediately followed by a rip-relative store of that register. The store's
/// displacement (+7 from the lea's next-ip) is the global's address.
fn find_hdr_global(exe: &[u8], ib: u64, secs: &[ExecSection], refs: &[RipRef], blob_va: u64) -> Option<u64> {
    for r in refs {
        if r.op != 0x8d || r.target != blob_va {
            continue;
        }
        let fo = crate::pe::Image::parse(exe).ok()?.va_to_file(r.site)? as usize + 7;
        let b = exe.get(fo..fo + 7)?;
        let rex = b[0];
        if rex != 0x48 && rex != 0x4c && rex != 0x4d && rex != 0x49 {
            continue;
        }
        if b[1] != 0x89 || b[2] & 0xc7 != 0x05 {
            continue;
        }
        let disp2 = i32::from_le_bytes([b[3], b[4], b[5], b[6]]);
        let s2 = r.site + 7;
        return Some((s2 as i64 + 7 + disp2 as i64) as u64);
    }
    let _ = (ib, secs);
    None
}

/// Constant-stripped instruction tokens for the function starting at `site`.
fn fingerprint(exe: &[u8], site: u64, n: usize) -> Vec<String> {
    let img = match crate::pe::Image::parse(exe) {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };
    let fo = match img.va_to_file(site) {
        Some(f) => f as usize,
        None => return Vec::new(),
    };
    let code = exe.get(fo..fo + n).unwrap_or(&[]);
    let mut d = Decoder::with_ip(64, code, site, DecoderOptions::NONE);
    let mut fmt = IntelFormatter::new();
    // capstone-compatible layout, so fingerprints mix with the existing
    // Python-generated seed files: `mov rdx, qword ptr [rip + 0x2f418]`
    let o = fmt.options_mut();
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_uppercase_hex(false);
    o.set_uppercase_registers(false);
    o.set_space_after_operand_separator(true);
    o.set_space_between_memory_add_operators(true);
    o.set_space_between_memory_mul_operators(false);
    o.set_rip_relative_addresses(true);

    o.set_memory_size_options(iced_x86::MemorySizeOptions::Always);
    // capstone prints signed numbers only for sign-EXTENDED encodings
    // (imm8->16/32/64, imm32->64); native-width immediates print unsigned.
    // Toggled per instruction below (imm8-extended = signed).
    o.set_signed_immediate_operands(true);
    let mut toks = Vec::new();
    let mut buf = String::new();
    while d.can_decode() {
        let ins = d.decode();
        // capstone's iterator stops at the first undecodable byte; iced emits
        // an `(bad)` placeholder instead — drop it and stop, so token counts
        // match the Python-generated artifacts
        if ins.is_invalid() {
            break;
        }
        // capstone ground truth (probed 2026-10-26 on every ALU form):
        // native-width immediates ALWAYS print unsigned; sign-EXTENDED
        // encodings (imm8->16/32/64, imm32->64) print signed only for the
        // arithmetic mnemonics add/adc/sub/sbb/cmp, unsigned for or/and/xor.
        let ext_kinds = [
            iced_x86::OpKind::Immediate8to16,
            iced_x86::OpKind::Immediate8to32,
            iced_x86::OpKind::Immediate8to64,
            iced_x86::OpKind::Immediate32to64,
        ];
        let arith = matches!(
            ins.mnemonic(),
            iced_x86::Mnemonic::Add
                | iced_x86::Mnemonic::Adc
                | iced_x86::Mnemonic::Sub
                | iced_x86::Mnemonic::Sbb
                | iced_x86::Mnemonic::Cmp
        );
        let extended = (0..ins.op_count())
            .filter_map(|k| ins.try_op_kind(k).ok())
            .any(|k| ext_kinds.contains(&k));
        let signed = arith && extended;
        // no-op when unchanged; cheap and keeps the formatter mutable
        fmt.options_mut().set_signed_immediate_operands(signed);
        buf.clear();
        fmt.format(&ins, &mut buf);
        let mut tok = normalize(&buf);
        // capstone shows a segment override only when it is a REAL prefix and
        // not the implicit default (ss for rbp/r13 bases, ds otherwise)
        use iced_x86::Register;
        let seg = ins.segment_prefix();
        if seg != Register::None {
            let base = ins.memory_base();
            let default_ss = matches!(
                base,
                Register::RBP | Register::EBP | Register::BP | Register::R13 | Register::R13D
            );
            let default_seg = if default_ss { Register::SS } else { Register::DS };
            if seg != default_seg {
                // iced already shows fs:/gs: overrides itself; only the
                // others need injecting (and never twice)
                let name = match seg {
                    Register::CS => Some("cs:"),
                    Register::ES => Some("es:"),
                    Register::SS => Some("ss:"),
                    Register::DS => Some("ds:"),
                    _ => None,
                };
                if let (Some(name), Some(pos)) = (name, tok.find('[')) {
                    tok.insert_str(pos, name);
                }
            }
        }
        // capstone emits `mnemonic + ' ' + op_str`, so zero-operand
        // instructions carry a trailing space — keep byte parity with the
        // Python-generated seed artifacts
        if !tok.contains(' ') {
            tok.push(' ');
        }
        // capstone spellings iced does not produce:
        //  * `mov r64, imm64` is `movabs` (capstone Intel dialect)
        //  * `imul r, r, imm` keeps the explicit duplicated destination
        if ins.mnemonic() == iced_x86::Mnemonic::Nop && ins.op_count() == 0 {
            // 0x90: iced formats it as `xchg ax, ax`, capstone says `nop`
            tok = "nop ".to_string();
        } else if ins.mnemonic() == iced_x86::Mnemonic::Mov
            && ins.op_count() == 2
            && ins.op1_kind() == iced_x86::OpKind::Immediate64
            && tok.starts_with("mov ")
        {
            tok.replace_range(0..4, "movabs ");
        } else if ins.mnemonic() == iced_x86::Mnemonic::Imul
            && ins.op_count() == 3
            && ins.op0_register() == ins.op1_register()
        {
            // the 3-operand encoding with dst==src: iced displays two
            // operands, capstone keeps the explicit duplicate
            if let Some(c1) = tok.find(',') {
                let dst = tok["imul ".len()..c1].to_string();
                if !dst.is_empty() {
                    tok.insert_str(c1, &format!(", {dst}"));
                }
            }
        }
        toks.push(tok);
        if ins.mnemonic() == iced_x86::Mnemonic::Ret {
            break;
        }
    }
    toks
}

/// Replace every numeric literal with `#` (hex first, then bare decimals),
/// mirroring the Python regex pair `0x[0-9a-fA-F]+` / `\b\d+\b`; also drops
/// the `short`/`near` qualifier iced adds to branches (capstone never does).
fn normalize(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let first_word_end = b.iter().position(|&c| c == b' ').unwrap_or(b.len());
    let branch = b[..first_word_end].starts_with(b"j");
    let mut seen_space = false;
    while i < b.len() {
        if branch && seen_space {
            if b[i..].starts_with(b"short ") {
                i += 6;
                continue;
            }
            if b[i..].starts_with(b"near ") {
                i += 5;
                continue;
            }
        }
        if b[i] == b' ' {
            seen_space = true;
        }
        if b[i] == b'0' && i + 1 < b.len() && b[i + 1] == b'x' || b[i] == b'0' && i + 1 < b.len() && b[i + 1] == b'X' {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            out.push('#');
            i = j;
            continue;
        }
        if b[i].is_ascii_digit() {
            // \b boundary: previous char is not a word char (hex run handled above)
            let prev_word = i > 0
                && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            if !prev_word {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                // a trailing word char directly after digits (e.g. `1e5`) keeps
                // the token — matches \b\d+\b semantics closely enough for
                // operands iced emits
                out.push('#');
                i = j;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Full pass: blob → header global → every load site of the global →
/// fingerprints. `fp_len` bytes of code per fingerprint (default 0x180).
pub fn loadsites(exe: &[u8], exe_path: &str, fp_len: usize) -> anyhow::Result<LoadSites> {
    let blob = find_blob(exe).ok_or_else(|| anyhow::anyhow!("no MHY\\0 blob in any section"))?;
    let (ib, secs) = exec_sections(exe)?;
    let refs = rip_refs(exe, ib, &secs);
    let hg = find_hdr_global(exe, ib, &secs, &refs, blob)
        .ok_or_else(|| anyhow::anyhow!("header global not located (lea+store pattern absent)"))?;
    let mut sites: Vec<u64> = refs
        .iter()
        .filter(|r| r.op == 0x8b && r.target == hg)
        .map(|r| r.site)
        .collect();
    sites.sort_unstable();
    sites.dedup();
    let out = LoadSites {
        exe: exe_path.to_string(),
        blob_va: blob,
        hdr_global: hg,
        body_global: hg.wrapping_add(8),
        sites: sites
            .into_iter()
            .map(|s| SiteFp {
                site: s,
                fp: fingerprint(exe, s, fp_len),
            })
            .collect(),
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_matches_python_regexes() {
        assert_eq!(normalize("mov rax, 0x1234"), "mov rax, #");
        assert_eq!(normalize("mov eax, 12"), "mov eax, #");
        assert_eq!(normalize("add rcx, rdx"), "add rcx, rdx");
        assert_eq!(
            normalize("mov eax, dword ptr [rax+rcx*4+0x10]"),
            "mov eax, dword ptr [rax+rcx*#+#]"
        );
        // hex without 0x prefix inside identifiers must survive
        assert_eq!(normalize("call qword ptr [r12+8]"), "call qword ptr [r12+#]");
    }
}
