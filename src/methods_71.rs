//! MethodDefinition table (stride 0x1A) + the runtime method-pointer array,
//! current-generation layout.
//!
//! Per-build constants (re-derive for a new build by decompiling the method
//! resolver + the class-setup loop — see repo notes):
//!
//! - table base:  `body + (i32(header+0x1E0) ^ MD_HDR_XOR)`
//! - record stride 0x1A; `nameIndex  = (u32@+0x04 ^ C_NAME) + pmask(i)`
//! - `declaringType = (u32@+0x0E ^ C_DECL) + pmask(i)` (a TypeDefinition index)
//! - `pmask(i) = ((((i*0x4E94 ^ 0x62D8B7B8) * 0x7572748A + 0x1F4D9EEA) ^ 0x6E8931D6)
//!   * 0xC6FC9C8B) & 0xFFFFFFFF`
//! - code addresses: the long run of 16-aligned il2cpp-section VAs in `.rdata`
//!   (one u64 per global method index, concatenated per-module sub-arrays).
//!
//! Method names decode through the shared string heap cipher (`decode_str`).

use anyhow::{bail, Result};
use std::io::Write;

use crate::decode_str::decode_str;
use crate::decrypt::Metadata;
use crate::mem::Buffer;

pub const MD_HDR_FIELD: usize = 0x1E0;
pub const MD_HDR_XOR: u32 = 0x2EE4_80FB;
pub const MD_STRIDE: usize = 0x1A;
pub const C_NAME: u32 = 0x0613_ACE3;
pub const C_DECL: u32 = 0x0394_729C;

/// per-record index mask (additive after the per-column xor)
pub fn pmask(i: u32) -> u32 {
    let mut v = ((i as u64) * 0x4E94) as u64 ^ 0x62D8_B7B8;
    v = v.wrapping_mul(0x7572_748A).wrapping_add(0x1F4D_9EEA);
    v ^= 0x6E89_31D6;
    (v as u32).wrapping_mul(0xC6FC_9C8B)
}

/// Locate the method-pointer array: the longest run of 16-aligned VAs pointing
/// into the `il2cpp` section, inside `.rdata`. Returns (file offset, count).
pub fn find_methodptrs(md: &Metadata) -> Option<(usize, usize)> {
    let image = &md.game_assembly;
    // il2cpp section VA range
    let il = crate::pe::Image::parse(image).ok()?;
    let sec = il.sections().iter().find(|s| s.name == "il2cpp")?;
    let lo = il.image_base() + sec.virtual_address as u64;
    let hi = lo + sec.virtual_size as u64;
    let rd = il.section(".rdata")?;
    let bytes = il.file_slice(rd.raw_pointer as u64, rd.raw_size as usize)?;
    let n = bytes.len() / 8;
    let mut best: (usize, usize) = (0, 0); // (len, start)
    let mut run = 0usize;
    let mut start = 0usize;
    for i in 0..n {
        let v = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().ok()?);
        if lo <= v && v < hi && v % 16 == 0 {
            if run == 0 { start = i; }
            run += 1;
        } else {
            if run > best.0 { best = (run, start); }
            run = 0;
        }
    }
    if run > best.0 { best = (run, start); }
    if best.0 < 1000 { return None; }
    Some((rd.raw_pointer as usize + best.1 * 8, best.0))
}

/// Full dump: types grouped from the TypeDefinition table, methods from the
/// MethodDefinition table with code addresses from the pointer array.
/// Writes an Il2CppDumper-flavoured dump.cs.
/// Escape a string for inclusion in a JSON string literal (names may contain quotes/backslashes).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Il2CppDumper-compatible script.json (ScriptMethod entries; the classic
/// Ghidra-Il2CppDumper plugin and our bundled ghidra/apply script consume it).
pub fn write_script_json(w: &mut dyn Write, methods: &[(u64, String)]) -> std::io::Result<()> {
    writeln!(w, "{{")?;
    writeln!(w, "\"ScriptMethod\": [")?;
    for (i, (va, name)) in methods.iter().enumerate() {
        let comma = if i + 1 == methods.len() { "" } else { "," };
        writeln!(w, "  {{\"Address\": {}, \"Name\": \"{}\", \"Signature\": \"\", \"TypeSignature\": \"\"}}{comma}",
                 va, json_escape(name))?;
    }
    writeln!(w, "],")?;
    writeln!(w, "\"ScriptString\": [],")?;
    writeln!(w, "\"ScriptMetadata\": [],")?;
    writeln!(w, "\"ScriptMetadataMethod\": [],")?;
    writeln!(w, "\"Addresses\": [0, 0, 0]")?;
    writeln!(w, "}}")
}

pub fn dump_full(md: &Metadata, w: &mut dyn Write, wj: &mut dyn Write) -> Result<(usize, usize, usize)> {
    let body = Buffer::new(&md.body);
    let strsec = strsec_of(md);

    // --- type names (same walk as td_dump, collected in memory) ---
    let td_base = (u32_le(&md.header, crate::td_dump::TD_HDR_FIELD)
        ^ crate::td_dump::TD_HDR_XOR) as usize;
    let mut type_names: Vec<String> = Vec::new();
    let mut run_bad = 0usize;
    let mut hidden_ct = 0usize;
    let n_td = md.body.len().saturating_sub(td_base) / crate::td_dump::TD_STRIDE;
    for i in 0..n_td.min(300_000) {
        let rec = td_base + i * crate::td_dump::TD_STRIDE;
        let Some(magic) = body.read_u32_opt(rec + 0x1C) else { break };
        if (magic as i32) != crate::td_dump::REC_MAGIC {
            run_bad += 1;
            if run_bad > 5000 { break; }
            // hidden records still occupy a TypeDefIndex slot — keep indices aligned
            hidden_ct += 1;
            type_names.push(format!("<hidden_{}>", hidden_ct));
            continue;
        }
        run_bad = 0;
        let raw_name = body.read_u32_opt(rec + 0x14).unwrap_or(0);
        let idx = if raw_name == crate::td_dump::NAME_SENTINEL { 0xFFFF_FFFF } else { raw_name.wrapping_add(crate::td_dump::C_NAME) };
        let name = decode_str(&body, strsec, idx);
        let ns_idx = body.read_u32_opt(rec + 0x18).unwrap_or(0) ^ crate::td_dump::C_NS;
        let ns = decode_str(&body, strsec, ns_idx);
        type_names.push(if ns.is_empty() { name } else { format!("{ns}.{name}") });
    }

    // --- method-pointer array ---
    let Some((mp_off, mp_count)) = find_methodptrs(md) else {
        bail!("method-pointer array not located in .rdata");
    };
    let mp_count = mp_count.min((md.game_assembly.len() - mp_off) / 8);

    // --- methods ---
    let md_base = (u32_le(&md.header, MD_HDR_FIELD) ^ MD_HDR_XOR) as usize;
    let n_m = md.body.len().saturating_sub(md_base) / MD_STRIDE;
    let n_methods = n_m.min(mp_count);

    // group by declaring type: (code VA, decoded name) per type
    let mut per_type: Vec<Vec<(u64, String)>> = vec![Vec::new(); type_names.len()];
    let mut all_methods: Vec<(u64, String)> = Vec::with_capacity(n_methods);
    let mut unnamed = 0usize;
    for i in 0..n_methods {
        let rec = md_base + i * MD_STRIDE;
        let stored_name = u32_le(&md.body, rec + 0x04);
        let idx = (stored_name ^ C_NAME).wrapping_add(pmask(i as u32));
        let name = decode_str(&body, strsec, idx);
        let stored_decl = u32_le(&md.body, rec + 0x0E);
        let decl = (stored_decl ^ C_DECL).wrapping_add(pmask(i as u32)) as usize;
        let va = u64::from_le_bytes(md.game_assembly[mp_off + i * 8..mp_off + i * 8 + 8].try_into()?);
        if i == 0 && name.is_empty() {
            bail!("name column transform mismatch (first record empty)");
        }
        match per_type.get_mut(decl) {
            Some(bucket) => bucket.push((va, name)),
            None => unnamed += 1,
        }
    }
    let _ = unnamed;

    // --- emit ---
    writeln!(w, "// dumped by mhydump (static, no game process)")?;
    writeln!(w, "// types: {}, methods: {}", type_names.len(), n_methods)?;
    let mut m_out = 0usize;
    for (tdi, tname) in type_names.iter().enumerate() {
        writeln!(w)?;
        writeln!(w, "public class {tname} // TypeDefIndex {tdi}")?;
        writeln!(w, "{{")?;
        if let Some(ms) = per_type.get(tdi) {
            for (mi, (va, name)) in ms.iter().enumerate() {
                let rva = va - md.tables.image_base;
                let display = if name.is_empty() { format!("M_{mi}") } else { name.clone() };
                all_methods.push((*va, format!("{tname}.{display}")));
                writeln!(w, "\t// RVA 0x{rva:X} VA 0x{va:X}")?;
                writeln!(w, "\tpublic void {display}();")?;
                m_out += 1;
            }
        }
        writeln!(w, "}}")?;
    }
    write_script_json(wj, &all_methods)?;
    Ok((type_names.len(), m_out, n_methods))
}

fn strsec_of(md: &Metadata) -> usize {
    let v = i32_le(&md.header, 0x150) as i64;
    (v - 0x37AB_D22E as i64) as usize
}

fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn i32_le(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
