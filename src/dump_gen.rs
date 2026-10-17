//! The generation-7.x dump pipeline: full `dump.cs` (Il2CppDumper format), plus
//! `script.json` and a derivation report. Driven entirely by a [`Profile`].

use std::collections::{HashMap, HashSet};
use std::io::Write;

use anyhow::Result;

use crate::derive::engine::Meta;
use crate::mem::Memory;

/// TypeDef row decoded through the profile.
pub struct Td {
    pub name: String,
    pub namespace: String,
    pub method_start: u32,
    /// Field rows [fields_start, fields_start + fields_count) in the full field table
    /// (u32::MAX = no fields).
    pub fields_start: u32,
    pub fields_count: u32,
    /// Base-class typearr index (u32::MAX = none: interfaces / System.Object).
    pub parent_tarr: u32,
    /// Interface-offsets start (None = no interfaces).
    pub iface_start: Option<u32>,
    /// Decoded TypeAttributes (u32::MAX when the generation lacks the column).
    pub flags: u32,
    /// Decoded bitfield: bit0 IsValueType, bit1 IsEnum (0 when absent).
    pub bitfield: u16,
}

/// One decoded method (signature pieces + code address).
pub struct Md {
    pub name: String,
    pub ret_type: u32,
    pub decl: u32,
    pub slot: i16,
    pub flags: u16,
    pub param_start: u32,
    pub param_count: u8,
    pub rva: u32,
}

pub fn collect<'a>(m: &'a Meta) -> (Vec<Td>, Vec<Md>) {
    let p = &m.profile;
    // row count: the typeDef size slot is authoritative (the tiling walk undercounts),
    // same rule as the method table below.
    let n_td = m.td_count();
    let n_md = m.md_count();
    let mut tds = Vec::with_capacity(n_td);
    for i in 0..n_td {
        let rec = m.td_base + p.td_stride as usize * i;
        let raw = m.body.read_u32(rec + p.td_name.offset as usize);
        let idx = if raw == p.td_name_sentinel { 0xFFFF_FFFF } else { raw.wrapping_add(p.td_name.c) };
        let name = m.decode_str(idx);
        let ns_raw = m.body.read_u32(rec + p.td_ns.offset as usize);
        let ns = m.decode_str(ns_raw ^ p.td_ns.c);
        let ms = m.body.read_u32(rec + p.td_method_start.offset as usize) ^ p.td_method_start.c;
        let (fs, fc) = m.td_fs_fc(i);
        let parent = m.td_parent(i);
        let iface = m.td_iface_start(i);
        let flags = m.td_flags(i).unwrap_or(u32::MAX);
        let bitfield = m.td_bitfield(i).unwrap_or(0);
        tds.push(Td { name, namespace: ns, method_start: ms, fields_start: fs, fields_count: fc, parent_tarr: parent, iface_start: iface, flags, bitfield });
    }
    let mut mds = Vec::with_capacity(n_md);
    for i in 0..n_md as u32 {
        let ret = m.md_col(&p.md_ret_type, i);
        let name = m.decode_str(m.md_col(&p.md_name, i));
        let decl = m.md_col(&p.md_decl, i);
        let slot = m.md_col(&p.md_slot, i) as u16 as i16;
        let flags = (m.md_col(&p.md_flags, i) & 0xFFFF) as u16;
        let ps = m.md_col(&p.md_param_start, i);
        let pc = (m.md_col(&p.md_param_count, i) & 0xFF) as u8;
        let rva = m.method_rva(i as usize);
        mds.push(Md { name, ret_type: ret, decl, slot, flags, param_start: ps, param_count: pc, rva });
    }
    (tds, mds)
}

/// Result of reconstructing one type's instance layout.
#[derive(Clone)]
struct Layout {
    /// Layout end (absolute; value types' own field offsets are boxed, so a struct's
    /// first field sits at 0x10 and its unboxed size is `end - 0x10`).
    end: u32,
    align: u32,
    /// Offsets of the INSTANCE fields, in field-declaration order.
    offsets: Vec<u32>,
}

/// Sequential instance-layout reconstruction.
///
/// The dat carries no field-offset table for this generation (proved by disassembly:
/// the field-definition rows hold name/type/attrs/second-type only), so the offsets are
/// rebuilt with il2cpp's own rules, validated against the 6.4 reference dump:
/// value types' own offsets are boxed (0x10-based), a value type embedded in another
/// type occupies its unboxed size (`end - 0x10`), a derived class starts at the aligned
/// end of its base, fields are laid out in declaration order with natural alignment.
/// Explicit-layout types (`TypeAttributes.LayoutKind == Explicit`, flags & 0x18 == 0x10)
/// are EXCLUDED: their offsets come from [FieldOffset] attributes and cannot be rebuilt.
struct LayoutCalc<'a> {
    m: &'a Meta<'a>,
    tds: &'a [Td],
    memo: HashMap<usize, Option<Layout>>,
    visiting: HashSet<usize>,
}

impl<'a> LayoutCalc<'a> {
    fn new(m: &'a Meta<'a>, tds: &'a [Td]) -> Self {
        Self { m, tds, memo: HashMap::new(), visiting: HashSet::new() }
    }

    /// Instance-field rows of a type: (field-table row, static?) in declaration order.
    fn instance_rows(m: &Meta, td: &Td) -> Vec<(u32, u32, bool)> {
        let mut out = Vec::new();
        if td.fields_start == u32::MAX {
            return out;
        }
        for k in 0..td.fields_count {
            let row = td.fields_start + k;
            let fti = m.field_type_idx(row);
            let attrs = m.il2cpp_type(fti as usize).map(|(_, _, a)| a).unwrap_or(0);
            out.push((row, fti, attrs & 0x10 != 0));
        }
        out
    }

    /// Size and alignment of a field type. `None` = not statically computable.
    fn type_size(&mut self, ti: u32) -> Option<(u32, u32)> {
        let (kind, data, _attrs) = self.m.il2cpp_type(ti as usize)?;
        Some(match kind {
            0x02 | 0x04 | 0x05 => (1, 1),          // bool / sbyte / byte
            0x03 | 0x06 | 0x07 => (2, 2),          // char / short / ushort
            0x08 | 0x09 | 0x0C => (4, 4),          // int / uint / float
            0x0A | 0x0B | 0x0D => (8, 8),          // long / ulong / double
            // string / ptr / byref / array / typedref / IntPtr / UIntPtr / object / szarray
            0x0E | 0x0F | 0x10 | 0x14 | 0x16 | 0x18 | 0x19 | 0x1C | 0x1D => (8, 8),
            0x11 => {
                // VALUE TYPE: embedded size is the unboxed layout size.
                let lay = self.type_layout(data as usize)?;
                (lay.end.checked_sub(0x10)?, lay.align)
            }
            // CLASS: reference. GENERICINST/VAR/MVAR/FNPTR: conservative reference size.
            0x12 | 0x15 | 0x13 | 0x1B | 0x1E => (8, 8),
            _ => (8, 8),
        })
    }

    fn type_layout(&mut self, tdi: usize) -> Option<Layout> {
        if let Some(v) = self.memo.get(&tdi) {
            return v.clone();
        }
        if !self.visiting.insert(tdi) {
            return None; // inheritance cycle: cannot be laid out
        }
        let r = self.compute_layout(tdi);
        self.visiting.remove(&tdi);
        self.memo.insert(tdi, r.clone());
        r
    }

    fn compute_layout(&mut self, tdi: usize) -> Option<Layout> {
        let td = self.tds.get(tdi)?;
        let (fs, fc, bitfield, parent_tarr, flags) =
            (td.fields_start, td.fields_count, td.bitfield, td.parent_tarr, td.flags);
        // Explicit layout: offsets come from [FieldOffset] attributes — not rebuildable.
        if flags != u32::MAX && flags & 0x18 == 0x10 {
            return None;
        }
        if bitfield & 2 != 0 {
            // enum: no instance fields; unboxed size 4.
            return Some(Layout { end: 0x14, align: 4, offsets: Vec::new() });
        }
        let mut off = if bitfield & 1 != 0 {
            // struct / value type: boxed offsets start at 0x10.
            0x10
        } else {
            // class: continue at the aligned end of the base class.
            let mut start = 0x10u32;
            if parent_tarr != u32::MAX {
                if let Some((ik, idata, _)) = self.m.il2cpp_type(parent_tarr as usize) {
                    if matches!(ik, 0x11 | 0x12 | 0x1C) && (idata as usize) != tdi {
                        if let Some(base) = self.type_layout(idata as usize) {
                            start = base.end.max(0x10);
                            start = (start + 7) & !7;
                        }
                    }
                }
            }
            start
        };
        let rows = Self::instance_rows(self.m, td);
        let mut offsets = Vec::new();
        let mut maxalign = 1u32;
        for (_row, fti, static_) in rows {
            if static_ {
                continue;
            }
            let (size, align) = self.type_size(fti)?;
            let align = if matches!(size, 1 | 2 | 4 | 8) { size } else { align.clamp(1, 8) };
            off = (off + align - 1) & !(align - 1);
            offsets.push(off);
            off = off.checked_add(size)?;
            maxalign = maxalign.max(align);
        }
        let end = (off + maxalign - 1) & !(maxalign - 1);
        Some(Layout { end, align: maxalign, offsets })
    }
}

/// Type name for an Il2CppType index, including the `&` suffix for byref types (the
/// byref flag lives in the typearr entry's flag byte bit6, not in the kind byte).
pub fn type_name(m: &Meta, tds: &[Td], ti: u32, depth: u32) -> String {
    let base = type_name_inner(m, tds, ti, depth);
    let byref = m
        .il2cpp_type_flags(ti as usize)
        .map(|f| f & 0x40 != 0)
        .unwrap_or(false);
    if byref {
        format!("{}&", base)
    } else {
        base
    }
}

/// Type name for an Il2CppType index (recursion depth-limited; class names via `tds`).
pub fn type_name_inner(m: &Meta, tds: &[Td], ti: u32, depth: u32) -> String {
    if depth > 8 {
        return "object".into();
    }
    let Some((kind, data, _attrs)) = m.il2cpp_type(ti as usize) else {
        return "object".into();
    };
    match kind {
        0x01 => "void".into(),
        0x02 => "bool".into(),
        0x03 => "char".into(),
        0x04 => "sbyte".into(),
        0x05 => "byte".into(),
        0x06 => "short".into(),
        0x07 => "ushort".into(),
        0x08 => "int".into(),
        0x09 => "uint".into(),
        0x0A => "long".into(),
        0x0B => "ulong".into(),
        0x0C => "float".into(),
        0x0D => "double".into(),
        0x0E | 0x18 | 0x19 | 0x16 => match kind {
            0x0E => "string".into(),
            0x18 => "IntPtr".into(),
            0x19 => "UIntPtr".into(),
            0x16 => "TypedReference".into(),
            _ => "object".into(),
        },
        0x11 | 0x12 | 0x1C => {
            // CLASS/VALUETYPE/OBJECT: data = typeDefIndex (mhy packs the tdi here)
            let tdi = data as usize;
            match tds.get(tdi) {
                Some(t) => match (t.namespace.as_str(), t.name.as_str()) {
                    // Only System.Object / System.String take the C# keyword form; other
                    // assemblies have their own `Object` / `String` types (UnityEngine.Object
                    // etc.) that must keep their qualified name.
                    ("System", "Object") => "object".into(),
                    ("System", "String") => "string".into(),
                    ("", n) => n.to_string(),
                    (ns, n) => format!("{}.{}", ns, n),
                },
                None => "object".into(),
            }
        }
        0x15 => {
            // GENERICINST: data = genericClass index; the def tdi lives at genericClasses[data]
            let _ = data;
            "object".into() // refined below via generic_classes when wired
        }
        0x1D => {
            // SZARRAY: data = Il2CppType* (VA into .rdata)
            let et = ptr_type_index(m, data);
            match et {
                Some(t) => format!("{}[]", type_name(m, tds, t, depth + 1)),
                None => "object[]".into(),
            }
        }
        0x14 => {
            let et = ptr_type_index(m, data);
            match et {
                Some(t) => format!("{}[,]", type_name(m, tds, t, depth + 1)),
                None => "Array".into(),
            }
        }
        0x0F => {
            let et = ptr_type_index(m, data);
            match et {
                Some(t) => format!("{}*", type_name(m, tds, t, depth + 1)),
                None => "object*".into(),
            }
        }
        0x10 => {
            // BYREF: `T&` (the runtime parameter table has no per-param flags column, so we
            // cannot tell `ref` from `out`; render the byref type form only).
            let et = ptr_type_index(m, data);
            match et {
                Some(t) => format!("{}&", type_name(m, tds, t, depth + 1)),
                None => "object&".into(),
            }
        }
        _ => format!("object/*k{kind:#x}*/"),
    }
}

/// Map an Il2CppType `data` back to its typearr index. `data` is a 32-bit truncated
/// VA pointing at a 16-byte entry in .rdata (the top bits of the VA are dropped).
fn ptr_type_index(m: &Meta, data: u32) -> Option<u32> {
    let (va_start, fs, sz) = m.rdata;
    let va = (m.image_base & 0xFFFF_FFFF_0000_0000) | data as u64;
    if va < va_start || va >= va_start + sz as u64 {
        return None;
    }
    let off = fs + (va - va_start) as usize;
    if off < m.typearr || (off - m.typearr) % 16 != 0 {
        return None;
    }
    Some(((off - m.typearr) / 16) as u32)
}

/// Declaration keyword. Preferred path: the decoded flags/bitfield columns
/// (Il2CppDumper rule order: interface -> enum -> struct -> class). Fallback for
/// generations without the columns: the legacy parent-chain inference.
fn type_kind(m: &Meta, tds: &[Td], td: &Td) -> &'static str {
    if td.flags != u32::MAX {
        if td.flags & 0x20 != 0 {
            return "interface";
        } else if td.bitfield & 2 != 0 {
            return "enum";
        } else if td.bitfield & 1 != 0 {
            return "struct";
        }
        return "class";
    }
    let parent_tarr = td.parent_tarr;
    if parent_tarr != u32::MAX {
        if let Some((kind, data, _)) = m.il2cpp_type(parent_tarr as usize) {
            if matches!(kind, 0x11 | 0x12) {
                if let Some(t) = tds.get(data as usize) {
                    match (t.namespace.as_str(), t.name.as_str()) {
                        ("System", "Enum") => return "enum",
                        ("System", "ValueType") => return "struct",
                        _ => return "class",
                    }
                }
            }
        }
    }
    "interface"
}

/// Type modifiers exactly as Il2CppDecompiler.cs renders them (else-if chain:
/// abstract+sealed collapses to `static`; interfaces get no abstract/sealed).
fn type_modifiers(td: &Td) -> String {
    let f = td.flags;
    let mut s = String::new();
    match f & 0x7 {
        1 | 2 => s.push_str("public "),
        3 => s.push_str("private "),
        4 => s.push_str("protected "),
        7 => s.push_str("protected internal "),
        _ => s.push_str("internal "),
    }
    if f & 0x80 != 0 && f & 0x100 != 0 {
        s.push_str("static ");
    } else if f & 0x20 == 0 && f & 0x80 != 0 {
        s.push_str("abstract ");
    } else if td.bitfield & 1 == 0 && td.bitfield & 2 == 0 && f & 0x100 != 0 {
        s.push_str("sealed ");
    }
    s
}

/// Rendered base-class name, or None when the parent is absent / renders as object.
fn base_name(m: &Meta, tds: &[Td], parent_tarr: u32) -> Option<String> {
    if parent_tarr == u32::MAX {
        return None;
    }
    let (kind, data, _) = m.il2cpp_type(parent_tarr as usize)?;
    if !matches!(kind, 0x11 | 0x12) {
        return None;
    }
    let t = tds.get(data as usize)?;
    match (t.namespace.as_str(), t.name.as_str()) {
        ("System", "Object") => None,
        (_, n) if t.namespace.is_empty() => Some(n.to_string()),
        (_, n) => Some(format!("{}.{}", t.namespace, n)),
    }
}

fn method_modifiers(f: u16) -> String {
    let mut s = String::new();
    match f & 0x7 {
        1 => s.push_str("private "),
        3 => s.push_str("internal "),
        4 => s.push_str("protected "),
        5 => s.push_str("protected internal "),
        6 => s.push_str("public "),
        _ => {}
    }
    if f & 0x10 != 0 {
        s.push_str("static ");
    }
    if f & 0x400 != 0 {
        s.push_str("abstract ");
    } else if f & 0x40 != 0 {
        if f & 0x100 != 0 && f & 0x80 == 0 {
            s.push_str("sealed override ");
        } else if f & 0x80 == 0 {
            s.push_str("virtual ");
        } else {
            s.push_str("override ");
        }
    }
    if f & 0x2000 != 0 {
        s.push_str("extern ");
    }
    s
}

fn field_modifiers(attrs: u16) -> String {
    let mut s = String::new();
    match attrs & 0x7 {
        1 => s.push_str("private "),
        3 => s.push_str("internal "),
        4 => s.push_str("protected "),
        5 => s.push_str("protected internal "),
        6 => s.push_str("public "),
        _ => {}
    }
    if attrs & 0x40 != 0 {
        s.push_str("const ");
    } else {
        if attrs & 0x10 != 0 {
            s.push_str("static ");
        }
        if attrs & 0x20 != 0 {
            s.push_str("readonly ");
        }
    }
    s
}

/// C# literal for a field default value (enum members, const fields).
/// Values live in the shared blob, decoded according to the value's Il2CppType kind —
/// the same dispatch the runtime uses at 0x1404C7D6B (kind in 2..=0xc -> primitive).
/// Returns `Err(kind)` for kinds we cannot render statically (string/valuetype/class).
fn default_literal(m: &Meta, tix: u32, dataoff: i32, unsigned: bool) -> Result<String, u8> {
    let Some((kind, _data, _attrs)) = m.il2cpp_type(tix as usize) else {
        return Err(0);
    };
    match kind {
        0x02 => {
            let b = m.default_value_bytes(dataoff, 1).ok_or(0)?;
            Ok(if b[0] != 0 { "true".into() } else { "false".into() })
        }
        0x03 => {
            let b = m.default_value_bytes(dataoff, 2).ok_or(0)?;
            let v = u16::from_le_bytes(b.try_into().unwrap());
            Ok(format!("'\\u{:04X}'", v))
        }
        0x04 => {
            let b = m.default_value_bytes(dataoff, 1).ok_or(0)?;
            if unsigned { Ok(format!("{}", b[0])) } else { Ok(format!("{}", b[0] as i8)) }
        }
        0x05 => {
            let b = m.default_value_bytes(dataoff, 1).ok_or(0)?;
            Ok(format!("{}", b[0]))
        }
        0x06 => {
            let b = m.default_value_bytes(dataoff, 2).ok_or(0)?;
            if unsigned { Ok(format!("{}", u16::from_le_bytes(b.try_into().unwrap()))) }
            else { Ok(format!("{}", i16::from_le_bytes(b.try_into().unwrap()))) }
        }
        0x07 => {
            let b = m.default_value_bytes(dataoff, 2).ok_or(0)?;
            Ok(format!("{}", u16::from_le_bytes(b.try_into().unwrap())))
        }
        0x08 => {
            let b = m.default_value_bytes(dataoff, 4).ok_or(0)?;
            if unsigned { Ok(format!("{}", u32::from_le_bytes(b.try_into().unwrap()))) }
            else { Ok(format!("{}", i32::from_le_bytes(b.try_into().unwrap()))) }
        }
        0x09 => {
            let b = m.default_value_bytes(dataoff, 4).ok_or(0)?;
            Ok(format!("{}", u32::from_le_bytes(b.try_into().unwrap())))
        }
        0x0A => {
            let b = m.default_value_bytes(dataoff, 8).ok_or(0)?;
            if unsigned { Ok(format!("{}", u64::from_le_bytes(b.try_into().unwrap()))) }
            else { Ok(format!("{}", i64::from_le_bytes(b.try_into().unwrap()))) }
        }
        0x0B => {
            let b = m.default_value_bytes(dataoff, 8).ok_or(0)?;
            Ok(format!("{}", u64::from_le_bytes(b.try_into().unwrap())))
        }
        0x0C => {
            let b = m.default_value_bytes(dataoff, 4).ok_or(0)?;
            let v = f32::from_le_bytes(b.try_into().unwrap());
            Ok(if v.is_nan() { "float.NaN".into() }
               else if v.is_infinite() { if v > 0.0 { "float.PositiveInfinity".into() } else { "float.NegativeInfinity".into() } }
               else if v.fract() == 0.0 { format!("{:.1}f", v) }
               else { format!("{}f", v) })
        }
        0x0D => {
            let b = m.default_value_bytes(dataoff, 8).ok_or(0)?;
            let v = f64::from_le_bytes(b.try_into().unwrap());
            Ok(if v.is_nan() { "double.NaN".into() }
               else if v.is_infinite() { if v > 0.0 { "double.PositiveInfinity".into() } else { "double.NegativeInfinity".into() } }
               else if v.fract() == 0.0 { format!("{:.1}", v) }
               else { format!("{}", v) })
        }
        0x0E => {
            // String default: {u32 byte-length, UTF-8 bytes} in the shared blob.
            let lb = m.default_value_bytes(dataoff, 4).ok_or(0x0E)?;
            let len = u32::from_le_bytes(lb.try_into().unwrap()) as usize;
            if len > 4096 {
                return Err(0x0E);
            }
            let bytes = m
                .default_value_bytes(dataoff + 4, len)
                .ok_or(0x0E)?;
            let s = String::from_utf8_lossy(bytes);
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c => out.push(c),
                }
            }
            out.push('"');
            Ok(out)
        }
        0x0F | 0x12 => Ok("null".into()),
        other => Err(other),
    }
}

/// Full dump: write `dump.cs` (Il2CppDumper style) and `script.json`.
pub fn dump<W: Write, WJ: Write>(m: &Meta, w: &mut W, wj: &mut WJ) -> Result<(usize, usize, usize)> {
    let (tds, mds) = collect(m);
    // group methods by declaring type (method_start order), hidden rows keep slots
    let mut per_type: Vec<Vec<usize>> = vec![Vec::new(); tds.len()];
    // derive method counts from methodStart monotonic order
    let mut counts = vec![0u32; tds.len()];
    {
        let mut sorted: Vec<u32> = tds.iter().map(|t| t.method_start).filter(|&s| s != u32::MAX).collect();
        sorted.sort_unstable();
        sorted.dedup();
        for (i, t) in tds.iter().enumerate() {
            if t.method_start == u32::MAX {
                continue;
            }
            let next = match sorted.binary_search(&t.method_start) {
                Ok(k) => sorted.get(k + 1).copied(),
                Err(_) => None,
            };
            counts[i] = next.map(|n| n.saturating_sub(t.method_start)).unwrap_or(0);
        }
    }
    for (gmi, md) in mds.iter().enumerate() {
        let decl = md.decl as usize;
        if decl < per_type.len() {
            per_type[decl].push(gmi);
        }
    }

    let mut ntypes = 0usize;
    let mut nfields = 0usize;
    let mut nmethods = 0usize;
    // Diagnostics for the "never silently emit placeholders" rule (REQUIREMENTS R3/R4).
    let mut unresolved_iface_runs = 0usize;
    let mut unresolved_params = 0usize;
    let mut unresolved_offsets = 0usize;
    let mut computed_offsets = 0usize;
    let mut static_offsets = 0usize;
    let mut defaults_rendered = 0usize;
    let mut defaults_unrendered = 0usize;

    // Distinct interface-offsets starts, computed once. This used to be rebuilt and
    // re-sorted inside the per-type loop, which made the whole dump O(types^2 log
    // types): 88,872 x (collect 88,872 u32 + sort) measured at ~2.7 ms/iteration and
    // was the dominant cost of a 3m15s run.
    let mut iface_starts: Vec<u32> = tds.iter().filter_map(|t| t.iface_start).collect();
    iface_starts.sort_unstable();
    iface_starts.dedup();

    // script.json first (streamed); fill ScriptMethod from all methods
    let mut script_methods: Vec<(u64, String)> = Vec::with_capacity(mds.len());
    // File-scope sequential token for non-constructor methods (reference dumps number
    // them 0x06000001.. in TypeDefIndex/methodStart order; constructors get Token 0).
    let mut method_token: u32 = 0;
    let mut unresolved_props = 0usize;

    // Rebuilds instance field offsets from type structure (the dat carries no offset table).
    let mut layout_calc = LayoutCalc::new(m, &tds);
    for (i, td) in tds.iter().enumerate() {
        // Reference dumps emit nameless typeDefs as empty names (`class  : Object`) rather
        // than dropping them, so no name-based skip here: the row count already excludes
        // the all-sentinel padding tail.
        ntypes += 1;
        writeln!(w, "\n// Namespace: {}", td.namespace)?;
        // kind + extends clause; interface count = next distinct iface start (offsets
        // list includes interfaces inherited from bases)
        let kind = type_kind(m, &tds, td);
        let mut extends = String::new();
        if let Some(base) = base_name(m, &tds, td.parent_tarr) {
            extends.push_str(&format!(" : {base}"));
        }
        if let Some(iface_start) = td.iface_start {
            // NOTE(known limitation): the per-type interface *count* column has not been
            // located, so the run length is approximated by the next distinct start.
            // This over-reports whenever the following rows belong to other types.
            let span = match iface_starts.binary_search(&iface_start) {
                Ok(k) => iface_starts.get(k + 1).map_or(0, |n| n - iface_start),
                Err(_) => 0,
            };
            let mut emitted = 0usize;
            for r in iface_start..iface_start + span {
                let (t, _) = m.iface_entry(r);
                if t < 0 {
                    break;
                }
                // An interface entry is an Il2CppType reference: CLASS / VALUETYPE / GENERICINST.
                // Rows past the type's own run belong to other types and typically decode to an
                // OBJECT kind, which is how the old approximation emitted dozens of bogus
                // 'object' entries (e.g. 15,604 on one type).
                match m.il2cpp_type(t as usize) {
                    Some((k, _, _)) if matches!(k, 0x11 | 0x12 | 0x15) => {}
                    _ => break,
                }
                extends.push_str(&format!(", {}", type_name(m, &tds, t as u32, 0)));
                emitted += 1;
            }
            if emitted > 0 {
                // Rendered from the run-length approximation: the per-type count column has
                // not been located, so a list can include interfaces inherited from bases
                // (and, for aliased starts, entries belonging to a neighbouring type).
                unresolved_iface_runs += 1;
            }
        }
        writeln!(w, "{}{kind} {}{extends} // TypeDefIndex: {i}", type_modifiers(td), td.name)?;
        writeln!(w, "{{")?;
        // fields, natively from the full field table (per-row masked name + type)
        write!(w, "\t// Fields\n")?;
        if td.fields_start != u32::MAX {
            // Field offsets are rebuilt from type structure (the dat has no offset table).
            let lay = layout_calc.type_layout(i);
            let mut ordinal = 0usize;
            for k in 0..td.fields_count {
                let row = td.fields_start + k;
                let fname = m.field_name(row);
                let fti = m.field_type_idx(row);
                let (kind, _data, attrs) = m.il2cpp_type(fti as usize).unwrap_or((0, 0, 0));
                let _ = kind;
                let tn = type_name(m, &tds, fti, 0);
                let static_ = attrs & 0x10 != 0;
                let offset = if static_ {
                    None
                } else {
                    let o = lay.as_ref().and_then(|l| l.offsets.get(ordinal).copied());
                    ordinal += 1;
                    o
                };
                let tail = match offset {
                    Some(o) => format!(" // 0x{:X}", o),
                    None => String::new(),
                };
                // Const fields (enum members, literal constants) get their value from the
                // field default-value table (gap #7): `= 3` before the offset comment.
                let literal = if attrs & 0x40 != 0 {
                    // Enum members print their underlying value unsigned (reference-dump
                    // behaviour); plain primitive consts print signed.
                    let is_enum = {
                        let fti = m.field_type_idx(row);
                        match m.il2cpp_type(fti as usize) {
                            Some((0x11, tdi, _)) => tds
                                .get(tdi as usize)
                                .map(|t| t.bitfield & 2 != 0)
                                .unwrap_or(false),
                            _ => false,
                        }
                    };
                    match m.field_default(row) {
                        Some((dataoff, tix)) => match default_literal(m, tix, dataoff, is_enum) {
                            Ok(lit) => {
                                defaults_rendered += 1;
                                Some(lit)
                            }
                            Err(_) => {
                                defaults_unrendered += 1;
                                None
                            }
                        },
                        None => {
                            defaults_unrendered += 1;
                            None
                        }
                    }
                } else {
                    None
                };
                let value = match literal {
                    Some(l) => format!(" = {}", l),
                    None => String::new(),
                };
                writeln!(w, "\t{}{} {}{};{}", field_modifiers(attrs), tn, fname, value, tail)?;
                match offset {
                    Some(_) => computed_offsets += 1,
                    None if static_ => static_offsets += 1,
                    None => unresolved_offsets += 1,
                }
                nfields += 1;
            }
        }
        // Il2CppDumper section structure: Fields / Properties / Constructors / Methods.
        // The property table has not been located for this generation, so Properties is
        // emitted empty and counted (never silently faked).
        writeln!(w, "\n\t// Properties")?;
        unresolved_props += 1;
        writeln!(w, "\n\t// Constructors")?;
        for &gmi in &per_type[i] {
            let md = &mds[gmi];
            if md.name != ".ctor" && md.name != ".cctor" {
                continue;
            }
            let ret = type_name(m, &tds, md.ret_type, 0);
            let (params, n_unresolved) = self_params(m, &tds, md);
            unresolved_params += n_unresolved;
            // Constructors carry Token 0 in the reference dumps (tokens number the
            // non-constructor methods sequentially from 0x06000001 in file order).
            writeln!(
                w,
                "\t{}{} {}({}) {{ }} // RVA: 0x{:X} Token: 0x{:08X} Slot: {}",
                method_modifiers(md.flags),
                ret,
                md.name,
                params.join(", "),
                md.rva,
                0u32,
                md.slot
            )?;
            nmethods += 1;
            script_methods.push((
                m.image_base + md.rva as u64,
                if td.namespace.is_empty() {
                    format!("{}.{}", td.name, md.name)
                } else {
                    format!("{}.{}.{}", td.namespace, td.name, md.name)
                },
            ));
        }
        writeln!(w, "\n\t// Methods")?;
        for &gmi in &per_type[i] {
            let md = &mds[gmi];
            if md.name == ".ctor" || md.name == ".cctor" {
                continue;
            }
            let ret = type_name(m, &tds, md.ret_type, 0);
            let (params, n_unresolved) = self_params(m, &tds, md);
            unresolved_params += n_unresolved;
            method_token = method_token.wrapping_add(1);
            let token = 0x0600_0000u32 | method_token;
            writeln!(
                w,
                "\t{}{} {}({}) {{ }} // RVA: 0x{:X} Token: 0x{:08X} Slot: {}",
                method_modifiers(md.flags),
                ret,
                md.name,
                params.join(", "),
                md.rva,
                token,
                md.slot
            )?;
            nmethods += 1;
            script_methods.push((
                m.image_base + md.rva as u64,
                // Fully-qualified: the namespace is what disambiguates the 689 duplicated
                // simple class names in this build (an earlier version emitted the bare
                // class name, so a Ghidra import collided across namespaces).
                if td.namespace.is_empty() {
                    format!("{}.{}", td.name, md.name)
                } else {
                    format!("{}.{}.{}", td.namespace, td.name, md.name)
                },
            ));
        }
        writeln!(w, "}}")?;
    }

    write_script_json(wj, &script_methods)?;
    // Never emit placeholders silently (REQUIREMENTS R3/R4): every unresolved category is
    // reported here with its count so a consumer can judge the dump instead of trusting it.
    if computed_offsets > 0 || unresolved_offsets > 0 || static_offsets > 0 {
        eprintln!(
            "[warn] field offsets: {computed_offsets} computed by sequential layout (validated 97.9% core against the 6.4 reference), {unresolved_offsets} unresolved (explicit layout / not statically sizeable), {static_offsets} static fields have no offset (module-level static area is not derivable statically)"
        );
    }
    if defaults_rendered > 0 || defaults_unrendered > 0 {
        eprintln!(
            "[warn] default values: {defaults_rendered} rendered, {defaults_unrendered} const fields without a renderable default (string/valuetype/class kinds or missing row)"
        );
    }
    if unresolved_params > 0 {
        eprintln!(
            "[warn] parameter names/types unresolved: {unresolved_params} parameters emitted as 'object /*unresolved*/'"
        );
    }
    if unresolved_props > 0 {
        eprintln!(
            "[warn] property/event tables not located: {unresolved_props} types emitted with an empty Properties section"
        );
    }
    if unresolved_iface_runs > 0 {
        eprintln!(
            "[warn] interface lists for {unresolved_iface_runs} types use the run-length approximation (per-type count column not located); they may include inherited interfaces"
        );
    }
    Ok((ntypes, nfields, nmethods))
}

/// Returns the rendered parameter list plus how many entries are still placeholders.
fn self_params(m: &Meta, tds: &[Td], md: &Md) -> (Vec<String>, usize) {
    // Parameter definitions: 8-byte rows indexed by the method's global paramStart
    // (disassembled runtime accessor 0x1405297EE). Type index -> Il2CppType, name via the
    // shared string cipher.
    let mut out = Vec::new();
    if md.param_count == 0 {
        return (out, 0);
    }
    let mut unresolved = 0usize;
    for k in 0..md.param_count as u32 {
        let idx = md.param_start.wrapping_add(k);
        let tn = match m.param_type(idx) {
            Some(Some(ti)) => type_name(m, tds, ti, 0),
            Some(None) => "object".to_string(),
            None => {
                unresolved += 1;
                "object /*unresolved*/".to_string()
            }
        };
        let name = m.param_name(idx).unwrap_or_else(|| format!("arg{k}"));
        out.push(format!("{} {}", tn, name));
    }
    (out, unresolved)
}

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

pub fn write_script_json(w: &mut dyn Write, methods: &[(u64, String)]) -> std::io::Result<()> {
    writeln!(w, "{{")?;
    writeln!(w, "\"ScriptMethod\": [")?;
    for (i, (va, name)) in methods.iter().enumerate() {
        let comma = if i + 1 == methods.len() { "" } else { "," };
        writeln!(
            w,
            "  {{\"Address\": {}, \"Name\": \"{}\", \"Signature\": \"\", \"TypeSignature\": \"\"}}{comma}",
            va,
            json_escape(name)
        )?;
    }
    writeln!(w, "],")?;
    writeln!(w, "\"ScriptString\": [],")?;
    writeln!(w, "\"ScriptMetadata\": [],")?;
    writeln!(w, "\"ScriptMetadataMethod\": [],")?;
    writeln!(w, "\"Addresses\": [0, 0, 0]")?;
    writeln!(w, "}}")
}
