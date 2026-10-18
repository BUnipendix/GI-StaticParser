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
        let mut flags = (m.md_col(&p.md_flags, i) & 0xFFFF) as u16;
        // Sentinel 0xFF86: GI writes this for the Mono AOT marshalling wrappers
        // (`__Gen_Wrap_*`, 18,135 rows). Decoded verbatim it would render as
        // `abstract extern`, which is not valid C# and does not match the reference dump
        // (which prints them as plain `public`); the sentinel therefore maps to
        // MethodAttributes.Public (0x0006). Verified: all 18,135 rows sample as `__Gen_Wrap_*`.
        if flags == 0xFF86 {
            flags = 0x0006;
        }
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
            // CLASS: reference. GENERICINST/FNPTR: conservative reference size.
            0x12 | 0x15 | 0x1B => (8, 8),
            // VAR / MVAR (generic parameter): size depends on the instantiation and is NOT
            // statically knowable — the whole enclosing layout becomes unknown (the reference
            // dump prints ` // 0x0` for the fields of such types instead of offsets).
            0x13 | 0x1E => return None,
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
pub fn type_name(m: &Meta, tds: &[Td], parents: &[Option<u32>], ti: u32, depth: u32) -> String {
    let base = type_name_inner(m, tds, parents, ti, depth);
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
pub fn type_name_inner(m: &Meta, tds: &[Td], parents: &[Option<u32>], ti: u32, depth: u32) -> String {
    if depth > 8 {
        return "object".into();
    }
    let Some((kind, data, _attrs)) = m.il2cpp_type(ti as usize) else {
        return "object".into();
    };
    render_kind(m, tds, parents, kind, data, depth)
}

/// Render one Il2CppType from its already-decoded `(kind, data)` pair. Shared by the typearr
/// path and by generic-instance arguments (which live as standalone 16-byte structs in the
/// image, reachable only through the GenericInst array).
fn render_kind(m: &Meta, tds: &[Td], parents: &[Option<u32>], kind: u8, data: u32, depth: u32) -> String {
    match kind {
        0x01 => "System.Void".into(),
        0x02 => "System.Boolean".into(),
        0x03 => "System.Char".into(),
        0x04 => "System.SByte".into(),
        0x05 => "System.Byte".into(),
        0x06 => "System.Int16".into(),
        0x07 => "System.UInt16".into(),
        0x08 => "System.Int32".into(),
        0x09 => "System.UInt32".into(),
        0x0A => "System.Int64".into(),
        0x0B => "System.UInt64".into(),
        0x0C => "System.Single".into(),
        0x0D => "System.Double".into(),
        0x0E => "System.String".into(),
        0x16 => "System.TypedReference".into(),
        0x18 => "System.IntPtr".into(),
        0x19 => "System.UIntPtr".into(),
        0x11 | 0x12 | 0x1C => {
            // CLASS/VALUETYPE/OBJECT: data = typeDefIndex (mhy packs the tdi here).
            // Reference dumps always use the fully-qualified name (System.Object/System.String,
            // not the C# keywords).
            let tdi = data as usize;
            match tds.get(tdi) {
                Some(_) => joined_type_name(tds, parents, data, depth + 1),
                None => "System.Object".into(),
            }
        }
        0x15 => {
            // GENERICINST: data = generic-class index. The definition tdi and the argument
            // types come from the 8-byte rows in startup-metadata.dat plus the Il2CppGenericInst
            // struct array in the image (see engine::Meta::generic_instance).
            match generic_inst_name(m, tds, parents, data, depth) {
                Some(s) => s,
                None => "System.Object".into(),
            }
        }
        0x1D => match pointee_name(m, tds, parents, data, depth) {
            Some(e) => format!("{}[]", e),
            None => "System.Object[]".into(),
        },
        0x14 => match pointee_name(m, tds, parents, data, depth) {
            Some(e) => format!("{}[,]", e),
            None => "Array".into(),
        },
        0x0F => match pointee_name(m, tds, parents, data, depth) {
            Some(e) => format!("{}*", e),
            None => "System.Object*".into(),
        },
        0x10 => match pointee_name(m, tds, parents, data, depth) {
            Some(e) => format!("{}&", e),
            None => "System.Object&".into(),
        },
        _ => format!("object/*k{kind:#x}*/"),
    }
}

/// Render an Il2CppType given its *file offset* inside the image (used for generic-instance
/// arguments, which are standalone structs rather than typearr slots).
fn type_name_at(m: &Meta, tds: &[Td], parents: &[Option<u32>], off: usize, depth: u32) -> Option<String> {
    if depth > 10 {
        return None;
    }
    let (data, kind, flags) = m.il2cpp_type_at(off)?;
    let mut s = render_kind(m, tds, parents, kind, data, depth);
    if flags & 0x40 != 0 {
        s.push('&');
    }
    Some(s)
}

/// Resolve the pointee of an array/pointer/byref `data` field to a rendered name. `data` is a
/// truncated VA; the target may be a main-typearr entry or a standalone type struct.
fn pointee_name(m: &Meta, tds: &[Td], parents: &[Option<u32>], data: u32, depth: u32) -> Option<String> {
    if let Some(ti) = ptr_type_index(m, data) {
        let off = m.typearr + ti as usize * 16;
        return type_name_at(m, tds, parents, off, depth + 1);
    }
    let full = (m.image_base & 0xFFFF_FFFF_0000_0000) | data as u64;
    let off = m.va_to_file(full)?;
    type_name_at(m, tds, parents, off, depth + 1)
}

/// `System.Collections.Generic.List` + arity suffix -> without the suffix (reference dumps
/// print generic definitions with their arguments instead of the metadata arity suffix).
fn strip_generic_arity(s: &str) -> &str {
    if let Some(pos) = s.rfind('`') {
        if pos + 1 < s.len() && s[pos + 1..].bytes().all(|b| b.is_ascii_digit()) {
            return &s[..pos];
        }
    }
    s
}

/// Render a generic instantiation: `Def<Arg1,Arg2,...>` (reference dumps use the fully-qualified
/// definition name without arity and comma-separated arguments without spaces).
fn generic_inst_name(
    m: &Meta,
    tds: &[Td],
    parents: &[Option<u32>],
    g: u32,
    depth: u32,
) -> Option<String> {
    if depth > 8 {
        return None;
    }
    let (def_tdi, args) = m.generic_instance(g)?;
    let def = joined_type_name(tds, parents, def_tdi, depth + 1);
    let mut out = String::with_capacity(def.len() + 16);
    out.push_str(strip_generic_arity(&def));
    out.push('<');
    for (i, off) in args.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&type_name_at(m, tds, parents, *off, depth + 1)?);
    }
    out.push('>');
    Some(out)
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
pub fn type_kind(m: &Meta, tds: &[Td], td: &Td) -> &'static str {
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
    // Reference dumps NEVER print `sealed` or `static` on a type header (verified: 0
    // occurrences of `sealed class/struct`; static classes render as `abstract`).
    // Only `abstract` (TypeAttributes.Abstract, 0x80) survives.
    if f & 0x80 != 0 {
        s.push_str("abstract ");
    }
    s
}

/// Rendered base-class name, or None when the parent is absent / renders as object.
fn base_name(m: &Meta, tds: &[Td], parent_tarr: u32) -> Option<String> {
    if parent_tarr == u32::MAX {
        return None;
    }
    let (kind, data, _) = m.il2cpp_type(parent_tarr as usize)?;
    // GENERICINST parent (0x15): the reference dump prints the generic DEFINITION name with
    // its arity suffix (`: Task`1`, `: ParameterOverride`1`) — not the instantiated form.
    // Resolve the generic-class index to its definition typeDef and use the raw metadata name.
    if kind == 0x15 {
        let (def_tdi, _args) = m.generic_instance(data)?;
        return tds.get(def_tdi as usize).map(|t| t.name.clone());
    }
    // CLASS (0x12) / VALUETYPE (0x11) / OBJECT (0x1C): the parent of a direct System.Object
    // subclass is stored as an OBJECT-kind Il2CppType, so 0x1C must be accepted here
    // (otherwise thousands of classes lose their `: Object` base in the header).
    if !matches!(kind, 0x11 | 0x12 | 0x1C) {
        return None;
    }
    let t = tds.get(data as usize)?;
    // Reference dumps print the base type UNQUALIFIED (e.g. `: Object`, `: InvalidOperationException`).
    Some(t.name.clone())
}

/// Fully-qualified display name, Il2CppDumper style: nested types carry their declaring
/// type chain (`UnityEngine.UI.Selectable.Transition`), top-level types are namespace-qualified.
pub fn joined_type_name(tds: &[Td], parents: &[Option<u32>], tdi: u32, depth: u32) -> String {
    if depth > 16 {
        return String::new();
    }
    let Some(t) = tds.get(tdi as usize) else {
        return String::new();
    };
    if let Some(Some(p)) = parents.get(tdi as usize) {
        return format!("{}.{}", joined_type_name(tds, parents, *p, depth + 1), t.name);
    }
    if t.namespace.is_empty() {
        t.name.clone()
    } else {
        format!("{}.{}", t.namespace, t.name)
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
        // Reference dumps (empirically fitted against 120 (flags, mods) pairs):
        //  - private virtual  -> visibility only (explicit interface implementation)
        //  - final + new-slot -> visibility only (interface implementation: C# cannot write
        //    `sealed override` on a new-slot impl, and the reference dump prints just `public`)
        //  - final, reused slot -> `sealed override`
        //  - new-slot           -> `virtual`
        //  - reused slot        -> `override`
        if f & 0x7 != 1 {
            if f & 0x100 != 0 {
                if f & 0x20 == 0 {
                    s.push_str("virtual ");
                }
            } else if f & 0x20 != 0 {
                s.push_str("sealed override ");
            } else {
                s.push_str("override ");
            }
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

/// C# legacy "R" formatting for `System.Single` (what the reference dump prints):
/// up to 9 significant digits, trailing zeros trimmed (at least one fractional digit in
/// fixed form), fixed notation for exponents in [-4, 9), scientific otherwise with a
/// lower-case 'e' and a two-digit exponent, plus the `f` suffix.
fn format_csharp_single(v: f32) -> String {
    if v == 0.0 {
        return if v.is_sign_negative() { "-0.0f".into() } else { "0.0f".into() };
    }
    // 9 significant digits, scientific form: d.dddddddde±E
    let sci = format!("{:.8e}", v as f64);
    let (mant, exp) = sci.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let sign = if v < 0.0 { "-" } else { "" };
    let mant = mant.trim_start_matches('-');
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let frac = mant.split_once('.').map(|(_, f)| f).unwrap_or("");
    let trimmed = frac.trim_end_matches('0');
    if exp >= -4 && exp < 9 {
        // fixed notation
        let mut int_part = String::new();
        let mut fr_part = String::new();
        if exp >= 0 {
            let ip = (exp + 1) as usize;
            if ip <= digits.len() {
                int_part.push_str(&digits[..ip]);
                fr_part.push_str(&digits[ip..]);
            } else {
                int_part.push_str(&digits);
                int_part.push_str(&"0".repeat(ip - digits.len()));
            }
        } else {
            int_part.push('0');
            fr_part.push_str(&"0".repeat((-exp - 1) as usize));
            fr_part.push_str(&digits);
        }
        let fr_trim = fr_part.trim_end_matches('0');
        let fr_final = if fr_trim.is_empty() { "0" } else { fr_trim };
        format!("{}{}.{}f", sign, int_part, fr_final)
    } else {
        let e_sign = if exp < 0 { '-' } else { '+' };
        format!("{}{}.{}e{}{:02}f", sign, &digits[..1], if trimmed.is_empty() { "0" } else { trimmed }, e_sign, exp.abs())
    }
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
               else { format_csharp_single(v) })
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
/// Write `[Class]` lines for the custom attributes attached to `token` (member token space).
fn write_member_attrs<W: Write>(
    w: &mut W,
    attrs: &std::collections::HashMap<u32, Vec<String>>,
    token: u32,
) -> std::io::Result<()> {
    if let Some(list) = attrs.get(&token) {
        for a in list {
            writeln!(w, "\t[{}]", a)?;
        }
    }
    Ok(())
}

/// Write `[Class]` lines for a type declaration (no leading tab, C# top-level form).
fn write_type_attrs<W: Write>(
    w: &mut W,
    attrs: &std::collections::HashMap<u32, Vec<String>>,
    token: u32,
) -> std::io::Result<()> {
    if let Some(list) = attrs.get(&token) {
        for a in list {
            writeln!(w, "[{}]", a)?;
        }
    }
    Ok(())
}

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
    let vtable_slots = crate::vtable::compute_slots(m, &tds, &per_type, &mds);
    let n_slot = vtable_slots.iter().filter(|v| v.is_some()).count();
    eprintln!("[info] vtable slots: {} virtual methods resolved statically", n_slot);


    // ---- Custom attributes (7.1.0 data layer, docs/re/attr-decoding.md) ----
    // The pair table maps every attribute instance to its member token. Only attributes whose
    // class has a parameterless constructor can be written as the C# shorthand `[Name]`; the
    // rest need constructor arguments (the attribute argument blob is not recovered yet) and
    // are skipped with an explicit count — no arguments are invented.
    let mut attr_by_token: std::collections::HashMap<u32, Vec<String>> = std::collections::HashMap::new();
    let mut attrs_rendered = 0usize;
    let mut attrs_arg_required = 0usize;
    let mut attrs_unsupported = 0usize;
    let mut attrs_unmapped = 0usize;
    {
        let count = m.attribute_instance_count() as usize;
        let pairs = m.attribute_instance_tokens();
        attrs_unmapped = count.saturating_sub(pairs.len());
        let mut ctor0_cache: std::collections::HashMap<u32, bool> = std::collections::HashMap::new();
        for (inst, token) in pairs {
            let (kind, idx) = (token >> 24, token & 0x00FF_FFFF);
            let member_ok = match kind {
                0x02 => idx >= 1 && (idx as usize) <= tds.len(),
                0x04 => idx >= 1,
                0x06 => idx >= 1 && (idx as usize) <= mds.len(),
                0x08 => idx >= 1, // parameter attribute: not rendered (no place in the dump grammar)
                _ => false,
            };
            if !member_ok || kind == 0x08 {
                attrs_unsupported += 1;
                continue;
            }
            let Some(ti) = m.attribute_type_idx(inst) else { continue };
            let Some((ak, adata, _)) = m.il2cpp_type(ti as usize) else { continue };
            if ak != 0x12 {
                attrs_unsupported += 1;
                continue;
            }
            let tdi = adata as usize;
            let Some(td) = tds.get(tdi) else {
                attrs_unsupported += 1;
                continue;
            };
            let ctor0 = *ctor0_cache.entry(adata).or_insert_with(|| {
                per_type
                    .get(tdi)
                    .map(|ms| {
                        ms.iter().any(|&g| mds[g].name == ".ctor" && mds[g].param_count == 0)
                    })
                    .unwrap_or(false)
            });
            if !ctor0 {
                attrs_arg_required += 1;
                continue;
            }
            let mut name = td.name.clone();
            if let Some(stripped) = name.strip_suffix("Attribute") {
                name = stripped.to_string();
            }
            if name.is_empty() {
                continue;
            }
            attr_by_token.entry(token).or_default().push(name);
            attrs_rendered += 1;
        }
    }
    let mut ntypes = 0usize;
    let mut nfields = 0usize;
    let mut nmethods = 0usize;
    // Diagnostics for the "never silently emit placeholders" rule (REQUIREMENTS R3/R4).
    let mut unresolved_iface_runs = 0usize;
    let mut unresolved_iface_generic = 0usize;
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

    // Nested-type parent map (child typeDef index -> declaring typeDef index), built from the
    // typeDef nestedTypesStart/Count columns and the nested-types table (u32 typeDef indexes).
    let mut parents: Vec<Option<u32>> = vec![None; tds.len()];
    for i in 0..tds.len() {
        let (Some(start), Some(count)) = (m.td_nested_start(i), m.td_nested_count(i)) else {
            continue;
        };
        if start == 0xFFFF || count == 0 {
            continue;
        }
        for k in 0..count {
            if let Some(child) = m.nested_types_at(start + k) {
                if (child as usize) < parents.len() {
                    parents[child as usize] = Some(i as u32);
                }
            }
        }
    }

    // script.json (Il2CppDumper StructGenerator-compatible): one entry per method that has a
    // code pointer, in method-table order. Built up-front because it needs the parent map and
    // the struct-name dictionary (see src/script_json.rs for the reference mapping).
    let mut script_methods: Vec<crate::script_json::ScriptMethod> = Vec::with_capacity(mds.len());
    // Il2CppDumper names metadata-method usages as `Method$<TypeDefName>.<name>()`; build that
    // map for every method row (not only the ones that get a ScriptMethod entry).
    let mut script_method_names: Vec<Option<String>> = vec![None; mds.len()];
    {
        let namer = crate::script_json::Namer { m, tds: &tds, parents: &parents };
        let structs = namer.struct_names();
        for ti in 0..tds.len() {
            for &gmi in &per_type[ti] {
                let tname = namer.typedef_name(ti, 0);
                script_method_names[gmi] = Some(format!("Method${}.{}()", tname, mds[gmi].name));
                if let Some(entry) = namer.method_entry(&structs, ti, &mds[gmi]) {
                    script_methods.push(entry);
                }
            }
        }
    }

    // Metadata usages (docs/re/71-usage-tables.md): kind 5 -> string literal, kind 3 -> method
    // def. 7.1 stores the handles in the metadata body, so the reference "usage slot Address"
    // does not exist statically and is written as 0; the payload fields are exact.
    let ut = crate::usage_tables::UsageTables::new(&m.header, m.body);
    let mut script_strings: Vec<crate::script_json::ScriptString> = Vec::new();
    let mut script_meta_methods: Vec<crate::script_json::ScriptMetadataMethod> = Vec::new();
    let mut literal_cache: Vec<Option<String>> = vec![None; crate::usage_tables::LITERAL_COUNT];
    let mut kind_counts = [0usize; 8];
    let (usage_groups, usage_pairs, _) = ut.scan_usages(|kind, idx| {
        kind_counts[kind as usize] += 1;
        match kind {
            5 => {
                let i = idx as usize;
                let cached = literal_cache.get_mut(i).map(|slot| {
                    if slot.is_none() {
                        *slot = ut.literal(idx);
                    }
                    slot.clone().unwrap_or_default()
                });
                script_strings.push(crate::script_json::ScriptString {
                    address: 0,
                    value: cached.unwrap_or_default(),
                });
            }
            3 => {
                let i = idx as usize;
                let name = script_method_names
                    .get(i)
                    .and_then(|n| n.clone())
                    .unwrap_or_else(|| format!("Method$method_{idx}"));
                script_meta_methods.push(crate::script_json::ScriptMetadataMethod {
                    address: 0,
                    name,
                    method_address: m.method_rva(i) as u64,
                });
            }
            _ => {}
        }
    });
    eprintln!(
        "[info] metadata usages: {usage_groups} groups / {usage_pairs} pairs; ScriptString {} (kind5) / ScriptMetadataMethod {} (kind3); unresolved kinds: kind6={} kind7={} kind1={} kind0={} kind4={}",
        script_strings.len(),
        script_meta_methods.len(),
        kind_counts[6], kind_counts[7], kind_counts[1], kind_counts[0], kind_counts[4]
    );
    let mut unresolved_props = 0usize;
    let mut synthesized_props = 0usize;
    let mut props_synth_types = 0usize;
    let mut real_props = 0usize;
    let mut real_prop_types = 0usize;
    let mut unnamed_props = 0usize;

    // Rebuilds instance field offsets from type structure (the dat carries no offset table).
    let mut layout_calc = LayoutCalc::new(m, &tds);
    for (i, td) in tds.iter().enumerate() {
        // Reference dumps emit nameless typeDefs as empty names (`class  : Object`) rather
        // than dropping them, so no name-based skip here: the row count already excludes
        // the all-sentinel padding tail.
        ntypes += 1;
        writeln!(w, "\n// Namespace: {}", td.namespace)?;
        write_type_attrs(w, &attr_by_token, 0x0200_0001u32.wrapping_add(i as u32))?;
        // kind + extends clause (Il2CppDumper rules: value types/enums/interfaces print no
        // base; base is unqualified; interfaces are qualified; every list is ` : a, b, c`).
        let kind = type_kind(m, &tds, td);
        let mut extends: Vec<String> = Vec::new();
        let is_value_like = td.bitfield & 3 != 0; // bit0 IsValueType, bit1 IsEnum
        if kind == "class" && !is_value_like {
            if let Some(base) = base_name(m, &tds, td.parent_tarr) {
                extends.push(base);
            }
        }
        // Il2CppDumper prints NO interface list for enums (verified: 0 enum lines with ` : `
        // in the 6.4 reference dump, while 669 structs do print interfaces). Enums implicitly
        // implement IComparable/IFormattable/IConvertible in the metadata, and echoing those
        // would add ~8k spurious interface lists.
        if let Some(iface_start) = td.iface_start.filter(|_| kind != "enum") {
            // Exact per-type interface count when the profile has the column (7.1: u8@0x42+0xA2);
            // otherwise fall back to the next-distinct-start run length (over-reports).
            let span = match m.td_iface_count(i) {
                Some(c) => c,
                None => match iface_starts.binary_search(&iface_start) {
                    Ok(k) => iface_starts.get(k + 1).map_or(0, |n| n - iface_start),
                    Err(_) => 0,
                },
            };
            if m.td_iface_count(i).is_none() {
                unresolved_iface_runs += 1;
            }
            let _ = &iface_starts;
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
                let (entry_kind, entry_data) = match m.il2cpp_type(t as usize) {
                    Some((k, d, _)) if matches!(k, 0x11 | 0x12 | 0x15) => (k, d),
                    _ => break,
                };
                // Approximation guard: a System.Object entry means we walked past this type's
                // own run (Object is never an interface).
                if matches!(m.il2cpp_type(t as usize), Some((0x12, d, _)) if tds
                    .get(d as usize)
                    .map(|x| x.namespace == "System" && x.name == "Object")
                    .unwrap_or(false))
                {
                    break;
                }
                // Generic-instantiated interfaces (IEquatable<T>, ...) render through the
                // startup-metadata generic-class rows; only count them as unresolved when that
                // table is missing (no startup-metadata.dat on hand).
                if entry_kind == 0x15 && m.generic_instance(entry_data).is_none() {
                    unresolved_iface_generic += 1;
                    continue;
                }
                extends.push(type_name(m, &tds, &parents, t as u32, 0));
                emitted += 1;
            }
            if emitted > 0 && m.td_iface_count(i).is_none() {
                // Only the run-length fallback can over-report; the count column is exact.
                unresolved_iface_runs += 1;
            }
        }
        let extends_str = if extends.is_empty() {
            String::new()
        } else {
            format!(" : {}", extends.join(", "))
        };
        let display = joined_type_name(&tds, &parents, i as u32, 0);
        writeln!(
            w,
            "{}{kind} {}{extends_str} // TypeDefIndex: {i}",
            type_modifiers(td),
            display
        )?;
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
                let tn = type_name(m, &tds, &parents, fti, 0);
                let static_ = attrs & 0x10 != 0;
                let offset = if static_ {
                    None
                } else {
                    let o = lay.as_ref().and_then(|l| l.offsets.get(ordinal).copied());
                    ordinal += 1;
                    o
                };
                // Offset comment rules (verified against the 6.4 reference dump):
                //  - literal/const fields (enum members included) always print ` // 0x0`
                //    (they occupy no instance storage);
                //  - `<PrivateImplementationDetails>` statics print ` // 0x0` (fixed-address);
                //  - other statics: module static layout is runtime-assigned → no comment;
                //  - instance fields: sequential layout offset.
                let tail = if attrs & 0x40 != 0 {
                    " // 0x0".to_string()
                } else {
                    match offset {
                        Some(o) => format!(" // 0x{:x}", o),
                        None if td.name.starts_with("<PrivateImplementationDetails>") => {
                            " // 0x0".to_string()
                        }
                        // Instance layout of a generic definition is not statically known once a
                        // field's type is a generic parameter (e.g. ValueTuple<T1> has
                        // `public T1 Item1;` at 0x0 in the reference dump, not a computed
                        // offset). Reference dumps print ` // 0x0` for those fields.
                        None if !static_ && td.name.contains('`') => " // 0x0".to_string(),
                        None => String::new(),
                    }
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
                // [NonSerialized] / [CompilerGenerated]: reference dumps print these two
                // attribute lines on fields. NonSerialized maps to the FieldAttributes
                // NotSerialized bit (0x80) carried in the field type's attrs word;
                // CompilerGenerated marks C# auto-property backing fields (verified 1:1 in the
                // 6.4 reference: 8,538 attribute lines == 8,538 k__BackingField fields). The
                // custom-attribute range table is not available, so only these derivable ones
                // are emitted (explicitly derived, never invented).
                write_member_attrs(w, &attr_by_token, 0x0400_0001u32.wrapping_add(row))?;
                if attrs & 0x80 != 0 {
                    writeln!(w, "\t[NonSerialized]")?;
                }
                if fname.contains("k__BackingField") {
                    writeln!(w, "\t[CompilerGenerated]")?;
                }
                // [FixedAddressValueType]: the reference dump prints it before EVERY field of
                // the compiler-generated `<PrivateImplementationDetails>` types (and nowhere
                // else) — verified 1:1 per type in 6.4 (583/583 and 310/310 fields).
                if td.name.starts_with("<PrivateImplementationDetails>") {
                    writeln!(w, "\t[FixedAddressValueType]")?;
                }
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
        // 7.1: the REAL property-definition table is decoded from the metadata body
        // (profile.property_defs, see src/derive/layout71.rs for the disassembly evidence):
        // the typeDef row gives propertyStart/propertyCount and each 10-byte property row
        // carries the packed name plus per-type getter/setter method indexes. Rows are emitted
        // in metadata (declaration) order. Generations without the table fall back to the old
        // synthesis from `get_X` / `set_X` accessor methods.
        writeln!(w, "\n\t// Properties")?;
        let accessor_mods = |flags: u16| -> String {
            method_modifiers(flags)
                .split_whitespace()
                .filter(|w| !matches!(*w, "virtual" | "override" | "abstract" | "extern" | "new" | "sealed" | "final" | "unsafe"))
                .map(|w| format!("{} ", w))
                .collect::<String>()
        };
        let vis_of = |m: &String| -> String {
            m.split_whitespace()
                .find(|w| matches!(*w, "private" | "protected" | "internal" | "public"))
                .map(|w| format!("{} ", w))
                .unwrap_or_default()
        };
        if let (Some(prop_start), Some(prop_count)) = (m.td_prop_start(i), m.td_prop_count(i)) {
            let mut emitted = 0usize;
            for row in prop_start..prop_start + prop_count {
                let Some((name_idx, getter, setter)) = m.property_row(row) else {
                    unresolved_props += 1;
                    continue;
                };
                let get_gmi = getter.and_then(|k| per_type[i].get(k as usize).copied());
                let set_gmi = setter.and_then(|k| per_type[i].get(k as usize).copied());
                if getter.is_some() && get_gmi.is_none() {
                    unresolved_props += 1;
                }
                if setter.is_some() && set_gmi.is_none() {
                    unresolved_props += 1;
                }
                if get_gmi.is_none() && set_gmi.is_none() {
                    unresolved_props += 1;
                    continue;
                }
                let name = m.decode_str(name_idx);
                if name.is_empty() {
                    unnamed_props += 1;
                }
                let ptype = if let Some(g) = get_gmi {
                    type_name(m, &tds, &parents, mds[g].ret_type, 0)
                } else if let Some(s) = set_gmi {
                    let smd = &mds[s];
                    if smd.param_count == 0 {
                        unresolved_props += 1;
                        "System.Object".to_string()
                    } else {
                        let pidx = smd.param_start.wrapping_add(smd.param_count as u32 - 1);
                        match m.param_type(pidx) {
                            Some(Some(ti)) => type_name(m, &tds, &parents, ti, 0),
                            _ => {
                                unresolved_props += 1;
                                "System.Object".to_string()
                            }
                        }
                    }
                } else {
                    unresolved_props += 1;
                    continue;
                };
                let owner_mods = if let Some(g) = get_gmi {
                    accessor_mods(mds[g].flags)
                } else if let Some(s) = set_gmi {
                    accessor_mods(mds[s].flags)
                } else {
                    String::new()
                };
                let owner_vis = vis_of(&owner_mods);
                let mut acc = String::new();
                if let Some(g) = get_gmi {
                    let extra = vis_of(&accessor_mods(mds[g].flags));
                    if extra != owner_vis && !extra.is_empty() {
                        acc.push_str(&extra);
                    }
                    acc.push_str("get; ");
                }
                if let Some(s) = set_gmi {
                    let extra = vis_of(&accessor_mods(mds[s].flags));
                    if extra != owner_vis && !extra.is_empty() {
                        acc.push_str(&extra);
                    }
                    acc.push_str("set; ");
                }
                writeln!(w, "\t{}{} {} {{ {} }}", owner_mods, ptype, name, acc.trim_end())?;
                emitted += 1;
            }
            if emitted > 0 {
                real_props += emitted;
                real_prop_types += 1;
            }
        } else {
            #[derive(Clone)]
            struct PropSynth {
                name: String,
                ptype: String,
                get_mods: Option<String>,
                set_mods: Option<String>,
                order: usize,
            }
            let mut props: Vec<PropSynth> = Vec::new();
            let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for &gmi in &per_type[i] {
                let md = &mds[gmi];
                let (is_get, prop) = if let Some(rest) = md.name.strip_prefix("get_") {
                    // Indexers (e.g. `get_Chars(int)`) are properties too: the reference dump
                    // prints them with the plain property name and no parameter list
                    // (`public System.Char Chars { get; }`), so any parameter count is accepted.
                    (true, rest)
                } else if let Some(rest) = md.name.strip_prefix("set_") {
                    if md.param_count == 0 {
                        continue;
                    }
                    (false, rest)
                } else {
                    continue;
                };
                if prop.is_empty() || prop.starts_with("Item") && false {
                    continue;
                }
                let ptype = if is_get {
                    type_name(m, &tds, &parents, md.ret_type, 0)
                } else {
                    // The property type is the setter's LAST parameter (indexers carry the
                    // index parameters before the value).
                    let pidx = md.param_start.wrapping_add(md.param_count as u32 - 1);
                    match m.param_type(pidx) {
                        Some(Some(ti)) => type_name(m, &tds, &parents, ti, 0),
                        _ => continue,
                    }
                };
                // Property-level modifier words (accessor-only words are dropped; static kept).
                let mods = method_modifiers(md.flags)
                    .split_whitespace()
                    .filter(|w| !matches!(*w, "virtual" | "override" | "abstract" | "extern" | "new" | "sealed" | "final" | "unsafe"))
                    .map(|w| format!("{} ", w))
                    .collect::<String>();
                if let Some(&pi) = index.get(prop) {
                    if is_get {
                        props[pi].get_mods = Some(mods);
                        props[pi].ptype = ptype;
                    } else {
                        props[pi].set_mods = Some(mods);
                    }
                } else {
                    index.insert(prop.to_string(), props.len());
                    let (gm, sm) = if is_get {
                        (Some(mods), None)
                    } else {
                        (None, Some(mods))
                    };
                    props.push(PropSynth {
                        name: prop.to_string(),
                        ptype,
                        get_mods: gm,
                        set_mods: sm,
                        order: props.len(),
                    });
                }
            }
            props.sort_by_key(|p| p.order);
            for p in &props {
                // Property visibility = getter's when present, else setter's.
                let owner_mods = p
                    .get_mods
                    .clone()
                    .or_else(|| p.set_mods.clone())
                    .unwrap_or_default();
                let vis_of = |m: &String| -> String {
                    m.split_whitespace()
                        .find(|w| matches!(*w, "private" | "protected" | "internal" | "public"))
                        .map(|w| format!("{} ", w))
                        .unwrap_or_default()
                };
                let owner_vis = vis_of(&owner_mods);
                let mut acc = String::new();
                if p.get_mods.is_some() {
                    let extra = p.get_mods.as_ref().map(vis_of).unwrap_or_default();
                    if extra != owner_vis && !extra.is_empty() {
                        acc.push_str(&extra);
                    }
                    acc.push_str("get; ");
                }
                if p.set_mods.is_some() {
                    let extra = p.set_mods.as_ref().map(vis_of).unwrap_or_default();
                    if extra != owner_vis && !extra.is_empty() {
                        acc.push_str(&extra);
                    }
                    acc.push_str("set; ");
                }
                writeln!(w, "\t{}{} {} {{ {} }}", owner_mods, p.ptype, p.name, acc.trim_end())?;
                synthesized_props += 1;
            }
            if !props.is_empty() {
                props_synth_types += 1;
            }
        }
        writeln!(w, "\n\t// Constructors")?;
        for &gmi in &per_type[i] {
            let md = &mds[gmi];
            if md.name != ".ctor" && md.name != ".cctor" {
                continue;
            }
            let ret = type_name(m, &tds, &parents, md.ret_type, 0);
            let (params, n_unresolved) = self_params(m, &tds, &parents, md);
            unresolved_params += n_unresolved;
            // Real metadata token: tokens are assigned in method-table order starting at
            // 0x06000001, constructors included (verified against the 6.4 reference dump).
            // [DllImport]: reference dumps put this line before every P/Invoke method
            // (MethodAttributes.PinvokeImpl, 0x2000) and nowhere else — verified 0 exceptions.
            write_member_attrs(w, &attr_by_token, 0x0600_0001u32.wrapping_add(gmi as u32))?;
            if md.flags & 0x2000 != 0 {
                writeln!(w, "\t[DllImport]")?;
            }
            let token = 0x0600_0001u32.wrapping_add(gmi as u32);
            writeln!(
                w,
                "\t{}{} {}({}) {{ }} // RVA: 0x{:x} Token: 0x{:x} Slot: {}",
                method_modifiers(md.flags),
                ret,
                md.name,
                params.join(", "),
                md.rva,
                token,
                vtable_slots[gmi].unwrap_or(md.slot as i32)
            )?;
            nmethods += 1;
        }
        writeln!(w, "\n\t// Methods")?;
        for &gmi in &per_type[i] {
            let md = &mds[gmi];
            if md.name == ".ctor" || md.name == ".cctor" {
                continue;
            }
            let ret = type_name(m, &tds, &parents, md.ret_type, 0);
            let (params, n_unresolved) = self_params(m, &tds, &parents, md);
            unresolved_params += n_unresolved;
            // [DllImport]: reference dumps put this line before every P/Invoke method
            // (MethodAttributes.PinvokeImpl, 0x2000) and nowhere else — verified 0 exceptions.
            write_member_attrs(w, &attr_by_token, 0x0600_0001u32.wrapping_add(gmi as u32))?;
            if md.flags & 0x2000 != 0 {
                writeln!(w, "\t[DllImport]")?;
            }
            let token = 0x0600_0001u32.wrapping_add(gmi as u32);
            writeln!(
                w,
                "\t{}{} {}({}) {{ }} // RVA: 0x{:x} Token: 0x{:x} Slot: {}",
                method_modifiers(md.flags),
                ret,
                md.name,
                params.join(", "),
                md.rva,
                token,
                vtable_slots[gmi].unwrap_or(md.slot as i32)
            )?;
            nmethods += 1;
        }
        writeln!(w, "}}")?;
    }

    // Addresses: sorted unique method-pointer RVAs (the reference additionally merges
    // genericMethodPointers / invokerPointers / customAttributeGenerators, which 7.1 does not
    // expose statically).
    let mut addresses: Vec<u64> = (0..m.methodptrs_len)
        .map(|i| m.method_rva(i) as u64)
        .filter(|r| *r != 0)
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    crate::script_json::write_json(
        wj,
        &script_methods,
        &script_strings,
        &script_meta_methods,
        &addresses,
    )?;
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
    if real_props > 0 {
        eprintln!(
            "[info] properties: {real_props} propertyDef entries across {real_prop_types} types decoded from the metadata property table ({unnamed_props} with an empty name)"
        );
    }
    if synthesized_props > 0 || unresolved_props > 0 {
        eprintln!(
            "[warn] properties: {synthesized_props} entries SYNTHESIZED from get_/set_ accessor methods across {props_synth_types} types (no property table in this profile); {unresolved_props} entries unresolved (missing accessor index or value type)"
        );
    }
    if attrs_rendered + attrs_arg_required + attrs_unsupported > 0 {
        eprintln!(
            "[warn] custom attributes: {attrs_rendered} rendered as [Class] (classes with a parameterless ctor), {attrs_arg_required} skipped because their constructor takes arguments (the attribute argument blob is not recovered), {attrs_unsupported} skipped (parameter attribute / unknown token kind), {attrs_unmapped} attribute instances have no member row"
        );
    }
    if unresolved_iface_generic > 0 {
        eprintln!(
            "[warn] generic-instantiated interface entries skipped: {unresolved_iface_generic} (GENERICINST rendering depends on the generic-class table, gap #11)"
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
fn self_params(m: &Meta, tds: &[Td], parents: &[Option<u32>], md: &Md) -> (Vec<String>, usize) {
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
            Some(Some(ti)) => type_name(m, tds, parents, ti, 0),
            Some(None) => "object".to_string(),
            None => {
                unresolved += 1;
                "object /*unresolved*/".to_string()
            }
        };
        let name = m.param_name(idx).unwrap_or_else(|| format!("arg{k}"));
        // ref/out modifiers: reference dumps prefix byref parameters with `ref` / `out`.
        // The distinction travels in the parameter type's attrs word (ParameterAttributes):
        // bit1 (0x0002) = Out. A byref type whose attrs say Out prints `out`, every other
        // byref prints `ref` (C# emits no flag for plain `ref`).
        let mut tn = tn;
        if tn.ends_with('&') {
            let attrs = m
                .param_type(idx)
                .flatten()
                .and_then(|ti| m.il2cpp_type(ti as usize))
                .map(|(_, _, a)| a)
                .unwrap_or(0);
            tn = if attrs & 0x2 != 0 {
                format!("out {}", tn)
            } else {
                format!("ref {}", tn)
            };
        }
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

/// Write every recovered custom-attribute instance as JSON, including the ones whose class
/// needs constructor arguments (they cannot be rendered as `[Name]` in dump.cs but the data
/// itself is recovered: class + member identity). Members are resolved through the metadata
/// tables; parameter and property attributes get a best-effort name.
pub fn write_attributes_json(m: &Meta, path: &str) -> Result<usize> {
    use std::io::Write;
    let (tds, mds) = collect(m);
    let mut parents: Vec<Option<u32>> = vec![None; tds.len()];
    for i in 0..tds.len() {
        let (Some(start), Some(count)) = (m.td_nested_start(i), m.td_nested_count(i)) else {
            continue;
        };
        if start == 0xFFFF || count == 0 {
            continue;
        }
        for k in 0..count {
            if let Some(child) = m.nested_types_at(start + k) {
                if (child as usize) < parents.len() {
                    parents[child as usize] = Some(i as u32);
                }
            }
        }
    }
    // field row -> declaring typeDef index
    let mut field_owner: Vec<u32> = vec![u32::MAX; 0];
    let mut max_row = 0usize;
    for td in tds.iter() {
        if td.fields_start != u32::MAX {
            max_row = max_row.max(td.fields_start as usize + td.fields_count as usize);
        }
    }
    field_owner.resize(max_row, u32::MAX);
    for (ti, td) in tds.iter().enumerate() {
        if td.fields_start == u32::MAX {
            continue;
        }
        for k in 0..td.fields_count {
            let row = td.fields_start as usize + k as usize;
            if row < field_owner.len() {
                field_owner[row] = ti as u32;
            }
        }
    }

    let mut out: Vec<(u32, u32, String, String)> = Vec::new();
    for (inst, token) in m.attribute_instance_tokens() {
        let (kind, idx) = (token >> 24, token & 0x00FF_FFFF);
        if idx == 0 {
            continue;
        }
        let member = match kind {
            0x02 => {
                let tdi = (idx - 1) as usize;
                if tdi >= tds.len() {
                    continue;
                }
                format!("TypeDef: {}", joined_type_name(&tds, &parents, tdi as u32, 0))
            }
            0x04 => {
                let row = (idx - 1) as usize;
                let owner = field_owner.get(row).copied().unwrap_or(u32::MAX);
                let owner_name = if owner != u32::MAX {
                    joined_type_name(&tds, &parents, owner, 0)
                } else {
                    String::new()
                };
                format!("Field: {}::{}", owner_name, m.field_name(row as u32))
            }
            0x06 => {
                let gmi = (idx - 1) as usize;
                let Some(md) = mds.get(gmi) else { continue };
                format!(
                    "Method: {}::{}",
                    joined_type_name(&tds, &parents, md.decl, 0),
                    md.name
                )
            }
            0x08 => {
                let pi = (idx - 1) as usize;
                format!("Parameter: {}", m.param_name(pi as u32).unwrap_or_default())
            }
            0x17 => format!("Property: #{}", idx - 1),
            _ => continue,
        };
        let Some(ti) = m.attribute_type_idx(inst) else { continue };
        let Some((ak, adata, _)) = m.il2cpp_type(ti as usize) else { continue };
        if ak != 0x12 {
            continue;
        }
        let Some(td) = tds.get(adata as usize) else { continue };
        let mut name = td.name.clone();
        if let Some(stripped) = name.strip_suffix("Attribute") {
            name = stripped.to_string();
        }
        out.push((inst, token, member, name));
    }
    out.sort_unstable_by_key(|r| r.0);
    let f = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::new(f);
    writeln!(w, "{{")?;
    writeln!(w, "\"AttributeCount\": {},", m.attribute_instance_count())?;
    writeln!(w, "\"Recovered\": {},", out.len())?;
    writeln!(w, "\"Attributes\": [")?;
    for (i, (inst, token, member, name)) in out.iter().enumerate() {
        let comma = if i + 1 == out.len() { "" } else { "," };
        writeln!(
            w,
            "  {{\"Instance\": {}, \"MemberToken\": {}, \"Member\": \"{}\", \"Attribute\": \"{}\"}}{comma}",
            inst,
            token,
            json_escape(member),
            json_escape(name)
        )?;
    }
    writeln!(w, "]")?;
    writeln!(w, "}}")?;
    w.flush()?;
    Ok(out.len())
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

/// Instance-field offsets per type (declaration order), statically reconstructed with
/// il2cpp's rules. None = the type cannot be laid out statically (explicit layout or
/// generic-parameter fields).
pub fn instance_offsets(m: &Meta, tds: &[Td]) -> Vec<Option<Vec<u32>>> {
    let mut lc = LayoutCalc::new(m, tds);
    (0..tds.len()).map(|i| lc.type_layout(i).map(|l| l.offsets)).collect()
}
