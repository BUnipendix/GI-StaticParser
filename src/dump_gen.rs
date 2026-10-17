//! The generation-7.x dump pipeline: full `dump.cs` (Il2CppDumper format), plus
//! `script.json` and a derivation report. Driven entirely by a [`Profile`].

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
    // chain-walk count: real slots tile the field rows exactly; padding ends the table
    let (n_td, _n_field_rows) = m.td_walk();
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

/// Type name for an Il2CppType index (recursion depth-limited; class names via `tds`).
pub fn type_name(m: &Meta, tds: &[Td], ti: u32, depth: u32) -> String {
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
                Some(t) => match t.name.as_str() {
                    "Object" => "object".into(),
                    "String" => "string".into(),
                    n if t.namespace.is_empty() => n.to_string(),
                    n => format!("{}.{}", t.namespace, n),
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

    for (i, td) in tds.iter().enumerate() {
        if td.name.is_empty() {
            continue;
        }
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
            for k in 0..td.fields_count {
                let row = td.fields_start + k;
                let fname = m.field_name(row);
                let fti = m.field_type_idx(row);
                let (kind, _data, attrs) = m.il2cpp_type(fti as usize).unwrap_or((0, 0, 0));
                let _ = kind;
                let tn = type_name(m, &tds, fti, 0);
                // The field-offset column has NOT been decoded for this generation, so the
                // offset comment is omitted rather than stamped with a constant 0x0 (which
                // looked like real data for all 440,061 fields). Counted and reported below.
                writeln!(w, "\t{}{} {};", field_modifiers(attrs), tn, fname)?;
                unresolved_offsets += 1;
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
    if unresolved_offsets > 0 {
        eprintln!(
            "[warn] field offsets unresolved: {unresolved_offsets} of {nfields} fields emitted without an offset comment"
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
    // params table: entries {key@0, type@4, ?@8}, key = paramStart search (stride 12).
    // The extra additive term of paramStart is resolved by anchoring: the first method
    // with N>0 params must find its key in the table; we search a small correction set.
    let mut out = Vec::new();
    if md.param_count == 0 {
        return (out, 0);
    }
    let _ = &md.param_start;
    let mut unresolved = 0usize;
    for _k in 0..md.param_count {
        // locate entry: linear scan over the table comparing column0 to the key
        // (the runtime does exactly this; the table is small per key region)
        let found: Option<(usize, u32, u32)> = None;
        // TODO(derive): the params table rows are shuffled; the runtime windowed-searches
        // an encoded key (decompiled at 0x140528890). Param NAMES are not runtime-readable
        // (metadata paramDef name table not yet located), so types alone cannot complete
        // the dump.cs signature — parked until both are solved (see IMPLEMENTATION_LOG).
        if let Some((_, ti, _)) = found {
            out.push(type_name(m, tds, ti, 0));
        } else {
            out.push("object /*unresolved*/".into());
            unresolved += 1;
        }
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
