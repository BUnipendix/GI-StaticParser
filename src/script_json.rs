//! Il2CppDumper-compatible script.json.
//!
//! Mirrors Il2CppDumper/Outputs/StructGenerator.cs::WriteScript for the non-generic-method
//! path (the generic-method-spec path needs methodSpecs, which our 7.1 metadata does not
//! expose). For every method that has a code pointer the reference dump emits:
//!
//!   ScriptMethod.Address       = RVA (pointer - imageBase)  -> we have md.rva
//!   ScriptMethod.Name          = "<TypeDefName>$$<methodName>"
//!   ScriptMethod.Signature     = "<retCType> <FixName(Name)> (<this>, <params>, const MethodInfo* method);"
//!   ScriptMethod.TypeSignature = per-type letter sequence ("i", "j", "f", "d", "v")
//!   ScriptString/ScriptMetadata/ScriptMetadataMethod -> need metadataUsage (unavailable)
//!   Addresses                  = sorted unique method pointers (RVA)

use std::collections::HashSet;
use std::io::Write;

use super::derive::engine::Meta;
use super::dump_gen::Md;
use super::dump_gen::Td;

pub type ScriptMethod = (u64, String, String, String);

const ARITY_SEP: char = '\u{60}';

fn fix_name(s: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "klass", "monitor", "register", "_cs", "auto", "friend", "template", "flat", "default",
        "_ds", "interrupt", "unsigned", "signed", "asm", "if", "case", "break", "continue", "do",
        "new", "_", "short", "union", "class", "namespace",
    ];
    const SPECIAL: &[&str] = &["inline", "near", "far"];
    let mut out = if KEYWORDS.contains(&s) {
        format!("_{}", s)
    } else if SPECIAL.contains(&s) {
        format!("_{}_", s)
    } else {
        s.to_string()
    };
    if out.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        out = format!("_{}", out);
    }
    out.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

pub struct Namer<'a> {
    pub m: &'a Meta<'a>,
    pub tds: &'a [Td],
    pub parents: &'a [Option<u32>],
}

impl<'a> Namer<'a> {
    fn arity_of(name: &str) -> usize {
        match name.rsplit_once(ARITY_SEP) {
            Some((_, n)) => n.parse().unwrap_or(0),
            None => 0,
        }
    }

    fn placeholders(argc: usize) -> String {
        let mut s = String::from("<");
        for i in 0..argc {
            if i > 0 {
                s.push_str(", ");
            }
            s.push('T');
            if argc > 1 {
                s.push_str(&format!("{}", i + 1));
            }
        }
        s.push('>');
        s
    }

    fn strip_arity(name: &str) -> String {
        match name.rsplit_once(ARITY_SEP) {
            Some((b, _)) => b.to_string(),
            None => name.to_string(),
        }
    }

    fn name_with_params(&self, tdi: usize) -> String {
        let td = &self.tds[tdi];
        let argc = Self::arity_of(&td.name);
        let base = Self::strip_arity(&td.name);
        if argc > 0 {
            format!("{}{}", base, Self::placeholders(argc))
        } else {
            base
        }
    }

    /// Declaring-type chain + own name (no generic parameter list). The reference resolves
    /// declaring types through the typeDef chain (GetTypeName of the declaring Il2CppType with
    /// is_nested=true), NOT through a typearr index — mixing the two corrupts nested names.
    fn typedef_nested_name(&self, tdi: usize, add_namespace: bool, depth: u32) -> String {
        if depth > 16 {
            return String::new();
        }
        let td = &self.tds[tdi];
        let base = Self::strip_arity(&td.name);
        if let Some(parent) = self.parents.get(tdi).and_then(|p| *p) {
            format!(
                "{}.{}",
                self.typedef_nested_name(parent as usize, add_namespace, depth + 1),
                base
            )
        } else if add_namespace && !td.namespace.is_empty() {
            format!("{}.{}", td.namespace, base)
        } else {
            base
        }
    }

    /// GetTypeDefName(typeDef, addNamespace, genericParameter = true)
    pub fn typedef_name(&self, tdi: usize, depth: u32) -> String {
        if depth > 16 {
            return String::new();
        }
        let td = &self.tds[tdi];
        let argc = Self::arity_of(&td.name);
        let mut s = self.typedef_nested_name(tdi, true, depth + 1);
        let _ = td;
        if argc > 0 {
            s.push_str(&Self::placeholders(argc));
        }
        s
    }

    pub fn type_name(&self, ti: u32, add_namespace: bool, depth: u32) -> String {
        if depth > 16 {
            return "object".into();
        }
        let Some((kind, data, _)) = self.m.il2cpp_type(ti as usize) else {
            return "object".into();
        };
        match kind {
            0x14 => "object[]".into(),
            0x1D => format!("{}[]", self.type_name(data, add_namespace, depth + 1)),
            0x0F => format!("{}*", self.type_name(data, add_namespace, depth + 1)),
            0x11 | 0x12 => {
                let tdi = data as usize;
                let Some(td) = self.tds.get(tdi) else { return "object".into() };
                let mut s = self.typedef_nested_name(tdi, add_namespace, depth + 1);
                let argc = Self::arity_of(&td.name);
                if argc > 0 {
                    s.push_str(&Self::placeholders(argc));
                }
                s
            }
            0x15 => {
                let Some((def_tdi, args)) = self.m.generic_instance(data) else {
                    return "object".into();
                };
                if self.tds.get(def_tdi as usize).is_none() {
                    return "object".into();
                }
                let mut s = self.typedef_nested_name(def_tdi as usize, add_namespace, depth + 1);
                s.push('<');
                for (k, arg) in args.iter().enumerate() {
                    if k > 0 {
                        s.push_str(", ");
                    }
                    s.push_str(&self.type_name(*arg as u32, false, depth + 1));
                }
                s.push('>');
                s
            }
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
            0x0E => "string".into(),
            0x16 => "TypedReference".into(),
            0x18 => "IntPtr".into(),
            0x19 => "UIntPtr".into(),
            0x1C => "object".into(),
            0x13 | 0x1E => "object".into(),
            _ => "object".into(),
        }
    }

    pub fn struct_names(&self) -> Vec<String> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::with_capacity(self.tds.len());
        for tdi in 0..self.tds.len() {
            let base = fix_name(&self.typedef_name(tdi, 0));
            let mut name = base.clone();
            let mut i = 1usize;
            while !seen.insert(name.clone()) {
                name = format!("{}_{}", base, i);
                i += 1;
            }
            out.push(name);
        }
        out
    }

    fn primitive_struct_name(kind: u8) -> Option<&'static str> {
        Some(match kind {
            0x01 => "System_Void",
            0x02 => "System_Boolean",
            0x03 => "System_Char",
            0x04 => "System_SByte",
            0x05 => "System_Byte",
            0x06 => "System_Int16",
            0x07 => "System_UInt16",
            0x08 => "System_Int32",
            0x09 => "System_UInt32",
            0x0A => "System_Int64",
            0x0B => "System_UInt64",
            0x0C => "System_Single",
            0x0D => "System_Double",
            0x0E => "System_String",
            0x16 => "System_TypedReference",
            0x18 => "System_IntPtr",
            0x19 => "System_UIntPtr",
            0x1C => "System_Object",
            _ => return None,
        })
    }

    fn il2cpp_struct_name(&self, structs: &[String], ti: u32, depth: u32) -> Option<String> {
        if depth > 12 {
            return None;
        }
        let (kind, data, _) = self.m.il2cpp_type(ti as usize)?;
        if let Some(p) = Self::primitive_struct_name(kind) {
            return Some(p.to_string());
        }
        match kind {
            0x11 | 0x12 => structs.get(data as usize).cloned(),
            0x0F => self.il2cpp_struct_name(structs, data, depth + 1),
            0x1D => {
                let elem = self.il2cpp_struct_name(structs, data, depth + 1)?;
                Some(format!("{}_array", elem))
            }
            0x14 => Some("System_Object_array".into()),
            0x15 => {
                let (def_tdi, _) = self.m.generic_instance(data)?;
                self.inst_struct_name(def_tdi, data, depth + 1)
            }
            0x13 | 0x1E => Some("Il2CppObject".into()),
            _ => None,
        }
    }

    fn inst_struct_name(&self, def_tdi: u32, g: u32, depth: u32) -> Option<String> {
        let (dt, args) = self.m.generic_instance(g)?;
        let _ = def_tdi;
        self.tds.get(dt as usize)?;
        let mut s = self.typedef_nested_name(dt as usize, true, depth + 1);
        s.push('<');
        for (k, a) in args.iter().enumerate() {
            if k > 0 {
                s.push_str(", ");
            }
            s.push_str(&self.type_name(*a as u32, false, depth + 1));
        }
        s.push('>');
        Some(fix_name(&s))
    }

    pub fn parse_type(&self, structs: &[String], ti: u32, depth: u32) -> Option<String> {
        if depth > 12 {
            return None;
        }
        let (kind, data, _) = self.m.il2cpp_type(ti as usize)?;
        Some(match kind {
            0x01 => "void".into(),
            0x02 => "bool".into(),
            0x03 => "uint16_t".into(),
            0x04 => "int8_t".into(),
            0x05 => "uint8_t".into(),
            0x06 => "int16_t".into(),
            0x07 => "uint16_t".into(),
            0x08 => "int32_t".into(),
            0x09 => "uint32_t".into(),
            0x0A => "int64_t".into(),
            0x0B => "uint64_t".into(),
            0x0C => "float".into(),
            0x0D => "double".into(),
            0x0E => "System_String_o*".into(),
            0x0F => format!("{}*", self.parse_type(structs, data, depth + 1)?),
            0x18 => "intptr_t".into(),
            0x19 => "uintptr_t".into(),
            0x1C => "Il2CppObject*".into(),
            0x16 => "Il2CppObject*".into(),
            0x13 | 0x1E => "Il2CppObject*".into(),
            0x11 => {
                let tdi = data as usize;
                let td = self.tds.get(tdi)?;
                if td.bitfield & 2 != 0 {
                    let fti = self.m.field_type_idx(td.fields_start);
                    self.parse_type(structs, fti, depth + 1)?
                } else {
                    format!("{}_o", structs.get(tdi)?.clone())
                }
            }
            0x12 => format!("{}_o*", structs.get(data as usize)?.clone()),
            0x14 => "Il2CppObject*".into(),
            0x1D => {
                let elem = self.il2cpp_struct_name(structs, data, depth + 1)?;
                format!("{}_array*", elem)
            }
            0x15 => {
                let (def_tdi, _) = self.m.generic_instance(data)?;
                let td = self.tds.get(def_tdi as usize)?;
                let name = self.inst_struct_name(def_tdi, data, depth + 1)?;
                if td.bitfield & 2 != 0 {
                    let fti = self.m.field_type_idx(td.fields_start);
                    self.parse_type(structs, fti, depth + 1)?
                } else if td.bitfield & 1 != 0 {
                    format!("{}_o", name)
                } else {
                    format!("{}_o*", name)
                }
            }
            _ => return None,
        })
    }

    fn type_sig_letter(kind: u8) -> char {
        match kind {
            0x01 => 'v',
            0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 => 'i',
            0x0A | 0x0B => 'j',
            0x0C => 'f',
            0x0D => 'd',
            _ => 'i',
        }
    }

    fn byref(&self, ti: u32) -> bool {
        self.m
            .il2cpp_type_flags(ti as usize)
            .map(|f| f & 0x40 != 0)
            .unwrap_or(false)
    }

    pub fn method_entry(&self, structs: &[String], tdi: usize, md: &Md) -> Option<ScriptMethod> {
        if md.rva == 0 {
            return None;
        }
        let td = self.tds.get(tdi)?;
        let mut full_name = self.typedef_name(tdi, 0);
        full_name.push_str("$$");
        full_name.push_str(&md.name);

        let mut tsig = String::new();
        let mut ret_c = self.parse_type(structs, md.ret_type, 0)?;
        if self.byref(md.ret_type) {
            ret_c.push('*');
            tsig.push('i');
        } else {
            let (kind, _, _) = self.m.il2cpp_type(md.ret_type as usize)?;
            tsig.push(Self::type_sig_letter(kind));
        }

        let mut params: Vec<String> = Vec::new();
        let is_static = md.flags & 0x10 != 0;
        if !is_static {
            let self_c = if td.bitfield & 1 != 0 {
                format!("{}_o", structs.get(tdi)?.clone())
            } else {
                format!("{}_o*", structs.get(tdi)?.clone())
            };
            params.push(format!("{} __this", self_c));
            tsig.push('i');
        }
        for k in 0..md.param_count as u32 {
            let idx = md.param_start.wrapping_add(k);
            let Some(Some(pti)) = self.m.param_type(idx) else {
                return None;
            };
            let mut c = self.parse_type(structs, pti, 0)?;
            if self.byref(pti) {
                c.push('*');
                tsig.push('i');
            } else {
                let (kind, _, _) = self.m.il2cpp_type(pti as usize)?;
                tsig.push(Self::type_sig_letter(kind));
            }
            let pname = self.m.param_name(idx).unwrap_or_else(|| format!("arg{}", k));
            params.push(format!("{} {}", c, fix_name(&pname)));
        }
        tsig.push('i');
        params.push("const MethodInfo* method".into());

        let signature = format!("{} {} ({});", ret_c, fix_name(&full_name), params.join(", "));
        Some((md.rva as u64, full_name, signature, tsig))
    }
}

/// Serialize script.json in the reference layout. ScriptString/ScriptMetadata/
/// ScriptMetadataMethod stay empty: they require metadataUsage, unavailable statically for 7.1.
pub fn write_json<W: Write>(
    w: &mut W,
    methods: &[ScriptMethod],
    addresses: &[u64],
) -> std::io::Result<()> {
    writeln!(w, "{{")?;
    writeln!(w, "\"ScriptMethod\": [")?;
    for (i, (addr, name, sig, tsig)) in methods.iter().enumerate() {
        let comma = if i + 1 == methods.len() { "" } else { "," };
        writeln!(
            w,
            "  {{\"Address\": {}, \"Name\": \"{}\", \"Signature\": \"{}\", \"TypeSignature\": \"{}\"}}{comma}",
            addr,
            json_escape(name),
            json_escape(sig),
            json_escape(tsig)
        )?;
    }
    writeln!(w, "],")?;
    writeln!(w, "\"ScriptString\": [],")?;
    writeln!(w, "\"ScriptMetadata\": [],")?;
    writeln!(w, "\"ScriptMetadataMethod\": [],")?;
    write!(w, "\"Addresses\": [")?;
    for (i, a) in addresses.iter().enumerate() {
        if i > 0 {
            write!(w, ", ")?;
        }
        write!(w, "{}", a)?;
    }
    writeln!(w, "]")?;
    writeln!(w, "}}")
}

pub fn json_escape(s: &str) -> String {
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
