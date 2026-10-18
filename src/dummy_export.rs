//! Structured export for the DummyDll generator (tools/dummygen).
//!
//! One JSON object per line. Record kinds:
//!   T type / I interface impl / F field / M method / P property / E event
//! Types are referenced by typeDef index; the generator defines all of them in one assembly, so
//! no cross-assembly references are needed for v1. `P` carries the real metadata property name
//! plus getter/setter method indexes (global method-table indexes, -1 = no accessor).
//!
//! Type encoding (compact string):
//!   primitives: v b c s8 u8 s16 u16 s32 u32 s64 u64 f4 f8 str ip up obj tr
//!   t<N>      class/valuetype by typeDef index
//!   p<inner>  pointer
//!   a<inner>  single-dimensional array
//!   obj       fallback / generic instance / generic parameter
//! A leading & marks a byref parameter type.

use std::io::Write;

use super::derive::engine::Meta;
use super::dump_gen::{collect, type_kind, Td};

pub(crate) fn enc_type(m: &Meta, ti: u32, depth: u32) -> String {
    if depth > 8 {
        return "obj".into();
    }
    let Some((kind, data, _)) = m.il2cpp_type(ti as usize) else {
        return "obj".into();
    };
    match kind {
        0x01 => "v".into(),
        0x02 => "b".into(),
        0x03 => "c".into(),
        0x04 => "s8".into(),
        0x05 => "u8".into(),
        0x06 => "s16".into(),
        0x07 => "u16".into(),
        0x08 => "s32".into(),
        0x09 => "u32".into(),
        0x0A => "s64".into(),
        0x0B => "u64".into(),
        0x0C => "f4".into(),
        0x0D => "f8".into(),
        0x0E => "str".into(),
        0x18 => "ip".into(),
        0x19 => "up".into(),
        0x1C => "obj".into(),
        0x16 => "tr".into(),
        0x11 | 0x12 => format!("t{}", data),
        0x0F => format!("p{}", enc_type(m, data, depth + 1)),
        0x1D => format!("a{}", enc_type(m, data, depth + 1)),
        _ => "obj".into(),
    }
}

fn byref(m: &Meta, ti: u32) -> bool {
    m.il2cpp_type_flags(ti as usize)
        .map(|f| f & 0x40 != 0)
        .unwrap_or(false)
}

fn enc_param_type(m: &Meta, ti: u32) -> String {
    let s = enc_type(m, ti, 0);
    if byref(m, ti) {
        format!("&{}", s)
    } else {
        s
    }
}

fn split_name(td: &Td, joined: &str) -> (String, String) {
    let ns = td.namespace.clone();
    if !ns.is_empty() {
        let prefix = format!("{}.", ns);
        if let Some(rest) = joined.strip_prefix(&prefix) {
            return (ns, rest.to_string());
        }
    }
    (ns, joined.to_string())
}

/// Map an image RVA to its file offset using the PE section table (None if not backed).
fn rva_to_file(m: &Meta, rva: u32) -> Option<u32> {
    for &(sva, vsz, ro, rsz) in &m.sections {
        let end = sva.saturating_add(vsz.max(rsz));
        if rva >= sva && rva < end {
            let delta = rva - sva;
            if delta < rsz {
                return Some(ro + delta);
            }
        }
    }
    None
}

/// Typed constant value for a field default: (kind tag, value as string). None means the kind
/// cannot be represented as a CLR Constant row (class/valuetype/generic) -> MetadataOffsetAttribute.
fn enc_default(m: &Meta, tix: u32, dataoff: i32) -> Option<(&'static str, String)> {
    let (kind, _, _) = m.il2cpp_type(tix as usize)?;
    let bytes = |n: usize| m.default_value_bytes(dataoff, n);
    match kind {
        0x02 => Some(("b", if bytes(1)?[0] != 0 { "1" } else { "0" }.to_string())),
        0x03 => Some(("c", u16::from_le_bytes(bytes(2)?.try_into().unwrap()).to_string())),
        0x04 => Some(("s8", (bytes(1)?[0] as i8).to_string())),
        0x05 => Some(("u8", bytes(1)?[0].to_string())),
        0x06 => Some(("s16", i16::from_le_bytes(bytes(2)?.try_into().unwrap()).to_string())),
        0x07 => Some(("u16", u16::from_le_bytes(bytes(2)?.try_into().unwrap()).to_string())),
        0x08 => Some(("s32", i32::from_le_bytes(bytes(4)?.try_into().unwrap()).to_string())),
        0x09 => Some(("u32", u32::from_le_bytes(bytes(4)?.try_into().unwrap()).to_string())),
        0x0A => Some(("s64", i64::from_le_bytes(bytes(8)?.try_into().unwrap()).to_string())),
        0x0B => Some(("u64", u64::from_le_bytes(bytes(8)?.try_into().unwrap()).to_string())),
        0x0C => {
            let v = f32::from_le_bytes(bytes(4)?.try_into().unwrap());
            let s = if v.is_nan() { "NaN".to_string() }
                else if v.is_infinite() { if v > 0.0 { "Infinity".into() } else { "-Infinity".into() } }
                else { format!("{:?}", v) };
            Some(("f4", s))
        }
        0x0D => {
            let v = f64::from_le_bytes(bytes(8)?.try_into().unwrap());
            let s = if v.is_nan() { "NaN".to_string() }
                else if v.is_infinite() { if v > 0.0 { "Infinity".into() } else { "-Infinity".into() } }
                else { format!("{:?}", v) };
            Some(("f8", s))
        }
        0x0E => {
            // String default: {u32 byte-length, UTF-8 bytes} in the shared value blob.
            let len = u32::from_le_bytes(bytes(4)?.try_into().unwrap()) as usize;
            if len > 1 << 20 {
                return None;
            }
            Some(("str", String::from_utf8_lossy(m.default_value_bytes(dataoff + 4, len)?).into_owned()))
        }
        _ => None,
    }
}

pub fn export_dummy(m: &Meta, path: &str) -> anyhow::Result<(usize, usize, usize, usize, usize, usize)> {
    let (tds, mds) = collect(m);
    let inst_offsets = super::dump_gen::instance_offsets(m, &tds);
    let mut per_type: Vec<Vec<usize>> = vec![Vec::new(); tds.len()];
    for (gmi, md) in mds.iter().enumerate() {
        let decl = md.decl as usize;
        if decl < per_type.len() {
            per_type[decl].push(gmi);
        }
    }
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

    let vtable_slots = crate::vtable::compute_slots(m, &tds, &per_type, &mds);
    let f = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::new(f);
    let mut n_types = 0usize;
    let mut n_fields = 0usize;
    let mut n_methods = 0usize;
    let mut n_props = 0usize;
    let mut n_events = 0usize;
    let mut n_attrs = 0usize;

    for (i, td) in tds.iter().enumerate() {
        let kind = type_kind(m, &tds, td);
        let joined = super::dump_gen::joined_type_name(&tds, &parents, i as u32, 0);
        let (ns, name) = split_name(td, &joined);
        let parent = td_parent_tdi(m, &tds, td);
        // Real generic-parameter names for generic type definitions (R23 table); the generator
        // falls back to positional T1..Tn when this is empty (obfuscated control-char names).
        let gps = m.type_generic_param_names(i as u32);
        writeln!(
            w,
            "{{\"k\":\"T\",\"id\":{},\"ns\":{},\"name\":{},\"kind\":\"{}\",\"parent\":{},\"flags\":{},\"bitfield\":{},\"gp\":{}}}",
            i,
            serde_json::to_string(&ns)?,
            serde_json::to_string(&name)?,
            kind,
            parent,
            td.flags,
            td.bitfield,
            serde_json::to_string(&gps)?
        )?;
        n_types += 1;

        if kind != "enum" {
            if let Some(start) = td.iface_start {
                let span = m.td_iface_count(i).unwrap_or(0);
                for r in start..start + span {
                    let (t, _) = m.iface_entry(r);
                    if t < 0 {
                        break;
                    }
                    let Some((ek, ed, _)) = m.il2cpp_type(t as usize) else { continue };
                    if !matches!(ek, 0x11 | 0x12 | 0x15) {
                        break;
                    }
                    let iface = if ek == 0x15 {
                        m.generic_instance(ed).map(|(d, _)| d).unwrap_or(u32::MAX)
                    } else {
                        ed
                    };
                    if iface == u32::MAX || (iface as usize) >= tds.len() {
                        continue;
                    }
                    writeln!(w, "{{\"k\":\"I\",\"id\":{},\"iface\":{}}}", i, iface)?;
                }
            }
        }

        if td.fields_start != u32::MAX {
            let mut inst_idx = 0usize;
            for k in 0..td.fields_count {
                let row = td.fields_start + k;
                let fname = m.field_name(row);
                let fti = m.field_type_idx(row);
                let attrs = m.il2cpp_type(fti as usize).map(|(_, _, a)| a).unwrap_or(0);
                let enc = enc_type(m, fti, 0);
                let is_static = attrs & 0x10 != 0;
                let off = if is_static {
                    None
                } else {
                    let v = inst_offsets.get(i).and_then(|o| o.as_ref());
                    let idx = inst_idx;
                    inst_idx += 1;
                    v.and_then(|o| o.get(idx).copied())
                };
                // Constant / MetadataOffset: field defaults exist for literal constants and for a
                // few non-literal fields (reference DummyDll emits a Constant row for every field
                // default, and a MetadataOffset marker when the value kind has no CLR Constant).
                let (cv_json, mo_json) = match m.field_default(row) {
                    Some((dataoff, tix)) => match enc_default(m, tix, dataoff) {
                        Some((tag, value)) => (
                            format!("{{\"t\":\"{}\",\"v\":{}}}", tag, serde_json::to_string(&value)?),
                            "null".to_string(),
                        ),
                        None => (
                            "null".to_string(),
                            (m.default_values as u64 + dataoff as u64).to_string(),
                        ),
                    },
                    None => ("null".to_string(), "null".to_string()),
                };
                writeln!(
                    w,
                    "{{\"k\":\"F\",\"id\":{},\"row\":{},\"name\":{},\"type\":{},\"flags\":{},\"token\":{},\"off\":{},\"cv\":{},\"mo\":{}}}",
                    i,
                    row,
                    serde_json::to_string(&fname)?,
                    serde_json::to_string(&enc)?,
                    attrs,
                    0x0400_0001u32.wrapping_add(row),
                    serde_json::to_string(&off)?,
                    cv_json,
                    mo_json
                )?;
                n_fields += 1;
            }
        }

        // Property definitions (real metadata table; getter/setter are per-type method indexes
        // that resolve to global method indexes through per_type).
        if let (Some(prop_start), Some(prop_count)) = (m.td_prop_start(i), m.td_prop_count(i)) {
            for row in prop_start..prop_start + prop_count {
                let Some((name_idx, getter, setter)) = m.property_row(row) else { continue };
                let get = getter
                    .and_then(|k| per_type[i].get(k as usize).copied())
                    .map(|g| g as i64)
                    .unwrap_or(-1);
                let set = setter
                    .and_then(|k| per_type[i].get(k as usize).copied())
                    .map(|g| g as i64)
                    .unwrap_or(-1);
                if get < 0 && set < 0 {
                    continue;
                }
                let pname = m.decode_str(name_idx);
                writeln!(
                    w,
                    "{{\"k\":\"P\",\"id\":{},\"row\":{},\"name\":{},\"get\":{},\"set\":{}}}",
                    i,
                    row,
                    serde_json::to_string(&pname)?,
                    get,
                    set
                )?;
                n_props += 1;
            }
        }

        // Event definitions (real metadata table; accessor indices are per-type method indexes).
        if let (Some(ev_start), Some(ev_count)) = (m.td_event_start(i), m.td_event_count(i)) {
            for row in ev_start as u32..ev_start as u32 + ev_count {
                let Some((name_idx, etype, add, remove, raise)) = m.event_row(row) else { continue };
                let gmi_of = |k: Option<u16>| -> i64 {
                    k.and_then(|k| per_type[i].get(k as usize).copied())
                        .map(|g| g as i64)
                        .unwrap_or(-1)
                };
                let ename = m.decode_str(name_idx);
                let ty = etype.map(|ti| enc_type(m, ti, 0));
                writeln!(
                    w,
                    "{{\"k\":\"E\",\"id\":{},\"row\":{},\"name\":{},\"type\":{},\"add\":{},\"remove\":{},\"raise\":{}}}",
                    i,
                    row,
                    serde_json::to_string(&ename)?,
                    serde_json::to_string(&ty)?,
                    gmi_of(add),
                    gmi_of(remove),
                    gmi_of(raise)
                )?;
                n_events += 1;
            }
        }

        for &gmi in &per_type[i] {
            let md = &mds[gmi];
            let ret = enc_type(m, md.ret_type, 0);
            let mut params = String::from("[]");
            if md.param_count > 0 {
                params = String::from("[");
                for k in 0..md.param_count as u32 {
                    let idx = md.param_start.wrapping_add(k);
                    if k > 0 {
                        params.push(',');
                    }
                    match m.param_type(idx) {
                        Some(Some(pti)) => {
                            let enc = enc_param_type(m, pti);
                            let pattrs = m.il2cpp_type(pti as usize).map(|(_, _, a)| a).unwrap_or(0);
                            let pname = m.param_name(idx).unwrap_or_default();
                            // Parameter default (optional parameter): typed Constant, or a
                            // MetadataOffset marker for kinds without a CLR Constant.
                            let (cv_json, mo_json) = match m.param_default(idx) {
                                Some((tix, Some(dataoff))) => match enc_default(m, tix, dataoff) {
                                    Some((tag, value)) => (
                                        format!("{{\"t\":\"{}\",\"v\":{}}}", tag, serde_json::to_string(&value)?),
                                        "null".to_string(),
                                    ),
                                    None => (
                                        "null".to_string(),
                                        (m.default_values as u64 + dataoff as u64).to_string(),
                                    ),
                                },
                                _ => ("null".to_string(), "null".to_string()),
                            };
                            params.push_str(&format!(
                                "{{\"n\":{},\"t\":{},\"a\":{},\"cv\":{},\"mo\":{}}}",
                                serde_json::to_string(&pname)?,
                                serde_json::to_string(&enc)?,
                                pattrs,
                                cv_json,
                                mo_json
                            ));
                        }
                        _ => params.push_str("{\"n\":\"\",\"t\":\"obj\",\"a\":0,\"cv\":null,\"mo\":null}"),
                    }
                }
                params.push(']');
            }
            writeln!(
                w,
                "{{\"k\":\"M\",\"id\":{},\"name\":{},\"ret\":{},\"flags\":{},\"rva\":{},\"token\":{},\"slot\":{},\"foff\":{},\"params\":{}}}",
                i,
                serde_json::to_string(&md.name)?,
                serde_json::to_string(&ret)?,
                md.flags,
                md.rva,
                0x0600_0001u32.wrapping_add(gmi as u32),
                serde_json::to_string(&vtable_slots[gmi])?,
                serde_json::to_string(&rva_to_file(m, md.rva))?,
                params
            )?;
            n_methods += 1;
        }
    }
    // Custom attribute instances (the real data layer): each record carries the member token, the
    // attribute class typeDef and the parameterless ctor's global method index when the class has
    // one (-1 = the class needs constructor arguments; the generator then writes an
    // AttributeAttribute marker with the class name, mirroring Il2CppDumper's DummyDll, except the
    // RVA/Offset fields whose custom-attribute-generator pointers are runtime-only).
    {
        let prop_rows: u32 = (0..tds.len())
            .map(|i| m.td_prop_count(i).unwrap_or(0))
            .sum();
        for (inst, token) in m.attribute_instance_tokens() {
            let kind = token >> 24;
            let idx = token & 0x00FF_FFFF;
            let member_ok = match kind {
                0x02 => idx >= 1 && (idx as usize) <= tds.len(),
                0x04 => idx >= 1,
                0x06 => idx >= 1 && (idx as usize) <= mds.len(),
                0x08 => idx >= 1,
                0x17 => idx >= 1 && idx <= prop_rows,
                _ => false,
            };
            if !member_ok {
                continue;
            }
            let Some(ti) = m.attribute_type_idx(inst) else { continue };
            let Some((ak, adata, _)) = m.il2cpp_type(ti as usize) else { continue };
            if ak != 0x12 {
                continue;
            }
            let tdi = adata as usize;
            let Some(td) = tds.get(tdi) else { continue };
            let ctor = per_type
                .get(tdi)
                .and_then(|ms| {
                    ms.iter()
                        .copied()
                        .find(|&g| mds[g].name == ".ctor" && mds[g].param_count == 0)
                })
                .map(|g| g as i64)
                .unwrap_or(-1);
            writeln!(
                w,
                "{{\"k\":\"A\",\"tok\":{},\"tdi\":{},\"name\":{},\"ctor\":{}}}",
                token,
                tdi,
                serde_json::to_string(&td.name)?,
                ctor
            )?;
            n_attrs += 1;
        }
    }
    w.flush()?;
    Ok((n_types, n_fields, n_methods, n_props, n_events, n_attrs))
}

fn td_parent_tdi(m: &Meta, tds: &[Td], td: &Td) -> i64 {
    let pt = td.parent_tarr;
    if pt == u32::MAX {
        return -1;
    }
    let Some((k, d, _)) = m.il2cpp_type(pt as usize) else {
        return -1;
    };
    match k {
        0x11 | 0x12 => {
            if (d as usize) < tds.len() {
                d as i64
            } else {
                -1
            }
        }
        0x1C => tds
            .iter()
            .position(|t| t.name == "Object" && t.namespace == "System")
            .map(|x| x as i64)
            .unwrap_or(-1),
        0x15 => m
            .generic_instance(d)
            .map(|(def, _)| def as i64)
            .unwrap_or(-1),
        _ => -1,
    }
}
