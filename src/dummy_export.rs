//! Structured export for the DummyDll generator (tools/dummygen).
//!
//! One JSON object per line. Types are referenced by typeDef index; the generator defines all
//! of them in one assembly, so no cross-assembly references are needed for v1.
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

pub fn export_dummy(m: &Meta, path: &str) -> anyhow::Result<(usize, usize, usize)> {
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

    for (i, td) in tds.iter().enumerate() {
        let kind = type_kind(m, &tds, td);
        let joined = super::dump_gen::joined_type_name(&tds, &parents, i as u32, 0);
        let (ns, name) = split_name(td, &joined);
        let parent = td_parent_tdi(m, &tds, td);
        writeln!(
            w,
            "{{\"k\":\"T\",\"id\":{},\"ns\":{},\"name\":{},\"kind\":\"{}\",\"parent\":{},\"flags\":{},\"bitfield\":{}}}",
            i,
            serde_json::to_string(&ns)?,
            serde_json::to_string(&name)?,
            kind,
            parent,
            td.flags,
            td.bitfield
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
                writeln!(
                    w,
                    "{{\"k\":\"F\",\"id\":{},\"row\":{},\"name\":{},\"type\":{},\"flags\":{},\"token\":{},\"off\":{}}}",
                    i,
                    row,
                    serde_json::to_string(&fname)?,
                    serde_json::to_string(&enc)?,
                    attrs,
                    0x0400_0001u32.wrapping_add(row),
                    serde_json::to_string(&off)?
                )?;
                n_fields += 1;
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
                            let pname = m.param_name(idx).unwrap_or_default();
                            params.push_str(&format!(
                                "{{\"n\":{},\"t\":{}}}",
                                serde_json::to_string(&pname)?,
                                serde_json::to_string(&enc)?
                            ));
                        }
                        _ => params.push_str("{\"n\":\"\",\"t\":\"obj\"}"),
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
    w.flush()?;
    Ok((n_types, n_fields, n_methods))
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
