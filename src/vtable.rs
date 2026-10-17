//! Static reconstruction of C# / IL2CPP vtable slots (method Slot column).
//!
//! GI zeroes the metadata slot field, but the layout is deterministic:
//!   1. start from the parent vtable (System.Object first: Equals, Finalize, GetHashCode, ToString);
//!   2. append one slot per implemented interface method, in interface order / interface-method
//!      order (these slots sit BEFORE the type's own new virtual methods);
//!   3. append the type's own virtual newslot methods in metadata order; a method that
//!      implements an interface method maps to the interface slot, and skips its own class slot
//!      when it is final (sealed) or an explicit implementation (name like IFace.Method);
//!   4. resolve non-newslot overrides to the matching parent slot by signature.
//!
//! Validated against the 6.4 reference dump (see IMPLEMENTATION_LOG for measured agreement).

use std::collections::HashMap;

use super::derive::engine::Meta;
use super::dump_gen::{type_kind, Md, Td};

#[derive(Clone, PartialEq, Eq, Hash)]
struct SigKey {
    name: String,
    params: Vec<String>,
    ret: String,
}

fn simple_name(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[i + 1..],
        _ => name,
    }
}

fn sig_key(m: &Meta, md: &Md) -> SigKey {
    let mut params = Vec::with_capacity(md.param_count as usize);
    for k in 0..md.param_count as u32 {
        let idx = md.param_start.wrapping_add(k);
        let ti = match m.param_type(idx) {
            Some(Some(t)) => t,
            _ => continue,
        };
        let mut e = crate::dummy_export::enc_type(m, ti, 0);
        if m.il2cpp_type_flags(ti as usize).map(|f| f & 0x40 != 0).unwrap_or(false) {
            e.insert(0, '&');
        }
        params.push(e);
    }
    SigKey { name: md.name.clone(), params, ret: crate::dummy_export::enc_type(m, md.ret_type, 0) }
}

/// Key matching a class method against an interface method: explicit interface implementations
/// are spelled "IFace.Method", so compare by simple method name plus canonical parameter types.
fn impl_key(m: &Meta, md: &Md) -> SigKey {
    let mut k = sig_key(m, md);
    k.name = simple_name(&md.name).to_string();
    k
}

fn object_tdi(tds: &[Td]) -> Option<usize> {
    tds.iter().position(|t| t.name == "Object" && t.namespace == "System")
}

fn parent_tdi(m: &Meta, tds: &[Td], td: &Td, obj: Option<usize>) -> Option<usize> {
    let pt = td.parent_tarr;
    if pt == u32::MAX {
        return None;
    }
    let (kind, data, _) = m.il2cpp_type(pt as usize)?;
    match kind {
        0x11 | 0x12 => {
            let tdi = data as usize;
            if tdi < tds.len() { Some(tdi) } else { None }
        }
        0x15 => m.generic_instance(data).map(|(def, _)| def as usize).filter(|d| *d < tds.len()),
        0x1C => obj,
        _ => None,
    }
}

fn interface_tdis(m: &Meta, tds: &[Td], td: &Td, ti: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let Some(start) = td.iface_start else { return out };
    let count = m.td_iface_count(ti).unwrap_or(0);
    for r in start..start + count {
        let (t, _) = m.iface_entry(r);
        if t < 0 {
            break;
        }
        let Some((ek, ed, _)) = m.il2cpp_type(t as usize) else { continue };
        if !matches!(ek, 0x11 | 0x12 | 0x15) {
            break;
        }
        let tdi = if ek == 0x15 {
            match m.generic_instance(ed) {
                Some((def, _)) => def as usize,
                None => continue,
            }
        } else {
            ed as usize
        };
        if tdi < tds.len() {
            out.push(tdi);
        }
    }
    out
}

#[derive(Default)]
struct TypeVt {
    entries: Vec<SigKey>,
    map: HashMap<SigKey, usize>,
    iface_map: HashMap<SigKey, usize>,
}

/// Compute the vtable slot for every method (index = global method index = index into Md).
/// Non-virtual / static methods stay None.
pub fn compute_slots(
    m: &Meta,
    tds: &[Td],
    per_type: &[Vec<usize>],
    mds: &[Md],
) -> Vec<Option<i32>> {
    let obj = object_tdi(tds);
    let mut slots: Vec<Option<i32>> = vec![None; mds.len()];
    let mut vts: Vec<Option<TypeVt>> = (0..tds.len()).map(|_| None).collect();
    let mut done: Vec<bool> = vec![false; tds.len()];
    let mut stack: Vec<usize> = Vec::new();

    for start in 0..tds.len() {
        if done[start] {
            continue;
        }
        stack.clear();
        let mut cur = start;
        loop {
            if done[cur] {
                break;
            }
            stack.push(cur);
            match parent_tdi(m, tds, &tds[cur], obj) {
                Some(p) if p != cur && !done[p] => cur = p,
                _ => break,
            }
        }
        while let Some(ti) = stack.pop() {
            if done[ti] {
                continue;
            }
            let t = &tds[ti];
            let is_iface = type_kind(m, tds, t) == "interface";
            let base = parent_tdi(m, tds, t, obj);
            let mut vt = match base {
                Some(p) if p != ti && vts[p].is_some() => {
                    let b = vts[p].as_ref().unwrap();
                    TypeVt { entries: b.entries.clone(), map: b.map.clone(), iface_map: HashMap::new() }
                }
                _ => TypeVt::default(),
            };
            if is_iface {
                for &gmi in &per_type[ti] {
                    let md = &mds[gmi];
                    if md.flags & 0x10 != 0 || md.flags & 0x40 == 0 {
                        continue;
                    }
                    let key = sig_key(m, md);
                    let idx = vt.entries.len();
                    vt.map.entry(key.clone()).or_insert(idx);
                    vt.entries.push(key);
                    slots[gmi] = Some(idx as i32);
                }
                vts[ti] = Some(vt);
                done[ti] = true;
                continue;
            }
            // (2) interface slots first: one per interface method, in interface order
            let ifaces = interface_tdis(m, tds, t, ti);
            for &f in &ifaces {
                for &gmi in &per_type[f] {
                    let md = &mds[gmi];
                    if md.flags & 0x10 != 0 || md.flags & 0x40 == 0 {
                        continue;
                    }
                    let key = sig_key(m, md);
                    if vt.iface_map.contains_key(&key) {
                        continue;
                    }
                    let idx = vt.entries.len();
                    vt.iface_map.insert(key.clone(), idx);
                    vt.entries.push(key);
                }
            }
            // (3) the type's own virtual newslot methods in metadata order
            for &gmi in &per_type[ti] {
                let md = &mds[gmi];
                if md.flags & 0x10 != 0 || md.flags & 0x40 == 0 {
                    continue;
                }
                let key = sig_key(m, md);
                if md.flags & 0x100 != 0 {
                    let ik = impl_key(m, md);
                    if let Some(&islot) = vt.iface_map.get(&ik) {
                        let final_ = md.flags & 0x20 != 0;
                        let explicit = md.name.contains('.');
                        slots[gmi] = Some(islot as i32);
                        if !final_ && !explicit {
                            let idx = vt.entries.len();
                            vt.map.insert(key.clone(), idx);
                            vt.entries.push(key);
                            slots[gmi] = Some(idx as i32);
                        }
                        continue;
                    }
                    let idx = vt.entries.len();
                    vt.map.insert(key.clone(), idx);
                    vt.entries.push(key);
                    slots[gmi] = Some(idx as i32);
                } else if let Some(&idx) = vt.map.get(&key) {
                    slots[gmi] = Some(idx as i32);
                } else {
                    let idx = vt.entries.len();
                    vt.map.insert(key.clone(), idx);
                    vt.entries.push(key);
                    slots[gmi] = Some(idx as i32);
                }
            }
            vts[ti] = Some(vt);
            done[ti] = true;
        }
    }
    slots
}
