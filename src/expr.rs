//! Expression tree interchange + evaluator + column transform families.
//!
//! This is the Rust half of R39 (port the cross-version pipeline out of the
//! Python prototypes in `tools/version-triage/`). The expression JSON is the
//! LANGUAGE-NEUTRAL interface produced by `symwalk.py` / `emu_chain.py`:
//!
//! ```json
//! ["imm", v] ["sym", name] ["hdr", slot, w] ["raw", off, w]
//! ["op2", op, a, b] ["lo", n, a] ["ext", n, a, signed]
//! ```
//!
//! Nodes are exactly what serde produces for the tuple variants below, so a
//! symwalk artifact loads without conversion. Column families mirror
//! `rowtable_solve.py` (FAMILIES / fam_value / fam_invert), including the
//! 32-bit domain rule: the game's own arithmetic truncates to the column
//! width, so u32 columns must be evaluated with `dom = u32::MAX` or sentinels
//! wrap into 64-bit junk.
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0.

use serde::{Deserialize, Serialize};

/// Binary operators, renamed to the exact strings the Python side emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    #[serde(rename = "+")]
    Add,
    #[serde(rename = "-")]
    Sub,
    #[serde(rename = "*")]
    Mul,
    #[serde(rename = "^")]
    Xor,
    #[serde(rename = "&")]
    And,
    #[serde(rename = "|")]
    Or,
    #[serde(rename = ">>")]
    Shr,
    #[serde(rename = "<<")]
    Shl,
}

/// symwalk expression node (see module docs for the wire format).
///
/// Serialize/Deserialize are HAND-WRITTEN for the array wire format
/// (`["imm", v]`, `["op2", op, a, b]`, ...): current serde (1.0.229) maps
/// tuple variants to `{"imm": v}` objects, but the Python tools emit and
/// consume arrays, and artifacts on disk use that shape.
#[derive(Debug, Clone)]
pub enum Expr {
    Imm(u64),
    Sym(String),
    Hdr(u32, u32),
    Raw(u32, u32),
    Op2(BinOp, Box<Expr>, Box<Expr>),
    Lo(u32, Box<Expr>),
    Ext(u32, Box<Expr>, bool),
}

impl Expr {
    /// Evaluate for row `i`. `raw` resolves a (offset, width-bytes) column
    /// load relative to the current row base; `hdr` serves the 0x210 header
    /// copy. A `sym` node evaluates to the row index (chains are pure
    /// functions of exactly one unknown).
    pub fn eval(
        &self,
        i: u64,
        hdr: &[u8],
        raw: &dyn Fn(u32, u32) -> u64,
    ) -> Result<u64, String> {
        Ok(match self {
            Expr::Imm(v) => *v,
            Expr::Sym(_) => i,
            Expr::Hdr(slot, _) => {
                let s = *slot as usize;
                if s + 4 > hdr.len() {
                    return Err(format!("hdr slot {:#x} out of range", slot));
                }
                u32::from_le_bytes(hdr[s..s + 4].try_into().unwrap()) as u64
            }
            Expr::Raw(off, w) => raw(*off, *w),
            Expr::Op2(op, a, b) => {
                let (x, y) = (a.eval(i, hdr, raw)?, b.eval(i, hdr, raw)?);
                eval_binop_pub(op, x, y)
            }
            Expr::Lo(n, a) => {
                let n = *n as u32;
                let v = a.eval(i, hdr, raw)?;
                if n >= 64 {
                    v
                } else {
                    v & ((1u64 << n) - 1)
                }
            }
            Expr::Ext(n, a, sg) => {
                let v = a.eval(i, hdr, raw)?;
                let n = *n as u32;
                if n >= 64 {
                    v
                } else if *sg && (v >> (n - 1)) & 1 == 1 {
                    v | (!0u64 << n)
                } else {
                    v & ((1u64 << n) - 1)
                }
            }
        })
    }
}

fn eval_binop_pub(op: &BinOp, x: u64, y: u64) -> u64 {
    match op {
        BinOp::Add => x.wrapping_add(y),
        BinOp::Sub => x.wrapping_sub(y),
        BinOp::Mul => x.wrapping_mul(y),
        BinOp::Xor => x ^ y,
        BinOp::And => x & y,
        BinOp::Or => x | y,
        BinOp::Shr => {
            if y >= 64 {
                0
            } else {
                x >> y
            }
        }
        BinOp::Shl => {
            if y >= 64 {
                0
            } else {
                x.wrapping_shl(y as u32)
            }
        }
    }
}

/// Column transform families (`rowtable_solve.py` FAMILIES). `dom` is the
/// integer domain mask: `u32::MAX` for u32 columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fam {
    #[serde(rename = "SubMaskAddC")]
    SubMaskAddC,
    #[serde(rename = "AddCSubMask")]
    AddCSubMask,
    #[serde(rename = "XorCXorMask")]
    XorCXorMask,
    #[serde(rename = "AddCXorMask")]
    AddCXorMask,
    #[serde(rename = "XorCSubMask")]
    XorCSubMask,
}

pub fn fam_value(fam: Fam, raw: u64, mask: u64, c: u64, dom: u64) -> u64 {
    match fam {
        Fam::SubMaskAddC => raw.wrapping_sub(mask).wrapping_add(c) & dom,
        Fam::AddCSubMask => raw.wrapping_add(c).wrapping_sub(mask) & dom,
        Fam::XorCXorMask => ((raw ^ c) ^ mask) & dom,
        Fam::AddCXorMask => ((raw.wrapping_add(c) & dom) ^ mask) & dom,
        Fam::XorCSubMask => (raw ^ c).wrapping_sub(mask) & dom,
    }
}

/// Inverse: the C for which fam_value(fam, raw, mask, C) == idx (u32 domain).
/// NOTE the XorCSubMask case: C = raw ^ ((idx + mask) mod 2^32) — the outer
/// xor is easy to miss and cost a full debugging round in the prototype.
pub fn fam_invert(fam: Fam, raw: u64, mask: u64, idx: u64) -> u64 {
    let (raw, mask, idx) = (raw as u32, mask as u32, idx as u32);
    let c = match fam {
        Fam::SubMaskAddC | Fam::AddCSubMask => idx.wrapping_sub(raw).wrapping_add(mask),
        Fam::XorCXorMask => raw ^ mask ^ idx,
        Fam::AddCXorMask => (idx ^ mask).wrapping_sub(raw),
        Fam::XorCSubMask => raw ^ idx.wrapping_add(mask),
    };
    c as u64
}


impl Serialize for Expr {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        match self {
            Expr::Imm(v) => {
                let mut t = ser.serialize_tuple(2)?;
                t.serialize_element("imm")?;
                t.serialize_element(v)?;
                t.end()
            }
            Expr::Sym(n) => {
                let mut t = ser.serialize_tuple(2)?;
                t.serialize_element("sym")?;
                t.serialize_element(n)?;
                t.end()
            }
            Expr::Hdr(a, b) => {
                let mut t = ser.serialize_tuple(3)?;
                t.serialize_element("hdr")?;
                t.serialize_element(a)?;
                t.serialize_element(b)?;
                t.end()
            }
            Expr::Raw(a, b) => {
                let mut t = ser.serialize_tuple(3)?;
                t.serialize_element("raw")?;
                t.serialize_element(a)?;
                t.serialize_element(b)?;
                t.end()
            }
            Expr::Op2(op, a, b) => {
                let mut t = ser.serialize_tuple(4)?;
                t.serialize_element("op2")?;
                t.serialize_element(op)?;
                t.serialize_element(a)?;
                t.serialize_element(b)?;
                t.end()
            }
            Expr::Lo(n, a) => {
                let mut t = ser.serialize_tuple(3)?;
                t.serialize_element("lo")?;
                t.serialize_element(n)?;
                t.serialize_element(a)?;
                t.end()
            }
            Expr::Ext(n, a, sg) => {
                let mut t = ser.serialize_tuple(4)?;
                t.serialize_element("ext")?;
                t.serialize_element(n)?;
                t.serialize_element(a)?;
                t.serialize_element(sg)?;
                t.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Expr {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Expr;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an expression array [tag, fields...]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Expr, A::Error> {
                use serde::de::Error;
                let tag: String = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("empty expression"))?;
                match tag.as_str() {
                    "imm" => Ok(Expr::Imm(req(&mut seq, "imm value")?)),
                    "sym" => Ok(Expr::Sym(req(&mut seq, "sym name")?)),
                    "hdr" => Ok(Expr::Hdr(req(&mut seq, "hdr slot")?, req(&mut seq, "hdr w")?)),
                    "raw" => Ok(Expr::Raw(req(&mut seq, "raw off")?, req(&mut seq, "raw w")?)),
                    "op2" => {
                        let op: BinOp = req(&mut seq, "op2 op")?;
                        let a: Box<Expr> = req(&mut seq, "op2 lhs")?;
                        let b: Box<Expr> = req(&mut seq, "op2 rhs")?;
                        Ok(Expr::Op2(op, a, b))
                    }
                    "lo" => Ok(Expr::Lo(req(&mut seq, "lo bits")?, req(&mut seq, "lo inner")?)),
                    "ext" => {
                        let n = req(&mut seq, "ext bits")?;
                        let a: Box<Expr> = req(&mut seq, "ext inner")?;
                        let sg: bool = req(&mut seq, "ext signed")?;
                        Ok(Expr::Ext(n, a, sg))
                    }
                    other => Err(A::Error::custom(format!("unknown tag {:?}", other))),
                }
            }
        }
        de.deserialize_seq(V)
    }
}

fn req<'de, A, T>(seq: &mut A, what: &str) -> Result<T, A::Error>
where
    A: serde::de::SeqAccess<'de>,
    T: serde::de::Deserialize<'de>,
{
    use serde::de::Error;
    seq.next_element::<T>()?
        .ok_or_else(|| A::Error::custom(format!("missing {}", what)))
}


// --------------------------------------------------------- shared utilities
/// Pretty-print in the same shape as the Python side (`0x...` immediates,
/// `rawN@0xoff`, infix ops). Regression tests match hex substrings here.
// --------------------------------------------------------- shared utilities
/// Pretty-print in the same shape as the Python side (`0x...` immediates,
/// `rawN@0xoff`, infix ops). Regression tests match hex substrings here.
impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expr::Imm(v) => write!(f, "{:#x}", v),
            Expr::Sym(n) => write!(f, "{}", n),
            Expr::Hdr(slot, _) => write!(f, "hdr[{:#x}]", slot),
            Expr::Raw(off, w) => write!(f, "raw{}@{:#x}", w, off),
            Expr::Op2(op, a, b) => {
                let o = match op {
                    BinOp::Add => "+",
                    BinOp::Sub => "-",
                    BinOp::Mul => "*",
                    BinOp::Xor => "^",
                    BinOp::And => "&",
                    BinOp::Or => "|",
                    BinOp::Shr => ">>",
                    BinOp::Shl => "<<",
                };
                write!(f, "({} {} {})", a, o, b)
            }
            Expr::Lo(n, a) => write!(f, "lo{}({})", n, a),
            Expr::Ext(n, a, sg) => write!(f, "{}ext{}({})", if *sg { "s" } else { "z" }, n, a),
        }
    }
}

pub fn expr_syms(e: &Expr, out: &mut std::collections::BTreeSet<String>) {
    match e {
        Expr::Sym(n) => {
            out.insert(n.clone());
        }
        Expr::Imm(_) | Expr::Hdr(_, _) | Expr::Raw(_, _) => {}
        Expr::Op2(_, a, b) => {
            expr_syms(a, out);
            expr_syms(b, out);
        }
        Expr::Lo(_, a) | Expr::Ext(_, a, _) => expr_syms(a, out),
    }
}

pub fn expr_syms_set(e: &Expr) -> std::collections::BTreeSet<String> {
    let mut s = std::collections::BTreeSet::new();
    expr_syms(e, &mut s);
    s
}

/// kind=true: contains Hdr; kind=false: contains Raw.
pub fn expr_has(e: &Expr, hdr: bool) -> bool {
    match e {
        Expr::Hdr(_, _) => hdr,
        Expr::Raw(_, _) => !hdr,
        Expr::Imm(_) | Expr::Sym(_) => false,
        Expr::Op2(_, a, b) => expr_has(a, hdr) || expr_has(b, hdr),
        Expr::Lo(_, a) | Expr::Ext(_, a, _) => expr_has(a, hdr),
    }
}

pub fn expr_size(e: &Expr) -> usize {
    1 + match e {
        Expr::Op2(_, a, b) => expr_size(a) + expr_size(b),
        Expr::Lo(_, a) | Expr::Ext(_, a, _) => expr_size(a),
        _ => 0,
    }
}

/// Pure-linear decomposition over symbols.
pub fn lin_terms(e: &Expr) -> Option<(std::collections::BTreeMap<String, u64>, u64)> {
    let mut m = std::collections::BTreeMap::new();
    let c = lin_rec(e, 1, &mut m)?;
    Some((m, c))
}

fn lin_rec(e: &Expr, k: u64, m: &mut std::collections::BTreeMap<String, u64>) -> Option<u64> {
    match e {
        Expr::Imm(v) => Some(v.wrapping_mul(k)),
        Expr::Sym(n) => {
            *m.entry(n.clone()).or_insert(0) = m.get(n).copied().unwrap_or(0).wrapping_add(k);
            Some(0)
        }
        Expr::Op2(BinOp::Add, a, b) => Some(lin_rec(a, k, m)?.wrapping_add(lin_rec(b, k, m)?)),
        Expr::Op2(BinOp::Sub, a, b) => Some(lin_rec(a, k, m)?.wrapping_sub(lin_rec(b, k, m)?)),
        Expr::Op2(BinOp::Mul, a, b) => {
            if let Expr::Imm(v) = a.as_ref() {
                lin_rec(b, k.wrapping_mul(*v), m)
            } else if let Expr::Imm(v) = b.as_ref() {
                lin_rec(a, k.wrapping_mul(*v), m)
            } else {
                None
            }
        }
        Expr::Op2(BinOp::Shl, a, b) => {
            if let Expr::Imm(sh) = b.as_ref() {
                if *sh < 64 {
                    return lin_rec(a, k.wrapping_mul(1u64 << sh), m);
                }
            }
            None
        }
        // lo/ext wrappers: row indices stay < 2^32 in these loops, so the
        // truncation never wraps and linear decomposition through the wrapper
        // is exact. Without this, every 32-bit loop counter kills the row
        // marker (the dominant encoding of the stride idioms).
        Expr::Lo(_, a) | Expr::Ext(_, a, _) => lin_rec(a, k, m),
        _ => None,
    }
}

/// Normalizer mirroring the Python `fold`: constant folding, coefficient
/// merging (x*A ± x*B -> x*(A ± B)), nested lo collapse. Sound mod 2^64.
pub fn fold(e: &Expr) -> Expr {
    match e {
        Expr::Imm(_) | Expr::Sym(_) | Expr::Hdr(_, _) | Expr::Raw(_, _) => e.clone(),
        Expr::Op2(op, a, b) => {
            let (a, b) = (fold(a), fold(b));
            if let (Expr::Imm(x), Expr::Imm(y)) = (&a, &b) {
                return Expr::Imm(eval_binop_pub(op, *x, *y));
            }
            if matches!(op, BinOp::Add | BinOp::Sub) {
                if let Some(out) = fold_lin_merge(*op, &a, &b) {
                    return out;
                }
            }
            match (op, &a, &b) {
                (BinOp::Add, Expr::Imm(0), _) => b,
                (BinOp::Add, _, Expr::Imm(0)) => a,
                (BinOp::Sub, _, Expr::Imm(0)) => a,
                (BinOp::Xor, _, Expr::Imm(0)) => a,
                (BinOp::Mul, _, Expr::Imm(1)) => a,
                (BinOp::Mul, Expr::Imm(1), _) => a,
                (BinOp::Mul, _, Expr::Imm(0)) => Expr::Imm(0),
                (BinOp::Mul, Expr::Imm(0), _) => Expr::Imm(0),
                _ => Expr::Op2(*op, Box::new(a), Box::new(b)),
            }
        }
        Expr::Lo(n, a) => {
            let a = fold(a);
            match &a {
                Expr::Imm(v) => Expr::Imm(v & ((1u64 << *n) - 1)),
                Expr::Raw(_, w) if w == n => a.clone(),
                Expr::Lo(m, inner) => fold(&Expr::Lo((*m).min(*n), inner.clone())),
                _ if *n >= 64 => a,
                _ => Expr::Lo(*n, Box::new(a)),
            }
        }
        Expr::Ext(n, a, sg) => {
            let a = fold(a);
            match &a {
                Expr::Imm(v) => {
                    let mut v = *v & ((1u64 << *n) - 1);
                    if *sg && *n < 64 && (v >> (*n - 1)) & 1 == 1 {
                        v |= !0u64 << *n;
                    }
                    Expr::Imm(v)
                }
                _ if *n >= 64 => a,
                _ => Expr::Ext(*n, Box::new(a), *sg),
            }
        }
    }
}

/// x*A ± x*B -> x*(A ± B) for a single shared symbol.
fn fold_lin_merge(op: BinOp, a: &Expr, b: &Expr) -> Option<Expr> {
    let (la, ca) = lin_terms(a)?;
    let (lb, cb) = lin_terms(b)?;
    let shared: Vec<String> = la.keys().filter(|k| lb.contains_key(*k)).cloned().collect();
    if shared.len() != 1 {
        return None;
    }
    let sym = shared[0].clone();
    let ka = *la.get(&sym).unwrap();
    let kb = *lb.get(&sym).unwrap();
    let (kc, cst) = match op {
        BinOp::Add => (ka.wrapping_add(kb), ca.wrapping_add(cb)),
        BinOp::Sub => (ka.wrapping_sub(kb), ca.wrapping_sub(cb)),
        _ => return None,
    };
    if kc == 0 {
        return Some(fold(&Expr::Imm(cst)));
    }
    let scaled = if kc == 1 {
        Expr::Sym(sym)
    } else {
        Expr::Op2(
            BinOp::Mul,
            Box::new(Expr::Sym(sym)),
            Box::new(Expr::Imm(kc)),
        )
    };
    Some(fold(&Expr::Op2(BinOp::Add, Box::new(scaled), Box::new(Expr::Imm(cst)))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 6.7 method-row mask chain in code form. Ground truth from the
    /// validated artifact docs/re/artifacts-6.7.0/method-param-layout.json:
    /// mask(1) = 0xE4A805CD (used to decode row 1 -> "GetText").
    fn chain67() -> Expr {
        // lo32( (((((i*0xCB87) ^ 0x1D9A1A7A) * 0x38036D18) >> 8) + 0x7964C76C) ^ 0x324CAF19 )
        let mul = Expr::Op2(
            BinOp::Mul,
            Box::new(Expr::Sym("i".into())),
            Box::new(Expr::Imm(0xCB87)),
        );
        let x1 = Expr::Op2(BinOp::Xor, Box::new(mul), Box::new(Expr::Imm(0x1D9A1A7A)));
        let prod = Expr::Op2(
            BinOp::Mul,
            Box::new(x1),
            Box::new(Expr::Imm(0x38036D18)),
        );
        let shr = Expr::Op2(BinOp::Shr, Box::new(prod), Box::new(Expr::Imm(8)));
        let add = Expr::Op2(BinOp::Add, Box::new(shr), Box::new(Expr::Imm(0x7964C76C)));
        let fin = Expr::Op2(BinOp::Xor, Box::new(add), Box::new(Expr::Imm(0x324CAF19)));
        Expr::Lo(32, Box::new(fin))
    }

    #[test]
    fn chain67_row1_matches_known_mask() {
        let hdr = [0u8; 0x210];
        let v = chain67().eval(1, &hdr, &|_, _| 0).unwrap();
        assert_eq!(v, 0xE4A805CD);
    }

    #[test]
    fn json_wire_format_parses_and_evaluates() {
        // wire-format check with small, hand-verifiable constants
        let j = r#"["op2","+",["op2","*",["sym","i"],["imm",3]],["imm",5]]"#;
        let e: Expr = serde_json::from_str(j).unwrap();
        assert_eq!(e.eval(4, &[0u8; 0x210], &|_, _| 0).unwrap(), 17);
        // lo/ext wire shapes
        let j2 = r#"["lo",8,["imm",300]]"#;
        let e2: Expr = serde_json::from_str(j2).unwrap();
        assert_eq!(e2.eval(0, &[0u8; 0x210], &|_, _| 0).unwrap(), 44);
        let j3 = r#"["ext",8,["imm",255],true]"#;
        let e3: Expr = serde_json::from_str(j3).unwrap();
        assert_eq!(e3.eval(0, &[0u8; 0x210], &|_, _| 0).unwrap(), u64::MAX);
    }

    #[test]
    fn hdr_node_reads_slot() {
        let mut hdr = [0u8; 0x210];
        hdr[0x1FC..0x200].copy_from_slice(&0x22414276u32.to_le_bytes());
        let e: Expr = serde_json::from_str(r#"["hdr",508,4]"#).unwrap();
        assert_eq!(e.eval(0, &hdr, &|_, _| 0).unwrap(), 0x22414276);
    }

    #[test]
    fn wire_bisect() {
        for (j, want) in [
            (r#"["imm",3]"#, 3u64),
            (r#"["sym","i"]"#, 7u64),
            (r#"["hdr",508,4]"#, 0u64),
            (r#"["raw",4,4]"#, 9u64),
            (r#"["op2","+",["imm",1],["imm",2]]"#, 3u64),
        ] {
            let e: Result<Expr, _> = serde_json::from_str(j);
            match e {
                Ok(e) => {
                    let v = e.eval(7, &[0u8; 0x210], &|_, _| 9).unwrap();
                    println!("{} -> {}", j, v);
                    assert_eq!(v, want);
                }
                Err(err) => panic!("{} failed: {}", j, err),
            }
        }
    }

    /// Real artifact regression: the 6.6 method chain found by emulation
    /// (R71) — mask(0) = (0*M ^ K1) + K2 must fold on constants alone.
    #[test]
    fn chain66_artifact_constants() {
        let j = r#"["lo",32,["op2","+",["op2","^",["op2","*",["sym","rcx"],["imm",27554674704714]],["imm",1397711153]],["imm",1657111429]]]"#;
        let e: Expr = serde_json::from_str(j).unwrap();
        let v0 = e.eval(0, &[0u8; 0x210], &|_, _| 0).unwrap();
        assert_eq!(v0, (0x534F6131u64 + 0x62C58385) & 0xFFFFFFFF);
        let v1 = e.eval(1, &[0u8; 0x210], &|_, _| 0).unwrap();
        assert_eq!(v1, ((0x190F9299014Au64 ^ 0x534F6131).wrapping_add(0x62C58385)) & 0xFFFFFFFF);
    }

    #[test]
    fn fam_value_invert_roundtrip_all_families() {
        let cases = [
            (Fam::SubMaskAddC, 0xDEADBEEFu64, 0x12345678u64, 0x0700_002Au64),
            (Fam::AddCSubMask, 0x0BAD_C0DE, 0x9E3779B9, 0x1A2B_3C4D),
            (Fam::XorCXorMask, 0x1111_2222, 0x3333_4444, 0x5555_6666),
            (Fam::AddCXorMask, 0x7777_8888, 0x9999_AAAA, 0xBBBB_CCCC),
            (Fam::XorCSubMask, 0xDDDD_EEEE, 0xFFFF_0000, 0x0700_002A),
        ];
        for (fam, raw, mask, idx) in cases {
            let c = fam_invert(fam, raw, mask, idx);
            let v = fam_value(fam, raw, mask, c, u32::MAX as u64);
            assert_eq!(v, idx, "family {:?} roundtrip", fam);
        }
    }

    /// 6.7 name column ground truth: XorCSubMask with C = 0x06BBF48D decodes
    /// row 1 raw to the "GetText" packed index (off 0x2A, len 7).
    #[test]
    fn name_column_67_gettext() {
        let mask = 0xE4A805CDu64;
        // raw observed at 6.7 row1 +8 (docs: method_rows.py validation)
        let raw = 0xED13F17Au64;
        let v = fam_value(Fam::XorCSubMask, raw, mask, 0x06BBF48D, u32::MAX as u64);
        assert_eq!(v, (7u64 << 24) | 0x2A);
    }
}
