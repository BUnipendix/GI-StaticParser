//! Data-side column solvers for metadata row tables — the Rust half of
//! `tools/version-triage/rowtable_solve.py` (R39 port, step 2 after
//! `expr.rs`).
//!
//! Given a table (body offset base, stride, row count), a per-row mask chain
//! (an `Expr` that is a pure function of the row index) and the heap string
//! enumeration from `mhydump strings --out`, this module pins the semantic
//! columns purely from data:
//!
//! * `solve_name_column`  — packed string-index column: C inverted from a
//!   prior-name row (cross-version stable corelib prefix), accepted when the
//!   identifier share AMONG DECODED rows is >= 95% (heap enumeration misses
//!   short strings, so the raw hit rate plateaus around 0.3-0.6 — using the
//!   overall rate as the gate was a prototype-era bug).
//! * `solve_count_column` — u8 column whose mode encodes plain 0.
//! * `solve_start_column`— u32 column whose 0xFFFFFFFF sentinel rows must
//!   coincide with count==0 and whose non-sentinel rows must equal the
//!   running count sum (methods are stored in parameter order).
//!
//! All constants are DATA (recovered per run); nothing here knows a version.
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0.

use crate::expr::{fam_invert, fam_value, fold, BinOp, Expr, Fam};
use serde::Serialize;
use std::collections::HashMap;

/// Cross-version stable corelib method-name prefix (the first methods of
/// `<Module>` / `Locale` in every build measured so far). Shipped as data,
/// not code: a build that reorders corelib only needs a different file via
/// `--prior`.
pub const PRIOR_METHOD_NAMES: &str = include_str!("../assets/prior_method_names.json");

// ------------------------------------------------------------------ heap
/// String-start offsets from `mhydump strings --out` (`0xOFF<TAB>text`).
pub struct HeapIndex {
    text: HashMap<u32, String>,
    /// (text, off) pre-sorted once — `starts_with` binary-searches the prefix
    /// range. Sorting per call (the first implementation) made `solve_table`
    /// quadratic: tens of thousands of prefix queries × an O(n log n) sort of
    /// ~500k entries each, which is why unsolvable builds ground for an hour.
    by_text: Vec<(String, u32)>,
}

impl HeapIndex {
    pub fn load(path: &str) -> std::io::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(Self::from_lines(raw.lines()))
    }

    pub fn from_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Self {
        let mut text = HashMap::new();
        for line in lines {
            if let Some(tab) = line.find('\t') {
                if let Ok(off) = u32::from_str_radix(line[..tab].trim_start_matches("0x"), 16) {
                    text.insert(off, line[tab + 1..].to_string());
                }
            }
        }
        let mut by_text: Vec<(String, u32)> =
            text.iter().map(|(o, t)| (t.clone(), *o)).collect();
        by_text.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        HeapIndex { text, by_text }
    }

    pub fn text(&self, off: u32) -> Option<&str> {
        self.text.get(&off).map(|s| &s[..])
    }

    /// Offsets whose decoded text begins with `prefix` (string starts),
    /// ascending, at most `limit`.
    pub fn starts_with(&self, prefix: &str, limit: usize) -> Vec<u32> {
        if prefix.is_empty() {
            return Vec::new();
        }
        // first key >= prefix, then walk while the prefix still matches
        let mut lo = self.by_text.partition_point(|(t, _)| t.as_str() < prefix);
        let mut out = Vec::new();
        while lo < self.by_text.len() {
            let (t, o) = &self.by_text[lo];
            if !t.starts_with(prefix) {
                break;
            }
            out.push(*o);
            if out.len() >= limit {
                break;
            }
            lo += 1;
        }
        out.sort_unstable();
        out
    }
}

pub fn is_identifier(s: &str) -> bool {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if c.is_ascii_alphabetic() || "_.<>`".contains(c) => {}
        _ => return false,
    }
    cs.all(|c| c.is_ascii_alphanumeric() || "_.<>`=+,-".contains(c))
}

// ------------------------------------------------------------ column reads
fn read_col_u32(body: &[u8], base: usize, stride: usize, off: usize, i: u64) -> Option<u32> {
    let p = base.checked_add(off)?.checked_add(stride * i as usize)?;
    if p + 4 > body.len() {
        return None;
    }
    Some(u32::from_le_bytes(body[p..p + 4].try_into().unwrap()))
}

fn read_col_u8(body: &[u8], base: usize, stride: usize, off: usize, i: u64) -> Option<u8> {
    let p = base.checked_add(off)?.checked_add(stride * i as usize)?;
    if p >= body.len() {
        return None;
    }
    Some(body[p])
}

/// Evaluate a pure chain `Expr` for rows [0, n).
pub fn eval_rows(e: &Expr, n: usize) -> Result<Vec<u64>, String> {
    let hdr = [0u8; 4];
    let mut out = Vec::with_capacity(n);
    for i in 0..n as u64 {
        out.push(e.eval(i, &hdr, &|_, _| 0)?);
    }
    Ok(out)
}

// ------------------------------------------------------------- name column
#[derive(Debug, Clone, Serialize)]
pub struct NameCol {
    pub off: usize,
    pub family: Fam,
    pub c: u64,
    pub pinned_row: usize,
    pub ok_rows: usize,
    pub idrate: f64,
}

struct DecodeStats {
    ok: usize,
    good: usize,
}

fn name_stats(
    body: &[u8],
    base: usize,
    stride: usize,
    off: usize,
    mask: &[u64],
    fam: Fam,
    c: u64,
    n: usize,
    heap: &HeapIndex,
) -> DecodeStats {
    let mut ok = 0usize;
    let mut good = 0usize;
    for i in 0..n {
        let (Some(raw), Some(&m)) = (read_col_u32(body, base, stride, off, i as u64), mask.get(i))
        else {
            continue;
        };
        let v = fam_value(fam, raw as u64, m, c, u32::MAX as u64);
        let ln = ((v >> 24) & 0xFF) as usize;
        let t = match heap.text((v & 0xFFFFFF) as u32) {
            Some(t) => t,
            None => continue,
        };
        if (1..=100).contains(&ln) && t.len() >= ln {
            ok += 1;
            if is_identifier(&t[..ln]) {
                good += 1;
            }
        }
    }
    DecodeStats { ok, good }
}

pub fn name_column_ok(col: &NameCol, sample: usize) -> bool {
    let floor = std::cmp::max(200, (0.45 * std::cmp::min(sample, 4000) as f64) as usize);
    col.ok_rows >= floor && col.idrate >= 0.95
}

/// Acceptance for SHORT-NAME tables (parameter definitions: `msg`, `fmt`,
/// `args` — 3-6 byte names). Heap-run coverage of such names is sparse even at
/// `--min-len 3` (6.5: 9 decodable rows of 4000 — the giant `ok_rows` floor
/// from the 40万-row method table rejects the CORRECT constant), so the gate
/// shifts to exact-prior evidence: every decoded row must be an identifier
/// AND the solved constant must reproduce the prior names EXACTLY on
/// non-pin rows. `exact` counts rows 1..prior.len() (row 0 is the pin).
pub fn short_name_column_ok(col: &NameCol, prior: &[String], exact: usize) -> bool {
    col.idrate >= 0.95
        && col.ok_rows >= 8
        && exact + 1 >= std::cmp::min(6, prior.len().saturating_sub(1))
}

/// Count exact prior matches for a solved (fam, C) over rows 1..prior.len().
/// `decode` = the caller's name-index decoder (fam-specific).
pub fn count_exact_prior(
    body: &[u8],
    base: usize,
    stride: usize,
    off: usize,
    mask: &[u64],
    fam: Fam,
    c: u64,
    prior: &[String],
    heap: &HeapIndex,
) -> usize {
    let mut exact = 0usize;
    for (r, name) in prior.iter().enumerate().take(64).skip(1) {
        let Some(raw) = read_col_u32(body, base, stride, off, r as u64) else {
            continue;
        };
        let m = mask.get(r).copied().unwrap_or(0);
        let v = fam_value(fam, raw as u64, m, c, u32::MAX as u64);
        let ln = ((v >> 24) & 0xFF) as usize;
        let hit = heap
            .text((v & 0xFFFFFF) as u32)
            .map(|t| t.len() >= ln && &t[..ln] == name.as_str())
            .unwrap_or(false);
        if hit {
            exact += 1;
        }
    }
    exact
}

/// Pin (off, family, C) for the packed-string-index column.
pub fn solve_name_column(
    body: &[u8],
    base: usize,
    stride: usize,
    rows: usize,
    mask: &[u64],
    heap: &HeapIndex,
    prior: &[String],
    sample: usize,
) -> Option<NameCol> {
    let nr = std::cmp::min(rows, std::cmp::max(sample, 64));
    let quick_n = std::cmp::min(nr, 40);
    let fams = [
        Fam::SubMaskAddC,
        Fam::AddCSubMask,
        Fam::XorCXorMask,
        Fam::AddCXorMask,
        Fam::XorCSubMask,
        Fam::AddMaskAddC,
    ];
    // pin rows: prior rows whose name has heap starts, LONGEST names first —
    // a long name pins the constant far more sharply (and short names are
    // exactly the ones the heap enumeration may not carry)
    let mut pin_rows: Vec<usize> = Vec::new();
    {
        let mut cand: Vec<(usize, &String)> = (0..std::cmp::min(prior.len(), 12))
            .filter(|&r| !heap.starts_with(&prior[r], 1).is_empty())
            .map(|r| (r, &prior[r]))
            .collect();
        cand.sort_by_key(|(_, n)| std::cmp::Reverse(n.len()));
        pin_rows.extend(cand.into_iter().map(|(r, _)| r).take(4));
    }
    let mut best: Option<NameCol> = None;
    for off in 0..stride.saturating_sub(3) {
        // quick reject: column must exist
        if read_col_u32(body, base, stride, off, 0).is_none() {
            continue;
        }
        for &fam in &fams {
            for &r in &pin_rows {
                let pinned_row_value = r;
                for so in heap.starts_with(&prior[r], 48) {
                    let idx = (u64::from(so)) | ((prior[r].len() as u64) << 24);
                    let Some(raw) = read_col_u32(body, base, stride, off, r as u64) else {
                        continue;
                    };
                    let c = fam_invert(fam, raw as u64, mask[r], idx);
                    let q = name_stats(body, base, stride, off, mask, fam, c, quick_n, heap);
                    if q.ok < 20 || (q.good as f64) / (q.ok.max(1) as f64) < 0.9 {
                        continue;
                    }
                    // exact-prior gate (Python _verify_name): several prior rows
                    // must decode to EXACTLY their expected name — kills
                    // constant-shift aliases on uniformly spaced heaps
                    let mut exact = 0usize;
                    for (r, name) in prior.iter().enumerate().take(16) {
                        if r == pinned_row_value {
                            continue;
                        }
                        if let (Some(raw), Some(&m)) = (
                            read_col_u32(body, base, stride, off, r as u64),
                            mask.get(r),
                        ) {
                            let v = fam_value(fam, raw as u64, m, c, u32::MAX as u64);
                            let ln = ((v >> 24) & 0xFF) as usize;
                            let hit = heap
                                .text((v & 0xFFFFFF) as u32)
                                .map(|t| t.len() >= ln && &t[..ln] == name.as_str())
                                .unwrap_or(false);
                            if hit {
                                exact += 1;
                            }
                        }
                    }
                    if exact + 1 < std::cmp::min(5, prior.len().saturating_sub(1)) {
                        continue;
                    }
                    let full = name_stats(body, base, stride, off, mask, fam, c, nr, heap);
                    let idrate = (full.good as f64) / (full.ok.max(1) as f64);
                    let cand = NameCol {
                        off,
                        family: fam,
                        c,
                        pinned_row: r,
                        ok_rows: full.ok,
                        idrate: (idrate * 10000.0).round() / 10000.0,
                    };
                    let better = match &best {
                        None => true,
                        Some(b) => (cand.ok_rows, cand.idrate) > (b.ok_rows, b.idrate),
                    };
                    if better {
                        best = Some(cand);
                    }
                }
            }
        }
    }
    best
}

// ------------------------------------------------------------ count column
#[derive(Debug, Clone, Serialize)]
pub struct CountCol {
    pub off: usize,
    pub op: String,
    pub c: u8,
    pub mean: f64,
}

#[allow(clippy::too_many_arguments)]
fn count_decode(op: &str, raw: u8, m8: u8, c: u8) -> u8 {
    match op {
        "xor" => raw ^ m8 ^ c,
        // (raw ^ C) - mask: 6.2's paramCount — xor the constant FIRST, then
        // subtract the chain value (neither plain xor nor plain sub models it)
        "xorsub" => (raw ^ c).wrapping_sub(m8),
        "sub" => raw.wrapping_sub(m8).wrapping_sub(c),
        _ => raw.wrapping_add(m8).wrapping_add(c),
    }
}

/// u8 count column: the most frequent (raw op mask) value encodes plain 0.
pub fn solve_count_column(
    body: &[u8],
    base: usize,
    stride: usize,
    rows: usize,
    mask: &[u64],
    off_max: usize,
    sample: usize,
) -> Vec<CountCol> {
    let n = std::cmp::min(rows, sample);
    let mut out = Vec::new();
    for off in 0..std::cmp::min(off_max, stride) {
        if read_col_u8(body, base, stride, off, 0).is_none() {
            continue;
        }
        for op in ["xor", "xorsub", "sub", "add"] {
            // mode of the constant-free part with C=0; for xorsub the plain-0
            // rows satisfy raw ^ m == C, so the histogram input is raw ^ m
            // (identical to xor's) and the mode IS the constant.
            let mut hist = [0usize; 256];
            let mut cnt = 0usize;
            for i in 0..n {
                if let (Some(raw), Some(&m)) =
                    (read_col_u8(body, base, stride, off, i as u64), mask.get(i))
                {
                    let key = if op == "xorsub" {
                        raw ^ (m & 0xFF) as u8
                    } else {
                        count_decode(op, raw, (m & 0xFF) as u8, 0)
                    };
                    hist[key as usize] += 1;
                    cnt += 1;
                }
            }
            if cnt == 0 {
                continue;
            }
            let mode = hist
                .iter()
                .enumerate()
                .max_by_key(|(v, h)| (*h, *v))
                .map(|(v, _)| v)
                .unwrap_or(0) as u8;
            let c = match op {
                "xor" | "xorsub" => mode,
                "sub" => mode,
                _ => mode.wrapping_neg(),
            };
            // validate
            let (mut mn, mut mx, mut sum) = (u8::MAX, 0u8, 0usize);
            for i in 0..n {
                if let (Some(raw), Some(&m)) =
                    (read_col_u8(body, base, stride, off, i as u64), mask.get(i))
                {
                    let v = count_decode(op, raw, (m & 0xFF) as u8, c);
                    mn = mn.min(v);
                    mx = mx.max(v);
                    sum += v as usize;
                }
            }
            if mn == 0 && mx <= 32 && (sum as f64) / (cnt as f64) < 2.5 {
                out.push(CountCol {
                    off,
                    op: op.to_string(),
                    c,
                    mean: (sum as f64) / (cnt as f64),
                });
            }
        }
    }
    out
}

// ------------------------------------------------------------ start column
#[derive(Debug, Clone, Serialize)]
pub struct StartCol {
    pub off: usize,
    pub family: Fam,
    pub c: u64,
    pub chain_bad: usize,
    pub sentinel_ok: usize,
    pub sentinel_total: usize,
    pub sum_counts: u64,
}

/// u32 start column: pin C from the 0xFFFFFFFF sentinel (count==0 rows), then
/// verify non-sentinel rows equal the running count sum.
pub fn solve_start_column(
    body: &[u8],
    base: usize,
    stride: usize,
    rows: usize,
    mask: &[u64],
    count: &CountCol,
) -> Vec<StartCol> {
    // decode the count column over all rows
    let mut cnt = Vec::with_capacity(rows);
    for i in 0..rows {
        match (read_col_u8(body, base, stride, count.off, i as u64), mask.get(i)) {
            (Some(raw), Some(&m)) => cnt.push(count_decode(
                &count.op,
                raw,
                (m & 0xFF) as u8,
                count.c,
            ) as u64),
            _ => cnt.push(0),
        }
    }
    let sentinel_rows: Vec<usize> = (0..rows).filter(|&i| cnt[i] == 0).collect();
    if sentinel_rows.is_empty() {
        return Vec::new();
    }
    let r0 = sentinel_rows[0];
    // exclusive prefix sum
    let mut cum = Vec::with_capacity(rows);
    let mut acc = 0u64;
    for c in &cnt {
        cum.push(acc);
        acc += c;
    }
    let fams = [
        Fam::SubMaskAddC,
        Fam::AddCSubMask,
        Fam::XorCXorMask,
        Fam::AddCXorMask,
        Fam::XorCSubMask,
        Fam::AddMaskAddC,
    ];
    let mut out = Vec::new();
    for off in 0..stride.saturating_sub(3) {
        let Some(raw0) = read_col_u32(body, base, stride, off, r0 as u64) else {
            continue;
        };
        for &fam in &fams {
            let c = fam_invert(fam, raw0 as u64, mask[r0], 0xFFFF_FFFF);
            let mut sent_ok = 0usize;
            let mut is_sent = vec![false; rows];
            let mut any = false;
            for i in 0..rows {
                if let (Some(raw), Some(&m)) =
                    (read_col_u32(body, base, stride, off, i as u64), mask.get(i))
                {
                    let v = fam_value(fam, raw as u64, m, c, u32::MAX as u64);
                    let s = v == 0xFFFF_FFFF;
                    is_sent[i] = s;
                    any = true;
                    if s && cnt[i] == 0 {
                        sent_ok += 1;
                    }
                }
            }
            if !any {
                continue;
            }
            let disagree = (0..rows)
                .filter(|&i| is_sent[i] != (cnt[i] == 0))
                .count();
            let sent_total = sentinel_rows.len();
            if sent_ok + 8 < (sent_total as f64 * 0.98) as usize
                || disagree > rows / 1000 + 8
            {
                continue;
            }
            let bad = (0..rows)
                .filter(|&i| {
                    if is_sent[i] {
                        return false;
                    }
                    match read_col_u32(body, base, stride, off, i as u64) {
                        Some(raw) => {
                            let m = mask.get(i).copied().unwrap_or(0);
                            fam_value(fam, raw as u64, m, c, u32::MAX as u64) != cum[i]
                        }
                        None => false,
                    }
                })
                .count();
            // Real tables carry a handful of irregular rows (7.1: 39 of
            // 733,481 = hidden/wrapper methods whose paramStart is not the
            // running sum) — a constant gate would reject the CORRECT
            // constant at scale. Rate-scaled: 0.1% + a small floor.
            if bad > rows / 1000 + 16 {
                continue;
            }
            out.push(StartCol {
                off,
                family: fam,
                c,
                chain_bad: bad,
                sentinel_ok: sent_ok,
                sentinel_total: sent_total,
                sum_counts: acc,
            });
        }
    }
    out.sort_by(|a, b| a.chain_bad.cmp(&b.chain_bad).then(b.sentinel_ok.cmp(&a.sentinel_ok)));
    out.truncate(4);
    out
}

// --------------------------------------------------------------- reports
#[derive(Serialize)]
pub struct TableReport {
    pub base: usize,
    pub stride: usize,
    pub rows: usize,
    pub chain: Expr,
    pub name: Option<NameCol>,
    pub counts: Vec<CountCol>,
    pub starts: Vec<StartCol>,
    /// Sum of the decoded count column over ALL rows (counts[0]). Carries the
    /// parameter-table row count even when the start column stays unsolved
    /// (6.2: count solved via the xorsub family, start uses a layout the u32
    /// solver does not model yet) — the param slice needs this row count.
    #[serde(default)]
    pub count_sum: u64,
}

/// End-to-end: pick the first chain that yields an accepted name column, then
/// solve count/start on that (base, chain). Start is validated against EACH
/// count candidate in turn — the count scan can surface a spurious earlier
/// byte column that passes the mode gate, and pairing starts with it fails
/// wholesale (the 7.1 mask2 run: counts hit a decoy, real count at +24).
pub fn solve_table(
    body: &[u8],
    base: usize,
    stride: usize,
    rows: usize,
    chains: &[Expr],
    heap: &HeapIndex,
    prior: &[String],
) -> Option<TableReport> {
    for chain in chains {
        let Ok(mask) = eval_rows(chain, std::cmp::min(rows, 4000)) else {
            continue;
        };
        if let Some(name) = solve_name_column(body, base, stride, rows, &mask, heap, prior, 4000) {
            if !name_column_ok(&name, 4000) {
                continue;
            }
            // full-length mask for count/start
            if let Ok(full_mask) = eval_rows(chain, rows) {
                let counts = solve_count_column(body, base, stride, rows, &full_mask, stride, 20_000);
                let count_sum = counts.first().map(|c| {
                    (0..rows as u64)
                        .filter_map(|i| {
                            let raw = read_col_u8(body, base, stride, c.off, i)?;
                            let m = full_mask.get(i as usize)?;
                            Some(count_decode(&c.op, raw, (m & 0xFF) as u8, c.c) as u64)
                        })
                        .sum::<u64>()
                }).unwrap_or(0);
                let mut starts = Vec::new();
                for c in counts.iter().take(4) {
                    // the internal gate already tolerates a rate of irregular
                    // rows; any survivor here is a valid start column
                    let st = solve_start_column(body, base, stride, rows, &full_mask, c);
                    if !st.is_empty() {
                        starts = st;
                        break;
                    }
                }
                return Some(TableReport {
                    base,
                    stride,
                    rows,
                    chain: chain.clone(),
                    name: Some(name),
                    counts,
                    starts,
                    count_sum,
                });
            }
        }
    }
    None
}

/// Lenient loader for chain pools: accepts a symwalk artifact
/// (`{"chains":[{"expr":...}]}`), a pool (`[{"expr":...}]`) or a bare array
/// of expressions.
pub fn load_chains(path: &str) -> Result<Vec<Expr>, String> {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let items: Vec<serde_json::Value> = match &v {
        serde_json::Value::Object(o) => o
            .get("chains")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default(),
        serde_json::Value::Array(a) => a.clone(),
        _ => return Err("unexpected chains JSON shape".into()),
    };
    let mut out = Vec::new();
    for it in items {
        let target = if it.is_object() {
            it.get("expr").cloned().ok_or("item missing expr")?
        } else {
            it
        };
        let e: Expr = serde_json::from_value(target).map_err(|e| e.to_string())?;
        out.push(e);
    }
    Ok(out)
}

/// Algebraic variants of a solved chain: additive shifts E±k for a handful of
/// constants observed as split addends in real accessors. When a game computes
/// `(raw ^ X1) - mask(i) + X2`, the X2 can live on either side; generating
/// E±k lets `solve_name_column`'s family inversion find the same column under
/// the OTHER form without needing a wider family set.
/// (Constants chosen from the 6.5 field accessor: its +0x847BFC89 sits outside
/// the chain while the mask itself is `(A0 + i*K) ^ X`.)
pub fn chain_variants(e: &Expr) -> Vec<Expr> {
    const KS: [u64; 8] = [
        0x847B_FC89,
        0x6AD4_D25D,
        0x81EC_E8F8,
        0x20B9_E5BE,
        0x2DD4_3D8D,
        0x2DD4_3D8Du64.wrapping_neg(),
        0x847B_FC89u64.wrapping_neg(),
        0x6AD4_D25Du64.wrapping_neg(),
    ];
    let mut out = vec![e.clone()];
    // negation: `raw + chain + C` is `raw - (-chain) + C` — the same
    // SubMaskAddC family on the flipped chain, with inversion unchanged
    // (6.5 param: `lea ecx,[rax+r14]; add ecx,0x92a9143c`)
    out.push(fold(&Expr::Op2(
        BinOp::Sub,
        Box::new(Expr::Imm(0)),
        Box::new(e.clone()),
    )));
    for k in KS {
        out.push(fold(&Expr::Op2(
            BinOp::Add,
            Box::new(e.clone()),
            Box::new(Expr::Imm(k)),
        )));
        out.push(fold(&Expr::Op2(
            BinOp::Sub,
            Box::new(e.clone()),
            Box::new(Expr::Imm(k)),
        )));
    }
    out
}

pub fn load_prior(path: Option<&str>) -> Result<Vec<String>, String> {
    match path {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string()),
        None => serde_json::from_str(PRIOR_METHOD_NAMES).map_err(|e| e.to_string()),
    }
}

// ---------------------------------------------------- differential locator

/// One name column located by differential invariants.
#[derive(Debug, Clone, Serialize)]
pub struct DiffHit {
    /// Byte offset of the row-0 raw u32 inside the body (4-aligned).
    pub col_pos: usize,
    pub fam: Fam,
    pub c: u64,
    /// Prior rows whose decode lands on a heap candidate for their name.
    pub hits: usize,
    /// Index into the chain pool of the winning chain.
    pub chain_idx: usize,
    /// Mask transform applied to the pool chain for this hit: the xor
    /// classes' row difference is not invariant under an additive mask
    /// shift, so phase 2 scans `mask = raw ± k` / `mask = -raw` variants;
    /// the caller must reproduce the same transform before validating.
    pub shift: u64,
    pub negated: bool,
}

/// Locate a u32 name column without knowing its base, its family constant, or
/// which function decodes it.
///
/// For every transform family the difference between two rows' raw values is
/// independent of the family constant C (linear families differ by the packed
/// values plus the mask delta, xor families by the masked packed values).
/// Expected packed indices for two consecutive rows come from the prior-name
/// list cross the heap (`(len<<24)|off` candidates); each (chain, candidate
/// pair) fixes the expected difference, and a single pass over the body's u32
/// words finds every column position reproducing it. C is then solved from the
/// anchor row and verified against all prior rows.
///
/// This replaces the anchor-sweep enumeration (bases × chains × families,
/// minutes on 6.2) with one bounded scan (seconds), and doubles as a POOL
/// PROBE: zero hits means no chain in the pool reproduces the prior names
/// under any family the sweep would try either — the sweep can be skipped.
/// Validated against 6.5 param before wiring in (rediscovered col 0x19D8E70
/// AddMaskAddC 0x92A9143C exactly, 28/28 prior rows).
///
/// `AddCXorMask` is not scanned: its row difference is NOT C-free
/// (`(a-C)^(b-C) != a^b`); it stays covered by `solve_name_column`.
pub fn locate_name_column_differential(
    body: &[u8],
    stride: usize,
    chains: &[Expr],
    prior: &[String],
    heap: &HeapIndex,
    min_hits: usize,
) -> Vec<DiffHit> {
    if stride % 4 != 0 || stride < 8 || chains.is_empty() {
        return Vec::new();
    }
    let rows_known = std::cmp::min(prior.len(), 48);
    if rows_known < 2 {
        return Vec::new();
    }
    let n = rows_known + 8;
    // packed candidates per prior row (heap starts cross the expected length)
    let cands: Vec<Vec<u64>> = (0..rows_known)
        .map(|r| {
            heap.starts_with(&prior[r], 3)
                .into_iter()
                .map(|o| (((prior[r].len() as u64) << 24) | o as u64) & 0xFFFF_FFFF)
                .collect()
        })
        .collect();
    // consecutive known pairs, most-constrained first (fewest candidates)
    let mut pairs: Vec<usize> = (0..rows_known - 1)
        .filter(|&r| !cands[r].is_empty() && !cands[r + 1].is_empty())
        .collect();
    if pairs.is_empty() {
        return Vec::new();
    }
    pairs.sort_by_key(|&r| cands[r].len() * cands[r + 1].len());
    pairs.truncate(2);

    let st = stride / 4;
    let masks: Vec<Vec<u64>> = chains
        .iter()
        .filter_map(|c| eval_rows(c, n).ok())
        .map(|m| m.into_iter().map(|v| v & 0xFFFF_FFFF).collect())
        .collect();
    if masks.is_empty() {
        return Vec::new();
    }

    let uwords = body.len() / 4;
    let u: Vec<u32> = body
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let mut out: Vec<DiffHit> = Vec::new();

    // scan one diff class for one (fam, mask-set); a nested item fn so the
    // mutable `out` doesn't hold a long-lived borrow across the phases.
    //
    // Classes: linear-add (SubMaskAddC == AddCSubMask), add-mask
    // (AddMaskAddC), xor-sub (XorCSubMask), xor-xor (XorCXorMask). `meta`
    // describes each mask row set as (chain index, additive shift, negated)
    // — the xor classes' row difference is NOT invariant under an additive
    // mask shift, unlike the linear classes, and the pool may carry the true
    // mask ± a split addend (6.5 field: true = pool chain ∓ 0x847bfc89).
    fn scan_class(
        u: &[u32],
        diff: &[u32],
        st: usize,
        rows_known: usize,
        cands: &[Vec<u64>],
        pairs: &[usize],
        out: &mut Vec<DiffHit>,
        min_hits: usize,
        uwords: usize,
        fam: Fam,
        ml: &[Vec<u64>],
        meta: &[(usize, u64, bool)],
    ) {
        for (m, &(ci, vshift, vneg)) in ml.iter().zip(meta) {
            for &r0 in pairs {
                let r1 = r0 + 1;
                for &v0 in cands[r0].iter().take(3) {
                    for &v1 in cands[r1].iter().take(3) {
                        let m0 = m[r0] as u32;
                        let m1 = m[r1] as u32;
                        let p0: u32 = match fam {
                            Fam::SubMaskAddC | Fam::AddCSubMask => {
                                ((v1 as u32).wrapping_sub(v0 as u32))
                                    .wrapping_add(m1.wrapping_sub(m0))
                            }
                            Fam::AddMaskAddC => ((v1 as u32).wrapping_sub(v0 as u32))
                                .wrapping_sub(m1.wrapping_sub(m0)),
                            Fam::XorCSubMask => {
                                ((v1 as u32).wrapping_add(m1)) ^ ((v0 as u32).wrapping_add(m0))
                            }
                            _ => (v1 as u32) ^ m1 ^ (v0 as u32) ^ m0,
                        };
                        let mut found = 0usize;
                        for (k, &d) in diff.iter().enumerate() {
                            if d != p0 {
                                continue;
                            }
                            let cw = k as i64 - st as i64 * r0 as i64;
                            if cw < 0 || (cw as usize) + st * (rows_known - 1) >= uwords {
                                continue;
                            }
                            let cw = cw as usize;
                            let raw0 = u[k] as u64;
                            let c: u64 = match fam {
                                Fam::SubMaskAddC | Fam::AddCSubMask => {
                                    v0.wrapping_sub(raw0).wrapping_add(m0 as u64) & 0xFFFF_FFFF
                                }
                                Fam::AddMaskAddC => {
                                    v0.wrapping_sub(raw0).wrapping_sub(m0 as u64) & 0xFFFF_FFFF
                                }
                                Fam::XorCSubMask => {
                                    (((raw0 as u32) ^ (v0 as u32).wrapping_add(m0)) as u64)
                                        & 0xFFFF_FFFF
                                }
                                _ => (raw0 as u32 ^ m0 ^ v0 as u32) as u64,
                            };
                            let mut hits = 0usize;
                            for r in 0..rows_known {
                                if cands[r].is_empty() {
                                    continue;
                                }
                                let w = cw + st * r;
                                let v = fam_value(fam, u[w] as u64, m[r], c, u32::MAX as u64);
                                if cands[r].contains(&(v & 0xFFFF_FFFF)) {
                                    hits += 1;
                                }
                            }
                            if hits >= min_hits {
                                out.push(DiffHit {
                                    col_pos: cw * 4,
                                    fam,
                                    c,
                                    hits,
                                    chain_idx: ci,
                                    shift: vshift,
                                    negated: vneg,
                                });
                            }
                            found += 1;
                            if found >= 8 {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    let idmap: Vec<usize> = (0..masks.len()).collect();
    let nometa: Vec<(usize, u64, bool)> =
        masks.iter().enumerate().map(|(ci, _)| (ci, 0, false)).collect();

    // Linear families share one diff array and are invariant under additive
    // mask shifts (the shift cancels in the row difference), so the raw pool
    // masks suffice; the negated chain is the AddMaskAddC class itself.
    // Build lazily, drop before the xor class to keep peak memory at two
    // body-sized buffers.
    {
        let add_d: Vec<u32> = (0..uwords - st)
            .map(|k| u[k + st].wrapping_sub(u[k]))
            .collect();
        scan_class(&u, &add_d, st, rows_known, &cands, &pairs, &mut out, min_hits, uwords, Fam::SubMaskAddC, &masks, &nometa);
        scan_class(&u, &add_d, st, rows_known, &cands, &pairs, &mut out, min_hits, uwords, Fam::AddMaskAddC, &masks, &nometa);
    }
    {
        // XOR classes: the row difference mixes mask and value additively
        // before the xor, so an additive mask shift does NOT cancel. Phase 1
        // scans the raw pool masks (the common case); on zero hits phase 2
        // retries with the same shift/negation variants chain_variants
        // enumerates for the sweep.
        let xor_d: Vec<u32> = (0..uwords - st).map(|k| u[k + st] ^ u[k]).collect();
        const KS: [u64; 8] = [
            0x847B_FC89,
            0x6AD4_D25D,
            0x81EC_E8F8,
            0x20B9_E5BE,
            0x2DD4_3D8D,
            0x2DD4_3D8Du64.wrapping_neg(),
            0x847B_FC89u64.wrapping_neg(),
            0x6AD4_D25Du64.wrapping_neg(),
        ];
        scan_class(&u, &xor_d, st, rows_known, &cands, &pairs, &mut out, min_hits, uwords, Fam::XorCSubMask, &masks, &nometa);
        scan_class(&u, &xor_d, st, rows_known, &cands, &pairs, &mut out, min_hits, uwords, Fam::XorCXorMask, &masks, &nometa);
        if out.is_empty() {
            let mut vmasks: Vec<Vec<u64>> = Vec::new();
            let mut vmeta: Vec<(usize, u64, bool)> = Vec::new();
            for (ci, m) in masks.iter().enumerate() {
                let neg: Vec<u64> =
                    m.iter().map(|v| v.wrapping_neg() & 0xFFFF_FFFF).collect();
                vmasks.push(neg);
                vmeta.push((ci, 0, true));
                for k in KS {
                    let shifted: Vec<u64> = m
                        .iter()
                        .map(|v| (v.wrapping_add(k)) & 0xFFFF_FFFF)
                        .collect();
                    vmasks.push(shifted);
                    vmeta.push((ci, k, false));
                }
            }
            // the best anchor pair only: phase 2 is the rare path
            let keep = pairs.clone();
            let pairs1: Vec<usize> = pairs.iter().take(1).copied().collect();
            scan_class(&u, &xor_d, st, rows_known, &cands, &pairs1, &mut out, min_hits, uwords, Fam::XorCSubMask, &vmasks, &vmeta);
            scan_class(&u, &xor_d, st, rows_known, &cands, &pairs1, &mut out, min_hits, uwords, Fam::XorCXorMask, &vmasks, &vmeta);
            pairs = keep;
        }
    }
    out.sort_by_key(|h| std::cmp::Reverse(h.hits));
    out.dedup_by(|a, b| a.col_pos == b.col_pos && a.fam == b.fam && a.c == b.c);
    out
}

/// Validate an externally-solved (off, fam, C) name column — e.g. the
/// differential locator's output — through the same DecodeStats the
/// pin-based solver scores with, so acceptance gates stay identical.
pub fn validate_solved_name(
    body: &[u8],
    base: usize,
    stride: usize,
    off: usize,
    mask: &[u64],
    fam: Fam,
    c: u64,
    heap: &HeapIndex,
    sample: usize,
) -> NameCol {
    let st = name_stats(body, base, stride, off, mask, fam, c, sample, heap);
    NameCol {
        off,
        family: fam,
        c,
        pinned_row: 0,
        ok_rows: st.ok,
        idrate: st.good as f64 / st.ok.max(1) as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::BinOp;

    fn chain_synthetic() -> Expr {
        // mask(i) = lo32(i * 0x9E3779B1 + 0x1234567)
        Expr::Lo(
            32,
            Box::new(Expr::Op2(
                BinOp::Add,
                Box::new(Expr::Op2(
                    BinOp::Mul,
                    Box::new(Expr::Sym("i".into())),
                    Box::new(Expr::Imm(0x9E3779B1)),
                )),
                Box::new(Expr::Imm(0x1234567)),
            )),
        )
    }

    fn enc_xcsm(raw: u64, mask: u64, c: u64) -> u64 {
        // inverse of XorCSubMask value = ((raw ^ c) - mask)
        ((raw + mask) & 0xFFFFFFFF) ^ c
    }

    /// Differential locator, synthetic: a stride-8 table whose name column
    /// sits at off 4 (XorCSubMask) next to a decoy u32 slot. The locator must
    /// recover the column's position, family and constant from the prior
    /// names alone.
    #[test]
    fn differential_locator_synthetic() {
        let stride = 8usize;
        let rows = 32usize;
        let c_x = 0x06BB_F48Du64;
        let mut body = vec![0u8; 0x1000 + stride * rows];
        let mut heap_lines: Vec<String> = Vec::new();
        let mut prior: Vec<String> = Vec::new();
        for i in 0..rows {
            let m = chain_synthetic().eval(i as u64, &[0u8; 4], &|_, _| 0).unwrap();
            let name = if i == 0 { "msg" } else { &format!("Param{}", i) };
            let hoff = 0x40 + i * 11;
            heap_lines.push(format!("{:#08x}\t{}", hoff, name));
            if i < 8 {
                prior.push(name.to_string());
            }
            let idx = ((name.len() as u64) << 24) | hoff as u64;
            // name column at off 4: XorCSubMask
            body[i * stride + 4..i * stride + 8]
                .copy_from_slice(&(enc_xcsm(idx, m, c_x) as u32).to_le_bytes());
            // decoy slot at off 0: noise that must not decode anywhere
            body[i * stride..i * stride + 4]
                .copy_from_slice(&((0x1234_5678u32 ^ (i as u32 * 0x9E3779B1)).to_le_bytes()));
        }
        let heap = HeapIndex::from_lines(heap_lines.iter().map(|s| s.as_str()));
        let chain = chain_synthetic();
        let hits = locate_name_column_differential(&body, stride, &[chain], &prior, &heap, 6);
        assert!(
            hits.iter().any(|h| h.col_pos == 4 && h.fam == Fam::XorCSubMask && h.c == c_x),
            "XorCSubMask column not located: {:?}",
            hits
        );
    }

    /// Same instrument against an AddMaskAddC column (6.5 param family):
    /// `v = raw + m + C` — the mask's sign cannot fold into the constant.
    #[test]
    fn differential_locator_addmask() {
        let stride = 8usize;
        let rows = 32usize;
        let c_a = 0x92A9_143Cu64;
        let mut body = vec![0u8; 0x1000 + stride * rows];
        let mut heap_lines: Vec<String> = Vec::new();
        let mut prior: Vec<String> = Vec::new();
        for i in 0..rows {
            let m = chain_synthetic().eval(i as u64, &[0u8; 4], &|_, _| 0).unwrap();
            let name = if i == 0 { "msg" } else { &format!("Arg{}", i) };
            let hoff = 0x40 + i * 11;
            heap_lines.push(format!("{:#08x}\t{}", hoff, name));
            if i < 8 {
                prior.push(name.to_string());
            }
            let idx = ((name.len() as u64) << 24) | hoff as u64;
            let raw = (idx.wrapping_sub(m).wrapping_sub(c_a)) & 0xFFFF_FFFF;
            body[i * stride..i * stride + 4].copy_from_slice(&(raw as u32).to_le_bytes());
        }
        let heap = HeapIndex::from_lines(heap_lines.iter().map(|s| s.as_str()));
        let chain = chain_synthetic();
        let hits = locate_name_column_differential(&body, stride, &[chain], &prior, &heap, 6);
        assert!(
            hits.iter().any(|h| h.col_pos == 0 && h.fam == Fam::AddMaskAddC && h.c == c_a),
            "AddMaskAddC column not located: {:?}",
            hits
        );
    }

    /// Synthetic 40-row table: name col at +8 (XorCSubMask), count at +24
    /// (sub, C=0xA8), start at +0 (XorCSubMask, sentinel on count==0 rows).
    fn synth_table() -> (Vec<u8>, HeapIndex, Vec<String>) {
        let stride = 26usize;
        let rows = 40usize;
        let c_name = 0x06BBF48Du64;
        let mut body = vec![0u8; stride * rows + 64];
        let mut heap_lines: Vec<String> = Vec::new();
        let mut prior = Vec::new();
        for i in 0..rows {
            let m = {
                let e = chain_synthetic();
                e.eval(i as u64, &[0u8; 4], &|_, _| 0).unwrap()
            };
            let name = if i == 0 { "Ctor0" } else { &format!("Method{}", i) };
            if !name.is_empty() {
                let hoff = 8 + i * 13; // non-uniform spacing: shift aliases must break
                heap_lines.push(format!("{:#08x}\t{}", hoff, name));
                if i <= 6 {
                    prior.push(name.to_string());
                }
            }
            let idx: u64 = if name.is_empty() {
                0xFFFF_FFFF
            } else {
                ((name.len() as u64) << 24) | (8 + i * 13) as u64
            };
            let raw_name = enc_xcsm(idx, m, c_name);
            body[i * stride + 8..i * stride + 12]
                .copy_from_slice(&(raw_name as u32).to_le_bytes());
            // count: sub family value = raw - mask8 - C, zeros dominate
            let cnt = if i % 2 == 0 { 0u8 } else { (i % 3 + 1) as u8 };
            let raw_cnt = cnt.wrapping_add((m & 0xFF) as u8).wrapping_add(0xA8);
            body[i * stride + 24] = raw_cnt;
            // start col: sentinel iff cnt==0 else running sum
            let mut cum = 0u32;
            for j in 0..i {
                cum += if j % 2 == 0 { 0u8 } else { (j % 3 + 1) as u8 } as u32;
            }
            let st: u64 = if i % 2 == 0 { 0xFFFF_FFFF } else { cum as u64 };
            let raw_st = enc_xcsm(st, m, 0xD62B555);
            body[i * stride..i * stride + 4].copy_from_slice(&(raw_st as u32).to_le_bytes());
        }
        let heap = HeapIndex::from_lines(heap_lines.iter().map(|s| s.as_str()));
        (body, heap, prior)
    }

    #[test]
    fn synthetic_name_count_start() {
        let (body, heap, prior) = synth_table();
        let mask = eval_rows(&chain_synthetic(), 40).unwrap();
        let name =
            solve_name_column(&body, 0, 26, 40, &mask, &heap, &prior, 40).expect("name col");
        assert_eq!(name.off, 8);
        assert_eq!(name.family, Fam::XorCSubMask);
        assert_eq!(name.c, 0x06BBF48D);
        let counts = solve_count_column(&body, 0, 26, 40, &mask, 26, 40);
        let cnt = counts
            .iter()
            .find(|c| c.off == 24 && c.op == "sub" && c.c == 0xA8)
            .expect("count col");
        assert_eq!(cnt.c, 0xA8);
        let starts = solve_start_column(&body, 0, 26, 40, &mask, cnt);
        let st = starts
            .iter()
            .find(|s| s.off == 0 && s.chain_bad == 0)
            .expect("start col");
        assert_eq!(st.sentinel_ok, st.sentinel_total);
    }

    /// Ground truth against the real 6.7.0 sample. Constants below are the
    /// VALIDATED artifact (docs/re/artifacts-6.7.0), used only to check the
    /// solver reproduces them from data. Run with:
    ///   MHY_SAMPLE_EXE=... MHY_SAMPLE_DAT=... MHY_SAMPLE_STRINGS=... \
    ///   cargo test rowtable_67 -- --ignored --nocapture
    #[test]
    #[ignore]
    fn rowtable_67_ground_truth() {
        let exe = std::env::var("MHY_SAMPLE_EXE").expect("MHY_SAMPLE_EXE");
        let dat = std::env::var("MHY_SAMPLE_DAT").expect("MHY_SAMPLE_DAT");
        let strings = std::env::var("MHY_SAMPLE_STRINGS").expect("MHY_SAMPLE_STRINGS");
        let d = std::fs::read(&exe).unwrap();
        let md = std::fs::read(&dat).unwrap();
        // find the MHY header blob (plain "MHY\0" scan)
        let pos = d.windows(4).position(|w| w == b"MHY\0").expect("blob");
        let hdr = &d[pos..pos + 0x210];
        let slot = u32::from_le_bytes(hdr[0x38..0x3C].try_into().unwrap());
        let base = (slot as u64).wrapping_add(0xD515CAA3) as usize & 0xFFFFFFFF;
        let body = &md[0x210..];
        let rows = 687467usize;
        // known-good chain (code form; see expr.rs tests)
        let mul = Expr::Op2(
            BinOp::Mul,
            Box::new(Expr::Sym("i".into())),
            Box::new(Expr::Imm(0xCB87)),
        );
        let x1 = Expr::Op2(BinOp::Xor, Box::new(mul), Box::new(Expr::Imm(0x1D9A1A7A)));
        let prod = Expr::Op2(BinOp::Mul, Box::new(x1), Box::new(Expr::Imm(0x38036D18)));
        let shr = Expr::Op2(BinOp::Shr, Box::new(prod), Box::new(Expr::Imm(8)));
        let add = Expr::Op2(BinOp::Add, Box::new(shr), Box::new(Expr::Imm(0x7964C76C)));
        let fin = Expr::Op2(BinOp::Xor, Box::new(add), Box::new(Expr::Imm(0x324CAF19)));
        let chain = Expr::Lo(32, Box::new(fin));
        let heap = HeapIndex::load(&strings).unwrap();
        let prior = load_prior(None).unwrap();
        let mask = eval_rows(&chain, 4000).unwrap();
        let name =
            solve_name_column(body, base, 26, rows, &mask, &heap, &prior, 4000).expect("name");
        println!("name col: {:?}", name);
        assert_eq!(name.off, 8);
        assert_eq!(name.family, Fam::XorCSubMask);
        assert_eq!(name.c, 0x06BBF48D);
        let full_mask = eval_rows(&chain, rows).unwrap();
        let counts = solve_count_column(body, base, 26, rows, &full_mask, 26, 20_000);
        println!("counts: {:?}", counts);
        // sub-family C=88 is the same transform as add-family +0xA8 (mod 256)
        assert!(counts.iter().any(|c| c.off == 24 && c.op == "sub" && c.c == 88));
        let cnt = counts.iter().find(|c| c.off == 24).unwrap();
        let starts = solve_start_column(body, base, 26, rows, &full_mask, cnt);
        println!("starts: {:?}", starts);
        let st = starts.first().expect("start col");
        assert_eq!(st.off, 0);
        assert_eq!(st.c, 0xD62B555);
        assert_eq!(st.chain_bad, 0);
    }

    #[test]
    fn heap_index_parses_lines() {
        let h = HeapIndex::from_lines(["0x000000\tmscorlib", "0x2a\tGetTextG"].into_iter());
        assert_eq!(h.text(0).unwrap(), "mscorlib");
        assert_eq!(h.starts_with("GetText", 4), vec![0x2a]);
    }
}
