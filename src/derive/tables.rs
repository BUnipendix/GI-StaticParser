//! Constant-free location of the metadata row tables.
//!
//! ## The predicate
//!
//! The typeDef table carries two columns that are *opaque* per row (`fieldStart`
//! is a per-build XOR transform, so the raw column is noise) but whose *decoded*
//! value is a dense index into the field table. Write it as
//!
//! ```text
//! raw(i) = fs(i) ^ C          (real row, 0 <= fs(i) < T)
//! raw(i) = 0xFFFFFFFF ^ C     (the "no fields" sentinel)
//! ```
//!
//! XOR is bitwise, so for any shift `k` with `2^k > T`, `raw(i) >> k` can only be
//! one of two values: `C >> k` for real rows and `(C >> k) ^ MASK` for sentinel
//! rows, where `MASK = (1 << (32 - k)) - 1`. **No constant is needed to test that**:
//! it is a property of the raw bytes alone. Requiring ALL rows of a run to have one
//! of two *complementary* high-bit patterns pins `(base, stride, column)` almost
//! uniquely.
//!
//! Which of the two classes is the sentinel is also constant-free: the sentinel is
//! stored as a single fixed 32-bit value (measured on 7.1.0: 0x8D9D7FF8 for all
//! 13,627 sentinel rows), while real rows hold many distinct values. Once the
//! sentinel class is identified, `C = !sentinel_raw`, and the chain
//! `fs(i+1) - fs(i) == fc(i)` (with `fc` a u16 column) has to tile
//! `[0, T)` exactly -- the decisive test that picks one candidate out of thousands.
//!
//! ## Measured on 7.1.0 (base 0x48F3FD8)
//!
//! The scan over stride 4..0x200 x every column offset leaves **2** survivors; the
//! winner reproduces `layout71::gen71()` exactly:
//!
//! | recovered | profile constant |
//! |---|---|
//! | stride 0x46 | `td_stride` |
//! | fs column 0x00, C 0x7262_8007 | `td_field_start` |
//! | sentinel raw 0x8D9D_7FF8 | `td_fs_sentinel_raw` |
//! | fc column 0x30, C 0x9A6B | `td_field_count` |
//! | rows 88904 | `td_walk()` |
//! | max fs 440170 | field rows 440172 |

use serde::{Deserialize, Serialize};

/// A row table whose first `u32` column is a dense row index with a sentinel, plus
/// the `u16` column that gives the per-row run length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexTable {
    /// Body offset of row 0.
    pub base: usize,
    pub stride: u32,
    /// Offset of the index column inside a row (the `fieldStart` column).
    pub idx_off: u32,
    /// The recovered constant: `fs = raw ^ c` (XOR) or `fs = raw - c` (ADD).
    pub idx_c: u32,
    /// Which of the two families the column uses.
    pub transform: IndexTransform,
    /// Raw value that decodes to "no rows"; `None` when the table has no empty rows.
    pub sentinel_raw: Option<u32>,
    /// Offset of the u16 count column, relative to the same `base` as [`Self::idx_off`].
    /// It may exceed `stride`: the count for row `i` can be stored in the following
    /// row of the scan grid when `base` does not sit on the table's row boundary.
    pub cnt_off: u32,
    /// The count column constant, under [`Self::cnt_transform`].
    pub cnt_c: u16,
    /// Transform of the count column.
    pub cnt_transform: IndexTransform,
    /// Number of rows in the run.
    pub rows: usize,
    /// Rows that are not the sentinel.
    pub real_rows: usize,
    /// Largest decoded index (the table this one indexes has at least max_index+1 rows).
    pub max_index: u32,
    /// Bit shift the predicate was found at (`2^hi_shift > max_index`).
    pub hi_shift: u32,
    /// Transitions verified against the count column.
    pub transitions: usize,
}

impl IndexTable {
    #[inline]
    pub fn index(&self, body: &[u8], row: usize) -> Option<u32> {
        let at = self.base + self.stride as usize * row + self.idx_off as usize;
        let raw = u32::from_le_bytes(body.get(at..at + 4)?.try_into().ok()?);
        if Some(raw) == self.sentinel_raw {
            return Some(u32::MAX);
        }
        Some(match self.transform {
            IndexTransform::Xor => raw ^ self.idx_c,
            IndexTransform::Add => raw.wrapping_sub(self.idx_c),
        })
    }
    #[inline]
    pub fn count(&self, body: &[u8], row: usize) -> Option<u32> {
        let at = self.base + self.stride as usize * row + self.cnt_off as usize;
        let raw = u16::from_le_bytes(body.get(at..at + 2)?.try_into().ok()?);
        Some(match self.cnt_transform {
            IndexTransform::Xor => (raw ^ self.cnt_c) as u32,
            IndexTransform::Add => raw.wrapping_sub(self.cnt_c) as u32,
        })
    }
}

/// Strides worth scanning. All observed metadata tables are <= 0x46 bytes, but
/// future layouts may grow, so the range is deliberately generous.
pub const MAX_STRIDE: u32 = 0x200;
/// Bit shifts tried for the high-bit predicate. `k` must satisfy `2^k > max_index`,
/// so larger tables need larger `k`; the scan simply tries a range.
pub const SHIFTS: [u32; 9] = [16, 17, 18, 19, 20, 21, 22, 23, 24];
/// A column that takes fewer than this many distinct decoded values is a constant,
/// not an index into another table.
pub const MIN_DISTINCT: usize = 8;
/// A run shorter than this is not a table.
pub const MIN_ROWS: usize = 512;
/// Transitions checked before the count column is accepted.
const TILE_LIMIT: usize = 1 << 16;

#[inline]
fn u32at(body: &[u8], at: usize) -> Option<u32> {
    body.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

#[inline]
fn u16at(body: &[u8], at: usize) -> Option<u16> {
    body.get(at..at + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}

/// Which group operation turns the raw column into a dense index.
///
/// Both generations of the same table shape are observed: 7.1.0 stores
/// `raw = fs ^ C` (the high bits of every real row agree), while an additive build
/// stores `raw = fs + C` (the real rows form a window of width `T`). Neither needs
/// a constant to *test*, so the finder tries both instead of assuming one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexTransform {
    Xor,
    Add,
}

/// The model fitted to the first [`FIT_ROWS`] rows of a candidate column.
#[derive(Clone, Copy, Debug)]
struct Model {
    transform: IndexTransform,
    /// `Xor`: the high bits shared by every real row. `Add`: the smallest real raw
    /// (which is `C`, because the first real row has index 0).
    anchor: u32,
    /// The single raw value stored by "empty" rows, if the table has any.
    sentinel: Option<u32>,
}

const FIT_ROWS: usize = 32;
const FIT_KEEP_PCT: usize = 70;

#[inline]
fn is_real(m: &Model, shift: u32, raw: u32) -> bool {
    match m.transform {
        IndexTransform::Xor => (raw >> shift) == m.anchor,
        IndexTransform::Add => {
            let hi = m.anchor as u64 + (1u64 << shift);
            (raw as u64) >= m.anchor as u64 && (raw as u64) < hi
        }
    }
}

/// Fit the two-families model to the first [`FIT_ROWS`] rows, or `None`.
fn fit_all(body: &[u8], base: usize, stride: u32, off: u32, shift: u32) -> Vec<Model> {
    let mut raws: Vec<u32> = Vec::with_capacity(FIT_ROWS);
    for i in 0..FIT_ROWS {
        match u32at(body, base + stride as usize * i + off as usize) {
            Some(v) => raws.push(v),
            None => return Vec::new(),
        }
    }
    let need = FIT_ROWS * FIT_KEEP_PCT / 100;
    let mut out: Vec<Model> = Vec::new();
    // --- XOR family: every real row shares the same high bits. ---
    //
    // The sentinel is identified STRUCTURALLY, not by majority: it is the high-bit
    // class whose raw values are all identical. A majority rule fails on columns whose
    // leading rows are sentinel-heavy -- measured on 7.1.0, the methodStart column has
    // 11 sentinel rows in the first 32 (34%), so the real class holds only 21/32 and a
    // 70% threshold rejects it.
    let mask = (1u32 << (32 - shift)) - 1;
    let mut classes: Vec<(u32, Vec<u32>)> = Vec::new();
    for &r in &raws {
        let h = r >> shift;
        match classes.iter_mut().find(|(k, _)| *k == h) {
            Some((_, v)) => v.push(r),
            None => {
                if classes.len() >= 2 {
                    classes.clear();
                    break;
                }
                classes.push((h, vec![r]));
            }
        }
    }
    if classes.len() == 2 && (classes[0].0 ^ classes[1].0) != mask {
        classes.clear();
    }
    if classes.len() == 1 {
        let (h, v) = &classes[0];
        let mut d = v.clone();
        d.sort_unstable();
        d.dedup();
        // A single class with a single repeated value is not a table column.
        if d.len() > 1 {
            out.push(Model { transform: IndexTransform::Xor, anchor: *h, sentinel: None });
        }
    } else if classes.len() == 2 {
        let distinct = |v: &Vec<u32>| {
            let mut d = v.clone();
            d.sort_unstable();
            d.dedup();
            d.len()
        };
        let (d0, d1) = (distinct(&classes[0].1), distinct(&classes[1].1));
        let (real, sent) = match (d0 == 1, d1 == 1) {
            (true, false) => (1usize, 0usize),
            (false, true) => (0usize, 1usize),
            _ => (usize::MAX, usize::MAX), // ambiguous
        };
        if real != usize::MAX {
            let s = classes[sent].1[0];
            out.push(Model { transform: IndexTransform::Xor, anchor: classes[real].0, sentinel: Some(s) });
        }
    }
    // --- ADD family: every real row lies in a window of width 2^shift. ---
    //
    // Unlike the XOR branch this one looks at a LONGER prefix: the additive sentinel is
    // `C - 1`, strictly below the real window, and it need not appear in the first
    // FIT_ROWS rows at all. Measured on 5.2.0 the first 32 rows are all real, so a
    // 32-row fit cannot pin the window and the whole family was unreachable.
    const ADD_FIT_ROWS: usize = 512;
    let width = 1u64 << shift;
    let mut araws: Vec<u32> = raws.clone();
    let mut i = raws.len();
    while i < ADD_FIT_ROWS {
        match u32at(body, base + stride as usize * i + off as usize) {
            Some(v) => araws.push(v),
            None => break,
        }
        i += 1;
    }
    // The additive sentinel is `C - 1`: strictly the SMALLEST raw in the column, and
    // repeated in every "empty" row. So the constant is the smallest raw that is not
    // the sentinel -- searching for a window edge instead picks the sentinel itself as
    // soon as the window is wide enough to contain it (measured on 5.2.0).
    let minv = *araws.iter().min().unwrap();
    let minc = araws.iter().filter(|&&x| x == minv).count();
    let others: Vec<u32> = araws.iter().copied().filter(|&x| x != minv).collect();
    if minc >= 2 && others.len() >= need {
        let anchor = *others.iter().min().unwrap();
        let hi = *others.iter().max().unwrap();
        let span = hi as u64 - anchor as u64 + 1;
        if span <= width {
            out.push(Model { transform: IndexTransform::Add, anchor, sentinel: Some(minv) });
        }
    }
    if false {
        // The edge above is the one that MAXIMISES coverage, which is not the model's
        // constant: with a wide window it sits one below the real minimum, so `raw -
        // edge` starts at 1 and the sentinel (which is `C - 1`) falls INSIDE the window
        // and looks absent. The constant is the smallest value the window contains.
        let anchor = 0u32;
        let mut sentinel: Option<u32> = None;
        let mut ok = false;
        if ok {
            sentinel = None;
        }
        // An additive index column is only accepted when the table also encodes its
        // "empty" case: a column with no repeated constant at all is far more likely
        // to be a slowly-varying region that happens to be monotone. Measured on
        // 7.0.0, dropping this check admits ~1037-row false tables in ordinary data.
        // The sentinel may live outside the first FIT_ROWS rows (measured on 5.2.0),
        // in which case it is learned from the run in `analyse_model`. Pushing the
        // model with `sentinel: None` is what lets that happen at all.
        if ok {
            out.push(Model { transform: IndexTransform::Add, anchor, sentinel });
        }
    }
    out
}

/// The first model `fit_all` produced. Only the diagnostics use this; `analyse` tries
/// every model, because a column can fit more than one family at once.
fn fit(body: &[u8], base: usize, stride: u32, off: u32, shift: u32) -> Option<Model> {
    fit_all(body, base, stride, off, shift).into_iter().next()
}

/// How far the fitted model holds from `base + idx_off`.
fn run_len(body: &[u8], base: usize, stride: u32, off: u32, shift: u32, cap: usize, m: &Model) -> usize {
    let mut n = 0usize;
    while n < cap {
        let Some(v) = u32at(body, base + stride as usize * n + off as usize) else { break };
        if is_real(m, shift, v) || Some(v) == m.sentinel {
            n += 1;
        } else {
            break;
        }
    }
    n
}

/// Cheapest test that rejects almost everything.
#[inline]
fn prefilter(body: &[u8], base: usize, stride: u32, off: u32, shift: u32) -> bool {
    fit(body, base, stride, off, shift).is_some()
}

/// How far a candidate got, for diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stage {
    TooShort,
    Prefilter,
    Run,
    Sentinel,
    Monotone,
    Tile,
    Ok,
}

/// Names parallel to the [`Stage`] discriminants, for the histogram in `MHY_DEBUG=1`.
const STAGE_NAMES: [&str; 7] = ["TooShort", "Prefilter", "Run", "Sentinel", "Monotone", "Tile", "Ok"];

/// Analyse one `(base, stride, column, shift)` candidate. Returns the stage it failed
/// at, so a build whose layout differs can be diagnosed instead of just rejected.
pub fn analyse(body: &[u8], base: usize, stride: u32, off: u32, shift: u32) -> Result<IndexTable, Stage> {
    let cap = ((body.len().saturating_sub(base)) / stride as usize).min(400_000);
    if cap < MIN_ROWS {
        return Err(Stage::TooShort);
    }
    let models = fit_all(body, base, stride, off, shift);
    if models.is_empty() {
        return Err(Stage::Prefilter);
    }
    // A column can satisfy more than one family at once -- measured on 5.2.0, the
    // fieldStart column's first 32 rows all share one high byte, so the XOR branch
    // fires and its early return used to hide the ADD model (whose sentinel lives
    // outside those 32 rows). Every model is therefore tried and the best kept.
    let mut best: Option<IndexTable> = None;
    let mut worst = Stage::Prefilter;
    for model in &models {
        match analyse_model(body, base, stride, off, shift, cap, model) {
            Ok(t) => {
                let better = match &best {
                    None => true,
                    Some(b) => t.rows > b.rows || (t.rows == b.rows && t.real_rows > b.real_rows),
                };
                if better {
                    best = Some(t);
                }
            }
            Err(st) if st as u8 > worst as u8 => worst = st,
            Err(_) => {}
        }
    }
    best.ok_or(worst)
}

/// Analyse one candidate column under one already-fitted model.
fn analyse_model(
    body: &[u8],
    base: usize,
    stride: u32,
    off: u32,
    shift: u32,
    cap: usize,
    model: &Model,
) -> Result<IndexTable, Stage> {
    let mut model = *model;
    if model.transform == IndexTransform::Add && model.sentinel.is_none() {
        // For the additive family the sentinel is `C - 1`, i.e. strictly BELOW the real
        // window, so it is always the smallest raw of the column -- but it need not
        // appear in the first FIT_ROWS rows. Measured on 5.2.0: all 32 leading rows are
        // real, the sentinel only shows up later, and the column was rejected before the
        // additive model could even be considered. Learn it from the first row outside
        // the window and redo the run.
        let n0 = run_len(body, base, stride, off, shift, cap, &model);
        if let Some(v) = u32at(body, base + stride as usize * n0 + off as usize) {
            model.sentinel = Some(v);
        }
    }
    let n = run_len(body, base, stride, off, shift, cap, &model);
    if n < MIN_ROWS {
        return Err(Stage::Run);
    }
    // The constant follows from the model: an XOR table stores the complement of the
    // index constant in its empty rows; an additive table stores the constant offset
    // itself as the smallest real raw. Without a sentinel, row 0 is the row whose
    // index is 0, so it pins the constant for either family.
    let idx_c = match (model.transform, model.sentinel) {
        (IndexTransform::Xor, Some(s)) => !s,
        (IndexTransform::Xor, None) => u32at(body, base + off as usize).ok_or(Stage::Run)?,
        (IndexTransform::Add, _) => model.anchor,
    };
    // Decode every row; require the real values to be non-decreasing and in range.
    let mut fs: Vec<i64> = Vec::with_capacity(n);
    let mut max_index = 0u32;
    let mut real_rows = 0usize;
    let mut prev: i64 = -1;
    for i in 0..n {
        let raw = u32at(body, base + stride as usize * i + off as usize).ok_or(Stage::Run)?;
        if !is_real(&model, shift, raw) {
            fs.push(-1);
            continue;
        }
        let v = match model.transform {
            IndexTransform::Xor => raw ^ idx_c,
            IndexTransform::Add => raw.wrapping_sub(idx_c),
        };
        if (v as i64) < prev {
            return Err(Stage::Monotone);
        }
        prev = v as i64;
        if v > max_index {
            max_index = v;
        }
        real_rows += 1;
        fs.push(v as i64);
    }
    if max_index >= (1u32 << shift) {
        return Err(Stage::Monotone);
    }
    // An ADD window that the data fills to its own top is not a fitted window: the
    // smallest power of two that covers the values is then just the data's range, and
    // the model explains nothing. Real additive tables keep headroom -- 4.8.0 uses
    // 47112 of 65536 and 84836 of 131072 -- while the false positives this rule was
    // measured on sit at 65535 of 65536 and 4193792 of 4194304.
    if model.transform == IndexTransform::Add
        && max_index >= (1u32 << shift) - (1u32 << (shift - 4))
    {
        return Err(Stage::Monotone);
    }
    // Degeneracy guard: a column that only ever takes a handful of values is a
    // constant, not a row index. Measured on 5.2.0: without this, additive runs of
    // ~2,000 rows pass the whole chain with `max_index == 0`.
    {
        let mut d: Vec<i64> = fs.iter().copied().filter(|&v| v >= 0).collect();
        d.sort_unstable();
        d.dedup();
        if d.len() < MIN_DISTINCT {
            return Err(Stage::Sentinel);
        }
    }
    // The count column: the per-row delta must equal a u16 column under one of the two
    // transforms, for thousands of consecutive transitions.
    //
    // The search starts AT the index column rather than at the start of the scan base,
    // because the scan base is arbitrary: it comes from an anchor that happens to land
    // somewhere in the table, not necessarily on a row boundary. A base sitting `k`
    // bytes before the row start puts the index column at `off + k` and the count
    // column at `off_cnt + k` -- still inside the same row, but past the point where
    // the old `0 .. stride` window stopped. Measured on 6.4.0, the anchor 0xE7579C is
    // 0x3E bytes before the row start, so the count column lands at 0x78 while
    // `stride` is only 0x46; the table was rejected at `Tile` because of it.
    let mut best: Option<(u32, u16, IndexTransform, usize)> = None;
    'outer: for off2 in off..off + stride {
        for op in [IndexTransform::Xor, IndexTransform::Add] {
            let mut c2: Option<u16> = None;
            let mut ok = true;
            let mut cnt = 0usize;
            let mut seen = 0usize;
            for i in 0..n - 1 {
                if fs[i] < 0 || fs[i + 1] < 0 {
                    continue;
                }
                let d = (fs[i + 1] - fs[i]) as u32;
                if d > 0xFFFF {
                    ok = false;
                    break;
                }
                let Some(v) = u16at(body, base + stride as usize * i + off2 as usize) else {
                    ok = false;
                    break;
                };
                let cur = match op {
                    IndexTransform::Xor => v ^ d as u16,
                    IndexTransform::Add => v.wrapping_sub(d as u16),
                };
                match c2 {
                    None => c2 = Some(cur),
                    Some(c) if c == cur => {}
                    _ => {
                        ok = false;
                        break;
                    }
                }
                cnt += 1;
                seen += 1;
                if seen >= TILE_LIMIT {
                    break;
                }
            }
            if ok && cnt > 1000 {
                best = Some((off2, c2.unwrap(), op, cnt));
                break 'outer;
            }
        }
    }
    let (cnt_off, cnt_c, cnt_transform, transitions) = best.ok_or(Stage::Tile)?;
    Ok(IndexTable {
        base,
        stride,
        idx_off: off,
        idx_c,
        transform: model.transform,
        sentinel_raw: model.sentinel,
        cnt_off,
        cnt_c,
        cnt_transform,
        rows: n,
        real_rows,
        max_index,
        hi_shift: shift,
        transitions,
    })
}

/// Every index table reachable from `base`.
///
/// The shift is a *nuisance* parameter, not a constant: a run computed at a shift
/// below `log2(max_index)` is truncated at the first row whose index crosses
/// `2^shift`, so the same `(stride, column)` shows up several times with different
/// run lengths. The longest run is the real one, so each column keeps its best
/// result and the output is deduplicated by `(base, stride, column)`.
pub fn find_from_base(body: &[u8], base: usize) -> Vec<IndexTable> {
    let mut out: Vec<IndexTable> = Vec::new();
    // `MHY_DEBUG=1` prints one line per base (the longest run reached, which stage
    // finally rejected it, and a histogram of how far the other columns got);
    // `MHY_DEBUG=2` additionally prints one line per rejected column. The flood from
    // level 2 is ~140 MB on a 300-base scan, so it is opt-in.
    let debug_level: u8 = std::env::var("MHY_DEBUG")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or(0);
    let debug = debug_level > 0;
    let verbose = debug_level > 1;
    // Diagnostics: `MHY_ONLY_STRIDE` restricts the scan to one stride, which is what
    // turns a two-minute sweep into a per-base report of the longest run reached.
    let only: Option<u32> = std::env::var("MHY_ONLY_STRIDE")
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok());
    let strides: Vec<u32> = match only {
        Some(s) => vec![s],
        None => (4..=MAX_STRIDE).collect(),
    };
    let mut best_run = (0usize, 0u32, 0u32, 0u32);
    // How far the columns got, bucketed by the best stage any shift reached. A base
    // whose histogram is all `Prefilter` is not a table location at all; one that
    // reaches `Tile` is a table the model already fits and only the count column
    // disagrees with.
    let mut hist = [0u64; 7];
    for stride in strides {
        if base + 8 * stride as usize >= body.len() {
            break;
        }
        for off in 0..stride.saturating_sub(3) {
            let mut best: Option<IndexTable> = None;
            let mut worst = Stage::TooShort;
            for shift in SHIFTS {
                match analyse(body, base, stride, off, shift) {
                    Ok(t) => {
                        let better = match &best {
                            None => true,
                            Some(b) => {
                                t.rows > b.rows || (t.rows == b.rows && t.real_rows > b.real_rows)
                            }
                        };
                        if better {
                            best = Some(t);
                        }
                    }
                    Err(st) if st as u8 > worst as u8 => worst = st,
                    Err(_) => {}
                }
            }
            if debug {
                // Track the longest run any shift reached: this is what tells a
                // structurally different build apart from a broken search.
                for shift in SHIFTS {
                    if let Some(m) = fit(body, base, stride, off, shift) {
                        let cap = ((body.len().saturating_sub(base)) / stride as usize).min(400_000);
                        let n = run_len(body, base, stride, off, shift, cap, &m);
                        if n > best_run.0 {
                            best_run = (n, stride, off, shift);
                        }
                    }
                }
            }
            hist[worst as usize] += 1;
            if best.is_none() && verbose && worst as u8 > 0 {
                eprintln!("[dbg] base=0x{base:X} stride=0x{stride:X} off=0x{off:X} died at {worst:?}");
            }
            if let Some(t) = best {
                out.push(t);
            }
        }
    }
    out.sort_by(|a, b| {
        b.rows
            .cmp(&a.rows)
            .then(b.real_rows.cmp(&a.real_rows))
            .then(a.idx_off.cmp(&b.idx_off))
    });
    let mut seen = std::collections::HashSet::new();
    out.retain(|t| seen.insert((t.base, t.stride, t.idx_off)));
    if debug {
        // The single line that answers "is this base a table at all?": the longest
        // column run found, and the stage it died at. A base whose histogram is all
        // Prefilter is not a table location; one that reaches Tile already fits the
        // model and only the count column disagrees.
        let mut h: Vec<String> = Vec::new();
        for (i, &c) in hist.iter().enumerate() {
            if c > 0 {
                h.push(format!("{}:{}", STAGE_NAMES[i], c));
            }
        }
        eprintln!(
            "[dbg] base=0x{base:X} run={} stride=0x{:X} off=0x{:X} shift={} hist=[{}]",
            best_run.0, best_run.1, best_run.2, best_run.3, h.join(" ")
        );
        // For a long run, say which later predicate rejected it -- that is the only
        // thing that tells a structurally different build from a broken search.
        if best_run.0 > MIN_ROWS {
            match analyse(body, base, best_run.1, best_run.2, best_run.3) {
                Ok(_) => eprintln!("[dbg]   ...and ACCEPTED"),
                Err(e) => eprintln!("[dbg]   ...but rejected at {e:?}"),
            }
        }
    }
    out
}

/// Scan every candidate body offset (normally the anchors recovered from the code).
///
/// Bases are independent, so the scan is spread over the available cores; a build
/// with ~40 recovered anchors completes in about the time of one anchor.
pub fn find(body: &[u8], bases: &[usize]) -> Vec<IndexTable> {
    let cands: Vec<usize> = bases
        .iter()
        .copied()
        .filter(|&b| b + MIN_ROWS * 8 < body.len())
        .collect();
    let jobs = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 16);
    let chunk = cands.len().div_ceil(jobs).max(1);
    let mut out: Vec<IndexTable> = Vec::new();
    std::thread::scope(|s| {
        let handles: Vec<_> = cands
            .chunks(chunk)
            .map(|part| s.spawn(move || {
                let mut local: Vec<IndexTable> = Vec::new();
                for &b in part {
                    local.extend(find_from_base(body, b));
                }
                local
            }))
            .collect();
        for h in handles {
            out.extend(h.join().unwrap_or_default());
        }
    });
    out.sort_by(|a, b| {
        b.rows
            .cmp(&a.rows)
            .then(b.real_rows.cmp(&a.real_rows))
            .then(a.base.cmp(&b.base))
            .then(a.idx_off.cmp(&b.idx_off))
    });
    let mut seen = std::collections::HashSet::new();
    out.retain(|t| seen.insert((t.base, t.stride, t.idx_off)));
    out
}

// ---------------------------------------------------------------------------
// String-index columns (name / namespace)
//
// A name column stores `idx = raw + C` (7.1.0 uses this for `td_name`) where
// `idx = (len << 24) | off`. Every type has a name, so `off_i` is the heap
// offset of a real string for EVERY row -- which gives a predicate that needs no
// constant at all: the first byte of the string at `off` must be printable.
//
// For a candidate low-24-bit constant `l`, row `i` demands
// `printable((u_i + l) & 0xFFFFFF)`. A wrong `l` satisfies that with probability
// 0.37 per row, so intersecting eight rows over the 2^24 space leaves the true `l`
// (and, measured, nothing else). The intersection is done as eight rotations of one
// 16 Mibit bitset, i.e. ~4M word operations per column.
//
// The top byte (the length) is then pinned by the only remaining constraint:
// `len_i = ((u_i + C) >> 24) & 0xFF` must satisfy `1 <= len_i <= R(off_i)`, where
// `R` is the printable run length at `off_i` -- computed from the real cipher, and
// independently an upper bound on the string length.
// ---------------------------------------------------------------------------

/// Bitset over the low-24-bit string-index space.
pub struct PrintableFirstByte {
    bits: Vec<u64>,
}

const IDX_BITS: usize = 1 << 24;
const IDX_WORDS: usize = IDX_BITS / 64;
const IDX_MASK: u32 = (1 << 24) - 1;

impl PrintableFirstByte {
    /// `bit o` is set when the first byte of the string at heap offset `o` decrypts
    /// to printable ASCII. Computed from the cipher, so it needs no plaintext.
    pub fn build(body: &[u8], strsec: usize, sched: &crate::derive::cipher::CipherSchedule) -> Self {
        let mut bits = vec![0u64; IDX_WORDS];
        for o in 0..IDX_BITS {
            let Some(src) = strsec.checked_add(o) else { continue };
            let Some(b) = body.get(src) else { continue };
            let k = sched.key(o as u64);
            let c = b ^ (k as u8);
            if (0x20..=0x7E).contains(&c) {
                bits[o >> 6] |= 1u64 << (o & 63);
            }
        }
        Self { bits }
    }

    /// Same as [`Self::build`], but the validity set is *printable-run starts* rather
    /// than first bytes.
    ///
    /// A string start is a printable byte that is not preceded by a printable byte.
    /// Measured: the real string heap has 654552 starts in 2^24 positions (3.9%), while
    /// plain "first byte printable" holds for 37.7% -- a 10x looser predicate that let
    /// false name columns outrank real ones (7.0.0: the reported `off 0x10` decoded to
    /// nothing, while the true `off 0x0C` decodes `<Module>` and `RuntimeClassHandle`).
    pub fn build_run_starts(
        body: &[u8],
        strsec: usize,
        sched: &crate::derive::cipher::CipherSchedule,
    ) -> Self {
        let first = Self::build(body, strsec, sched);
        let mut bits = first.bits.clone();
        for o in 1..IDX_BITS {
            if first.bits[(o - 1) >> 6] & (1u64 << ((o - 1) & 63)) != 0 {
                bits[o >> 6] &= !(1u64 << (o & 63));
            }
        }
        Self { bits }
    }

    #[inline]
    pub fn get(&self, off: u32) -> bool {
        let o = (off & IDX_MASK) as usize;
        self.bits[o >> 6] & (1u64 << (o & 63)) != 0
    }

    /// `dst[l] = self[(l + u) & 0xFFFFFF]`
    ///
    /// With `u = 64k + r`, bit `l = 64i + j` maps to bit `64(i+k) + (j+r)`,
    /// i.e. a *right* shift of word `i+k` by `r` with the next word carried in.
    fn rotate_add(&self, u: u32, dst: &mut [u64]) {
        let k = (u >> 6) as usize;
        let r = u & 63;
        for i in 0..IDX_WORDS {
            let a = self.bits[(i + k) & (IDX_WORDS - 1)];
            dst[i] = if r == 0 {
                a
            } else {
                (a >> r) | (self.bits[(i + k + 1) & (IDX_WORDS - 1)] << (64 - r))
            };
        }
    }

    /// `dst[l] = self[l ^ u]` over the 24-bit index space.
    ///
    /// XOR-permuting a bitmap is a sequence of block swaps: index bit `b` selects which
    /// of two blocks maps where. Bits 6..24 are whole-word blocks, bits 0..6 are groups
    /// inside each word.
    fn permute_xor(&self, u: u32, dst: &mut [u64]) {
        dst.copy_from_slice(&self.bits);
        for b in 6..24u32 {
            if u & (1 << b) == 0 {
                continue;
            }
            let w = 1usize << (b - 6);
            let mut i = 0usize;
            while i + 2 * w <= IDX_WORDS {
                for k in 0..w {
                    dst.swap(i + k, i + w + k);
                }
                i += 2 * w;
            }
        }
        for b in 0..6u32 {
            if u & (1 << b) == 0 {
                continue;
            }
            let g = 1u64 << b;
            let mut mask = 0u64;
            let mut s = 0u32;
            while s < 64 {
                mask |= ((1u64 << g) - 1) << s;
                s += 2 * (g as u32);
            }
            for w in dst.iter_mut() {
                *w = ((*w & mask) << g) | ((*w >> g) & mask);
            }
        }
    }
}

/// Longest run of printable bytes at heap offset `off`, in decode order.
pub fn printable_run(
    body: &[u8],
    strsec: usize,
    sched: &crate::derive::cipher::CipherSchedule,
    off: usize,
    cap: usize,
) -> usize {
    let Some(mut src) = strsec.checked_add(off) else { return 0 };
    let mut key = sched.key(off as u64);
    let mut n = 0usize;
    while n < cap && src + 8 <= body.len() {
        let enc = u64::from_le_bytes(body[src..src + 8].try_into().unwrap());
        let dec = (enc ^ key).to_le_bytes();
        for &b in dec.iter() {
            if (0x20..=0x7E).contains(&b) {
                n += 1;
            } else {
                return n;
            }
        }
        key = key.wrapping_add(sched.step);
        src += 8;
    }
    n
}

/// Find every column of the row table at `(base, stride)` that behaves like a string
/// index column under an XOR transform (`idx = raw ^ c`).
///
/// Mirror of [`find_additive_string_columns`], and needed because the two families flip
/// together: measured on 7.0.0 the index column is additive while its name column is XOR
/// (`off 0x0C`, low-24 constant `0x6B619D`, decoding `<Module>` and `RuntimeClassHandle`),
/// the exact opposite of 7.1.0 (index XOR, name additive).
pub fn find_xor_string_columns(
    body: &[u8],
    strsec: usize,
    sched: &crate::derive::cipher::CipherSchedule,
    base: usize,
    stride: u32,
    rows: usize,
) -> Vec<StringColumn> {
    if rows < 16 {
        return Vec::new();
    }
    let pf = PrintableFirstByte::build(body, strsec, sched);
    let sample: Vec<usize> = (0..STRING_SAMPLE_ROWS)
        .map(|k| (k * rows / STRING_SAMPLE_ROWS).min(rows - 1))
        .collect();
    let verify: Vec<usize> = (0..STRING_VERIFY_ROWS)
        .map(|k| (k * rows / STRING_VERIFY_ROWS).min(rows - 1))
        .collect();
    let mut out = Vec::new();
    let mut acc = vec![0u64; IDX_WORDS];
    let mut tmp = vec![0u64; IDX_WORDS];
    for off in 0..stride.saturating_sub(3) {
        let mut us: Vec<u32> = Vec::with_capacity(STRING_SAMPLE_ROWS);
        for &r in &sample {
            match u32_at_row(body, base, stride, r, off) {
                Some(v) => us.push(v),
                None => break,
            }
        }
        if us.len() < STRING_SAMPLE_ROWS {
            continue;
        }
        pf.permute_xor(us[0] & IDX_MASK, &mut acc);
        for &u in &us[1..] {
            pf.permute_xor(u & IDX_MASK, &mut tmp);
            for i in 0..IDX_WORDS {
                acc[i] &= tmp[i];
            }
            if acc.iter().all(|&w| w == 0) {
                break;
            }
        }
        let n: u32 = acc.iter().map(|w| w.count_ones()).sum();
        if std::env::var("MHY_DEBUG").is_ok() {
            eprintln!("[dbg] xorstrcol off=0x{off:X} survivors={n}");
        }
        if n == 0 || n > 16 {
            continue;
        }
        let cands: Vec<u32> = (0..IDX_BITS as u32)
            .filter(|l| acc[(*l as usize) >> 6] & (1u64 << (l & 63)) != 0)
            .collect();
        // XOR does not carry, so the length byte is `(raw >> 24) ^ h` while the heap
        // offset is `(raw ^ l) & 0xFFFFFF` -- the two halves are independent.
        for l in cands {
            let mut votes = vec![0u16; 256];
            let mut tested = 0usize;
            for &r in &verify {
                let Some(u) = u32_at_row(body, base, stride, r, off) else { continue };
                tested += 1;
                let o = ((u ^ l) & IDX_MASK) as usize;
                let run = printable_run(body, strsec, sched, o, 255) as u32;
                if run == 0 {
                    continue;
                }
                let m = (u >> 24) & 0xFF;
                for h in 0..256u32 {
                    let len = (m ^ h) & 0xFF;
                    if len >= 1 && len <= run {
                        votes[h as usize] += 1;
                    }
                }
            }
            if tested == 0 {
                continue;
            }
            if let Some((h, &v)) = votes.iter().enumerate().max_by_key(|(_, &v)| v) {
                if v as usize * 100 >= tested * STRING_ACCEPT_PCT {
                    out.push(StringColumn {
                        off,
                        c: ((h as u32) << 24) | l,
                        rows_ok: v as usize,
                        rows_tested: tested,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| b.rows_ok.cmp(&a.rows_ok));
    let mut seen = std::collections::HashSet::new();
    out.retain(|c| seen.insert(c.off));
    out
}

/// A table column that decodes to a string index by adding a per-build constant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringColumn {
    pub off: u32,
    /// `idx = raw.wrapping_add(c)`
    pub c: u32,
    /// Sample rows that decoded to a well-formed string.
    pub rows_ok: usize,
    pub rows_tested: usize,
}

/// Rows intersected to pin the additive constant. The predicate holds for a wrong
/// constant with probability 0.377 per row (measured: the fraction of heap offsets
/// whose first byte decrypts printable), so 24 rows give 0.377^23 * 2^24 ~= 1e-5
/// false survivors. Measured convergence on 7.1.0: 4 at row 16, 1 from row 18 on,
/// and that one is the true `td_name` constant 0xE811F779.
const STRING_SAMPLE_ROWS: usize = 24;
/// Rows used to accept a candidate. The vote skips a row only when the first byte
/// at the decoded offset is not printable, and such a row is counted as a FAILURE,
/// not ignored -- otherwise a wrong column that is invalid on most rows still
/// reports a perfect ratio. 256 rows is enough that a wrong column cannot pass while
/// the ~30 sentinel-named rows out of 88904 almost never appear in the sample.
const STRING_VERIFY_ROWS: usize = 256;
/// Minimum fraction of verify rows that must decode to a well-formed string.
const STRING_ACCEPT_PCT: usize = 97;

fn u32_at_row(body: &[u8], base: usize, stride: u32, row: usize, off: u32) -> Option<u32> {
    u32at(body, base + stride as usize * row + off as usize)
}

/// Find every column of the row table at `(base, stride)` that behaves like a string
/// index column under an additive transform.
pub fn find_additive_string_columns(
    body: &[u8],
    strsec: usize,
    sched: &crate::derive::cipher::CipherSchedule,
    base: usize,
    stride: u32,
    rows: usize,
) -> Vec<StringColumn> {
    if rows < 16 {
        return Vec::new();
    }
    let pf = PrintableFirstByte::build(body, strsec, sched);
    let sample: Vec<usize> = (0..STRING_SAMPLE_ROWS)
        .map(|k| (k * rows / STRING_SAMPLE_ROWS).min(rows - 1))
        .collect();
    let verify: Vec<usize> = (0..STRING_VERIFY_ROWS)
        .map(|k| (k * rows / STRING_VERIFY_ROWS).min(rows - 1))
        .collect();
    let mut out = Vec::new();
    let mut acc = vec![0u64; IDX_WORDS];
    let mut tmp = vec![0u64; IDX_WORDS];
    for off in 0..stride.saturating_sub(3) {
        let mut us: Vec<u32> = Vec::with_capacity(STRING_SAMPLE_ROWS);
        for &r in &sample {
            match u32_at_row(body, base, stride, r, off) {
                Some(v) => us.push(v),
                None => break,
            }
        }
        if us.len() < STRING_SAMPLE_ROWS {
            continue;
        }
        pf.rotate_add(us[0], &mut acc);
        for &u in &us[1..] {
            pf.rotate_add(u, &mut tmp);
            for i in 0..IDX_WORDS {
                acc[i] &= tmp[i];
            }
            if acc.iter().all(|&w| w == 0) {
                break;
            }
        }
        let n: u32 = acc.iter().map(|w| w.count_ones()).sum();
        if std::env::var("MHY_DEBUG").is_ok() {
            eprintln!("[dbg] strcol off=0x{off:X} survivors={n}");
        }
        if n == 0 || n > 16 {
            continue;
        }
        let cands: Vec<u32> = (0..IDX_BITS as u32)
            .filter(|l| acc[(*l as usize) >> 6] & (1u64 << (l & 63)) != 0)
            .collect();
        // Pin the length byte using `1 <= len <= printable_run(off)`. Rows whose
        // first decoded byte is not printable cannot be valid for ANY `h`, so they stay
        // in the denominator.
        for l in cands {
            let mut votes = vec![0u16; 256];
            let mut tested = 0usize;
            for &r in &verify {
                let Some(u) = u32_at_row(body, base, stride, r, off) else { continue };
                tested += 1;
                let w = u.wrapping_add(l);
                let o = (w & IDX_MASK) as usize;
                let run = printable_run(body, strsec, sched, o, 255) as u32;
                if run == 0 {
                    continue;
                }
                let m = (w >> 24) & 0xFF;
                for h in 0..256u32 {
                    let len = (m + h) & 0xFF;
                    if len >= 1 && len <= run {
                        votes[h as usize] += 1;
                    }
                }
            }
            if tested == 0 {
                continue;
            }
            if let Some((h, &v)) = votes.iter().enumerate().max_by_key(|(_, &v)| v) {
                if std::env::var("MHY_DEBUG").is_ok() {
                    eprintln!("[dbg] strcol off=0x{off:X} l=0x{l:06X} h=0x{h:02X} ok={v}/{tested}");
                }
                if v as usize * 100 >= tested * STRING_ACCEPT_PCT {
                    out.push(StringColumn {
                        off,
                        c: ((h as u32) << 24) | l,
                        rows_ok: v as usize,
                        rows_tested: tested,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| b.rows_ok.cmp(&a.rows_ok));
    let mut seen = std::collections::HashSet::new();
    out.retain(|c| seen.insert(c.off));
    out
}

    /// 5.4.0 ground truth: a DIFFERENT build with different columns and a different
    /// count transform. The index column is at 0x1F/0x08 rather than 7.1.0's 0x00/0x08,
    /// the count column is ADDitive, the name column is at 0x3E with `+0xD13BCB2F`,
    /// and the chain still has to tile exactly and decode real type names.
    #[test]
    #[ignore = "needs MHY_SAMPLE2_EXE / MHY_SAMPLE2_DAT (5.4.0)"]
    fn recovers_540_typedef_table_and_names() {
        let exe = std::fs::read(std::env::var("MHY_SAMPLE2_EXE").expect("MHY_SAMPLE2_EXE")).unwrap();
        let dat = std::fs::read(std::env::var("MHY_SAMPLE2_DAT").expect("MHY_SAMPLE2_DAT")).unwrap();
        let body = &dat[0x210..];
        let b = crate::derive::cipher::derive_build(&exe, &dat).expect("derive").expect("header");
        let c = b.cipher.expect("cipher");
        let t = find_from_base(body, 0x0213_921C)
            .into_iter()
            .next()
            .expect("typedef table");
        assert_eq!(t.stride, 0x46);
        assert_eq!(t.rows, 58938);
        assert_eq!(t.transform, IndexTransform::Xor);
        assert_eq!(t.cnt_transform, IndexTransform::Add);
        // The chain must tile the indexed table exactly, over the whole run.
        let mut expected = 0u32;
        let mut real = 0usize;
        for i in 0..t.rows {
            let fs = t.index(body, i).unwrap();
            if fs == u32::MAX {
                continue;
            }
            assert_eq!(fs, expected, "row {i}");
            expected += t.count(body, i).unwrap();
            real += 1;
        }
        assert_eq!(real, 50401);
        assert_eq!(expected, 285058);
        // And the name column must decode real type names.
        let cols = find_additive_string_columns(
            body, c.strsec as usize, &c.schedule, t.base, t.stride, t.rows,
        );
        let name = cols.iter().find(|c| c.off == 0x3E).expect("name column");
        assert_eq!(name.c, 0xD13B_CB2F);
        let dec = |row: usize| {
            let raw = u32at(body, t.base + t.stride as usize * row + 0x3E).unwrap();
            crate::decode_str::decode_str_sched(
                &crate::mem::Buffer::new(body),
                c.strsec as usize,
                raw.wrapping_add(name.c),
                &c.schedule,
            )
        };
        assert_eq!(dec(0), "Locale");
        assert_eq!(dec(1), "SR");
        assert_eq!(dec(2), "Runtime");
    }

/// 6.4.0 ground truth: the anchor recovery only reaches `0x00E7579C`, which sits
/// `0x3E` bytes before the table's row start. That puts the count column at `0x78`
/// -- past `stride` (`0x46`) -- so the whole table used to be rejected at `Tile`
/// even though its index column had been found correctly.
#[test]
#[ignore = "needs MHY_SAMPLE3_EXE / MHY_SAMPLE3_DAT (6.4.0)"]
fn recovers_640_typedef_table_and_names() {
    let exe = std::fs::read(std::env::var("MHY_SAMPLE3_EXE").expect("MHY_SAMPLE3_EXE")).unwrap();
    let dat = std::fs::read(std::env::var("MHY_SAMPLE3_DAT").expect("MHY_SAMPLE3_DAT")).unwrap();
    let body = &dat[0x210..];
    let b = crate::derive::cipher::derive_build(&exe, &dat).expect("derive").expect("header");
    let c = b.cipher.expect("cipher");
    // Select by identity, not by position: since `fit_all` returns every applicable
    // model, the same physical column is also describable as an ADD table (one row more,
    // `max_index` 631103), and that description currently sorts first. Which of the two
    // is the real layout is still open -- see the round-5 note in IMPLEMENTATION_LOG.
    let got = find_from_base(body, 0x00E7_579C);
    let t = got
        .iter()
        .find(|t| t.sentinel_raw == Some(0x9016_4A97))
        .expect("typedef table")
        .clone();
    assert_eq!(t.stride, 0x46);
    assert_eq!(t.rows, 77261);
    assert_eq!(t.transform, IndexTransform::Xor);
    assert_eq!(t.max_index, 384409);
    // The count column really does land past `stride`; that is the point of the fix.
    assert!(t.cnt_off >= t.stride, "cnt_off = 0x{:X}", t.cnt_off);
    let mut expected = 0u32;
    let mut real = 0usize;
    for i in 0..t.rows {
        let fs = t.index(body, i).unwrap();
        if fs == u32::MAX {
            continue;
        }
        assert_eq!(fs, expected, "row {i}");
        expected += t.count(body, i).unwrap();
        real += 1;
    }
    assert_eq!(real, 65289);
    // And the name column decodes real type names, not heap noise.
    let cols = find_additive_string_columns(
        body, c.strsec as usize, &c.schedule, t.base, t.stride, t.rows,
    );
    let name = cols.iter().find(|c| c.off == 0x18).expect("name column");
    let dec = |row: usize| {
        let raw = u32at(body, t.base + t.stride as usize * row + 0x18).unwrap();
        crate::decode_str::decode_str_sched(
            &crate::mem::Buffer::new(body),
            c.strsec as usize,
            raw.wrapping_add(name.c),
            &c.schedule,
        )
    };
    assert_eq!(dec(0), "<Module>");
    assert_eq!(dec(4), "RuntimeClassHandle");
}
#[cfg(test)]
mod tests {
    use super::*;

    /// 7.1.0 ground truth: the recovery must reproduce `layout71::gen71()` exactly.
    #[test]
    #[ignore = "needs MHY_SAMPLE_DAT (7.1.0)"]
    fn recovers_71_typedef_table() {
        let dat = std::fs::read(std::env::var("MHY_SAMPLE_DAT").expect("MHY_SAMPLE_DAT")).unwrap();
        let body = &dat[0x210..];
        let got = find_from_base(body, 0x48F3_FD8);
        // Two columns of the same row table are expected (fieldStart at 0x00 and
        // methodStart at 0x08) plus their count columns; pick the fieldStart one.
        let t = got.iter().find(|t| t.idx_off == 0x00).expect("fieldStart column");
        assert_eq!(t.stride, 0x46);
        assert_eq!(t.idx_off, 0x00);
        assert_eq!(t.idx_c, 0x7262_8007);
        assert_eq!(t.sentinel_raw, Some(0x8D9D_7FF8));
        assert_eq!(t.cnt_off, 0x30);
        assert_eq!(t.cnt_c, 0x9A6B);
        assert_eq!(t.rows, 88904);
        assert_eq!(t.max_index, 440170);
        // The decoded chain must tile the field table.
        let mut expected = 0u32;
        let mut typed = 0usize;
        for i in 0..t.rows {
            let fs = t.index(body, i).unwrap();
            let fc = t.count(body, i).unwrap();
            if fs == u32::MAX {
                assert_eq!(fc, 0);
                continue;
            }
            assert_eq!(fs, expected, "row {i}");
            expected += fc;
            typed += 1;
        }
        assert_eq!(expected, 440172);
        assert!(typed > 50_000);
    }

    /// 7.1.0 ground truth: the additive string column must be `td_name` and row 0
    /// must decode to `<Module>`.
    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE / MHY_SAMPLE_DAT (7.1.0)"]
    fn recovers_71_name_column() {
        let exe = std::fs::read(std::env::var("MHY_SAMPLE_EXE").expect("MHY_SAMPLE_EXE")).unwrap();
        let dat = std::fs::read(std::env::var("MHY_SAMPLE_DAT").expect("MHY_SAMPLE_DAT")).unwrap();
        let body = &dat[0x210..];
        let b = crate::derive::cipher::derive_build(&exe, &dat).expect("derive").expect("header");
        let c = b.cipher.expect("cipher");
        let td = find_from_base(body, 0x48F3_FD8).into_iter().next().expect("typedef table");
        let cols = find_additive_string_columns(
            body, c.strsec as usize, &c.schedule, td.base, td.stride, td.rows,
        );
        assert_eq!(cols.len(), 1, "expected exactly one string column, got {cols:?}");
        assert_eq!(cols[0].off, 0x14);
        assert_eq!(cols[0].c, 0xE811_F779);
        let raw = u32at(body, td.base + 0x14).unwrap();
        let idx = raw.wrapping_add(cols[0].c);
        let s = crate::decode_str::decode_str_sched(
            &crate::mem::Buffer::new(body), c.strsec as usize, idx, &c.schedule,
        );
        assert_eq!(s, "<Module>");
    }
}
