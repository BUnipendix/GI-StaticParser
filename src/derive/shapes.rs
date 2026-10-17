//! Column de-obfuscation shapes and validators (the column cracker).
//!
//! A "shape" is the per-column plaintext formula observed in mhy builds; 7.0 and 7.1
//! differ in shape and constants, so the cracker enumerates shape × constant with
//! structural validators. All results are deterministic (known-plaintext or
//! self-consistency verified), never guesses.

/// Per-row index mask used by the 7.1 methodDef table (`pmask`, shape "m71").
pub fn pmask_71(i: u32) -> u32 {
    let mut v = ((i as u64) * 0x4E94) ^ 0x62D8_B7B8;
    v = v.wrapping_mul(0x7572_748A).wrapping_add(0x1F4D_9EEA);
    v ^= 0x6E89_31D6;
    ((v as u32).wrapping_mul(0xC6FC_9C8B)) as u32
}

/// Per-row index mask of the 7.0 methodDef table (shape library entry "m70").
pub fn pmask_70(i: u32) -> u32 {
    let v = ((i as u64).wrapping_mul(0x11C1_79E1_B7D6).wrapping_add(0x1EF8_D469_61E5_672) & 0xFFFF_FFFF_FFFF_FFFF) >> 16;
    let v = v.wrapping_mul(0x445E_9994) & 0xFFFF_FFFF_FFFF_FFFF;
    let v = (v >> 9) as u32;
    v.wrapping_mul(0x613D_19A0)
}

/// How a stored u32 column value de-obfuscates to plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Shape {
    /// plain = (raw ^ C) + t
    XorAdd,
    /// plain = (raw + C) ^ t
    AddXor,
    /// plain = raw ^ C ^ t
    XorXor,
    /// plain = raw + C + t
    AddAdd,
    /// plain = raw ^ C (no per-row mask)
    XorOnly,
    /// plain = raw + C (no per-row mask)
    AddOnly,
}

impl Shape {
    pub fn all() -> &'static [Shape] {
        &[Shape::XorAdd, Shape::AddXor, Shape::XorXor, Shape::AddAdd, Shape::XorOnly, Shape::AddOnly]
    }

    #[inline]
    pub fn eval(&self, raw: u32, c: u32, t: u32) -> u32 {
        match self {
            Shape::XorAdd => (raw ^ c).wrapping_add(t),
            Shape::AddXor => raw.wrapping_add(c) ^ t,
            Shape::XorXor => raw ^ c ^ t,
            Shape::AddAdd => raw.wrapping_add(c).wrapping_add(t),
            Shape::XorOnly => raw ^ c,
            Shape::AddOnly => raw.wrapping_add(c),
        }
    }
}

/// Validators score a decoded column; they must be deterministic.
pub mod validators {
    /// Fraction of values < `limit`.
    pub fn frac_below(v: &[u32], limit: u32) -> f64 {
        v.iter().filter(|&&x| x < limit).count() as f64 / v.len() as f64
    }

    /// Share of the modal value (0..1).
    pub fn mode_share(v: &[u32]) -> f64 {
        let mut counts = std::collections::HashMap::new();
        for &x in v {
            *counts.entry(x).or_insert(0u32) += 1;
        }
        counts.values().copied().max().unwrap_or(0) as f64 / v.len() as f64
    }

    /// Fraction of rows where plain is monotonically non-decreasing vs the previous row.
    pub fn monotonic_share(v: &[u32]) -> f64 {
        if v.len() < 2 {
            return 1.0;
        }
        let ok = v.windows(2).filter(|w| w[1] >= w[0]).count();
        ok as f64 / (v.len() - 1) as f64
    }

    /// Fraction equal to a sentinel.
    pub fn sentinel_share(v: &[u32], sentinel: u32) -> f64 {
        v.iter().filter(|&&x| x == sentinel).count() as f64 / v.len() as f64
    }
}
