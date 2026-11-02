//! Column de-obfuscation shapes and validators (the column cracker).
//!
//! A "shape" is the per-column plaintext formula observed in mhy builds; 7.0 and 7.1
//! differ in shape and constants, so the cracker enumerates shape × constant with
//! structural validators. All results are deterministic (known-plaintext or
//! self-consistency verified), never guesses.


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
