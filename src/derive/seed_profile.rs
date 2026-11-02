//! The built-in seed profile (a full worked example, shipped as data): every constant
//! lives in `assets/seed-profile.json`, loaded here once. The historical
//! in-code constant table was retired because a data-driven dumper should not
//! embed per-build constants in code — a profile file is the only carrier.
//!
//! Provenance of the constants (unchanged): recovered from the 7.1.0
//! YuanShen.exe metadata accessors (kuna decompilation, cross-checked with the
//! 6.4 community dump oracle) and validated structurally over the full tables.

use super::profile::Profile;

/// The JSON export of the retired in-code table (generated 2026-10-27 from the
/// last seed_profile() build; the two are checked byte-for-byte by
/// `profile_matches_retired_seed_profile` in the derive tests).
pub const SEED_PROFILE_JSON: &str = include_str!("../../assets/seed-profile.json");

/// The 7.1 profile from the data file. Panics only on a corrupted asset.
pub fn seed_profile() -> Profile {
    serde_json::from_str(SEED_PROFILE_JSON).expect("assets/seed-profile.json is valid JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data file must round-trip through the Profile schema with every
    /// optional field intact (anchor regression for the retirement).
    #[test]
    fn profile_json_loads_fully() {
        let p = seed_profile();
        assert_eq!(p.td_stride, 70);
        assert_eq!(p.td_name.offset, 0x14);
        assert_eq!(p.td_name.c, 0xE811_F779);
        assert_eq!(p.md_stride, 26);
        assert_eq!(p.md_name.offset, 4);
        assert_eq!(p.md_mask2_mul, 0x3903_6375);
        assert_eq!(p.td_size.as_ref().unwrap().hdr_off, 0x60);
        assert_eq!(p.md_size.as_ref().unwrap().hdr_off, 0x134);
        assert!(p.property_defs.is_some() && p.event_defs.is_some() && p.param_defs.is_some());
        assert_eq!(p.startup_images.as_ref().unwrap().stride, 40);
    }
}
