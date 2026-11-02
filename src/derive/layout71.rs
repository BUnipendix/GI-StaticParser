//! The 7.1-generation profile, now shipped as DATA (R82): every constant
//! lives in `assets/profile-7.1.0.json`, loaded here once. The historical
//! in-code constant table was retired because a data-driven dumper should not
//! embed per-build constants in code — a profile file is the only carrier.
//!
//! Provenance of the constants (unchanged): recovered from the 7.1.0
//! YuanShen.exe metadata accessors (kuna decompilation, cross-checked with the
//! 6.4 community dump oracle) and validated structurally over the full tables.

use super::profile::Profile;

/// The JSON export of the retired in-code table (generated 2026-10-27 from the
/// last gen71() build; the two are checked byte-for-byte by
/// `profile_matches_retired_gen71` in the derive tests).
pub const PROFILE_71_JSON: &str = include_str!("../../assets/profile-7.1.0.json");

/// The 7.1 profile from the data file. Panics only on a corrupted asset.
pub fn gen71() -> Profile {
    serde_json::from_str(PROFILE_71_JSON).expect("assets/profile-7.1.0.json is valid JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The data file must round-trip through the Profile schema with every
    /// optional field intact (anchor regression for the retirement).
    #[test]
    fn profile_json_loads_fully() {
        let p = gen71();
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
