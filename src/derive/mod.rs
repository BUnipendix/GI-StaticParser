//! `derive` — automatic derivation of per-build constants, table locations and
//! column transforms from the executable + encrypted metadata (no hard-coded VAs
//! or keys). See REQUIREMENTS.md R2.

pub mod anchor;
pub mod cipher;
pub mod constpool;
pub mod engine;
pub mod layout71;
pub mod profile;
pub mod shapes;
pub mod tables;
