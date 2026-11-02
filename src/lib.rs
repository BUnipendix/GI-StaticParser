//! Static, assembly-scan-based IL2CPP "MHY" metadata dumper.
//!
//! Reads the on-disk files (`GenshinImpact.exe`, `global-metadata.dat`) and emits an
//! Il2CppDumper-style `dump.cs` purely statically — no live process. The decryption recipe (all
//! offsets/constants/algorithms) is documented in `RECIPE.md`.
//!
//! Copyright (C) 2026. Licensed under the GNU General Public License v3.0 (see LICENSE).

pub mod class_model;
pub mod code_addresses;
pub mod decode_str;
pub mod decrypt;
pub mod default_values;
pub mod derive;
pub mod dump;
pub mod expr;
pub mod rowtable;
pub mod profile_splice;
pub mod events_solve;
pub mod loadsites;
pub mod symwalk;
pub mod emu_chain;
pub mod shape_transfer;
pub mod dump_gen;
pub mod vtable;
pub mod dummy_export;
pub mod field_meta;
pub mod il2cpp_api;
pub mod mem;
pub mod metadata;
pub mod method_meta;
pub mod methods_71;
pub mod pe;
pub mod script_json;
pub mod td_dump;
pub mod typenames;
pub mod usage_tables;
