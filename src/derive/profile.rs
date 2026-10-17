//! Version profile — every build-specific constant in one serializable struct.
//!
//! A profile is *derived* from the exe + encrypted metadata (see `super::discover`)
//! and cached next to the output, so a same-version re-run never re-derives and a
//! new version can be attacked without touching code. Field docs cite the evidence:
//! `kuna` decompilation of the 7.1 metadata accessors or structural verification.

use serde::{Deserialize, Serialize};

use super::cipher::{CipherOp, CipherSchedule};

/// Per-row index mask chains. Each chain is evaluated on `i` (u32-domain row index)
/// in 64-bit arithmetic, then truncated to u32.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaskChain {
    pub mul1: u32,
    pub xor1: u32,
    pub mul2: u32,
    pub add1: u32,
    pub xor2: u32,
    /// Optional trailing multiply (the "full" chain: v * mul_last).
    #[serde(default)]
    pub mul_last: u32,
}

/// The field-table row mask: a 64-bit additive variant of [`MaskChain`] with a
/// pre-truncation shift (`mask = ((v >> shift) + add2) as u32`).
#[derive(Clone, Serialize, Deserialize)]
pub struct FieldMaskChain {
    pub mul1: u32,
    pub xor1: u32,
    pub mul2: u32,
    pub add1: u64,
    pub shift: u32,
    pub add2: u32,
}

impl FieldMaskChain {
    #[inline]
    pub fn eval(&self, i: u32) -> u32 {
        let mut v = ((i as u64) * self.mul1 as u64) ^ self.xor1 as u64;
        v = v.wrapping_mul(self.mul2 as u64);
        v = v.wrapping_add(self.add1);
        let v = (v >> self.shift) as u32;
        v.wrapping_add(self.add2)
    }
}

impl MaskChain {
    #[inline]
    pub fn eval(&self, i: u32) -> u32 {
        let mut v = ((i as u64) * self.mul1 as u64) ^ self.xor1 as u64;
        v = v.wrapping_mul(self.mul2 as u64);
        v = v.wrapping_add(self.add1 as u64);
        v ^= self.xor2 as u64;
        let v = v as u32;
        if self.mul_last != 0 {
            v.wrapping_mul(self.mul_last)
        } else {
            v
        }
    }
}

/// A table located relative to the metadata body, keyed by an obfuscated header slot.
#[derive(Clone, Serialize, Deserialize)]
pub struct TableBase {
    /// Header field offset (into the embedded MHY header).
    pub hdr_off: u32,
    /// Transform: `plain = i32(hdr[hdr_off]) - sub` or `plain = u32(hdr[hdr_off]) ^ xor`
    /// or `plain = u32(hdr[hdr_off]) + add`.
    #[serde(default)]
    pub sub: Option<u32>,
    #[serde(default)]
    pub xor: Option<u32>,
    #[serde(default)]
    pub add: Option<u32>,
}

impl TableBase {
    #[inline]
    pub fn resolve(&self, hdr: &[u8]) -> usize {
        let raw = u32::from_le_bytes(
            hdr[self.hdr_off as usize..self.hdr_off as usize + 4].try_into().unwrap(),
        );
        match (self.sub, self.xor, self.add) {
            (Some(s), _, _) => (raw.wrapping_sub(s)) as usize,
            (_, Some(x), _) => (raw ^ x) as usize,
            (_, _, Some(a)) => (raw.wrapping_add(a)) as usize,
            _ => raw as usize,
        }
    }
}

impl Profile {
    /// The effective key schedule: the carried one, or the legacy triple rebuilt as
    /// an equivalent op list. One code path, so a 5-constant generation and a
    /// 3-constant one differ only in data.
    pub fn schedule(&self) -> CipherSchedule {
        match &self.cipher {
            Some(c) => c.clone(),
            None => CipherSchedule {
                ops: vec![
                    CipherOp::And(0xFF_FFFF),
                    CipherOp::Mul(self.str_m1),
                    CipherOp::Add(self.str_x1),
                    CipherOp::Xor(self.str_x2),
                ],
                step: self.str_m4,
            },
        }
    }

    /// First-qword key for a string at heap offset `off`.
    #[inline]
    pub fn key(&self, off: u64) -> u64 {
        self.schedule().key(off)
    }

    /// Per-qword key increment inside one string.
    #[inline]
    pub fn key_step(&self) -> u64 {
        self.cipher.as_ref().map(|c| c.step).unwrap_or(self.str_m4)
    }
}

/// A column transform inside a table. `c` is the per-column constant.
#[derive(Clone, Serialize, Deserialize)]
pub struct Column {
    pub offset: u32,
    pub kind: ColKind,
    #[serde(default)]
    pub c: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ColKind {
    /// plain = raw ^ C ^ mask(i)
    XorCMask,
    /// plain = (raw ^ C) + mask(i)
    XorCAddMask,
    /// plain = raw + C + mask(i)
    AddCAddMask,
    /// plain = raw + C - mask2(i)  (the -0x39036375 variant)
    AddCSubMask2,
    /// plain = (raw ^ C) - mask2(i)
    XorCSubMask2,
    /// plain = (int16)((raw ^ C) - mask2(i))
    XorCSubMask2I16,
    /// plain = (raw - mask2(i) + C) & 0xFFFF
    SubMask2AddC16,
    /// plain = (raw - mask2(i) + C) & 0xFF
    SubMask2AddC8,
    /// plain = raw ^ C (static)
    XorC,
    /// plain = raw + C (static)
    AddC,
    /// plain = (raw + C) ^ mask(i)
    AddCXorMask,
}

/// The full per-build profile (generation 7.x layout).
#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    /// String-key schedule, **as data**. When present it supersedes the legacy
    /// `str_m1..str_m4` triple, and it is the only form that can describe the
    /// two-stage 5-constant generations (7.0.0 / 6.4.0 complete only after the
    /// algorithm itself changed), so new profiles should always set it.
    #[serde(default)]
    pub cipher: Option<CipherSchedule>,
    /// LEGACY string cipher: key0 = (off * m1 + x1) ^ x2, per qword key += m4.
    /// Kept so old profile JSON still loads; ignored when `cipher` is set.
    pub str_m1: u64,
    pub str_x1: u64,
    pub str_x2: u64,
    pub str_m4: u64,
    /// `strsec = i32(header[hdr_off]) - strsub` — offset of the string section in body.
    pub str_hdr_off: u32,
    pub str_sub: u32,

    pub type_defs: TableBase,
    /// typeDef-table BYTE SIZE (not an offset): `rows = size / td_stride`. The structural
    /// chain walk stops at the first tiling irregularity and undercounts (7.1.0: 88,872 vs
    /// 88,904 rows); the size slot is authoritative. Trailing all-sentinel padding rows are
    /// trimmed after the division. 7.1.0: header slot 0x60 ^ 0x15335474 = 6,223,280.
    #[serde(default)]
    pub td_size: Option<TableBase>,
    pub method_defs: TableBase,
    /// Method-table BYTE SIZE (not an offset): `rows = size / md_stride`. Needed because the
    /// method-pointer array covers only the methods that have a direct code pointer
    /// (7.1.0: 460,282 of 733,481 rows), so it is not a valid row-count source.
    /// 7.1.0: header slot 0x134 + 0x8EEFDB56 = 19,070,516 -> 733,481 rows.
    #[serde(default)]
    pub md_size: Option<TableBase>,
    pub fields: TableBase,
    pub params: TableBase,
    pub slot_table: TableBase,

    pub td_stride: u32,
    pub td_magic: i32,
    pub td_name: Column,
    /// Raw sentinel stored value that means "no name".
    pub td_name_sentinel: u32,
    pub td_ns: Column,
    pub td_method_start: Column,
    /// typeDef fieldStart column: `idx = raw ^ c`, `td_fs_sentinel_raw` = stored value
    /// meaning "no fields" (decodes to 0xFFFFFFFF).
    pub td_field_start: Column,
    pub td_fs_sentinel_raw: u32,
    /// typeDef fieldCount column (u16): `count = (raw as u16) ^ (c as u16)`.
    pub td_field_count: Column,
    /// typeDef flags column (u32, decoded TypeAttributes). 7.1.0: raw@0x0C + 0xDFA09F90
    /// (== raw - 0x205F6070), read in the .upx0 class builder at 0x159F64354.
    /// None = generation without the column located (dump falls back to parent-chain kind).
    #[serde(default)]
    pub td_flags: Option<Column>,
    /// typeDef bitfield column (u16): bit0 = IsValueType, bit1 = IsEnum (same packing as
    /// canonical Il2CppDumper). 7.1.0: raw@0x32 ^ 0x8BA4.
    #[serde(default)]
    pub td_bitfield: Option<Column>,

    /// The full field table (all images): stride 8, `{name_raw@0, type_raw@4}` per row.
    pub field_names: TableBase,
    pub field_stride: u32,
    /// Per-row mask shared by both field columns.
    pub field_mask: FieldMaskChain,
    /// `name_idx = name_raw ^ mask ^ field_name_xor`.
    pub field_name_xor: u32,
    /// `type_idx = (type_raw + field_type_add) ^ mask ^ field_type_xor`.
    pub field_type_add: u32,
    pub field_type_xor: u32,

    /// typeDef parent column: `parent_tarr = raw ^ tag(0x1C) ^ parent_xor` (typearr index;
    /// 0xFFFFFFFF sentinel = no base, i.e. interfaces / System.Object).
    pub td_parent_off: u32,
    pub td_parent_xor: u32,
    /// Interface-offsets table + per-type start column.
    pub iface_table: TableBase,
    pub iface_stride: u32,
    pub td_iface_start_off: u32,
    pub td_iface_start_xor: u32,

    pub md_stride: u32,
    pub md_ret_type: Column,
    pub md_name: Column,
    pub md_param_start: Column,
    pub md_decl: Column,
    pub md_slot: Column,
    pub md_flags: Column,
    pub md_param_count: Column,
    pub md_pmask: MaskChain,
    /// Second per-row mask: `pmid(i) * mask2_mul` where pmid = pmask without the last mul.
    pub md_mask2_mul: u32,
    /// Extra additive term in paramStart (per-method; resolved against the params table).
    pub md_param_extra: u32,

    pub fd_stride: u32,
    pub fd_name: Column,
    pub fd_type: Column,
    pub fd_attrs: Column,
    pub fd_pmask: MaskChain,

    /// 7.1 params table: entries {key@0, type@4, ?@8}, key searched linearly.
    pub param_stride: u32,
    pub param_key_c: u32,
    pub param_extra_is_slot: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm71() -> MaskChain {
        MaskChain { mul1: 0x4E94, xor1: 0x62D8_B7B8, mul2: 0x7572_748A, add1: 0x1F4D_9EEA, xor2: 0x6E89_31D6, mul_last: 0xC6FC_9C8B }
    }

    #[test]
    fn pmask_matches_reference() {
        let c = pm71();
        // value cross-checked against methods_71::pmask for i=1
        assert_eq!(c.eval(1), {
            let mut v = ((1u64) * 0x4E94) ^ 0x62D8_B7B8u64;
            v = v.wrapping_mul(0x7572_748A).wrapping_add(0x1F4D_9EEA);
            v ^= 0x6E89_31D6;
            ((v as u32).wrapping_mul(0xC6FC_9C8B)) as u32
        });
    }
}
