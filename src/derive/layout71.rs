//! The 7.1-generation layout shape: every constant was recovered from the 7.1.0
//! YuanShen.exe metadata accessors (kuna decompilation, cross-checked with the
//! 6.4 community dump oracle) and validated structurally over the full tables.
//!
//! Future builds with the same layout but rotated constants are handled by
//! `discover` (constant-pool re-derivation); a layout change surfaces as a
//! validator failure naming the broken step.

use super::profile::{ColKind, Column, FieldMaskChain, MaskChain, Profile, TableBase};

/// The 7.1 layout with its measured constants.
pub fn gen71() -> Profile {
    Profile {
        // The legacy triple below is the same schedule `derive::cipher` recovers from
        // 7.1.0 (verified bit-identical: ((off & 0xFFFFFF) * M1 + X1) ^ X2, step M4),
        // so it is left in the legacy form on purpose -- it is the oracle the derived
        // form is checked against.
        cipher: None,
        str_m1: 0xB33E_4042_7D56_68C0,
        str_x1: 0x6D8C_4AAB_00FE_8E27,
        str_x2: 0x30EE_5B43_130F_E0CD,
        str_m4: 0x0889_EEEA_326A_FB36,
        str_hdr_off: 0x150,
        str_sub: 0x37AB_D22E,

        type_defs: TableBase { hdr_off: 0xDC, sub: None, xor: Some(0x5278_CA3B) },
        method_defs: TableBase { hdr_off: 0x1E0, sub: None, xor: Some(0x2EE4_80FB) },
        fields: TableBase { hdr_off: 0x158, sub: Some(0x1D54_5CCC), xor: None },
        params: TableBase { hdr_off: 0x1D0, sub: None, xor: Some(0x07D0_BBF9) },
        // MEASURED WRONG, and currently dead: `derive::anchor` recovers the real code as
        // `mov edx,[r13+0x200] ; mov eax,0xB43E0EB1 ; add edx,eax` (=> body + 0xA03E64),
        // whereas this `sub` resolves to 0x9824_2102, outside the body. `Meta::slot_base`
        // has no reader, so nothing consumes it today; left as-is on purpose (changing a
        // shared constant is a behaviour change, not a fix). See IMPLEMENTATION_LOG §12.
        slot_table: TableBase { hdr_off: 0x200, sub: Some(0xB43E_0EB1), xor: None },

        td_stride: 0x46,
        td_magic: -0x2145_AFB7,
        td_name: Column { offset: 0x14, kind: ColKind::AddC, c: 0xE811_F779 },
        td_name_sentinel: 0x17EE_0886,
        td_ns: Column { offset: 0x18, kind: ColKind::XorC, c: 0x6667_69B5 },
        td_method_start: Column { offset: 0x08, kind: ColKind::XorC, c: 0x0478_AF59 },
        // typeDef fieldStart/fieldCount (validated: chain-walk tiles [0, 440172) exactly
        // over slots 0..88903; cross-checked against 6.4Dump.cs field sets at 2747 anchors).
        td_field_start: Column { offset: 0x00, kind: ColKind::XorC, c: 0x7262_8007 },
        td_fs_sentinel_raw: 0x8D9D_7FF8,
        td_field_count: Column { offset: 0x30, kind: ColKind::XorC, c: 0x9A6B },
        // flags = raw + 0xDFA09F90 (mod 2^32) — decoded from the .upx0 mutated class
        // builder 0x159F63C4D: `mov edx,0xDFA09F90; add edx,[row+0xC]; mov [klass+0xAC],edx`.
        // Validated statistically (iface 0.0181/abs 0.089/sealed 0.505/pub 0.790) and
        // row-by-row against the calibrated rows 0..4 (log §28).
        td_flags: Some(Column { offset: 0x0C, kind: ColKind::AddC, c: 0xDFA0_9F90 }),
        // bitfield = u16@0x32 ^ 0x8BA4 — bit0 IsValueType (rate 0.1464), bit1 IsEnum
        // (0.0916); row4 Mono.RuntimeClassHandle decodes sealed|vt as expected.
        td_bitfield: Some(Column { offset: 0x32, kind: ColKind::XorC, c: 0x8BA4 }),

        // Full field table (all images): stride 8 {name_raw@0, type_raw@4}; per-row mask
        // with a 64-bit add (add1 > 2^32) and a pre-truncation shift. 440172 rows.
        field_names: TableBase { hdr_off: 0x4C, sub: Some(0xE5D2_49BFu32.wrapping_neg()), xor: None },
        field_stride: 8,
        field_mask: FieldMaskChain {
            mul1: 0x23CF,
            xor1: 0x3D27_C42E,
            mul2: 0x7F76_A166,
            add1: 0x0F06_651F_C0B8_A,
            shift: 16,
            add2: 0x49AC_DCBC,
        },
        field_name_xor: 0x048E_6373,
        field_type_add: 0xB36B_852D,
        field_type_xor: 0x4F6E_2A1D,

        // typeDef parent: parent_tarr = raw@0x2C ^ tag@0x1C ^ 0x8177D738 (validated:
        // Enum->ValueType->Object chain, MonoBehaviour/MonoUIProxy clusters; confirmed in
        // the class-setup decompilation). 0xFFFFFFFF = no base (interfaces, System.Object).
        td_parent_off: 0x2C,
        td_parent_xor: 0x8177_D738,
        // Interface-offsets table hdr[0x70] - 0x6EA5B3FD, stride 6 {typeIdx i32, off i16};
        // per-type start = u16@0x3A ^ 0x4BCE (0xFFFF = none); count = next distinct start
        // (offsets list includes interfaces inherited from bases).
        iface_table: TableBase { hdr_off: 0x70, sub: Some(0x6EA5_B3FD), xor: None },
        iface_stride: 6,
        td_iface_start_off: 0x3A,
        td_iface_start_xor: 0x4BCE,

        md_stride: 0x1A,
        md_ret_type: Column { offset: 0x00, kind: ColKind::AddCSubMask2, c: 0xE5EE_4081 },
        md_name: Column { offset: 0x04, kind: ColKind::XorCAddMask, c: 0x0613_ACE3 },
        md_param_start: Column { offset: 0x08, kind: ColKind::XorCSubMask2, c: 0x20D5_5D01 },
        md_decl: Column { offset: 0x0E, kind: ColKind::XorCAddMask, c: 0x0394_729C },
        md_slot: Column { offset: 0x0C, kind: ColKind::XorCSubMask2I16, c: 0x1E2A },
        md_flags: Column { offset: 0x12, kind: ColKind::SubMask2AddC16, c: 0x8D17 },
        md_param_count: Column { offset: 0x18, kind: ColKind::SubMask2AddC8, c: 0x8C },
        md_pmask: MaskChain {
            mul1: 0x4E94,
            xor1: 0x62D8_B7B8,
            mul2: 0x7572_748A,
            add1: 0x1F4D_9EEA,
            xor2: 0x6E89_31D6,
            mul_last: 0xC6FC_9C8B,
        },
        md_mask2_mul: 0x3903_6375,
        md_param_extra: 0,

        fd_stride: 10,
        fd_name: Column { offset: 0x00, kind: ColKind::AddC, c: 0xEE88_95EA_u32.wrapping_neg() },
        fd_type: Column { offset: 0x04, kind: ColKind::SubMask2AddC16, c: 0x238F },
        fd_attrs: Column { offset: 0x06, kind: ColKind::SubMask2AddC16, c: 0x720A_u32.wrapping_neg() },
        fd_pmask: MaskChain {
            mul1: 0xA593,
            xor1: 0x3CA3_FFA0,
            mul2: 0x5CD0_B62E,
            add1: 0x63A3_41E6,
            xor2: 0x2411_ED71,
            mul_last: 0,
        },
        param_stride: 12,
        param_key_c: 0x20D5_5D01,
        param_extra_is_slot: false,
    }
}
