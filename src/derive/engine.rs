//! Engine: load exe + encrypted metadata under a [`Profile`] and decode every table.

use anyhow::{anyhow, bail, Result};

use super::profile::{ColKind, Column, Profile};
use crate::mem::{Buffer, Memory};

/// Loaded metadata + resolved tables, addressed through a profile.
pub struct Meta<'a> {
    pub profile: Profile,
    /// The profile's key schedule, materialised once (see [`Profile::schedule`]).
    pub schedule: crate::derive::cipher::CipherSchedule,
    pub body: Buffer<'a>,
    pub image: &'a [u8],
    pub image_base: u64,
    /// The embedded MHY header (0x210 bytes) that every table anchor is resolved against.
    pub header: Vec<u8>,
    /// PE sections as `(rva, virtual_size, raw_pointer, raw_size)` (for VA -> file offset).
    pub sections: Vec<(u32, u32, u32, u32)>,
    /// Sibling `startup-metadata.dat` bytes (4 MB), when present. It holds the generic-class
    /// row table and other tables that are NOT in the global-metadata body.
    pub startup: Option<&'a [u8]>,
    /// Offset of the 8-byte generic-class rows in `startup` (0 = not available).
    pub gc_rows: usize,
    /// File offset of the 16-byte `Il2CppGenericInst` struct array (0 = not available).
    pub generic_insts: usize,
    pub typearr: usize,
    pub typearr_len: usize,
    /// Generic-parameter table base (body offset; 7.1: hdr[0x174] + 0xCED1EDB1 = 0xDF8708).
    pub gp_base: usize,
    /// Generic-parameter count (derived from the highest VAR/MVAR index used in typearr;
    /// 7.1: 5,796, matching the contiguous encrypted table at `gp_base`).
    pub gp_count: usize,
    /// typeDef index -> global generic-parameter indexes (type owners only; the encrypted
    /// 16-byte container table at slot 0xC8 marks type owners with `data == mask2`).
    pub generic_params_by_type: std::collections::HashMap<u32, Vec<u32>>,
    /// method index -> global generic-parameter indexes (method owners; container MVAR rows).
    pub generic_params_by_method: std::collections::HashMap<u32, Vec<u32>>,
    pub methodptrs: usize,
    pub methodptrs_len: usize,
    pub rdata: (u64, usize, usize),
    pub strsec: usize,
    pub td_base: usize,
    pub md_base: usize,
    /// Real method-row count (from the method-table size slot when the profile has one;
    /// falls back to the code-pointer array length, which is only a lower bound).
    pub md_rows: usize,
    /// typeDef-row count from the table-size slot (padding trimmed in `td_count`).
    pub td_rows: usize,
    pub fd_base: usize,
    pub param_base: usize,
    pub slot_base: usize,
    pub field_base: usize,
    pub iface_base: usize,
    /// Parameter-definition table base (8B rows; name@+4, typearr index@+0).
    pub param_def_base: usize,
    /// Nested-types table base (u32 typeDef indexes per row).
    pub nested_base: usize,
    /// Parameter-default table base (12-byte rows; 0 when the profile lacks it).
    pub param_default_base: usize,
    /// Parameter-default table row count (0 when the profile lacks it).
    pub param_default_rows: usize,
    /// Property-definition table base (10-byte rows in 7.1; 0 when the profile lacks it).
    pub property_base: usize,
    /// Event-definition table base (14-byte rows in 7.1; 0 when the profile lacks it).
    pub event_base: usize,
    /// Field default values: field-table index -> (value byte offset in the shared blob, value Il2CppType index).
    pub field_defaults: std::collections::HashMap<u32, (i32, u32)>,
    /// Body offset of the shared default-value data blob.
    pub default_values: usize,
}

impl<'a> Meta<'a> {
    pub fn load(exe: &'a [u8], dat: &'a [u8], profile: Profile) -> Result<Self> {
        Self::load_with_startup(exe, dat, None, profile)
    }

    /// Like [`Meta::load`], but also accepts the sibling `startup-metadata.dat`, which carries
    /// the generic-class row table (without it `GENERICINST` types have no static form and are
    /// rendered as `System.Object`).
    pub fn load_with_startup(
        exe: &'a [u8],
        dat: &'a [u8],
        startup: Option<&'a [u8]>,
        profile: Profile,
    ) -> Result<Self> {
        const BODY_OFF: usize = 0x210;
        if dat.len() <= BODY_OFF || &dat[..4] != b"MHY\0" {
            bail!("global-metadata.dat missing MHY magic");
        }
        let body_buf = &dat[BODY_OFF..];
        let header_bytes = find_header(exe, body_buf, &profile)
            .ok_or_else(|| anyhow!("embedded MHY header not located (self-validation failed)"))?;
        let body = Buffer::new(body_buf);

        let strsec = (i32::from_le_bytes(
            header_bytes[profile.str_hdr_off as usize..profile.str_hdr_off as usize + 4].try_into().unwrap(),
        )
        .wrapping_sub(profile.str_sub as i32)) as usize;

        let img = crate::pe::Image::parse(exe)?;
        let image_base = img.image_base();
        let sections: Vec<(u32, u32, u32, u32)> = img
            .sections()
            .iter()
            .map(|s| (s.virtual_address, s.virtual_size, s.raw_pointer, s.raw_size))
            .collect();
        let rd = img.section(".rdata").ok_or_else(|| anyhow!(".rdata missing"))?;
        let rdata = (image_base + rd.virtual_address as u64, rd.raw_pointer as usize, rd.raw_size as usize);

        // Generic tables: the row table is in startup-metadata, the GenericInst struct array
        // is in the image (registration+0x28). Both are optional — absence just means
        // `GENERICINST` types cannot be rendered (explicit warning at dump time).
        let gc_rows = match (&profile.generic_class_rows, startup) {
            (Some(t), Some(_)) => t.resolve(&header_bytes),
            _ => 0,
        };
        let generic_insts = match profile.generic_insts_va {
            Some(va) => img.va_to_file(va).unwrap_or(0) as usize,
            None => 0,
        };

        let (typearr, typearr_len) =
            locate_typearr(exe, &rdata).ok_or_else(|| anyhow!("typearr not located"))?;
        // Generic-parameter table (docs/re/71-generic-params.md):
        //   base  = body + (hdr[0x174] + 0xCED1EDB1)   (14-byte rows, 7.1: 0xDF8708)
        //   row i is XOR-masked with  ((i*0x6F1C0337A0897415 + 0x31061C4212D60D89) >> 22)
        // Count is not stored in the header; the highest VAR/MVAR index referenced by typearr is
        // 5,795, so the table holds 5,796 entries (the contiguous run ends exactly there).
        let gp_base = {
            let h = i32::from_le_bytes(header_bytes[0x174..0x178].try_into().unwrap());
            h.wrapping_add(0xCED1_EDB1u32 as i32) as u32 as usize
        };
        let mut gp_count = 0usize;
        for i in 0..typearr_len {
            let Some(b) = exe.get(typearr + 16 * i..typearr + 16 * i + 16) else { break };
            let kind = b[0xA];
            if kind == 0x13 || kind == 0x1E {
                let data = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
                gp_count = gp_count.max(data + 1);
            }
        }
        // Encrypted 16-byte generic-container table (7.1: slot 0xC8 = body+0x3C479D8).
        // container(V).data + 0x8EDEA6E9 == mask2(V) marks a *type* owner; then
        // ownerTdi = container(V).attrs ^ (data+0x8EDEA6E9) ^ 0x5C56350B.
        let gc_base = {
            let h = i32::from_le_bytes(header_bytes[0xC8..0xCC].try_into().unwrap());
            (h ^ 0x8D70_1A3) as u32 as usize
        };
        let gp_mask = |gpi: u32| -> u32 {
            ((gpi as u64)
                .wrapping_mul(0x6F1C_0337_A089_7415)
                .wrapping_add(0x3106_1C42_12D6_0D89)
                >> 22) as u32
        };
        let container_mask2 = |v: u32| -> u32 {
            let mut r = (v.wrapping_mul(0x8187) ^ 0x42D5_A190).wrapping_mul(0x7B2D_0E18);
            r = r.wrapping_add(0xB6F0_0C08);
            r ^= 0x7A3E_254D;
            r.wrapping_add(0x7155_5646)
        };
        let mut generic_params_by_type: std::collections::HashMap<u32, Vec<u32>> =
            std::collections::HashMap::new();
        let mut generic_params_by_method: std::collections::HashMap<u32, Vec<u32>> =
            std::collections::HashMap::new();
        for gpi in 0..gp_count as u32 {
            let at = gp_base + 14 * gpi as usize + 0xC;
            let Some(row) = body_buf.get(at..at + 2) else { break };
            let raw = u16::from_le_bytes([row[0], row[1]]);
            let v = raw.wrapping_add(0xA8E2) ^ (gp_mask(gpi) as u16);
            let entry = gc_base + 16 * v as usize;
            let Some(ent) = body_buf.get(entry..entry + 16) else { continue };
            let data = u32::from_le_bytes([ent[0], ent[1], ent[2], ent[3]]);
            let attrs = u32::from_le_bytes([ent[12], ent[13], ent[14], ent[15]]);
            let x = data.wrapping_add(0x8EDE_A6E9);
            let owner = attrs ^ x ^ 0x5C56_350B;
            if x == container_mask2(v as u32) {
                // VAR: owner is a typeDef index.
                generic_params_by_type.entry(owner).or_default().push(gpi);
            } else {
                // MVAR: owner is a method index.
                generic_params_by_method.entry(owner).or_default().push(gpi);
            }
        }
        let (methodptrs, methodptrs_len) =
            locate_methodptrs(exe, image_base).ok_or_else(|| anyhow!("method pointers not located"))?;

        let schedule = profile.schedule();
        // Method-row count: the table-size slot is authoritative. The code-pointer array
        // length is only a lower bound (7.1.0: 460,282 vs 733,481 real rows) because
        // generic/shared methods have no direct pointer.
        let md_stride = profile.md_stride.max(1) as usize;
        let body_cap = (body.size().saturating_sub(profile.method_defs.resolve(&header_bytes))) / md_stride;
        let md_rows = match &profile.md_size {
            Some(t) => (t.resolve(&header_bytes) / md_stride).min(body_cap),
            None => methodptrs_len.min(body_cap),
        };
        // typeDef-row count: same rule; the chain walk undercounts (7.1.0: 88,872 vs 88,904).
        let td_stride = profile.td_stride.max(1) as usize;
        let td_cap = body.size().saturating_sub(profile.type_defs.resolve(&header_bytes)) / td_stride;
        let td_rows = match &profile.td_size {
            Some(t) => (t.resolve(&header_bytes) / td_stride).min(td_cap),
            None => 0, // 0 = fall back to the chain walk in td_count()
        };
        // Field default values (12-byte rows {valueOff, fieldIdx, typeIdx}) + shared value blob.
        let mut field_defaults = std::collections::HashMap::new();
        let mut default_values = 0usize;
        if let (Some(tb), Some(szb), Some(vd)) = (
            profile.field_defaults.as_ref(),
            profile.field_defaults_size.as_ref(),
            profile.default_value_data.as_ref(),
        ) {
            let base = tb.resolve(&header_bytes);
            let count = szb.resolve(&header_bytes) / 12;
            default_values = vd.resolve(&header_bytes);
            for r in 0..count {
                let at = base + r * 12;
                let Some(b) = body.read_slice(at, 12) else { break };
                let dataoff = i32::from_le_bytes(b[0..4].try_into().unwrap());
                let fidx = i32::from_le_bytes(b[4..8].try_into().unwrap());
                let tix = i32::from_le_bytes(b[8..12].try_into().unwrap());
                if fidx >= 0 {
                    field_defaults.insert(fidx as u32, (dataoff, tix as u32));
                }
            }
        }
        Ok(Self {
            schedule,
            td_base: profile.type_defs.resolve(&header_bytes),
            md_base: profile.method_defs.resolve(&header_bytes),
            md_rows,
            td_rows,
            fd_base: profile.fields.resolve(&header_bytes),
            param_base: profile.params.resolve(&header_bytes),
            slot_base: profile.slot_table.resolve(&header_bytes),
            field_base: profile.field_names.resolve(&header_bytes),
            iface_base: profile.iface_table.resolve(&header_bytes),
            param_def_base: profile.param_defs.as_ref().map(|t| t.resolve(&header_bytes)).unwrap_or(0),
            nested_base: profile.nested_types.as_ref().map(|t| t.resolve(&header_bytes)).unwrap_or(0),
            param_default_base: profile.params.resolve(&header_bytes),
            param_default_rows: profile
                .param_defaults_size
                .as_ref()
                .map(|t| t.resolve(&header_bytes) / profile.param_stride.max(1) as usize)
                .unwrap_or(0),
            property_base: profile.property_defs.as_ref().map(|t| t.resolve(&header_bytes)).unwrap_or(0),
            event_base: profile.event_defs.as_ref().map(|t| t.resolve(&header_bytes)).unwrap_or(0),
            field_defaults,
            default_values,
            profile,
            body,
            image: exe,
            image_base,
            header: header_bytes,
            sections,
            startup,
            gc_rows,
            generic_insts,
            typearr,
            typearr_len,
            gp_base,
            gp_count,
            generic_params_by_type,
            generic_params_by_method,
            methodptrs,
            methodptrs_len,
            rdata,
            strsec,
        })
    }

    #[inline]
    /// Generic-parameter name for global index `gpi` (VAR/MVAR `Il2CppType.data` is this index).
    /// The row's name index is masked per row; 7.1 stores real source names (TKey/TValue/TRest/…)
    /// with a few single-control-char obfuscated names.
    pub fn generic_param_name(&self, gpi: u32) -> Option<String> {
        if gpi as usize >= self.gp_count {
            return None;
        }
        let at = self.gp_base + 14 * gpi as usize;
        let raw = self.body.read_u32_opt(at)?;
        let idx = raw.wrapping_add(0x9E52_99B1) ^ Self::generic_param_mask(gpi);
        let s = self.decode_str(idx);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Declaring generic-container index for `gpi` (the row's +0xC column).
    pub fn generic_param_owner(&self, gpi: u32) -> Option<u16> {
        if gpi as usize >= self.gp_count {
            return None;
        }
        let at = self.gp_base + 14 * gpi as usize + 0xC;
        if !self.body.readable(at, 2) {
            return None;
        }
        let raw = self.body.read_u16(at);
        Some(raw.wrapping_add(0xA8E2) ^ (Self::generic_param_mask(gpi) as u16))
    }

    #[inline]
    /// Names of a generic type definition's parameters (type owners only; method generic
    /// parameters are not attached here). One slot per parameter is kept so the generator's
    /// positional fallback stays aligned; control-character names come back as empty strings.
    pub fn type_generic_param_names(&self, tdi: u32) -> Vec<String> {
        let Some(list) = self.generic_params_by_type.get(&tdi) else {
            return Vec::new();
        };
        list.iter()
            .map(|g| match self.generic_param_name(*g) {
                Some(n) if !n.chars().any(char::is_control) => n,
                _ => String::new(),
            })
            .collect()
    }

    /// Names of a generic *method* definition's parameters (MVAR containers), one slot per
    /// parameter; control-character names come back as empty strings.
    pub fn method_generic_param_names(&self, mi: u32) -> Vec<String> {
        let Some(list) = self.generic_params_by_method.get(&mi) else {
            return Vec::new();
        };
        list.iter()
            .map(|g| match self.generic_param_name(*g) {
                Some(n) if !n.chars().any(char::is_control) => n,
                _ => String::new(),
            })
            .collect()
    }

    pub fn generic_param_mask(gpi: u32) -> u32 {
        ((gpi as u64)
            .wrapping_mul(0x6F1C_0337_A089_7415)
            .wrapping_add(0x3106_1C42_12D6_0D89)
            >> 22) as u32
    }

    pub fn decode_str(&self, idx: u32) -> String {
        crate::decode_str::decode_str_sched(&self.body, self.strsec, idx, &self.schedule)
    }

    /// Per-row mask 2 (the `-0x39036375` variant) for row `i`.
    #[inline]
    pub fn mask2(&self, i: u32) -> u32 {
        let p = &self.profile.md_pmask;
        let mut v = ((i as u64) * p.mul1 as u64) ^ p.xor1 as u64;
        v = v.wrapping_mul(p.mul2 as u64);
        v = v.wrapping_add(p.add1 as u64);
        v ^= p.xor2 as u64;
        (v as u32).wrapping_mul(self.profile.md_mask2_mul)
    }

    /// methodDef column decode (32-bit result; narrow kinds truncate afterwards).
    #[inline]
    pub fn md_col(&self, c: &Column, i: u32) -> u32 {
        let at = self.md_base + self.profile.md_stride as usize * i as usize + c.offset as usize;
        let raw = u32::from_le_bytes(self.body.read_slice(at, 4).unwrap_or(&[0, 0, 0, 0]).try_into().unwrap_or([0; 4]));
        let t = self.profile.md_pmask.eval(i);
        let m2 = self.mask2(i);
        match c.kind {
            ColKind::XorCAddMask => (raw ^ c.c).wrapping_add(t),
            ColKind::AddCAddMask => raw.wrapping_add(c.c).wrapping_add(t),
            ColKind::AddCSubMask2 => raw.wrapping_add(c.c).wrapping_sub(m2),
            ColKind::XorCSubMask2 => (raw ^ c.c).wrapping_sub(m2),
            ColKind::XorCSubMask2I16 => (raw ^ c.c).wrapping_sub(m2),
            ColKind::SubMask2AddC16 => raw.wrapping_sub(m2).wrapping_add(c.c),
            ColKind::SubMask2AddC8 => raw.wrapping_sub(m2).wrapping_add(c.c),
            ColKind::XorC => raw ^ c.c,
            ColKind::AddC => raw.wrapping_add(c.c),
            _ => raw,
        }
    }

    pub fn md_count(&self) -> usize {
        self.md_rows
    }

    pub fn td_count(&self) -> usize {
        if self.td_rows > 0 {
            // Size-slot count; trim trailing all-sentinel padding rows (no name, no
            // methods, no fields).
            let p = &self.profile;
            let stride = p.td_stride as usize;
            let mut n = self.td_rows.min((self.body.size().saturating_sub(self.td_base)) / stride);
            while n > 0 {
                let rec = self.td_base + (n - 1) * stride;
                let raw_name = self.body.read_u32(rec + p.td_name.offset as usize);
                let name_empty = raw_name == p.td_name_sentinel
                    || self.decode_str(raw_name.wrapping_add(p.td_name.c)).is_empty();
                let ms = self.body.read_u32(rec + p.td_method_start.offset as usize)
                    ^ p.td_method_start.c;
                let fs_raw = self.body.read_u32(rec + p.td_field_start.offset as usize);
                if name_empty && ms == u32::MAX && fs_raw == p.td_fs_sentinel_raw {
                    n -= 1;
                } else {
                    break;
                }
            }
            return n;
        }
        // Fallback (profiles without a typeDef size slot): magic-column walk.
        let stride = self.profile.td_stride as usize;
        let mut n = 0usize;
        let mut run_bad = 0usize;
        let mut i = 0usize;
        while i < 400_000 {
            let rec = self.td_base + i * stride;
            if rec + stride > self.body.size() {
                break;
            }
            let m = i32::from_le_bytes(self.body.read_slice(rec + 0x1C, 4).unwrap_or(&[0; 4]).try_into().unwrap_or([0; 4]));
            if m != self.profile.td_magic {
                run_bad += 1;
                if run_bad > 5_000 {
                    break;
                }
            } else {
                run_bad = 0;
                n = i + 1;
            }
            i += 1;
        }
        n
    }

    /// Decoded (fieldStart, fieldCount) for typeDef slot `i` (no chain validation).
    /// `fieldStart == u32::MAX` means "no fields".
    #[inline]
    pub fn td_fs_fc(&self, i: usize) -> (u32, u32) {
        let p = &self.profile;
        let rec = self.td_base + p.td_stride as usize * i;
        let raw = self.body.read_u32(rec + p.td_field_start.offset as usize);
        let fs = if raw == p.td_fs_sentinel_raw {
            u32::MAX
        } else {
            raw ^ p.td_field_start.c
        };
        let raw_fc = self.body.read_u16(rec + p.td_field_count.offset as usize);
        (fs, (raw_fc ^ p.td_field_count.c as u16) as u32)
    }

    /// Chain-walk the typeDef table: real slots tile the field rows exactly
    /// (`fs == expected`, or the no-fields sentinel). Trailing padding records
    /// break the chain and end the walk. Returns the number of real slots and
    /// the total field-row count.
    pub fn td_walk(&self) -> (usize, usize) {
        let stride = self.profile.td_stride as usize;
        let mut expected = 0u32;
        let mut n = 0usize;
        loop {
            let rec = self.td_base + n * stride;
            if rec + stride > self.body.size() {
                break;
            }
            let (fs, fc) = self.td_fs_fc(n);
            if fs == u32::MAX {
                if fc != 0 {
                    break;
                }
            } else if fs == expected && fc as u64 + expected as u64 <= self.field_rows_cap() as u64 {
                expected += fc;
            } else {
                break;
            }
            n += 1;
        }
        (n, expected as usize)
    }

    /// Upper bound for the field table rows (table size / stride).
    fn field_rows_cap(&self) -> usize {
        (self.body.size().saturating_sub(self.field_base)) / self.profile.field_stride as usize
    }

    /// Read a little-endian u32 out of the sibling `startup-metadata.dat`.
    #[inline]
    fn startup_u32(&self, at: usize) -> Option<u32> {
        let s = self.startup?;
        let b = s.get(at..at + 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    /// Names from one startup-metadata name table (images / assemblies).
    ///
    /// Self-validating: rows are walked until the masked packed index no longer decodes to a
    /// plausible assembly/image file name, so a wrong table anchor yields an empty vector
    /// instead of garbage.
    fn startup_name_table_names(&self, t: &crate::derive::profile::StartupNameTable) -> Vec<String> {
        let Some(_) = self.startup else { return Vec::new() };
        let base = t.table.resolve(&self.header);
        let mut out = Vec::new();
        for i in 0..4096u32 {
            let Some(row) = base.checked_add((i as usize).wrapping_mul(t.stride as usize)) else { break };
            let Some(at) = row.checked_add(t.name_off as usize) else { break };
            let Some(raw) = self.startup_u32(at) else { break };
            let packed = t.packed_index(raw, i);
            let name = self.decode_str(packed);
            // Assembly names may start with `_` (e.g. `__Generated`) and need not end in
            // `.dll`; the stop condition is simply the first row that fails to decode to a
            // plausible identifier-ish name.
            let first_ok = name
                .chars()
                .next()
                .map(|c| c.is_ascii_alphanumeric() || c == '_')
                .unwrap_or(false);
            let ok = !name.is_empty()
                && name.len() <= 200
                && first_ok
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'+' | b'`'));
            if !ok {
                break;
            }
            out.push(name);
        }
        out
    }

    /// Image names from the startup-metadata images table (7.1.0: 75 entries, `mscorlib.dll` first).
    pub fn startup_image_names(&self) -> Vec<String> {
        match self.profile.startup_images.as_ref() {
            Some(t) => self.startup_name_table_names(t),
            None => Vec::new(),
        }
    }

    /// Assembly names from the startup-metadata assemblies table (7.1.0: 75 entries).
    pub fn startup_assembly_names(&self) -> Vec<String> {
        match self.profile.startup_assemblies.as_ref() {
            Some(t) => self.startup_name_table_names(t),
            None => Vec::new(),
        }
    }

    /// Attribute-instance type (typearr index) for instance `i`, when the profile has the
    /// attribute table (7.1.0: body 0x9BACA4, 74,864 plaintext entries).
    pub fn attribute_type_idx(&self, i: u32) -> Option<u32> {
        let off = self.profile.attribute_types_off?;
        let count = self.profile.attribute_count?;
        if i >= count {
            return None;
        }
        let at = off as usize + 4 * i as usize;
        let b = self.body.read_slice(at, 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    pub fn attribute_instance_count(&self) -> u32 {
        self.profile.attribute_count.unwrap_or(0)
    }

    /// `instance -> member token` map for the custom-attribute pair table.
    ///
    /// 7.1.0 stores it as 8-byte rows `{member token, tag + instance}` spread over several
    /// sorted chunks of the body (not one contiguous array), so the whole body is scanned:
    /// any 8-byte row whose second word is `tag + i` for `i < attribute_count` contributes
    /// the mapping. First occurrence wins; rows with a zero/invalid token are ignored by the
    /// caller (the token space is validated there against table sizes).
    pub fn attribute_instance_tokens(&self) -> Vec<(u32, u32)> {
        let (Some(tag), Some(count)) = (
            self.profile.attribute_instance_tag,
            self.profile.attribute_count,
        ) else {
            return Vec::new();
        };
        let mut out: Vec<Option<u32>> = vec![None; count as usize];
        let bytes = self.body.size();
        let mut at = 0usize;
        // Scan u64-aligned windows: read (a,b) at +0 and (b,c) at +4 is unnecessary — the pair
        // table rows are 8-byte aligned in every chunk, so step by 4 and read both words.
        while at + 8 <= bytes {
            let (Some(a), Some(b)) = (
                self.body.read_u32_opt(at),
                self.body.read_u32_opt(at + 4),
            ) else {
                break;
            };
            let va = b.wrapping_sub(tag);
            if va < count {
                let slot = &mut out[va as usize];
                if slot.is_none() {
                    *slot = Some(a);
                }
            }
            at += 4;
        }
        out.into_iter()
            .enumerate()
            .filter_map(|(i, t)| t.map(|t| (i as u32, t)))
            .collect()
    }

    /// Per-row field-table mask.
    #[inline]
    pub fn field_mask(&self, i: u32) -> u32 {
        self.profile.field_mask.eval(i)
    }

    /// Field name index for row `i` of the full field table.
    #[inline]
    pub fn field_name_idx(&self, i: u32) -> u32 {
        let raw = self.body.read_u32(self.field_base + self.profile.field_stride as usize * i as usize);
        raw ^ self.field_mask(i) ^ self.profile.field_name_xor
    }

    /// Field name for row `i`.
    pub fn field_name(&self, i: u32) -> String {
        self.decode_str(self.field_name_idx(i))
    }

    /// Field type (typearr index) for row `i`.
    #[inline]
    pub fn field_type_idx(&self, i: u32) -> u32 {
        let raw = self.body.read_u32(
            self.field_base + self.profile.field_stride as usize * i as usize + 4,
        );
        (raw.wrapping_add(self.profile.field_type_add)) ^ self.field_mask(i) ^ self.profile.field_type_xor
    }

    /// typeDef parent (typearr index; u32::MAX = no base — interfaces / System.Object).
    /// Mask material is the per-record tag at +0x1C.
    #[inline]
    /// Field default value: (value-offset in the shared blob, value Il2CppType index).
    #[inline]
    pub fn field_default(&self, field_idx: u32) -> Option<(i32, u32)> {
        self.field_defaults.get(&field_idx).copied()
    }

    /// Bytes of a default value inside the shared blob.
    #[inline]
    pub fn default_value_bytes(&self, off: i32, len: usize) -> Option<&[u8]> {
        if off < 0 {
            return None;
        }
        self.body.read_slice(self.default_values + off as usize, len)
    }

    /// Parameter-definition row mask (parameter index space).
    #[inline]
    pub fn param_def_mask(&self, i: u32) -> Option<u32> {
        Some(self.profile.param_def_mask.as_ref()?.eval(i))
    }

    /// Parameter NAME for global parameter index `i` (disassembled accessor 0x1405297EE).
    pub fn param_name(&self, i: u32) -> Option<String> {
        let stride = self.profile.param_def_stride as usize;
        self.profile.param_defs.as_ref()?;
        let mask = self.param_def_mask(i)?;
        let row = self.param_def_base + stride * i as usize;
        let raw = self.body.read_u32(row + 4);
        let idx = (raw ^ self.profile.param_def_name_xor).wrapping_sub(mask);
        Some(self.decode_str(idx))
    }

    /// Parameter TYPE for global parameter index `i`: `Some(None)` = declared `null` type,
    /// `None` = table unavailable.
    pub fn param_type(&self, i: u32) -> Option<Option<u32>> {
        let stride = self.profile.param_def_stride as usize;
        self.profile.param_defs.as_ref()?;
        let mask = self.param_def_mask(i)?;
        let row = self.param_def_base + stride * i as usize;
        let raw = self.body.read_u32(row);
        let v = (raw ^ self.profile.param_def_type_xor).wrapping_sub(mask);
        Some(if v == u32::MAX { None } else { Some(v) })
    }

    /// Parameter DEFAULT value for global parameter index `gpi`: `(value typearr index,
    /// optional byte offset in the shared default-value blob)`. `None` = no default row for that
    /// parameter. Row format (12 bytes, sorted by parameterIndex):
    /// {parameterIndex u32, valueTypeIndex u32, dataOffset i32}.
    pub fn param_default(&self, gpi: u32) -> Option<(u32, Option<i32>)> {
        if self.param_default_rows == 0 {
            return None;
        }
        let stride = self.profile.param_stride as usize;
        let (mut lo, mut hi) = (0usize, self.param_default_rows);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let at = self.param_default_base + stride * mid;
            let key = self.body.read_u32(at);
            if key < gpi {
                lo = mid + 1;
            } else if key > gpi {
                hi = mid;
            } else {
                let tix = self.body.read_u32(at + 4);
                let off = self.body.read_u32(at + 8) as i32;
                return Some((tix, if off == -1 { None } else { Some(off) }));
            }
        }
        None
    }

    /// typeDef nestedTypesStart (u16 column; 0xFFFF = none).
    pub fn td_nested_start(&self, i: usize) -> Option<u32> {
        let col = self.profile.td_nested_start.as_ref()?;
        let rec = self.td_base + self.profile.td_stride as usize * i;
        let raw = u16::from_le_bytes(
            self.body.read_slice(rec + col.offset as usize, 2)?.try_into().ok()?,
        ) as u32;
        Some(match col.kind {
            ColKind::XorC => raw ^ col.c,
            _ => raw.wrapping_add(col.c),
        })
    }

    /// typeDef nestedTypesCount (u8 column).
    pub fn td_nested_count(&self, i: usize) -> Option<u32> {
        let col = self.profile.td_nested_count.as_ref()?;
        let rec = self.td_base + self.profile.td_stride as usize * i;
        let raw = *self.body.read_slice(rec + col.offset as usize, 1)?.first()? as u32;
        Some(match col.kind {
            ColKind::XorC => (raw ^ (col.c & 0xFF)) & 0xFF,
            _ => raw.wrapping_add(col.c) & 0xFF,
        })
    }

    /// Row of the nested-types table (u32 typeDef index).
    pub fn nested_types_at(&self, row: u32) -> Option<u32> {
        self.profile.nested_types.as_ref()?;
        let stride = self.profile.nested_stride as usize;
        self.body
            .read_slice(self.nested_base + stride * row as usize, stride)
            .and_then(|b| b.get(0..4).map(|s| u32::from_le_bytes(s.try_into().unwrap())))
    }

    /// typeDef propertyStart (u32 column; `raw + c`). None when the profile lacks the
    /// property-definition table.
    pub fn td_prop_start(&self, i: usize) -> Option<u32> {
        let col = self.profile.td_property_start.as_ref()?;
        self.profile.property_defs.as_ref()?;
        let rec = self.td_base + self.profile.td_stride as usize * i;
        let raw = self.body.read_u32(rec + col.offset as usize);
        Some(match col.kind {
            ColKind::XorC => raw ^ col.c,
            _ => raw.wrapping_add(col.c),
        })
    }

    /// typeDef propertyCount (u8 column; `raw ^ (c & 0xFF)`). None without the table.
    pub fn td_prop_count(&self, i: usize) -> Option<u32> {
        let col = self.profile.td_property_count.as_ref()?;
        self.profile.property_defs.as_ref()?;
        let rec = self.td_base + self.profile.td_stride as usize * i;
        let raw = *self.body.read_slice(rec + col.offset as usize, 1)?.first()? as u32;
        Some(match col.kind {
            ColKind::XorC => (raw ^ (col.c & 0xFF)) & 0xFF,
            _ => raw.wrapping_add(col.c) & 0xFF,
        })
    }

    /// One property-definition row: `(name packed string index, getter method index, setter
    /// method index)`. The accessor options are None for the 0xFFFF sentinel (no such accessor).
    /// Row format (10 bytes): `{u32 name, u16 getter, u16 attrs, u16 setter}`.
    pub fn property_row(&self, row: u32) -> Option<(u32, Option<u16>, Option<u16>)> {
        let mask_chain = self.profile.property_mask.as_ref()?;
        let stride = self.profile.property_stride as usize;
        if stride < 10 {
            return None;
        }
        let at = self.property_base + stride * row as usize;
        let b = self.body.read_slice(at, 10)?;
        let raw_name = u32::from_le_bytes(b[0..4].try_into().ok()?);
        let raw_get = u16::from_le_bytes(b[4..6].try_into().ok()?);
        let raw_set = u16::from_le_bytes(b[8..10].try_into().ok()?);
        let mask = mask_chain.eval(row);
        let name = raw_name.wrapping_add(self.profile.property_name_add) ^ mask;
        let get = (raw_get as u32)
            .wrapping_sub(self.profile.property_get_sub as u32)
            ^ mask;
        let get = (get & 0xFFFF) as u16;
        let set = ((raw_set ^ (mask as u16)) as u32) ^ self.profile.property_set_xor as u32;
        let set = (set & 0xFFFF) as u16;
        Some((
            name,
            if get == 0xFFFF { None } else { Some(get) },
            if set == 0xFFFF { None } else { Some(set) },
        ))
    }

    /// typeDef eventStart (u16 column, `raw + c`; 0xFFFF = none). None without the event table.
    pub fn td_event_start(&self, i: usize) -> Option<u16> {
        let col = self.profile.td_event_start.as_ref()?;
        self.profile.event_defs.as_ref()?;
        let rec = self.td_base + self.profile.td_stride as usize * i;
        let raw = self.body.read_u16(rec + col.offset as usize);
        let v = raw.wrapping_add(col.c as u16);
        if v == 0xFFFF { None } else { Some(v) }
    }

    /// typeDef eventCount (u8 column, `raw ^ (c & 0xFF)`). None without the event table.
    pub fn td_event_count(&self, i: usize) -> Option<u32> {
        let col = self.profile.td_event_count.as_ref()?;
        self.profile.event_defs.as_ref()?;
        let rec = self.td_base + self.profile.td_stride as usize * i;
        let raw = *self.body.read_slice(rec + col.offset as usize, 1)?.first()? as u32;
        Some(match col.kind {
            ColKind::XorC => (raw ^ (col.c & 0xFF)) & 0xFF,
            _ => raw.wrapping_add(col.c) & 0xFF,
        })
    }

    /// One event-definition row: (name packed index, event type typearr index, add, remove,
    /// raise). Accessor fields are per-type method indexes (None for the 0xFFFF sentinel); the
    /// type is None for 0xFFFFFFFF. Row format (14 bytes):
    /// {u32 name, u32 type, u16 remove, u16 raise, u16 add}.
    pub fn event_row(
        &self,
        row: u32,
    ) -> Option<(u32, Option<u32>, Option<u16>, Option<u16>, Option<u16>)> {
        let mask_chain = self.profile.event_mask.as_ref()?;
        let stride = self.profile.event_stride as usize;
        if stride < 14 {
            return None;
        }
        let at = self.event_base + stride * row as usize;
        let b = self.body.read_slice(at, 14)?;
        let raw_name = u32::from_le_bytes(b[0..4].try_into().ok()?);
        let raw_type = u32::from_le_bytes(b[4..8].try_into().ok()?);
        let raw_remove = u16::from_le_bytes(b[8..10].try_into().ok()?);
        let raw_raise = u16::from_le_bytes(b[10..12].try_into().ok()?);
        let raw_add = u16::from_le_bytes(b[12..14].try_into().ok()?);
        let mask = mask_chain.eval(row);
        let m16 = mask as u16;
        let name = (raw_name ^ mask) ^ self.profile.event_name_xor;
        let type_idx = raw_type.wrapping_add(self.profile.event_type_add) ^ mask;
        let remove = ((raw_remove as u32).wrapping_add(self.profile.event_remove_add as u32) ^ mask) & 0xFFFF;
        let raise = ((raw_raise as u32).wrapping_add(self.profile.event_raise_add as u32) ^ mask) & 0xFFFF;
        let add = (((raw_add ^ m16) as u32) ^ self.profile.event_add_xor as u32) & 0xFFFF;
        Some((
            name,
            if type_idx == 0xFFFF_FFFF { None } else { Some(type_idx) },
            if add == 0xFFFF { None } else { Some(add as u16) },
            if remove == 0xFFFF { None } else { Some(remove as u16) },
            if raise == 0xFFFF { None } else { Some(raise as u16) },
        ))
    }

    /// typeDef interfacesCount (u8 column, `raw + add`); None when the profile lacks it.
    pub fn td_iface_count(&self, i: usize) -> Option<u32> {
        let off = self.profile.td_iface_count_off? as usize;
        let rec = self.td_base + self.profile.td_stride as usize * i;
        let raw = *self.body.read_slice(rec + off, 1)?.first()? as u32;
        Some(raw.wrapping_add(self.profile.td_iface_count_add) & 0xFF)
    }

    /// typeDef flags (TypeAttributes) — None when the profile lacks the column.
    pub fn td_flags(&self, i: usize) -> Option<u32> {
        let p = &self.profile;
        let col = p.td_flags.as_ref()?;
        let rec = self.td_base + p.td_stride as usize * i;
        let raw = self.body.read_u32(rec + col.offset as usize);
        Some(match col.kind {
            ColKind::XorC => raw ^ col.c,
            _ => raw.wrapping_add(col.c),
        })
    }

    /// typeDef bitfield (bit0 IsValueType, bit1 IsEnum) — None when absent.
    pub fn td_bitfield(&self, i: usize) -> Option<u16> {
        let p = &self.profile;
        let col = p.td_bitfield.as_ref()?;
        let rec = self.td_base + p.td_stride as usize * i;
        let raw = self.body.read_u16(rec + col.offset as usize);
        Some(raw ^ (col.c as u16))
    }

    /// typeDef parent (typearr index; u32::MAX = no base — interfaces / System.Object).
    /// Fixed-mask column: parent = raw@0x2C ^ profile.td_parent_xor. (An earlier version also
    /// xored the +0x1C tag; that only coincided with this mask on rows whose element-type
    /// column holds its sentinel, corrupting 25,981 rows.)
    pub fn td_parent(&self, i: usize) -> u32 {
        let p = &self.profile;
        let rec = self.td_base + p.td_stride as usize * i;
        self.body.read_u32(rec + p.td_parent_off as usize) ^ p.td_parent_xor
    }

    /// Interface-offsets start for typeDef `i`.
    ///
    /// The stored column is a u16; the sentinel is **all-ones after the per-version
    /// xor** (verified on 7.1: 47,110 of 88,904 records decode to 0xFFFF while real
    /// starts span 0x0000..0xBF5C). Comparing the decoded value against `u32::MAX`
    /// — as an earlier version did — is never true, which both wasted a full-table
    /// scan per type and let sentinel records into the span logic.
    #[inline]
    pub fn td_iface_start(&self, i: usize) -> Option<u32> {
        let p = &self.profile;
        let rec = self.td_base + p.td_stride as usize * i;
        let raw = self.body.read_u16(rec + p.td_iface_start_off as usize);
        let v = raw ^ p.td_iface_start_xor as u16;
        if v == u16::MAX {
            None
        } else {
            Some(v as u32)
        }
    }

    /// Interface-offsets entry `row`: (typearr idx, -1 = none, vtable offset).
    #[inline]
    pub fn iface_entry(&self, row: u32) -> (i32, i16) {
        let stride = self.profile.iface_stride as usize;
        let at = self.iface_base + stride * row as usize;
        let t = self.body.read_i32(at);
        let off = self.body.read_u16(at + 4) as i16;
        (t, off)
    }

    /// Il2CppType entry (kind@+0xA, data u32@+0, attrs u16@+8) from typearr.
    pub fn il2cpp_type(&self, idx: usize) -> Option<(u8, u32, u16)> {
        let o = self.typearr + idx * 16;
        if o + 16 > self.image.len() {
            return None;
        }
        let d = &self.image[o..o + 16];
        Some((
            d[0xA],
            u32::from_le_bytes(d[0..4].try_into().unwrap()),
            u16::from_le_bytes(d[8..10].try_into().unwrap()),
        ))
    }

    /// Il2CppType flag byte (typearr entry +0xB): bit6 = byref, bit7 = pinned.
    #[inline]
    pub fn il2cpp_type_flags(&self, idx: usize) -> Option<u8> {
        let o = self.typearr + idx * 16;
        if o + 16 > self.image.len() {
            return None;
        }
        Some(self.image[o + 0xB])
    }

    /// Map an absolute VA back to a file offset through the PE section table.
    pub fn va_to_file(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.image_base)?;
        if rva > u32::MAX as u64 {
            return None;
        }
        let rva = rva as u32;
        for &(sva, vsz, ro, rsz) in &self.sections {
            if rva >= sva && rva < sva.saturating_add(vsz.max(rsz)) {
                let rel = rva - sva;
                if rel < rsz {
                    let off = ro as usize + rel as usize;
                    if off < self.image.len() {
                        return Some(off);
                    }
                }
                return None;
            }
        }
        None
    }

    /// Read one 16-byte Il2CppType struct at a file offset: `(data u32, kind u8, flags u8)`.
    pub fn il2cpp_type_at(&self, off: usize) -> Option<(u32, u8, u8)> {
        if off + 16 > self.image.len() {
            return None;
        }
        let data = u32::from_le_bytes(self.image[off..off + 4].try_into().ok()?);
        Some((data, self.image[off + 0xA], self.image[off + 0xB]))
    }

    /// Resolve one `GENERICINST` generic-class index (`typearr` data) to
    /// `(definition typeDefIndex, argument Il2CppType file offsets)`.
    ///
    /// `startup-metadata.dat` holds 8-byte rows `{defTdi u32, genericInstIndex i32}`; the
    /// `genericInstIndex` selects a 16-byte `Il2CppGenericInst {argc, pad, Il2CppType** argv}`
    /// in the image, whose `argv` points at an array of `Il2CppType*`.
    pub fn generic_instance(&self, g: u32) -> Option<(u32, Vec<usize>)> {
        let startup = self.startup?;
        if self.gc_rows == 0 || self.generic_insts == 0 {
            return None;
        }
        let at = self.gc_rows.checked_add((g as usize).checked_mul(8)?)?;
        let row = startup.get(at..at + 8)?;
        let def_tdi = u32::from_le_bytes(row[0..4].try_into().ok()?);
        let gi = i32::from_le_bytes(row[4..8].try_into().ok()?);
        if gi < 0 {
            return None;
        }
        let gi_off = self.generic_insts.checked_add(gi as usize * 16)?;
        let b = self.image.get(gi_off..gi_off + 16)?;
        let argc = u32::from_le_bytes(b[0..4].try_into().ok()?);
        let argv_va = u64::from_le_bytes(b[8..16].try_into().ok()?);
        if argc > 64 {
            return None;
        }
        let argv_off = self.va_to_file(argv_va)?;
        let mut args = Vec::with_capacity(argc as usize);
        for a in 0..argc as usize {
            let p_off = argv_off.checked_add(a * 8)?;
            let p = u64::from_le_bytes(self.image.get(p_off..p_off + 8)?.try_into().ok()?);
            args.push(self.va_to_file(p)?);
        }
        Some((def_tdi, args))
    }

    pub fn method_rva(&self, gmi: usize) -> u32 {
        let o = self.methodptrs + gmi * 8;
        if o + 8 > self.image.len() {
            return 0;
        }
        let va = u64::from_le_bytes(self.image[o..o + 8].try_into().unwrap());
        if va > self.image_base && va < self.image_base + 0x4000_0000 {
            (va - self.image_base) as u32
        } else {
            0
        }
    }
}

fn find_header(exe: &[u8], body: &[u8], profile: &Profile) -> Option<Vec<u8>> {
    let img = crate::pe::Image::parse(exe).ok()?;
    let rd = img.section(".rdata")?;
    let start = rd.raw_pointer as usize;
    let end = (start + rd.raw_size as usize).min(exe.len());
    let region = exe.get(start..end)?;
    let mut pos = 0usize;
    while let Some(rel) = region[pos..].windows(4).position(|w| w == b"MHY\0") {
        let at = pos + rel;
        if let Some(hdr) = region.get(at..at + 0x600) {
            let raw = u32::from_le_bytes(
                hdr[profile.str_hdr_off as usize..profile.str_hdr_off as usize + 4].try_into().ok()?,
            );
            let ss = (i32::from_le_bytes(raw.to_le_bytes()).wrapping_sub(profile.str_sub as i32)) as usize;
            if ss > 0 && ss < body.len() {
                let buf = crate::mem::Buffer::new(body);
                let s = crate::decode_str::decode_str_sched(&buf, ss, 8 << 24, &profile.schedule());
                if s == "mscorlib" {
                    return Some(hdr.to_vec());
                }
            }
        }
        pos = at + 1;
    }
    None
}

fn locate_typearr(exe: &[u8], rdata: &(u64, usize, usize)) -> Option<(usize, usize)> {
    let (_, fs, sz) = *rdata;
    let rd = exe.get(fs..fs + sz)?;
    let n = rd.len() / 16;
    let mut best = (0usize, 0usize);
    let mut run = 0usize;
    let mut rs = 0usize;
    for i in 0..n {
        let k = rd[i * 16 + 0xA];
        if (1..=0x20).contains(&k) {
            if run == 0 {
                rs = i;
            }
            run += 1;
            if run > best.0 {
                best = (run, rs);
            }
        } else {
            run = 0;
        }
    }
    if best.0 < 100_000 {
        return None;
    }
    Some((fs + best.1 * 16, best.0))
}

fn locate_methodptrs(exe: &[u8], image_base: u64) -> Option<(usize, usize)> {
    let img = crate::pe::Image::parse(exe).ok()?;
    let il = img.sections().iter().find(|s| s.name == "il2cpp")?;
    let lo = image_base + il.virtual_address as u64;
    let hi = lo + il.virtual_size as u64;
    let rd = img.section(".rdata")?;
    let bytes = img.file_slice(rd.raw_pointer as u64, rd.raw_size as usize)?;
    let n = bytes.len() / 8;
    let mut best = (0usize, 0usize);
    let mut run = 0usize;
    let mut rs = 0usize;
    for i in 0..n {
        let v = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().ok()?);
        if (lo..hi).contains(&v) && v % 16 == 0 {
            if run == 0 {
                rs = i;
            }
            run += 1;
            if run > best.0 {
                best = (run, rs);
            }
        } else {
            run = 0;
        }
    }
    if best.0 < 1000 {
        return None;
    }
    Some((rd.raw_pointer as usize + best.1 * 8, best.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generic parameter table (R23): 5,796 masked 14-byte rows, real source names.
    #[test]
    #[ignore = "needs MHY_SAMPLE_EXE / MHY_SAMPLE_DAT"]
    fn generic_param_names_sample() {
        let exe = std::fs::read(std::env::var("MHY_SAMPLE_EXE").expect("MHY_SAMPLE_EXE")).unwrap();
        let dat = std::fs::read(std::env::var("MHY_SAMPLE_DAT").expect("MHY_SAMPLE_DAT")).unwrap();
        let m = Meta::load(&exe, &dat, crate::derive::layout71::gen71()).expect("load");
        assert_eq!(m.gp_count, 5_796);
        assert_eq!(m.generic_param_name(0).as_deref(), Some("T"));
        let names: Vec<String> = (0..m.gp_count as u32)
            .filter_map(|i| m.generic_param_name(i))
            .collect();
        assert!(names.iter().any(|n| n == "TKey"));
        assert!(names.iter().any(|n| n == "TValue"));
        assert!(names.iter().any(|n| n == "TRest"));
        eprintln!("generic params: {} names, {} distinct", names.len(), {
            let mut s = names.clone(); s.sort(); s.dedup(); s.len()
        });
    }
}
