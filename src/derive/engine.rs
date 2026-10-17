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
    pub typearr: usize,
    pub typearr_len: usize,
    pub methodptrs: usize,
    pub methodptrs_len: usize,
    pub rdata: (u64, usize, usize),
    pub strsec: usize,
    pub td_base: usize,
    pub md_base: usize,
    pub fd_base: usize,
    pub param_base: usize,
    pub slot_base: usize,
    pub field_base: usize,
    pub iface_base: usize,
}

impl<'a> Meta<'a> {
    pub fn load(exe: &'a [u8], dat: &'a [u8], profile: Profile) -> Result<Self> {
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
        let rd = img.section(".rdata").ok_or_else(|| anyhow!(".rdata missing"))?;
        let rdata = (image_base + rd.virtual_address as u64, rd.raw_pointer as usize, rd.raw_size as usize);

        let (typearr, typearr_len) =
            locate_typearr(exe, &rdata).ok_or_else(|| anyhow!("typearr not located"))?;
        let (methodptrs, methodptrs_len) =
            locate_methodptrs(exe, image_base).ok_or_else(|| anyhow!("method pointers not located"))?;

        let schedule = profile.schedule();
        Ok(Self {
            schedule,
            td_base: profile.type_defs.resolve(&header_bytes),
            md_base: profile.method_defs.resolve(&header_bytes),
            fd_base: profile.fields.resolve(&header_bytes),
            param_base: profile.params.resolve(&header_bytes),
            slot_base: profile.slot_table.resolve(&header_bytes),
            field_base: profile.field_names.resolve(&header_bytes),
            iface_base: profile.iface_table.resolve(&header_bytes),
            profile,
            body,
            image: exe,
            image_base,
            typearr,
            typearr_len,
            methodptrs,
            methodptrs_len,
            rdata,
            strsec,
        })
    }

    #[inline]
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
        (self.body.size().saturating_sub(self.md_base) / self.profile.md_stride as usize)
            .min(self.methodptrs_len)
    }

    pub fn td_count(&self) -> usize {
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

    pub fn td_parent(&self, i: usize) -> u32 {
        let p = &self.profile;
        let rec = self.td_base + p.td_stride as usize * i;
        let tag = self.body.read_u32(rec + 0x1C);
        self.body.read_u32(rec + p.td_parent_off as usize) ^ tag ^ p.td_parent_xor
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
