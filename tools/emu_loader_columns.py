#!/usr/bin/env python3
"""Emulate the startup-metadata image-table decode block instead of transcribing formulas.

The MHY loader decodes each image row in the straight-line block
0x140536FE6..0x1405370BB (no calls inside): it takes the row pointer in rdi, the shared
row mask in r15d, the output struct base in r14 and i*0x58 in r13, and writes the
decoded columns into the output struct.  This tool maps the PE, writes each startup
row into scratch memory, runs that block with Unicorn, and reads the decoded fields.

Cross-check: the same fields are also computed from the formulas recovered by
disassembling the loader (tools/decode_image_table_columns.py).  Both must agree.

Usage: python3 tools/emu_loader_columns.py <YuanShen.exe> <startup-metadata.dat>
"""
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_RDI, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_EAX,
)

IB = 0x140000000
# decode block inside the image-table loader (disassembled; see log section 78)
BLOCK_START = 0x140536FE6
BLOCK_END = 0x1405370BB
ROW_VA = 0x300000000
OUT_VA = 0x300100000
GLOB_VA = 0x300200000
STACK_VA = 0x300300000
M32 = (1 << 32) - 1
M64 = (1 << 64) - 1
STRIDE = 40
ROWS = 75


def pe_sections(exe):
    pe = struct.unpack_from('<I', exe, 0x3C)[0]
    nsec = struct.unpack_from('<H', exe, pe + 6)[0]
    opt = struct.unpack_from('<H', exe, pe + 20)[0]
    out = []
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        nm = exe[o:o + 8].rstrip(b'\x00').decode(errors='replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', exe, o + 8)
        out.append((nm, va, vsz, ro, rsz))
    return pe, out


def row_mask(i):
    m = ((i * 0xBD1E70EB664) & M64) >> 16
    m = (m + 0x724F4CCB) & M32
    return m ^ 0x2BE02F3D


def formula_columns(raw):
    """Reference decode (from the disassembly, see log section 78)."""
    m = raw['mask']
    def u32(off):
        return struct.unpack_from('<I', raw['row'], off)[0]
    return {
        0x04: ((((u32(0x24) ^ 0x40B24EE6) - m) & M32) ^ 0x07B236BA),
        0x08: (((((u32(0x10) - m) & M32) + 0xD3ED43CA)) & M32),
        0x18: (((((u32(0x08) - m) & M32) + 0x96612B2C) & M32) ^ 0x7362B478),
        0x28: (((((u32(0x1C) - m) & M32) + 0xB789942C)) & M32),
        0x2C: ((((((u32(0x14) ^ 0x0F90FC6D) - m) & M32) + 0x50105F4F)) & M32),
        0x30: (((((u32(0x20) - m) & M32) + 0xD61DDDDC) & M32) ^ 0x06E0B2A6),
        0x50: ((((((u32(0x04) - m) & M32) + 0xBB4B5110) & M32) ^ 0x4FBFA07B)),
        0x0C: (((u32(0x0C) ^ 0x1066FCA3) - m) & M32),
    }


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    exe = open(sys.argv[1], 'rb').read()
    startup = open(sys.argv[2], 'rb').read()
    pe, secs = pe_sections(exe)

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    img_end = max(va + max(vsz, rsz) for _, va, vsz, _, rsz in secs)
    img_lo = IB & ~0xFFF
    img_size = (img_end + 0x1000 + 0xFFF) & ~0xFFF
    uc.mem_map(img_lo, img_size)
    for nm, va, vsz, ro, rsz in secs:
        data = exe[ro:ro + rsz]
        if data:
            uc.mem_write(IB + va, data)
    for va, size in ((ROW_VA, 0x1000), (OUT_VA, 0x10000), (GLOB_VA, 0x1000), (STACK_VA, 0x4000)):
        uc.mem_map(va, size)
    # loader-block global (only used for the pointer field we ignore)
    uc.mem_write(GLOB_VA, b'\x00' * 0x1000)

    # image table base: startup + (i32(hdr[0x84]) ^ 0x582F3633); the header lives in the
    # exe image at VA 0x1427D5CB0 for 7.1, but we do not need it: the caller passes the
    # row pointer directly, so just compute the table base from the profile constants.
    # (kept explicit above for documentation; block uses rdi only.)
    hdr_blob_va = 0x1427D5CB0
    # read the header from the mapped image to derive the table base (no hardcoded slots)
    hdr_off = None
    for nm, va, vsz, ro, rsz in secs:
        if va <= hdr_blob_va - IB < va + max(vsz, rsz):
            hdr_off = ro + (hdr_blob_va - IB - va)
            break
    hdr = exe[hdr_off:hdr_off + 0x210]
    table_off = (struct.unpack_from('<i', hdr, 0x84)[0] ^ 0x582F3633) & M32
    print(f'header blob 0x{hdr_blob_va:X} -> image table = startup + 0x{table_off:X}')

    keys = (0x04, 0x08, 0x18, 0x28, 0x2C, 0x30, 0x50)
    bad = 0
    for i in range(ROWS):
        row = startup[table_off + i * STRIDE: table_off + (i + 1) * STRIDE]
        if len(row) < STRIDE:
            print(f'row {i}: out of range')
            break
        uc.mem_write(ROW_VA, row)
        uc.mem_write(OUT_VA, b'\xCC' * 0x1000)
        uc.mem_write(GLOB_VA, b'\x00' * 0x1000)
        uc.reg_write(UC_X86_REG_RDI, ROW_VA)
        uc.reg_write(UC_X86_REG_R13, i * 0x58)
        uc.reg_write(UC_X86_REG_R14, OUT_VA)
        uc.reg_write(UC_X86_REG_R15, row_mask(i))
        uc.reg_write(UC_X86_REG_RCX, 0)
        uc.reg_write(UC_X86_REG_RDX, 0)
        uc.reg_write(UC_X86_REG_RBP, STACK_VA + 0x2000)
        uc.reg_write(UC_X86_REG_RSP, STACK_VA + 0x3000)
        uc.emu_start(BLOCK_START, BLOCK_END, count=0x400)
        emu = {k: struct.unpack_from('<I', uc.mem_read(OUT_VA + i * 0x58, 0x58), k)[0] for k in keys}
        ref = formula_columns({'mask': row_mask(i), 'row': row})
        diffs = {hex(k): (hex(emu[k]), hex(ref[k])) for k in keys if emu[k] != ref[k]}
        if diffs:
            bad += 1
            if bad <= 5:
                print(f'row {i:2d} MISMATCH {diffs}')
        if i < 3:
            print(f'row {i:2d} mask=0x{row_mask(i):08X} emu[0x04,0x08,0x18]='
                  f'{emu[0x04]:#x},{emu[0x08]:#x},{emu[0x18]:#x}')
    print(f'emulation vs formula: {ROWS - bad}/{ROWS} rows identical')
    if bad == 0:
        print('OK: the emulated loader block and the transcribed formulas agree on all columns')
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
