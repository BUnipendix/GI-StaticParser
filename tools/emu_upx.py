#!/usr/bin/env python3
"""Black-box emulation harness for the `.upx0` (VMProtect-mutated) metadata functions.

Why: the 7.1 exe keeps ~206 metadata accessor functions inside `.upx0`, where each
function is a register-saving stub followed by mutated native code. Static disassembly
shows the real operations interleaved with junk, and the game's own anti-debug never runs
because this harness never starts the process — it maps the PE image plus our reconstructed
metadata blobs into Unicorn and executes one function.

Usage (default: the flags/klass resolver at 0x14051DB00, input rcx=293):
    python3 tools/emu_upx.py [entry_hex] [rcx] [max_insns]

What it currently does:
  * maps every PE section at its preferred base (ASLR delta 0, so in-image absolute
    pointers are already correct and relocations are no-ops),
  * maps global-metadata body / startup-metadata / the reconstructed 0x210 MHY header at
    dedicated VAs and points the loader globals at them
    (0x145AD62B8 header, 0x145AD62C0 body, 0x145AD62C8 startup),
  * builds the runtime typeDef-pointer cache table (global 0x145AD62D8) pointing at real
    typeDef rows (base 0x48F3FD8, stride 0x46) so accessors take the fast path,
  * runs to the sentinel return address while logging every read inside the metadata blobs
    and the executed-instruction ring buffer (printed on fault).

Verified: the flags/klass function executes to completion and its internals match the
statically recovered formulas (hdr[0xDC]^0x5278CA3B = typeDef base, stride 0x46,
hdr[0x198]^0x5303F399 = a u32 table indexed by the same index, typeDef row +0x40 read).
"""
import struct
import sys

import numpy as np
from unicorn import (
    Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_INVALID, UC_HOOK_INTR, UC_HOOK_CODE,
)
from unicorn.x86_const import *

EXE = '/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen.exe'
DAT = '/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
STARTUP = '/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/startup-metadata.dat'

# Reconstructed embedded header VA in the image (0x210 bytes) — see docs/re/metadata-loading-flow-7.1.0.md
HDR_IN_IMAGE = 0x1427D5CB0
# Loader globals in .data (set by the real loader at startup)
G_HDR, G_BODY, G_STARTUP, G_CACHE = 0x145AD62B8, 0x145AD62C0, 0x145AD62C8, 0x145AD62D8
# 7.1 layout constants (profile)
TD_BASE, TD_STRIDE, TD_ROWS = 0x48F3FD8, 0x46, 88902


def align(x, a=0x1000):
    return (x + a - 1) // a * a


def load_sections():
    exe = open(EXE, 'rb').read()
    e = struct.unpack_from('<I', exe, 0x3C)[0]
    nsec = struct.unpack_from('<H', exe, e + 6)[0]
    optsz = struct.unpack_from('<H', exe, e + 20)[0]
    ib = struct.unpack_from('<Q', exe, e + 24 + 24)[0]
    secs = []
    for i in range(nsec):
        off = e + 24 + optsz + i * 40
        nm = exe[off:off + 8].rstrip(b'\0').decode()
        vsz, va, rsz, ro = struct.unpack_from('<IIII', exe, off + 8)
        secs.append((nm, va, vsz, ro, rsz))
    return exe, ib, secs


def main():
    entry = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x14051DB00
    arg_rcx = int(sys.argv[2], 16) if len(sys.argv) > 2 else 293
    max_insns = int(sys.argv[3]) if len(sys.argv) > 3 else 3_000_000

    exe, ib, secs = load_sections()
    dat = open(DAT, 'rb').read()
    startup = open(STARTUP, 'rb').read()
    body = dat[0x210:]

    BODY_VA, STARTUP_VA, HDR_VA = 0x300000000, 0x320000000, 0x310000000
    STACK_VA, STACK_SZ, TEB_VA, TABLE_VA = 0x200000000, 8 << 20, 0x1F0000000, 0x330000000
    SENTINEL = 0xDEADBEEF

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    for nm, va, vsz, ro, rsz in secs:
        base = ib + va
        mu.mem_map(base, align(max(vsz, rsz)), UC_PROT_ALL)
        if rsz:
            mu.mem_write(base, exe[ro:ro + rsz])

    mu.mem_map(STACK_VA, STACK_SZ)
    mu.mem_map(BODY_VA, align(len(body)))
    mu.mem_write(BODY_VA, body)
    mu.mem_map(STARTUP_VA, align(len(startup)))
    mu.mem_write(STARTUP_VA, startup)
    mu.mem_map(HDR_VA, 0x1000)
    rva = HDR_IN_IMAGE - ib
    hdr_off = None
    for nm, va, vsz, ro, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            hdr_off = ro + (rva - va)
            break
    mu.mem_write(HDR_VA, exe[hdr_off:hdr_off + 0x210])

    teb = bytearray(0x2000)
    struct.pack_into('<Q', teb, 0x30, TEB_VA)
    struct.pack_into('<Q', teb, 0x60, TEB_VA)
    mu.mem_map(TEB_VA, 0x4000)
    mu.mem_write(TEB_VA, bytes(teb))
    mu.reg_write(UC_X86_REG_GS_BASE, TEB_VA + 0x1000)
    mu.reg_write(UC_X86_REG_FS_BASE, TEB_VA + 0x2000)

    for addr, val in ((G_HDR, HDR_VA), (G_BODY, BODY_VA), (G_STARTUP, STARTUP_VA)):
        mu.mem_write(addr, struct.pack('<Q', val))

    # runtime-built cache table: typeDef index -> pointer to the row in our body image
    mu.mem_map(TABLE_VA, align(TD_ROWS * 8))
    mu.mem_write(TABLE_VA, b''.join(struct.pack('<Q', BODY_VA + TD_BASE + r * TD_STRIDE) for r in range(TD_ROWS)))
    mu.mem_write(G_CACHE, struct.pack('<Q', TABLE_VA))

    rsp = STACK_VA + STACK_SZ - 0x1000
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RBP, rsp)
    mu.mem_write(rsp, struct.pack('<Q', SENTINEL))

    reads, ring = [], []
    body_end, startup_end = BODY_VA + len(body), STARTUP_VA + len(startup)

    def on_read(uc, access, address, size, value, user):
        if BODY_VA <= address < body_end:
            reads.append(('body', address - BODY_VA, size))
        elif STARTUP_VA <= address < startup_end:
            reads.append(('startup', address - STARTUP_VA, size))

    def on_code(uc, address, size, user):
        if len(ring) >= 4096:
            ring.pop(0)
        ring.append(address)

    def on_invalid(uc, access, address, size, value, user):
        print(f'[fault] access={access} addr={address:#x} size={size} rip={uc.reg_read(UC_X86_REG_RIP):#x}')
        return False

    def on_intr(uc, intno, user):
        print(f'[intr] {intno} rip={uc.reg_read(UC_X86_REG_RIP):#x}')
        return False

    mu.hook_add(UC_HOOK_MEM_READ, on_read)
    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
    mu.hook_add(UC_HOOK_INTR, on_intr)

    mu.reg_write(UC_X86_REG_RCX, arg_rcx)
    print(f'emulating entry={entry:#x} rcx={arg_rcx:#x} max_insns={max_insns}')
    try:
        mu.emu_start(entry, SENTINEL, count=max_insns)
    except UcError as err:
        print('UC error:', err, 'rip=', hex(mu.reg_read(UC_X86_REG_RIP)))
        print('last insns:', [hex(a) for a in ring[-12:]])
    else:
        print('ret ok, last insns:', [hex(a) for a in ring[-8:]])
    print('metadata reads:', len(reads), 'unique:', len(set(reads)))
    print('  first:', reads[:16])
    print('rax =', hex(mu.reg_read(UC_X86_REG_RAX)))


if __name__ == '__main__':
    main()
