#!/usr/bin/env python3
"""Black-box emulation harness for the `.upx0` (VMProtect-mutated) metadata functions.

Why: part of the 7.1 exe's metadata accessors live in `.upx0`, where each function is a
register-saving stub followed by mutated native code (real operations interleaved with junk).
Static disassembly helps, but the fastest way to learn what each accessor consumes is to
execute it with a reconstructed runtime state. The game's anti-debug never runs: no process
is started — the PE image plus our reconstructed metadata blobs are mapped into Unicorn.

Library API:
    ctx = build_emulator()
    result = run_once(ctx, entry, rcx=293, max_insns=300_000)
    result = {'ok': bool, 'reads': [(region, offset, size)], 'rip': int, 'rax': int, ...}

CLI (default: the flags/klass resolver 0x14051DB00, input rcx=293):
    python3 tools/emu_upx.py [entry_hex] [rcx] [max_insns]
"""
import struct
import sys

from unicorn import (
    Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UC_HOOK_MEM_READ,
    UC_HOOK_MEM_INVALID, UC_HOOK_INTR, UC_HOOK_CODE,
)
from unicorn.x86_const import *

EXE = '/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen.exe'
DAT = '/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
STARTUP = '/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/startup-metadata.dat'

HDR_IN_IMAGE = 0x1427D5CB0          # reconstructed 0x210 MHY header inside .rdata
G_HDR, G_BODY, G_STARTUP, G_CACHE = 0x145AD62B8, 0x145AD62C0, 0x145AD62C8, 0x145AD62D8
TD_BASE, TD_STRIDE, TD_ROWS = 0x48F3FD8, 0x46, 88902

BODY_VA, STARTUP_VA, HDR_VA = 0x300000000, 0x320000000, 0x310000000
STACK_VA, STACK_SZ, TEB_VA, TABLE_VA = 0x200000000, 8 << 20, 0x1F0000000, 0x330000000
SENTINEL = 0xDEADBEEF


def align(x, a=0x1000):
    return (x + a - 1) // a * a


def _load_sections():
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


def build_emulator(fill_cache=True, lenient=False):
    exe, ib, secs = _load_sections()
    dat = open(DAT, 'rb').read()
    startup = open(STARTUP, 'rb').read()
    body = dat[0x210:]

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

    mu.mem_map(TABLE_VA, align(TD_ROWS * 8))
    if fill_cache:
        mu.mem_write(TABLE_VA, b''.join(struct.pack('<Q', BODY_VA + TD_BASE + r * TD_STRIDE) for r in range(TD_ROWS)))
    mu.mem_write(G_CACHE, struct.pack('<Q', TABLE_VA))

    ctx = {
        'mu': mu,
        'faults': [],
        'stubs': [],
        'body_len': len(body),
        'startup_len': len(startup),
        'reads': [],
        'ring': [],
    }

    def on_read(uc, access, address, size, value, user):
        if BODY_VA <= address < BODY_VA + ctx['body_len']:
            ctx['reads'].append(('body', address - BODY_VA, size))
        elif STARTUP_VA <= address < STARTUP_VA + ctx['startup_len']:
            ctx['reads'].append(('startup', address - STARTUP_VA, size))
        elif HDR_VA <= address < HDR_VA + 0x210:
            ctx['reads'].append(('header', address - HDR_VA, size))

    def on_code(uc, address, size, user):
        ring = ctx['ring']
        if len(ring) >= 4096:
            ring.pop(0)
        ring.append(address)

    def on_invalid(uc, access, address, size, value, user):
        ctx['faults'].append((uc.reg_read(UC_X86_REG_RIP), address, access))
        if not lenient:
            return False
        # Lenient discovery mode: bring up a page for the refused access and keep going.
        # Execution jumps into VMP's runtime-resolved slots (the file stores placeholders
        # that the VMP initializer patches at runtime) — stub them as `xor eax,eax; ret`.
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
        except UcError:
            return False
        if access & (UC_MEM_FETCH_UNMAPPED | UC_MEM_FETCH_PROT):
            ctx['stubs'].append(address)
            uc.mem_write(address, b'\x31\xc0\xc3')  # xor eax, eax; ret
            return True
        return True

    mu.hook_add(UC_HOOK_MEM_READ, on_read)
    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
    return ctx


def run_once(ctx, entry, rcx=0, max_insns=300_000, trace_code=False):
    mu = ctx['mu']
    ctx['reads'] = []
    ctx['ring'] = []
    ctx['faults'] = []
    ctx['stubs'] = []
    rsp = STACK_VA + STACK_SZ - 0x1000
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RBP, rsp)
    mu.reg_write(UC_X86_REG_RCX, rcx)
    for reg in (UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI,
                UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
                UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15):
        mu.reg_write(reg, 0)
    mu.mem_write(rsp, struct.pack('<Q', SENTINEL))
    err = None
    try:
        mu.emu_start(entry, SENTINEL, count=max_insns)
    except UcError as e:
        err = str(e)
    return {
        'ok': err is None,
        'faults': list(ctx['faults']),
        'stubs': list(ctx['stubs']),
        'err': err,
        'rip': mu.reg_read(UC_X86_REG_RIP),
        'rax': mu.reg_read(UC_X86_REG_RAX),
        'reads': list(ctx['reads']),
    }


def main():
    entry = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x14051DB00
    rcx = int(sys.argv[2], 16) if len(sys.argv) > 2 else 293
    max_insns = int(sys.argv[3]) if len(sys.argv) > 3 else 3_000_000
    ctx = build_emulator()
    res = run_once(ctx, entry, rcx, max_insns)
    print(f'entry={entry:#x} rcx={rcx:#x} ok={res["ok"]} err={res["err"]} rax={res["rax"]:#x} rip={res["rip"]:#x}')
    print('last insns:', [hex(a) for a in ctx['ring'][-10:]])
    reads = res['reads']
    print('metadata reads:', len(reads), 'unique:', len(set(reads)))
    print('  first:', reads[:16])


if __name__ == '__main__':
    main()
