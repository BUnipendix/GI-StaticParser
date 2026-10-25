#!/usr/bin/env python3
"""Dynamic mask-chain extraction via static emulation (unicorn).

Why this exists (R71): the 6.6 method-table chain was not reachable by any
window-based technique -- shape transfer matched a sibling function, dense
sweeps found no stride-26+chain window, and decoder call-site tracing only
covered lazy accessors. The leading hypothesis is that the chain lives in a
CALLEE of the anchor function (symwalk never follows calls) or the mask comes
from a runtime-precomputed table. Emulation follows real control flow, so it
answers both cases directly: we run the anchor's function with the real exe
mapped, the real metadata mapped, the header/body globals planted, and log

  * every executed arithmetic op with an immediate (chain steps),
  * every hdr[slot] load (anchors),
  * every read inside the metadata body (column candidates),
  * every call target (control-flow evidence).

Post-processing rebuilds expression trees from the op log (same JSON format
as symwalk) and feeds the same downstream validators. Rust port note: the
log-then-rebuild design maps 1:1 onto unicorn-engine + serde (R39).

Usage:
  emu_chain.py <exe> --metadata <dat> --blob-va 0x.. --hdr-global 0x..
      --site 0x.. [--fn-start 0x..] [--set r10=body,rax=64]
      [--max-insns 200000] [--json out.json]
"""
import argparse, json, struct, sys

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn import UC_MEM_FETCH_UNMAPPED, UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED
from unicorn.x86_const import *

from symwalk import ALIAS, name_bits, fold, expr_str, expr_syms, expr_has  # noqa: E402

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True
M64 = 0xFFFFFFFFFFFFFFFF

META_BASE = 0x40000000
SCRATCH = 0x50000000
STACK_TOP = 0x7FF100000000
CALLER_SAVED = ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11')
GPR = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'] + ['r%d' % i for i in range(8, 16)]


def pe_map(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]
    opt = pe + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    ib = struct.unpack_from('<Q', d, opt + 24)[0] if magic == 0x20b else struct.unpack_from('<I', d, opt + 28)[0]
    so = opt + struct.unpack_from('<H', d, pe + 20)[0]
    secs = []
    for i in range(n):
        o = so + i * 40
        vsz, va, rsz, roff = struct.unpack_from('<IIII', d, o + 8)
        secs.append((va, vsz, roff, min(rsz, len(d) - roff)))
    return d, ib, secs


def va2file(ib, secs, va):
    rva = va - ib
    for sva, vsz, roff, rsz in secs:
        if sva <= rva < sva + max(vsz, rsz):
            return roff + (rva - sva)
    return None


def find_fn_start(d, ib, secs, site):
    """Function start = first byte after the int3 padding run preceding it."""
    fo = va2file(ib, secs, site)
    if fo is None:
        return None
    i = fo
    while i > fo - 0x8000:
        if d[i] == 0xCC and d[i + 1] != 0xCC and i + 1 < fo:
            return ib + (secs and 0) + 0  # placeholder, fixed below
        i -= 1
    return None


def fn_start_by_padding(d, ib, secs, site):
    """Function start = first byte after the nearest preceding int3 run
    (>=2 consecutive 0xCC) inside the same section."""
    fo = va2file(ib, secs, site)
    if fo is None:
        return None
    i = fo - 1
    while i > 1 and i > fo - 0x10000:
        if d[i] == 0xCC and d[i - 1] == 0xCC:
            j = i
            while d[j] == 0xCC:
                j -= 1
            start_off = i + 1          # first non-CC after the run
            if start_off <= fo:
                return site - (fo - start_off)
            i = j
        i -= 1
    return None


class Emu:
    def __init__(self, a, seed_mode='zero'):
        self.a = a
        self.seed_mode = seed_mode
        self.d, self.ib, self.secs = pe_map(a.exe)
        self.meta = open(a.metadata, 'rb').read()
        self.body_len = len(self.meta) - 0x210
        self.stop_reason = None
        self.oplog = []       # (addr, mnemonic, dst, srcs, imm)
        self.anchors = []     # (addr, slot)
        self.col_reads = set()
        self.calls = []
        self.icount = 0
        self.tail = []
        self._insn_cache = {}
        self._reg_expr = {}
        self.chains = {}

        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.mu = mu
        lo = self.ib & ~0xFFF
        hi = self.ib + max(s[0] + s[1] for s in self.secs)
        hi = (hi + 0xFFF) & ~0xFFF
        mu.mem_map(lo, hi - lo)
        for va, vsz, roff, rsz in self.secs:
            mu.mem_write(self.ib + va, self.d[roff:roff + rsz])
        mu.mem_map(META_BASE, (len(self.meta) + 0xFFF) & ~0xFFF)
        mu.mem_write(META_BASE, self.meta)
        mu.mem_map(SCRATCH, 0x500000)
        mu.mem_map(STACK_TOP - 0x200000, 0x200000)
        # ret-forest: unknown pointer args are seeded here so chained derefs
        # land on qwords that all point at a `ret` stub -- indirect calls
        # through garbage then return immediately instead of faulting.
        self.ret_stub = SCRATCH + 0x4FF000
        mu.mem_write(self.ret_stub, b'\xc3')
        forest = SCRATCH + 0x300000
        mu.mem_write(forest, struct.pack('<Q', self.ret_stub) * (0x100000 // 8))
        self.forest = forest
        # plant the two globals: header ptr / body ptr (loadsites convention)
        mu.mem_write(a.hdr_global, struct.pack('<Q', a.blob_va))
        mu.mem_write(a.hdr_global + 8, struct.pack('<Q', META_BASE + 0x210))
        # seed registers
        vals = {'rsp': STACK_TOP - 0x10000, 'rbp': SCRATCH + 0x1000, 'rax': 64}
        for i, r in enumerate(GPR):
            if r not in vals:
                if self.seed_mode == 'forest':
                    vals[r] = forest + ((i * 0x800) & 0xFFFF8)
                else:
                    vals[r] = SCRATCH + 0x2000 + i * 0x40
        setitems = []
        for chunk in (a.set or []):
            setitems.extend(chunk.split(','))
        for kv in setitems:
            k, v = kv.split("=", 1)
            k = k.strip().lower()
            v = v.strip().lower()
            if v == 'body':
                v = META_BASE + 0x210
            elif v == 'hdr':
                v = a.blob_va
            else:
                v = int(v, 0)
            vals[k] = v
        for r, v in vals.items():
            mu.reg_write(reg_id(r), v & M64)
        self.vals = vals

        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        mu.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
        self.mu_start = None

    def insn(self, addr, size):
        if addr in self._insn_cache:
            return self._insn_cache[addr]
        fo = va2file(self.ib, self.secs, addr)
        if fo is None:
            self._insn_cache[addr] = None
            return None
        try:
            ins = next(MD.disasm(self.d[fo:fo + max(size, 15)], addr))
        except StopIteration:
            ins = None
        self._insn_cache[addr] = ins
        return ins

    # ---------------------------------------------------------------- hooks
    def hook_code(self, mu, addr, size, ud):
        self.icount += 1
        if self.icount > self.a.max_insns:
            self.stop_reason = 'insn limit'
            mu.emu_stop()
            return
        ins = self.insn(addr, size)
        if ins is None:
            return
        self.tail.append(f'{addr:x} {ins.mnemonic} {ins.op_str}')
        if len(self.tail) > 14:
            self.tail.pop(0)
        m = ins.mnemonic
        ops = ins.operands
        try:
            if m in ('mov', 'movsxd', 'movzx', 'movsx') and len(ops) == 2 \
               and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
                base = ins.reg_name(ops[1].mem.base) if ops[1].mem.base else ''
                if base:
                    bv = mu.reg_read(reg_id(ALIAS.get(base, base)))
                    if bv == self.a.blob_va:
                        disp = ops[1].mem.disp
                        if 0 <= disp < 0x210:
                            self.anchors.append((hex(addr), hex(disp)))
            if m == 'call' and ops and ops[0].type == X86_OP_IMM:
                self.calls.append(hex(ops[0].imm & M64))
                for r in CALLER_SAVED:
                    self._reg_expr.pop(r, None)
                    self._reg_expr.pop(ALIAS.get(r, r), None)
            self.track(ins, mu)
        except Exception:
            pass

    def track(self, ins, mu):
        """Symbolic mini-tracker over executed arithmetic (chain rebuild)."""
        m = ins.mnemonic
        ops = ins.operands
        def cname(x):
            n = ins.reg_name(x)
            return ALIAS.get(n, n)
        def gete(regname):
            return self._reg_expr.get(regname, ['sym', regname])
        def sete(regname, e):
            e = fold(e)
            self._reg_expr[regname] = e
            s = expr_syms(e)
            if len(s) == 1 and not expr_has(e, 'raw') and not expr_has(e, 'hdr') \
               and not any(x.startswith(('sym:mem', 'post', 'mulhi')) for x in s):
                if e[0] == 'op2' and self._has_bigmul(e):
                    self.chains.setdefault(expr_str(e), dict(addr=ins.address, expr=e))
            # also record index-derivations (mask2 = mask*K) even without big mul
        if m == 'movabs' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            self._reg_expr[cname(ops[0].reg)] = ['imm', ops[1].imm & M64]
        elif m == 'imul' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            # imul dst, src  ->  dst = dst * src (movabs+imul idiom: src holds imm64)
            dst, src = cname(ops[0].reg), cname(ops[1].reg)
            nb = name_bits(ins.reg_name(ops[0].reg))
            e = ['op2', '*', gete(dst), gete(src)]
            if nb < 64:
                e = ['lo', nb, e]
            sete(dst, e)
            self.oplog.append((hex(ins.address), m, dst, src, 'reg,reg'))
        elif m == 'imul' and len(ops) == 3 and ops[2].type == X86_OP_IMM and ops[0].type == X86_OP_REG:
            src = cname(ops[1].reg) if ops[1].type == X86_OP_REG else None
            e = ['op2', '*', gete(src) if src else ['sym', 'mem'], ['imm', ops[2].imm & M64]]
            sete(cname(ops[0].reg), e)
            self.oplog.append((hex(ins.address), m, cname(ops[0].reg), src, hex(ops[2].imm & M64)))
        elif m in ('add', 'sub', 'xor', 'and', 'or', 'shr', 'shl', 'sar') and len(ops) == 2 \
                and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            op = {'add': '+', 'sub': '-', 'xor': '^', 'and': '&', 'or': '|',
                  'shr': '>>', 'shl': '<<', 'sar': '>>'}[m]
            dst = cname(ops[0].reg)
            nb = name_bits(ins.reg_name(ops[0].reg))
            e = ['op2', op, gete(dst), ['imm', ops[1].imm & M64]]
            if nb < 64:
                e = ['lo', nb, e]
            sete(dst, e)
            self.oplog.append((hex(ins.address), m, dst, dst, hex(ops[1].imm & M64)))
        elif m in ('mov', 'movabs') and len(ops) == 2 and ops[0].type == X86_OP_REG:
            dst = cname(ops[0].reg)
            nb = name_bits(ins.reg_name(ops[0].reg))
            if ops[1].type == X86_OP_IMM:
                e = ['imm', ops[1].imm & M64]
            elif ops[1].type == X86_OP_REG:
                e = gete(cname(ops[1].reg))
            else:
                e = ['sym', 'mem']
            if nb < 64:
                e = fold(['lo', nb, e])
            self._reg_expr[dst] = fold(e)
        elif m in ('movzx', 'movsx', 'movsxd') and len(ops) == 2 \
                and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
            dst, src = cname(ops[0].reg), cname(ops[1].reg)
            nb = name_bits(ins.reg_name(ops[1].reg))
            e = gete(src)
            if m == 'movzx':
                e = fold(['lo', nb, e])
            else:
                e = fold(['ext', nb, e, True])
            self._reg_expr[dst] = e
        elif m in ('inc', 'dec') and ops and ops[0].type == X86_OP_REG:
            dst = cname(ops[0].reg)
            self._reg_expr[dst] = ['sym', dst]   # counter-ish: keep as index symbol

    @staticmethod
    def _has_bigmul(e):
        if not isinstance(e, (list, tuple)):
            return False
        if e[0] == 'op2' and e[1] == '*' and e[3][0] == 'imm' and e[3][1] > 0xFFFF:
            return True
        return any(Emu._has_bigmul(x) for x in e[1:] if isinstance(x, (list, tuple)))

    def hook_mem_invalid(self, mu, access, address, size, value, ud):
        if access & UC_MEM_FETCH_UNMAPPED:
            # indirect call/jmp through a runtime-only pointer: emulate `ret`
            # when the stack top is a plausible return address (keeps the
            # loop running past heap/vtable indirections)
            try:
                rsp = mu.reg_read(UC_X86_REG_RSP)
                ret = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
                lo = self.ib & ~0xFFF
                hi = self.ib + max(s[0] + s[1] for s in self.secs)
                if lo <= ret < hi:
                    mu.reg_write(UC_X86_REG_RSP, rsp + 8)
                    mu.reg_write(UC_X86_REG_RIP, ret)
                    self.calls.append('ret@' + hex(address))
                    return True
            except Exception:
                pass
            self.stop_reason = f'fetch unmapped @ {address:#x}'
            return False
        try:
            page = address & ~0xFFF
            mu.mem_map(page, 0x1000)
            mu.mem_write(page, b'\x00' * 0x1000)
            return True
        except Exception:
            return False

    def run(self, start):
        try:
            self.mu.emu_start(start, 0, timeout=0, count=self.a.max_insns)
        except Exception as ex:
            self.stop_reason = self.stop_reason or str(ex)
        # column reads: scan the metadata copy for touched pages is unreliable;
        # instead we re-derive from the oplog? Keep a direct mem-read hook:
        # (unicorn read hook added separately below)


def reg_id(name):
    return globals()['UC_X86_REG_' + name.upper()]


def add_read_hook(emu):
    """Log reads inside the mapped metadata body -> column candidates."""
    from unicorn import UC_HOOK_MEM_READ
    def h(mu, access, address, size, value, ud):
        if META_BASE + 0x210 <= address < META_BASE + 0x210 + emu.body_len:
            emu.col_reads.add(address - (META_BASE + 0x210))
    emu.mu.hook_add(UC_HOOK_MEM_READ, h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('exe')
    ap.add_argument('--metadata', required=True)
    ap.add_argument('--blob-va', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--hdr-global', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--site', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--fn-start', type=lambda x: int(x, 0), default=None)
    ap.add_argument('--set', action='append', default=[])
    ap.add_argument('--max-insns', type=int, default=200000)
    ap.add_argument('--json', default=None)
    a = ap.parse_args()

    d, ib, secs = pe_map(a.exe)
    start = a.fn_start or fn_start_by_padding(d, ib, secs, a.site)
    print(f'emulating from {start:#x} (site {a.site:#x}), hdr={a.blob_va:#x}, '
          f'body mapped @{META_BASE + 0x210:#x}')
    merged = None
    for mode in ('zero', 'forest'):
        emu = Emu(a, seed_mode=mode)
        add_read_hook(emu)
        emu.run(start)
        print(f'  [{mode}] {emu.icount} insns, stop={ (emu.stop_reason or "clean")[:48] }, '
              f'chains={len(emu.chains)}, anchors={len(emu.anchors)}')
        if merged is None:
            merged = emu
        else:
            merged.anchors.extend(emu.anchors)
            for k, v in emu.chains.items():
                merged.chains.setdefault(k, v)
            merged.calls.extend(emu.calls)
            merged.col_reads |= emu.col_reads
            merged.icount += emu.icount
    emu = merged
    if emu.tail:
        print('tail:')
        for t in emu.tail:
            print('   ', t)
    print(f'stopped: {emu.stop_reason or "clean"} after {emu.icount} insns; '
          f'{len(emu.anchors)} anchors, {len(emu.chains)} chains, '
          f'{len(emu.calls)} calls, {len(emu.col_reads)} body reads')
    out = dict(exe=a.exe, start=hex(start), site=hex(a.site),
               stop=emu.stop_reason, insns=emu.icount,
               anchors=emu.anchors[:40],
               chains=[dict(addr=hex(c['addr']), expr=c['expr'])
                       for c in emu.chains.values()],
               calls=emu.calls[:60],
               col_offsets=sorted(emu.col_reads)[:200])
    if a.json:
        json.dump(out, open(a.json, 'w'), indent=1)
    for c in out['chains']:
        print('  chain', expr_str(c['expr'])[:120])
    if out['anchors']:
        print('  anchors:', out['anchors'][:8])


if __name__ == '__main__':
    main()
