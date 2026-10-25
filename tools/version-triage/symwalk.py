#!/usr/bin/env python3
"""Symbolic dataflow walker over a metadata-table builder/accessor function.

Purpose (L4a of docs/re/generalize-method.md): replace the manual
"read the decompilation and copy the constants" step with a machine step.
Given one anchor site inside a function that reads a metadata row table
(the `hdr[slot] op imm` idiom located by shape_transfer / derive anchors),
this tool linearly disassembles a window, symbolically interprets the
instruction stream, and emits DATA (no version constants live in this file):

  * anchors    -- every (slot, op, imm) applied to a header-pointer load
  * chains     -- expressions that are pure functions of one unknown symbol
                  (the row index): these are the per-row mask chains and
                  their derivations (mask2 = mask1 * K ...)
  * columns    -- (column offset, load width, full expression) for every
                  row-relative load combined with constants or a chain

Row addressing is tracked with a generalized linear marker
(coeffs {sym: C}, const): the address of a row load is
    base_expr + sum(C_k * sym_k) + const
where base_expr contains a hdr node. The column offset is `const`; the
symbol whose mask chain exists is the row index and its coeff is the stride.
Acceptance is decided downstream by data validators.

Usage:
  symwalk.py <exe> --blob-va 0x.. --site 0x.. [--hdr-global 0x..]
             [--win 0x500] [--back 0x40] [--json out.json]

JSON expression nodes (interchange format for evaluators):
  ["imm", v]  ["sym", name]  ["hdr", slot, w]  ["raw", off, w]
  ["op2", op, a, b]  ["lo", n, a]  ["ext", n, a, signed]
"""
import argparse, json, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True

ALIAS = {}
_LOW8 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
for base in _LOW8 + ['r%d' % i for i in range(8, 16)]:
    ALIAS[base] = base
    if base in _LOW8:
        stem = base[1:]                      # ax, cx, ...
        ALIAS['e' + stem] = base             # eax
        ALIAS[stem] = base                   # ax
        ALIAS[{'rax': 'al', 'rcx': 'cl', 'rdx': 'dl', 'rbx': 'bl',
               'rsi': 'sil', 'rdi': 'dil', 'rsp': 'spl', 'rbp': 'bpl'}[base]] = base
        if base == 'rsi': ALIAS['si'] = base
        if base == 'rdi': ALIAS['di'] = base
        if base == 'rbp': ALIAS['bp'] = base
        if base == 'rsp': ALIAS['sp'] = base
    else:
        ALIAS[base + 'd'] = base
        ALIAS[base + 'w'] = base
        ALIAS[base + 'b'] = base
ALIAS['rip'] = 'rip'
ALIAS['eip'] = 'rip'

M64 = 0xFFFFFFFFFFFFFFFF


def name_bits(n):
    if n in ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'rip'):
        return 64
    if n.startswith('r') and n[1:].isdigit():
        return 64
    if n.startswith('r') and n[1:-1].isdigit() and n[-1] in 'dwb':
        return {'d': 32, 'w': 16, 'b': 8}[n[-1]]
    if n in ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip'):
        return 32
    if n in ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'):
        return 16
    return 8


# ------------------------------------------------------------------ expr utils
def fold(e):
    if not isinstance(e, (list, tuple)):
        return e
    t = e[0]
    if t in ('imm', 'sym', 'hdr', 'raw'):
        return list(e)
    if t == 'op2':
        op, a, b = e[1], fold(e[2]), fold(e[3])
        if a[0] == 'imm' and b[0] == 'imm':
            x, y = a[1] & M64, b[1] & M64
            if op == '+': v = (x + y) & M64
            elif op == '-': v = (x - y) & M64
            elif op == '*': v = (x * y) & M64
            elif op == '^': v = x ^ y
            elif op == '&': v = x & y
            elif op == '|': v = x | y
            elif op == '>>': v = 0 if y >= 64 else x >> y
            elif op == '<<': v = 0 if y >= 64 else (x << y) & M64
            else: v = None
            if v is not None:
                return ['imm', v]
        if op == '+' and b == ['imm', 0]: return a
        if op == '+' and a == ['imm', 0]: return b
        if op == '-' and b == ['imm', 0]: return a
        if op == '^' and b == ['imm', 0]: return a
        if op == '*' and b == ['imm', 1]: return a
        if op == '*' and b == ['imm', 0]: return ['imm', 0]
        if op == '*':
            # (x*A)*B -> x*(A*B)  [sound mod 2^64]
            for inner, other in ((a, b), (b, a)):
                if inner[0] == 'op2' and inner[1] == '*' and inner[3][0] == 'imm' and other[0] == 'imm':
                    return fold(['op2', '*', inner[2], ['imm', (inner[3][1] * other[1]) & M64]])
        if op == '-':
            # x*A - x*B -> x*(A-B)  (stride idioms: (i<<4)-i-i = 14i)
            la, lb = lin_terms(a), lin_terms(b)
            if la is not None and lb is not None and la[0] and lb[0] and \
               set(la[0]) == set(lb[0]) and len(la[0]) == 1:
                s = next(iter(la[0]))
                c = (la[0][s] - lb[0][s]) & M64
                if c != 0:
                    e2 = ['op2', '*', ['sym', s], ['imm', c]] if c != 1 else ['sym', s]
                    return fold(['op2', '+', e2, ['imm', (la[1] - lb[1]) & M64]])
        if op == '+':
            # x*A + x*B -> x*(A+B)  [distributive, sound mod 2^64]
            # (only when BOTH sides carry terms of the same single sym --
            #  otherwise this branch rebuilds its own input and recurses forever)
            la, lb = lin_terms(a), lin_terms(b)
            if la is not None and lb is not None and la[0] and lb[0] and \
               set(la[0]) == set(lb[0]) and len(la[0]) == 1:
                s = next(iter(la[0]))
                c = (la[0][s] + lb[0][s]) & M64
                if c != 0:
                    e2 = ['op2', '*', ['sym', s], ['imm', c]] if c != 1 else ['sym', s]
                    return fold(['op2', '+', e2, ['imm', (la[1] + lb[1]) & M64]])
            # const gather (x*A + C1) + C2
            if a[0] == 'op2' and a[1] == '+' and a[3][0] == 'imm' and b[0] == 'imm':
                return fold(['op2', '+', a[2], ['imm', (a[3][1] + b[1]) & M64]])
            if b[0] == 'op2' and b[1] == '+' and b[3][0] == 'imm' and a[0] == 'imm':
                return fold(['op2', '+', b[2], ['imm', (b[3][1] + a[1]) & M64]])
        return ['op2', op, a, b]
    if t == 'lo':
        n, a = e[1], fold(e[2])
        if a[0] == 'imm':
            return ['imm', a[1] & ((1 << n) - 1)]
        if n >= 64:
            return a
        if a[0] == 'raw' and a[2] == n:
            return a
        if a[0] == 'lo':            # lo_n(lo_m(x)) -> lo_min(n,m)(x)
            return fold(['lo', min(n, a[1]), a[2]])
        if a[0] == 'ext' and a[1] <= n:
            return fold(['lo', n, a[2]])
        return ['lo', n, a]
    if t == 'ext':
        n, a, s = e[1], fold(e[2]), e[3]
        if a[0] == 'imm':
            v = a[1] & ((1 << n) - 1)
            if s and n < 64 and (v >> (n - 1)) & 1:
                v = (v | (M64 << n)) & M64
            return ['imm', v]
        if n >= 64:
            return a
        return ['ext', n, a, s]
    return list(e)


def lin_terms(e):
    """Decompose a purely linear expr over syms: ({sym: coeff}, const).
    Returns None if non-linear (^ & | >> << raw hdr op with unknown side)."""
    if e[0] == 'imm':
        return ({}, e[1] & M64)
    if e[0] == 'sym':
        return ({e[1]: 1}, 0)
    if e[0] == 'op2':
        op = e[1]
        if op == '+':
            a, b = lin_terms(e[2]), lin_terms(e[3])
            if a is None or b is None: return None
            c = dict(a[0])
            for k, v in b[0].items(): c[k] = (c.get(k, 0) + v) & M64
            return (c, (a[1] + b[1]) & M64)
        if op == '-':
            a, b = lin_terms(e[2]), lin_terms(e[3])
            if a is None or b is None: return None
            c = dict(a[0])
            for k, v in b[0].items(): c[k] = (c.get(k, 0) - v) & M64
            return (c, (a[1] - b[1]) & M64)
        if op == '*':
            a, b = lin_terms(e[2]), lin_terms(e[3])
            if a is None or b is None: return None
            if not a[0]:  # const * linear
                k = a[1] & M64
                return ({s: (v * k) & M64 for s, v in b[0].items()}, (b[1] * k) & M64)
            if not b[0]:
                k = b[1] & M64
                return ({s: (v * k) & M64 for s, v in a[0].items()}, (a[1] * k) & M64)
            return None
        if op == '<<':  # x << k  == x * 2^k for linear x (stride idioms)
            a = lin_terms(e[2])
            if a is None or e[3][0] != 'imm':
                return None
            k = (1 << (e[3][1] & 63)) & M64
            return ({s: (v * k) & M64 for s, v in a[0].items()}, (a[1] * k) & M64)
    return None


def expr_syms(e):
    if not isinstance(e, (list, tuple)): return set()
    if e[0] == 'sym': return {e[1]}
    if e[0] in ('imm', 'hdr', 'raw'): return set()
    out = set()
    for x in e[1:]:
        if isinstance(x, (list, tuple)): out |= expr_syms(x)
    return out


def expr_has(e, kind):
    if not isinstance(e, (list, tuple)): return False
    if e[0] == kind: return True
    for x in e[1:]:
        if isinstance(x, (list, tuple)) and expr_has(x, kind):
            return True
    return False


def expr_size(e):
    if not isinstance(e, (list, tuple)): return 1
    return 1 + sum(expr_size(x) for x in e[1:] if isinstance(x, (list, tuple)))


def expr_str(e):
    if not isinstance(e, (list, tuple)): return str(e)
    if e[0] == 'imm': return hex(e[1] & M64)
    if e[0] == 'sym': return e[1]
    if e[0] == 'hdr': return f'hdr[{e[1]:#x}]'
    if e[0] == 'raw': return f'raw{e[2]}@{e[1]:#x}'
    if e[0] == 'op2': return f'({expr_str(e[2])} {e[1]} {expr_str(e[3])})'
    if e[0] == 'lo': return f'lo{e[1]}({expr_str(e[2])})'
    if e[0] == 'ext': return f'{"s" if e[3] else "z"}ext{e[1]}({expr_str(e[2])})'
    return str(e)


def _unwrap_hdr(e):
    while e[0] in ('ext', 'lo'):
        e = e[2]
    return e[1] if e[0] == 'hdr' else None


# ------------------------------------------------------------------------- PE
_PE_CACHE = {}


def pe_map(path):
    """Parse a PE once per path; the module bytes are SHARED (never copied
    per Walker instance -- 100+ walkers over a 450MB exe must not OOM)."""
    if path in _PE_CACHE:
        return _PE_CACHE[path]
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
    if len(_PE_CACHE) >= 3:
        _PE_CACHE.clear()
    _PE_CACHE[path] = (d, ib, secs)
    return _PE_CACHE[path]


def va2file(ib, secs, va):
    rva = va - ib
    for sva, vsz, roff, rsz in secs:
        if sva <= rva < sva + max(vsz, rsz):
            return roff + (rva - sva)
    return None


class Val:
    """expr + optional row marker (coeffs {sym:C}, const) meaning
    this value = <expr> addresses base + sum(C*sym) + const, base has hdr."""
    __slots__ = ('e', 'row')

    def __init__(self, e, row=None):
        self.e = e
        self.row = row


class Walker:
    CALLER_SAVED = {'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'}

    def __init__(self, exe, blob_va, hdr_global=None):
        self.d, self.ib, self.secs = pe_map(exe)
        self.blob_va = blob_va
        self.hdr_global = hdr_global
        fo = va2file(self.ib, self.secs, blob_va)
        self.hdr_copy = self.d[fo:fo + 0x210] if fo else b''
        self.reset()

    def reset(self):
        self.regs = {}
        self.stack = {}
        self.hdr_ptrs = set()
        self.anchors = []
        self.chains = {}
        self.columns = {}
        self.calls = []
        self.stores = []
        self.push_depth = 0
        self.sym_last = {}   # canon -> last pure-index-chain expr assigned

    # -- state helpers ----------------------------------------------------
    def get(self, canon):
        canon = ALIAS.get(canon, canon)
        v = self.regs.get(canon)
        if v is None:
            v = Val(['sym', canon])
            self.regs[canon] = v
        return v

    def get_named(self, name):
        canon = ALIAS.get(name, name)
        v = self.get(canon)
        nb = name_bits(name)
        if nb < 64:
            return Val(fold(['lo', nb, v.e]))
        return v

    def set(self, canon, val):
        canon = ALIAS.get(canon, canon)
        self.regs[canon] = val
        # remember the latest chain-like (pure function of one unknown) value
        # each register held, so bare-symbol uses in column formulas can be
        # back-substituted after the walk
        e = val.e
        s = expr_syms(e)
        if len(s) == 1 and not expr_has(e, 'raw') and not expr_has(e, 'hdr') \
           and expr_size(e) >= 3 and 'mem' not in s and 'post_call' not in s \
           and not any(x.startswith(('glob@', 'mulhi@', 'ripdata')) for x in s):
            self.sym_last[canon] = e

    def record_chain(self, addr, canon, e):
        s = expr_syms(e)
        if len(s) == 1 and expr_size(e) >= 3 and not expr_has(e, 'raw') and not expr_has(e, 'hdr'):
            self.chains.setdefault(expr_str(e), dict(addr=hex(addr), reg=canon, expr=e))

    def record_column(self, addr, canon, e, sink=None):
        if not expr_has(e, 'raw'):
            return
        raws = list(iter_kind(e, 'raw'))
        if len(raws) > 2 or raws[0][1] >= 0x100:
            return
        k = expr_str(e)
        rec = self.columns.get(k)
        if rec is None:
            self.columns[k] = dict(off=raws[0][1], width=raws[0][2] // 8, expr=e,
                                   addr=hex(addr), reg=canon, sink=sink)
        elif sink and not rec.get('sink'):
            rec['sink'] = sink

    def substitute(self, e, depth=0):
        """Replace bare syms by their last recorded chain value (1 level)."""
        if depth > 2 or not isinstance(e, (list, tuple)):
            return e
        if e[0] == 'sym':
            name = ALIAS.get(e[1], e[1])
            if name in self.sym_last:
                return self.sym_last[name]
            return e
        out = [e[0]]
        for x in e[1:]:
            out.append(self.substitute(x, depth + 1) if isinstance(x, (list, tuple)) else x)
        return out

    def finalize(self):
        """Back-substitute dangling register syms in column formulas."""
        for k in list(self.columns.keys()):
            rec = self.columns[k]
            e2 = fold(self.substitute(rec['expr']))
            if expr_str(e2) != k:
                self.columns.pop(k)
                raws = list(iter_kind(e2, 'raw'))
                if raws and len(raws) <= 2 and raws[0][1] < 0x100:
                    self.columns[expr_str(e2)] = dict(off=raws[0][1], width=raws[0][2] // 8,
                                                      expr=e2, addr=rec['addr'],
                                                      reg=rec['reg'], sink=rec.get('sink'))

    # -- row marker ---------------------------------------------------------
    def try_row(self, a, b, sign=1):
        """a ± b: if one side carries a row marker (or contains hdr) and the
        other side is linear-over-syms, produce a marker-merged Val."""
        # existing marker + linear addend
        for x, y in ((a, b), (b, a)):
            if x.row is not None:
                ly = lin_terms(y.e)
                if ly is not None:
                    coeffs = dict(x.row[0])
                    for s, c in ly[0].items():
                        coeffs[s] = (coeffs.get(s, 0) + sign * c) & M64
                    const = (x.row[1] + sign * ly[1]) & M64
                    op = '+' if sign > 0 else '-'
                    nv = Val(fold(['op2', op, x.e, y.e]), (coeffs, const))
                    return nv
        # base (hdr) + linear-with-syms -> new marker
        for x, y in ((a, b), (b, a)):
            if expr_has(x.e, 'hdr') and not expr_has(x.e, 'raw'):
                ly = lin_terms(y.e)
                lx = lin_terms(x.e)
                if ly is not None and ly[0] and lx is not None:
                    coeffs = dict(lx[0])
                    for s, c in ly[0].items():
                        coeffs[s] = (coeffs.get(s, 0) + sign * c) & M64
                    if not coeffs:
                        continue
                    const = (lx[1] + sign * ly[1]) & M64
                    nv = Val(fold(['op2', '+', x.e, y.e]) if sign > 0 else fold(['op2', '-', x.e, y.e]),
                             (coeffs, const))
                    return nv
                elif ly is not None and ly[0]:
                    # base is non-linear (hdr^imm etc): take addend coeffs only
                    coeffs = {s: (sign * c) & M64 for s, c in ly[0].items()}
                    const = (sign * ly[1]) & M64
                    nv = Val(fold(['op2', '+', x.e, y.e]) if sign > 0 else fold(['op2', '-', x.e, y.e]),
                             (coeffs, const))
                    return nv
        return None

    # -- memory -------------------------------------------------------------
    def mem_val(self, op, ins):
        m = op.mem
        acc = None
        if m.base:
            bname = ALIAS.get(ins.reg_name(m.base), '')
            acc = self.get(bname)
        if m.index:
            iname = ALIAS.get(ins.reg_name(m.index), '')
            iv = self.get(iname)
            scaled = Val(fold(['op2', '*', iv.e, ['imm', m.scale & M64]]))
            acc = scaled if acc is None else self.try_row(acc, scaled) or Val(fold(['op2', '+', acc.e, scaled.e]))
        disp = Val(['imm', m.disp & M64])
        if acc is None:
            return disp
        return self.try_row(acc, disp) or Val(fold(['op2', '+', acc.e, disp.e]), acc.row)

    def mem_val_rip(self, o, ins):
        if o.type != X86_OP_MEM:
            return None
        base_name = ins.reg_name(o.mem.base) if o.mem.base else ''
        if base_name == 'rip':
            tgt = ins.address + ins.size + o.mem.disp
            fo = va2file(self.ib, self.secs, tgt)
            if fo is None:
                return Val(['sym', 'ripdata'])
            if o.size == 8:
                q = struct.unpack_from('<Q', self.d, fo)[0]
                if (self.hdr_global is not None and q == self.hdr_global) or q == self.blob_va:
                    return Val(['sym', 'HDRPTR'])
                return Val(['sym', f'glob@{tgt:x}={q:x}'])
            return Val(['imm', int.from_bytes(self.d[fo:fo + o.size], 'little')])
        return None

    def read_mem(self, addr_val, width, signed, addr):
        e = addr_val.e
        slot = self.hdr_slot_in(e)
        if slot is not None:
            v = ['hdr', slot, 4]
            if signed and width < 8:
                v = fold(['ext', width * 8, v, True])
            return Val(v)
        if addr_val.row is not None:
            raw = ['raw', addr_val.row[1] & 0xFF, width * 8] if width <= 2 else \
                  ['raw', addr_val.row[1] & 0xFFFFFFFF, width * 8]
            if signed and width < 8:
                raw = fold(['ext', width * 8, raw, True])
            return Val(raw)
        return None

    def hdr_slot_in(self, e):
        if e[0] == 'sym' and (e[1] in self.hdr_ptrs or e[1] == 'HDRPTR'):
            return 0
        if e[0] == 'op2' and e[1] == '+':
            a, b = e[2], e[3]
            for x, y in ((a, b), (b, a)):
                if x[0] == 'sym' and (x[1] in self.hdr_ptrs or x[1] == 'HDRPTR') and y[0] == 'imm' and y[1] < 0x210:
                    self.hdr_ptrs.add(x[1])
                    return y[1]
            # lazy promotion: lone non-stack sym + small disp
            for x, y in ((a, b), (b, a)):
                if x[0] == 'sym' and x[1] != 'rsp' and not x[1].startswith('post_call') \
                   and y[0] == 'imm' and y[1] < 0x210 and y[1] % 4 == 0:
                    self.hdr_ptrs.add(x[1])
                    return y[1]
        if e[0] == 'sym' and e[1] != 'rsp' and not e[1].startswith('post_call'):
            # [reg] with no disp -- cannot be a slot read; skip
            return None
        return None

    # -- interpreter ----------------------------------------------------------
    def step(self, ins):
        m = ins.mnemonic
        ops = ins.operands
        addr = ins.address

        def rn(i):
            return ALIAS.get(ins.reg_name(ops[i].reg), '')

        def rm_val(i):
            o = ops[i]
            if o.type == X86_OP_REG:
                return self.get_named(ins.reg_name(o.reg))
            if o.type == X86_OP_IMM:
                return Val(['imm', o.imm & M64])
            av = self.mem_val_rip(o, ins)
            if av is not None:
                return av
            av = self.mem_val(o, ins)
            v = self.read_mem(av, o.size, False, addr)
            if v is not None:
                return v
            if av.e[0] == 'op2' and av.e[1] == '+' and av.e[2][0] == 'sym' and av.e[2][1] == 'rsp' and av.e[3][0] == 'imm':
                sv = self.stack.get(av.e[3][1])
                if sv is not None and o.size == 8:
                    return sv
            return Val(['sym', 'mem'])

        def write(i, val):
            o = ops[i]
            if o.type == X86_OP_MEM:
                av = self.mem_val_rip(o, ins)
                if av is None:
                    av = self.mem_val(o, ins)
                if av.e[0] == 'op2' and av.e[1] == '+' and av.e[2][0] == 'sym' and av.e[2][1] == 'rsp' and av.e[3][0] == 'imm':
                    self.stack[av.e[3][1]] = val
                else:
                    self.stores.append(dict(addr=hex(addr), val=expr_str(val.e), row=bool(av.row)))
                return
            if o.type != X86_OP_REG:
                return
            name = ins.reg_name(o.reg)
            canon = ALIAS.get(name, name)
            nb = name_bits(name)
            e = val.e
            if nb < 64:
                e = fold(['lo', nb, e])
            nv = Val(e)
            self.set(canon, nv)
            if expr_has(e, 'raw'):
                self.record_column(addr, canon, e)
            else:
                self.record_chain(addr, canon, e)

        if m in ('mov', 'movabs'):
            if ops[1].type == X86_OP_IMM:
                write(0, Val(['imm', ops[1].imm & M64]))
            elif ops[1].type == X86_OP_REG:
                write(0, Val(self.get_named(ins.reg_name(ops[1].reg)).e))
            else:
                write(0, rm_val(1))
        elif m == 'movzx':
            srcbits = ops[1].size * 8
            v = rm_val(1)
            if v is not None:
                write(0, Val(fold(['lo', srcbits, v.e])))
        elif m in ('movsx', 'movsxd'):
            srcbits = ops[1].size * 8
            v = rm_val(1)
            if v is not None:
                write(0, Val(fold(['ext', srcbits, v.e, True])))
        elif m == 'lea':
            o = ops[1]
            av = self.mem_val_rip(o, ins) or self.mem_val(o, ins)
            write(0, av)
        elif m in ('add', 'sub', 'xor', 'and', 'or', 'shl', 'shr', 'sar'):
            opmap = {'add': '+', 'sub': '-', 'xor': '^', 'and': '&', 'or': '|',
                     'shl': '<<', 'shr': '>>', 'sar': '>>'}
            sign = 1 if m == 'add' else (-1 if m == 'sub' else 0)
            dname = ins.reg_name(ops[0].reg)
            dw = name_bits(dname)
            a = self.get_named(dname)
            if ops[1].type == X86_OP_IMM:
                b = Val(['imm', ops[1].imm & M64])
            else:
                b = rm_val(1)
            if m in ('add', 'sub') and ops[0].type == X86_OP_REG:
                mk = self.try_row(a, b, sign if m == 'add' else 1) if m == 'add' else self.try_row(a, b, -1)
                if mk is not None:
                    if dw < 64:
                        mk = Val(fold(['lo', dw, mk.e]))
                    self.set(ALIAS.get(dname, dname), mk)
                    self.record_chain(addr, ALIAS.get(dname, dname), mk.e)
                    return
            self.apply_op2(addr, ALIAS.get(dname, dname), a, opmap[m], b, dw)
        elif m == 'imul':
            if len(ops) >= 2:
                dst = ins.reg_name(ops[0].reg)
                dw = name_bits(dst)
                a = rm_val(1)
                if len(ops) == 3 and ops[2].type == X86_OP_IMM:
                    b = Val(['imm', ops[2].imm & M64])
                else:
                    b = rm_val(2) if len(ops) == 3 else self.get_named(dst)
                self.apply_op2(addr, ALIAS.get(dst, dst), a, '*', b, dw)
        elif m == 'mul':
            a = self.get('rax')
            b = rm_val(1)
            prod = fold(['op2', '*', a.e, b.e])
            self.set('rax', Val(prod))
            self.set('rdx', Val(['sym', 'mulhi@' + hex(addr)]))
        elif m == 'neg':
            a = self.get_named(ins.reg_name(ops[0].reg))
            self.apply_op2(addr, ALIAS.get(ins.reg_name(ops[0].reg), ''), Val(['imm', 0]), '-', a,
                           name_bits(ins.reg_name(ops[0].reg)))
        elif m == 'not':
            a = self.get_named(ins.reg_name(ops[0].reg))
            self.apply_op2(addr, ALIAS.get(ins.reg_name(ops[0].reg), ''), a, '^', Val(['imm', M64]),
                           name_bits(ins.reg_name(ops[0].reg)))
        elif m == 'cdqe':
            a = self.get('rax')
            self.set('rax', Val(fold(['ext', 32, a.e, True])))
        elif m == 'push':
            self.push_depth += 1
            if ops and ops[0].type == X86_OP_REG:
                self.stack[('push', self.push_depth)] = self.get_named(ins.reg_name(ops[0].reg))
        elif m == 'pop':
            v = self.stack.pop(('push', self.push_depth), None)
            self.push_depth = max(0, self.push_depth - 1)
            if v is not None and ops and ops[0].type == X86_OP_REG:
                write(0, v)
        elif m == 'call':
            tgt = None
            if ops and ops[0].type == X86_OP_IMM:
                tgt = hex(ops[0].imm & M64)
            args = []
            for r in ('rcx', 'rdx', 'r8', 'r9'):
                v = self.regs.get(r)
                args.append(expr_str(v.e) if v is not None else None)
                if v is not None and expr_has(v.e, 'raw'):
                    self.record_column(addr, r, v.e, sink='call:' + str(tgt))
                    self.record_chain(addr, r, v.e)
            self.calls.append(dict(addr=hex(addr), target=tgt, args=args))
            for r in self.CALLER_SAVED:
                self.set(r, Val(['sym', 'post_call']))

    def apply_op2(self, addr, canon, a, op, b, width=64):
        ha = _unwrap_hdr(a.e)
        if ha is not None and b.e[0] == 'imm' and op in ('+', '^', '-'):
            slot = ha
            resolved = None
            if self.hdr_copy and slot + 4 <= len(self.hdr_copy):
                raw = struct.unpack_from('<I', self.hdr_copy, slot)[0]
                resolved = (raw + b.e[1]) & M64 if op == '+' else ((raw ^ b.e[1]) if op == '^' else (raw - b.e[1]) & M64)
            self.anchors.append(dict(slot=hex(slot), op=op, imm=hex(b.e[1]),
                                     addr=hex(addr), resolved=hex(resolved) if resolved is not None else None))
        e = fold(['op2', op, a.e, b.e])
        if width < 64:
            e = fold(['lo', width, e])
        self.set(canon, Val(e))
        if expr_has(e, 'raw'):
            self.record_column(addr, canon, e)
        else:
            self.record_chain(addr, canon, e)


def iter_kind(e, kind):
    if not isinstance(e, (list, tuple)):
        return
    if e[0] == kind:
        yield e
    for x in e[1:]:
        if isinstance(x, (list, tuple)):
            yield from iter_kind(x, kind)


def walk_window(walker, start, win):
    code_start = va2file(walker.ib, walker.secs, start)
    if code_start is None:
        return 0
    code = walker.d[code_start:code_start + win]
    n = 0
    for ins in MD.disasm(code, start):
        if ins.mnemonic == 'int3':
            break
        try:
            walker.step(ins)
        except Exception:
            pass
        n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('exe')
    ap.add_argument('--blob-va', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--hdr-global', type=lambda x: int(x, 0), default=None)
    ap.add_argument('--site', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--win', type=lambda x: int(x, 0), default=0x500)
    ap.add_argument('--back', type=lambda x: int(x, 0), default=0x90)
    ap.add_argument('--json', default=None)
    a = ap.parse_args()

    walks = []
    for back in range(0, a.back + 1):
        w = Walker(a.exe, a.blob_va, a.hdr_global)
        n = walk_window(w, a.site - back, a.win)
        if n >= 8:
            walks.append(w)
    if not walks:
        print(json.dumps({'error': 'no walkable window'}))
        sys.exit(1)

    def has_big_mul(e):
        if not isinstance(e, (list, tuple)):
            return False
        if e[0] == 'op2' and e[1] == '*' and e[3][0] == 'imm' and e[3][1] > 0xFFFF:
            return True
        return any(has_big_mul(x) for x in e[1:] if isinstance(x, (list, tuple)))

    def quality(w):
        good = 0
        for an in w.anchors:
            r = an.get('resolved')
            if r is not None and (int(r, 16) & 0xFFFFFFFF) < (1 << 26):
                good += 1
        big = sum(1 for c in w.chains.values() if has_big_mul(c['expr']))
        return 2 * len(w.columns) + good + 2 * big

    walks.sort(key=quality, reverse=True)
    chosen = [w for w in walks[:3] if quality(w) > 0]
    if not chosen:  # nothing scored: fall back to any non-empty walk
        chosen = [w for w in walks if (w.anchors or w.columns or w.chains)][:3]
    m = Walker(a.exe, a.blob_va, a.hdr_global)
    for w in chosen:
        m.anchors.extend(w.anchors)
        for k, v in w.chains.items():
            m.chains.setdefault(k, v)
        for k, v in w.columns.items():
            if k not in m.columns or (v.get('sink') and not m.columns[k].get('sink')):
                m.columns[k] = v
        m.calls.extend(w.calls)
        m.sym_last.update({k: v for k, v in w.sym_last.items() if k not in m.sym_last})
    # dedupe anchors by (slot, op, imm, addr)
    seen = set()
    m.anchors = [an for an in m.anchors
                 if not (an['slot'], an['op'], an['imm'], an['addr']) in seen
                 and not seen.add((an['slot'], an['op'], an['imm'], an['addr']))]
    w = m
    back = len(chosen)
    w.finalize()
    cols = sorted(w.columns.values(), key=lambda c: int(c['addr'], 16))
    chains = sorted(w.chains.values(), key=lambda c: -expr_size(c['expr']))[:60]
    out = dict(exe=a.exe, site=hex(a.site), back=back,
               anchors=w.anchors, chains=chains, columns=cols,
               calls=w.calls[:80])
    if a.json:
        json.dump(out, open(a.json, 'w'), indent=1)
    print(f'site {a.site:#x} back {back}: {len(w.anchors)} anchors, '
          f'{len(chains)} chains, {len(cols)} column candidates')
    for c in cols:
        print(f"  col@{c['addr']} off {c['off']:#x} w{c['width']} {expr_str(c['expr'])[:110]}"
              + (f'  -> {c["sink"]}' if c.get('sink') else ''))
    for ch in chains[:14]:
        print(f"  chain {expr_str(ch['expr'])[:110]}")


if __name__ == '__main__':
    main()
