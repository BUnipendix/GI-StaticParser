#!/usr/bin/env python3
"""Diagnose 6.2's method-table paramStart/paramCount columns (oracle-driven).

The method table (base 0x1CACE4, stride 26) has its name column solved
(XorCSubMask c=0x614FCEDD) but count/start columns stay seed data. From the
oracle dump we know every method's parameter count -> the expected paramStart
prefix-sum sequence -> brute-force (column offset x chain x fam x C) and
report every combination that reproduces the oracle.
"""
import json, os, re, struct, sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exprvm import ExprVM

M32 = 0xFFFFFFFF
BATTLE = '/home/yangsanyi/gire/out/zero-touch/battle'
DAT = '/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
DUMP = '/home/yangsanyi/gire/out/oracle/6.2Dump.cs'

FAMS = ['SubMaskAddC', 'AddCSubMask', 'XorCSubMask', 'XorCXorMask', 'AddCXorMask', 'AddMaskAddC']


def oracle_method_params():
    """Parameter count per method, in dump (= method-table) order."""
    pat = re.compile(r'\((.*?)\)\s*\{')
    pcs = []
    for line in open(DUMP, encoding='utf-8', errors='replace'):
        if line.startswith('\t') and '(' in line and line.rstrip().endswith('{ }'):
            m = pat.search(line)
            if not m:
                continue
            inner = m.group(1).strip()
            if not inner:
                pcs.append(0)
            else:
                # count top-level commas (generic args contain no commas here;
                # array types may: `System.Int32[] a, ...` still splits on ', ')
                depth = 0
                commas = 0
                for ch in inner:
                    if ch == '<':
                        depth += 1
                    elif ch == '>':
                        depth -= 1
                    elif ch == ',' and depth == 0:
                        commas += 1
                pcs.append(commas + 1)
    return pcs


def fam_value(fam, raw, m, C):
    if fam in (0, 1):
        return ((raw - m) + C) & M32
    if fam == 2:
        return ((raw ^ C) - m) & M32
    if fam == 3:
        return ((raw ^ C) ^ m) & M32
    if fam == 4:
        return ((raw + C) ^ m) & M32
    return (raw + m + C) & M32


def solve_C(fam, raw0, m0, v0):
    if fam in (0, 1):
        return (v0 - raw0 + m0) & M32
    if fam == 2:
        return (raw0 ^ ((v0 + m0) & M32)) & M32
    if fam == 3:
        return (raw0 ^ m0 ^ v0) & M32
    if fam == 4:
        return ((v0 ^ m0) - raw0) & M32
    return (v0 - raw0 - m0) & M32


def main():
    ROWS = 512
    dat = open(DAT, 'rb').read()
    body = dat[0x210:]
    pcs = oracle_method_params()
    print(f'oracle methods: {len(pcs)}', file=sys.stderr)
    # expected paramStart prefix sums
    v = []
    s = 0
    for pc in pcs[:ROWS]:
        v.append(s)
        s += pc
    # for the count column the expected value is the param count itself
    vcnt = pcs[:ROWS]

    auto = json.load(open(f'{BATTLE}/6.2.auto.json'))
    chains = auto['semantics']['method_defs']['chains']

    def collect_syms(e, out):
        if isinstance(e, list):
            if e and e[0] == 'sym':
                out.add(e[1])
            for x in e[1:]:
                if isinstance(x, list):
                    collect_syms(x, out)

    allsyms = set()
    for c in chains:
        collect_syms(c, allsyms)
    idx = np.arange(ROWS, dtype=np.uint64)
    symmap = {s: idx for s in allsyms}
    hdr = dat[:0x210]
    masks = []
    for ci, c in enumerate(chains):
        try:
            vm = ExprVM(body, 0, 1, ROWS, symmap, hdr)
            m = np.asarray(vm.ev(c), dtype=np.uint64) & np.uint64(M32)
            masks.append((ci, m.astype(np.uint32).tolist()))
        except Exception:
            pass
    print(f'chains evaluated: {len(masks)}/{len(chains)}', file=sys.stderr)

    BASE, STRIDE = 0x1CACE4, 26
    arr = body

    def raws(off, width):
        out = []
        for i in range(ROWS):
            if width == 4:
                out.append(struct.unpack_from('<I', arr, BASE + i * STRIDE + off)[0])
            else:
                out.append(arr[BASE + i * STRIDE + off])
        return out

    print('--- paramStart column (u32): expected v[i] = prefix sum', file=sys.stderr)
    hits = []
    for off in range(0, STRIDE - 3):
        try:
            rws = raws(off, 4)
        except struct.error:
            continue
        for ci, ml in masks:
            for fam in range(6):
                C = solve_C(fam, rws[0], ml[0], v[0])
                okc = 0
                for i in range(ROWS):
                    if fam_value(fam, rws[i], ml[i], C) == v[i]:
                        okc += 1
                if okc >= ROWS * 0.98:
                    rec = (okc, off, ci, fam, C)
                    hits.append(rec)
                    print(f'START-HIT rows={okc}/{ROWS} off={off} chain={ci} '
                          f'fam={FAMS[fam]} C={C:#x}', file=sys.stderr, flush=True)
    if not hits:
        print('no paramStart hit — trying count column instead for coverage')
    # count column (u8 at 24, u16 elsewhere)
    print('--- paramCount column (u8/u16)', file=sys.stderr)
    chits = []
    for off, width, modm in [(o, w, m) for o in range(STRIDE) for w, m in ((1, 0xFF), (2, 0xFFFF))]:
        rws = raws(off, width) if off + width <= STRIDE else None
        if not rws:
            continue
        for ci, ml in masks:
            for fam in range(6):
                C = solve_C(fam, rws[0], ml[0], vcnt[0])
                okc = 0
                for i in range(ROWS):
                    if fam_value(fam, rws[i], ml[i], C) & modm == vcnt[i]:
                        okc += 1
                if okc >= ROWS * 0.98:
                    rec = (okc, off, width, ci, fam, C)
                    chits.append(rec)
                    print(f'COUNT-HIT rows={okc}/{ROWS} off={off} w={width} chain={ci} '
                          f'fam={FAMS[fam]} C={C:#x}', file=sys.stderr, flush=True)
    print(f'start hits={len(hits)} count hits={len(chits)}')


if __name__ == '__main__':
    main()
