#!/usr/bin/env python3
"""6.2 param-table differential diagnosis (C-free column location).

The param name column did not solve via the anchor sweep (R88). This script
applies the differential-invariant locator to the param chain pool:
  - prior_param_names.json (48 corelib names, table order) -> packed candidates
  - param_defs transfer chains -> mask[i]
  - six families' row-difference patterns (C-free) scanned over the whole body
Reports every (col_pos, chain, fam, C) reproducing the prior names. Zero hits
means the transfer pool lacks the true chain (extraction-layer gap).
"""
import json, os, struct, sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exprvm import ExprVM

M32 = 0xFFFFFFFF
BATTLE = '/home/yangsanyi/gire/out/zero-touch/battle'
DAT = '/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
REPO = '/home/yangsanyi/Documents/git-repo/GI-StaticParser'

FAMS = ['SubMaskAddC', 'AddCSubMask', 'XorCSubMask', 'XorCXorMask', 'AddCXorMask', 'AddMaskAddC']


def fam_diff(fam, v1, v0, m1, m0):
    """raw[i+1] op raw[i] pattern, C-free."""
    if fam in (0, 1, 5):  # linear: raw1 - raw0 = (v1-v0) ± (m1-m0)
        d = (v1 - v0) & M32
        dm = (m1 - m0) & M32
        return (d + dm) & M32 if fam != 5 else (d - dm) & M32
    if fam == 2:  # XorCSubMask: raw = (v+m) ^ C -> raw1^raw0 = (v1+m1)^(v0+m0)
        return ((v1 + m1) & M32) ^ ((v0 + m0) & M32)
    if fam == 3:  # XorCXorMask: raw = (v^m)^C -> raw1^raw0 = (v1^m1)^(v0^m0)
        return (v1 ^ m1) ^ (v0 ^ m0)
    # AddCXorMask: raw = (v+C)^m -> raw1^raw0 = (v1^m1)^(v0^m0)  (same as 3!)
    return (v1 ^ m1) ^ (v0 ^ m0)


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


def main():
    rows_known = 48
    dat = open(DAT, 'rb').read()
    body = dat[0x210:]
    prior = json.load(open(f'{REPO}/assets/prior_param_names.json'))
    print(f'prior param names: {len(prior)}: {prior[:8]}', file=sys.stderr)

    heap = {}
    for line in open(f'{BATTLE}/6.2.strings.txt', encoding='utf-8', errors='replace'):
        off_s, _, txt = line.rstrip('\n').partition('\t')
        heap.setdefault(txt, []).append(int(off_s, 16))

    # packed candidates per prior row
    cands = []
    for nm in prior[:rows_known]:
        h = heap.get(nm, [])[:3]
        cands.append([((len(nm) << 24) | o) & M32 for o in h])
    known = [i for i in range(rows_known) if cands[i]]
    print(f'prior rows with heap candidates: {len(known)}/{rows_known}', file=sys.stderr)
    for i in range(min(12, rows_known)):
        print(f'  row{i:2d} {prior[i]!r:20s} cands={cands[i]}', file=sys.stderr)
    # consecutive known pairs
    pairs = [(i, i + 1) for i in range(rows_known - 1) if cands[i] and cands[i + 1]]
    print(f'consecutive known pairs: {len(pairs)}: {pairs[:6]}', file=sys.stderr)
    if not pairs:
        print('FATAL: no consecutive known pair — differential cannot anchor')
        return

    if len(sys.argv) > 1 and sys.argv[1] == '--chains':
        # chain_hunt pool: [{"expr": [...], "site": "...", "imm": "..."}]
        chains = [it['expr'] for it in json.load(open(sys.argv[2]))]
    else:
        auto = json.load(open(f'{BATTLE}/6.2.auto.json'))
        chains = auto['semantics']['param_defs']['chains']
    N = rows_known + 8

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
    idx = np.arange(N, dtype=np.uint64)
    symmap = {s: idx for s in allsyms}
    masks = []
    for ci, c in enumerate(chains):
        try:
            vm = ExprVM(body, 0, 1, N, symmap, dat[:0x210])
            m = np.asarray(vm.ev(c), dtype=np.uint64) & np.uint64(M32)
            masks.append((ci, m.astype(np.uint32).tolist()))
        except Exception:
            pass
    print(f'chains evaluated: {len(masks)}/{len(chains)}', file=sys.stderr)

    U = np.frombuffer(body, dtype='<u4')
    STRIDE = 8
    ST = STRIDE // 4
    addD = (U[ST:].astype(np.int64) - U[:-ST].astype(np.int64)) % (1 << 32)
    xorD = U[ST:] ^ U[:-ST]

    found = []
    for ci, ml in masks:
        for fam in range(6):
            arr = xorD if fam in (2, 3, 4) else addD
            for (r0, r1) in pairs[:2]:
                for v0 in cands[r0][:2]:
                    for v1 in cands[r1][:2]:
                        p0 = fam_diff(fam, v1, v0, ml[r1], ml[r0])
                        js = np.nonzero(arr == p0)[0]
                        for j in js.tolist():
                            col_pos = j * 4
                            C = solve_C(fam, int(U[j]), ml[r0], v0)
                            hits = 0
                            for r in known:
                                if r >= N:
                                    break
                                w = j + ST * r
                                if w >= len(U):
                                    break
                                v = fam_value(fam, int(U[w]), ml[r], C)
                                if v in cands[r]:
                                    hits += 1
                            if hits >= 6:
                                rec = (hits, col_pos, ci, fam, C)
                                found.append(rec)
                                print(f'HIT hits={hits} col={col_pos:#x} chain={ci} '
                                      f'fam={FAMS[fam]} C={C:#x} (anchor row {r0})',
                                      file=sys.stderr, flush=True)
    print(f'total: {len(found)}')
    found.sort(reverse=True)
    for rec in found[:10]:
        print(rec)


if __name__ == '__main__':
    main()
