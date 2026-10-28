#!/usr/bin/env python3
"""6.2 field-table joint solver diagnosis (oracle-driven).

Given the transfer chain pool, the derive anchor set, and the oracle dump's
field-name sequence, brute-force (base x stride x name_off x chain x fam x C)
and report every combination whose decode lands in the heap at the oracle
field names. Purely diagnostic: tells us the TRUE 6.2 field solution so the
Rust-side gap (missing chain? missing base form? missing family?) can be
located.

Usage: diag62_field.py [--rows 256] [--stride 8,10,12] [--hits 160]
"""
import argparse, json, os, sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exprvm import ExprVM

M32 = np.uint64(0xFFFFFFFF)
BATTLE = '/home/yangsanyi/gire/out/zero-touch/battle'
DAT = '/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
DUMP = '/home/yangsanyi/gire/out/oracle/6.2Dump.cs'


def oracle_field_names():
    names, infields = [], False
    for line in open(DUMP, encoding='utf-8', errors='replace'):
        s = line.strip()
        if s == '// Fields':
            infields = True
            continue
        if s == '// Methods':
            infields = False
            continue
        if infields and s:
            decl = s.split('//')[0].strip().rstrip(';').strip()
            if decl:
                names.append(decl.split()[-1])
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rows', type=int, default=256)
    ap.add_argument('--stride', default='8,10,12')
    ap.add_argument('--hits', type=int, default=160)
    ap.add_argument('--maxoff0', type=int, default=8)
    a = ap.parse_args()

    dat = open(DAT, 'rb').read()
    body = dat[0x210:]
    names = oracle_field_names()
    print(f'oracle fields: {len(names)}', file=sys.stderr)

    need = set(names[:a.rows + 16])
    heap = {}
    for line in open(f'{BATTLE}/6.2.strings.txt', encoding='utf-8', errors='replace'):
        off_s, _, txt = line.rstrip('\n').partition('\t')
        if txt in need:
            heap.setdefault(txt, []).append(int(off_s, 16))
    for v in heap.values():
        v.sort()

    ROWS = a.rows
    # the decoded value is a PACKED string index: (len << 24) | heap offset
    cands = [set((len(names[i]) << 24) | o for o in heap.get(names[i], ()))
             for i in range(ROWS)]
    known = sum(1 for c in cands if c)
    print(f'rows with packed-index candidates: {known}/{ROWS}', file=sys.stderr)

    auto = json.load(open(f'{BATTLE}/6.2.auto.json'))
    chains = auto['semantics']['field_names']['chains']

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
            m = np.asarray(vm.ev(c), dtype=np.uint64) & M32
            masks.append((ci, m))
        except Exception:
            pass
    print(f'chains evaluated: {len(masks)}/{len(chains)}', file=sys.stderr)

    dv = json.load(open(f'{BATTLE}/6.2.0.derive.json'))
    bases = sorted({an['resolved'] for an in dv['anchors']
                    if isinstance(an.get('resolved'), int)})
    b0 = auto['semantics']['field_names'].get('resolved')
    if isinstance(b0, int) and b0 not in bases:
        bases.append(b0)
    print(f'base candidates: {len(bases)} (b0={b0})', file=sys.stderr)

    off0s = sorted(cands[0])[:a.maxoff0] if cands[0] else []
    if not off0s:
        print('FATAL: row0 has no off candidates', file=sys.stderr)
        return
    # flat (off,row) membership for fast vectorized scoring
    member = {}
    for i, c in enumerate(cands):
        for o in c:
            member[o] = i
    rows_of = [np.array(sorted({o for o in member if member[o] == i}, ), dtype=np.uint64) for i in range(ROWS)]

    def score(dec):
        hits = 0
        for i in range(ROWS):
            if np.any(rows_of[i] == dec[i]):
                hits += 1
        return hits

    fam_names = ['SubMaskAddC', 'AddCSubMask', 'XorCSubMask', 'XorCXorMask',
                 'AddCXorMask', 'AddMaskAddC']
    strides = [int(x) for x in a.stride.split(',')]
    n_cols = 0
    found = []
    arr = np.frombuffer(body, dtype=np.uint8)
    ii = np.arange(ROWS, dtype=np.int64)
    # per-row python sets + list of first probe rows for coarse rejection
    cand_sets = [set(c) for c in cands]
    probe = [i for i in range(min(12, ROWS)) if cands[i]][:8]
    for stride in strides:
        for noff in range(0, min(stride, 8), 4):
            for base in bases:
                start = base + noff
                if start < 0 or start + stride * (ROWS - 1) + 4 > len(body):
                    continue
                raw = np.zeros(ROWS, dtype=np.uint64)
                for k in range(4):
                    raw |= arr[start + stride * ii + k].astype(np.uint64) << np.uint64(8 * k)
                n_cols += 1
                r0 = int(raw[0])
                raw_l = raw.tolist()
                for ci, mask in masks:
                    m0 = int(mask[0])
                    mask_l = mask.tolist()
                    for off0 in off0s:
                        Csm = [(0, (off0 - r0 + m0) & 0xFFFFFFFF),
                               (2, (r0 ^ ((off0 + m0) & 0xFFFFFFFF))),
                               (3, r0 ^ m0 ^ off0),
                               (4, ((off0 ^ m0) - r0) & 0xFFFFFFFF),
                               (5, (off0 - r0 - m0) & 0xFFFFFFFF)]
                        for fam, C in Csm:
                            Cu = C
                            # coarse: decode probe rows only
                            ok = True
                            for i in probe:
                                r, m = raw_l[i], mask_l[i]
                                if fam == 0:
                                    d = ((r - m) + Cu) & 0xFFFFFFFF
                                elif fam == 2:
                                    d = ((r ^ Cu) - m) & 0xFFFFFFFF
                                elif fam == 3:
                                    d = ((r ^ Cu) ^ m) & 0xFFFFFFFF
                                elif fam == 4:
                                    d = ((r + Cu) ^ m) & 0xFFFFFFFF
                                else:
                                    d = (r + m + Cu) & 0xFFFFFFFF
                                if d not in cand_sets[i]:
                                    ok = False
                                    break
                            if not ok:
                                continue
                            hits = 0
                            for i in range(ROWS):
                                r, m = raw_l[i], mask_l[i]
                                if fam == 0:
                                    d = ((r - m) + Cu) & 0xFFFFFFFF
                                elif fam == 2:
                                    d = ((r ^ Cu) - m) & 0xFFFFFFFF
                                elif fam == 3:
                                    d = ((r ^ Cu) ^ m) & 0xFFFFFFFF
                                elif fam == 4:
                                    d = ((r + Cu) ^ m) & 0xFFFFFFFF
                                else:
                                    d = (r + m + Cu) & 0xFFFFFFFF
                                if d in cand_sets[i]:
                                    hits += 1
                            if hits >= a.hits:
                                rec = (hits, base, stride, noff, ci, fam, C)
                                found.append(rec)
                                print(f'HIT {rec[0]} base={rec[1]:#x} stride={rec[2]} '
                                      f'noff={rec[3]} chain={rec[4]} fam={fam_names[rec[5]]} '
                                      f'C={rec[6]:#x}', file=sys.stderr, flush=True)
    print(f'scanned {n_cols} columns, hits={len(found)}')
    found.sort(reverse=True)
    for rec in found[:10]:
        print(rec)


if __name__ == '__main__':
    main()
