#!/usr/bin/env python3
"""Locate 6.2's field-name column by DIFFERENTIAL invariants (C-free).

For every transform family, consecutive-row differences of the raw u32 column
do not depend on the family constant C:
  linear (SubMaskAddC / AddCSubMask): raw[i+1]-raw[i] = (v[i+1]-v[i]) + (mask[i+1]-mask[i])
  AddMaskAddC:  raw[i+1]-raw[i] = (v[i+1]-v[i]) - (mask[i+1]-mask[i])
  XorCSubMask:  raw[i]^raw[i+1] = (v[i]+mask[i]) ^ (v[i+1]+mask[i+1])
  XorCXorMask:  raw[i]^raw[i+1] = (v[i]^mask[i]) ^ (v[i+1]^mask[i+1])
  AddCXorMask:  raw[i+1]-raw[i] = (v[i+1]^mask[i+1]) - (v[i]^mask[i])

raw[i] = U[b + st*i] where U is the body as u32 words (stride = st*4 bytes).
Search the whole U for the expected difference pattern -> no base-candidate
list needed. Then solve C from row 0 and verify against all known rows.
"""
import json, os, sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exprvm import ExprVM

M32 = 0xFFFFFFFF
BATTLE = '/home/yangsanyi/gire/out/zero-touch/battle'
DAT = '/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
DUMP = '/home/yangsanyi/gire/out/oracle/6.2Dump.cs'

FAMS = ['SubMaskAddC', 'AddCSubMask', 'XorCSubMask', 'XorCXorMask', 'AddCXorMask', 'AddMaskAddC']


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
    rows = 256
    dat = open(DAT, 'rb').read()
    body = dat[0x210:]
    names = oracle_field_names()
    print(f'oracle fields: {len(names)}', file=sys.stderr)

    need = set(names[:rows + 16])
    heap = {}
    for line in open(f'{BATTLE}/6.2.strings.txt', encoding='utf-8', errors='replace'):
        off_s, _, txt = line.rstrip('\n').partition('\t')
        if txt in need:
            heap.setdefault(txt, []).append(int(off_s, 16))

    v_cands = []
    for i in range(rows):
        h = heap.get(names[i], [])
        v_cands.append([((len(names[i]) << 24) | o) & M32 for o in h[:4]])
    known = [i for i in range(rows) if v_cands[i]]
    run0 = 0
    while run0 < rows and v_cands[run0]:
        run0 += 1
    print(f'known rows: {len(known)}/{rows}, consecutive from row0: {run0}', file=sys.stderr)

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
    idx = np.arange(rows, dtype=np.uint64)
    symmap = {s: idx for s in allsyms}
    hdr = dat[:0x210]
    masks = []
    for ci, c in enumerate(chains):
        try:
            vm = ExprVM(body, 0, 1, rows, symmap, hdr)
            m = np.asarray(vm.ev(c), dtype=np.uint64) & np.uint64(M32)
            masks.append((ci, m.astype(np.uint32)))
        except Exception:
            pass
    print(f'chains evaluated: {len(masks)}/{len(chains)}', file=sys.stderr)

    U = np.frombuffer(body, dtype='<u4')
    SEG = min(run0, 10)
    if SEG < 4:
        print('FATAL: too few consecutive known rows from row0', file=sys.stderr)
        return
    v0_cands = v_cands[0]

    found = []
    # st = u32 words per row; stride bytes = st*4
    for st in (2, 3, 4, 1, 5, 6, 8):
        addD = (U[st:].astype(np.int64) - U[:-st].astype(np.int64)) % (1 << 32)
        xorD = U[st:] ^ U[:-st]
        for ci, mask in masks:
            ml = mask.tolist()
            for fam in range(6):
                for v0 in v0_cands:
                    vs = [v0] + [v_cands[i][0] for i in range(1, SEG)]
                    pat = []
                    for i in range(SEG - 1):
                        a, b_ = vs[i], vs[i + 1]
                        ma, mb = ml[i], ml[i + 1]
                        if fam in (0, 1):
                            pat.append(((b_ - a) + (mb - ma)) & M32)
                        elif fam == 5:
                            pat.append(((b_ - a) - (mb - ma)) & M32)
                        elif fam == 2:
                            pat.append((((b_ + mb) & M32) ^ ((a + ma) & M32)))
                        elif fam == 3:
                            pat.append(((b_ ^ mb) ^ (a ^ ma)) & M32)
                        else:
                            pat.append((((b_ ^ mb) - (a ^ ma)) & M32))
                    arr = xorD if fam in (2, 3) else addD
                    js = np.nonzero(arr == pat[0])[0]
                    for j in js.tolist():
                        if j + st * (SEG - 2) >= len(arr):
                            continue
                        okp = all(int(arr[j + st * k]) == pat[k] for k in range(1, SEG - 1))
                        if not okp:
                            continue
                        raw0 = int(U[j])
                        C = solve_C(fam, raw0, ml[0], v0)
                        hits = 0
                        for i in known:
                            if j + st * i >= len(U):
                                break
                            v = fam_value(fam, int(U[j + st * i]), ml[i], C)
                            if v in v_cands[i]:
                                hits += 1
                        if hits >= 80:
                            rec = (hits, j * 4, st * 4, ci, fam, C)
                            found.append(rec)
                            print(f'HIT hits={hits} base_byte={j*4:#x} stride={st*4} '
                                  f'chain={ci} fam={FAMS[fam]} C={C:#x}', file=sys.stderr, flush=True)
    print(f'total: {len(found)}')
    found.sort(reverse=True)
    for rec in found[:12]:
        print(rec)


if __name__ == '__main__':
    main()
