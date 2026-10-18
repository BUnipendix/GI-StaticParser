#!/usr/bin/env python3
"""Oracle-driven column brute-forcer.

Given a row table (base slot/op/imm + stride + mask chain) and an oracle dump (dump.cs),
brute-force (column offset x transform family x constant) for a semantic column and report
every combination that reproduces the oracle exactly.

Usage:
  oracle_column_bf.py --dump <dump.cs> --exe <game.exe> --metadata <global-metadata.dat>
      --blob-va 0x.. --base-slot 0x1FC --base-op xor --base-imm 0x22414276
      --stride 26 --mask '{"mul":"0x11D36B90D36A8EDD","add":"0x68C1F6C86562CBFC","shr":19}'
      --rows 631108 --field param_count --limit 60
"""
import argparse, json, re, struct, sys

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dump', required=True)
    ap.add_argument('--exe', required=True)
    ap.add_argument('--metadata', required=True)
    ap.add_argument('--blob-va', type=lambda x: int(x, 16), required=True)
    ap.add_argument('--base-slot', type=lambda x: int(x, 16), required=True)
    ap.add_argument('--base-op', choices=['add', 'xor'], required=True)
    ap.add_argument('--base-imm', type=lambda x: int(x, 16), required=True)
    ap.add_argument('--stride', type=int, required=True)
    ap.add_argument('--mask', required=True)
    ap.add_argument('--rows', type=int, required=True)
    ap.add_argument('--field', choices=['param_count', 'param_start'], required=True)
    ap.add_argument('--limit', type=int, default=60)
    return ap.parse_args()

def pe_map(path):
    d = open(path, 'rb').read(); pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]; opt = pe + 24
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

def dump_param_counts(path, limit):
    out = []
    pat = re.compile(r'\((.*?)\)\s*\{')
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            s = line.strip()
            if '{ }' in s and '// RVA' in s:
                m = pat.search(s)
                if m:
                    pt = m.group(1).strip()
                    out.append(0 if not pt else len(pt.split(',')))
                if len(out) >= limit:
                    break
    return out

def main():
    a = parse_args()
    mk = json.loads(a.mask)
    d, ib, secs = pe_map(a.exe)
    hdr = d[va2file(ib, secs, a.blob_va):][:0x210]
    body = open(a.metadata, 'rb').read()[0x210:]
    raw_slot = struct.unpack_from('<I', hdr, a.base_slot)[0]
    base = (raw_slot + a.base_imm) & 0xFFFFFFFF if a.base_op == 'add' else ((raw_slot ^ a.base_imm) & 0xFFFFFFFF)
    M = int(mk['mul'], 0); A = int(mk['add'], 0); S = int(mk['shr'])
    def mask(i):
        x = (i * M + A) & 0xFFFFFFFFFFFFFFFF
        return (x >> S) & 0xFFFFFFFF
    exp = dump_param_counts(a.dump, a.limit)
    print(f'base 0x{base:X} stride {a.stride} mask mul {hex(M)} add {hex(A)} shr {S}; oracle rows {len(exp)}')
    hits = []
    if a.field == 'param_count':
        for off in range(0, a.stride):
            for fam in ('xor', 'sub', 'add', 'nomask'):
                for C in range(256):
                    ok = True
                    for i, e in enumerate(exp):
                        if i >= a.rows: break
                        raw = body[base + i * a.stride + off]
                        m = mask(i) & 0xFF
                        if fam == 'xor': v = (raw ^ m ^ C) & 0xFF
                        elif fam == 'sub': v = (raw - m - C) & 0xFF
                        elif fam == 'add': v = (raw + m + C) & 0xFF
                        else: v = (raw ^ C) & 0xFF
                        if v != e: ok = False; break
                    if ok: hits.append((off, fam, C))
    else:
        cum = [0]
        for e in exp[:-1]: cum.append(cum[-1] + e)
        for off in range(0, a.stride - 3):
            for fam in ('xor', 'sub', 'add'):
                ok = True
                for i in range(1, len(exp)):
                    def val(j):
                        raw = struct.unpack_from('<I', body, base + j * a.stride + off)[0]; m = mask(j)
                        if fam == 'xor': return raw ^ m
                        if fam == 'sub': return (raw - m) & 0xFFFFFFFF
                        return (raw + m) & 0xFFFFFFFF
                    if ((val(i) - val(0)) & 0xFFFFFFFF) != cum[i]: ok = False; break
                if ok: hits.append((off, fam, 0))
    if not hits:
        print('NO MATCH')
        sys.exit(1)
    for h in hits:
        print('MATCH', h)

if __name__ == '__main__':
    main()
