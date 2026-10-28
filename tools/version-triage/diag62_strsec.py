#!/usr/bin/env python3
"""Decrypt 6.2's string section and check where the oracle field names actually
live: exact offset, byte context, and whether the heap file agrees. Explains
the 52/192 missing-off-candidate rows from diag62_field.py.
"""
import json, struct, sys
import numpy as np

M64 = 0xFFFFFFFFFFFFFFFF
BATTLE = '/home/yangsanyi/gire/out/zero-touch/battle'
DAT = '/home/yangsanyi/gire/sample/gi/6.2.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
DUMP = '/home/yangsanyi/gire/out/oracle/6.2Dump.cs'

def key_at(off, ops):
    k = off
    for o in ops:
        if o['op'] == 'And':
            k &= o['v']
        elif o['op'] == 'Mul':
            k = (k * o['v']) & M64
        elif o['op'] == 'Xor':
            k ^= o['v']
    return k & M64

def main():
    prof = json.load(open(f'{BATTLE}/6.2.profile.json'))
    ops, step = prof['cipher']['ops'], prof['cipher']['step']
    strsec = prof['strsec_direct']
    dat = open(DAT, 'rb').read()
    body = dat[0x210:]
    end = len(body)
    n = (end - strsec) // 8
    src = np.frombuffer(body[strsec:strsec + n * 8], dtype='<u8').copy()
    off0 = 0
    k = np.uint64(key_at(off0, ops))
    ks = np.empty(n, dtype=np.uint64)
    st = np.uint64(step)
    for i in range(n):
        ks[i] = k
        k = (k + st) & np.uint64(M64)
    # key stream is per-string (key restarts at each string offset), NOT
    # continuous — a continuous stream only works if we decrypt with the key
    # that starts at strsec base... test both: continuous from base, and
    # per-string keys won't work for bulk search. First try continuous.
    out = (src ^ ks).astype('<u8').tobytes()
    print(f'strsec {strsec:#x}..{end:#x} ({end-strsec} bytes), nq={n}', file=sys.stderr)

    # oracle field names (first 300)
    names, infields = [], False
    for line in open(DUMP, encoding='utf-8', errors='replace'):
        s = line.strip()
        if s == '// Fields':
            infields = True; continue
        if s == '// Methods':
            infields = False; continue
        if infields and s:
            decl = s.split('//')[0].strip().rstrip(';').strip()
            if decl:
                names.append(decl.split()[-1])
    names = names[:300]

    # heap off map
    heap = {}
    for line in open(f'{BATTLE}/6.2.strings.txt', encoding='utf-8', errors='replace'):
        off_s, _, txt = line.rstrip('\n').partition('\t')
        if txt in set(names):
            heap.setdefault(txt, []).append(int(off_s, 16))

    found_plain, missing_plain = 0, []
    offs_true = []
    for i, nm in enumerate(names):
        b = nm.encode()
        p = out.find(b)
        if p >= 0:
            found_plain += 1
            # context: bytes before/after
            offs_true.append((i, nm, p, out[p-1] if p else 0, out[p+len(b)] if p+len(b) < len(out) else 0))
        else:
            missing_plain.append((i, nm))
            offs_true.append((i, nm, -1, 0, 0))
    print(f'plain-search: {found_plain}/{len(names)} found', file=sys.stderr)
    for rec in offs_true[:24]:
        i, nm, p, before, after = rec
        h = heap.get(nm, [])
        print(f'row{i:4d} {nm!r:40s} plain_off={p:8d} prev={before:#04x} next={after:#04x} heap={h[:4]}')
    print('--- missing in plain decrypt:')
    for i, nm in missing_plain[:20]:
        print(f'row{i:4d} {nm!r}')

if __name__ == '__main__':
    main()
