#!/usr/bin/env python3
"""Discover additional typeDef row column PAIRS (start,count) from data alone.

Each metadata range pair (fields, methods, properties, events, nested types, interface
offsets) is a per-type START column + per-type COUNT column. The count column is
constant-obfuscated and u8 or u16 wide; the start column is u16/u32 with an all-ones
sentinel on "this type has none".

Constants are pinned WITHOUT a version constant:
  * count: most types have no member -> the most frequent raw value is the encoding of
    plain 0 (xor: C = raw; add: C = -raw). If that fails, row 0 (<Module>) has 0 too.
  * start: any row with count 0 holds the sentinel (all-ones), which pins C.
Tiling is verified over the whole table: start values must be non-decreasing and
must not overlap the previous end; gaps are counted (nested/interface arrays can have
holes) but gross overlap rejects the pair.
"""
import json, sys
import numpy as np

def load_body(vdir):
    return open(vdir + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]

def column(body, base, stride, rows, off, width):
    a = np.frombuffer(body, dtype=np.uint8)
    idx = base + off + stride * np.arange(rows, dtype=np.int64)
    if width == 4:
        return (a[idx].astype(np.uint32) | (a[idx+1].astype(np.uint32) << 8)
                | (a[idx+2].astype(np.uint32) << 16) | (a[idx+3].astype(np.uint32) << 24))
    if width == 2:
        return a[idx].astype(np.uint32) | (a[idx+1].astype(np.uint32) << 8)
    return a[idx].astype(np.uint32)

def decode(raw, width, fam, c):
    mask = (1 << (8 * width)) - 1
    v = (raw ^ c) if fam == 'xor' else ((raw + c) & mask)
    return v & mask

def count_candidates(body, base, stride, rows, off, width):
    raw = column(body, base, stride, rows, off, width)
    mask = (1 << (8 * width)) - 1
    out = []
    bc = np.bincount(raw.astype(np.int64), minlength=mask + 1)
    mode = int(bc.argmax())
    for fam in ('xor', 'add'):
        c = mode if fam == 'xor' else ((-mode) & mask)
        dec = decode(raw, width, fam, c)
        s = int(dec.sum())
        if 50 <= s <= 2_000_000 and int(dec.max()) < 20000:
            out.append((fam, c, s, int(dec.max())))
    r0 = int(raw[0]) & mask
    for fam in ('xor', 'add'):
        c = r0 if fam == 'xor' else ((-r0) & mask)
        if any(x[0] == fam and x[1] == c for x in out):
            continue
        dec = decode(raw, width, fam, c)
        s = int(dec.sum())
        if 50 <= s <= 2_000_000 and int(dec.max()) < 20000:
            out.append((fam, c, s, int(dec.max())))
    return raw, out

def main():
    vdir, tables_path, out_path = sys.argv[1:4]
    tj = json.load(open(tables_path))
    t = tj['tables'][0]
    base, stride, rows = t['base'], t['stride'], t['rows']
    body = load_body(vdir)
    starts = {}
    for w in (4, 2):
        for off in range(0, stride - w + 1):
            starts[(off, w)] = column(body, base, stride, rows, off, w)
    results = []
    for cw in (1, 2):
        for coff in range(0, stride + 0x60):
            craw, cands = count_candidates(body, base, stride, rows, coff, cw)
            for cfam, Cc, total, mx in cands:
                cdec = decode(craw, cw, cfam, Cc)
                zero_rows = np.nonzero(cdec == 0)[0]
                if len(zero_rows) == 0:
                    continue
                sent_row = int(zero_rows[0])
                for (soff, sw), sraw in starts.items():
                    smask = (1 << (8 * sw)) - 1
                    r0 = int(sraw[sent_row])
                    for sfam in ('xor', 'add'):
                        Cs = (r0 ^ smask) if sfam == 'xor' else ((smask - r0) & smask)
                        sdec = decode(sraw, sw, sfam, Cs)
                        bad = 0; gaps = 0; nz = 0; prev = 0; maxs = 0
                        for i in range(rows):
                            c = int(cdec[i])
                            if c == 0:
                                continue
                            st = int(sdec[i])
                            if st < prev:
                                bad += 1
                                if bad > 4:
                                    break
                            elif st > prev:
                                gaps += 1
                            prev = st + c; nz += 1
                            if st > maxs: maxs = st
                        if bad <= 4 and nz >= 50 and prev > 0 and prev < 26_000_000 \
                                and gaps <= max(16, nz // 10):
                            results.append(dict(start_off=soff, start_w=sw, start_fam=sfam, start_c=Cs,
                                                cnt_off=coff, cnt_w=cw, cnt_fam=cfam, cnt_c=Cc,
                                                chain_rows=nz, gaps=gaps, end=prev))
    seen = set(); uniq = []
    for r in results:
        k = (r['start_off'], r['cnt_off'])
        if k in seen: continue
        seen.add(k); uniq.append(r)
    uniq.sort(key=lambda r: -r['chain_rows'])
    json.dump(uniq, open(out_path, 'w'), indent=1)
    print(f'{vdir}: {len(uniq)} pairs -> {out_path}')

if __name__ == '__main__':
    main()
