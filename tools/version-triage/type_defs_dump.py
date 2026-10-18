#!/usr/bin/env python3
"""Emit the typeDef list of one build from data-solved layout (no 7.1 seed needed).

Inputs:
  <version dir>            e.g. ~/gire/sample/gi/6.4.0
  <derive artifact>        mhydump derive JSON (cipher schedule + strsec)
  <tables JSON>            mhydump tables --base <typeDef base> --json
Output: JSONL rows {i, ns, name, fieldStart, fieldCount, methodStart, methodCount}

The row layout (name/ns columns, field/method range columns) is solved from data by
tables.rs: string columns are validated by decoding the heap, and the two range pairs
by the tiling predicate. No version constant is embedded here.
"""
import json, struct, re, sys

def load_sched(art):
    c = art['cipher']['schedule']
    return [(o['op'], o['v']) for o in c['ops']], c['step'], art['cipher']['strsec']

def key(off, ops):
    v = off & 0xFFFFFFFF
    for k, val in ops:
        if k == 'And': v &= val
        elif k == 'Mul': v = (v * val) & 0xFFFFFFFFFFFFFFFF
        elif k == 'Add': v = (v + val) & 0xFFFFFFFFFFFFFFFF
        elif k == 'Xor': v ^= val
        elif k == 'Sub': v = (v - val) & 0xFFFFFFFFFFFFFFFF
    return v

def dec(body, strsec, idx, ops, step):
    if idx == 0xFFFFFFFF: return ''
    off = idx & 0xFFFFFF; ln = (idx >> 24) & 0xFF
    if ln == 0: return ''
    nq = (ln + 7) >> 3; src = strsec + off
    if src + nq * 8 + 8 > len(body): return ''
    k = key(off, ops); buf = bytearray()
    for i in range(nq):
        enc = struct.unpack_from('<Q', body, src + 8 * i)[0]
        buf += (enc ^ k).to_bytes(8, 'little')
        k = (k + step) & 0xFFFFFFFFFFFFFFFF
    b = bytes(buf[:ln])
    if any(x < 0x20 or x > 0x7e for x in b): return ''
    return b.split(b'\x00')[0].decode('utf-8', 'replace')

def transform(raw, col):
    if col['transform'] == 'Add': return (raw + col['c']) & 0xFFFFFFFF
    return raw ^ col['c']

def main():
    vdir, derive_path, tables_path = sys.argv[1:4]
    art = json.load(open(derive_path)); ops, step, strsec = load_sched(art)
    tj = json.load(open(tables_path))
    dat = open(vdir + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()
    body = dat[0x210:]
    t = tj['tables'][0]
    base, stride, rows = t['base'], t['stride'], t['rows']
    cols = tj['string_columns']
    name_col = [c for c in cols if c['rows_ok'] == c['rows_tested']][0]
    ns_cols = [c for c in cols if c is not name_col and c['rows_ok'] >= 30]
    ns_col = ns_cols[0] if ns_cols else None
    # row pair semantics: the pair whose max_index is larger is methodStart/count
    ts = tj['tables']
    fld = min(ts, key=lambda x: x['max_index']); mth = max(ts, key=lambda x: x['max_index'])
    out = sys.argv[4] if len(sys.argv) > 4 else None
    f = open(out, 'w') if out else sys.stdout
    n = 0
    for i in range(rows):
        row_off = base + i * stride
        def u32(off):
            return struct.unpack_from('<I', body, row_off + off)[0]
        def u16(off):
            return struct.unpack_from('<H', body, row_off + off)[0]
        nm = dec(body, strsec, transform(u32(name_col['off']), name_col), ops, step)
        ns = dec(body, strsec, transform(u32(ns_col['off']), ns_col), ops, step) if ns_col else ''
        # IndexTable semantics (src/derive/tables.rs): Add means raw = plain + C,
        # Xor means raw = plain ^ C; a raw equal to sentinel_raw decodes to no rows.
        # A row model only fitted its own run of rows; rows beyond it are padding
        # (e.g. 6.4 typeDef: 77,262 rows but the field model fitted 77,261) and must
        # not be read -- the column offset can point past the row grid there.
        def idx_col(c):
            if i >= c.get('rows', rows):
                return 0xFFFFFFFF
            raw = u32(c['idx_off'])
            if c.get('sentinel_raw') is not None and raw == c['sentinel_raw']:
                return 0xFFFFFFFF
            val = (raw ^ c['idx_c']) if c['transform'] == 'Xor' else (raw - c['idx_c'])
            return val & 0xFFFFFFFF
        def cnt_col(c):
            if i >= c.get('rows', rows):
                return 0
            raw = u16(c['cnt_off'])
            val = (raw ^ c['cnt_c']) if c['cnt_transform'] == 'Xor' else (raw - c['cnt_c'])
            return val & 0xFFFF
        fs = idx_col(fld); fc = cnt_col(fld)
        ms = idx_col(mth); mc = cnt_col(mth)
        f.write(json.dumps({'i': i, 'ns': ns, 'name': nm, 'fieldStart': fs, 'fieldCount': fc,
                            'methodStart': ms, 'methodCount': mc}, ensure_ascii=False) + '\n')
        n += 1
    if out: f.close()
    print(f'{vdir}: wrote {n} typeDef rows', file=sys.stderr)

if __name__ == '__main__':
    main()
