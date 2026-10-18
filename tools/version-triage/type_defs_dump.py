#!/usr/bin/env python3
"""Emit the typeDef list of one build from data-solved layout (no 7.1 seed needed).

Inputs:
  <version dir>            e.g. ~/gire/sample/gi/6.4.0
  <derive artifact>        mhydump derive JSON (cipher schedule + strsec)
  <tables JSON>            mhydump tables --base <typeDef base> --json
Optional: <ranges JSON> from find_type_ranges.py adds propertyStart/Count and
eventStart/Count, which makes the row a full typeDef record for the dump pipeline.
Output: JSONL rows {i, ns, name, fieldStart, fieldCount, methodStart, methodCount,
                    propStart, propCount, eventStart, eventCount}

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
    ranges_path = sys.argv[5] if len(sys.argv) > 5 else None
    ranges = json.load(open(ranges_path)) if ranges_path else []
    # Classify the discovered (start,count) pairs that are NOT the field/method pairs:
    #   property: chain_rows > 10k and end > 5k; event: chain_rows >= 50 and end <= 5k.
    # Ambiguous pairs (e.g. nested-type arrays, 35k rows) are reported but not wired
    # until the semantic is settled by a validator.
    prop_pair = ev_pair = None
    for r in ranges:
        if r['start_off'] == fld['idx_off'] and r['cnt_off'] == fld['cnt_off']:
            continue
        if r['start_off'] == mth['idx_off'] and r['cnt_off'] == mth['cnt_off']:
            continue
        if r['chain_rows'] > 10000 and r['end'] > 5000 and prop_pair is None:
            prop_pair = r
        elif r['chain_rows'] >= 50 and r['end'] <= 5000 and ev_pair is None:
            ev_pair = r
    def pair_cols(r):
        sw, cw = r['start_w'], r['cnt_w']
        def rd(off, w):
            if w == 4: return u32(off)
            if w == 2: return (struct.unpack_from('<H', body, row_off + off)[0])
            return body[row_off + off]
        def sval(): return rd(r['start_off'], sw)
        def cval(): return rd(r['cnt_off'], cw)
        smask = (1 << (8 * sw)) - 1
        cmask = (1 << (8 * cw)) - 1
        def dec_s(raw):
            v = (raw ^ r['start_c']) if r['start_fam'] == 'xor' else ((raw + r['start_c']) & smask)
            return v & smask
        def dec_c(raw):
            v = (raw ^ r['cnt_c']) if r['cnt_fam'] == 'xor' else ((raw + r['cnt_c']) & cmask)
            return v & cmask
        return sval, cval, dec_s, dec_c
    if prop_pair: ps_fn, pc_fn, ps_dec, pc_dec = pair_cols(prop_pair)
    if ev_pair: es_fn, ec_fn, es_dec, ec_dec = pair_cols(ev_pair)
    # A range pair is only accepted when its counts sum to the discovered chain end
    # (i.e. the array is one contiguous run). An overlapping/multi-run array (e.g.
    # the 5.4.0 35,864-row pair) fails this and is reported instead of being wired.
    def read_at(off, w, i):
        at = base + i * stride + off
        if w == 4: return struct.unpack_from('<I', body, at)[0]
        if w == 2: return struct.unpack_from('<H', body, at)[0]
        return body[at]
    def pair_total(r):
        cmask = (1 << (8 * r['cnt_w'])) - 1
        s = 0
        for i in range(rows):
            raw = read_at(r['cnt_off'], r['cnt_w'], i)
            c = (raw ^ r['cnt_c']) if r['cnt_fam'] == 'xor' else ((raw + r['cnt_c']) & cmask)
            s += c & cmask
        return s
    if prop_pair and pair_total(prop_pair) != prop_pair['end']:
        sys.stderr.write(f"{vdir}: property pair rejected (sum != end); pair={prop_pair}\n")
        prop_pair = None
    if ev_pair and pair_total(ev_pair) != ev_pair['end']:
        sys.stderr.write(f"{vdir}: event pair rejected (sum != end); pair={ev_pair}\n")
        ev_pair = None
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
        prop_start = prop_count = ev_start = ev_count = None
        if prop_pair:
            prop_start = ps_dec(ps_fn()); prop_count = pc_dec(pc_fn())
            if prop_count == 0:
                prop_start = 0xFFFFFFFF if prop_pair['start_w'] == 4 else 0xFFFF
        if ev_pair:
            ev_start = es_dec(es_fn()); ev_count = ec_dec(ec_fn())
            if ev_count == 0:
                ev_start = 0xFFFFFFFF if ev_pair['start_w'] == 4 else 0xFFFF
        f.write(json.dumps({'i': i, 'ns': ns, 'name': nm, 'fieldStart': fs, 'fieldCount': fc,
                            'methodStart': ms, 'methodCount': mc,
                            'propStart': prop_start, 'propCount': prop_count,
                            'eventStart': ev_start, 'eventCount': ev_count}, ensure_ascii=False) + '\n')
        n += 1
    if out: f.close()
    print(f'{vdir}: wrote {n} typeDef rows', file=sys.stderr)

if __name__ == '__main__':
    main()
