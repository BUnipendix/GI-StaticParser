#!/usr/bin/env python3
"""Decode a build's method paramStart/paramCount + parameter name/type rows from a
method-param layout JSON (data only, fail loud on unknown kinds).

Usage: decode_params.py <version dir> <derive json> <sites json> <layout json>
"""
import json, struct, sys

def h(s): return int(s, 16) if isinstance(s, str) else s

def main():
    vdir, derive_p, sites_p, lay_p = sys.argv[1:5]
    sys.path.insert(0, '/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage')
    import field_rows as fr
    import method_rows as mr
    art = json.load(open(derive_p)); cipher = mr.Cipher(art)
    sites = json.load(open(sites_p))
    d, ib, secs = fr.pe_map(sites['exe']); hdr = d[fr.va2file(ib, secs, sites['blob_va']):][:0x210]
    body = open(vdir + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]
    lay = json.load(open(lay_p))
    def tbase(t):
        raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
        return (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    mb = tbase(lay['method_table']); ms = lay['method_stride']; rows = lay['method_rows']
    mk = lay['method_mask']
    def mask(i):
        x = (i * h(mk['mul1'])) & 0xFFFFFFFFFFFFFFFF
        x ^= h(mk['xor0'])
        x = (x * h(mk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        x = (x >> mk['shr']) & 0xFFFFFFFFFFFFFFFF
        x = (x + h(mk['add1'])) & 0xFFFFFFFFFFFFFFFF
        x ^= h(mk['xor1'])
        return x & 0xFFFFFFFF
    def m32(a): return struct.unpack_from('<I', body, a)[0]
    def m8(a): return body[a]
    col = lay['method_columns']
    def mname(i):
        c = col['name']
        raw = m32(mb + i * ms + c['off'])
        return cipher.dec(body, ((raw ^ h(c['c'])) - mask(i)) & 0xFFFFFFFF)
    def mval(name, i):
        c = col[name]
        if name == 'param_start':
            raw = m32(mb + i * ms + c['off'])
            return ((raw ^ h(c['c'])) - mask(i)) & 0xFFFFFFFF
        if name == 'param_count':
            raw = m8(mb + i * ms + c['off'])
            return (raw + h(c['c']) - (mask(i) & 0xFF)) & 0xFF
        raise SystemExit('unknown method column ' + name)
    pb = tbase(lay['param_table']); pst = lay['param_stride']
    pm = lay['param_mask']
    def pmask(i):
        return ((i * h(pm['mul'])) + h(pm['add'])) & 0xFFFFFFFF
    pcol = lay['param_columns']
    def pval(name, i):
        c = pcol[name]
        raw = m32(pb + i * pst + c['off'])
        return (raw ^ pmask(i) ^ h(c['c'])) & 0xFFFFFFFF
    print(f'{vdir}: method base 0x{mb:X} param base 0x{pb:X} rows {rows}')
    sent = 0; bad = 0; shown = 0
    for i in range(rows):
        ps = mval('param_start', i); pc = mval('param_count', i)
        if ps == 0xFFFFFFFF:
            sent += 1
            if pc != 0: bad += 1
            continue
        names = []
        for j in range(pc):
            n = cipher.dec(body, pval('name', ps + j))
            names.append(n)
            if n is None: bad += 1
        if shown < 8:
            print(f'  method {i}: {mname(i)!r} start {ps} count {pc} params {names}')
            shown += 1
    print(f'paramStart sentinels {sent}, bad rows {bad}')

if __name__ == '__main__':
    main()
