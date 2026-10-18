#!/usr/bin/env python3
"""Emit the 7.0 type listing (dump70-partial) with rendered field/method/property types.

Generics are still placeholders (genericinst#N / !n / !!n); type kind (class vs struct) and
attributes are not decoded yet, so this is a listing, not a compilable dump.cs.
"""
import io, json, re, struct, sys
sys.path.insert(0, '/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage')
import type_render as tr
import type_kinds as tk
import field_rows as fr
import method_rows as mr

V = '/home/yangsanyi/gire/sample/gi/7.0.0'
CROSS = '/home/yangsanyi/gire/out/cross'
ART = '/home/yangsanyi/Documents/git-repo/GI-StaticParser/docs/re/artifacts-7.0.0'
OUT = '/home/yangsanyi/gire/out/cross/dump70-partial.txt'
h = fr.h

def main():
    art = json.load(open(CROSS + '/7.0.0.derive.json')); cipher = mr.Cipher(art)
    sites = json.load(open(CROSS + '/sites/7.0.0.json'))
    d, ib, secs = fr.pe_map(sites['exe']); hdr = d[fr.va2file(ib, secs, sites['blob_va']):][:0x210]
    body = open(V + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]
    def tbase(t):
        raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
        return (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    tt = tr.TypeTable(sites['exe'], CROSS + '/typedefs/7.0.0.jsonl')
    types = tt.types
    fl = json.load(open(ART + '/field-layout.json'))
    fb = tbase(fl['table']); fstride = fl['stride']; mk = fl['mask']
    def fmask(i):
        x = ((i * h(mk['mul1'])) & 0xFFFFFFFFFFFFFFFF) >> mk['shr1']
        x = (x * h(mk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        return ((x + h(mk['add1'])) & 0xFFFFFFFFFFFFFFFF) >> mk['shr2'] & 0xFFFFFFFF
    fname = fl['columns']['name']; ftype = fl['columns']['type']
    def fname_of(i):
        raw = struct.unpack_from('<I', body, fb + i * fstride + fname['off'])[0]
        return cipher.dec(body, ((raw ^ h(fname['c'])) - fmask(i)) & 0xFFFFFFFF)
    def ftype_of(i):
        raw = struct.unpack_from('<I', body, fb + i * fstride + ftype['off'])[0]
        return ((raw + h(ftype['c'])) - fmask(i)) & 0xFFFFFFFF
    ml = json.load(open(ART + '/method-layout.json'))
    mb = tbase(ml['method']['table']); mstride = ml['method']['stride']; mm = mr.mask_fn(ml['method']['mask'])
    mcols = {k: (v['off'], v['kind'], h(v['c'])) for k, v in ml['method']['columns'].items()}
    def mcol(name, i):
        off, kind, c = mcols[name]; width = 1 if name == 'param_count' else 4
        raw = struct.unpack_from('<B' if width == 1 else '<I', body, mb + i * mstride + off)[0]
        return mr.col_value(kind, c, raw, mm(i))
    pl = json.load(open(ART + '/param-layout.json')) if False else ml['param']
    pb = tbase(pl['table']); pstride = pl['stride']; pm = mr.mask_fn(pl['mask'])
    pname = pl['name']; ptype = pl['type']
    def pcol(which, i):
        ro = pb + i * pstride
        if which == 'name':
            raw = struct.unpack_from('<I', body, ro + pname['off'])[0]
            return ((raw + h(pname['c'])) & 0xFFFFFFFF) ^ pm(i)
        raw = struct.unpack_from('<I', body, ro + ptype['off'])[0]
        return (((raw + h(ptype['c'])) & 0xFFFFFFFF) ^ pm(i)) & 0xFFFFFFFF
    pr = json.load(open(ART + '/property-layout.json'))
    pb2 = tbase(pr['table']); pstride2 = pr['stride']; pmk = pr['mask']
    def pmask2(i):
        x = ((i * h(pmk['mul1'])) & 0xFFFFFFFFFFFFFFFF) ^ h(pmk['xor1'])
        x = (x * h(pmk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        x = (x + h(pmk['add1'])) & 0xFFFFFFFFFFFFFFFF
        x ^= h(pmk['xor2'])
        return ((x + h(pmk['add2'])) & 0xFFFFFFFFFFFFFFFF) & 0xFFFFFFFF
    pcols = {k: (v['off'], v['kind'], h(v['c'])) for k, v in pr['columns'].items()}
    def prow(i, key):
        off, kind, c = pcols[key]; ro = pb2 + i * pstride2
        raw = struct.unpack_from('<H' if key in ('getter', 'setter') else '<I', body, ro + off)[0]
        return mr.col_value(kind, c, raw, pmask2(i))
    out = io.open(OUT, 'w', encoding='utf-8')
    kinds = tk.classify(sites['exe'], body)
    # enum: a valuetype whose field list contains value__ (validated 5/5 enums, 0/18 structs wrong)
    enum_like = set()
    for typ in types:
        if typ['i'] < len(kinds) and kinds[typ['i']] == 'struct' and typ['fieldCount']:
            for j in range(typ['fieldCount']):
                if fname_of(typ['fieldStart'] + j) == 'value__':
                    enum_like.add(typ['i'])
                    break
    for i in enum_like:
        kinds[i] = 'enum' 
    cur_ns = None
    nf = nm_ = np_ = 0
    for typ in types:
        tn = (typ['ns'] + '.' if typ['ns'] else '') + typ['name']
        out.write(f'// TypeDefIndex: {typ["i"]}  Fields={typ["fieldCount"]} Methods={typ["methodCount"]} Properties={typ["propCount"] or 0}\n')
        out.write(f'type {tn}\n{{\n')
        if typ['fieldCount']:
            out.write('  // Fields\n')
            for j in range(typ['fieldCount']):
                i = typ['fieldStart'] + j
                out.write(f'  {tt.render(ftype_of(i))} {fname_of(i)}\n'); nf += 1
        pc = typ['propCount'] or 0
        if pc and typ['propStart'] != 0xFFFFFFFF:
            out.write('  // Properties\n')
            for j in range(pc):
                i = typ['propStart'] + j
                nm = cipher.dec(body, prow(i, 'name'))
                g = prow(i, 'getter'); s = prow(i, 'setter')
                pty = tt.render(mcol('return_type', typ['methodStart'] + g)) if g != 0xFFFF else '?'
                acc = ('get;' if g != 0xFFFF else '') + ('set;' if s != 0xFFFF else '')
                out.write(f'  {pty} {nm} {{ {acc} }}\n'); np_ += 1
        if typ['methodCount'] and typ['methodStart'] != 0xFFFFFFFF:
            out.write('  // Methods\n')
            for k in range(typ['methodCount']):
                mi = typ['methodStart'] + k
                nm = cipher.dec(body, mcol('name', mi)); ret = tt.render(mcol('return_type', mi))
                ps = mcol('param_start', mi); pcn = mcol('param_count', mi)
                psx = []
                if ps != 0xFFFFFFFF:
                    for j in range(pcn):
                        pi = ps + j
                        psx.append(f'{tt.render(pcol("type", pi))} {cipher.dec(body, pcol("name", pi))}')
                out.write(f'  {ret} {nm}({", ".join(psx)})\n'); nm_ += 1
        out.write('}\n\n')
    out.close()
    # second pass: prefix each type with class/struct/interface from the kind classifier
    nl = chr(10)
    lines = open(OUT, encoding='utf-8').read().split(nl)
    cur = None
    outp = []
    for ln in lines:
        if ln.startswith('// TypeDefIndex: '):
            try:
                cur = int(ln.split(': ')[1].split()[0])
            except Exception:
                cur = None
        elif ln.startswith('type ') and cur is not None and cur < len(kinds) and kinds[cur] != '?':
            ln = kinds[cur] + ' ' + ln[5:]
        outp.append(ln)
    open(OUT, 'w', encoding='utf-8').write(nl.join(outp))
    print(f'dump70-partial -> {OUT}: fields {nf}, properties {np_}, methods {nm_}')

if __name__ == '__main__':
    main()
