#!/usr/bin/env python3
"""Emit the 6.7 type listing (dump67-partial) with rendered field names and method signatures.

Uses the data-only layouts in docs/re/artifacts-6.7.0/. Properties are not decoded yet, so
the listing has types + fields + methods only; it is a listing, not a compilable dump.cs.
"""
import io, json, struct, sys
sys.path.insert(0, '/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage')
import field_rows as fr
import method_rows as mr

V = '/home/yangsanyi/gire/sample/gi/6.7.0'
CROSS = '/home/yangsanyi/gire/out/cross'
ART = '/home/yangsanyi/Documents/git-repo/GI-StaticParser/docs/re/artifacts-6.7.0'
OUT = '/home/yangsanyi/gire/out/cross/dump67-partial.txt'
h = fr.h

def main():
    art = json.load(open(CROSS + '/6.7.0.derive.json')); cipher = mr.Cipher(art)
    sites = json.load(open(CROSS + '/sites/6.7.0.json'))
    d, ib, secs = fr.pe_map(sites['exe']); hdr = d[fr.va2file(ib, secs, sites['blob_va']):][:0x210]
    body = open(V + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]
    types = [json.loads(l) for l in open(CROSS + '/typedefs/6.7.0.jsonl', encoding='utf-8')]
    def tbase(t):
        raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
        return (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    ml = json.load(open(ART + '/method-param-layout.json'))
    mb = tbase(ml['method_table']); ms = ml['method_stride']
    mk = ml['method_mask']
    def mmask(i):
        x = (i * h(mk['mul1'])) & 0xFFFFFFFFFFFFFFFF
        x ^= h(mk['xor0'])
        x = (x * h(mk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        x = (x >> mk['shr']) & 0xFFFFFFFFFFFFFFFF
        x = (x + h(mk['add1'])) & 0xFFFFFFFFFFFFFFFF
        x ^= h(mk['xor1'])
        return x & 0xFFFFFFFF
    def m32(a): return struct.unpack_from('<I', body, a)[0]
    def m8(a): return body[a]
    def m16(a): return struct.unpack_from('<H', body, a)[0]
    mc = ml['method_columns']
    def mcol(name, i):
        c = mc[name]
        if name == 'param_count':
            return (m8(mb + i * ms + c['off']) + h(c['c']) - (mmask(i) & 0xFF)) & 0xFF
        raw = m32(mb + i * ms + c['off'])
        if name == 'param_start':
            return ((raw ^ h(c['c'])) - mmask(i)) & 0xFFFFFFFF
        if name == 'name':
            return cipher.dec(body, ((raw ^ h(c['c'])) - mmask(i)) & 0xFFFFFFFF)
        if name == 'return_type':
            return ((raw ^ h(c['c'])) - mmask(i)) & 0xFFFFFFFF
        raise SystemExit('unknown method column ' + name)
    pb = tbase(ml['param_table']); pst = ml['param_stride']; pm = ml['param_mask']
    def pmask(i): return ((i * h(pm['mul'])) + h(pm['add'])) & 0xFFFFFFFF
    pn = ml['param_columns']['name']; pt = ml['param_columns']['type']
    def pname(i): return cipher.dec(body, ((m32(pb + i * pst + pn['off']) ^ pmask(i) ^ h(pn['c']))) & 0xFFFFFFFF)
    def ptype(i): return ((m32(pb + i * pst + pt['off']) ^ pmask(i) ^ h(pt['c']))) & 0xFFFFFFFF
    fl = json.load(open(ART + '/field-name-layout.json'))
    fb = tbase(fl['table']); fmk = fl['mask']
    def fmask(i): return (((i * h(fmk['mul1']) + h(fmk['add1'])) & 0xFFFFFFFFFFFFFFFF) >> fmk['shr']) & 0xFFFFFFFF
    fc = fl['columns']['name']; ftc = fl['columns']['type']
    def fname(i):
        m = fmask(i)
        extra = ((((m + h(fmk['extra_add'])) & 0xFFFFFFFF) ^ h(fmk['extra_xor'])) * h(fmk['extra_mul'])) & 0xFFFFFFFF
        raw = m32(fb + i * fl['stride'] + fc['off'])
        return cipher.dec(body, ((raw ^ h(fc['c'])) + extra) & 0xFFFFFFFF)
    def ftype(i):
        m = fmask(i)
        extra = ((((m + h(fmk['extra_add'])) & 0xFFFFFFFF) ^ h(fmk['extra_xor'])) * 0x364C6D3D) & 0xFFFFFFFF
        raw = m32(fb + i * fl['stride'] + ftc['off'])
        return (raw - extra + 0xF94BD493) & 0xFFFFFFFF
    ta = json.load(open(ART + '/typearr.json'))
    tb = open(sites['exe'], 'rb').read(); TA = int(ta['file_off'], 16); TN = ta['count']
    TA_VA = int(ta['va'], 16)
    def tyname(i, depth=0):
        if i >= TN or depth > 6: return 'OOB'
        off = TA + 16 * i
        typ = tb[off + 10]; data = struct.unpack_from('<Q', tb, off)[0]
        flags = tb[off + 11]
        prim = ta['type_enum'].get(f'0x{typ:02x}')
        if prim: base = prim
        elif typ in (0x11, 0x12):
            base = f'typedef#{data}'
            if data < len(types):
                t = types[data]; base = (t['ns'] + '.' if t['ns'] else '') + t['name']
        elif typ == 0x13: base = f'!{data}'
        elif typ == 0x1e: base = f'!!{data}'
        elif typ in (0x0f, 0x1d, 0x14):
            e = (data - TA_VA) // 16 if TA_VA <= data < TA_VA + 16 * TN else None
            suf = '*' if typ == 0x0f else '[]'
            base = tyname(e, depth + 1) + suf if e is not None else f'kind0x{typ:02x}'
        elif typ == 0x15: base = f'genericinst#{data}'
        else: base = f'kind0x{typ:02x}'
        if flags & 0x40: base += '&'
        return base
    out = io.open(OUT, 'w', encoding='utf-8')
    nf = nmv = 0
    for typ in types:
        tn = (typ['ns'] + '.' if typ['ns'] else '') + typ['name']
        out.write(f'// TypeDefIndex: {typ["i"]}  Fields={typ["fieldCount"]} Methods={typ["methodCount"]}\n')
        out.write(f'type {tn}\n{{\n')
        if typ['fieldCount']:
            out.write('  // Fields\n')
            for j in range(typ['fieldCount']):
                fi = typ['fieldStart'] + j
                out.write(f'  {tyname(ftype(fi))} {fname(fi)}\n'); nf += 1
        pc = typ['propCount'] or 0
        if pc and typ['propStart'] != 0xFFFFFFFF:
            pr = json.load(open(ART + '/property-layout.json'))
            pb2 = tbase(pr['table']); pst2 = pr['stride']; pmk = pr['mask']
            def pm2(i):
                x = (i * h(pmk['mul1'])) & 0xFFFFFFFFFFFFFFFF
                x ^= h(pmk['xor0']); x = (x * h(pmk['mul2'])) & 0xFFFFFFFFFFFFFFFF
                x >>= pmk['shr1']; x = (x * h(pmk['mul3'])) & 0xFFFFFFFFFFFFFFFF
                x >>= pmk['shr2']; x = (x + h(pmk['add1'])) & 0xFFFFFFFFFFFFFFFF
                return x & 0xFFFFFFFF
            out.write('  // Properties' + chr(10))
            for j in range(pc):
                i = typ['propStart'] + j; mm = pm2(i)
                raw = m32(pb2 + i * pst2); nm = cipher.dec(body, ((raw ^ mm ^ 0x2BFBE794) & 0xFFFFFFFF))
                g = (m16(pb2 + i * pst2 + 8) ^ (mm & 0xFFFF) ^ 0x5D18) & 0xFFFF
                st = (m16(pb2 + i * pst2 + 4) ^ (mm & 0xFFFF) ^ 0xD662) & 0xFFFF
                pty = tyname(mcol('return_type', typ['methodStart'] + g)) if g != 0xFFFF else '?'
                acc = ('get;' if g != 0xFFFF else '') + ('set;' if st != 0xFFFF else '')
                out.write(f'  {pty} {nm} {{ {acc} }}\n')
        ec = typ['eventCount'] or 0
        if ec and typ['eventStart'] != 0xFFFFFFFF:
            ev = json.load(open(ART + '/event-layout.json'))
            eb = tbase(ev['table']); est = ev['stride']; emk = ev['mask']
            def em2(i):
                return (((i * h(emk['mul1']) + h(emk['add1'])) & 0xFFFFFFFFFFFFFFFF) & 0xFFFFFFFF)
            out.write('  // Events' + chr(10))
            for j in range(ec):
                i = typ['eventStart'] + j; em = em2(i)
                etype = ((m32(eb + i * est) + 0xE2CC29CA) & 0xFFFFFFFF) ^ em
                ename = cipher.dec(body, ((m32(eb + i * est + 4) + 0xA16DD35B) & 0xFFFFFFFF) ^ em)
                out.write(f'  event {tyname(etype)} {ename}\n')
        if typ['methodCount'] and typ['methodStart'] != 0xFFFFFFFF:
            out.write('  // Methods\n')
            for k in range(typ['methodCount']):
                mi = typ['methodStart'] + k
                ret = tyname(mcol('return_type', mi)); nm = mcol('name', mi)
                ps = mcol('param_start', mi); pc = mcol('param_count', mi)
                psx = []
                if ps != 0xFFFFFFFF:
                    for j in range(pc):
                        psx.append(f'{tyname(ptype(ps + j))} {pname(ps + j)}')
                out.write(f'  {ret} {nm}({", ".join(psx)})\n'); nmv += 1
        out.write('}\n\n')
    out.close()
    print(f'dump67-partial -> {OUT}: types {len(types)}, fields {nf}, methods {nmv}')

if __name__ == '__main__':
    main()
