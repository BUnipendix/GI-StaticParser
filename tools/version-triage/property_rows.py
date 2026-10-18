#!/usr/bin/env python3
"""Decode one build's property rows from a layout JSON and validate them structurally.

Layout is DATA (docs/re/artifacts-<ver>/property-layout.json). Validation uses only
independent data invariants:
  * property names must decode to printable identifiers;
  * a non-0xFFFF getter index must be a PER-TYPE method index: base_method + accessor
    must fall inside the declaring type's method range (typeDef methodStart/Count);
  * the accessor method's name must be the get_/set_ counterpart for un-obfuscated
    members (obfuscation renames the two independently, so the match rate is reported,
    not required).
Usage: property_rows.py <version dir> <derive JSON> <sites JSON> <property layout> <typedefs JSONL> <method layout>
"""
import json, re, struct, sys

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

def h(s): return int(s, 16) if isinstance(s, str) else s

class Cipher:
    def __init__(self, art):
        c = art['cipher']; self.ops = [(o['op'], o['v']) for o in c['schedule']['ops']]
        self.step = c['schedule']['step']; self.strsec = c['strsec']
    def key(self, off):
        v = off & 0xFFFFFFFF
        for k, val in self.ops:
            if k == 'And': v &= val
            elif k == 'Mul': v = (v * val) & 0xFFFFFFFFFFFFFFFF
            elif k == 'Add': v = (v + val) & 0xFFFFFFFFFFFFFFFF
            elif k == 'Xor': v ^= val
            elif k == 'Sub': v = (v - val) & 0xFFFFFFFFFFFFFFFF
        return v
    def dec(self, body, idx):
        if idx == 0xFFFFFFFF: return None
        off = idx & 0xFFFFFF; ln = (idx >> 24) & 0xFF
        if ln == 0: return ''
        nq = (ln + 7) >> 3; src = self.strsec + off
        if src + nq * 8 + 8 > len(body): return None
        k = self.key(off); buf = bytearray()
        for i in range(nq):
            enc = struct.unpack_from('<Q', body, src + 8 * i)[0]
            buf += (enc ^ k).to_bytes(8, 'little')
            k = (k + self.step) & 0xFFFFFFFFFFFFFFFF
        b = bytes(buf[:ln])
        if any(x < 0x20 or x > 0x7e for x in b): return None
        return b.split(b'\x00')[0].decode('utf-8', 'replace')

def col(kind, c, raw, m):
    if kind == 'XorCSubMask32': return (raw ^ c) - (m & 0xFFFFFFFF) & 0xFFFFFFFF
    if kind == 'SubMaskAddC16': return (raw - (m & 0xFFFF) + c) & 0xFFFF
    if kind == 'XorCSubMask16': return ((raw ^ c) - (m & 0xFFFF)) & 0xFFFF
    raise SystemExit('unknown kind ' + kind)

def main():
    vdir, derive_path, sites_path, layout_path, typedefs_path, method_layout_path = sys.argv[1:7]
    art = json.load(open(derive_path)); cipher = Cipher(art)
    sites = json.load(open(sites_path)); d, ib, secs = pe_map(sites['exe'])
    hdr = d[va2file(ib, secs, sites['blob_va']):][:0x210]
    body = open(vdir + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]
    lay = json.load(open(layout_path)); mlay = json.load(open(method_layout_path))
    def base(t):
        raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
        return (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    pbase = base(lay['table']); stride = lay['stride']; rows = lay['rows']; mk = lay['mask']
    def mask(i):
        x = ((i * h(mk['mul1'])) & 0xFFFFFFFFFFFFFFFF) ^ h(mk['xor1'])
        x = (x * h(mk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        x = (x + h(mk['add1'])) & 0xFFFFFFFFFFFFFFFF
        x ^= h(mk['xor2'])
        return (x + h(mk['add2'])) & 0xFFFFFFFFFFFFFFFF
    cols = {k: (v['off'], v['kind'], h(v['c'])) for k, v in lay['columns'].items()}
    def row(i, key):
        off, kind, c = cols[key]; ro = pbase + i * stride
        width = 2 if key in ('getter', 'setter') else 4
        raw = struct.unpack_from('<H' if width == 2 else '<I', body, ro + off)[0]
        return col(kind, c, raw, mask(i))
    # method names for the accessor cross-check
    mbase = base(mlay['method']['table']); mstride = mlay['method']['stride']
    mmk = mlay['method']['mask']
    def mmask(i):
        x = (i * h(mmk['mul1']) + h(mmk['add1'])) & 0xFFFFFFFFFFFFFFFF
        x >>= mmk['shr']
        x = (x * h(mmk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        return (x + h(mmk['add2'])) & 0xFFFFFFFF
    mn = mlay['method']['columns']['name']
    def mname(i):
        raw = struct.unpack_from('<I', body, mbase + i * mstride + mn['off'])[0]
        return cipher.dec(body, ((raw + h(mn['c'])) - mmask(i)) & 0xFFFFFFFF)
    types = [json.loads(l) for l in open(typedefs_path, encoding='utf-8')]
    idre = re.compile(r'^[A-Za-z_.<>][A-Za-z0-9_.<>' + chr(96) + r'=+]*$')
    named = badname = 0; checked = oob = 0; get_ok = set_ok = named_acc = 0
    for t in types:
        if not t['propCount']: continue
        base_m = t['methodStart']; mc = t['methodCount']
        for j in range(t['propCount']):
            i = t['propStart'] + j
            if i >= rows: break
            nm = cipher.dec(body, row(i, 'name'))
            if nm and idre.match(nm): named += 1
            elif nm is not None: badname += 1
            if not nm: continue
            for key, is_get in (('getter', True), ('setter', False)):
                a = row(i, key)
                if a == 0xFFFF or base_m == 0xFFFFFFFF: continue
                checked += 1
                if a >= mc: oob += 1; continue
                mn_ = mname(base_m + a)
                if not mn_: continue
                mshort = mn_.rsplit('.', 1)[-1]
                if (is_get and mshort.startswith('get_')) or ((not is_get) and mshort.startswith('set_')):
                    named_acc += 1
                    if mshort == ('get_' if is_get else 'set_') + nm.rsplit('.', 1)[-1]:
                        if is_get: get_ok += 1
                        else: set_ok += 1
    print(f'property rows {rows}: name identifiers {named}, other {badname}')
    print(f'accessors checked {checked}, out-of-type-method-range {oob} ({100*oob/max(1,checked):.2f}%)')
    print(f'accessors with get_/set_ names {named_acc}: getter match {get_ok}, setter match {set_ok}')
    print(f'  (obfuscated properties/accessors are renamed independently, so the match rate is informational)')

if __name__ == '__main__':
    main()
