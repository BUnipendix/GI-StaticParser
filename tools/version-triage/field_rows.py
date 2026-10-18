#!/usr/bin/env python3
"""Decode one build's field names from a layout JSON and validate structurally.

Layout is DATA (docs/re/artifacts-<ver>/field-layout.json). Validation:
  * every field name must decode to a printable identifier;
  * the field rows a typeDef claims (fieldStart..fieldStart+fieldCount) must exist and
    the names must still decode (i.e. the typeDef range columns and the field table
    agree on the same row universe).
Usage: field_rows.py <version dir> <derive JSON> <field layout> <typedefs JSONL>
"""
import json, re, struct, sys

def h(s): return int(s, 16) if isinstance(s, str) else s

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

def main():
    vdir, derive_path, layout_path, typedefs_path = sys.argv[1:5]
    art = json.load(open(derive_path)); cipher = Cipher(art)
    lay = json.load(open(layout_path))
    sites = json.load(open('/home/yangsanyi/gire/out/cross/sites/7.0.0.json'))
    d, ib, secs = pe_map(sites['exe'])
    hdr = d[va2file(ib, secs, sites['blob_va']):][:0x210]
    body = open(vdir + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]
    t = lay['table']
    raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
    base = (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    stride = lay['stride']; rows = lay['rows']; mk = lay['mask']
    def mask(i):
        x = ((i * h(mk['mul1'])) & 0xFFFFFFFFFFFFFFFF) >> mk['shr1']
        x = (x * h(mk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        x = ((x + h(mk['add1'])) & 0xFFFFFFFFFFFFFFFF) >> mk['shr2']
        return x & 0xFFFFFFFF
    col = lay['columns']['name']; off = col['off']; c = h(col['c'])
    def name(i):
        if i >= rows: return None
        raw = struct.unpack_from('<I', body, base + i * stride + off)[0]
        return cipher.dec(body, ((raw ^ c) - mask(i)) & 0xFFFFFFFF)
    idre = re.compile(r'^[A-Za-z_.<>][A-Za-z0-9_.<>' + chr(96) + r'=+]*$')
    ok = bad = sentinel = 0
    for i in range(rows):
        s = name(i)
        if s is None: sentinel += 1
        elif idre.match(s): ok += 1
        else: bad += 1
    print(f'field rows {rows}: identifiers {ok}, other {bad}, sentinel/undecodable {sentinel} (base 0x{base:X})')
    types = [json.loads(l) for l in open(typedefs_path, encoding='utf-8')]
    covered = mismatch = 0
    for typ in types:
        if not typ['fieldCount']: continue
        for j in range(typ['fieldCount']):
            i = typ['fieldStart'] + j
            if i >= rows: mismatch += 1; continue
            s = name(i)
            if s and idre.match(s): covered += 1
            else: mismatch += 1
    print(f'typeDef field ranges: rows covered by decodable names {covered}, mismatch {mismatch}')

if __name__ == '__main__':
    main()
