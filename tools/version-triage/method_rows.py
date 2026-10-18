#!/usr/bin/env python3
"""Decode one build's method + parameter rows from a layout JSON recovered from code.

The layout JSON (docs/re/artifacts-<ver>/method-layout.json) is DATA: table slot/op/imm,
stride, the per-row mask chain, and each column's transform. This tool only applies them
and validates the result against data invariants (no version constant lives here):

  * paramStart must be non-decreasing across all method rows;
  * paramStart[i+1] - paramStart[i] must equal paramCount[i] (methods are in param order);
  * the parameter table rows implied by paramStart/paramCount must have decodable names
    (valid packed string index -> printable identifier through the shared cipher).

Usage: method_rows.py <version dir> <derive JSON> <sites JSON> <layout JSON>
"""
import json, struct, sys

def pe_map(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]
    opt = pe + 24
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
        c = art['cipher']
        self.ops = [(o['op'], o['v']) for o in c['schedule']['ops']]
        self.step = c['schedule']['step']
        self.strsec = c['strsec']
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

def mask_fn(m):
    mul1, add1, shr, mul2 = h(m['mul1']), h(m['add1']), m['shr'], h(m['mul2'])
    if 'add2' in m:
        add2 = h(m['add2'])
        def f(i):
            x = (i * mul1 + add1) & 0xFFFFFFFFFFFFFFFF
            x >>= shr
            x = (x * mul2 + add2) & 0xFFFFFFFFFFFFFFFF
            return x & 0xFFFFFFFF
    else:
        xor2 = h(m['xor2'])
        def f(i):
            x = (i * mul1 + add1) & 0xFFFFFFFFFFFFFFFF
            x >>= shr
            x = ((x * mul2) & 0xFFFFFFFFFFFFFFFF) ^ xor2
            return x & 0xFFFFFFFF
    return f

def col_value(kind, c, raw, m):
    """Apply one column transform. m is the low-32 mask for this row."""
    if kind == 'AddCSubMask32':  return (raw + c - m) & 0xFFFFFFFF
    if kind == 'SubMaskAddC32':  return (raw - m + c) & 0xFFFFFFFF
    if kind == 'SubMaskAddC16':  return (raw - m + c) & 0xFFFF
    if kind == 'XorCSubMask8':   return ((raw ^ c) - (m & 0xFF)) & 0xFF
    if kind == 'AddCXorMask32':  return ((raw + c) & 0xFFFFFFFF) ^ m
    raise SystemExit('unknown column kind ' + kind)

def main():
    vdir, derive_path, sites_path, layout_path = sys.argv[1:5]
    art = json.load(open(derive_path)); cipher = Cipher(art)
    sites = json.load(open(sites_path))
    d, ib, secs = pe_map(sites['exe'])
    fo = va2file(ib, secs, sites['blob_va']); hdr = d[fo:fo + 0x210]
    dat = open(vdir + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()
    body = dat[0x210:]
    lay = json.load(open(layout_path))
    def table_base(t):
        raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
        return (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    mbase = table_base(lay['method']['table']); pbase = table_base(lay['param']['table'])
    stride = lay['method']['stride']; rows = lay['method']['rows']
    pstride = lay['param']['stride']
    mm = mask_fn(lay['method']['mask']); pm = mask_fn(lay['param']['mask'])
    cols = {k: (v['off'], v['kind'], h(v['c'])) for k, v in lay['method']['columns'].items()}
    def col(name, i):
        off, kind, c = cols[name]
        ro = mbase + i * stride
        width = {'flags': 2, 'param_count': 1}.get(name, 4)
        raw = struct.unpack_from('<H' if width == 2 else ('<B' if width == 1 else '<I'), body, ro + off)[0]
        return col_value(kind, c, raw, mm(i))
    starts = [0] * rows; counts = [0] * rows; flags = [0] * rows; decls = [0] * rows
    for i in range(rows):
        starts[i] = col('param_start', i)
        counts[i] = col('param_count', i)
        flags[i] = col('flags', i)
        decls[i] = col('decl', i)
    # paramStart uses 0xFFFFFFFF as "this method has no parameters"; those rows are
    # skipped in the chain check and must carry count 0. Everything else must equal the
    # running parameter count exactly (methods are stored in parameter order).
    cum = 0; chain_bad = 0; sentinel_bad = 0; sentinel_rows = 0
    for i in range(rows):
        if starts[i] == 0xFFFFFFFF:
            sentinel_rows += 1
            if counts[i] != 0:
                sentinel_bad += 1
        else:
            if starts[i] != cum:
                chain_bad += 1
        cum += counts[i]
    print(f'{vdir}: method base 0x{mbase:X} rows {rows} stride {stride}')
    print(f'  sentinel paramStart rows: {sentinel_rows} (count!=0: {sentinel_bad})')
    print(f'  paramStart chain violations (non-sentinel): {chain_bad}')
    print(f'  sum(paramCount) = {cum}')
    print(f'  flags: max 0x{max(flags):X}, distinct {len(set(flags))}, static(0x10) {sum(1 for f in flags if f & 0x10)}')
    real_decls = [x for x in decls if x != 0xFFFFFFFF]
    print(f'  decl: sentinel(0xFFFFFFFF) {len(decls) - len(real_decls)}, max 0x{(max(real_decls) if real_decls else 0):X}')
    total_params = cum
    ok = bad = 0; sample = []
    pname = lay['param']['name']; ptype = lay['param']['type']
    for t in range(total_params):
        ro = pbase + t * pstride; m = pm(t)
        def pcol(pc):
            raw = struct.unpack_from('<I', body, ro + pc['off'])[0]
            return col_value(pc['kind'], h(pc['c']), raw, m)
        nm = cipher.dec(body, pcol(pname))
        ty = cipher.dec(body, pcol(ptype))
        if nm is None and ty is None: bad += 1
        else:
            ok += 1
            if len(sample) < 12 and nm: sample.append(nm)
    print(f'  params {total_params}: name/type decoded {ok}, both failed {bad}, sample {sample}')

if __name__ == '__main__':
    main()
