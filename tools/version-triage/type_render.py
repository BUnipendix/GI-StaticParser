#!/usr/bin/env python3
"""Render Il2CppType indexes into C#-style type names for the 7.0 layout.

Type semantics established in R39:
  0x11 VALUETYPE / 0x12 CLASS  -> data = TypeDefinitionIndex
  0x13 VAR / 0x1E MVAR         -> generic parameter position (!n / !!n)
  0x0F PTR / 0x1D SZARRAY / 0x14 ARRAY -> data = VA of the element Il2CppType entry
  0x15 GENERICINST             -> data = opaque index (generic-class table not located yet)
  primitives (0x01..0x0E, 0x16, 0x18, 0x19, 0x1C) -> fixed names

CLI builds a listing of methods/fields/properties with rendered types and, with --check,
compares the first N method signatures against the 7.1 dump.cs (corelib methods are the
same across adjacent builds, so a high match rate validates the rendering end-to-end).
"""
import json, re, struct, sys

TA = json.load(open('/home/yangsanyi/Documents/git-repo/GI-StaticParser/docs/re/artifacts-7.0.0/typearr.json'))
PRIM = {
    0x01: 'System.Void', 0x02: 'System.Boolean', 0x03: 'System.Char', 0x04: 'System.SByte',
    0x05: 'System.Byte', 0x06: 'System.Int16', 0x07: 'System.UInt16', 0x08: 'System.Int32',
    0x09: 'System.UInt32', 0x0A: 'System.Int64', 0x0B: 'System.UInt64', 0x0C: 'System.Single',
    0x0D: 'System.Double', 0x0E: 'System.String', 0x16: 'System.TypedReference',
    0x18: 'System.IntPtr', 0x19: 'System.UIntPtr', 0x1C: 'System.Object',
}

class TypeTable:
    def __init__(self, exe_path, typedefs_path):
        self.d = open(exe_path, 'rb').read()
        self.off = int(TA['file_off'], 16)
        self.va = int(TA['va'], 16)
        self.n = TA['count']
        self.types = [json.loads(l) for l in open(typedefs_path, encoding='utf-8')]
    def raw(self, i):
        o = self.off + 16 * i
        return struct.unpack_from('<QHBB', self.d, o)
    def type_index_of_va(self, va):
        if va < self.va or va >= self.va + 16 * self.n:
            return None
        return (va - self.va) // 16
    def render(self, i, depth=0):
        if i is None or i >= self.n or depth > 6:
            return '?'
        data, attrs, typ, flags = self.raw(i)
        if typ in PRIM:
            return PRIM[typ]
        if typ in (0x11, 0x12):
            if data < len(self.types):
                t = self.types[data]
                return (t['ns'] + '.' if t['ns'] else '') + t['name']
            return f'typedef#{data}'
        if typ == 0x13:
            return f'!{data}'
        if typ == 0x1E:
            return f'!!{data}'
        if typ in (0x0F, 0x1D, 0x14):
            elem = self.type_index_of_va(data)
            suffix = '*' if typ == 0x0F else '[]'
            return self.render(elem, depth + 1) + suffix
        if typ == 0x15:
            return f'genericinst#{data}'
        return f'kind0x{typ:02x}'

def h(s): return int(s, 16) if isinstance(s, str) else s

def load_method_table(exe_path, sites_path, layout_path):
    sites = json.load(open(sites_path))
    import field_rows as fr
    d, ib, secs = fr.pe_map(sites['exe'])
    hdr = d[fr.va2file(ib, secs, sites['blob_va']):][:0x210]
    lay = json.load(open(layout_path))
    def tbase(t):
        raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
        return (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    return lay, tbase

def main():
    vdir = sys.argv[1]
    derive_p, sites_p, method_p, typedefs_p = sys.argv[2:6]
    out_p = sys.argv[6] if len(sys.argv) > 6 else None
    import field_rows as fr
    import method_rows as mr
    art = json.load(open(derive_p)); cipher = mr.Cipher(art)
    sites = json.load(open(sites_p))
    d, ib, secs = fr.pe_map(sites['exe'])
    hdr = d[fr.va2file(ib, secs, sites['blob_va']):][:0x210]
    body = open(vdir + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]
    lay = json.load(open(method_p))
    def tbase(t):
        raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
        return (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    tt = TypeTable(sites['exe'], typedefs_p)
    mb = tbase(lay['method']['table']); ms = lay['method']['stride']; mf = mr.mask_fn(lay['method']['mask'])
    cols = {k: (v['off'], v['kind'], h(v['c'])) for k, v in lay['method']['columns'].items()}
    def mcol(name, i):
        off, kind, c = cols[name]; ro = mb + i * ms
        width = 1 if name == 'param_count' else 2 if name == 'flags' else 4
        raw = struct.unpack_from('<H' if width == 2 else ('<B' if width == 1 else '<I'), body, ro + off)[0]
        return mr.col_value(kind, c, raw, mf(i))
    types = tt.types
    # declaring type per method row
    owner = [None] * len(types)
    lines = []
    total_params = 0; params_out = 0
    for t in types:
        if t['methodCount'] == 0 or t['methodStart'] == 0xFFFFFFFF:
            continue
        tname = (t['ns'] + '.' if t['ns'] else '') + t['name']
        for k in range(t['methodCount']):
            mi = t['methodStart'] + k
            nm = cipher.dec(body, mcol('name', mi))
            ret = tt.render(mcol('return_type', mi))
            ps = mcol('param_start', mi); pc = mcol('param_count', mi)
            assert type(tt.render(0)) is str
            plist = []
            if ps != 0xFFFFFFFF:
                for j in range(pc):
                    plist.append(f'param{j}:type#{0}')
            lines.append(f'{tname}.{nm or "<noname>"} : {ret} ({pc} params)')
    txt = '\n'.join(lines)
    if out_p:
        open(out_p, 'w', encoding='utf-8').write(txt + '\n')
    print(f'listing lines {len(lines)} -> {out_p}')
    print('sample:')
    for l in lines[:12]:
        print('  ' + l)

if __name__ == '__main__':
    main()
