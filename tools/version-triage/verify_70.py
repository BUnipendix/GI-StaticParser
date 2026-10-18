#!/usr/bin/env python3
"""End-to-end verification harness for the 7.0.0 data-solved layout.

It re-decodes samples from every solved table and asserts the structural invariants that
were established across R28..R37. Exit code is non-zero on the first violated invariant
(R12: fail loud). This is the regression gate for the 7.0 profile draft.

Usage: verify_70.py
"""
import json, re, struct, sys

VD = '/home/yangsanyi/gire/sample/gi/7.0.0'
CROSS = '/home/yangsanyi/gire/out/cross'
ART = '/home/yangsanyi/Documents/git-repo/GI-StaticParser/docs/re/artifacts-7.0.0'
sys.path.insert(0, '/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage')
import field_rows as fr
import method_rows as mr

def h(s): return int(s, 16) if isinstance(s, str) else s

def main():
    art = json.load(open(f'{CROSS}/7.0.0.derive.json'))
    cipher = fr.Cipher(art)
    sites = json.load(open(f'{CROSS}/sites/7.0.0.json'))
    d, ib, secs = fr.pe_map(sites['exe'])
    hdr = d[fr.va2file(ib, secs, sites['blob_va']):][:0x210]
    body = open(VD + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]
    def tbase(t):
        raw = struct.unpack_from('<I', hdr, h(t['slot']))[0]
        return (raw + h(t['imm'])) & 0xFFFFFFFF if t['op'] == 'add' else ((raw ^ h(t['imm'])) & 0xFFFFFFFF)
    idre = re.compile(r'^[A-Za-z_.<>][A-Za-z0-9_.<>' + chr(96) + r'=+]*$')
    checks = []
    def check(name, ok, detail):
        checks.append((name, ok, detail))
        print(('PASS ' if ok else 'FAIL ') + name + ': ' + detail)

    # --- typeDef table -------------------------------------------------------
    tables = json.load(open(f'{CROSS}/tables-7.0.0.json'))
    types = [json.loads(l) for l in open(f'{CROSS}/typedefs/7.0.0.jsonl', encoding='utf-8')]
    check('typeDef rows', len(types) == 86932, f'{len(types)} rows')
    check('typeDef named', sum(1 for t in types if t['name']) == 86900,
          f"{sum(1 for t in types if t['name'])} named")
    check('field range sum', sum(t['fieldCount'] for t in types) == 430290,
          f"{sum(t['fieldCount'] for t in types)}")
    check('method range sum', sum(t['methodCount'] for t in types) == 713956,
          f"{sum(t['methodCount'] for t in types)}")
    check('property range sum', sum(t['propCount'] or 0 for t in types) == 112949,
          f"{sum(t['propCount'] or 0 for t in types)}")
    check('event range sum', sum(t['eventCount'] or 0 for t in types) == 625,
          f"{sum(t['eventCount'] or 0 for t in types)}")

    # --- method table: name / paramStart chain (sampled) --------------------
    ml = json.load(open(f'{ART}/method-layout.json'))
    mb = tbase(ml['method']['table']); ms = ml['method']['stride']
    mf = mr.mask_fn(ml['method']['mask'])
    mn = ml['method']['columns']['name']; ps_c = h(ml['method']['columns']['param_start']['c'])
    pc_c = h(ml['method']['columns']['param_count']['c'])
    nid = 0; nsent = 0; nbad = 0; nbad_idx = 0
    for i in range(20000):
        raw = struct.unpack_from('<I', body, mb + i * ms + mn['off'])[0]
        idx = ((raw + h(mn['c'])) - mf(i)) & 0xFFFFFFFF
        s = cipher.dec(body, idx)
        if s is None:
            nsent += 1
            if idx != 0xFFFFFFFF: nbad_idx += 1
        elif idre.match(s): nid += 1
        else: nbad += 1
    # A few methods legitimately carry the 0xFFFFFFFF "no name" sentinel; anything else
    # that fails to decode is a layout error.
    check('method name sample', nid >= 19000 and nbad <= 60 and nbad_idx == 0,
          f'{nid} ids / {nsent} none / {nbad} other / {nbad_idx} invalid')
    prev_end = 0; chain_bad = 0
    for i in range(20000):
        m = mf(i)
        pc = ((body[mb + i * ms + ml['method']['columns']['param_count']['off']] ^ pc_c) - (m & 0xFF)) & 0xFF
        raw = struct.unpack_from('<I', body, mb + i * ms + ml['method']['columns']['param_start']['off'])[0]
        v = (raw + ps_c - m) & 0xFFFFFFFF
        if v == 0xFFFFFFFF:
            if pc != 0: chain_bad += 1
        elif v != prev_end: chain_bad += 1
        prev_end += pc
    check('paramStart chain sample', chain_bad == 0, f'{chain_bad} violations in 20k rows')

    # --- parameter table: name/type decodes ---------------------------------
    pb = tbase(ml['param']['table']); pst = ml['param']['stride']
    pm = mr.mask_fn(ml['param']['mask'])
    pt = ml['param']['type']; pnm = ml['param']['name']
    ok = bad = 0
    for t in range(20000):
        a = t * pst; m = pm(t)
        nm = cipher.dec(body, ((struct.unpack_from('<I', body, pb + a + pnm['off'])[0] + h(pnm['c'])) & 0xFFFFFFFF) ^ m)
        ty = (((struct.unpack_from('<I', body, pb + a + pt['off'])[0] + h(pt['c'])) & 0xFFFFFFFF) ^ m) & 0xFFFFFFFF
        if nm is None and ty == 0xFFFFFFFF: bad += 1
        else: ok += 1
    check('param name/type sample', ok >= 19990, f'{ok} decoded / {bad} empty')

    # --- property table: names + accessor semantics -------------------------
    pl = json.load(open(f'{ART}/property-layout.json'))
    pb2 = tbase(pl['table']); ps2 = pl['stride']; mk = pl['mask']
    def pmask(i):
        x = ((i * h(mk['mul1'])) & 0xFFFFFFFFFFFFFFFF) ^ h(mk['xor1'])
        x = (x * h(mk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        x = (x + h(mk['add1'])) & 0xFFFFFFFFFFFFFFFF
        x ^= h(mk['xor2'])
        return ((x + h(mk['add2'])) & 0xFFFFFFFFFFFFFFFF) & 0xFFFFFFFF
    pcol = pl['columns']['name']
    pid = 0
    for i in range(20000):
        raw = struct.unpack_from('<I', body, pb2 + i * ps2 + pcol['off'])[0]
        s = cipher.dec(body, ((raw ^ h(pcol['c'])) - pmask(i)) & 0xFFFFFFFF)
        if s and idre.match(s): pid += 1
    check('property name sample', pid >= 19700, f'{pid}/20000 identifiers')

    # --- field table: names + type range ------------------------------------
    fl = json.load(open(f'{ART}/field-layout.json'))
    fb = tbase(fl['table']); fst = fl['stride']; frows = fl['rows']; fmk = fl['mask']
    def fmask(i):
        x = ((i * h(fmk['mul1'])) & 0xFFFFFFFFFFFFFFFF) >> fmk['shr1']
        x = (x * h(fmk['mul2'])) & 0xFFFFFFFFFFFFFFFF
        return ((x + h(fmk['add1'])) & 0xFFFFFFFFFFFFFFFF) >> fmk['shr2'] & 0xFFFFFFFF
    fcol = fl['columns']['name']; tcol = fl['columns']['type']
    fid = fsent = 0
    for i in range(20000):
        raw = struct.unpack_from('<I', body, fb + i * fst + fcol['off'])[0]
        s = cipher.dec(body, ((raw ^ h(fcol['c'])) - fmask(i)) & 0xFFFFFFFF)
        if s is None: fsent += 1
        elif idre.match(s): fid += 1
    check('field name sample', fid >= 19300, f'{fid} ids / {fsent} none')
    tmax = 0
    for i in range(20000):
        raw = struct.unpack_from('<I', body, fb + i * fst + tcol['off'])[0]
        v = (raw + h(tcol['c']) - fmask(i)) & 0xFFFFFFFF
        if v > tmax: tmax = v
    check('field type range', tmax <= 300000, f'max type index {tmax} in 20k rows')

    # --- typearr + corrected return type column -----------------------------
    ta = json.load(open(f'{ART}/typearr.json'))
    N = ta['count']; exe_d = open(sites['exe'], 'rb').read(); ta_off = int(ta['file_off'], 16)
    rcol = ml['method']['columns']['return_type']
    rv = 0; void = 0
    for i in range(50000):
        raw = struct.unpack_from('<I', body, mb + i * ms + rcol['off'])[0]
        v = (((raw ^ h(rcol['c'])) - mf(i)) & 0xFFFFFFFF)
        rv += 1
        if v >= N: rv = -10**9; break
        if exe_d[ta_off + 16 * v + 10] == 0x01: void += 1
    check('return type column', rv >= 0 and void >= 24000,
          f'{void}/50000 resolve to System.Void, all in-typearr')

    failed = [n for n, ok, _ in checks if not ok]
    print()
    if failed:
        print('VERIFY FAILED:', ', '.join(failed))
        sys.exit(1)
    print(f'VERIFY PASS ({len(checks)} checks)')

if __name__ == '__main__':
    main()
