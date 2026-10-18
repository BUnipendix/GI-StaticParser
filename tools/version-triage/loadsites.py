
#!/usr/bin/env python3
"""Recover every rip-relative load of the MHY header global and a normalized
instruction fingerprint for the function that performs it.

Usage: loadsites.py <exe> <out.json> [--fp-len 0x180]
Output: {blob_va, hdr_global, body_global, sites: [{site, fp:[tokens]}]}
"""
import struct, json, sys, re, time
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def pe(path):
    d = open(path, 'rb').read()
    pe_off = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe_off + 6)[0]
    opt = pe_off + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    ib = struct.unpack_from('<Q', d, opt + 24)[0] if magic == 0x20b else struct.unpack_from('<I', d, opt + 28)[0]
    secoff = opt + struct.unpack_from('<H', d, pe_off + 20)[0]
    secs = []
    for i in range(nsec):
        o = secoff + i * 40
        vsz, va, rsz, roff = struct.unpack_from('<IIII', d, o + 8)
        ch = struct.unpack_from('<I', d, o + 36)[0]
        secs.append(dict(va=va, vsz=vsz, roff=roff, rsz=min(rsz, len(d) - roff), ch=ch))
    return d, ib, secs

def va2file(ib, secs, va):
    rva = va - ib
    for s in secs:
        if s['va'] <= rva < s['va'] + max(s['vsz'], s['rsz']):
            return s['roff'] + (rva - s['va'])

def find_blob(d, ib, secs):
    for s in secs:
        i = d[s['roff']:s['roff'] + s['rsz']].find(b'MHY\0')
        if i >= 0:
            return ib + s['va'] + i

def rip_refs(d, ib, secs):
    bb = np.frombuffer(d, dtype=np.uint8)
    out = []
    for s in secs:
        if not (s['ch'] & 0x20000000):
            continue
        n, roff = s['rsz'], s['roff']
        b = bb[roff:roff + n]
        m = ((b[:-7] == 0x48) | (b[:-7] == 0x4c) | (b[:-7] == 0x4d) | (b[:-7] == 0x49)) \
            & ((b[1:-6] == 0x8b) | (b[1:-6] == 0x8d) | (b[1:-6] == 0x89)) \
            & ((b[2:-5] & 0xc7) == 0x05)
        idx = np.nonzero(m)[0].astype(np.int64)
        if len(idx) == 0:
            continue
        di = idx + roff + 3
        v = (bb[di].astype(np.int64) | (bb[di+1].astype(np.int64) << 8)
             | (bb[di+2].astype(np.int64) << 16) | (bb[di+3].astype(np.int64) << 24))
        v = (v ^ 0x80000000) - 0x80000000
        sites = ib + s['va'] + idx
        tg = (sites + 7 + v).astype(np.uint64)
        ops = b[1:-6][idx]
        for k in range(len(idx)):
            out.append((int(ops[k]), int(tg[k]), int(idx[k]), s))
    return out

def find_hg(d, ib, secs, blob_va):
    refs = rip_refs(d, ib, secs)
    for op, tg, si, s in refs:
        if op == 0x8d and tg == blob_va:
            fo = s['roff'] + si + 7
            if d[fo] in (0x48, 0x4c, 0x4d, 0x49) and d[fo+1] == 0x89 and (d[fo+2] & 0xc7) == 0x05:
                disp2 = struct.unpack_from('<i', d, fo + 3)[0]
                s2 = ib + s['va'] + si + 7
                return (s2 + 7 + disp2) & 0xFFFFFFFFFFFFFFFF
    return None

MD = Cs(CS_ARCH_X86, CS_MODE_64)

def fingerprint(d, ib, secs, site, n):
    fo = va2file(ib, secs, site)
    code = d[fo:fo + n]
    toks = []
    for ins in MD.disasm(code, site):
        ops = re.sub(r'0x[0-9a-fA-F]+', '#', ins.op_str)
        ops = re.sub(r'\b\d+\b', '#', ops)
        toks.append(ins.mnemonic + ' ' + ops)
        if ins.mnemonic == 'ret':
            break
    return toks

def main():
    exe, out = sys.argv[1], sys.argv[2]
    n = 0x180
    if '--fp-len' in sys.argv:
        n = int(sys.argv[sys.argv.index('--fp-len') + 1], 0)
    t0 = time.time()
    d, ib, secs = pe(exe)
    blob = find_blob(d, ib, secs)
    hg = find_hg(d, ib, secs, blob)
    refs = rip_refs(d, ib, secs)
    sites = sorted({ib + s['va'] + si for op, tg, si, s in refs if op == 0x8b and tg == hg})
    fps = {s: fingerprint(d, ib, secs, s, n) for s in sites}
    json.dump(dict(exe=exe, blob_va=blob, hdr_global=hg, body_global=hg + 8 if hg else None,
                   sites=[dict(site=s, fp=fps[s]) for s in sites]),
              open(out, 'w'))
    print(f'{exe}: blob={hex(blob) if blob else None} hg={hex(hg) if hg else None} sites={len(sites)} t={time.time()-t0:.1f}s', flush=True)

if __name__ == '__main__':
    main()
