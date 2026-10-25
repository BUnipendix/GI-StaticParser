#!/usr/bin/env python3
"""Hunt per-row mask-chain functions by code SHAPE (not by fingerprint transfer).

A mask chain compiles to a tight cluster of big-immediate arithmetic:
    imul r, r, imm32 | movabs+imul | xor/add r, imm32 | shr r, imm8
Scanning .text for `imul reg, rm, imm32` (0x69 /r id with REX.W) hits whose
immediate looks random (> 0xFFFF, not 2^k), clustering hits that lie within
~96 bytes of each other, and running the symwalk Walker over each cluster
window yields candidate chains -- constants included -- without knowing which
function reads which table. Downstream validators (name decode, tiling)
decide which chain belongs to which table.

Usage:
  chain_hunt.py <exe> --blob-va 0x.. [--hdr-global 0x..] [--out chains.json]
                 [--win 0x400] [--max-clusters 4000]
"""
import argparse, json, struct, sys
import numpy as np

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from symwalk import Walker, walk_window, expr_str, expr_syms, expr_has  # noqa: E402


def sections(d):
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
        ch = struct.unpack_from('<I', d, o + 36)[0]
        secs.append((va, vsz, roff, min(rsz, len(d) - roff), ch))
    return ib, secs


def find_imul_clusters(d, secs, gap=96):
    """Offsets (file) of imul r,rm,imm32 sites with random-looking imm32,
    grouped into clusters of nearby hits. Vectorized scan."""
    hits = []
    for va, vsz, roff, rsz, ch in secs:
        if not (ch & 0x20000000) or rsz < 16:
            continue
        b = np.frombuffer(d[roff:roff + rsz], dtype=np.uint8)
        m = (b[:-10] == 0x69) & ((b[1:-9] & 0xC0) == 0xC0)
        idx = np.nonzero(m)[0]
        if len(idx) == 0:
            continue
        di = idx + 2
        imm = (b[di].astype(np.uint64) | (b[di + 1].astype(np.uint64) << 8)
               | (b[di + 2].astype(np.uint64) << 16) | (b[di + 3].astype(np.uint64) << 24))
        keep = (imm > 0xFFFF) & (imm < 0xFE000000)
        pow2 = imm & (imm - 1)
        keep &= pow2 != 0
        for k in np.nonzero(keep)[0]:
            i = int(idx[k])
            rex = i > 0 and 0x40 <= b[i - 1] <= 0x4F
            hits.append((roff + i - (1 if rex else 0), int(imm[k]), bool(rex)))
    hits.sort()
    clusters = []
    cur = []
    for h in hits:
        if cur and h[0] - cur[-1][0] > gap:
            if len(cur) >= 2:
                clusters.append(cur)
            cur = []
        cur.append(h)
    if len(cur) >= 2:
        clusters.append(cur)
    return clusters


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('exe')
    ap.add_argument('--blob-va', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--hdr-global', type=lambda x: int(x, 0), default=None)
    ap.add_argument('--out', default=None)
    ap.add_argument('--win', type=lambda x: int(x, 0), default=0x400)
    ap.add_argument('--max-clusters', type=int, default=4000)
    a = ap.parse_args()

    d = open(a.exe, 'rb').read()
    ib, secs = sections(d)
    clusters = find_imul_clusters(d, secs)
    print(f'{len(clusters)} immul clusters (>=2 hits within 96B)', file=sys.stderr)

    def has_big_mul(e):
        if not isinstance(e, (list, tuple)): return False
        if e[0] == 'op2' and e[1] == '*' and e[3][0] == 'imm' and e[3][1] > 0xFFFF:
            return True
        return any(has_big_mul(x) for x in e[1:] if isinstance(x, (list, tuple)))

    pool = {}
    # file offset -> VA
    def file2va(fo):
        for va, vsz, roff, rsz, ch in secs:
            if roff <= fo < roff + rsz:
                return ib + va + (fo - roff)
        return None

    walked = 0
    for cl in clusters[:a.max_clusters]:
        center = (cl[0][0] + cl[-1][0]) // 2
        va = file2va(center)
        if va is None:
            continue
        for back in (0x20, 0x48, 0x70):
            w = Walker(a.exe, a.blob_va, a.hdr_global)
            n = walk_window(w, va - back, a.win)
            if n < 12:
                continue
            walked += 1
            for key, rec in w.chains.items():
                e = rec['expr']
                sy = expr_syms(e)
                if len(sy) != 1 or expr_has(e, 'raw') or expr_has(e, 'hdr'):
                    continue
                if any(x.startswith(('mem', 'post_call', 'mulhi', 'glob')) for x in sy):
                    continue
                if has_big_mul(e) and key not in pool:
                    pool[key] = dict(expr=e, site=hex(va - back), imm=hex(cl[0][1]))
            break
    out = list(pool.values())
    if a.out:
        json.dump(out, open(a.out, 'w'))
    print(f'walked {walked} clusters -> {len(out)} distinct chains', file=sys.stderr)
    for c in out[:20]:
        print(' ', c['site'], c['imm'], expr_str(c['expr'])[:110])


if __name__ == '__main__':
    main()
