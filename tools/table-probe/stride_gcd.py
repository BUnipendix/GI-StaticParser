import sys, numpy as np
from math import gcd
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
s = int(sys.argv[2], 16)
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
ART = {0x00000000, 0xFFFFFFFF, 0xFFFF0000, 0x0000FFFF, 0xFF000064, 0xFFFFFF00}
best = []
for r in range(s):
    off = np.arange(r, n - 3, s, dtype=np.int64)
    if off.size < 10: continue
    v = (b[off].astype(np.uint32) | (b[off+1].astype(np.uint32) << 8)
         | (b[off+2].astype(np.uint32) << 16) | (b[off+3].astype(np.uint32) << 24))
    u, c = np.unique(v, return_counts=True)
    top = np.argsort(-c)[:6]
    for k in top:
        val = int(u[k])
        if val in ART: continue
        if int(c[k]) < 3000: continue
        pos = off[v == u[k]]
        d = np.diff(pos)
        g = 0
        for x in d[:4000]: g = gcd(g, int(x))
        best.append((int(c[k]), r, val, g, int(pos[0]), int(pos[-1]), d.size))
    del v, u, c
best.sort(reverse=True)
print("stride 0x%X: top non-artifact values per residue" % s)
print("count    res  value       gcd(diffs)  first        last         npos")
for h in best[:8]:
    print("%7d  0x%02X 0x%08X  0x%06X    0x%08X   0x%08X  %d" % h)
