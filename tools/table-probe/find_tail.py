import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
s = int(sys.argv[2], 16)
W0 = int(sys.argv[3], 16); W1 = int(sys.argv[4], 16)
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
W1 = min(W1, n)
print("stride 0x%X  window 0x%X..0x%X of 0x%X" % (s, W0, W1, n))
ART = {0x00000000, 0xFFFFFFFF, 0xFFFF0000, 0x0000FFFF, 0xFF000064, 0xFFFFFF00}
hits = []
for r in range(s):
    off = np.arange(W0 + ((r - W0) % s), W1 - 3, s, dtype=np.int64)
    if off.size < 10: continue
    v = (b[off].astype(np.uint32) | (b[off+1].astype(np.uint32) << 8)
         | (b[off+2].astype(np.uint32) << 16) | (b[off+3].astype(np.uint32) << 24))
    u, c = np.unique(v, return_counts=True)
    sel = [k for k in np.where(c >= 3000)[0] if int(u[k]) not in ART]
    if sel:
        us = u; idx = np.searchsorted(us, (~u[np.array(sel, dtype=np.int64)]).astype(np.uint32) & 0xFFFFFFFF)
        for k in sel:
            C = (~int(u[k])) & 0xFFFFFFFF
            j = np.searchsorted(us, C)
            if j < us.size and int(us[j]) == C:
                pv = off[v == u[k]]; pC = off[v == C]
                hits.append((int(c[k]), r, int(u[k]), C, int(pv[0]), int(pv[-1]), int(pC[0]), int(pC.size)))
    del v, u, c
hits.sort(reverse=True)
print("count    res  value       C=~v        first_v     last_v      first_C     cnt_C")
for h in hits[:14]:
    print("%7d  0x%02X 0x%08X  0x%08X  0x%08X  0x%08X  0x%08X  %6d" % h)
if not hits: print("(none)")
