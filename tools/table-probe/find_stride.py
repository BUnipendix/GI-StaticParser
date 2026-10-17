import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
S0 = int(sys.argv[2], 16); S1 = int(sys.argv[3], 16)
W0 = int(sys.argv[4], 16); W1 = int(sys.argv[5], 16)
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
W1 = min(W1, n); W0 = max(0, W0)
print("body 0x%X  window 0x%X..0x%X  strides 0x%X..0x%X" % (n, W0, W1, S0, S1))
ART = {0x00000000, 0xFFFFFFFF, 0xFFFF0000, 0x0000FFFF, 0xFF000064, 0xFFFFFF00}
rows = []
for s in range(S0, S1 + 1):
    best = None
    for r in range(s):
        p0 = W0 + ((r - W0) % s)
        off = np.arange(p0, W1 - 3, s, dtype=np.int64)
        if off.size < 200: continue
        v = (b[off].astype(np.uint32) | (b[off+1].astype(np.uint32) << 8)
             | (b[off+2].astype(np.uint32) << 16) | (b[off+3].astype(np.uint32) << 24))
        u, c = np.unique(v, return_counts=True)
        order = np.argsort(-c)
        for k in order[:4]:
            val = int(u[k]); cnt = int(c[k])
            if val in ART or cnt < 2000: continue
            C = (~val) & 0xFFFFFFFF
            j = np.searchsorted(u, C)
            has = j < u.size and int(u[j]) == C
            cC = int(c[j]) if has else 0
            if best is None or cnt > best[0]: best = (cnt, r, val, C, cC)
        del v, u, c
    if best: rows.append((best[0], s, best[1], best[2], best[3], best[4]))
rows.sort(reverse=True)
print("count    stride res  value       C=~v        cnt_C")
for h in rows[:20]:
    print("%7d  0x%03X  0x%02X 0x%08X  0x%08X %6d" % h)
if not rows: print("(no value with count>=2000 outside the boring set)")
