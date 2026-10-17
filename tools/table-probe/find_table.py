import sys, numpy as np

dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
s = int(sys.argv[2], 16)
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
MINC = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
print("stride 0x%X  body %d bytes  min_count %d" % (s, n, MINC))

hits = []
for r in range(s):
    off = np.arange(r, n - 3, s, dtype=np.int64)
    if off.size < 10: continue
    v = (b[off].astype(np.uint32) | (b[off+1].astype(np.uint32) << 8)
         | (b[off+2].astype(np.uint32) << 16) | (b[off+3].astype(np.uint32) << 24))
    u, c = np.unique(v, return_counts=True)
    sel = np.where(c >= MINC)[0]
    ART = {0x00000000, 0xFFFFFFFF, 0xFFFF0000, 0x0000FFFF, 0xFF000064, 0xFFFFFF00, 0x640000FF}
    sel = np.array([k for k in sel if int(u[k]) not in ART], dtype=np.int64)
    if sel.size == 0: continue
    comp = (~u.astype(np.uint32)) & 0xFFFFFFFF          # C = !v for the XOR family
    # where does the demanded C occur in this same residue class?
    order = np.argsort(u)
    us = u[order]
    idx = np.searchsorted(us, comp[sel])
    ok = (idx < us.size) & (us[np.minimum(idx, us.size-1)] == comp[sel])
    for k, good in zip(sel, ok):
        if not good: continue
        cv = int(c[k]); C = int(comp[k])
        pos_v = off[v == u[k]]
        pos_C = off[v == C]
        hits.append((cv, r, int(u[k]), C, int(pos_v[0]), int(pos_C[0]), int(pos_v[-1]), int(pos_C.size)))
    del v, u, c
hits.sort(reverse=True)
print("count_v  res  value_v     C=~v       first_v     first_C     last_v      cnt_C")
for h in hits[:30]:
    print("%7d  0x%02X 0x%08X  0x%08X  0x%08X  0x%08X  0x%08X  %6d" % h)
if not hits:
    print("(no residue class holds a value whose complement also occurs -- no XOR-family sentinel)")
