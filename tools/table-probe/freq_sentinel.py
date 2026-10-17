import sys, numpy as np

path = sys.argv[1]; dat = open(path, "rb").read(); body = dat[0x210:]
stride = int(sys.argv[2], 16)
b = np.frombuffer(body, dtype=np.uint8)
n = len(b)
print("body %d bytes, stride 0x%X" % (n, stride))
base_ref = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
if base_ref is not None:
    print("reference base 0x%X -> residue %d (0x%X)" % (base_ref, base_ref % stride, base_ref % stride))
rows = []
for r in range(stride):
    off = np.arange(r, n - 3, stride, dtype=np.int64)
    if off.size == 0: continue
    v = (b[off].astype(np.uint32) | (b[off+1].astype(np.uint32) << 8)
         | (b[off+2].astype(np.uint32) << 16) | (b[off+3].astype(np.uint32) << 24))
    u, c = np.unique(v, return_counts=True)
    k = np.argsort(-c)[:3]
    rows.append((int(c[k[0]]), r, int(u[k[0]]), int(u[k[1]]), int(c[k[1]]), int(u[k[2]]), int(c[k[2]]), off.size))
rows.sort(reverse=True)
print("cnt_max  res  value_max   2nd value  cnt2    3rd value  cnt3    positions")
for c0, r, u0, u1, c1, u2, c2, tot in rows[:12]:
    print("%8d  0x%02X 0x%08X  0x%08X %6d  0x%08X %6d  %d" % (c0, r, u0, u1, c1, u2, c2, tot))
