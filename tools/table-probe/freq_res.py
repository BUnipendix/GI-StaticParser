import sys, numpy as np
path = sys.argv[1]; dat = open(path, "rb").read(); body = dat[0x210:]
stride = int(sys.argv[2], 16)
ref = int(sys.argv[3], 16)
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
BORING = {0x00000000, 0xFFFFFFFF, 0xFFFF0000, 0xFF000064, 0xFFFFFF00, 0x0000FFFF}
r = ref % stride
off = np.arange(r, n - 3, stride, dtype=np.int64)
v = (b[off].astype(np.uint32) | (b[off+1].astype(np.uint32) << 8)
     | (b[off+2].astype(np.uint32) << 16) | (b[off+3].astype(np.uint32) << 24))
print("residue 0x%X over %d positions" % (r, off.size))
u, c = np.unique(v, return_counts=True)
order = np.argsort(-c)
for i in order[:15]:
    uu = int(u[i]); cc = int(c[i])
    if uu in BORING:
        print("  0x%08X  %8d   (boring constant run)" % (uu, cc)); continue
    pos = off[v == uu]
    d = np.diff(pos)
    print("  0x%08X  %8d   first=0x%X last=0x%X  diffs==stride: %d/%d  maxdiff=%d"
          % (uu, cc, pos[0], pos[-1], int((d == stride).sum()), d.size, int(d.max()) if d.size else 0))
