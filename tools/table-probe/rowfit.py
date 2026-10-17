import sys, numpy as np, struct, collections
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
s = int(sys.argv[2], 16)
MINR = int(sys.argv[3]) if len(sys.argv) > 3 else 20000
TOP = int(sys.argv[4]) if len(sys.argv) > 4 else 20
d = b[:n-s] ^ b[s:]
M = (d == 0) | (d == 0xFF)
C = M; step = 1
while step < 32:
    sh = step * s
    if sh >= C.size: break
    C = C[:C.size-sh] & C[sh:]
    step *= 2
m = C.size // s
R = C[:m*s].reshape(m, s)
def u32(p): return struct.unpack_from("<I", body, p)[0] if 0 <= p and p+4 <= n else None
res = []
for r in range(s):
    col = R[:, r]
    z = np.flatnonzero(~col)
    bounds = np.concatenate(([-1], z, [col.size]))
    starts = bounds[:-1]+1; lens = (bounds[1:]-1)-starts+1
    for k in np.flatnonzero(lens >= MINR):
        a = int(starts[k]); L = int(lens[k])
        q0 = a*s + r - 3
        if q0 < 0: continue
        raw = np.array([u32(q0 + i*s) for i in range(0, L, max(1, L//3000))])
        raw = raw[raw != None]
        tb, cnt = np.unique(raw >> 24, return_counts=True)
        if tb.size != 2: continue
        if int(tb[0]) ^ int(tb[1]) != 0xFF: continue
        # one class must be a single repeated raw (the sentinel)
        sent = None
        for t in tb:
            vs = raw[(raw >> 24) == t]
            if np.unique(vs).size == 1 and vs.size >= 2:
                sent = int(vs[0]); break
        if sent is None: continue
        Cc = (~sent) & 0xFFFFFFFF
        fs = raw ^ Cc
        real = int(((raw >> 24) == (Cc >> 24)).sum())
        mx = int(fs[(raw >> 24) == (Cc >> 24)].max()) if real else 0
        res.append((L, r, a, q0, int(tb[0]), int(tb[1]), sent, real, mx))
res.sort(reverse=True)
print("stride 0x%X  rows_total %d  real-fit runs: %d" % (s, m, len(res)))
print("  rows    phase startrow   u32pos       classes    sentinel     maxidx")
for L, r, a, q0, t0, t1, sent, real, mx in res[:TOP]:
    print("  %7d 0x%02X %8d   0x%08X  0x%02X/0x%02X  0x%08X  %d" % (L, r, a, q0, t0, t1, sent, mx))
