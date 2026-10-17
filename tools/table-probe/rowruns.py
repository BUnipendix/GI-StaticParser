import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
s = int(sys.argv[2], 16)
MINR = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
TOP = int(sys.argv[4]) if len(sys.argv) > 4 else 30
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
res = []
for r in range(s):
    col = R[:, r]
    z = np.flatnonzero(~col)
    bounds = np.concatenate(([-1], z, [col.size]))
    starts = bounds[:-1] + 1; lens = (bounds[1:] - 1) - starts + 1
    for k in np.flatnonzero(lens >= MINR):
        a = int(starts[k]); L = int(lens[k])
        q0 = a*s + r - 3
        if q0 < 0: continue
        val = int(b[a*s + r])
        cnt = min(L, 20000); st = max(1, cnt // 4000)
        seen = set()
        for i in range(0, cnt, st):
            q = q0 + i*s
            if q + 4 > n: break
            seen.add(int.from_bytes(body[q:q+4], "little"))
        res.append((L, r, a, q0, val, len(seen)))
res.sort(reverse=True)
print("stride 0x%X  body %d  rows_total %d  runs>=%d : %d" % (s, n, m, MINR, len(res)))
print("  rows    phase  startrow  u32pos       byte  distinct")
for L, r, a, q0, val, dis in res[:TOP]:
    print("  %7d 0x%02X   %7d   0x%08X  0x%02X  %d" % (L, r, a, q0, val, dis))
