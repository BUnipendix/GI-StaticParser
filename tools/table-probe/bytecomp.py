import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
s = int(sys.argv[2], 16)
MINR = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
TOP = int(sys.argv[4]) if len(sys.argv) > 4 else 12
# At shift 24 the two classes must XOR to 0xFF, so along the column every adjacent
# pair of rows is either equal or complementary.
d = b[:n-s] ^ b[s:]
M = (d == 0) | (d == 0xFF)
C = M
step = 1
while step < 32:
    sh = step * s
    if sh >= C.size: break
    C = C[:C.size-sh] & C[sh:]
    step *= 2
runs = []
if C.any():
    z = np.flatnonzero(~C)
    bounds = np.concatenate(([-1], z, [C.size]))
    starts = bounds[:-1] + 1; ends = bounds[1:] - 1
    lens = ends - starts + 1
    for k in np.argsort(-lens)[:200]:
        a = int(starts[k]); L = int(lens[k]); rows = L // s + 33
        if rows < MINR: continue
        val = int(b[a])
        q0 = a - 3
        if q0 < 0: continue
        cnt = min(rows, 20000); stride_s = max(1, cnt // 4000)
        seen = set()
        for i in range(0, cnt, stride_s):
            q = q0 + i * s
            if q + 4 > n: break
            seen.add(int.from_bytes(body[q:q+4], "little"))
            if len(seen) > 20000: break
        runs.append((rows, a, L, val, len(seen)))
print("stride 0x%X  body %d  M true %d  C true %d  candidates=%d" % (s, n, int(M.sum()), int(C.sum()), len(runs)))
print("  bytepos     rows      byte  distinct_u32")
for rows, a, L, val, dis in runs[:TOP]:
    print("  0x%08X  %8d  0x%02X  %d" % (a, rows, val, dis))
