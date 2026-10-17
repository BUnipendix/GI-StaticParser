import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
s = int(sys.argv[2], 16)
MINR = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
# eq[i] = body[i] == body[i+s]
eq = (b[:n-s] == b[s:])
C = eq
step = 1
while step < 32:
    sh = step * s
    if sh >= C.size: break
    C = C[:C.size-sh] & C[sh:]
    step *= 2
print("stride 0x%X  body %d  eq true %d  C len %d  C true %d" % (s, n, int(eq.sum()), C.size, int(C.sum())))
if C.any():
    z = np.flatnonzero(~C)
    bounds = np.concatenate(([-1], z, [C.size]))
    starts = bounds[:-1] + 1
    ends = bounds[1:] - 1
    lens = ends - starts + 1
    order = np.argsort(-lens)[:12]
    print("  start      positions  rows      byte  distinct_u32")
    for k in order:
        a = int(starts[k]); e = int(ends[k]); L = int(lens[k])
        rows = L // s + 33
        if rows < MINR: continue
        val = int(b[a])
        p = a - 3
        cnt = min(rows, 4000)
        vals = []
        for i in range(0, cnt, max(1, cnt // 2000)):
            q = p + i * s
            if q < 0 or q + 4 > n: continue
            vals.append(int.from_bytes(body[q:q+4], "little"))
        print("  0x%08X  %9d %7d   0x%02X  %d" % (a, L, rows, val, len(set(vals))))
