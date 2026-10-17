import sys, struct
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
base = int(sys.argv[2], 16); stride = int(sys.argv[3], 16)
off = int(sys.argv[4], 16); sent = int(sys.argv[5], 16); shift = int(sys.argv[6])
C = (~sent) & 0xFFFFFFFF
def rd(w, p):
    if p < 0 or p + w > len(body): return None
    return int.from_bytes(body[p:p+w], "little")
anchor = C >> shift
N = int(sys.argv[7]) if len(sys.argv) > 7 else 4000
fs = []
for i in range(N):
    raw = rd(4, base + stride*i + off)
    fs.append(-1 if (raw is None or (raw >> shift) != anchor) else (raw ^ C))
real_idx = [i for i in range(N) if fs[i] >= 0]
print("real rows in first %d: %d  (first real row %s)" % (N, len(real_idx), real_idx[0] if real_idx else None))
deltas = {}
for k in range(len(real_idx)-1):
    i, j = real_idx[k], real_idx[k+1]
    deltas[i] = fs[j] - fs[i]
best = []
for ds in (-3,-2,-1,0,1,2,3):
    for off2 in range(stride):
        for width, mask in ((1,0xFF),(2,0xFFFF),(4,0xFFFFFFFF)):
            for op in ("xor","add"):
                c = None; streak = 0; bad = None
                for k in range(len(real_idx)-1):
                    i = real_idx[k]; d = deltas[i]
                    if d > mask: bad = i; break
                    v = rd(width, base + stride*(i+ds) + off2)
                    if v is None: bad = i; break
                    cur = (v ^ d) if op == "xor" else ((v - d) & mask)
                    if c is None: c = cur
                    elif c != cur: bad = i; break
                    streak += 1
                best.append((0 if bad is None else 1, -streak, ds, off2, width, op, c, bad))
best.sort()
print("rowshift  off2  width  op   streak  constant   first_bad")
for b in best[:12]:
    print("  %+d      0x%02X   %d     %-3s  %-7d 0x%X  %s" % (b[2], b[3], b[4], b[5], -b[1], b[6] if b[6] is not None else 0, b[7]))
print("total real-real pairs: %d" % (len(real_idx)-1))
