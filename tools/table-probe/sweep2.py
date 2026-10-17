import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
S0 = int(sys.argv[2], 16); S1 = int(sys.argv[3], 16)
FAM = sys.argv[4] if len(sys.argv) > 4 else "add"
MINRUN = int(sys.argv[5]) if len(sys.argv) > 5 else 20000
hits = []
for s in range(S0, S1+1):
    if s < 8: continue
    dv = (b[:n-s].astype(np.int16) - b[s:].astype(np.int16)) & 0xFF
    if FAM == "xor":
        M = (dv == 0) | (dv == 0xFF)
    else:
        M = (dv == 0) | (dv == 1) | (dv == 0xFF)
    C = M; st = 1
    while st < 32:
        sh = st*s
        if sh >= C.size: break
        C = C[:C.size-sh] & C[sh:]
        st *= 2
    m = C.size // s
    R = C[:m*s].reshape(m, s)
    for r in range(s):
        col = R[:, r]
        z = np.flatnonzero(~col)
        bounds = np.concatenate(([-1], z, [col.size]))
        starts = bounds[:-1]+1; lens = (bounds[1:]-1)-starts+1
        for k in np.flatnonzero(lens >= MINRUN):
            a = int(starts[k]); L = int(lens[k])
            q0 = a*s + r - 3
            if q0 < 0 or q0 + (L-1)*s + 4 > n: continue
            idx = q0 + np.arange(L, dtype=np.int64)*s
            raw = (b[idx].astype(np.uint64) | (b[idx+1].astype(np.uint64) << 8)
                   | (b[idx+2].astype(np.uint64) << 16) | (b[idx+3].astype(np.uint64) << 24))
            if FAM == "xor":
                tb, tc = np.unique(raw >> 24, return_counts=True)
                if tb.size != 2: continue
                if int(tb[0]) ^ int(tb[1]) != 0xFF: continue
                sent = None
                for t in tb:
                    vs = raw[(raw >> 24) == t]
                    if np.unique(vs).size == 1 and vs.size >= 2:
                        sent = int(vs[0]); break
                if sent is None: continue
                Cc = (~sent) & 0xFFFFFFFF
                isreal = (raw >> 24) == (Cc >> 24)
                fs = raw ^ Cc
                if not np.all(np.diff(fs[isreal]) >= 0): continue
                dist = np.unique(fs[isreal]).size
                if dist < 8: continue
                mx = int(fs[isreal].max())
                if mx >= (1 << 24): continue
                hits.append((int(isreal.sum()), s, r, q0, int(tb[0]), int(tb[1]), sent, mx, dist))
            else:
                # For the additive family the sentinel is C-1, i.e. strictly BELOW the
                # real window, so it is the smallest raw value. Only that one needs testing.
                v0 = int(raw.min())
                if (raw == v0).sum() < 2: continue
                others = raw[raw != v0]
                if others.size < MINRUN: continue
                lo = int(others.min()); hi = int(others.max())
                w = hi - lo + 1
                sh = 16
                while (1 << sh) < w: sh += 1
                if sh > 24: continue
                fs = others - lo
                if not np.all(np.diff(fs) >= 0): continue
                du = np.unique(fs)
                if du.size < 8: continue
                hits.append((int(others.size), s, r, q0, -1, -1, v0, int(fs.max()), int(du.size)))
    del dv, M, C, R
hits.sort(reverse=True)
print("family=%s strides 0x%X..0x%X  full-pass candidates: %d" % (FAM, S0, S1, len(hits)))
print("  real   stride phase u32pos       sentinel     maxidx    distinct")
n = 0
for real, s, r, q0, t0, t1, sent, mx, dist in hits:
    if dist < 0.8 * real: continue
    print("  %6d 0x%03X  0x%02X  0x%08X  0x%08X  %8d  %d" % (real, s, r, q0, sent, mx, dist))
    n += 1
    if n >= 40: break
if n == 0: print("  (none after the distinct >= 0.8*real filter)")
