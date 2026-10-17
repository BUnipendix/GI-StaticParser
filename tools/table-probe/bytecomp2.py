import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
s = int(sys.argv[2], 16)
d = b[:n-s] ^ b[s:]
M = (d == 0) | (d == 0xFF)
p0 = 0x48F3FD8 + 3
idx = p0 + 70*np.arange(4, 46)
print("byte:", " ".join("%02X" % b[i] for i in idx))
print("M   :", " ".join("%d" % M[i] for i in idx))
C = M; step = 1
while step < 32:
    sh = step * s
    if sh >= C.size: break
    C = C[:C.size-sh] & C[sh:]
    step *= 2
print("C   :", " ".join("%d" % C[i] for i in idx if i < C.size))
z = np.flatnonzero(~C)
bounds = np.concatenate(([-1], z, [C.size]))
lens = (bounds[1:] - 1) - (bounds[:-1] + 1) + 1
o = np.argsort(-lens)[:6]
print("max runs (rows):", [(int(lens[k]//s+33), hex(int(bounds[:-1][k]+1))) for k in o])
print("C.size=%d C.true=%d" % (C.size, int(C.sum())))
