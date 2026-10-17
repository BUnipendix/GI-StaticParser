import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
s = int(sys.argv[2], 16)
d = b[:n-s] ^ b[s:]
M = (d == 0) | (d == 0xFF)
C = M; step = 1
while step < 32:
    sh = step * s
    if sh >= C.size: break
    C = C[:C.size-sh] & C[sh:]
    step *= 2
p0 = 0x48F3FD8 + 3
print("checking C at the index column for rows 0..500 step 50, then further")
for row in [0, 50, 100, 500, 1000, 5000, 20000, 50000, 88000, 88800]:
    p = p0 + 70*row
    if p < C.size:
        print("  row %6d  p=0x%08X  M=%d C=%d" % (row, p, M[p], C[p]))
print()
print("M zeros within [p0, p0+70*2000]:")
w = M[p0:p0+70*2000]
zz = np.flatnonzero(~w)
print("  count=%d  first few idx mod 70: %s" % (zz.size, sorted(set((int(x) % 70) for x in zz[:40]))))
print("  first 10 abs: %s" % [hex(p0+int(x)) for x in zz[:10]])
print()
print("C zeros within [p0, p0+70*2000]:")
wc = C[p0:p0+70*2000]
zc = np.flatnonzero(~wc)
print("  count=%d" % zc.size)
print("  first 10 abs: %s" % [hex(p0+int(x)) for x in zc[:10]])
