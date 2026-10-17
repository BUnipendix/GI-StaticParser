import sys, numpy as np
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
b = np.frombuffer(body, dtype=np.uint8); n = len(b)
s = int(sys.argv[2], 16)
eq = (b[:n-s] == b[s:])
C = eq; step = 1
while step < 32:
    sh = step * s
    if sh >= C.size: break
    C = C[:C.size-sh] & C[sh:]
    step *= 2
z = np.flatnonzero(~C)
bounds = np.concatenate(([-1], z, [C.size]))
starts = bounds[:-1] + 1; ends = bounds[1:] - 1
lens = ends - starts + 1
order = np.argsort(-lens)[:8]
print("top runs (no MINR filter):")
for k in order:
    a = int(starts[k]); L = int(lens[k]); rows = L // s + 33
    print("  0x%08X  len=%-9d rows=%-8d byte=0x%02X" % (a, L, rows, int(b[a])))
print()
print("probe: byte at 0x48F3FD8+3 + 70*i for i=4..40 (expect 0x72):")
p0 = 0x48F3FD8 + 3
print("  " + " ".join("%02X" % b[p0 + 70*i] for i in range(4, 40)))
print("probe: byte at 0x48F3FDB+70i step check around row 1000:")
print("  " + " ".join("%02X" % b[p0 + 70*i] for i in range(1000, 1032)))
