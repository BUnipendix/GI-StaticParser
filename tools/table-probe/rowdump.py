import sys, struct
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
base = int(sys.argv[2], 16); stride = int(sys.argv[3], 16)
rows = [int(x) for x in sys.argv[4].split(",")]
want = [int(x) for x in sys.argv[5].split(",")]
print("row bytes; want = expected count per row")
print("off  " + " ".join("%6s" % ("r%d" % r) for r in rows))
for o in range(stride - 1):
    vals = []
    for r in rows:
        p = base + stride*r + o
        vals.append(struct.unpack_from("<H", body, p)[0] if p+2 <= len(body) else -1)
    print("0x%02X " % o + " ".join("%6d" % v for v in vals))
print()
print("want  " + " ".join("%6d" % w for w in want))
