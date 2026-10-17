import struct, sys, collections

dat = open(sys.argv[1], "rb").read()
body = dat[0x210:]
base = int(sys.argv[2], 16); stride = int(sys.argv[3], 16)
N = int(sys.argv[4]) if len(sys.argv) > 4 else 200
def u32(row, off):
    p = base + stride*row + off
    if p+4 > len(body): return None
    return struct.unpack_from("<I", body, p)[0]
print("base=0x%X stride=0x%X rows_sampled=%d" % (base, stride, N))
print("off  shift24classes(top)                                        ident-class  run")
for off in range(stride - 3):
    cls = collections.defaultdict(list)
    for r in range(N):
        v = u32(r, off)
        if v is None: break
        cls[v >> 24].append(v)
    # identical class = every member has the same raw
    ident = [h for h, vs in cls.items() if len(set(vs)) == 1 and len(vs) >= 2]
    top = sorted(cls.items(), key=lambda kv: -len(kv[1]))[:3]
    ts = " ".join("0x%02X:%d" % (h, len(vs)) for h, vs in top)
    print("0x%02X  %-46s %-12s" % (off, ts, ",".join("0x%02X" % h for h in ident)))
