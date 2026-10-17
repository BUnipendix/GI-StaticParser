import sys, struct
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
base = int(sys.argv[2], 16); s = int(sys.argv[3], 16); N = int(sys.argv[4]) if len(sys.argv) > 4 else 48
print("base=0x%X stride=0x%X" % (base, s))
for i in range(N):
    p = base + s*i
    raw = struct.unpack_from("<I", body, p)[0]
    print("  row %3d raw=0x%08X top=0x%02X  byte3=0x%02X" % (i, raw, raw >> 24, body[p+3]))
