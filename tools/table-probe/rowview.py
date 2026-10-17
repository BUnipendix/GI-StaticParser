import sys, struct
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
base = int(sys.argv[2], 16); s = int(sys.argv[3], 16)
def u32(p): return struct.unpack_from("<I", body, p)[0] if p+4 <= len(body) else 0
def u16(p): return struct.unpack_from("<H", body, p)[0] if p+2 <= len(body) else 0
print("row bytes at base=0x%X stride=0x%X" % (base, s))
print("off  u32(row0)   u32(row1)   d0-1    u32(row2)   topbytes(r0..r4)")
for o in range(0, s-3):
    v = [u32(base + s*i + o) for i in range(5)]
    print("0x%02X 0x%08X 0x%08X %-8d 0x%08X  %s" % (o, v[0], v[1], (v[1]-v[0]) & 0xFFFFFFFF, v[2],
          " ".join("%02X" % (x >> 24) for x in v)))
print()
print("row0 all u16 at offsets 0..0x44:")
print("  " + " ".join("%04X" % u16(base + o) for o in range(0, s-1, 2)))
print("row1 all u16:")
print("  " + " ".join("%04X" % u16(base + s + o) for o in range(0, s-1, 2)))
