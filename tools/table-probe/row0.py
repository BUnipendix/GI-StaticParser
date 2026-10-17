import sys, struct
dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
base = int(sys.argv[2], 16); stride = int(sys.argv[3], 16); off = int(sys.argv[4], 16)
C = int(sys.argv[5], 16)
for i in range(12):
    p = base + stride*i + off
    raw = struct.unpack_from("<I", body, p)[0]
    print("row %2d  pos=0x%08X raw=0x%08X  raw^C=0x%08X" % (i, p, raw, raw ^ C))
