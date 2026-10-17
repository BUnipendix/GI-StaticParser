import struct, sys, collections

dat = open(sys.argv[1], "rb").read()
body = dat[0x210:]
base = int(sys.argv[2], 16); stride = int(sys.argv[3], 16); off = int(sys.argv[4], 16)
def u32(i):
    p = base + stride*i + off
    if p+4 > len(body): return None
    return struct.unpack_from("<I", body, p)[0]
print("body len 0x%X" % len(body))
print("first 48 raws of column off=0x%X at stride 0x%X:" % (off, stride))
for i in range(48):
    v = u32(i)
    print("  row %3d  raw=0x%08X   hi16=0x%04X hi12=0x%03X hi8=0x%02X" % (i, v, v>>16, v>>20, v>>24))
