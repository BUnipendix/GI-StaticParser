import struct
dat = open("/home/yangsanyi/gire/sample/gi/6.4.0/YuanShen_Data/Managed/Metadata/global-metadata.dat","rb").read(); body = dat[0x210:]
base = 0xE7579C; stride = 0x46; off = 0x18; c = 0xE169AC15
for r in [0,1,2,3,4,5,6,7,8,100,1000,5000]:
    raw = struct.unpack_from("<I", body, base + stride*r + off)[0]
    print(r, hex((raw + c) & 0xFFFFFFFF))