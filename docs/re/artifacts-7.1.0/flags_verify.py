import struct
exe=open('/home/yangsanyi/kuna_in/710/YuanShen.exe','rb').read()
e=struct.unpack('<I',exe[0x3C:0x40])[0]
nsec=struct.unpack('<H',exe[e+6:e+8])[0]; optsz=struct.unpack('<H',exe[e+20:e+22])[0]
ib=struct.unpack('<Q',exe[e+24+24:e+24+32])[0]
secs=[]
for i in range(nsec):
    o=e+24+optsz+40*i
    nm=exe[o:o+8].rstrip(b'\x00').decode('latin1')
    vsz,va,rsz,ro=struct.unpack('<IIII',exe[o+8:o+24])
    secs.append((nm,ib+va,vsz,ro,rsz))
def read(va,n):
    for (nm,sva,vsz,ro,rsz) in secs:
        if sva<=va<sva+max(vsz,rsz): return exe[ro+(va-sva):ro+(va-sva)+n]
hdr=read(0x1427D5CB0,0x210)
body=open('/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/global-metadata.dat','rb').read()[0x210:]
def u32(b,o): return struct.unpack('<I',b[o:o+4])[0]
def u16(b,o): return struct.unpack('<H',b[o:o+2])[0]
tdoff=u32(hdr,0xDC)^0x5278CA3B
n=(u32(hdr,0x60)^0x15335474)//0x46
# flags = u32(row+0x0C) - 0x205F6070 ; bitfield = u16(row+0x32) ^ 0x8BA4
# bit0=IsValueType bit1=IsEnum (Il2CppDumper semantics); kind rendering per Il2CppDecompiler.cs
for i in range(min(n,20)):
    r=tdoff+i*0x46
    flags=(u32(body,r+0xC)-0x205F6070)&0xFFFFFFFF
    bf=u16(body,r+0x32)^0x8BA4
    print(i,hex(flags),hex(bf))
