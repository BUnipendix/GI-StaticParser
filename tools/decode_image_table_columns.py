import struct
exe=open('/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen.exe','rb').read()
e=struct.unpack_from('<I',exe,0x3C)[0]; nsec=struct.unpack_from('<H',exe,e+6)[0]; optsz=struct.unpack_from('<H',exe,e+20)[0]
secs=[]
for i in range(nsec):
    off=e+24+optsz+i*40
    nm=exe[off:off+8].rstrip(b'\x00').decode(); vsz,va,rsz,ro=struct.unpack_from('<IIII',exe,off+8)
    secs.append((nm,vsz,va,rsz,ro))
def va2off(va):
    rva=va-0x140000000
    for nm,vsz,va2,rsz,ro in secs:
        if va2<=rva<va2+max(vsz,rsz): return ro+(rva-va2)
    return None
header=exe[va2off(0x1427D5CB0):va2off(0x1427D5CB0)+0x210]
startup=open('/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/startup-metadata.dat','rb').read()
base=struct.unpack_from('<I',header,132)[0] ^ 1479489075
rows=75; stride=40
def u32(i,off):
    return struct.unpack_from('<I',startup,base+i*stride+off)[0]
M=(1<<64)-1; M32=(1<<32)-1
def mask(i):
    m=((i*0xBD1E70EB664 & M)>>16)&M32
    m=(m+0x724F4CCB)&M32
    m^=0x2BE02F3D
    return m
def d_sub_add(t,m,c): return ((t-m)+c)&M32
def d_sub_add_xor(t,m,c,x): return ((((t-m)+c)&M32)^x)&M32
def d_xor_sub(t,m,c): return ((t^c)-m)&M32
def d_xor_sub_add(t,m,c,a): return ((((t^c)-m)&M32)+a)&M32
def d_xor_sub_xor(t,m,c,x): return ((((t^c)-m)&M32)^x)&M32
COLS={
 0x00: lambda t,m: d_xor_sub_add(t,m,0x57631D22,0x3A3F5F30),
 0x04: lambda t,m: d_sub_add_xor(t,m,0xBB4B5110,0x4FBFA07B),
 0x08: lambda t,m: d_sub_add_xor(t,m,0x96612B2C,0x7362B478),
 0x0c: lambda t,m: d_xor_sub(t,m,0x1066FCA3),
 0x10: lambda t,m: d_sub_add(t,m,0xD3ED43CA),
 0x14: lambda t,m: d_xor_sub_add(t,m,0x0F90FC6D,0x50105F4F),
 0x1c: lambda t,m: d_sub_add(t,m,0xB789942C),
 0x20: lambda t,m: d_sub_add_xor(t,m,0xD61DDDDC,0x06E0B2A6),
 0x24: lambda t,m: d_xor_sub_xor(t,m,0x40B24EE6,0x07B236BA),
}
vals={off:[COLS[off](u32(i,off),mask(i)) for i in range(rows)] for off in COLS}
for off,v in vals.items():
    print(f'col {off:#04x}: first6={v[:6]} min={min(v)} max={max(v)}')
# test tiling: find (start,cnt) pair
for a in COLS:
    for b in COLS:
        if a==b: continue
        s=vals[a]; c=vals[b]
        if s[0]!=0: continue
        acc=0; ok=True
        for i in range(rows):
            if s[i]!=acc: ok=False; break
            acc+=c[i]
        if ok and acc==88902:
            print('SOLUTION start col',hex(a),'count col',hex(b),'total',acc,'counts',c[:10])
