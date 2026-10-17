
import numpy as np
dat='/home/yangsanyi/gire/sample/gi/4.8.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
buf=np.fromfile(dat,dtype=np.uint8,offset=0x210)
strsec=0x21A78D0
M1=0x9C9BC1DE1BC7E406; X1=0x187E17AE6D781B2A; X2=0x79833B980C2747C1; M4=0x3BF3D8192287239D
M=(1<<64)-1
def u32(o): return int.from_bytes(buf[o:o+4].tobytes(),'little')
def u16(o): return int.from_bytes(buf[o:o+2].tobytes(),'little')
def key(o): return ((((o*M1)&M)+X1)&M)^X2
def dec(idx):
    off=idx&0xFFFFFF; ln=(idx>>24)&0xFF
    if ln==0: return ''
    if ln>200: return '<len %d>'%ln
    k=key(off); out=b''
    for i in range((ln+7)//8):
        v=int.from_bytes(buf[strsec+off+8*i:strsec+off+8*i+8].tobytes(),'little')^k
        out+=v.to_bytes(8,'little'); k=(k+M4)&M
    out=out[:ln]; z=out.find(b'\0')
    return (out[:z] if z>=0 else out).decode('latin1')
base=0x02CC8CC5; stride=0x4A
print('=== 4.8.0 candidate: is any column a name column? ===')
for off in [0x1F,0x2B,0x3F,0x39,0x08,0x14,0x3E]:
    found=None
    for C in [0] :
        pass
    print('  off=0x%02X raw row0=0x%08X row1=0x%08X'%(off,u32(base+off),u32(base+stride+off)))
print('=== tiling check for the reported pair ===')
for (foff,fc,coff,cc,op) in [(0x1F,0x697076A2,0x3F,0x2646,'xor'),(0x2B,0x4DEAED44,0x39,0xD7FE,'add')]:
    exp=0; ok=0; bad=0
    for i in range(9585):
        raw=u32(base+stride*i+foff)
        fs=(raw^fc)&0xFFFFFFFF
        c=u16(base+stride*i+coff)
        c=(c^cc)&0xFFFF if op=='xor' else (c-cc)&0xFFFF
        if fs==exp: ok+=1
        else: bad+=1
        exp=fs+c
    print('  fs_off=0x%02X exact=%d mismatch=%d final=%d'%(foff,ok,bad,exp))
print('=== try to decode something plausible from the string column c=0xD13BCB2F? (not reported for 4.8.0) ===')

