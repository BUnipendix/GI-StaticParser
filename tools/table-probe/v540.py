
import numpy as np
dat='/home/yangsanyi/gire/sample/gi/5.4.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
buf=np.fromfile(dat,dtype=np.uint8,offset=0x210)
N=len(buf)
strsec=0x2B7E820
M1=0xABA245CD4BE8E3B0; X1=0x32AA522A0281FDAA; X2=0x34CC45C5274E0D3A; M4=0x05510ECD3314C022
M=(1<<64)-1
def u32(o): return int.from_bytes(buf[o:o+4].tobytes(),'little')
def key(o): return ((((o*M1)&M)+X1)&M)^X2
def dec(idx):
    off=idx&0xFFFFFF; ln=(idx>>24)&0xFF
    if ln==0: return ''
    k=key(off); out=b''
    for i in range((ln+7)//8):
        v=int.from_bytes(buf[strsec+off+8*i:strsec+off+8*i+8].tobytes(),'little')^k
        out+=v.to_bytes(8,'little'); k=(k+M4)&M
    out=out[:ln]
    z=out.find(b'\0')
    return (out[:z] if z>=0 else out).decode('latin1')
base=0x0213921C; stride=0x46
print('--- name column 0x3E, C=0xD13BCB2F ---')
for i in range(8):
    raw=u32(base+stride*i+0x3E)
    idx=(raw+0xD13BCB2F)&0xFFFFFFFF
    print('  row %d raw=0x%08X idx=0x%08X -> %r'%(i,raw,idx,dec(idx)))
print('--- index column 0x08 (idx_c=0x5CB2D477, sentinel 0xA34D2B88) ---')
tot=0; nonempty=0
for i in range(0,58938):
    raw=u32(base+stride*i+0x08)
    if raw==0xA34D2B88: continue
    nonempty+=1
    idx=raw^0x5CB2D477
    if idx>tot: tot=idx
print('  sentinel rows=%d real=%d max_index=%d'%(58938-nonempty,nonempty,tot))
print('--- fieldCount col 0x1A (add, C=0xED8D) ---')
ok=0; bad=0; prev=None; exp=0
for i in range(58938):
    raw=u32(base+stride*i+0x08)
    fs = 0xFFFFFFFF if raw==0xA34D2B88 else (raw^0x5CB2D477)
    c = (int.from_bytes(buf[base+stride*i+0x1A:base+stride*i+0x1C].tobytes(),'little') - 0xED8D) & 0xFFFF
    if fs!=0xFFFFFFFF:
        if fs==exp: ok+=1
        else: bad+=1
        exp=fs+c
print('  tiling exact=%d mismatch=%d final=%d'%(ok,bad,exp))

