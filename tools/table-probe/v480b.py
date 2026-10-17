
import numpy as np
dat='/home/yangsanyi/gire/sample/gi/4.8.0/YuanShen_Data/Managed/Metadata/global-metadata.dat'
buf=np.fromfile(dat,dtype=np.uint8,offset=0x210)
def u32(o): return int.from_bytes(buf[o:o+4].tobytes(),'little')
def u16(o): return int.from_bytes(buf[o:o+2].tobytes(),'little')
base=0x02CC8CC5; stride=0x4A
for (foff,fc,sent,coff,cc,op) in [(0x1F,0x697076A2,0x696D5325,0x3F,0x2646,'xor'),
                                  (0x2B,0x4DEAED44,0x4DE5409E,0x39,0xD7FE,'add')]:
    exp=0; ok=0; bad=0; firstbad=None
    for i in range(9585):
        raw=u32(base+stride*i+foff)
        if raw==sent: continue
        fs=(raw^fc)&0xFFFFFFFF if op=='xor' else (raw-fc)&0xFFFFFFFF
        c=u16(base+stride*i+coff); c=(c^cc)&0xFFFF if op=='xor' else (c-cc)&0xFFFF
        if fs==exp: ok+=1
        else:
            bad+=1
            if firstbad is None: firstbad=(i,exp,fs)
        exp=fs+c
    print('fs_off=0x%02X: exact=%d mismatch=%d final=%d firstbad=%s'%(foff,ok,bad,exp,firstbad))

