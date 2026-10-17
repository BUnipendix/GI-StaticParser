
import numpy as np, sys
body=np.fromfile(sys.argv[1],dtype=np.uint8,offset=0x210)
strsec=0x3C58E68
M1=0xB33E40427D5668C0; X1=0x6D8C4AAB00FE8E27; X2=0x30EE5B43130FE0CD
M=(1<<64)-1
o=np.arange(1<<24,dtype=np.uint64)
key=((((o*np.uint64(M1))&np.uint64(M))+np.uint64(X1))&np.uint64(M))^np.uint64(X2)
first=(body[strsec:strsec+(1<<24)].astype(np.uint64) ^ (key & np.uint64(0xFF))).astype(np.uint8)
P=(first>=0x20)&(first<=0x7E)
print('P fraction',P.mean())
base=0x48F3FD8; st=0x46
rows=88904
for off in [0x14,0x18,0x00,0x08]:
    acc=None
    for k in range(8):
        r=k*rows//8
        u=int.from_bytes(body[base+st*r+off:base+st*r+off+4],'little')
        idx=(np.arange(1<<24,dtype=np.uint64)+np.uint64(u))&np.uint64(0xFFFFFF)
        a=P[idx.astype(np.int64)]
        acc=a if acc is None else (acc&a)
        if not acc.any(): break
    cnt=int(acc.sum())
    print('off=0x%02X intersection after 8 rows = %d'%(off,cnt))
    if 0<cnt<=8:
        for l in np.flatnonzero(acc): print('    l=0x%06X'%int(l))

