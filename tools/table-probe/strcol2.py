
import numpy as np, sys
body=np.fromfile(sys.argv[1],dtype=np.uint8,offset=0x210)
strsec=0x3C58E68
M1=0xB33E40427D5668C0; X1=0x6D8C4AAB00FE8E27; X2=0x30EE5B43130FE0CD
M=(1<<64)-1
o=np.arange(1<<24,dtype=np.uint64)
key=((((o*np.uint64(M1))&np.uint64(M))+np.uint64(X1))&np.uint64(M))^np.uint64(X2)
first=(body[strsec:strsec+(1<<24)].astype(np.uint64) ^ (key & np.uint64(0xFF))).astype(np.uint8)
P=(first>=0x20)&(first<=0x7E)
L=np.arange(1<<24,dtype=np.uint64)
base=0x48F3FD8; st=0x46; rows=88904
for N in [16,24,28,32]:
    print('--- %d rows ---'%N)
    for off in [0x14,0x18,0x00,0x08,0x10]:
        acc=None
        for k in range(N):
            r=k*rows//N
            u=int.from_bytes(body[base+st*r+off:base+st*r+off+4],'little')
            idx=(L+np.uint64(u))&np.uint64(0xFFFFFF)
            a=P[idx.astype(np.int64)]
            acc=a if acc is None else (acc&a)
            if not acc.any(): break
        c=int(acc.sum())
        extra=''
        if 0<c<=4:
            extra=' l='+','.join('0x%06X'%int(x) for x in np.flatnonzero(acc))
        print('  off=0x%02X survivors=%d%s'%(off,c,extra))

