
import numpy as np, sys
p=sys.argv[1]
body=np.fromfile(p,dtype=np.uint8,offset=0x210)
N=len(body)
# verify the 7.1 typeDef magic column directly (unaligned)
base=0x48F3FD8; stride=0x46; magic=0xDEBA5049
n=0; tot=88904
for i in range(tot):
    o=base+0x1C+stride*i
    if int.from_bytes(body[o:o+4],'little')==magic: n+=1
print('7.1 td_magic hits over %d rows: %d'%(tot,n))
print()
# constant-free discovery: for each of the 4 byte shifts, find values with a long arithmetic progression
for k in range(4):
    v=body[k:k+((N-k)//4)*4].view(np.uint32)
    vals,counts=np.unique(v,return_counts=True)
    sel=counts>1500
    order=np.argsort(-counts[sel])
    vs=vals[sel][order][:6]
    for val in vs:
        idx=np.flatnonzero(v==val)
        pos=k+4*idx            # byte offsets
        d=np.diff(pos)
        bc=np.bincount(d)
        s=int(bc.argmax()); nm=int(bc[s])
        if nm<2000: continue
        best=0;run=1;bstart=int(pos[0])
        for i in range(1,len(pos)):
            if pos[i]-pos[i-1]==s: run+=1
            else:
                if run>best: best=run;bstart=int(pos[i-1]-(run-1)*s)
                run=1
        if run>best: best=run;bstart=int(pos[-1]-(run-1)*s)
        print('shift=%d v=0x%08X count=%d stride=0x%X n=%d run=%d base=0x%X'%(k,int(val),len(pos),s,nm,best,bstart))

