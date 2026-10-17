
import numpy as np, sys, collections
p=sys.argv[1]
body=np.fromfile(p,dtype=np.uint8,offset=0x210)
u32=body[:len(body)//4*4].view(np.uint32)
print('body u32 len',len(u32))
vals,counts=np.unique(u32,return_counts=True)
print('distinct',len(vals),'max count',counts.max())
cand=vals[counts>800]
print('candidates with count>800:',len(cand))
cand=cand[np.argsort(-counts[counts>800])][:8]
for v in cand:
    pos=np.flatnonzero(u32==v)
    d=np.diff(pos)
    bc=np.bincount(d)
    s=int(bc.argmax()); n=int(bc[s])
    # longest run with diff s
    best=0; run=1; start=pos[0]
    for i in range(1,len(pos)):
        if pos[i]-pos[i-1]==s:
            run+=1
        else:
            if run>best: best=run; bstart=pos[i-1]-(run-1)*s
            run=1
    if run>best: best=run; bstart=pos[-1]-(run-1)*s
    print('v=0x%08X count=%d modal_stride=0x%X modal_n=%d longest_run=%d base=0x%X'%(v,len(pos),s,n,best,bstart))

