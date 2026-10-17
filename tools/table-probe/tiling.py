
import sys
body=open(sys.argv[1],'rb').read()[0x210:]
N=len(body)
def u32(o): return int.from_bytes(body[o:o+4],'little')
def u16(o): return int.from_bytes(body[o:o+2],'little')
base=0x48F3FD8
K=19
MASK13=0x1FFF

def try_col(base,st,off,maxrows=400000):
    # extend the run while hi(raw) is one of two complementary values
    h=None; his=None; n=0
    while n<maxrows:
        o=base+st*n+off
        if o+4>N: break
        x=u32(o)>>K
        if his is None: his={x}
        if x not in his:
            if len(his)==1 and (x^next(iter(his)))==MASK13:
                his.add(x)
            else: break
        n+=1
    if n<1000 or len(his)!=2: return None
    a,b=sorted(his)
    # raw with hi==a are "real", hi==b are sentinel (or vice versa); sentinel decodes to 0xFFFFFFFF
    raw_first_real=None
    for i in range(min(n,64)):
        if u32(base+st*i+off)>>K==a: raw_first_real=u32(base+st*i+off); break
    if raw_first_real is None: return None
    C=raw_first_real              # first real row has fieldStart 0
    real=0; sent=0; prev=None; mono=True; maxv=0
    fslist=[]
    for i in range(n):
        raw=u32(base+st*i+off)
        if raw>>K != a:
            sent+=1; fslist.append(-1); continue
        f=raw^C
        if f>maxv: maxv=f
        if prev is not None and f<prev: mono=False
        prev=f; real+=1; fslist.append(f)
    if not mono: return None
    # tiling: find a u16 column giving delta = fs[i+1]-fs[i]
    best=None
    for off2 in range(0,st-1):
        C2=None; ok=True; cnt=0
        for i in range(n-1):
            if fslist[i]<0 or fslist[i+1]<0: continue
            d=fslist[i+1]-fslist[i]
            if d<0 or d>0xFFFF: ok=False; break
            v=u16(base+st*i+off2)
            if C2 is None: C2=v^d
            elif v^C2!=d: ok=False; break
            cnt+=1
        if ok and cnt>1000:
            best=(off2,C2,cnt); break
    return (st,off,n,real,sent,maxv,best)

# scan the whole (stride, off) space for this base
found=[]
for st in range(4,0x120):
    for off in range(0,st-3):
        r=try_col(base,st,off)
        if r and r[6] is not None:
            found.append(r)
for r in found[:10]:
    print('stride=0x%X fs_off=0x%X rows=%d real=%d sentinel=%d max_fs=%d  fc: off=0x%X C=0x%X matched=%d'%r)
print('surviving (stride,off) with tiling:',len(found))

