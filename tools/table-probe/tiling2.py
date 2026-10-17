
import sys
body=open(sys.argv[1],'rb').read()[0x210:]
N=len(body)
def u32(o): return int.from_bytes(body[o:o+4],'little')
def u16(o): return int.from_bytes(body[o:o+2],'little')
base=int(sys.argv[2],16)
K=19; M13=0x1FFF

def prefilter(st,off):
    his=set()
    for i in range(6):
        o=base+st*i+off
        if o+4>N: return False
        his.add(u32(o)>>K)
        if len(his)>2: return False
    if len(his)==2:
        a,b=his; return (a^b)==M13
    return True

def try_col(st,off,maxrows=200000):
    h1=None; h2=None; n=0
    while n<maxrows:
        o=base+st*n+off
        if o+4>N: break
        x=u32(o)>>K
        if h1 is None: h1=x
        elif x!=h1:
            if h2 is None:
                if (x^h1)!=M13: break
                h2=x
            elif x!=h2: break
        n+=1
    if n<1000 or h2 is None: return None
    a=h1
    raw_first=None
    for i in range(min(n,64)):
        if u32(base+st*i+off)>>K==a: raw_first=u32(base+st*i+off); break
    if raw_first is None: return None
    C=raw_first
    fs=[]; prev=None; mono=True; mx=0
    for i in range(n):
        raw=u32(base+st*i+off)
        if raw>>K!=a: fs.append(-1); continue
        f=raw^C; fs.append(f)
        if f>mx: mx=f
        if prev is not None and f<prev: mono=False
        prev=f
    if not mono or mx>=(1<<K): return None
    for off2 in range(0,st-1):
        C2=None; ok=True; cnt=0
        for i in range(n-1):
            if fs[i]<0 or fs[i+1]<0: continue
            d=fs[i+1]-fs[i]
            if d<0 or d>0xFFFF: ok=False; break
            v=u16(base+st*i+off2)
            if C2 is None: C2=v^d
            elif (v^C2)!=d: ok=False; break
            cnt+=1
        if ok and cnt>1000: return (st,off,n,sum(1 for f in fs if f>=0),sum(1 for f in fs if f<0),mx,off2,C2,cnt)
    return None

found=[]
for st in range(4,0x120):
    for off in range(0,st-3):
        if not prefilter(st,off): continue
        r=try_col(st,off)
        if r: found.append(r)
for r in found[:12]:
    print('stride=0x%X fs_off=0x%X rows=%d real=%d sentinel=%d max_fs=%d | fc_off=0x%X fc_C=0x%X matched=%d'%r)
print('surviving:',len(found))

