
import sys
body=open(sys.argv[1],'rb').read()[0x210:]
N=len(body)
def u32(o): return int.from_bytes(body[o:o+4],'little')
def u16(o): return int.from_bytes(body[o:o+2],'little')
base=int(sys.argv[2],16)
K=19; M13=0x1FFF

def col_run(st,off,maxrows=200000):
    h1=None;h2=None;n=0
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
    return h1,h2,n

def analyze(st,off):
    h1,h2,n=col_run(st,off)
    if n<1000 or h2 is None: return None
    # which hi class is the sentinel? the one whose raw values are all identical
    def classinfo(h):
        vals=set(); cnt=0
        for i in range(n):
            raw=u32(base+st*i+off)
            if raw>>K!=h: continue
            cnt+=1; vals.add(raw)
            if len(vals)>3: break
        return cnt,len(vals),vals
    c1,d1,v1=classinfo(h1); c2,d2,v2=classinfo(h2)
    if d1==1 and d2>1: sent_h,real_h,sent_raw= h1,h2,next(iter(v1))
    elif d2==1 and d1>1: sent_h,real_h,sent_raw= h2,h1,next(iter(v2))
    else: return None
    C=(~sent_raw)&0xFFFFFFFF
    fs=[];prev=None;mono=True;mx=0;nreal=0
    for i in range(n):
        raw=u32(base+st*i+off)
        if raw>>K==sent_h: fs.append(-1); continue
        f=raw^C; fs.append(f); nreal+=1
        if f>mx: mx=f
        if prev is not None and f<prev: mono=False
        prev=f
    if not mono: return None
    res={'stride':st,'fs_off':off,'rows':n,'real':nreal,'sentinel':n-nreal,'max_fs':mx,'C':C,'sent_raw':sent_raw}
    # tiling: fc column
    for off2 in range(0,st-1):
        C2=None;ok=True;cnt=0;acc=0
        for i in range(n-1):
            if fs[i]<0 or fs[i+1]<0: continue
            d=fs[i+1]-fs[i]
            if d<0 or d>0xFFFF: ok=False;break
            v=u16(base+st*i+off2)
            if C2 is None: C2=v^d
            elif (v^C2)!=d: ok=False;break
            cnt+=1; acc+=d
        if ok and cnt>1000:
            res['fc_off']=off2; res['fc_C']=C2; res['matched']=cnt; res['sum_delta']=acc
            return res
    return None

found=[]
for st in [4,8,0x0C,0x10,0x14,0x18,0x1C,0x20,0x24,0x28,0x2C,0x30,0x34,0x38,0x3C,0x40,0x44,0x46,0x48,0x4A,0x50,0x60,0x70,0x80,0x90,0xA0,0xB0,0xC0,0x100,0x110]:
    for off in range(0,st-3):
        r=analyze(st,off)
        if r: found.append(r)
found.sort(key=lambda r:-r['rows'])
for r in found[:10]:
    print('stride=0x%(stride)X fs_off=0x%(fs_off)X rows=%(rows)d real=%(real)d sent=%(sentinel)d max_fs=%(max_fs)d C=0x%(C)X sent_raw=0x%(sent_raw)X fc_off=0x%(fc_off)X fc_C=0x%(fc_C)X matched=%(matched)d sum_delta=%(sum_delta)d'%r)
print('surviving:',len(found))

