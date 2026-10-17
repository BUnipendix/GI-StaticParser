
import sys, collections
body=open(sys.argv[1],'rb').read()[0x210:]
def u32(o): return int.from_bytes(body[o:o+4],'little')

# 7.1.0 ground truth from layout71: td_base=0x48F3FD8 stride=0x46 fs@0x00 C=0x72628007
base=0x48F3FD8
K=19
raws=[u32(base+0x46*i+0x00) for i in range(88904)]
his=collections.Counter(x>>K for x in raws)
print('7.1 fs column: distinct hi(raw>>%d) ='%K, len(his), {hex(k):v for k,v in his.most_common(4)})
C=0x72628007
print('  hi(C)=0x%X hi(~C)=0x%X  complement-check=%s'%(C>>K,(~C&0xFFFFFFFF)>>K, ((~C&0xFFFFFFFF)>>K)==(0x1FFF^(C>>K))))
fs=[ (x^C) for x in raws ]
real=[f for f in fs if f!=0xFFFFFFFF]
print('  sentinel rows=%d real=%d min(fs)=%d max(fs)=%d'%(len(fs)-len(real),len(real),min(real),max(real)))

# ---- constant-free search: which (stride, off) have the "<=2 hi values, complements" property? ----
print()
print('constant-free scan over base=0x%X:'%base)
hits=[]
for st in range(4,0x200):
    for off in range(0,st-3):
        ok=True
        vals=[]
        for i in range(6):
            vals.append(u32(base+st*i+off)>>K)
        s=set(vals)
        if len(s)>2: continue
        if len(s)==2:
            a,b=list(s)
            if (a^b)!=0x1FFF: continue
        hits.append((st,off,len(s)))
for st,off,n in hits[:20]:
    print('   stride=0x%X off=0x%X distinct_hi=%d'%(st,off,n))
print('  total hits:',len(hits))

