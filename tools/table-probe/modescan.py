
import json,subprocess,sys,numpy as np
v=sys.argv[1]; ROWS=int(sys.argv[2]) if len(sys.argv)>2 else 600
D='/home/yangsanyi/gire/sample/gi/'+v
exe=D+'/YuanShen.exe'; dat=D+'/YuanShen_Data/Managed/Metadata/global-metadata.dat'
js=json.loads(subprocess.run(['/home/yangsanyi/Documents/git-repo/GI-StaticParser/target/release/mhydump','anchors','--exe',exe,'--metadata',dat,'--json'],capture_output=True,text=True).stdout)
bases=sorted({a['resolved'] for a in js['anchors'] if a.get('resolved') and a['resolved']>0x40})
buf=np.fromfile(dat,dtype=np.uint8,offset=0x210)
N=len(buf)-4
def raws(base,stride,off,n):
    i=base+off+stride*np.arange(n,dtype=np.int64)
    if i[-1]+4>=N: return None
    return (buf[i].astype(np.uint64) | (buf[i+1].astype(np.uint64)<<8) | (buf[i+2].astype(np.uint64)<<16) | (buf[i+3].astype(np.uint64)<<24)).astype(np.uint32)
hits=[]
for base in bases:
    for stride in list(range(8,0x100,2)):
        if base+stride*ROWS+8>=N: continue
        for off in range(0,stride-3,2):
            r=raws(base,stride,off,ROWS)
            if r is None: continue
            val,cnt=np.unique(r,return_counts=True)
            k=int(np.argmax(cnt)); mode=int(val[k]); f=int(cnt[k])
            if f < ROWS//10: continue
            C=(~mode)&0xFFFFFFFF
            fs=r^np.uint32(C)
            real=fs[fs!=0xFFFFFFFF]
            if len(real)==0: continue
            if np.any(np.diff(real.astype(np.int64))<0): continue
            if int(real.max())>= (1<<20): continue
            hits.append((f,base,stride,off,int(real.max()),len(real)))
hits.sort(reverse=True)
print(v,'rows=%d hits=%d'%(ROWS,len(hits)))
for h in hits[:6]: print('   modefreq=%d base=0x%X stride=0x%X off=0x%X max_fs=%d real=%d'%h)

