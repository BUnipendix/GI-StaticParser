
import json,subprocess,sys
v=sys.argv[1]
D='/home/yangsanyi/gire/sample/gi/'+v
exe=D+'/YuanShen.exe'; dat=D+'/YuanShen_Data/Managed/Metadata/global-metadata.dat'
js=json.loads(subprocess.run(['/home/yangsanyi/Documents/git-repo/GI-StaticParser/target/release/mhydump','anchors','--exe',exe,'--metadata',dat,'--json'],capture_output=True,text=True).stdout)
bases=sorted({a['resolved'] for a in js['anchors'] if a.get('resolved') and a['resolved']>0x40})
body=open(dat,'rb').read()[0x210:]
print(v,'bases',len(bases))
def u32(o): return int.from_bytes(body[o:o+4],'little')
best=[]
for b in bases:
    if b+0x46*2000>len(body): continue
    for off in range(0,0x46-3):
        prev=None; good=0; tot=0
        for i in range(64):
            x=u32(b+0x46*i+off)
            if prev is not None:
                d=x-prev
                tot+=1
                if 0<=d<=0xFFFF: good+=1
            prev=x
        if good>=58:
            best.append((good,b,off))
best.sort(reverse=True)
for g,b,off in best[:6]:
    print('  ADD-like good=%d/63 base=0x%X off=0x%X'%(g,b,off))
if not best: print('  no ADD-like column at stride 0x46')

