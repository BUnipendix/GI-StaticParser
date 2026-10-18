import io, re, json, struct, sys, collections
sys.path.insert(0,'/home/yangsanyi/gire/out/cross')
sys.path.insert(0,'/home/yangsanyi/gire/sample/gi/7.0.0/YuanShen_Data/Managed/Metadata')
sys.path.insert(0,'/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage')
import type_render as tr
import field_rows as fr
import method_rows as mr
V='/home/yangsanyi/gire/sample/gi/7.0.0'
CROSS='/home/yangsanyi/gire/out/cross'
ART='/home/yangsanyi/Documents/git-repo/GI-StaticParser/docs/re/artifacts-7.0.0'
h=fr.h
art=json.load(open(CROSS+'/7.0.0.derive.json')); cipher=mr.Cipher(art)
sites=json.load(open(CROSS+'/sites/7.0.0.json'))
d,ib,secs=fr.pe_map(sites['exe']); hdr=d[fr.va2file(ib,secs,sites['blob_va']):][:0x210]
body=open(V+'/YuanShen_Data/Managed/Metadata/global-metadata.dat','rb').read()[0x210:]
def tbase(t):
    raw=struct.unpack_from('<I',hdr,h(t['slot']))[0]
    return (raw+h(t['imm']))&0xFFFFFFFF if t['op']=='add' else ((raw^h(t['imm']))&0xFFFFFFFF)
tt=tr.TypeTable(sites['exe'], CROSS+'/typedefs/7.0.0.jsonl')
types=tt.types
fl=json.load(open(ART+'/field-layout.json'))
fb=tbase(fl['table']); fstride=fl['stride']; mk=fl['mask']
def fmask(i):
    x=((i*h(mk['mul1']))&0xFFFFFFFFFFFFFFFF)>>mk['shr1']
    x=(x*h(mk['mul2']))&0xFFFFFFFFFFFFFFFF
    return ((x+h(mk['add1']))&0xFFFFFFFFFFFFFFFF)>>mk['shr2'] & 0xFFFFFFFF
fname=fl['columns']['name']; ftype=fl['columns']['type']
def fname_of(i):
    raw=struct.unpack_from('<I',body,fb+i*fstride+fname['off'])[0]
    return cipher.dec(body,((raw^h(fname['c']))-fmask(i))&0xFFFFFFFF)
def ftype_of(i):
    raw=struct.unpack_from('<I',body,fb+i*fstride+ftype['off'])[0]
    return ((raw+h(ftype['c']))-fmask(i))&0xFFFFFFFF
# method table for property types
ml=json.load(open(ART+'/method-layout.json'))
mb=tbase(ml['method']['table']); mstride=ml['method']['stride']; mm=mr.mask_fn(ml['method']['mask'])
mcols={k:(v['off'],v['kind'],h(v['c'])) for k,v in ml['method']['columns'].items()}
def mcol(name,i):
    off,kind,c=mcols[name]; width=1 if name=='param_count' else 4
    raw=struct.unpack_from('<B' if width==1 else '<I',body,mb+i*mstride+off)[0]
    return mr.col_value(kind,c,raw,mm(i))
pl=json.load(open(ART+'/property-layout.json'))
pb=tbase(pl['table']); pstride=pl['stride']; pmk=pl['mask']
def pmask(i):
    x=((i*h(pmk['mul1']))&0xFFFFFFFFFFFFFFFF)^h(pmk['xor1'])
    x=(x*h(pmk['mul2']))&0xFFFFFFFFFFFFFFFF
    x=(x+h(pmk['add1']))&0xFFFFFFFFFFFFFFFF
    x^=h(pmk['xor2'])
    return ((x+h(pmk['add2']))&0xFFFFFFFFFFFFFFFF)&0xFFFFFFFF
pcols={k:(v['off'],v['kind'],h(v['c'])) for k,v in pl['columns'].items()}
def prow(i,key):
    off,kind,c=pcols[key]; raw=struct.unpack_from('<I',body,pb+i*pstride+off)[0]
    return mr.col_value(kind,c,raw,pmask(i))
def pcol16(i,key):
    off,kind,c=pcols[key]; raw=struct.unpack_from('<H',body,pb+i*pstride+off)[0]
    return mr.col_value(kind,c,raw,pmask(i))
# parse dump
dump=collections.defaultdict(lambda: {'fields':{}, 'props':{}})
cur=None
with io.open('/home/yangsanyi/gire/out/71/dump.cs',encoding='utf-8',errors='replace') as f:
    for line in f:
        s=line.strip()
        m=re.match(r'^(?:public |internal |private |protected |sealed |abstract |static )*(?:class|struct|interface|enum) ([^\s:]+)', s)
        if m: cur=m.group(1).split('.')[-1]; continue
        if not cur: continue
        m=re.search(r';\s*// 0x[0-9a-fA-F]+$', s)
        if m and ' ' in s:
            bodyline=s.split('//')[0].strip()
            t=re.sub(r'^(public|private|protected|internal|static|readonly|volatile|const)\s+','',bodyline)
            parts=t.rsplit(' ',1)
            if len(parts)==2:
                nm=parts[1].split(';')[0].strip(); ty=parts[0].strip()
                dump[cur]['fields'][nm]=ty
            continue
        m=re.search(r'\{\s*(get;\s*)?(set;\s*)?\}', s)
        if m:
            head=s.split('{')[0].strip()
            parts=head.rsplit(' ',1)
            if len(parts)==2:
                nm=parts[1].strip(); ty=parts[0].strip()
                dump[cur]['props'][nm]=(ty, bool(m.group(1)), bool(m.group(2)))
def short(t):
    t=t.replace(' ','')
    for suf in ('[]','*','&'):
        while t.endswith(suf): t=t[:-len(suf)]
    t=re.sub(r'<.*','',t)
    return t.split('.')[-1]
ourtypes={}
fo=fo_ok=fo_tot=0
for typ in types[:60]:
    if not typ['fieldCount']: continue
    tname=(typ['ns']+'.' if typ['ns'] else '')+typ['name']
    key=tname.split('.')[-1]
    for j in range(typ['fieldCount']):
        i=typ['fieldStart']+j
        nm=fname_of(i); ty=tt.render(ftype_of(i))
        d= dump.get(key,{}).get('fields',{})
        if nm and nm in d:
            fo_tot+=1
            if short(ty)==short(d[nm]): fo_ok+=1
print('fields matched by name:',fo_ok,'/',fo_tot,'=',round(fo_ok/max(1,fo_tot),4))
pr=pr_ok=pr_tot=0; acc_ok=acc_tot=0
for typ in types[:60]:
    if not typ['propCount'] or typ['propStart']==0xFFFFFFFF: continue
    key=((typ['ns']+'.' if typ['ns'] else '')+typ['name']).split('.')[-1]
    d=dump.get(key,{}).get('props',{})
    for j in range(typ['propCount']):
        i=typ['propStart']+j
        nm=cipher.dec(body,prow(i,'name'))
        g=pcol16(i,'getter'); s=pcol16(i,'setter')
        if not nm: continue
        pty=None
        if g!=0xFFFF: pty=tt.render(mcol('return_type',typ['methodStart']+g))
        if nm in d:
            pr_tot+=1
            dty,dg,ds=d[nm]
            if pty is not None and short(pty)==short(dty): pr_ok+=1
            acc_tot+=1
            if (g!=0xFFFF)==dg and (s!=0xFFFF)==ds: acc_ok+=1
print('props matched by name:',pr_ok,'/',pr_tot,'=',round(pr_ok/max(1,pr_tot),4),'accessor-presence',acc_ok,'/',acc_tot)
