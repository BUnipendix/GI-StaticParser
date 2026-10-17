import re, struct, random
name_re=re.compile(r'^(?:(?:public|internal|private|protected|static|abstract|sealed)\s+)*(class|struct|interface|enum) ([^ :]+?)((?: : .*)?)$')
f2=re.compile(r'^\t(.+?) ([A-Za-z_][A-Za-z0-9_]*);(?: // (0x[0-9a-f]+))?$')
MODS={'public','internal','private','protected','static','readonly','const','volatile','new'}
types=[]; cur=None; in_fields=False
for line in open('/home/yangsanyi/gire/out/71/dump.cs',errors='replace'):
    s=line.rstrip('\n')
    if not s or s.startswith('//'): continue
    if not s.startswith('\t'):
        i=s.find(' //')
        if i>0: s=s[:i]
        m=name_re.match(s)
        if m: cur=dict(name=m.group(2), inst=[]); types.append(cur)
        continue
    st=s.strip()
    if st.startswith('//'):
        in_fields='Fields' in st; continue
    if not in_fields or cur is None: continue
    m=f2.match(s)
    if not m: continue
    toks=m.group(1).split(); mods=[t for t in toks if t in MODS]
    off=m.group(3)
    cur['inst'].append(None if ('static' in mods or 'const' in mods or not off) else int(off,16))
exe=open('/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen.exe','rb').read()
# collect types whose first N fields are instance with a rare-ish offset value >0x80
pats=[]
for t in types:
    seq=[]
    for v in t['inst'][:10]:
        if v is None: break
        seq.append(v)
    if len(seq)>=4 and max(seq[:4])>0x80:
        pats.append((t['name'],seq))
print('types with >=4 leading instance fields and a distinctive offset:', len(pats))
random.seed(0)
sample=random.sample(pats, min(400,len(pats)))
raw_hits=0; verified=0; examples=[]
for name,seq in sample:
    pat=b''.join(struct.pack('<I',x) for x in seq[:5])
    pos=0
    while True:
        i=exe.find(pat,pos)
        if i<0: break
        raw_hits+=1
        # verify continuing values
        full_ok=True
        for k,v in enumerate(seq):
            if struct.unpack_from('<I',exe,i+4*k)[0]!=v: full_ok=False; break
        if full_ok:
            verified+=1
            if len(examples)<5: examples.append((name,hex(i),seq[:8]))
        pos=i+1
print('sample size',len(sample),'raw pattern hits',raw_hits,'verified full sequences',verified)
for e in examples: print(' ',e)
