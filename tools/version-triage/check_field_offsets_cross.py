import re, struct, random
name_re=re.compile(r'^(?:(?:public|internal|private|protected|static|abstract|sealed)\s+)*(class|struct|interface|enum) ([^ :]+?)((?: : .*)?)$')
f2=re.compile(r'^\t(.+?) ([A-Za-z_][A-Za-z0-9_]*);(?: // (0x[0-9a-f]+))?$')
MODS={'public','internal','private','protected','static','readonly','const','volatile','new'}
types=[]; cur=None; in_fields=False
for line in open('/home/yangsanyi/Documents/git-repo/Genshin-Impact-Dump-collection/6.4Dump.cs',errors='replace'):
    s=line.rstrip('\n')
    if not s or s.startswith('//'): continue
    if not s.startswith('\t'):
        i=s.find(' //')
        if i>0: s=s[:i]
        m=name_re.match(s)
        if m: cur=dict(name=m.group(2), inst=[], static=[]); types.append(cur)
        continue
    st=s.strip()
    if st.startswith('//'):
        in_fields='Fields' in st; continue
    if not in_fields or cur is None: continue
    m=f2.match(s)
    if not m: continue
    toks=m.group(1).split(); mods=[t for t in toks if t in MODS]
    off=m.group(3)
    if 'static' in mods or 'const' in mods:
        cur['static'].append(None if not off else int(off,16))
    else:
        cur['inst'].append(None if not off else int(off,16))
print('types',len(types))
st=[t for t in types if t['static'] and any(v is not None for v in t['static'])]
print('types with static offsets',len(st),'example',st[0]['name'] if st else None)
exe=open('/home/yangsanyi/gire/sample/gi/6.4.0/YuanShen.exe','rb').read()
print('exe size',len(exe))
pats=[]
for t in types:
    seq=[v for v in t['inst'][:8] if v is not None]
    if len(seq)>=4 and max(seq[:4])>0x80:
        pats.append((t['name'],t['inst'][:8]))
print('instance-seq candidates',len(pats))
random.seed(1)
sample=random.sample(pats,min(200,len(pats)))
verified=0; ex=[]
for name,seq8 in sample:
    seq=[v for v in seq8 if v is not None]
    if len(seq)<4: continue
    pat=b''.join(struct.pack('<I',x) for x in seq[:4])
    pos=0
    while True:
        i=exe.find(pat,pos)
        if i<0: break
        if all(struct.unpack_from('<I',exe,i+4*k)[0]==v for k,v in enumerate(seq)):
            verified+=1
            if len(ex)<5: ex.append((name,hex(i),seq[:8]))
        pos=i+1
print('verified full instance sequences in 6.4 exe:',verified)
for e in ex: print(' ',e)
