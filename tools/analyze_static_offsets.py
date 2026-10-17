import re
name_re=re.compile(r'^(?:(?:public|internal|private|protected|static|abstract|sealed)\s+)*(class|struct|interface|enum) ([^ :]+?)((?: : .*)?)$')
f2=re.compile(r'^\t(.+?) ([A-Za-z_][A-Za-z0-9_]*);(?: // (0x[0-9a-f]+))?$')
PRIM={'System.Boolean','System.Char','System.Byte','System.SByte','System.Int16','System.UInt16','System.Int32','System.UInt32','System.Int64','System.UInt64','System.Single','System.Double','System.IntPtr','System.UIntPtr','System.Decimal','System.DateTime','System.TimeSpan','System.Guid','System.Void'}
MODS={'public','internal','private','protected','static','readonly','const','volatile','new'}
types=[]; cur=None; in_fields=False; cnt=0
for line in open('/home/yangsanyi/Documents/git-repo/Genshin-Impact-Dump-collection/6.4Dump.cs',errors='replace'):
    s=line.rstrip('\r\n')
    if not s or s.startswith('//'): continue
    if not s.startswith('\t'):
        i=s.find(' //')
        if i>0: s=s[:i]
        m=name_re.match(s)
        if m: cur=dict(name=m.group(2), stat=[]); types.append(cur)
        continue
    st=s.strip()
    if st.startswith('//'):
        in_fields='Fields' in st; continue
    if not in_fields or cur is None: continue
    m=f2.match(s)
    if not m: continue
    toks=m.group(1).split()
    mods=[t for t in toks if t in MODS]
    ttype=' '.join(t for t in toks if t not in MODS)
    off=m.group(3)
    if 'static' not in mods or 'const' in mods or not off or off=='0x0': continue
    is_ref = ('[]' in ttype) or ('*' in ttype) or (ttype not in PRIM)
    cur['stat'].append((int(off,16),is_ref,ttype)); cnt+=1
print('static fields parsed',cnt)
mixed=0; ok=0; bad=[]
for t in types:
    if len(t['stat'])<2: continue
    refs=[o for o,r,_ in t['stat'] if r]
    nrefs=[o for o,r,_ in t['stat'] if not r]
    if not refs or not nrefs: continue
    mixed+=1
    if max(nrefs)<min(refs): ok+=1
    elif len(bad)<8: bad.append((t['name'],sorted(nrefs)[:3],sorted(refs)[:3]))
print('mixed types',mixed,'nonref<ref',ok,f'({ok/max(mixed,1):.2%})')
for b in bad[:6]: print('  ',b)
