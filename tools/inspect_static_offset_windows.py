import re
name_re=re.compile(r'^(?:(?:public|internal|private|protected|static|abstract|sealed)\s+)*(class|struct|interface|enum) ([^ :]+?)((?: : .*)?)$')
f2=re.compile(r'^\t(.+?) ([A-Za-z_][A-Za-z0-9_]*);(?: // (0x[0-9a-f]+))?$')
MODS={'public','internal','private','protected','static','readonly','const','volatile','new'}
rows=[]; cur=None; in_fields=False
for line in open('/home/yangsanyi/Documents/git-repo/Genshin-Impact-Dump-collection/6.4Dump.cs',errors='replace'):
    s=line.rstrip('\r\n')
    if not s or s.startswith('//'): continue
    if not s.startswith('\t'):
        m=name_re.match(s)
        if m: cur=m.group(2)
        continue
    st=s.strip()
    if st.startswith('//'):
        in_fields='Fields' in st; continue
    if not in_fields: continue
    m=f2.match(s)
    if not m: continue
    mods=[t for t in m.group(1).split() if t in MODS]
    ttype=' '.join(t for t in m.group(1).split() if t not in MODS)
    if 'static' not in mods or 'const' in mods: continue
    off=m.group(3)
    if off: rows.append((cur,m.group(2),ttype,int(off,16)))
window=[r for r in rows if 0x380<=r[3]<0x400]
print('window 0x380-0x400 rows (oracle order):')
for t,f,ty,o in window: print(f'  {hex(o)} {t}.{f} : {ty}')
win2=[r for r in rows if 0x60<=r[3]<0x90]
print('\nwindow 0x60-0x90:')
for t,f,ty,o in win2[:40]: print(f'  {hex(o)} {t}.{f} : {ty}')
