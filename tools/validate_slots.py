import re
from collections import defaultdict
name_re=re.compile(r'^(?:(?:public|internal|private|protected|static|abstract|sealed)\s+)*(class|struct|interface|enum) ([^ :]+?)((?: : .*)?)$')
method_re=re.compile(r'^\t(.+) \{ \} // RVA: 0x[0-9a-f]+ Token: 0x([0-9a-f]+) Slot: (-?\d+)$')
def split_params(s):
    if s=='': return []
    out=[]; depth=0; cur=''
    for ch in s:
        if ch=='<': depth+=1
        elif ch=='>': depth-=1
        if ch==',' and depth==0: out.append(cur.strip()); cur=''
        else: cur+=ch
    if cur.strip(): out.append(cur.strip())
    return out
MODS=('public','internal','private','protected','static','abstract','sealed','virtual','override','extern','new','readonly')
def parse(path):
    blocks=[]; cur=None
    for line in open(path,errors='replace'):
        s=line.rstrip('\r\n')
        if not s or s.startswith('//'): continue
        if not s.startswith('\t'):
            i=s.find(' //')
            if i>0: s=s[:i]
            m=name_re.match(s)
            if m:
                tail=m.group(3).strip()
                parts=[x.strip() for x in tail[1:].split(',')] if tail.startswith(':') else []
                cur=dict(name=m.group(2), base=(parts[0] if parts else None), ifaces=parts[1:], methods=[])
                blocks.append(cur)
            continue
        if cur is None: continue
        m=method_re.match(s)
        if not m: continue
        sig=m.group(1); tok=int(m.group(2),16); slot=int(m.group(3))
        pm=re.match(r'^(.+?) ([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$',sig)
        if not pm: continue
        mods=tuple(x for x in pm.group(1).split() if x in MODS)
        cur['methods'].append((tok,pm.group(2),tuple(split_params(pm.group(3))),mods,slot))
    for b in blocks: b['methods'].sort(key=lambda x:x[0])
    byname=defaultdict(list)
    for b in blocks: byname[b['name']].append(b)
    return blocks,byname
def sigset(b): return set((x[1],x[2]) for x in b['methods'])
ors,obn=parse('/home/yangsanyi/Documents/git-repo/Genshin-Impact-Dump-collection/6.4Dump.cs')
mys,mbn=parse('/home/yangsanyi/gire/out/71/dump.cs')
def uniq(bn): return {k:v[0] for k,v in bn.items() if len(v)==1}
om=uniq(obn); mm=uniq(mbn)
tot=eq=0; same=0; skip=0; mism=[]; reasons=defaultdict(int)
for name in set(om)&set(mm):
    if '`' in name or '<' in name: continue
    o=om[name]; m=mm[name]
    if [(x[1],x[2]) for x in o['methods']] != [(x[1],x[2]) for x in m['methods']]: reasons['seq']+=1; continue
    if [(x[3]) for x in o['methods']] != [(x[3]) for x in m['methods']]: reasons['mods']+=1; continue
    if o['base']!=m['base']: reasons['base']+=1; continue
    if o['ifaces']!=m['ifaces']: reasons['iface_order']+=1; continue
    ok=True
    for iname in o['ifaces']:
        a=om.get(iname); b=mm.get(iname)
        if a is None or b is None or sigset(a)!=sigset(b): ok=False; break
    if not ok: reasons['iface_content']+=1; continue
    same+=1
    for ox,mx in zip(o['methods'],m['methods']):
        if ox[4]>=0:
            tot+=1
            if ox[4]==mx[4]: eq+=1
            elif len(mism)<10: mism.append((name,ox[1],ox[2],ox[4],mx[4]))
print('reasons:',dict(reasons))
print(f'fully-identical types={same}')
print(f'slot agreement: {eq}/{tot} = {eq/max(tot,1):.2%}')
for x in mism: print('  ',x)
