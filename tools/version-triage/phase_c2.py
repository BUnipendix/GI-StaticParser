#!/usr/bin/env python3
"""Phase C post-processor: redo typeDef discovery from triage JSONs, no exe rescan.
Stride candidate pool = union of strides seen in any version's records (data-derived).
"""
import json, os, glob, struct, sys
from collections import Counter, defaultdict

OUT=sys.argv[1]
BASE='/home/yangsanyi/gire/sample/gi'
import re
files=sorted(f for f in glob.glob(os.path.join(OUT,'*.json')) if re.match(r'^\d+\.\d+\.\d+\.json$',os.path.basename(f)))
data={}
stride_pool=set()
for p in files:
    v=os.path.basename(p)[:-5]
    try: data[v]=json.load(open(p))
    except Exception: pass
for d in data.values():
    for k,e in d.get('slots',{}).items():
        for s in e.get('strides',[]): stride_pool.add(s)
print('stride pool:',sorted(stride_pool),file=sys.stderr)

def vkey(v): return [int(x) for x in v.split('.')]
res={}
for v in sorted(data,key=vkey):
    d=data[v]
    if d.get('hdr_global') is None: continue
    blob=(d.get('blob_cands') or [None])[0]
    if not blob or not blob.get('score') or blob['score'][1]==0: continue
    blob_va=blob['va']
    import mmap
    _f=open(os.path.join(BASE,v,'YuanShen.exe'),'rb')
    exe=mmap.mmap(_f.fileno(),0,access=mmap.ACCESS_READ)
    e=struct.unpack('<I',exe[0x3C:0x40])[0]
    nsec=struct.unpack('<H',exe[e+6:e+8])[0]; optsz=struct.unpack('<H',exe[e+20:e+22])[0]
    ib=struct.unpack('<Q',exe[e+24+24:e+24+32])[0]
    secs=[]
    for i in range(nsec):
        o=e+24+optsz+40*i
        nm=exe[o:o+8].rstrip(b'\x00').decode('latin1')
        vsz,va,rsz,ro=struct.unpack('<IIII',exe[o+8:o+24])
        secs.append((nm,ib+va,max(vsz,rsz),ro,rsz))
    hdr=None
    for (nm,sva,vsz,ro,rsz) in secs:
        if sva<=blob_va<sva+vsz:
            off=blob_va-sva
            hdr=bytes(exe[ro+off:ro+off+0x210]); break
    if hdr is None or len(hdr)<0x210: continue
    _g=open(os.path.join(BASE,v,'YuanShen_Data/Managed/Metadata/global-metadata.dat'),'rb')
    _mm=mmap.mmap(_g.fileno(),0,access=mmap.ACCESS_READ)
    class BV:
        def __init__(s,m): s.m=m; s.base=0x210
        def __len__(s): return max(0,len(s.m)-0x210)
        def __getitem__(s,sl):
            if isinstance(sl,slice): return s.m[sl.start+0x210:sl.stop+0x210]
            return s.m[sl+0x210]
    body=BV(_mm)
    def u32(b,o): return struct.unpack('<I',b[o:o+4])[0]
    def dec(slot,op,imm):
        raw=u32(hdr,slot)
        if op=='xor': return raw^(imm&0xFFFFFFFF)
        if op=='add': return (raw+imm)&0xFFFFFFFF
        if op=='sub': return (raw-imm)&0xFFFFFFFF
        return raw
    cands=[]
    for k,e2 in d.get('slots',{}).items():
        parts=k.split('|')
        if len(parts)<3 or parts[1]=='None': continue
        slot=int(parts[0],16); op=parts[1]; imm=int(parts[2],16) if parts[2].startswith('0x') else int(parts[2])
        if e2['n']<2: continue
        base=dec(slot,op,imm)
        if base<=0 or base>=len(body)-0x1000: continue
        for S in sorted(stride_pool):
            if S<8 or S>0x200: continue
            if base+4*S>len(body): continue
            best=None
            for dd in range(0,S-3,4):
                lim=min(1024,(len(body)-base-dd)//S)
                if lim<512: continue
                cc=Counter(u32(body,base+i*S+dd) for i in range(lim))
                (mv,mc),=cc.most_common(1)
                if best is None or mc>best[1]: best=(dd,mc,mv,lim)
            if best and best[1]>=0.55*best[3]:
                # extra: profile at 0x1C if within row
                prof={}
                for dd2 in (0x1C,0x34):
                    if dd2<S-3:
                        rows_n=min(512,(len(body)-base-dd2)//S)
                        if rows_n<64: continue
                        cc2=Counter(u32(body,base+i*S+dd2) for i in range(rows_n))
                        (m2,c2),=cc2.most_common(1)
                        prof['0x%X'%dd2]=[hex(m2),round(c2/rows_n,3)]
                cands.append({'slot':hex(slot),'op':op,'imm':hex(imm&0xFFFFFFFF),'stride':S,
                              'base':hex(base),'best_dd':hex(best[0]),'maj':best[1],'lim':best[3],
                              'maj_val':hex(best[2]),'n':e2['n'],'prof':prof})
    cands.sort(key=lambda t:(-t['n'],-t['maj']))
    res[v]=cands[:3]
json.dump(res,open(os.path.join(OUT,'phase_c2.json'),'w'),indent=1)
for v in sorted(res,key=vkey):
    print(v, json.dumps(res[v][:1]))
