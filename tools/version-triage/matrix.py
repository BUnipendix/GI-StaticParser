#!/usr/bin/env python3
"""Analyze triage outputs across versions: constant rotation / epochs / coverage."""
import json, os, glob, sys
from collections import defaultdict

OUT=sys.argv[1] if len(sys.argv)>1 else '/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage/out'
def vkey(v):
    return [int(x) for x in v.split('.')]
rows={}
for p in sorted(glob.glob(os.path.join(OUT,'*.json'))):
    v=os.path.basename(p)[:-5]
    try: rows[v]=json.load(open(p))
    except Exception as ex:
        rows[v]={'error':str(ex)}
vers=sorted(rows,key=vkey)
print('== per-version summary ==')
print('%-7s %-6s %-12s %-10s %-6s %s'%('ver','recs','hdr@','blob','slots','typeDef#1 (slot|op|imm|stride|base|sentinel_raw@off)'))
sets={}
for v in vers:
    d=rows[v]
    if 'error' in d or d.get('hdr_global') is None:
        print('%-7s FAIL %s'%(v,d.get('error','no hdr'))) ; continue
    td=(d.get('typedef_tables') or [None])[0]
    tds='-'
    if td:
        tds='%s|%s|%s|S=%d|%s|@+0x%X=0x..%s'%(td['slot'],td['op'],td['imm'],td['stride'],td['base'],td['sentinel_off'],td['sentinel_raw'][-6:])
    print('%-7s %-6d %-12s %-10s %-6d %s'%(v,d['recs'],hex(d['hdr_global']),hex((d.get('blob_cands') or [{}])[0].get('va',0)) if (d.get('blob_cands') or [{}])[0] else '-',len(d['slots']),tds))
    sets[v]={k for k,e in d['slots'].items() if e['body']>=1}
print()
print('== adjacent-version constant-set Jaccard (typeDef-relevant slots only) ==')
for a,b in zip(vers,vers[1:]):
    if a in sets and b in sets:
        A,B=sets[a],sets[b]
        j=len(A&B)/len(A|B) if A|B else 1
        same='SAME' if A==B else ('%d common, %d only-%s, %d only-%s'%(len(A&B),len(A-B),a,len(B-A),b))
        print('%-7s->%-7s J=%.2f  %s'%(a,b,j,same if A!=B else 'IDENTICAL'))
print()
print('== typeDef table constants by version (from ranked #1) ==')
grp=defaultdict(list)
for v in vers:
    d=rows[v]
    td=(d.get('typedef_tables') or [None])[0]
    if td: grp[(td['slot'],td['op'],td['imm'],td['stride'])].append(v)
for k,vs in sorted(grp.items(),key=lambda kv:len(kv[1]),reverse=True):
    print('%s %s %s S=%d  ->  %s'%(k[0],k[1],k[2],k[3],', '.join(vs)))
