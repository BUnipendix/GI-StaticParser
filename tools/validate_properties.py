#!/usr/bin/env python3
"""Compare the statically decoded 7.1 propertyDef table against the 6.4 reference dump.

Not a requirement file: validation tool. The reference dump is a different game version, so
this measures structural agreement on shared library types (mscorlib/System etc.), where
property definitions are stable across versions, plus per-type name-set overlap.
"""
import re, sys, collections

OURS = sys.argv[1] if len(sys.argv) > 1 else '/home/yangsanyi/gire/out/71/dump.cs'
REF = sys.argv[2] if len(sys.argv) > 2 else '/home/yangsanyi/Documents/git-repo/Genshin-Impact-Dump-collection/6.4Dump.cs'

type_re = re.compile(r'^(?:\[.*\]\s*)?(?P<mods>(?:(?:public|private|protected|internal|static|abstract|sealed|readonly|ref)\s+)*)'
                     r'(?:class|struct|interface|enum)\s+(?P<name>[^\s:]+)(?:\s*:\s*(?P<bases>[^{]+))?\s*(?:// TypeDefIndex: (?P<tdi>\d+))?\s*$')

def parse(path):
    types = {}
    cur = None
    in_props = False
    for ln in open(path, encoding='utf-8', errors='replace'):
        ln = ln.rstrip('\n')
        if '// Namespace:' in ln:
            continue
        m = type_re.match(ln)
        if m and ('class ' in ln or 'struct ' in ln or 'interface ' in ln or 'enum ' in ln):
            name = m.group('name')
            cur = name
            types.setdefault(cur, [])
            in_props = False
            continue
        if cur is None:
            continue
        if ln.strip() == '// Properties':
            in_props = True
            continue
        if ln.strip().startswith('// '):
            in_props = False
            continue
        if in_props and ln.strip():
            types[cur].append(ln.strip())
    return types

def prop_name(line):
    # `{mods}{type} {name} { get; set; }` -> name = token before the accessor block
    head = line.split('{', 1)[0].strip()
    return head.split()[-1] if head.split() else ''

ours = parse(OURS)
ref = parse(REF)
shared = [t for t in ours if ours[t] and t in ref and ref[t]]
print(f'types with properties: ours={sum(1 for v in ours.values() if v)} ref={sum(1 for v in ref.values() if v)}')
print(f'property lines: ours={sum(len(v) for v in ours.values())} ref={sum(len(v) for v in ref.values())}')
print(f'shared types with properties on both sides: {len(shared)}')
same_order = 0
inter = 0
union = 0
exact_lines = 0
common_lines = 0
for t in shared:
    a, b = ours[t], ref[t]
    if a == b:
        same_order += 1
    na, nb = set(map(prop_name, a)), set(map(prop_name, b))
    inter += len(na & nb)
    union += len(na | nb)
    sa, sb = set(a), set(b)
    common_lines += len(sa & sb)
    exact_lines += len(sa & sb)
print(f'exact property sequence equal: {same_order}/{len(shared)}')
print(f'property name Jaccard on shared types: {inter}/{union} = {inter/union:.4f}' if union else 'n/a')
print(f'exact line matches on shared types: {common_lines}')
# Corelib-ish namespaces are the cross-version-stable part (no independent property-name
# obfuscation there); this is the meaningful structural metric for a table recovered from a
# different game version.
core = [t for t in shared if t.startswith(('System.', 'Mono.', 'UnityEngine.'))]
if core:
    ci = sum(len(set(map(prop_name, ours[t])) & set(map(prop_name, ref[t]))) for t in core)
    cu = sum(len(set(map(prop_name, ours[t])) | set(map(prop_name, ref[t]))) for t in core)
    cseq = sum(1 for t in core if ours[t] == ref[t])
    print(f'corelib-ish shared types: {len(core)}, sequence equal {cseq}, name Jaccard {ci}/{cu} = {ci/cu:.4f}')
# accessor shape histogram on our side
shapes = collections.Counter()
for v in ours.values():
    for ln in v:
        acc = ln.split('{', 1)[1].split('}', 1)[0] if '{' in ln else ''
        shapes[acc.strip()] += 1
print('our accessor shapes:', shapes.most_common(6))
# per-visibility count
vis = collections.Counter()
for v in ours.values():
    for ln in v:
        vis[ln.split()[0]] += 1
print('our property visibility:', vis.most_common())
