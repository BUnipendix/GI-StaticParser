#!/usr/bin/env python3
"""End-to-end verification of the 7.1 static-unpack artifacts (counts + sizes).

Usage: python3 tools/final_verify.py [artifact_dir]   (default ~/gire/out/71)
Exit code 0 = every check passed. Expected numbers are the 7.1.0 results recorded in
IMPLEMENTATION_LOG (§83-§88) and docs/re/71-final-status.md.
"""
import json
import os
import re
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser('~/gire/out/71')

EXPECT_SIZE = {
    'dump.cs': 127_769_231,
    'script.json': 176_764_249,
    'attributes.json': 10_025_050,
    'literals.json': 6_287_449,
    'images.json': 14_326,
    'dummy.jsonl': 224_397_559,
    'DummyDll.dll': 146_724_352,
}
EXPECT_DUMMY = {'T': 88_902, 'F': 440_172, 'M': 733_442, 'P': 115_596, 'E': 628, 'A': 70_692}

fail = 0


def check(name, ok, detail):
    global fail
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    if not ok:
        fail = 1


for fname, size in EXPECT_SIZE.items():
    path = os.path.join(OUT, fname)
    actual = os.path.getsize(path) if os.path.exists(path) else -1
    check(f'size {fname}', actual == size, f'{actual} (expected {size})')

# --- dump.cs counts ---
types = methods = props = 0
with open(os.path.join(OUT, 'dump.cs'), encoding='utf-8', errors='replace') as f:
    for ln in f:
        if '// TypeDefIndex:' in ln:
            types += 1
        if '{ } // RVA: 0x' in ln:
            methods += 1
        if re.search(r'\t.*\{ (get|set);', ln):
            props += 1
check('dump.cs typeDefs', types == 88_902, str(types))
check('dump.cs methods', methods == 733_442, str(methods))
check('dump.cs properties', props == 115_596, str(props))

# --- script.json metadata-usage arrays (R20; docs/re/71-usage-tables.md) ---
script_strings = script_meta = script_addresses = 0
with open(os.path.join(OUT, 'script.json'), encoding='utf-8', errors='replace') as f:
    for ln in f:
        if '"Value":' in ln:
            script_strings += 1
        elif '"MethodAddress":' in ln:
            script_meta += 1
        elif '"Addresses":' in ln:
            body = ln.split('[', 1)[1].strip()
            script_addresses = 0 if body.startswith(']') else body.count(',') + 1
check('script.json ScriptString', script_strings == 137_466, str(script_strings))
check('script.json ScriptMetadataMethod', script_meta == 84_875, str(script_meta))
check('script.json Addresses', script_addresses == 483_496, str(script_addresses))

# --- dummy.jsonl record counts ---
counts = {k: 0 for k in EXPECT_DUMMY}
with open(os.path.join(OUT, 'dummy.jsonl'), encoding='utf-8', errors='replace') as f:
    for ln in f:
        i = ln.find('"k":"')
        if i >= 0:
            k = ln[i + 5]
            if k in counts:
                counts[k] += 1
for k, n in EXPECT_DUMMY.items():
    check(f'dummy.jsonl {k} records', counts[k] == n, f'{counts[k]} (expected {n})')

# --- attributes.json ---
attrs = json.load(open(os.path.join(OUT, 'attributes.json'), encoding='utf-8'))
check('attributes.json instances', attrs.get('AttributeCount') == 74_864, str(attrs.get('AttributeCount')))
check('attributes.json recovered', attrs.get('Recovered') == 70_693, str(attrs.get('Recovered')))
check('attributes.json rows', len(attrs.get('Attributes', [])) == 70_693, str(len(attrs.get('Attributes', []))))

# --- images.json ---
images = json.load(open(os.path.join(OUT, 'images.json'), encoding='utf-8'))
img_list = images.get('Images') or images.get('images') or []
check('images.json images', len(img_list) == 75, str(len(img_list)))

# --- literals.json ---
literals = json.load(open(os.path.join(OUT, 'literals.json'), encoding='utf-8'))
check('literals.json entries', len(literals) == 86_108, str(len(literals)))

print('\nRESULT:', 'PASS' if fail == 0 else 'FAIL')
sys.exit(1 if fail else 0)
