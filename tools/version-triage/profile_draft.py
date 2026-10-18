#!/usr/bin/env python3
"""Assemble one build's solved layout pieces into a single profile draft (data only).

The draft is the hand-off artifact of the "profile derivation pipeline": every piece is
already solved elsewhere (derive / tables / find_type_ranges / method_rows layout /
property_rows layout) and this tool only composes, checks presence, and reports what is
still missing. It refuses to write a draft that would silently claim a table it does not
have: unresolved tables are listed explicitly under "unresolved".

Usage:
  profile_draft.py <version dir> <out.json> <derive.json> <tables.json> <typedefs.jsonl>
                   <ranges.json> <method-layout.json> <property-layout.json>
"""
import json, struct, sys

def h(s):
    return int(s, 16) if isinstance(s, str) else s

def fail(msg):
    print('profile_draft: ' + msg, file=sys.stderr)
    sys.exit(1)

def main():
    (vdir, out, derive_p, tables_p, typedefs_p,
     ranges_p, method_p, property_p) = sys.argv[1:9]
    derive = json.load(open(derive_p))
    tables = json.load(open(tables_p))
    ranges = json.load(open(ranges_p))
    mlay = json.load(open(method_p))
    play = json.load(open(property_p))
    trows = [json.loads(l) for l in open(typedefs_p, encoding='utf-8')]
    if not trows:
        fail('empty typeDef list')
    t = tables['tables'][0]
    cols = tables['string_columns']
    name = [c for c in cols if c['rows_ok'] == c['rows_tested']]
    ns = [c for c in cols if c not in name and c['rows_ok'] >= 30]
    if not name:
        fail('no name column recovered for typeDef')
    idx_tables = tables['tables']
    fld = min(idx_tables, key=lambda x: x['max_index'])
    mth = max(idx_tables, key=lambda x: x['max_index'])
    prop_pair = ev_pair = None
    for r in ranges:
        if r['start_off'] == fld['idx_off'] and r['cnt_off'] == fld['cnt_off']:
            continue
        if r['start_off'] == mth['idx_off'] and r['cnt_off'] == mth['cnt_off']:
            continue
        if r['chain_rows'] > 10000 and r['end'] > 5000 and prop_pair is None:
            prop_pair = r
        elif r['chain_rows'] >= 50 and r['end'] <= 5000 and ev_pair is None:
            ev_pair = r
    draft = {
        'artifact': 'profile-draft',
        'artifact_version': 1,
        'version_dir': vdir,
        'cipher': derive.get('cipher'),
        'hdr_global': None,
        'type_defs': {
            'base': t['base'], 'stride': t['stride'], 'rows': t['rows'],
            'name_column': {'off': name[0]['off'], 'transform': name[0]['transform'], 'c': name[0]['c']},
            'namespace_column': ({'off': ns[0]['off'], 'transform': ns[0]['transform'], 'c': ns[0]['c']}
                                 if ns else None),
            'field_range': fld, 'method_range': mth,
            'property_range': prop_pair, 'event_range': ev_pair,
        },
        'method': {'table': mlay['method']['table'], 'stride': mlay['method']['stride'],
                   'rows': mlay['method']['rows'], 'mask': mlay['method']['mask'],
                   'columns': mlay['method']['columns']},
        'param': {'table': mlay['param']['table'], 'stride': mlay['param']['stride'],
                  'mask': mlay['param']['mask'], 'columns': {'name': mlay['param']['name'],
                                                             'type': mlay['param']['type']}},
        'property': {'table': play['table'], 'stride': play['stride'], 'rows': play['rows'],
                     'mask': play['mask'], 'columns': play['columns']},
        'unresolved': ['field table (name/type/attrs)', 'method slot/slot column',
                       'typeDef flags/bitfield/parent/nested ranges',
                       'generic tables', 'param default values', 'usage/literal tables'],
        'counts': {
            'types': len(trows),
            'types_named': sum(1 for r in trows if r['name']),
            'field_rows': sum(r['fieldCount'] for r in trows),
            'method_rows': sum(r['methodCount'] for r in trows),
            'property_rows': sum(r['propCount'] or 0 for r in trows),
            'event_rows': sum(r['eventCount'] or 0 for r in trows),
        },
    }
    json.dump(draft, open(out, 'w'), indent=1)
    print(f'profile draft -> {out}')
    print('  counts:', draft['counts'])
    print('  unresolved:', ', '.join(draft['unresolved']))

if __name__ == '__main__':
    main()
