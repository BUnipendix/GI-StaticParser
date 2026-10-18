#!/usr/bin/env python3
"""Cross-version profile diff: compare two versions' table layouts (slot/op/imm, stride,
mask chains, column offsets) and emit a markdown report.

Usage: diff_profiles.py <artA dir> <artB dir> <labelA> <labelB> <out.md>
Artifact files are looked up by name with fallbacks so different schema generations work.
"""
import json, os, sys

def load_first(d, names):
    for n in names:
        p = os.path.join(d, n)
        if os.path.exists(p):
            return json.load(open(p)), n
    return None, None

def norm_method(d):
    """Return {family: {'table':..,'stride':..,'rows':..,'mask':..,'columns':{name:off}}}."""
    j, fn = load_first(d, ['method-param-layout.json', 'method-layout.json'])
    if not j:
        return None, fn
    out = {}
    if 'method_table' in j:  # flat 6.7 schema
        out['method'] = {'table': j['method_table'], 'stride': j['method_stride'], 'rows': j.get('method_rows'), 'mask': j.get('method_mask'), 'columns': j.get('method_columns')}
        out['param'] = {'table': j['param_table'], 'stride': j['param_stride'], 'mask': j.get('param_mask'), 'columns': j.get('param_columns')}
    else:  # nested 7.0 schema
        m = j['method']; p = j['param']
        out['method'] = {'table': m['table'], 'stride': m['stride'], 'rows': m.get('rows'), 'mask': m.get('mask'), 'columns': m.get('columns')}
        out['param'] = {'table': p['table'], 'stride': p['stride'], 'mask': p.get('mask'), 'columns': {'name': p.get('name'), 'type': p.get('type')}}
    return out, fn

def norm_field(d):
    j, fn = load_first(d, ['field-layout.json', 'field-name-layout.json'])
    if not j:
        return None, fn
    cols = {}
    for k, v in j.get('columns', {}).items():
        cols[k] = v.get('off')
    return {'': {'table': j['table'], 'stride': j['stride'], 'rows': j.get('rows'), 'mask': j.get('mask'), 'columns': cols}}, fn

def norm_property(d):
    j, fn = load_first(d, ['property-layout.json'])
    if not j:
        return None, fn
    return {'': {'table': j['table'], 'stride': j['stride'], 'rows': j.get('rows'), 'mask': j.get('mask'), 'columns': {k: v.get('off') for k, v in j.get('columns', {}).items()}}}, fn

def norm_event(d):
    j, fn = load_first(d, ['event-layout.json'])
    if not j:
        return None, fn
    return {'': {'table': j['table'], 'stride': j['stride'], 'rows': j.get('rows'), 'mask': j.get('mask'), 'columns': {k: v.get('off') for k, v in j.get('columns', {}).items()}}}, fn

def norm_typearr(d):
    j, fn = load_first(d, ['typearr.json'])
    if not j:
        return None, fn
    return {'': {'va': j.get('va'), 'count': j.get('count'), 'entry': j.get('entry')}}, fn

def fmt(v):
    if isinstance(v, dict):
        return ' '.join(f'{k}={v[k]}' for k in sorted(v))
    return str(v)

def main():
    a, b, la, lb, out = sys.argv[1:6]
    fams = [('method', norm_method), ('field', norm_field), ('property', norm_property), ('event', norm_event)]
    lines = [f'# 跨版本 profile 差异：{la} vs {lb}', '']
    for name, fn in fams:
        ja = fn(a)[0] or {}; jb = fn(b)[0] or {}
        for sub in sorted(set(ja) | set(jb)):
            sa = ja.get(sub); sb = jb.get(sub)
            title = name if sub == '' else f'{name}.{sub}'
            lines.append(f'## {title}')
            lines.append('')
            if not sa or not sb:
                lines.append(f'- {la}: {"缺失" if not sa else "有"} / {lb}: {"缺失" if not sb else "有"}')
                lines.append('')
                continue
            lines.append('| 项 | ' + la + ' | ' + lb + ' | 差异 |')
            lines.append('|---|---|---|---|')
            for k in ('table', 'stride', 'rows', 'mask'):
                va, vb = fmt(sa.get(k)), fmt(sb.get(k))
                lines.append(f'| {k} | {va} | {vb} | ' + ('同' if sa.get(k) == sb.get(k) else '**异**') + ' |')
            ca, cb = sa.get('columns') or {}, sb.get('columns') or {}
            for ck in sorted(set(ca) | set(cb)):
                va, vb = ca.get(ck), cb.get(ck)
                lines.append(f'| col:{ck} | {va} | {vb} | ' + ('同' if va == vb else '**异**') + ' |')
            lines.append('')
    ta = (norm_typearr(a)[0] or {}).get(''); tb = (norm_typearr(b)[0] or {}).get('')
    lines.append('## typearr')
    lines.append('')
    if ta and tb:
        lines.append('| 项 | ' + la + ' | ' + lb + ' | 差异 |')
        lines.append('|---|---|---|---|')
        for k in ('va', 'count'):
            same = '同' if ta.get(k) == tb.get(k) else '**异**'
            lines.append(f'| {k} | {ta.get(k)} | {tb.get(k)} | {same} |')
    else:
        lines.append('（一侧缺失）')
    open(out, 'w', encoding='utf-8').write(chr(10).join(lines) + chr(10))
    print('written', out, len(lines), 'lines')

if __name__ == '__main__':
    main()
