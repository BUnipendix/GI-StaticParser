#!/usr/bin/env python3
"""Generate the per-version profile status matrix by scanning the artifacts/cache dirs.
Writes docs/re/version-status.md.
"""
import json, os, sys

CROSS = '/home/yangsanyi/gire/out/cross'
REPO = '/home/yangsanyi/Documents/git-repo/GI-StaticParser'
SAMPLES = '/home/yangsanyi/gire/sample/gi'

def exists(p): return os.path.exists(p)

def td_rows(v):
    p = f'{CROSS}/tables-{v}.json'
    if not exists(p): return None
    try:
        j = json.load(open(p)); return j['tables'][0]['rows']
    except Exception:
        return None

def artifact(v, name):
    return exists(f'{REPO}/docs/re/artifacts-{v}/{name}')

def main():
    versions = sorted([d for d in os.listdir(SAMPLES) if os.path.isdir(os.path.join(SAMPLES, d))], key=lambda s: [int(x) for x in s.split('.')])
    lines = ['# 各版本 profile 状态矩阵', '',
             '自动扫描生成（tools/version-triage/status_matrix.py）。列含义：',
             'derive=密码/锚点产物；sites=载入点指纹；tables/ranges/typedefs=typeDef 与区间数据；',
             'shape=形态转移结果；method/param/prop/field/event/typearr=已解的布局 JSON。', '']
    lines.append('| 版本 | derive | sites | tables | ranges | typedefs | shape | method | param | prop | field | event | typearr | typeDef 行数 |')
    lines.append('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    for v in versions:
        cells = []
        cells.append('Y' if exists(f'{CROSS}/{v}.derive.json') else '-')
        cells.append('Y' if exists(f'{CROSS}/sites/{v}.json') else '-')
        cells.append('Y' if exists(f'{CROSS}/tables-{v}.json') else '-')
        cells.append('Y' if exists(f'{CROSS}/ranges-{v}.json') else '-')
        cells.append('Y' if exists(f'{CROSS}/typedefs/{v}.jsonl') else '-')
        cells.append('Y' if exists(f'{CROSS}/shape/{v}.json') else '-')
        mp = artifact(v, 'method-param-layout.json') or artifact(v, 'method-layout.json')
        cells.append('Y' if mp else ('P' if artifact(v, 'method-param-layout-candidate.json') else '-'))
        cells.append('Y' if mp else '-')
        cells.append('Y' if artifact(v, 'property-layout.json') else '-')
        cells.append('Y' if (artifact(v, 'field-layout.json') or artifact(v, 'field-name-layout.json')) else '-')
        cells.append('Y' if artifact(v, 'event-layout.json') else '-')
        cells.append('Y' if artifact(v, 'typearr.json') else '-')
        rows = td_rows(v)
        cells.append(str(rows) if rows else '-')
        lines.append('| ' + v + ' | ' + ' | '.join(cells) + ' |')
    lines.append('')
    lines.append('Y=已解/已产出；P=候选未验证；-=缺失。')
    open(f'{REPO}/docs/re/version-status.md', 'w', encoding='utf-8').write(chr(10).join(lines) + chr(10))
    print('wrote docs/re/version-status.md;', len(versions), 'versions')

if __name__ == '__main__':
    main()
