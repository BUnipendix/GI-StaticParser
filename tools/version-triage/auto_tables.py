#!/usr/bin/env python3
"""Zero-touch secondary-table extraction campaign (mini-orchestrator).

For each target version this runs the universal pipeline with ZERO version
constants of its own:
  1. shape_transfer from a solved seed version (multi-table seed file with
     KNOOD anchors) -> candidate table slots + matched builder functions
  2. symwalk each matched function -> chains + column expressions
  3. validate what solves end-to-end (param tables get the full
     rowtable_solve treatment; others record chains + column constants)

Output: docs/re/zero-touch/<ver>.json -- per-table {base, stride, chain,
columns, validation} with explicit `open` entries where automation failed.

Usage:
  auto_tables.py <ver> [--seed 6.7.0] [--sample-root ~/gire/sample/gi]
                  [--cross-root ~/gire/out/cross] [--out-dir ...]
"""
import argparse, json, subprocess, sys, os, struct

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable if 'python' in sys.executable else '/usr/sbin/python3'
M64 = 0xFFFFFFFFFFFFFFFF

# seed semantics from the SOLVED 6.7 (docs/re/artifacts-6.7.0/*.json),
# expressed as data -- this file carries no target-version constants
SEED_67 = {
    'method_defs': {'slot': 0x38, 'op': 'add', 'imm': 0xD515CAA3, 'stride': 26},
    'param_defs': {'slot': 0x14C, 'op': 'xor', 'imm': 0x12C9258B, 'stride': 8},
    'field_names': {'slot': 0xC, 'op': 'add', 'imm': 0xD34ADB03, 'stride': 8},
    'prop': {'slot': 0x1E8, 'op': 'add', 'imm': 0xE9FF5F7F, 'stride': 10},
    'event': {'slot': 0x140, 'op': 'add', 'imm': 0xB8765480, 'stride': 14},
}


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('version')
    ap.add_argument('--seed', default='6.7.0')
    ap.add_argument('--sample-root', default=os.path.expanduser('~/gire/sample/gi'))
    ap.add_argument('--cross-root', default=os.path.expanduser('~/gire/out/cross'))
    ap.add_argument('--out-dir', default=os.path.expanduser('~/gire/out/zero-touch'))
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)

    vdir = f'{a.sample_root}/{a.version}'
    sites_p = f'{a.cross_root}/sites/{a.version}.json'
    derive_p = f'{a.cross_root}/{a.version}.derive.json'
    seed_sites_p = f'{a.cross_root}/sites/{a.seed}.json'
    seed_derive_p = f'{a.cross_root}/{a.seed}.derive.json'
    for p in (sites_p, derive_p, seed_sites_p, seed_derive_p):
        if not os.path.exists(p):
            print(f'missing input {p}', file=sys.stderr)
            sys.exit(2)

    sites = json.load(open(sites_p))
    seed_sites = json.load(open(seed_sites_p))

    # 1. shape transfer (multi-table seed)
    seed_file = f'{a.out_dir}/seed_{a.seed}.json'
    json.dump({'semantics': {k: dict(slot=v['slot'], op=v['op'], imm=v['imm'], stride=v['stride'])
                             for k, v in SEED_67.items()}}, open(seed_file, 'w'))
    shape_p = f'{a.out_dir}/{a.version}.shape.json'
    r = run([PY, f'{HERE}/shape_transfer.py', seed_file, seed_sites_p, seed_derive_p, sites_p, shape_p])
    if not os.path.exists(shape_p):
        print('shape transfer failed:', r.stdout, r.stderr, file=sys.stderr)
        sys.exit(3)
    shape = json.load(open(shape_p))

    # 2. symwalk matched fns, collect chains + columns
    report = {'version': a.version, 'seed': a.seed, 'tables': {}}
    for name, rec in shape['semantics'].items():
        m = rec.get('match', {})
        p = rec.get('picked', {})
        entry = {'shape_score': m.get('score'), 'matched_fn': m.get('fn'),
                 'slot': p.get('slot'), 'op': p.get('op'), 'imm': p.get('imm'),
                 'base': p.get('resolved')}
        fn = m.get('fn')
        if fn and p.get('slot') is not None:
            sw_p = f'{a.out_dir}/{a.version}.{name}.walk.json'
            run([PY, f'{HERE}/symwalk.py', sites['exe'], '--blob-va', hex(sites['blob_va']),
                 '--site', fn, '--hdr-global', hex(sites['hdr_global']), '--json', sw_p])
            # emulation fallback (R71): follows real control flow into callees,
            # catches movabs+imul chains that window walks miss. Chains are
            # merged into the walk artifact so downstream solvers see both.
            meta = f'{a.sample_root}/{a.version}/YuanShen_Data/Managed/Metadata/global-metadata.dat'
            emu_p = f'{a.out_dir}/{a.version}.{name}.emu.json'
            er = run([PY, f'{HERE}/emu_chain.py', sites['exe'], '--metadata', meta,
                      '--blob-va', hex(sites['blob_va']), '--hdr-global', hex(sites['hdr_global']),
                      '--site', fn, '--fn-start', fn, '--max-insns', '60000', '--json', emu_p])
            if not er.returncode and os.path.exists(emu_p):
                try:
                    emu = json.load(open(emu_p))
                    sw0 = json.load(open(sw_p)) if os.path.exists(sw_p) else {'chains': [], 'columns': [], 'anchors': []}
                    have = {json.dumps(c.get('expr')) for c in sw0.get('chains', [])}
                    for c in emu.get('chains', []):
                        if json.dumps(c.get('expr')) not in have:
                            sw0.setdefault('chains', []).append(c)
                    json.dump(sw0, open(sw_p, 'w'))
                    entry['emu_chains'] = len(emu.get('chains', []))
                except Exception as ex:
                    entry['emu_error'] = str(ex)
            try:
                sw = json.load(open(sw_p))
                from symwalk import expr_str, expr_syms, expr_has  # noqa
                chains = [c for c in sw.get('chains', [])
                          if len(expr_syms(c['expr'])) == 1
                          and not expr_has(c['expr'], 'raw')
                          and not expr_has(c['expr'], 'hdr')
                          and not any(x.startswith(('mem', 'post_call', 'mulhi', 'glob'))
                                      for x in expr_syms(c['expr']))]
                entry['chains'] = [expr_str(c['expr']) for c in chains[:12]]
                entry['columns'] = [dict(off=c['off'], width=c['width'],
                                         expr=expr_str(c['expr'])) for c in sw.get('columns', [])][:12]
                entry['anchors'] = sw.get('anchors', [])[:8]
            except Exception as ex:
                entry['walk_error'] = str(ex)
        report['tables'][name] = entry

    out_p = f'{a.out_dir}/{a.version}.json'
    json.dump(report, open(out_p, 'w'), indent=1)
    ok = sum(1 for t in report['tables'].values() if t.get('chains'))
    print(f'{a.version}: {ok}/{len(report["tables"])} tables yielded chains -> {out_p}')
    for name, t in report['tables'].items():
        print(f"  {name:12s} score={t.get('shape_score')} fn={t.get('matched_fn')} "
              f"base={t.get('base')} chains={len(t.get('chains', []))} cols={len(t.get('columns', []))}")


if __name__ == '__main__':
    main()
