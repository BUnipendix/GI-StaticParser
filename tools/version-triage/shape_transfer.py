#!/usr/bin/env python3
"""Shape-transfer solver: carry a semantic seed (7.1 table slots) to another build.

Why this exists
---------------
The header struct is re-randomised every build (slot ids and the xor/add bias
rotate independently) and the table layout inside the metadata body is shuffled,
so neither slots nor body offsets can be carried over. What *is* stable is the
code: the metadata accessors are the same source functions and compile to the
same normalised instruction shapes (only the immediates/displacements differ).
Measured across 4.8.0..7.1.0 in docs/re/generalize-method.md.

Algorithm
---------
1. Seed: for every semantic (table base / size / string section) take the 7.1
   anchor (header slot, op, immediate) and the function that contains it (the
   nearest 'mov reg,[rip+hdr_global]' load site).
2. Match: fingerprint each load-site function by a constant-free instruction
   skeleton (mnemonic + operand shape, all numbers replaced by '#') and match
   against the target build's load sites (trigram LSH + Jaccard).
3. Extract: re-scan the matched target function with the same slot idiom
   (mov/movsxd reg,[hdr+slot] + add/xor/sub, or mov reg,imm + op [hdr+slot]),
   pick the anchor at the same ordinal position, and resolve it against the
   target header copy: base = hdr[slot] OP imm.
4. The result is a semantic map (constants only -- no code constants, R24).
   Acceptance is decided downstream by the data validators, not here.

Usage
-----
  shape_transfer.py <seed.json> <seed_sites.json> <seed_derive.json> \
                    <target_sites.json> <out.json>

The *_sites.json files are produced by tools/version-triage/loadsites.py.
"""
import json, struct, bisect, sys
from collections import defaultdict, Counter
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

MD = Cs(CS_ARCH_X86, CS_MODE_64); MD.detail = True

# 64-bit canonical register for every capstone alias (the slot idiom is written
# with mixed operand widths across builds: movsxd rsi,[rdx+slot] vs mov esi,imm).
ALIAS = {}
for base in ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'] + ['r%d' % i for i in range(8,16)]:
    ALIAS[base] = base
    if base in ('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'):
        pre = base[1]
        ALIAS['e'+pre] = base
        ALIAS[pre] = base
        ALIAS[{'rax':'al','rcx':'cl','rdx':'dl','rbx':'bl','rsi':'sil','rdi':'dil',
               'rsp':'spl','rbp':'bpl'}[base]] = base
        if base == 'rsi': ALIAS['si'] = base
        if base == 'rdi': ALIAS['di'] = base
        if base == 'rbp': ALIAS['bp'] = base
    else:
        ALIAS[base+'d'] = base; ALIAS[base+'w'] = base; ALIAS[base+'b'] = base
ALIAS['rip'] = 'rip'; ALIAS['eip'] = 'rip'

def canon(name): return ALIAS.get(name, name)

def pe(path):
    d = open(path, 'rb').read()
    pe_off = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe_off + 6)[0]
    opt = pe_off + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    ib = struct.unpack_from('<Q', d, opt + 24)[0] if magic == 0x20b else struct.unpack_from('<I', d, opt + 28)[0]
    secoff = opt + struct.unpack_from('<H', d, pe_off + 20)[0]
    secs = []
    for i in range(nsec):
        o = secoff + i * 40
        vsz, va, rsz, roff = struct.unpack_from('<IIII', d, o + 8)
        secs.append(dict(va=va, vsz=vsz, roff=roff, rsz=min(rsz, len(d) - roff)))
    return d, ib, secs

def va2file(ib, secs, va):
    rva = va - ib
    for s in secs:
        if s['va'] <= rva < s['va'] + max(s['vsz'], s['rsz']):
            return s['roff'] + (rva - s['va'])

def scan_anchors(module, fn_site, hg, window=0x700):
    """Recover (slot, op, imm, addr) for the slot idiom inside one load-site window."""
    d, ib, secs = pe(module)
    fo = va2file(ib, secs, fn_site)
    code = d[fo:fo + window]
    hregs, pending, immreg, out = set(), {}, {}, []
    for ins in MD.disasm(code, fn_site):
        m = ins.mnemonic; ops = ins.operands
        if m in ('mov','movsxd','movzx') and len(ops) == 2:
            o0, o1 = ops
            if o0.type == X86_OP_REG and o1.type == X86_OP_MEM:
                dst = canon(ins.reg_name(o0.reg))
                base = canon(ins.reg_name(o1.mem.base)) if o1.mem.base else ''
                if base == 'rip':
                    tgt = ins.address + ins.size + o1.mem.disp
                    if tgt == hg: hregs.add(dst)
                elif base in hregs:
                    pending[dst] = (int(o1.mem.disp) & 0xFFFFFFFF, ins.address)
            elif o0.type == X86_OP_REG and o1.type == X86_OP_REG:
                a, b = canon(ins.reg_name(o0.reg)), canon(ins.reg_name(o1.reg))
                if a != b:
                    if b in hregs: hregs.add(a)
                    if b in pending: pending[a] = pending[b]
                    if b in immreg: immreg[a] = immreg[b]
            elif o0.type == X86_OP_REG and o1.type == X86_OP_IMM:
                immreg[canon(ins.reg_name(o0.reg))] = int(o1.imm) & 0xFFFFFFFF
            continue
        if m in ('add','xor','sub') and len(ops) == 2:
            o0, o1 = ops
            if o0.type != X86_OP_REG: continue
            an = canon(ins.reg_name(o0.reg))
            if o1.type == X86_OP_REG:
                bn = canon(ins.reg_name(o1.reg))
                if an in pending and bn in immreg:
                    slot, saddr = pending[an]
                    if ins.address - saddr <= 0x40:
                        out.append((slot, m, immreg[bn], ins.address))
            elif o1.type == X86_OP_IMM:
                if an in pending:
                    slot, saddr = pending.pop(an)
                    if ins.address - saddr <= 0x40:
                        out.append((slot, m, int(o1.imm) & 0xFFFFFFFF, ins.address))
            elif o1.type == X86_OP_MEM:
                base = canon(ins.reg_name(o1.mem.base)) if o1.mem.base else ''
                if base in hregs and an in immreg:
                    out.append((int(o1.mem.disp) & 0xFFFFFFFF, m, immreg[an], ins.address))
    return out

def trigrams(fp): return set(tuple(fp[i:i+3]) for i in range(len(fp)-2))

def build_index(sites):
    idx = defaultdict(list)
    for j, s in enumerate(sites):
        for g in trigrams(s['fp']):
            idx[g].append(j)
    return idx

def match(qfp, sites, idx, topn=3):
    tq = trigrams(qfp); cand = Counter()
    for g in tq:
        for j in idx.get(g, ()): cand[j] += 1
    best = []
    for j, _ in cand.most_common(400):
        sj = trigrams(sites[j]['fp'])
        best.append((len(tq & sj) / max(1, len(tq | sj)), j))
    best.sort(reverse=True)
    return best[:topn]

def resolve(raw, op, imm):
    if op == 'add': return (raw + imm) & 0xFFFFFFFF
    if op == 'xor': return (raw ^ imm) & 0xFFFFFFFF
    return (raw - imm) & 0xFFFFFFFF

def read_header(sites):
    d, ib, secs = pe(sites['exe'])
    fo = va2file(ib, secs, sites['blob_va'])
    return d[fo:fo + 0x210]

def main():
    seed_path, seed_sites_path, seed_derive_path, target_sites_path, out_path = sys.argv[1:6]
    seed = json.load(open(seed_path))['semantics']
    seed_sites = json.load(open(seed_sites_path))
    seed_derive = json.load(open(seed_derive_path))
    target_sites = json.load(open(target_sites_path))
    seed_fn_sites = sorted(s['site'] for s in seed_sites['sites'])
    tgt_sites = target_sites['sites']
    tgt_idx = build_index(tgt_sites)
    tgt_hdr = read_header(target_sites)
    result = {'exe': target_sites['exe'], 'blob_va': hex(target_sites['blob_va']),
              'hdr_global': hex(target_sites['hdr_global']), 'semantics': {}}
    for name, sem in seed.items():
        slot, op, imm = sem['slot'], sem['op'], sem['imm']
        anch = [a for a in seed_derive['anchors']
                if a['hdr_off'] == slot and a['op'].lower() == op and a['imm'] == imm]
        if not anch:
            result['semantics'][name] = {'error': 'seed anchor not found in derive artifact'}
            continue
        asite = int(anch[0]['site'], 16)
        i = bisect.bisect_right(seed_fn_sites, asite) - 1
        fn = seed_fn_sites[i]
        seed_seq = scan_anchors(seed_sites['exe'], fn, seed_sites['hdr_global'])
        # The derive artifact records the confirmation site, which can differ from
        # the immediate-op site; match the seed by (slot, op, imm) instead.
        ai = next((k for k, (s, o, m, a) in enumerate(seed_seq)
                   if s == slot and o.lower() == op and m == imm), None)
        seed_off = seed_seq[ai][3] - fn if ai is not None else None
        qfp = next(s['fp'] for s in seed_sites['sites'] if s['site'] == fn)
        cands = match(qfp, tgt_sites, tgt_idx, topn=3)
        rec = {'seed': {'slot': slot, 'op': op, 'imm': hex(imm), 'fn': hex(fn),
                        'anchor_index': ai, 'seq_len': len(seed_seq)}}
        if not cands:
            rec['error'] = 'no function match'
            result['semantics'][name] = rec; continue
        score, j = cands[0]
        tfn = tgt_sites[j]['site']
        tseq = scan_anchors(target_sites['exe'], tfn, target_sites['hdr_global'])
        rec['match'] = {'score': round(score, 4), 'fn': hex(tfn),
                        'runners_up': [{'score': round(s, 4), 'fn': hex(tgt_sites[k]['site'])}
                                       for s, k in cands[1:]], 'seq_len': len(tseq),
                        'anchors': [{'slot': s, 'op': o, 'imm': hex(m), 'addr': hex(a)}
                                    for s, o, m, a in tseq]}
        picked = None
        # L5 validator: a byte-size semantic must be rows*stride, so its resolved
        # value has to be an exact multiple of the row stride. When exactly one
        # candidate in the matched function satisfies that, prefer it over the
        # ordinal heuristic (the ordinal is only a shape prior, the validator is
        # the acceptance test -- R8/R12).
        size_stride = sem.get('size_stride')
        if size_stride:
            passing = []
            for (s2, o2, m2, a2) in tseq:
                if s2 + 4 > len(tgt_hdr): continue
                raw2 = struct.unpack_from('<I', tgt_hdr, s2)[0]
                v2 = resolve(raw2, o2, m2)
                if v2 and v2 % size_stride == 0:
                    passing.append((s2, o2, m2, a2))
            if len(passing) == 1:
                picked = passing[0]
        if picked is None and ai is not None and ai < len(tseq):
            picked = tseq[ai]
        if picked is None and seed_off is not None and tseq:
            # Fallback: same relative position inside the function (instruction
            # encodings shift by a few bytes between builds).
            picked = min(tseq, key=lambda t: abs((t[3] - tfn) - seed_off))
        if picked is None:
            rec['error'] = 'no candidate anchor in the matched function'
            result['semantics'][name] = rec; continue
        s, o, m, a = picked
        raw = struct.unpack_from('<I', tgt_hdr, s)[0] if s + 4 <= len(tgt_hdr) else None
        val = resolve(raw, o, m) if raw is not None else None
        rec['picked'] = {'slot': s, 'op': o, 'imm': hex(m), 'addr': hex(a),
                         'raw': hex(raw) if raw is not None else None,
                         'resolved': hex(val) if val is not None else None,
                         'stride_expected': sem.get('stride')}
        result['semantics'][name] = rec
    json.dump(result, open(out_path, 'w'), indent=1)
    ok = sum(1 for r in result['semantics'].values() if 'picked' in r)
    print('%s: %d/%d semantics resolved -> %s' % (target_sites['exe'], ok, len(result['semantics']), out_path))

if __name__ == '__main__':
    main()
