#!/usr/bin/env python3
"""Data-side semantic solver for one metadata row table (L4b/L5 of
docs/re/generalize-method.md).

Inputs (all DATA, no version constants in this file):
  * version dir + derive artifact (cipher + anchors) + sites artifact (exe/blob)
  * table candidates: base (slot/op/imm) + stride + expected rows
  * symwalk artifacts for the anchor sites (chains + column exprs)
  * heap string enumeration (mhydump strings --out) for known-plaintext pinning
  * prior-version name prefix (cross-version stable corelib order) -- optional

It then:
  1. picks the true table base among candidates by decoding power,
  2. identifies the row mask chain (validated by name-column decoding),
  3. solves each column semantic (name / param_start / param_count / flags /
     return_type / type) with structural validators,
  4. emits a layout JSON (same shape as docs/re/artifacts-*/method-layout.json,
     but with generic expression trees) plus a validation report.

Usage (see auto_profile.py for orchestration):
  rowtable_solve.py --vdir <dir> --derive d.json --sites s.json
      --strings strings.json --semantic method
      --base-candidates '[{"slot":"0x134","op":"add","imm":"0x861f234f"}]'
      [--prior-names prior.json] [--out layout.json]
"""
import argparse, json, re, struct, sys
import numpy as np

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from symwalk import expr_str, expr_syms, expr_has  # noqa: E402

M64 = 0xFFFFFFFFFFFFFFFF
IDRE = re.compile(r'^[A-Za-z_.<>`][A-Za-z0-9_.<>`=+,-]*$')


def pe_map(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]
    opt = pe + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    ib = struct.unpack_from('<Q', d, opt + 24)[0] if magic == 0x20b else struct.unpack_from('<I', d, opt + 28)[0]
    so = opt + struct.unpack_from('<H', d, pe + 20)[0]
    secs = []
    for i in range(n):
        o = so + i * 40
        vsz, va, rsz, roff = struct.unpack_from('<IIII', d, o + 8)
        secs.append((va, vsz, roff, min(rsz, len(d) - roff)))
    return d, ib, secs


def va2file(ib, secs, va):
    rva = va - ib
    for sva, vsz, roff, rsz in secs:
        if sva <= rva < sva + max(vsz, rsz):
            return roff + (rva - sva)
    return None


class Cipher:
    def __init__(self, art):
        c = art['cipher']
        self.ops = [(o['op'], o['v']) for o in c['schedule']['ops']]
        self.step = c['schedule']['step']
        self.strsec = c['strsec']

    def key(self, off):
        v = off & 0xFFFFFFFF
        for k, val in self.ops:
            if k == 'And': v &= val
            elif k == 'Mul': v = (v * val) & M64
            elif k == 'Add': v = (v + val) & M64
            elif k == 'Xor': v ^= val
            elif k == 'Sub': v = (v - val) & M64
        return v

    def dec_len(self, body, idx, n):
        """Decode exactly n bytes for packed index idx; None if unreadable."""
        if idx == 0xFFFFFFFF: return None
        off = idx & 0xFFFFFF
        ln = (idx >> 24) & 0xFF
        if ln != n: return None
        nq = (n + 7) >> 3
        src = self.strsec + off
        if src + nq * 8 + 8 > len(body): return None
        k = self.key(off)
        buf = bytearray()
        for i in range(nq):
            enc = struct.unpack_from('<Q', body, src + 8 * i)[0]
            buf += (enc ^ k).to_bytes(8, 'little')
            k = (k + self.step) & M64
        b = bytes(buf[:n])
        if any(x < 0x20 or x > 0x7e for x in b): return None
        return b.decode('utf-8', 'replace')


def read_col(body, base, stride, off, width, rows):
    a = np.frombuffer(body, dtype=np.uint8)
    idx = np.arange(rows, dtype=np.int64)
    start = base + off
    if start < 0 or start + stride * (rows - 1) + width > len(body):
        return None
    if width == 1:
        return a[start + stride * idx].astype(np.uint64)
    v = a[start + stride * idx].astype(np.uint64)
    for k in range(1, width):
        v |= a[start + stride * idx + k].astype(np.uint64) << np.uint64(8 * k)
    return v


class ExprEval:
    """Evaluate a symwalk expr over rows; raw/sym leaves resolved by caller."""

    def __init__(self, body, base, stride, rows):
        self.body, self.base, self.stride, self.rows = body, base, stride, rows
        self._cache = {}

    def col(self, off, w):
        k = (off, w)
        if k not in self._cache:
            self._cache[k] = read_col(self.body, self.base, self.stride, off, w, self.rows)
        return self._cache[k]

    def ev(self, e, sym):
        t = e[0]
        if t == 'imm': return np.uint64(e[1] & M64)
        if t == 'sym':
            if e[1] == sym: return np.arange(self.rows, dtype=np.uint64)
            raise ValueError('foreign sym ' + e[1])
        if t == 'raw': return self.col(e[1], e[2] // 8)
        if t == 'op2':
            a = self.ev(e[2], sym); b = self.ev(e[3], sym)
            op = e[1]
            if op == '+': return (a + b) & M64
            if op == '-': return (a - b) & M64
            if op == '*': return (a * b) & M64
            if op == '^': return a ^ b
            if op == '&': return a & b
            if op == '|': return a | b
            if op == '>>': return a >> np.uint64(int(b) if isinstance(b, np.uint64) else int(b))
            if op == '<<': return (a << np.uint64(int(b))) & M64
            raise ValueError(op)
        if t == 'lo':
            return self.ev(e[2], sym) & np.uint64((1 << e[1]) - 1)
        if t == 'ext':
            n = e[1]
            a = self.ev(e[2], sym) & np.uint64((1 << n) - 1)
            if e[3]:
                mask = np.uint64((((1 << (64 - n)) - 1) << n) & M64)
                a = np.where((a & np.uint64(1 << (n - 1))) != 0, a | mask, a).astype(np.uint64)
            return a
        raise ValueError(t)


def chain_pure(e):
    """A recorded chain usable as mask(i): pure function of exactly one sym."""
    s = expr_syms(e)
    if len(s) != 1 or expr_has(e, 'raw') or expr_has(e, 'hdr'):
        return None
    return next(iter(s))


# ---------------------------------------------------------------- heap index
class HeapIndex:
    """String-start offsets from `mhydump strings --out` (off<TAB>decoded-text)."""

    def __init__(self, path):
        self.text = {}
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                tab = line.find('\t')
                if tab <= 0: continue
                try:
                    off = int(line[:tab], 16)
                except ValueError:
                    continue
                self.text[off] = line[tab + 1:].rstrip('\n')
        self.offs = np.array(sorted(self.text), dtype=np.int64)

    def starts_with(self, s, limit=64):
        """Offsets whose decoded text begins with s (string starts)."""
        out = []
        # linear scan is fine at load time for a handful of probes; for many
        # probes use the sorted offsets + dict
        for off, t in self.text.items():
            if t.startswith(s):
                out.append(off)
                if len(out) >= limit:
                    break
        return out

    def check(self, idx, name):
        """packed idx decodes to exactly `name`?"""
        ln = (int(idx) >> 24) & 0xFF
        if ln != len(name):
            return False
        t = self.text.get(int(idx) & 0xFFFFFF)
        return t is not None and t.startswith(name)


# ---------------------------------------------------------------- column solvers
FAMILIES = ('SubMaskAddC', 'AddCSubMask', 'XorCXorMask', 'AddCXorMask', 'XorCSubMask')


def fam_value(fam, raw, mask, C, dom=M64):
    """dom: 0xFFFFFFFF for u32 columns (the game's own arithmetic truncates
    to the column width; without it sentinel wraparounds show as 64-bit junk)."""
    if fam == 'SubMaskAddC': return (raw - mask + C) & dom
    if fam == 'AddCSubMask': return (raw + C - mask) & dom
    if fam == 'XorCXorMask': return ((raw ^ C) ^ mask) & dom
    if fam == 'AddCXorMask': return (((raw + C) & dom) ^ mask) & dom
    if fam == 'XorCSubMask': return ((raw ^ C) - mask) & dom
    raise ValueError(fam)


def fam_invert(fam, raw, mask, idx):
    """C such that fam_value(fam, raw, mask, C) == idx (all uint32 domain)."""
    raw, mask, idx = int(raw) & 0xFFFFFFFF, int(mask) & 0xFFFFFFFF, int(idx) & 0xFFFFFFFF
    if fam in ('SubMaskAddC', 'AddCSubMask'):
        return (idx - raw + mask) & 0xFFFFFFFF
    if fam == 'XorCXorMask':
        return (raw ^ mask ^ idx) & 0xFFFFFFFF
    if fam == 'AddCXorMask':
        return ((idx ^ mask) - raw) & 0xFFFFFFFF
    if fam == 'XorCSubMask':
        return (raw ^ ((idx + mask) & 0xFFFFFFFF)) & 0xFFFFFFFF
    raise ValueError(fam)


def solve_name_column(body, base, stride, rows, mask, heap, cipher, prior_names, sample=4000):
    """Pin (off, width=4, family, C) for a packed-string-index column.

    prior_names: expected names for rows 0..K-1 (cross-version stable corelib
    order). C candidates are inverted from the first rows whose name has heap
    starts; verified against more rows + identifier rate over `sample` rows.
    """
    nr = min(rows, max(sample, 64))
    raws = {off: read_col(body, base, stride, off, 4, nr) for off in range(0, stride - 3)}
    m = mask[:nr]
    prefix_cache = {}

    def starts(name):
        if name not in prefix_cache:
            prefix_cache[name] = [o | (len(name) << 24) for o in heap.starts_with(name, limit=48)]
        return prefix_cache[name]

    best = None
    K = min(len(prior_names), 24)
    pin_rows = [r for r in range(min(K, 8)) if starts(prior_names[r])][:4]
    for off, raw in raws.items():
        if raw is None:
            continue
        for fam in FAMILIES:
            for r in pin_rows:
                for idx in starts(prior_names[r]):
                    C = fam_invert(fam, raw[r], m[r], idx)
                    quick = _score_name(body, min(nr, 40), m, heap, raw, fam, C, 40)
                    if quick[0] < 20 or quick[1] < 0.9:
                        continue
                    ok_rows, idrate = _score_name(body, nr, m, heap, raw, fam, C, sample)
                    cand = dict(off=off, width=4, family=fam, C=hex(C), pinned_row=r,
                                ok_rows=ok_rows, idrate=round(idrate, 4))
                    if best is None or (ok_rows, idrate) > (best['ok_rows'], best['idrate']):
                        best = cand
    return best


def _name_decode_stats(body, rows, mask, heap, raw, fam, C, sample):
    n = min(rows, sample)
    vals = fam_value(fam, raw[:n], mask[:n], C)
    ok = 0
    good = 0
    for v in vals:
        v = int(v)
        t = heap.text.get(v & 0xFFFFFF)
        if t is None: continue
        ln = (v >> 24) & 0xFF
        if 1 <= ln <= 120 and len(t) >= ln:
            s = t[:ln]
            ok += 1
            if IDRE.match(s): good += 1
    return ok, good


def _verify_name(body, rows, mask, heap, raw, fam, C, prior_names, skip_row):
    hit = 0
    for r, name in enumerate(prior_names[:16]):
        if r == skip_row: continue
        v = int(fam_value(fam, raw[r:r + 1], mask[r:r + 1], C)[0])
        if heap.check(v, name):
            hit += 1
    return hit >= min(5, len(prior_names) - 2)


def _score_name(body, rows, mask, heap, raw, fam, C, sample):
    ok, good = _name_decode_stats(body, rows, mask, heap, raw, fam, C, sample)
    # idrate = identifier share AMONG DECODED rows (heap enumeration misses
    # short strings, so the raw hit rate plateaus around 0.6)
    return ok, (good / max(1, ok))


def name_column_ok(col, sample=4000):
    """Acceptance: enough rows hit the enumerated heap AND almost all decoded
    rows are identifiers."""
    if not col:
        return False
    return col['ok_rows'] >= max(200, 0.45 * min(sample, 4000)) and col['idrate'] >= 0.95


def solve_count_column(body, base, stride, rows, mask, off_max, sample=20000):
    """u8 count column: decoded mode must be 0, values small."""
    n = min(rows, sample)
    out = []
    for off in range(0, min(off_max, stride)):
        raw = read_col(body, base, stride, off, 1, rows)
        if raw is None: continue
        m8 = mask[:n] & np.uint64(0xFF)
        r8 = raw[:n]
        for fam, fn in (('xor', lambda r, m, c: (r ^ m ^ c) & 0xFF),
                        ('sub', lambda r, m, c: (r - m - c) & 0xFF),
                        ('add', lambda r, m, c: (r + m + c) & 0xFF)):
            bc = np.bincount(fn(r8, m8, 0).astype(np.int64), minlength=256)
            mode = int(bc.argmax())
            for C in (mode, (256 - mode) & 0xFF, mode if fam == 'xor' else 0):
                v = fn(r8, m8, C)
                if int(v.min()) == 0 and int(v.max()) <= 32 and float(v.mean()) < 2.5:
                    out.append((off, fam, int(C), float(v.mean())))
    return out


def solve_start_column(body, base, stride, rows, mask, count_off_fam_C):
    """u32 start column: pin C from the 0xFFFFFFFF sentinel (count==0 rows),
    then verify the cumulative chain start[i+1]-start[i] == count[i] with C."""
    off_c, fam_c, C_c = count_off_fam_C
    rawc = read_col(body, base, stride, off_c, 1, rows)
    m8 = mask & np.uint64(0xFF)
    if fam_c == 'xor': cnt = (rawc ^ m8 ^ np.uint64(C_c)) & np.uint64(0xFF)
    elif fam_c == 'sub': cnt = (rawc - m8 - np.uint64(C_c)) & np.uint64(0xFF)
    else: cnt = (rawc + m8 + np.uint64(C_c)) & np.uint64(0xFF)
    sent = cnt == 0
    if not sent.any():
        return []
    r0 = int(np.nonzero(sent)[0][0])
    results = []
    for off in range(0, stride - 3):
        raw = read_col(body, base, stride, off, 4, rows)
        if raw is None:
            continue
        for fam in FAMILIES:
            try:
                C = fam_invert(fam, raw[r0], mask[r0], 0xFFFFFFFF)
            except ValueError:
                continue
            vals = fam_value(fam, raw, mask, np.uint64(C), np.uint64(0xFFFFFFFF))
            is_sent = vals == np.uint64(0xFFFFFFFF)
            sent_ok = int(np.sum(vals[sent] == np.uint64(0xFFFFFFFF)))
            # sentinel and count==0 must agree
            disagree = int(np.sum(is_sent != sent))
            if sent_ok < int(sent.sum()) * 0.98 or disagree > int(rows * 0.001) + 8:
                continue
            # non-sentinel rows must equal the running parameter count
            cum = np.cumsum(cnt.astype(np.int64)) - cnt.astype(np.int64)
            bad = int(np.sum(vals[~is_sent] != cum[~is_sent].astype(np.uint64)))
            if bad > 8:
                continue
            results.append(dict(off=off, family=fam, C=hex(C), chain_bad=bad,
                                sentinel_ok=sent_ok, sentinel_total=int(sent.sum()),
                                sum_counts=int(cnt.sum())))
    results.sort(key=lambda r: (r['chain_bad'], -r['sentinel_ok']))
    return results[:4]


def eval_chain(chain_expr, rows):
    """Evaluate a pure chain expr over [0, rows) -> (uint64 array, sym)."""
    sym = chain_pure(chain_expr)
    if sym is None:
        return None, None

    def rec(e, i):
        t = e[0]
        if t == 'imm':
            return e[1] & 0xFFFFFFFFFFFFFFFF
        if t == 'sym' and e[1] == sym:
            return i
        if t == 'op2':
            a = rec(e[2], i); b = rec(e[3], i)
            op = e[1]
            if op == '+': return (a + b) & 0xFFFFFFFFFFFFFFFF
            if op == '-': return (a - b) & 0xFFFFFFFFFFFFFFFF
            if op == '*': return (a * b) & 0xFFFFFFFFFFFFFFFF
            if op == '^': return a ^ b
            if op == '&': return a & b
            if op == '|': return a | b
            if op == '>>': return a >> b
            if op == '<<': return (a << b) & 0xFFFFFFFFFFFFFFFF
            raise ValueError(op)
        if t == 'lo':
            return rec(e[2], i) & ((1 << e[1]) - 1)
        if t == 'ext':
            n = e[1]; v = rec(e[2], i) & ((1 << n) - 1)
            if e[3] and (v >> (n - 1)) & 1:
                v |= (((1 << (64 - n)) - 1) << n) & 0xFFFFFFFFFFFFFFFF
            return v
        raise ValueError(t)

    try:
        return np.array([rec(chain_expr, i) for i in range(rows)], dtype=np.uint64), sym
    except Exception:
        return None, None


def solve_flags_column(body, base, stride, rows, mask):
    """u16 flags: brute 3 families over stride offsets; sanity on value range
    (MethodAttributes fits 16 bits, static ratio 8-25%, distinct < 4096)."""
    n = min(rows, 50000)
    out = []
    for off in range(0, stride - 1):
        raw = read_col(body, base, stride, off, 2, rows)
        if raw is None: continue
        m16 = mask[:n] & np.uint64(0xFFFF)
        r16 = raw[:n]
        for fam, fn in (('sub', lambda r, m: (r - m) & 0xFFFF),
                        ('xor', lambda r, m: (r ^ m) & 0xFFFF),
                        ('add', lambda r, m: (r + m) & 0xFFFF)):
            v = fn(r16, m16)
            distinct = len(np.unique(v))
            static = float(np.mean((v & 0x10) != 0))
            if 500 <= distinct <= 3500 and 0.06 <= static <= 0.28:
                out.append(dict(off=off, family=fam + 'mask', distinct=distinct, static=static,
                                maxhex=hex(int(v.max()))))
    return out


def solve_window_column(body, base, stride, rows, mask, span_max=1 << 21, sample=200000):
    """u32 index column pinned by the window property: (raw -/+/^ mask) + C
    lands in a narrow contiguous span (type-index space)."""
    n = min(rows, sample)
    cands = []
    for off in range(0, stride - 3):
        raw = read_col(body, base, stride, off, 4, rows)
        if raw is None: continue
        for fam in ('sub', 'xor', 'add'):
            A = fam_value({'sub': 'SubMaskAddC', 'xor': 'XorCXorMask', 'add': 'AddCXorMask'}[fam],
                          raw[:n], mask[:n], 0, np.uint64(0xFFFFFFFF))
            # circular span: try C = -min and also -max+span candidates
            for shift in (int(A.min()), int(A.max())):
                C = (-shift) & 0xFFFFFFFF
                v = (A + np.uint64(C)) & np.uint64(0xFFFFFFFF)
                lo, hi = int(v.min()), int(v.max())
                span = hi - lo if hi >= lo else (M64 - (lo - hi)) + 1
                if lo <= span and hi - lo <= span_max:
                    frac = float(np.mean((v >= np.uint64(lo)) & (v <= np.uint64(hi))))
                    if frac > 0.995 and (hi - lo) >= 1000:
                        cands.append(dict(off=off, family=fam + '+C', C=hex(C),
                                          lo=lo, hi=hi, frac=frac))
    cands.sort(key=lambda c: (c['hi'] - c['lo']))
    return cands[:5]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vdir', required=True)
    ap.add_argument('--derive', required=True)
    ap.add_argument('--sites', required=True)
    ap.add_argument('--strings', required=True)
    ap.add_argument('--semantic', default='method')
    ap.add_argument('--stride', type=lambda x: int(x, 0), default=26)
    ap.add_argument('--rows', type=int, required=True)
    ap.add_argument('--base-candidates', required=True,
                    help='JSON list: [{"slot":"0x..","op":"add","imm":"0x.."}]')
    ap.add_argument('--walks', default='[]', help='JSON list of symwalk result JSONs')
    ap.add_argument('--prior-names', required=True, help='JSON list of names for rows 0..K')
    ap.add_argument('--out', default=None)
    a = ap.parse_args()

    art = json.load(open(a.derive))
    sites = json.load(open(a.sites))
    body = open(a.vdir.rstrip('/') + '/YuanShen_Data/Managed/Metadata/global-metadata.dat', 'rb').read()[0x210:]
    d, ib, secs = pe_map(sites['exe'])
    fo = va2file(ib, secs, sites['blob_va'])
    hdr = d[fo:fo + 0x210]
    cipher = Cipher(art)
    heap = HeapIndex(a.strings)
    prior = json.load(open(a.prior_names))
    walks = json.load(open(a.walks)) if a.walks not in ('[]', '') else []

    bases = []
    for bc in json.loads(a.base_candidates):
        raw = struct.unpack_from('<I', hdr, int(bc['slot'], 16))[0]
        imm = int(bc['imm'], 16)
        # header domain is 32-bit: the + can carry into bit 32, drop it
        base = ((raw + imm) if bc['op'] == 'add' else (raw ^ imm)) & 0xFFFFFFFF
        if base + a.stride * a.rows <= len(body):
            bases.append((base, bc))

    # chain candidates: symwalk artifacts (results with .chains) or a flat
    # pool of {expr,...} from chain_hunt / dense sweeps
    chains = []
    seen = set()
    for wj in walks:
        entries = wj.get('chains', []) if isinstance(wj, dict) and 'chains' in wj else [wj]
        for c in entries:
            e = c['expr']
            if chain_pure(e) is None:
                continue
            k = expr_str(e)
            if k not in seen:
                seen.add(k)
                chains.append(e)

    report = dict(semantic=a.semantic, stride=a.stride, rows=a.rows,
                  base_candidates=[dict(base=hex(b), **bc) for b, bc in bases],
                  chains_tried=len(chains))
    solved = None
    n_mask = min(a.rows, 200000)
    for base, bc in bases:
        for ch in chains:
            mask, sym = eval_chain(ch, n_mask)
            if mask is None:
                continue
            namecol = solve_name_column(body, base, a.stride, a.rows, mask, heap, cipher, prior)
            if name_column_ok(namecol):
                solved = dict(base=hex(base), base_src=bc, chain=ch, chain_sym=sym,
                              name=namecol, mask_rows=n_mask)
                break
        if solved:
            break
    if not solved:
        report['error'] = 'no (base, chain) pair decoded the name column'
        print(json.dumps(report, indent=1))
        sys.exit(1)
    base = int(solved['base'], 16)
    mask, _ = eval_chain(solved['chain'], a.rows)
    report['solved_base'] = solved['base']
    report['chain'] = expr_str(solved['chain'])

    name = solved['name']
    rawN = read_col(body, base, a.stride, name['off'], 4, a.rows)
    mN = mask
    if name['family'] == 'SubMaskAddC': vals = (rawN - mN + np.uint64(int(name['C'], 16))) & M64
    elif name['family'] == 'AddCSubMask': vals = (rawN + np.uint64(int(name['C'], 16)) - mN) & M64
    elif name['family'] == 'XorCXorMask': vals = (rawN ^ np.uint64(int(name['C'], 16))) ^ mN
    elif name['family'] == 'AddCXorMask': vals = ((rawN + np.uint64(int(name['C'], 16))) & M64) ^ mN
    else: vals = ((rawN ^ np.uint64(int(name['C'], 16))) - mN) & M64
    dec = np.array([1 if heap.text.get(int(v) & 0xFFFFFF) is not None else 0 for v in vals[:2000]])
    report['name'] = name
    report['name_first8'] = [heap.text.get(int(v) & 0xFFFFFF, '?')[:20] for v in vals[:8]]

    counts = solve_count_column(body, base, a.stride, a.rows, mask, a.stride)
    report['count_candidates'] = counts[:6]
    starts = []
    if counts:
        starts = solve_start_column(body, base, a.stride, a.rows, mask, (counts[0][0], counts[0][1], counts[0][2]))
    report['start_candidates'] = starts
    report['flags_candidates'] = solve_flags_column(body, base, a.stride, a.rows, mask)[:6]
    report['window_candidates'] = solve_window_column(body, base, a.stride, a.rows, mask)
    if a.out:
        json.dump(report, open(a.out, 'w'), indent=1)
    print(json.dumps({k: report[k] for k in ('solved_base', 'chain', 'name_first8', 'count_candidates', 'start_candidates') if k in report}, indent=1))


if __name__ == '__main__':
    main()
