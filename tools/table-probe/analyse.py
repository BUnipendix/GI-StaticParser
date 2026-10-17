import sys, struct, collections

dat = open(sys.argv[1], "rb").read(); body = dat[0x210:]
base = int(sys.argv[2], 16); stride = int(sys.argv[3], 16)
SHIFTS = list(range(16, 25))
MIN_ROWS = 512; MIN_DISTINCT = 8; FIT_ROWS = 32; KEEP = 70

def u32(rowoff):
    if rowoff + 4 > len(body): return None
    return struct.unpack_from("<I", body, rowoff)[0]
def u16(rowoff):
    if rowoff + 2 > len(body): return None
    return struct.unpack_from("<H", body, rowoff)[0]
def col(row, off): return u32(base + stride*row + off)

def fit(off, shift):
    raws = []
    for i in range(FIT_ROWS):
        v = col(i, off)
        if v is None: return None
        raws.append(v)
    mask = (1 << (32 - shift)) - 1
    cls = []
    for r in raws:
        h = r >> shift
        for c in cls:
            if c[0] == h: c[1].append(r); break
        else:
            if len(cls) >= 2: cls = []; break
            cls.append((h, [r]))
    if len(cls) == 2 and (cls[0][0] ^ cls[1][0]) != mask: cls = []
    if len(cls) == 1:
        h, vs = cls[0]
        if len(set(vs)) > 1: return ("xor", h, None)
    elif len(cls) == 2:
        d0 = len(set(cls[0][1])); d1 = len(set(cls[1][1]))
        if (d0 == 1) != (d1 == 1):
            real, sent = (0, 1) if d0 != 1 else (1, 0)  # constant class is the sentinel
            return ("xor", cls[real][0], cls[sent][1][0])
    width = 1 << shift
    need = FIT_ROWS * KEEP // 100
    best = (0, 0)
    for lo in raws:
        c = sum(1 for x in raws if lo <= x < lo + width)
        if c > best[1]: best = (lo, c)
    if best[1] >= need:
        sent = None; ok = True
        for r in raws:
            if best[0] <= r < best[0] + width: continue
            if sent is None: sent = r
            elif sent != r: ok = False; break
        if ok and sent is not None: return ("add", best[0], sent)
    return None

def is_real(m, shift, raw):
    t, anchor, sent = m
    if t == "xor": return (raw >> shift) == anchor
    return anchor <= raw < anchor + (1 << shift)

def run_len(off, shift, m, cap):
    n = 0
    while n < cap:
        v = col(n, off)
        if v is None: break
        if is_real(m, shift, v) or v == m[2]: n += 1
        else: break
    return n

print("base=0x%X stride=0x%X  body=0x%X" % (base, stride, len(body)))
print("off  shift model         run    real  maxidx  distinct  monotone  bestcnt(off2,op,ratio,const)")
for off in range(stride - 3):
    for shift in SHIFTS:
        m = fit(off, shift)
        if m is None: continue
        cap = min((len(body) - base) // stride, 400000)
        n = run_len(off, shift, m, cap)
        t, anchor, sent = m
        if t == "xor":
            idx_c = (~sent) & 0xFFFFFFFF if sent is not None else col(0, off)
        else:
            idx_c = anchor
        fs = []; maxidx = 0; prev = -1; mono = True; real = 0; mono_at = None
        for i in range(n):
            raw = col(i, off)
            if not is_real(m, shift, raw): fs.append(-1); continue
            v = (raw ^ idx_c) if t == "xor" else ((raw - idx_c) & 0xFFFFFFFF)
            if v < prev: mono = False; mono_at = i; break
            prev = v; maxidx = max(maxidx, v); real += 1; fs.append(v)
        dist = len(set(v for v in fs if v >= 0))
        stage = "Run" if n < MIN_ROWS else ("Monotone@%s" % mono_at if not mono else ("Range" if maxidx >= (1 << shift) else ("Thin" if dist < MIN_DISTINCT else None)))
        if stage is not None:
            if int(__import__("os").environ.get("ALL", "0")):
                print("0x%02X %5d %-3s a=0x%08X s=%-10s %6d %6d %7d %8d  DIE %s"
                      % (off, shift, t, anchor, ("0x%08X" % sent) if sent is not None else "-", n, real, maxidx, dist, stage))
            continue
        if False: pass
        # best count column: exactly the Rust inner loop, but report the first
        # transition that breaks the u16 relation instead of only pass/fail.
        bestc = None
        # The count column may lie anywhere from the index column forward by up to
        # one row: the scan base is arbitrary, so "row i" of the scan can start
        # before the row start the count column is measured from.
        for off2 in range(off, off + stride):
            for op in ("xor", "add"):
                c2 = None; cnt = 0; first_bad = None; bad_why = ""
                for i in range(min(n - 1, 1 << 16)):
                    if fs[i] < 0 or fs[i+1] < 0: continue
                    d = fs[i+1] - fs[i]
                    if d > 0xFFFF:
                        first_bad = i; bad_why = "delta>0xFFFF(%d)" % d; break
                    v2 = u16(base + stride*i + off2)
                    if v2 is None: first_bad = i; bad_why = "eof"; break
                    cur = (v2 ^ d) if op == "xor" else ((v2 - d) & 0xFFFF)
                    if c2 is None: c2 = cur
                    elif c2 != cur:
                        first_bad = i
                        bad_why = "want 0x%04X got 0x%04X (raw 0x%04X d %d)" % (c2, cur, v2, d)
                        break
                    cnt += 1
                score = (1 if first_bad is None else 0, cnt)
                if bestc is None or score > bestc[0]:
                    bestc = (score, off2, op, cnt, c2, first_bad, bad_why)
        b = bestc if bestc else ((0, 0), 0, "-", 0, None, None, "")
        print("0x%02X %5d %-3s a=0x%08X s=%-10s %6d %6d %7d %8d | cnt off2=0x%02X %s c=%-6s streak=%-6d bad@%s %s"
              % (off, shift, t, anchor, ("0x%08X" % sent) if sent is not None else "-",
                 n, real, maxidx, dist, b[1], b[2], b[4], b[3],
                 ("-" if b[5] is None else b[5]), b[6]))
