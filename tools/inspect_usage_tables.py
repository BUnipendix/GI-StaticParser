#!/usr/bin/env python3
"""GI 7.1 metadata-usage + string-literal tables (discovered 2026-10-18, round R19).

Decoded from the runtime metadata-usage resolver at 0x140524250 and the
string-literal cipher 0x140526BD0:

  usage index table : body + (hdr[0x19C] ^ 0x159FBC84), u32 entries,
                      range for usage i = masks(i,i+1) + raw(i,i+1) + 0xE6495E3D
  usage pair table  : body + (hdr[0x14C] ^ 0x2F249C2F), 8B rows, handle @+4:
                      handle = raw4 ^ maskB(j) ^ 0x5CD30101, kind = handle>>29
  literal offset tbl: body + (hdr[0x88] + 0xF3C0B2FE), cumulative u32 offsets
  literal data blob : body + (hdr[0x13C] ^ 0x28B1D785), 64-bit XOR cipher

Usage:
  tools/inspect_usage_tables.py                      # sanity + counts
  tools/inspect_usage_tables.py --literals-out F     # dump literals.json
  tools/inspect_usage_tables.py --usages-out F       # dump usage pairs jsonl
"""
import argparse, json, os, struct, sys, collections

EXE = os.path.expanduser("~/gire/sample/gi/7.1.0/YuanShen.exe")
DAT = os.path.expanduser("~/gire/global-metadata.dat")
EXE_HDR_VA = 0x1427D5CB0
M64 = (1 << 64) - 1

# --- slot constants (7.1.0) ---
U_FIRST = (0x19C, 0x159FBC84)   # usage index table
U_PAIRS = (0x14C, 0x2F249C2F)   # usage pair table
L_OFFS  = (0x88,  0xF3C0B2FE)   # literal offset table (add)
L_DATA  = (0x13C, 0x28B1D785)   # literal data blob (xor)

# literal cipher (decrypt_to_string 0x140526BD0)
L_M1 = 0x34044C3B94B40C; L_X1 = 0x2C165A1E0D09C29E
L_M2 = 0x4D613E5575A12594; L_X2 = 0x1B34FA773FEE107E
L_M3 = 0x29140A6156B9041E; L_STEP = 0x70BA8080760AC800


def pe_sections(exe_bytes):
    d = exe_bytes[:4096]
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt = struct.unpack_from("<H", d, pe + 20)[0]
    off = pe + 24 + opt
    secs = {}
    for i in range(nsec):
        s = d[off + 40 * i: off + 40 * i + 40]
        name = s[:8].rstrip(b"\0").decode(errors="replace")
        vsz, va, rsz, rp = struct.unpack_from("<IIII", s, 8)
        secs[name] = (0x140000000 + va, vsz, rp, rsz)
    return secs


def load(exe_path, dat_path):
    exe = open(exe_path, "rb").read()
    secs = pe_sections(exe)
    sva, vsz, rp, rsz = secs[".rdata"]
    hdr_off = rp + (EXE_HDR_VA - sva)
    hdr = exe[hdr_off:hdr_off + 0x210]
    body = open(dat_path, "rb").read()[0x210:]
    return hdr, body


def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]
def i32_hdr(hdr, off): return struct.unpack_from("<i", hdr, off)[0]
def u32_hdr(hdr, off): return struct.unpack_from("<I", hdr, off)[0]


def mask_lit(i):
    r = (i * 0x9825) & M64
    r ^= 0x250621A3
    r = (r * 0x76C8023D) & M64; r >>= 0xC
    r = (r * 0x5E626528) & M64; r >>= 0xF
    return (((r + 0x3483F478) & 0xFFFFFFFF) ^ 0xA0D4507F)


def mask_usage_index(i):
    r = (i * 0x6536) & M64
    r ^= 0x138D67F3
    r = (r * 0x44B1AAD4) & M64
    r = (r + 0x1F9EA55AD057D0) & M64
    return (((r >> 0x15) * 0xD0DC29D5) & 0xFFFFFFFF)


def mask_pair(j):
    r = (j * 0x3C5F6DC3F5D0) & M64
    r >>= 0x14
    return (((r ^ 0x615EB706) + 0x63D46A21) & 0xFFFFFFFF)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=EXE)
    ap.add_argument("--dat", default=DAT)
    ap.add_argument("--literals-out")
    ap.add_argument("--usages-out")
    ap.add_argument("--ref-literals", default=os.path.expanduser("~/gire/out/71/literals.json"))
    args = ap.parse_args()
    hdr, body = load(args.exe, args.dat)

    lit_tab = (u32_hdr(hdr, L_OFFS[0]) + L_OFFS[1]) & 0xFFFFFFFF
    lit_dat = (u32_hdr(hdr, L_DATA[0]) ^ L_DATA[1]) & 0xFFFFFFFF
    use_tab = (i32_hdr(hdr, U_FIRST[0]) ^ U_FIRST[1]) & 0xFFFFFFFF
    use_prs = (i32_hdr(hdr, U_PAIRS[0]) ^ U_PAIRS[1]) & 0xFFFFFFFF
    print("literal offsets 0x%X  data 0x%X  usage idx 0x%X  pairs 0x%X" %
          (lit_tab, lit_dat, use_tab, use_prs))

    def lit_bounds(i):
        a = u32(body, lit_tab + 4 * i); b = u32(body, lit_tab + 4 * (i + 1))
        st = ((mask_lit(i) + a) & 0xFFFFFFFF)
        st = (st + 0x81555D04) & 0xFFFFFFFF
        en = ((mask_lit(i + 1) + b) & 0xFFFFFFFF)
        en = (en + 0x81555D04) & 0xFFFFFFFF
        return st, en

    def lit_decrypt(i, src, n):
        key = (((((i * L_M1) & M64) ^ L_X1) * L_M2) & M64)
        key = ((key ^ L_X2) * L_M3) & M64
        out = bytearray()
        for k in range((n + 7) // 8):
            out += ((u64(body, src + 8 * k) ^ key).to_bytes(8, "little"))
            key = (key + L_STEP) & M64
        # NOTE: reference literals.json keeps embedded NULs, so no C-string truncation
        # here (the 27 apparent diffs are exactly this policy difference).
        return bytes(out[:n])

    def literal(i):
        st, en = lit_bounds(i)
        return lit_decrypt(i, lit_dat + st, en - st).decode("utf-8", "replace")

    ref = None
    if args.ref_literals and os.path.exists(args.ref_literals):
        ref = json.load(open(args.ref_literals))
    n_lit = len(ref) if ref else 0
    if not n_lit:
        n_lit = 0
        while True:
            st, en = lit_bounds(n_lit)
            if not (0 <= st <= en <= len(body) - lit_dat) or en - st > 0x2000:
                break
            n_lit += 1
    mismatch = 0
    out = []
    for i in range(n_lit):
        s = literal(i)
        if ref is not None:
            want = ref[i]["value"] if isinstance(ref[i], dict) else ref[i]
            if s != want: mismatch += 1
        if args.literals_out:
            out.append({"index": i, "value": s})
    print("literals: %d  (ref mismatch %d)" % (n_lit, mismatch))
    if args.literals_out:
        json.dump(out, open(args.literals_out, "w"), ensure_ascii=False)

    def use_range(i):
        a = u32(body, use_tab + 4 * i); b = u32(body, use_tab + 4 * (i + 1))
        st = ((mask_usage_index(i) + ((a ^ 0x15A6F604) & 0xFFFFFFFF) + 0xE6495E3D) & 0xFFFFFFFF)
        en = ((mask_usage_index(i + 1) + ((b ^ 0x15A6F604) & 0xFFFFFFFF) + 0xE6495E3D) & 0xFFFFFFFF)
        return st, en

    def handle(j):
        return (u32(body, use_prs + 8 * j + 4) ^ mask_pair(j) ^ 0x5CD30101) & 0xFFFFFFFF

    kinds = collections.Counter()
    idx_max = collections.defaultdict(int)
    usages = 0
    last = 0
    pairs = 0
    f = open(args.usages_out, "w") if args.usages_out else None
    while usages < 400000:
        st, en = use_range(usages)
        if not (0 <= st <= en <= 1000000) or en - st > 200000:
            break
        last = en
        if f:
            f.write(json.dumps({"usage": usages, "start": st, "end": en}) + "\n")
        for j in range(st, en):
            h = handle(j)
            k = h >> 29
            kinds[k] += 1
            idx_max[k] = max(idx_max[k], h & 0x1FFFFFFF)
        usages += 1
    if f:
        f.close()
    pairs = last
    print("usages: %d  pairs: %d" % (usages, pairs))
    print("handle kinds:", dict(sorted(kinds.items())))
    for k in sorted(idx_max):
        print("  kind %d: max index 0x%X" % (k, idx_max[k]))

    ok = True
    if ref is not None and mismatch > 30:
        print("FAIL: literal mismatch %d > 30" % mismatch); ok = False
    if idx_max.get(5, 0) != n_lit - 1:
        print("FAIL: string-literal kind max 0x%X != literals-1 0x%X" %
              (idx_max.get(5, 0), n_lit - 1)); ok = False
    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
