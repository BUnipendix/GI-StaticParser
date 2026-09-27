#!/usr/bin/env python3
"""MHY-obfuscated il2cpp metadata: TypeDefinition table dumper.

The vendor replaces the stock il2cpp metadata header with an embedded private
header inside the game executable, biases every section-offset field, encrypts
the identifier string heap, and repacks tables with private strides. This tool
statically recovers the TypeDefinition table (type + namespace names) without
running the game.

Portability notes:
- The four string-cipher constants are AUTO-DERIVED here from known plaintext
  (the first heap entry is always the runtime bootstrap identifier), so this
  part survives version bumps as-is.
- The TypeDefinition table constants (header field index, xor/add biases,
  stride, record magic) are per-build and must be re-derived for a new build:
  decompile the in-game class-lookup routine, locate the table base expression
  and the two index transforms, then update the constants below.
"""
import struct, sys

MASK = (1<<64)-1

# ---- per-build constants (re-derive for a new build) ----
HDR_TD_FIELD   = 0xDC          # embedded-header field holding the TD base
HDR_TD_XOR     = 0x5278CA3B    # ... decoded as i32(field) ^ HDR_TD_XOR
TD_STRIDE      = 0x46
REC_MAGIC      = -0x2145AFB7   # per-record sanity tag at +0x1C (mismatch = hidden entry)
C_NAME         = 0xE811F779    # nameIndex:      idx = (u32 + C_NAME) & 0xFFFFFFFF
C_NS           = 0x666769B5    # namespaceIndex: idx =  u32 ^  C_NS
NAME_SENTINEL  = 0x17EE0886    # stored value meaning "no name" (idx -> -1)
BODY_OFF       = 0x210         # metadata body starts here in the file

# ---- string cipher: auto-derived (version-agnostic) ----
DIVMAGICS = {0x8888888888888889,0xd6bf94d5e57a42bd,0xa2e3ff1de20581e3,0x346dc5d63886594b,
0x2bca2875f4373fff,0x20c49ba5e353f7cf,0x3d157fab34c210b5,0xe5109ec205d7bea7,
0xcccccccccccccccd,0x51eb851eb851eb85,0x431bde82d7b634db,0x89705f4136b4a597,
0x9e3779b185ebca87,0xc2b2ae3d27d4eb4f,0x165667b19e3779f9,0x85ebca77c2b2ae63,
0x27d4eb2f165667c5,0x2545f4914f6cdd1d}

def entropy_ok(v):
    if v <= 0x10000000000 or v in DIVMAGICS: return False
    return len(set(f"{v:016x}")) >= 10

def pe_sections(exe):
    d = exe[:4096]
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe+6)[0]
    opt = struct.unpack_from('<H', d, pe+20)[0]
    off = pe+24+opt
    secs = {}
    for i in range(nsec):
        s = d[off+40*i:off+40*i+40]
        name = s[:8].rstrip(b'\0').decode(errors='replace')
        vsz, va, rsz, rp = struct.unpack_from('<IIII', s, 8)
        secs[name] = (0x140000000+va, vsz, rp, rsz)
    return secs

def derive_strcipher(exe, meta):
    """Known-plaintext derivation of the 4 string-cipher constants + heap base.

    The identifier heap always opens with the runtime bootstrap identifier
    (8 bytes) at offset 0; the heap is tightly packed without terminators, so
    the second entry starts at offset 8. Cipher blocks are 8 bytes with a
    per-block additive step; the derivation scans the executable's immediate-
    constant clusters and validates candidates against both anchor blocks.
    """
    secs = pe_sections(exe)
    tv, tsz, trp, trs = secs['.text']
    text = exe[trp:trp+min(tsz,trs)]
    rdata = secs['.rdata']
    rd = exe[rdata[2]:rdata[2]+rdata[1]]
    hits, i, n = [], 0, len(text)-10
    while i < n-10:
        if text[i] == 0x48 and 0xb8 <= text[i+1] <= 0xbf:
            v = struct.unpack_from('<Q', text, i+2)[0]
            if entropy_ok(v): hits.append((i, v))
        i += 1
    clusters, j = [], 0
    while j < len(hits):
        k = j
        while k < len(hits) and hits[k][0]-hits[j][0] < 400: k += 1
        imms = sorted({v for _,v in hits[j:k]})
        if len(imms) >= 3: clusters.append(imms)
        j = k
    printable = lambda b: all(32 <= x < 127 for x in b)
    anchor0 = struct.pack('<8s', b'mscorlib')[:8]
    for consts in clusters:
        for xi in range(len(consts)):
            for xj in range(len(consts)):
                if xi == xj: continue
                X1, X2 = consts[xj], consts[xi]
                k0 = X1 ^ X2
                pat = (struct.unpack('<Q', anchor0)[0] ^ k0).to_bytes(8,'little')
                # locate the heap inside the metadata body (not in the exe)
                s = meta.find(pat)
                if s < 0: continue
                strsec = s - BODY_OFF
                if not (0 < strsec < len(meta)): continue
                rest = [c for c in consts if c not in (consts[xi], consts[xj])]
                c2 = struct.unpack_from('<Q', meta, s+8)[0]
                for M1 in rest:
                    k1 = ((8*M1 + X1) & MASK) ^ X2
                    if not printable((((c2 ^ k1) & MASK).to_bytes(8,'little'))[:4]): continue
                    c3 = struct.unpack_from('<Q', meta, s+16)[0]
                    for M4 in rest:
                        if M4 == M1: continue
                        p3 = ((c3 ^ ((k1+M4)&MASK)) & MASK).to_bytes(8,'little')
                        if printable(p3[:3]):
                            return M1, X1, X2, M4, strsec
    raise SystemExit("[-] cipher constants not derived; formula shape may have changed")

def main():
    exe_path, meta_path = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else 'typedefs.txt'
    exe = open(exe_path,'rb').read()
    meta = open(meta_path,'rb').read()
    M1, X1, X2, M4, strsec = derive_strcipher(exe, meta)
    print(f"[+] cipher: M1={M1:#x} X1={X1:#x} X2={X2:#x} M4={M4:#x} heap@body+{strsec:#x}")
    base = BODY_OFF
    def key0(off): return (((off * M1 + X1) & MASK) ^ X2) & MASK
    def dec(off, ln):
        k = key0(off); src = base + strsec + off
        outb = bytearray()
        for i in range((ln+7)>>3):
            blk = struct.unpack_from('<Q', meta, src+8*i)[0]
            outb += ((blk ^ k) & MASK).to_bytes(8,'little'); k = (k+M4) & MASK
        return bytes(outb[:ln])
    # locate the embedded private header: scan .rdata for the vendor magic and
    # self-validate each candidate by the TD record tag hit-rate
    secs = pe_sections(exe)
    rdv, rdsz, rdp, rdrs = secs['.rdata']
    rd = exe[rdp:rdp+rdsz]
    hdr = None
    pos = 0
    best = (0, None)
    while True:
        pos = rd.find(b'MHY\x00', pos)
        if pos < 0: break
        cand = rd[pos:pos+0x210]
        if len(cand) == 0x210:
            tb = struct.unpack_from('<I', cand, HDR_TD_FIELD)[0] ^ HDR_TD_XOR
            st = base + tb
            hit = sum(1 for r in range(40)
                      if st + r*TD_STRIDE + 0x46 <= len(meta) and
                      struct.unpack_from('<i', meta, st + r*TD_STRIDE + 0x1c)[0] == REC_MAGIC)
            if hit > best[0]: best = (hit, cand)
        pos += 1
    if best[1] is None or best[0] < 20:
        raise SystemExit("[-] embedded header not located")
    hdr = best[1]
    td_base = struct.unpack_from('<I', hdr, HDR_TD_FIELD)[0] ^ HDR_TD_XOR
    td_start = base + td_base
    names, hidden, run_bad = [], 0, 0
    for i in range(300000):
        rec = td_start + i*TD_STRIDE
        if rec+TD_STRIDE > len(meta): break
        if struct.unpack_from('<i', meta, rec+0x1c)[0] != REC_MAGIC:
            hidden += 1; run_bad += 1
            if run_bad > 5000: break
            continue
        run_bad = 0
        ni = (struct.unpack_from('<I', meta, rec+0x14)[0] + C_NAME) & 0xFFFFFFFF
        off, ln = ni & 0xFFFFFF, ni >> 24
        nm = dec(off, ln).decode('utf-8','replace') if 0 < ln <= 96 else '?'
        si = struct.unpack_from('<I', meta, rec+0x18)[0] ^ C_NS
        so, sl = si & 0xFFFFFF, si >> 24
        ns = dec(so, sl).decode('utf-8','replace') if 0 < sl <= 96 else ''
        names.append((ns + '.' + nm) if ns else nm)
    with open(out, 'w') as f:
        for i, n in enumerate(names): f.write(f"{i}\t{n}\n")
    print(f"[+] {len(names)} types ({hidden} hidden-marker records skipped) -> {out}")

if __name__ == '__main__':
    main()
