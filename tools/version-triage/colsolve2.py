#!/usr/bin/env python3
"""Known-plaintext column solver v2 (unaligned packed heap aware).

The string heap stores strings contiguously with no terminator and no padding;
the length rides in the index high byte. Anchor chain: <Module>(8) Locale(6)
SR(2) Mono.Runtime(12) Mono.RuntimeClassHandle(24) — offsets derive from one
hit via contiguity, then every typeDef column constant falls out of rows 0-4.

Usage: colsolve2.py <dat> <td_base-hex> <stride> <strsec-hex> <m1> <x1> <x2> <step> [rows]
"""
import struct
import sys

import numpy as np

MASK = (1 << 64) - 1
ANCHOR = b"<Module>"
CHAIN = [(b"Locale", 6), (b"SR", 2), (b"Mono.Runtime", 12), (b"Mono.RuntimeClassHandle", 24)]


def key_at(off, m1, x1, x2):
    return ((((off & 0xFFFFFF) * m1) & MASK) + x1 & MASK) ^ x2


def decrypt(data, strsec, off, ln, m1, x1, x2, step):
    nq = (ln + 7) >> 3
    src = strsec + off
    if src + nq * 8 > len(data):
        return None
    k = key_at(off, m1, x1, x2)
    out = bytearray()
    for i in range(nq):
        enc = struct.unpack_from("<Q", data, src + 8 * i)[0]
        out += struct.pack("<Q", (enc ^ k) & MASK)
        k = (k + step) & MASK
    return bytes(out[:ln])


def find_anchor(data, strsec, m1, x1, x2, needle=ANCHOR):
    """All byte offsets (rel. to strsec) whose unaligned decrypt starts with needle."""
    heap = np.frombuffer(data, dtype=np.uint8, count=len(data) - strsec, offset=strsec)
    n = len(heap) - 8
    k = min(len(needle), 8)
    mask = (1 << (8 * k)) - 1
    target = int.from_bytes(needle[:k], "little")
    hits = []
    CH = 1 << 22
    m1n, x1n, x2n = np.uint64(m1), np.uint64(x1), np.uint64(x2)
    for c0 in range(0, n, CH):
        seg = heap[c0 : min(n, c0 + CH) + 8]
        q = seg[:-7].astype(np.uint64)
        for j in range(1, 8):
            q |= seg[j : j + len(q)].astype(np.uint64) << np.uint64(8 * j)
        offs = np.arange(c0, c0 + len(q), dtype=np.uint64)
        keys = ((((offs & np.uint64(0xFFFFFF)) * m1n) + x1n) ^ x2n)
        d = (q ^ keys) & np.uint64(mask)
        idx = np.nonzero(d == np.uint64(mask & target))[0]
        for i in idx:
            hits.append(int(c0 + i))
    return hits


def main():
    dat = sys.argv[1]
    td_base = int(sys.argv[2], 0)
    stride = int(sys.argv[3], 0)
    strsec = int(sys.argv[4], 0)
    m1, x1, x2, step = (int(sys.argv[5], 0), int(sys.argv[6], 0), int(sys.argv[7], 0), int(sys.argv[8], 0))
    nrows = int(sys.argv[9], 0) if len(sys.argv) > 9 else 8192

    data = open(dat, "rb").read()[0x210:]
    print(f"body={len(data):#x} td_base={td_base:#x} stride={stride} strsec={strsec:#x}", file=sys.stderr)
    assert decrypt(data, strsec, 0, 8, m1, x1, x2, step)[:8] == b"mscorlib", "heap[0] must be mscorlib"

    hits = find_anchor(data, strsec, m1, x1, x2)
    print("<Module> offsets:", [hex(h) for h in hits], file=sys.stderr)

    # each anchor independently (heap is NOT laid out in row order)
    anchors = {}
    for nm, ln in [(b"<Module>", 8)] + CHAIN:
        hs = find_anchor(data, strsec, m1, x1, x2, nm) if nm != b"<Module>" else hits
        if not hs:
            print(f"anchor {nm} not found", file=sys.stderr)
            continue
        anchors[nm] = (hs, ln)
        print(f"anchor {nm.decode()}: {[hex(h) for h in hs[:6]]} ({len(hs)} hits)", file=sys.stderr)
    if b"<Module>" not in anchors:
        print("NO <Module> anchor", file=sys.stderr)
        return 1

    rows = [data[td_base + i * stride : td_base + (i + 1) * stride] for i in range(nrows)]

    def raw(i, disp, sz=4):
        return int.from_bytes(rows[i][disp : disp + sz], "little")

    def dec(i, disp, op, K, sz=4):
        v = raw(i, disp, sz)
        return (v ^ K) if op == "xor" else (v + K) & ((1 << (8 * sz)) - 1)

    report = []

    # --- name column: solve K from row0, verify rows 1-4 by decrypting ---
    print("\n== name column ==")
    hs0, _ = anchors[b"<Module>"]
    for disp in range(0, stride - 3, 4):
        r0 = raw(0, disp)
        for off0 in hs0:
            idx0 = off0 | (8 << 24)
            for op, K in (("xor", r0 ^ idx0), ("add", (idx0 - r0) & 0xFFFFFFFF)):
                ok = True
                got = []
                for ri, nm in ((1, b"Locale"), (2, b"SR"), (3, b"Mono.Runtime"), (4, b"Mono.RuntimeClassHandle")):
                    idx = dec(ri, disp, op, K)
                    o2, l2 = idx & 0xFFFFFF, (idx >> 24) & 0xFF
                    if o2 + 8 > len(data) - strsec:
                        ok = False
                        break
                    txt = decrypt(data, strsec, o2, l2 if l2 else 8, m1, x1, x2, step)
                    got.append((ri, l2, txt))
                    if not txt or not txt.startswith(nm[: min(len(nm), l2)]):
                        ok = False
                if ok:
                    line = f"NAME: disp={disp:#04x} op={op} K={K:#010x}"
                    print(" ", line, got)
                    report.append({"col": "name", "disp": disp, "op": op, "K": K})

    # --- ns column: row0 empty, row3 = System ---
    print("\n== ns column ==")
    sys_offs = find_anchor(data, strsec, m1, x1, x2, b"System")[:256]
    print("  System offsets:", [hex(o) for o in sys_offs[:8]], file=sys.stderr)
    for disp in range(0, stride - 3, 4):
        r3 = raw(3, disp)
        for so in sys_offs:
            idx3 = so | (6 << 24)
            for op, K in (("xor", r3 ^ idx3), ("add", (idx3 - r3) & 0xFFFFFFFF)):
                v0 = dec(0, disp, op, K)
                v1 = dec(1, disp, op, K)
                v2 = dec(2, disp, op, K)
                if v0 == 0xFFFFFFFF and v1 == 0xFFFFFFFF and v2 == 0xFFFFFFFF:
                    line = f"NS: disp={disp:#04x} op={op} K={K:#010x} (System@{so:#x})"
                    print(" ", line)
                    report.append({"col": "ns", "disp": disp, "op": op, "K": K})

    # --- flags: row0==0, row1 Locale sealed(+pub?), row4 vt|sealed ---
    print("\n== flags column ==")
    for disp in range(0, stride - 3, 4):
        r0 = raw(0, disp)
        for op, K in (("xor", r0), ("add", (-r0) & 0xFFFFFFFF)):
            f1 = dec(1, disp, op, K)
            f4 = dec(4, disp, op, K)
            if (f1 & ~7) == 0x100 and (f1 & 7) in (1, 3, 4, 0, 5, 6) and (f4 & ~7) == 0x108:
                line = f"FLAGS: disp={disp:#04x} op={op} K={K:#010x} row1={f1:#x} row4={f4:#x}"
                print(" ", line)
                report.append({"col": "flags", "disp": disp, "op": op, "K": K, "row1": f1, "row4": f4})

    # --- u16 columns: counts / bitfield; row0 == 0 ---
    print("\n== u16 columns (row0 decodes 0; distribution over rows) ==")
    for disp in range(0, stride - 1, 2):
        r0 = raw(0, disp, 2)
        K = r0  # xor-0
        z = sum(1 for i in range(min(nrows, 2000)) if dec(i, disp, "xor", K, 2) == 0)
        if z > 3:
            vs = [dec(i, disp, "xor", K, 2) for i in range(6)]
            print(f"  disp={disp:#04x} K={K:#06x} zeros={z}/2000 rows0-5={vs}")

    # --- monotone start columns (methodStart row0==0, increasing) ---
    print("\n== start columns (row0==0) ==")
    for disp in range(0, stride - 3, 4):
        r0 = raw(0, disp)
        for op, K in (("xor", r0), ("add", (-r0) & 0xFFFFFFFF)):
            vals = [dec(i, disp, op, K) for i in range(512)]
            mono = all(vals[i] <= vals[i + 1] for i in range(len(vals) - 1))
            nzero = sum(1 for v in vals if v == 0xFFFFFFFF)
            if mono and vals[1] > 0:
                print(f"  disp={disp:#04x} op={op} K={K:#010x} monotone512 v1={vals[1]} v511={vals[511]} sentinels={nzero}")
            elif nzero > 400:
                print(f"  disp={disp:#04x} op={op} K={K:#010x} sentinel-heavy ({nzero}/512)")

    import json
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
