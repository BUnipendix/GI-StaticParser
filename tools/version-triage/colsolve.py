#!/usr/bin/env python3
"""Known-plaintext column solver for a MHY metadata build.

Inputs (all derived on-site, no hardcoded constants):
  - global-metadata.dat
  - td_base, td_stride          (from code-derived anchors / triage)
  - string schedule M1,X1,X2,STEP + strsec   (from cipher derivation)

Row anchors (version-stable semantics): row0 <Module> flags=0 no fields/no
methods; row1 Locale(sealed); row2 SR(static); row3 Mono.Runtime; row4
Mono.RuntimeClassHandle(sealed|vt). For every u32 column offset we solve the
transform constant against these anchors, then verify with global statistics.

Usage: colsolve.py <dat> <td_base-hex> <stride> <strsec-hex> <m1-hex> <x1-hex> <x2-hex> <step-hex> [rows]
"""
import struct
import sys

MASK = (1 << 64) - 1


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


def find_string_offsets(data, strsec, m1, x1, x2, step, needle, limit=None):
    """Offsets (8-aligned, relative to strsec) whose decryption starts with needle."""
    end = limit or (len(data) - strsec - 16)
    n = struct.pack("<Q", int.from_bytes(needle.ljust(8, b"\x00")[:8], "little"))
    hits = []
    off = 0
    # first qword key is a pure function of off; step only matters past qword 0,
    # and the needle (<=8 bytes) lives in qword 0 except long names handled separately
    while off < end:
        k = key_at(off, m1, x1, x2)
        enc = struct.unpack_from("<Q", data, strsec + off)[0]
        if ((enc ^ k) & MASK).to_bytes(8, "little")[: len(needle)] == needle:
            hits.append(off)
        off += 8
    return hits


def main():
    dat = sys.argv[1]
    td_base = int(sys.argv[2], 0)
    stride = int(sys.argv[3], 0)
    strsec = int(sys.argv[4], 0)
    m1, x1, x2, step = (int(sys.argv[5], 0), int(sys.argv[6], 0), int(sys.argv[7], 0), int(sys.argv[8], 0))
    nrows = int(sys.argv[9], 0) if len(sys.argv) > 9 else 4096

    data = open(dat, "rb").read()[0x210:]  # body
    print(f"body={len(data):#x} td_base={td_base:#x} stride={stride} strsec={strsec:#x}", file=sys.stderr)

    need = {}
    for nm in (b"<Module>", b"Locale", b"SR", b"Mono.Runtime", b"Mono.RuntimeClassHandle"):
        hs = find_string_offsets(data, strsec, m1, x1, x2, step, nm)
        need[nm] = hs
        print(f"  heap: {nm.decode():26s} -> {[hex(h) for h in hs[:6]]} ({len(hs)} hits)", file=sys.stderr)

    # sanity: first heap string must be mscorlib
    first = decrypt(data, strsec, 0, 8, m1, x1, x2, step)
    print("  heap[0]:", first, file=sys.stderr)

    rows = []
    for i in range(nrows):
        rows.append(data[td_base + i * stride : td_base + (i + 1) * stride])

    def raw(i, disp, sz=4):
        r = rows[i]
        return int.from_bytes(r[disp : disp + sz], "little")

    # --- solve columns against anchors ---
    # name column: row0 -> <Module> (len 8), row1 -> Locale (len 6), row2 -> SR (len 2)
    print("\n== name column solve ==")
    for disp in range(0, stride - 3, 4):
        for op in ("xor", "add"):
            sols = []
            for off in need[b"<Module>"]:
                idx = off | (8 << 24)
                r0 = raw(0, disp)
                K = (r0 ^ idx) if op == "xor" else (idx - r0) & 0xFFFFFFFF
                ok = True
                for nm, ri, ln in ((b"Locale", 1, 6), (b"SR", 2, 2)):
                    v = raw(ri, disp)
                    idx2 = (v ^ K) if op == "xor" else (v + K) & 0xFFFFFFFF
                    o2, l2 = idx2 & 0xFFFFFF, (idx2 >> 24) & 0xFF
                    if l2 != ln or o2 not in need[nm]:
                        ok = False
                        break
                if ok:
                    sols.append((op, K))
            if sols:
                print(f"  disp={disp:#04x}: {sols}")

    # ns column: row0 empty (idx 0xFFFFFFFF or len=0); row3 'System'
    print("\n== ns column solve (row3 Mono.Runtime ns='System') ==")
    sys_offs = find_string_offsets(data, strsec, m1, x1, x2, step, b"System")
    print("  System offsets:", [hex(h) for h in sys_offs[:8]], file=sys.stderr)
    for disp in range(0, stride - 3, 4):
        for op in ("xor", "add"):
            for soff in sys_offs[:64]:
                idx = soff | (6 << 24)
                r3 = raw(3, disp)
                K = (r3 ^ idx) if op == "xor" else (idx - r3) & 0xFFFFFFFF
                v0 = (raw(0, disp) ^ K) if op == "xor" else (raw(0, disp) + K) & 0xFFFFFFFF
                if v0 in (0xFFFFFFFF, 0):
                    v1 = (raw(1, disp) ^ K) if op == "xor" else (raw(1, disp) + K) & 0xFFFFFFFF
                    if v1 in (0xFFFFFFFF, 0):
                        print(f"  disp={disp:#04x} op={op} K={K:#010x}  (row0/1 empty, row3->System@{soff:#x})")

    # flags column: row0 == 0
    print("\n== flags column candidates (row0 plain == 0) ==")
    for disp in range(0, stride - 3, 4):
        r0 = raw(0, disp)
        Kx = r0  # xor K -> 0
        Ka = (-r0) & 0xFFFFFFFF
        for op, K in (("xor", Kx), ("add", Ka)):
            f1 = (raw(1, disp) ^ K) if op == "xor" else (raw(1, disp) + K) & 0xFFFFFFFF
            f4 = (raw(4, disp) ^ K) if op == "xor" else (raw(4, disp) + K) & 0xFFFFFFFF
            if f1 == 0x104 or f1 == 0x105 or f1 == 0x101 or f1 == 0x100:
                print(f"  disp={disp:#04x} op={op} K={K:#010x} row1={f1:#x} row4={f4:#x}")

    # bitfield column (u16 or u8): row0 == 0, row4 == 3 (vt|enum? no: bit0 vt)
    print("\n== u16 columns (row0 == 0 candidates) ==")
    for disp in range(0, stride - 1, 2):
        r0 = raw(0, disp)
        if r0 == 0:
            print(f"  disp={disp:#04x} raw0=0 (K=0 xor) — check distribution")


if __name__ == "__main__":
    main()
