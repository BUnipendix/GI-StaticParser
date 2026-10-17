#!/usr/bin/env python3
"""Adjacent-version typeDef column solver (data-driven, no code RE).

Derives every typeDef column (name/ns/flags/bitfield/starts/counts/element/
parent) from the metadata body alone, given td_base/stride/strsec/cipher:
  name      : row0 must decode to a string that decrypts to "<Module>"
              (heap-scanned once, unaligned, numpy).
  ns        : row0 empty (0xFFFFFFFF); spot-decrypt rows 3..40 and score
              real namespaces (System/UnityEngine/...).
  flags     : row0==0; row1==0x100|vis, row4==0x108|vis, row2==0x180|vis.
  bitfield  : row0==0, row4==1 (RuntimeClassHandle is a vt), bit1 density
              ~ enum count (thousands).
  methodStart/Count : ms(row0)==0, monotone; mc anchored by first increment;
              chain ms(i+1)==ms(i)+mc(i) over the whole table.
  fieldStart/Count  : fs sentinel (raw(0)==raw(1)==raw(2)==raw(3)); first
              non-sentinel decodes 0; fc anchored by the second increment;
              chain + sentinel rows must have fc==0.
  elementType/parent: row0 decodes 0xFFFFFFFF; sentinel density > 50%.

Usage: colsolve4.py <dat> <td_base> <stride> <strsec> <m1> <x1> <x2> <step>
"""
import json
import struct
import sys

import numpy as np

sys.path.insert(0, __import__("os").path.dirname(__file__))
from colsolve2 import decrypt, find_anchor

KNOWN_NS = [b"System", b"UnityEngine", b"Mono", b"Microsoft", b"System.Collections.Generic"]


def main():
    dat, td_base, stride, strsec = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), int(sys.argv[4], 0)
    m1, x1, x2, step = (int(sys.argv[5], 0), int(sys.argv[6], 0), int(sys.argv[7], 0), int(sys.argv[8], 0))
    data = open(dat, "rb").read()[0x210:]
    n = min((len(data) - td_base) // stride, 200000)
    NCHK = min(n, 30000)
    print(f"rows={n}", file=sys.stderr)

    A = np.frombuffer(data, dtype=np.uint8)
    # row starts as a numpy view basis
    starts = td_base + np.arange(n, dtype=np.int64) * stride

    def col32(disp):
        return (A[starts + disp, None].astype(np.uint64) | A[starts + disp + 1, None] << 8).ravel().view() if False else None

    def u32(i, d):
        o = td_base + i * stride + d
        return int.from_bytes(data[o : o + 4], "little")

    def u16(i, d):
        o = td_base + i * stride + d
        return int.from_bytes(data[o : o + 2], "little")

    def d32(i, d, op, K):
        v = u32(i, d)
        return (v ^ K) if op == "xor" else (v + K) & 0xFFFFFFFF

    def d16(i, d, op, K):
        v = u16(i, d)
        m = 0xFFFF
        return (v ^ K) if op == "xor" else (v + K) & m

    out = {}

    # ---------- name ----------
    mod_hits = find_anchor(data, strsec, m1, x1, x2, b"<Module>")
    best = None
    for off0 in mod_hits[:4]:
        idx0 = off0 | (8 << 24)
        for disp in range(0, stride - 3, 4):
            r0 = u32(0, disp)
            for op, K in (("xor", r0 ^ idx0), ("add", (idx0 - r0) & 0xFFFFFFFF)):
                ok = True
                for ri in (1, 2):
                    idx = d32(ri, disp, op, K)
                    o, l = idx & 0xFFFFFF, (idx >> 24) & 0xFF
                    t = decrypt(data, strsec, o, l, m1, x1, x2, step) if 0 < l <= 127 else b""
                    if not t:
                        ok = False
                        break
                if not ok:
                    continue
                bad = 0
                for i in range(3, 64):
                    idx = d32(i, disp, op, K)
                    o, l = idx & 0xFFFFFF, (idx >> 24) & 0xFF
                    t = decrypt(data, strsec, o, l, m1, x1, x2, step) if 0 < l <= 127 else b""
                    if not t or not all(33 <= b < 127 for b in t):
                        bad += 1
                if bad <= 1:
                    sc = -bad
                    if best is None or sc > best[0]:
                        best = (sc, disp, op, K)
    if best:
        _, disp, op, K = best
        out["name"] = {"disp": disp, "op": op, "K": K}
        idxs = [d32(i, disp, op, K) for i in range(10)]
        out["name"]["rows0_9"] = [decrypt(data, strsec, v & 0xFFFFFF, (v >> 24) & 0xFF, m1, x1, x2, step).decode("latin1", "replace") for v in idxs]
    print("name:", out.get("name"), file=sys.stderr)

    # ---------- ns ----------
    best = None
    for disp in range(0, stride - 3, 4):
        if "name" in out and disp == out["name"]["disp"]:
            continue
        r0 = u32(0, disp)
        K = r0 ^ 0xFFFFFFFF
        hits = 0
        tot = 0
        for i in range(3, 44):
            v = d32(i, disp, "xor", K)
            if v == 0xFFFFFFFF:
                continue
            o, l = v & 0xFFFFFF, (v >> 24) & 0xFF
            t = decrypt(data, strsec, o, l, m1, x1, x2, step) if 0 < l <= 127 else b""
            tot += 1
            if any(t.startswith(k) for k in KNOWN_NS):
                hits += 1
        if tot >= 8 and hits >= 5:
            sc = hits
            if best is None or sc > best[0]:
                best = (sc, disp, K)
    if best:
        out["ns"] = {"disp": best[1], "op": "xor", "K": best[2], "ns_hits": best[0]}
    print("ns:", out.get("ns"), file=sys.stderr)

    # ---------- flags (u16) ----------
    cands = []
    for disp in range(0, stride - 1, 2):
        r0 = u16(0, disp)
        for op, K in (("xor", r0), ("add", (-r0) & 0xFFFF)):
            f1, f2, f4 = d16(1, disp, op, K), d16(2, disp, op, K), d16(4, disp, op, K)
            if (f1 & ~7) == 0x100 and (f2 & ~7) == 0x180 and (f4 & ~7) == 0x108:
                cands.append((disp, op, K))
    if len(cands) == 1:
        disp, op, K = cands[0]
        out["flags"] = {"disp": disp, "op": op, "K": K, "sz": 2}
    print("flags:", out.get("flags"), cands, file=sys.stderr)

    # ---------- bitfield (u16): 99% of values <= 7, row4 == 1 (vt handle) ----------
    for disp in range(0, stride - 1, 2):
        r0 = u16(0, disp)
        K = r0
        if d16(4, disp, "xor", K) != 1:
            continue
        nn = min(n, 20000)
        vals = [d16(i, disp, "xor", K) for i in range(nn)]
        small = sum(1 for v in vals if v <= 7)
        b1 = sum(1 for v in vals if v & 2)
        if small > 0.99 * nn and 2000 < b1 < 20000:
            out["bitfield"] = {"disp": disp, "op": "xor", "K": K, "enum_n": b1}
    print("bitfield:", out.get("bitfield"), file=sys.stderr)

    # ---------- methodStart / methodCount (count may be u16 or u8) ----------
    bf = out.get("bitfield", {}).get("disp")
    best = None
    for disp in range(0, stride - 3, 4):
        if disp in (out.get("name", {}).get("disp"), out.get("ns", {}).get("disp")):
            continue
        r0 = u32(0, disp)
        for op, K in (("xor", r0), ("add", (-r0) & 0xFFFFFFFF)):
            v1 = d32(1, disp, op, K)
            if not (0 < v1 <= 64):
                continue
            mono = all(d32(i, disp, op, K) <= d32(i + 1, disp, op, K) for i in range(512))
            if not mono:
                continue
            inc0 = v1
            for sz in (2, 1):
                for dm in range(0, stride - sz + 1, 1):
                    if dm == bf:
                        continue
                    rm0 = int.from_bytes(data[td_base + dm : td_base + dm + sz], "little")
                    for opm, Km in (("xor", rm0 ^ inc0), ("add", (inc0 - rm0) & ((1 << (8 * sz)) - 1))):
                        ok = bad = 0
                        exp = 0
                        for i in range(0, 4000):
                            v = d32(i, disp, op, K)
                            c1 = d16(i, dm, opm, Km) if sz == 2 else (data[td_base + i * stride + dm] ^ Km if opm == "xor" else (data[td_base + i * stride + dm] + Km) & 0xFF)
                            if v == exp and c1 < 2048:
                                ok += 1
                                exp += c1
                            else:
                                bad += 1
                                if bad > 40:
                                    break
                        if ok > 3900:
                            sc = ok
                            if best is None or sc > best[0]:
                                best = (sc, disp, op, K, dm, opm, Km, sz)
    if best:
        sc, disp, op, K, dm, opm, Km, sz = best
        out["methodStart"] = {"disp": disp, "op": op, "K": K}
        out["methodCount"] = {"disp": dm, "op": opm, "K": Km, "sz": sz, "chain_ok": sc}
    print("methodStart:", out.get("methodStart"), out.get("methodCount"), file=sys.stderr)

    # ---------- fieldStart / fieldCount (count may be u16 or u8) ----------
    bf = out.get("bitfield", {}).get("disp")
    best = None
    for disp in range(0, stride - 3, 4):
        if disp in (out.get("name", {}).get("disp"), out.get("ns", {}).get("disp"), out.get("methodStart", {}).get("disp")):
            continue
        raws = [u32(i, disp) for i in range(6)]
        if not (raws[0] == raws[1] == raws[2] == raws[3] and raws[4] != raws[0]):
            continue
        for op, K in (("xor", raws[4]), ("add", (-raws[4]) & 0xFFFFFFFF)):
            f4 = d32(4, disp, op, K)
            if f4 != 0:
                continue
            sent = (raws[0] ^ K) if op == "xor" else (raws[0] + K) & 0xFFFFFFFF
            if sent != 0xFFFFFFFF:
                continue
            inc1 = d32(5, disp, op, K) - f4
            for sz in (2, 1):
                for dm in range(0, stride - sz + 1, 1):
                    if dm == bf:
                        continue
                    rm4 = int.from_bytes(data[td_base + 4 * stride + dm : td_base + 4 * stride + dm + sz], "little")
                    for opm, Km in (("xor", rm4 ^ inc1), ("add", (inc1 - rm4) & ((1 << (8 * sz)) - 1))):
                        ok = bad = 0
                        exp = 0
                        mx = 0
                        for i in range(0, 4000):
                            r = u32(i, disp)
                            c1 = d16(i, dm, opm, Km) if sz == 2 else (data[td_base + i * stride + dm] ^ Km if opm == "xor" else (data[td_base + i * stride + dm] + Km) & 0xFF)
                            if r == raws[0] and c1 == 0:
                                ok += 1
                                continue
                            v = d32(i, disp, op, K)
                            if v == exp and c1 < 4096:
                                ok += 1
                                exp += c1
                                mx = max(mx, c1)
                            else:
                                bad += 1
                                if bad > 40:
                                    break
                        if ok > 3900 and mx >= 8:
                            sc = ok
                            if best is None or sc > best[0]:
                                best = (sc, disp, op, K, dm, opm, Km, raws[0], sz, mx)
    if best:
        sc, disp, op, K, dm, opm, Km, sentraw, sz, mx = best
        out["fieldStart"] = {"disp": disp, "op": op, "K": K, "sentinel_raw": sentraw}
        out["fieldCount"] = {"disp": dm, "op": opm, "K": Km, "sz": sz, "chain_ok": sc, "max_fc": mx}
    print("fieldStart:", out.get("fieldStart"), out.get("fieldCount"), file=sys.stderr)

    # ---------- elementType / parent (sentinel-dense + wide value span) ----------
    used = {v["disp"] for k, v in out.items() if isinstance(v, dict) and "disp" in v}
    for nm, min_dense in (("elementType", 0.3), ("parent", 0.05)):
        for disp in range(0, stride - 3, 4):
            if disp in used:
                continue
            K = u32(0, disp) ^ 0xFFFFFFFF
            nn = min(n, 30000)
            vals = [d32(i, disp, "xor", K) for i in range(nn)]
            cnt = sum(1 for v in vals if v == 0xFFFFFFFF)
            rest = [v for v in vals if v != 0xFFFFFFFF]
            if cnt / nn < min_dense or not rest:
                continue
            span = max(rest) - min(rest)
            inrange = all(0 <= v < 400000 for v in rest)
            if span > 1000 and inrange:
                out[nm] = {"disp": disp, "op": "xor", "K": K, "density": round(cnt / nn, 3), "span": span}
                used.add(disp)
                break
    print("elementType:", out.get("elementType"), "parent:", out.get("parent"), file=sys.stderr)

    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
