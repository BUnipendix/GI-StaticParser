#!/usr/bin/env python3
"""Full-table column validator: takes column hypotheses (from rows 0-8 anchors
+ code events) and verifies each against whole-table structure.

Tests: monotone starts; fieldStart/fieldCount tiling; methodStart/methodCount
chaining; flags bit distribution; bitfield bit0/bit1 counts + row4==1;
ns spot-decrypt (real namespace strings); elementType -1 density.

Usage: colverify.py <dat> <td_base> <stride> <strsec> <m1> <x1> <x2> <step> <hypo.json>
"""
import json
import struct
import sys

sys.path.insert(0, __import__("os").path.dirname(__file__))
from colsolve2 import decrypt


def main():
    dat, td_base, stride, strsec = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), int(sys.argv[4], 0)
    m1, x1, x2, step = (int(sys.argv[5], 0), int(sys.argv[6], 0), int(sys.argv[7], 0), int(sys.argv[8], 0))
    hypo = json.load(open(sys.argv[9]))
    nrows = int(sys.argv[10], 0) if len(sys.argv) > 10 else 0

    data = open(dat, "rb").read()[0x210:]
    n = nrows or (len(data) - td_base) // stride
    n = min(n, (len(data) - td_base) // stride, 200000)
    print(f"rows={n}", file=sys.stderr)

    def raw(i, d, sz=4):
        o = td_base + i * stride + d
        return int.from_bytes(data[o : o + sz], "little")

    def dec(i, d, op, K, sz=4):
        v = raw(i, d, sz)
        m = (1 << (8 * sz)) - 1
        return (v ^ K) if op == "xor" else (v + K) & m

    out = {}

    # 1. name: decrypt rows 0..31, all must be plausible type names
    c = hypo["name"]
    names = []
    bad = 0
    for i in range(32):
        idx = dec(i, c["disp"], c["op"], c["K"])
        o, l = idx & 0xFFFFFF, (idx >> 24) & 0xFF
        t = decrypt(data, strsec, o, l, m1, x1, x2, step) if 0 < l <= 127 else b""
        names.append(t)
        if not t or not all(32 <= b < 127 for b in t):
            bad += 1
    out["name"] = {"rows0_7": [x.decode("latin1", "replace") for x in names[:8]], "bad_of_32": bad}

    # 2. ns: decrypt 32 rows, count real-looking namespaces
    if "ns" in hypo:
        c = hypo["ns"]
        nss = []
        bad = 0
        for i in range(32):
            idx = dec(i, c["disp"], c["op"], c["K"])
            if idx == 0xFFFFFFFF:
                nss.append("")
                continue
            o, l = idx & 0xFFFFFF, (idx >> 24) & 0xFF
            t = decrypt(data, strsec, o, l, m1, x1, x2, step) if 0 < l <= 127 else b""
            nss.append(t)
            if t and not all(32 <= b < 127 for b in t):
                bad += 1
        out["ns"] = {"rows0_11": nss[:12], "bad_of_32": bad}

    # 3. flags: distribution
    if "flags" in hypo:
        c = hypo["flags"]
        m = (1 << (8 * c.get("sz", 4))) - 1
        vis = [0] * 8
        nsealed = nabst = nvtlayout = 0
        for i in range(0, min(n, 60000)):
            f = dec(i, c["disp"], c["op"], c["K"], c.get("sz", 4))
            vis[f & 7] += 1
            if f & 0x100:
                nsealed += 1
            if f & 0x80:
                nabst += 1
            if f & 0x08:
                nvtlayout += 1
        out["flags"] = {"vis": vis, "sealed": nsealed, "abstract": nabst, "vtlayout": nvtlayout,
                        "row0": dec(0, c["disp"], c["op"], c["K"], c.get("sz", 4)),
                        "row1": dec(1, c["disp"], c["op"], c["K"], c.get("sz", 4)),
                        "row4": dec(4, c["disp"], c["op"], c["K"], c.get("sz", 4))}

    # 4. bitfield: bit0 (vt) / bit1 (enum) counts; row4 must be 1 (RuntimeClassHandle is vt)
    if "bitfield" in hypo:
        c = hypo["bitfield"]
        b0 = b1 = 0
        for i in range(0, min(n, 60000)):
            v = dec(i, c["disp"], c["op"], c["K"], 2)
            if v & 1:
                b0 += 1
            if v & 2:
                b1 += 1
        out["bitfield"] = {"vt": b0, "enum": b1, "row0": dec(0, c["disp"], c["op"], c["K"], 2),
                           "row4": dec(4, c["disp"], c["op"], c["K"], 2)}

    # 5. fieldStart/fieldCount tiling
    if "fieldStart" in hypo and "fieldCount" in hypo:
        fs, fc = hypo["fieldStart"], hypo["fieldCount"]
        sent = hypo.get("fs_sentinel_raw")
        exp = 0
        ok = bad = 0
        for i in range(0, min(n, 60000)):
            r = raw(i, fs["disp"])
            f = r if sent is None and False else r
            rfs = raw(i, fs["disp"])
            if rfs == sent:
                fcv = dec(i, fc["disp"], fc["op"], fc["K"], 2)
                if fcv == 0:
                    ok += 1
                else:
                    bad += 1
            else:
                v = (rfs ^ fs["K"]) if fs["op"] == "xor" else (rfs + fs["K"]) & 0xFFFFFFFF
                fcv = dec(i, fc["disp"], fc["op"], fc["K"], 2)
                if v == exp and fcv < 4096:
                    ok += 1
                    exp += fcv
                else:
                    bad += 1
        out["fs_fc"] = {"ok": ok, "bad": bad, "total_fields": exp}

    # 6. methodStart/methodCount chain
    if "methodStart" in hypo and "methodCount" in hypo:
        ms, mc = hypo["methodStart"], hypo["methodCount"]
        exp = 0
        ok = bad = 0
        for i in range(0, min(n, 60000)):
            v = dec(i, ms["disp"], ms["op"], ms["K"])
            c1 = dec(i, mc["disp"], mc["op"], mc["K"], 2)
            if v == exp and c1 < 8192:
                ok += 1
                exp += c1
            else:
                bad += 1
        out["ms_mc"] = {"ok": ok, "bad": bad, "total_methods": exp}

    # 7. elementType: -1 density (the td_magic / sentinel column)
    if "elementType" in hypo:
        c = hypo["elementType"]
        sent = 0
        for i in range(0, min(n, 60000)):
            if dec(i, c["disp"], c["op"], c["K"]) == 0xFFFFFFFF:
                sent += 1
        out["elementType"] = {"sentinels": sent, "of": min(n, 60000)}

    # 8. parent: sentinel 0xFFFFFFFF density + small-index validity
    if "parent" in hypo:
        c = hypo["parent"]
        sent = 0
        for i in range(0, min(n, 60000)):
            if dec(i, c["disp"], c["op"], c["K"]) == 0xFFFFFFFF:
                sent += 1
        out["parent"] = {"sentinels": sent, "of": min(n, 60000)}

    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
