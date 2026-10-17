#!/usr/bin/env python3
"""Column-constant extractor for one table of one build.

Given (exe, table_transform_const) it byte-scans every site whose code applies
that constant, disassembles a window around each site with capstone, and does a
light register dataflow to collect column reads: loads [row_base + disp] with
disp < stride, plus the immediate transform applied to the loaded value.

Output: JSON {site: [events]} + aggregated per-disp candidate constants.

Usage: colscan.py <exe> <const-hex> <stride> [window-bytes]
"""
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM, CS_GRP_JUMP, CS_GRP_CALL


def parse_pe(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    optsz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    imagebase = struct.unpack_from("<Q", data, e_lfanew + 24 + 24)[0]
    secs = []
    for i in range(nsec):
        off = e_lfanew + 24 + optsz + i * 40
        name = data[off : off + 8].rstrip(b"\0").decode("latin1")
        vsz, va, rsz, ro = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        secs.append({"name": name, "va": va, "vsz": vsz, "ro": ro, "rsz": rsz, "chars": chars})
    return imagebase, secs


ALIAS = {}
for _i, (_r, _e) in enumerate(
    [("rax", "eax"), ("rcx", "ecx"), ("rdx", "edx"), ("rbx", "ebx"),
     ("rsp", "esp"), ("rbp", "ebp"), ("rsi", "esi"), ("rdi", "edi")]
):
    ALIAS[_r] = _r
    ALIAS[_e] = _r
for _i in range(8, 16):
    ALIAS[f"r{_i}"] = f"r{_i}"
    ALIAS[f"r{_i}d"] = f"r{_i}"
    ALIAS[f"r{_i}w"] = f"r{_i}"


def canon(r):
    return ALIAS.get(r, r)


def main():
    exe_path = sys.argv[1]
    const = int(sys.argv[2], 16)
    stride = int(sys.argv[3], 0)
    win = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x150
    data = open(exe_path, "rb").read()
    imagebase, secs = parse_pe(data)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    needle = struct.pack("<I", const)

    sites = []
    for s in secs:
        if not (s["chars"] & 0x20000000):
            continue
        blob = data[s["ro"] : s["ro"] + s["rsz"]]
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            va = imagebase + s["va"] + i
            sites.append((va, s, i))
            start = i + 1

    results = {}
    agg = {}
    for va, s, i in sites:
        code = data[s["ro"] + max(0, i - 0x40) : s["ro"] + min(s["rsz"], i + win)]
        base_va = imagebase + s["va"] + max(0, i - 0x40)
        events = []
        tags = {}
        pending_col = None  # (reg, disp, size, va)
        for insn in md.disasm(code, base_va):
            m = insn.mnemonic
            ops = insn.operands
            if m == "xor" and len(ops) == 2 and ops[1].type == CS_OP_IMM and (ops[1].imm & 0xFFFFFFFF) == const:
                tags[canon(insn.reg_name(ops[0].reg))] = "BASE"
                continue
            if m == "add" and len(ops) == 2:
                if ops[1].type == CS_OP_IMM:
                    if tags.get(canon(insn.reg_name(ops[0].reg))) == "BASE" and 0 < ops[1].imm < 0x10000:
                        tags[canon(insn.reg_name(ops[0].reg))] = "ROW"
                elif ops[1].type == 1 and insn.reg_name(ops[1].reg):
                    a, b = canon(insn.reg_name(ops[0].reg)), canon(insn.reg_name(ops[1].reg))
                    if tags.get(a) in ("BASE", "ROW") or tags.get(b) in ("BASE", "ROW"):
                        tags[a] = "ROW"
                continue
            if m == "mov" and len(ops) == 2:
                if ops[1].type == 1 and insn.reg_name(ops[1].reg):  # reg,reg
                    src = canon(insn.reg_name(ops[1].reg))
                    dst = canon(insn.reg_name(ops[0].reg))
                    if tags.get(src):
                        tags[dst] = tags[src]
                    else:
                        tags.pop(dst, None)
                    continue
                if ops[1].type == CS_OP_MEM:
                    mem = ops[1].mem
                    breg = canon(insn.reg_name(mem.base)) if mem.base else None
                    bs = tags.get(breg)
                    disp = mem.disp & 0xFFFFFFFFFFFFFFFF
                    if disp > 0xFFFFFFFF:
                        disp -= 1 << 64
                    dst = canon(insn.reg_name(ops[0].reg)) if ops[0].type == 1 else None
                    if bs in ("BASE", "ROW") and 0 <= disp < stride:
                        sz = insn.op_str.split()[1].startswith("word") and 2 or (insn.op_str.split()[1].startswith("byte") and 1 or 4)
                        pending_col = (dst, disp, sz, insn.address)
                        events.append({"t": "load", "disp": disp, "sz": sz, "va": hex(insn.address)})
                    elif dst is not None:
                        tags.pop(dst, None)
                    continue
            if m == "movzx" and len(ops) == 2 and ops[1].type == CS_OP_MEM:
                mem = ops[1].mem
                breg = canon(insn.reg_name(mem.base)) if mem.base else None
                bs = tags.get(breg)
                disp = mem.disp
                dst = canon(insn.reg_name(ops[0].reg)) if ops[0].type == 1 else None
                if bs in ("BASE", "ROW") and 0 <= disp < stride:
                    sz = 2 if "word" in insn.op_str else 1
                    pending_col = (dst, disp, sz, insn.address)
                    events.append({"t": "load", "disp": disp, "sz": sz, "va": hex(insn.address), "zx": True})
                elif dst is not None:
                    tags.pop(dst, None)
                continue
            if m == "lea" and len(ops) == 2 and ops[1].type == CS_OP_MEM:
                mem = ops[1].mem
                breg = canon(insn.reg_name(mem.base)) if mem.base else None
                dst = canon(insn.reg_name(ops[0].reg)) if ops[0].type == 1 else None
                if tags.get(breg) in ("BASE", "ROW") and dst:
                    tags[dst] = "ROW"
                elif dst:
                    tags.pop(dst, None)
                continue
            if m in ("xor", "add", "sub") and len(ops) == 2 and ops[1].type == CS_OP_IMM and pending_col:
                dst = canon(insn.reg_name(ops[0].reg)) if ops[0].type == 1 else None
                if dst == pending_col[0] and (ops[1].imm & 0xFFFFFFFF) > 0xFFFF:
                    ev = {"t": "col", "disp": pending_col[1], "sz": pending_col[2], "op": m,
                          "imm": ops[1].imm & 0xFFFFFFFF, "va": hex(insn.address)}
                    events.append(ev)
                    agg.setdefault((pending_col[1], pending_col[2], m, ops[1].imm & 0xFFFFFFFF), 0)
                    agg[(pending_col[1], pending_col[2], m, ops[1].imm & 0xFFFFFFFF)] += 1
                    pending_col = None
                continue
            # anything that writes a register we track clobbers its tag
            if insn.reg_name(ops[0].reg) if ops and ops[0].type == 1 else None:
                pass
        if events:
            results[hex(va)] = events

    out = {"sites": len(sites), "agg": [
        {"disp": k[0], "sz": k[1], "op": k[2], "imm": k[3], "n": v} for k, v in sorted(agg.items(), key=lambda kv: -kv[1])
    ], "events": results}
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
