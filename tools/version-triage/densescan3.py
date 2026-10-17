#!/usr/bin/env python3
"""Dense column-consumer finder v3.

Two transform directions, register-family normalization, junk-tolerant:
  A) mov/movzx reg, [base+disp<max] ... op reg, imm32      -> (disp, op, imm)
  B) mov reg, imm32 ... op reg, [base+disp<max]             -> (disp, op, imm)
     (sub K, [mem] recorded as op='rsub': plain = K - raw)
  plus: cmp reg, imm32 after a load                          -> sentinel candidate

Usage: densescan3.py <exe> <section> <out-jsonl> [disp-max] [resync]
"""
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM

FAMS = {}
for _b in ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"):
    FAMS[_b] = _b
    FAMS[_b[1:]] = _b  # ax..di
    FAMS["e" + _b[1:]] = _b
for _b in ("al", "cl", "dl", "bl", "sil", "dil", "spl", "bpl"):
    FAMS[_b] = "r" + _b[1:]
for _i in range(8, 16):
    FAMS[f"r{_i}"] = f"r{_i}"
    FAMS[f"r{_i}b"] = f"r{_i}"
    FAMS[f"r{_i}w"] = f"r{_i}"
    FAMS[f"r{_i}d"] = f"r{_i}"


def fam(r):
    return FAMS.get(r, r)


def parse_pe(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    optsz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    imagebase = struct.unpack_from("<Q", data, e_lfanew + 24 + 24)[0]
    out = []
    for i in range(nsec):
        off = e_lfanew + 24 + optsz + i * 40
        name = data[off : off + 8].rstrip(b"\0").decode("latin1")
        vsz, va, rsz, ro = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        out.append({"name": name, "va": va, "vsz": vsz, "ro": ro, "rsz": rsz, "chars": chars})
    return imagebase, out


def sweep(md, code, va0, disp_max, events):
    loadp = {}   # fam -> dict(disp, lva, ld)
    constp = {}  # fam -> dict(imm, lva)
    for insn in md.disasm(code, va0):
        m = insn.mnemonic
        ops = insn.operands
        written = []
        if m in ("mov", "movzx", "movsx") and len(ops) == 2 and ops[0].type == 1:
            d = fam(insn.reg_name(ops[0].reg))
            written = [d]
            if ops[1].type == CS_OP_MEM:
                mem = ops[1].mem
                disp = mem.disp
                if 0 <= disp < disp_max and (mem.base or mem.index):
                    loadp[d] = {"disp": disp, "lva": insn.address, "ld": m,
                                "breg": mem.base and insn.reg_name(mem.base),
                                "ireg": mem.index and insn.reg_name(mem.index)}
                    constp.pop(d, None)
            elif ops[1].type == CS_OP_IMM:
                imm = ops[1].imm & 0xFFFFFFFF
                if imm > 0xFFFF:
                    constp[d] = {"imm": imm, "lva": insn.address}
                    loadp.pop(d, None)
            continue
        if m in ("xor", "add", "sub") and len(ops) == 2 and ops[0].type == 1:
            d = fam(insn.reg_name(ops[0].reg))
            written = [d]
            if ops[1].type == CS_OP_IMM:
                imm = ops[1].imm & 0xFFFFFFFF
                if d in loadp and imm > 0xFFFF:
                    p = loadp.pop(d)
                    events.append({"va": insn.address, "lva": p["lva"], "ld": p["ld"], "reg": d,
                                   "breg": p["breg"], "ireg": p["ireg"], "disp": p["disp"],
                                   "op": m, "imm": imm})
                constp.pop(d, None)
            elif ops[1].type == CS_OP_MEM:
                mem = ops[1].mem
                disp = mem.disp
                if 0 <= disp < disp_max and (mem.base or mem.index) and d in constp:
                    p = constp.pop(d)
                    op = m if m != "sub" else "rsub"
                    events.append({"va": insn.address, "lva": p["lva"], "ld": "constfirst", "reg": d,
                                   "breg": mem.base and insn.reg_name(mem.base),
                                   "ireg": mem.index and insn.reg_name(mem.index), "disp": disp,
                                   "op": op, "imm": p["imm"]})
                loadp.pop(d, None)
            continue
        if m == "cmp" and len(ops) == 2 and ops[0].type == 1 and ops[1].type == CS_OP_IMM:
            d = fam(insn.reg_name(ops[0].reg))
            imm = ops[1].imm & 0xFFFFFFFF
            if d in loadp and imm > 0xFFFF:
                p = loadp[d]
                events.append({"va": insn.address, "lva": p["lva"], "ld": p["ld"], "reg": d,
                               "breg": p["breg"], "ireg": p["ireg"], "disp": p["disp"],
                               "op": "cmp", "imm": imm})
            continue
        if not ops:
            continue
        # generic invalidation: any instruction whose first operand is a written register
        for o in ops:
            if o.type == 1:
                written.append(fam(insn.reg_name(o.reg)))
                break
        if insn.mnemonic in ("xchg", "xadd", "cmpxchg") and len(ops) > 1 and ops[1].type == 1:
            written.append(fam(insn.reg_name(ops[1].reg)))
        for d in set(written):
            loadp.pop(d, None)
            constp.pop(d, None)


def main():
    exe = sys.argv[1]
    secname = sys.argv[2]
    outp = sys.argv[3]
    disp_max = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x100
    resync = int(sys.argv[5], 0) if len(sys.argv) > 5 else 4096

    data = open(exe, "rb").read()
    imagebase, secs = parse_pe(data)
    sec = next(s for s in secs if s["name"] == secname)
    base_va = imagebase + sec["va"]
    blob = data[sec["ro"] : sec["ro"] + sec["rsz"]]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    events = []
    for c0 in range(0, len(blob), resync):
        code = blob[c0 : c0 + resync + 32]
        sweep(md, code, base_va + c0, disp_max, events)
    with open(outp, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(json.dumps({"section": secname, "events": len(events), "out": outp}))


if __name__ == "__main__":
    main()
