#!/usr/bin/env python3
"""Dense column-consumer finder: scan a PE section linearly for row-column read
idioms ([base+disp] load followed by an imm32 transform on the loaded reg),
then report (window, base-register) clusters that touch many distinct small
disps -- i.e. functions that consume a metadata row.

Usage: densescan.py <exe> <section-name> <out-jsonl> [disp-max] [chunk-kb]
"""
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM


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


def main():
    exe = sys.argv[1]
    secname = sys.argv[2]
    outp = sys.argv[3]
    disp_max = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x100
    chunk_kb = int(sys.argv[5], 0) if len(sys.argv) > 5 else 256

    data = open(exe, "rb").read()
    imagebase, secs = parse_pe(data)
    sec = next(s for s in secs if s["name"] == secname)
    base_va = imagebase + sec["va"]
    blob = data[sec["ro"] : sec["ro"] + sec["rsz"]]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    chunk = chunk_kb * 1024
    events = []
    for c0 in range(0, len(blob), chunk):
        code = blob[c0 : c0 + chunk + 64]
        # one linear disasm per chunk (overlaps handled by event dedup later)
        pending = {}  # reg -> (disp, sz, load_va)
        for insn in md.disasm(code, base_va + c0):
            m = insn.mnemonic
            ops = insn.operands
            if m in ("mov", "movzx", "movsx") and len(ops) == 2 and ops[0].type == 1 and ops[1].type == CS_OP_MEM:
                mem = ops[1].mem
                if mem.base and not mem.index:
                    disp = mem.disp
                    if 0 <= disp < disp_max:
                        r = insn.reg_name(ops[0].reg)
                        pending[r] = (disp, insn.address, m)
                pending.pop(insn.reg_name(ops[0].reg), None) if False else None
                continue
            if m in ("xor", "add", "sub") and len(ops) == 2 and ops[1].type == CS_OP_IMM and ops[0].type == 1:
                r = insn.reg_name(ops[0].reg)
                imm = ops[1].imm & 0xFFFFFFFF
                if r in pending and imm > 0xFFFF:
                    disp, lva, ld = pending[r]
                    events.append({
                        "va": insn.address, "lva": lva, "ld": ld, "reg": r,
                        "disp": disp, "op": m, "imm": imm,
                    })
                    del pending[r]
                continue
            # any other write to a tracked reg invalidates it
            if ops and ops[0].type == 1:
                r0 = insn.reg_name(ops[0].reg)
                if r0 in pending:
                    del pending[r0]
        if c0 % (chunk * 8) == 0:
            print(f"  ..{secname} {c0:#x}/{len(blob):#x} events={len(events)}", file=sys.stderr)
    with open(outp, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(json.dumps({"section": secname, "events": len(events), "out": outp}))


if __name__ == "__main__":
    main()
