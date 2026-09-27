# Applies an Il2CppDumper-compatible script.json (as emitted by `mhydump dump`)
# inside Ghidra: creates functions at each method address and renames them to
# the fully-qualified managed name.
#
# Usage: Script Manager -> run this script -> pick the script.json written next
# to dump.cs. Works headless too:
#   analyzeHeadless <proj> <prog> -postScript apply_mhy_dump.py <path-to-script.json>
#
# @category MHY.Il2Cpp
# @runtime Jython

import json


def to_addr(va):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(hex(int(va)))


def run():
    f = askFile("Select script.json (from mhydump dump)", "Apply")
    data = json.load(open(f.getAbsolutePath()))
    fm = currentProgram.getFunctionManager()
    methods = data.get("ScriptMethod", [])
    applied = 0
    created = 0
    failed = 0
    monitor.setMessage("applying il2cpp method names")
    for i, e in enumerate(methods):
        try:
            addr = to_addr(e["Address"])
            fn = fm.getFunctionAt(addr)
            if fn is None:
                fn = createFunction(addr, None)
                if fn is not None:
                    created += 1
            if fn is not None:
                fn.setName(e["Name"], True)
                applied += 1
            else:
                failed += 1
        except Exception:
            failed += 1
        if i % 50000 == 0:
            print("progress: %d/%d" % (i, len(methods)))
    print("done: %d named, %d functions created, %d failed" % (applied, created, failed))


run()
