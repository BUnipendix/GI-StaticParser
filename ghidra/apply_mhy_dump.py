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

from ghidra.program.model.symbol import SourceType


def safe_name(n):
    """Ghidra symbols reject some characters; map them to '_' (Il2CppDumper
    names may contain generic backticks etc.)."""
    out = []
    for c in n:
        if c.isalnum() or c in '_.$<>':
            out.append(c)
        else:
            out.append('_')
    r = ''.join(out)
    if r and r[0].isdigit():
        r = '_' + r
    return r or 'il2cpp_method'


def to_addr(va):
    # Jython is Python 2: hex() of a big int yields a trailing "L" that Ghidra
    # rejects, so pass the numeric offset directly.
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(long(va))


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
                try:
                    fn.setName(e["Name"], SourceType.USER_DEFINED)
                    applied += 1
                except Exception:
                    fn.setName(safe_name(e["Name"]), SourceType.USER_DEFINED)
                    applied += 1
            else:
                failed += 1
        except Exception:
            failed += 1
        if i % 50000 == 0:
            print("progress: %d/%d" % (i, len(methods)))
    print("done: %d named, %d functions created, %d failed" % (applied, created, failed))


run()
