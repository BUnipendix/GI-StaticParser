#!/usr/bin/env python3
"""Classify 7.0 typeDefs into class/struct/interface from two data-solved columns.

* byvalTypeIndex: typeDef row u32 @12, xor 0x1253E298 -> Il2CppType index whose entry has
  data == typeDefIndex; its kind byte is 0x12 (CLASS) or 0x11 (VALUETYPE).
* parentTypeIndex: typeDef row u32 @4, xor 0x149B1F48 -> parent typeDef index; 0xFFFFFFFF
  means "no parent" (interfaces and <Module>; <Module> is special-cased).

Enums are VALUETYPEs and are currently reported as struct: distinguishing them needs the
System.Enum parent, whose value this column does not provide yet (documented, not guessed).
"""
import struct, sys
sys.path.insert(0, '/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage')

TD_BASE = 17522200
TD_STRIDE = 70
TD_ROWS = 86932
BYVAL_OFF, BYVAL_XOR = 12, 0x1253E298
PARENT_OFF, PARENT_XOR = 4, 0x149B1F48
TA_FILE_OFF = 0x2D3C7F0
TA_COUNT = 662534

def classify(exe_path, body):
    d = open(exe_path, 'rb').read()
    rows = TD_ROWS
    out = []
    for i in range(rows):
        ro = TD_BASE + i * TD_STRIDE
        byval = (struct.unpack_from('<I', body, ro + BYVAL_OFF)[0] ^ BYVAL_XOR) & 0xFFFFFFFF
        parent = (struct.unpack_from('<I', body, ro + PARENT_OFF)[0] ^ PARENT_XOR) & 0xFFFFFFFF
        if byval >= TA_COUNT:
            out.append('?')
            continue
        typ = d[TA_FILE_OFF + 16 * byval + 10]
        if i == 0:
            out.append('class')        # <Module>: no parent, but not an interface
        elif parent == 0xFFFFFFFF:
            out.append('interface')
        elif typ == 0x11:
            out.append('struct')       # includes enums (not distinguished yet)
        else:
            out.append('class')
    return out
