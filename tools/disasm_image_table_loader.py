import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
exe=open('/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen.exe','rb').read()
IB=0x140000000
e=struct.unpack_from('<I',exe,0x3C)[0]; nsec=struct.unpack_from('<H',exe,e+6)[0]; optsz=struct.unpack_from('<H',exe,e+20)[0]
secs=[]
for i in range(nsec):
    off=e+24+optsz+i*40
    nm=exe[off:off+8].rstrip(b'\x00').decode(); vsz,va,rsz,ro=struct.unpack_from('<IIII',exe,off+8)
    secs.append((nm,vsz,va,rsz,ro))
def va2off(va):
    rva=va-IB
    for nm,vsz,va2,rsz,ro in secs:
        if va2<=rva<va2+max(vsz,rsz): return ro+(rva-va2)
    return None
start=0x140536f00; end=0x140537120
o=va2off(start)
code=exe[o:va2off(end)]
md=Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(code, start):
    op=insn.op_str
    if 'rsi' in op or '0x58' in op or 'r12' in op or insn.mnemonic.startswith('call') or insn.mnemonic in ('xor','add','sub','imul','shr') or insn.mnemonic=='mov':
        print(f'{insn.address:#x}: {insn.mnemonic:8s} {op}')
