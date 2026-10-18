import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
EXE='/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen.exe'
IB=0x140000000
exe=open(EXE,'rb').read()
e=struct.unpack_from('<I',exe,0x3C)[0]; n=struct.unpack_from('<H',exe,e+6)[0]; optz=struct.unpack_from('<H',exe,e+20)[0]
secs=[]
for i in range(n):
    o=e+24+optz+i*40
    nm=exe[o:o+8].rstrip(b'\x00').decode(); vsz,va,rsz,ro=struct.unpack_from('<IIII',exe,o+8)
    secs.append((nm,vsz,va,rsz,ro))
TARGETS={
 0x143B4B248:'slot_0x143B4B248',
 0x145AD62B8:'G_HDR',
 0x145AD62C0:'G_BODY',
 0x145AD62C8:'G_STARTUP',
 0x145AD62D8:'G_CACHE',
}
md=Cs(CS_ARCH_X86, CS_MODE_64)
md.detail=True
for nm,vsz,va,rsz,ro in secs:
    if nm not in ('.text','.upx0'): continue
    d=exe[ro:ro+rsz]
    base=IB+va
    print(f'== scanning {nm} {base:#x} size {rsz:#x}', flush=True)
    hits={k:[] for k in TARGETS}
    CH=1<<20
    pos=0
    while pos<len(d):
        chunk=d[pos:pos+CH]
        start=base+pos
        for insn in md.disasm(chunk,start):
            for op in insn.operands:
                if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    tgt=insn.address+insn.size+op.mem.disp
                    if tgt in hits: hits[tgt].append((insn.address,insn.mnemonic,insn.op_str))
                elif op.type==X86_OP_IMM and op.imm in hits:
                    hits[op.imm].append((insn.address,insn.mnemonic,insn.op_str))
        pos+=CH
    for k,v in hits.items():
        print(f'  {TARGETS[k]} {k:#x}: {len(v)} hits')
        for a,m,o in v[:12]: print(f'    {a:#x}: {m} {o}')

