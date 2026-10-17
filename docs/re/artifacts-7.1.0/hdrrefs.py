import struct, sys
from capstone import *
from capstone.x86 import *

p='/home/yangsanyi/kuna_in/710/YuanShen.exe'
d=open(p,'rb').read()
e=struct.unpack('<I',d[0x3C:0x40])[0]
nsec=struct.unpack('<H',d[e+6:e+8])[0]; optsz=struct.unpack('<H',d[e+20:e+22])[0]
ib=struct.unpack('<Q',d[e+24+24:e+24+32])[0]
secs=[]
for i in range(nsec):
    o=e+24+optsz+40*i
    nm=d[o:o+8].rstrip(b'\x00').decode('latin1')
    vsz,va,rsz,ro=struct.unpack('<IIII',d[o+8:o+24])
    secs.append((nm,ib+va,vsz,ro,rsz))
nm,sva,vsz,ro,rsz=[s for s in secs if s[0]=='.text'][0]
T=d[ro:ro+rsz]
print('.text VA=0x%X size=0x%X'%(sva,rsz))

HDR=0x145ad62b8; BODY=0x145ad62c0
LO,HI=0x145ad6200,0x145ad6480

md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True; md.skipdata=True
hits={}
n=0
for ins in md.disasm(T,sva):
    n+=1
    if ins.id==0: continue
    for op in ins.operands:
        if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
            tgt=ins.address+ins.size+op.mem.disp
            if LO<=tgt<HI:
                isw = (ins.mnemonic=='mov' and ins.operands[0].type==X86_OP_MEM and ins.operands[0].mem.base==X86_REG_RIP)
                hits.setdefault(tgt,[]).append((ins.address,ins.bytes.hex(),ins.mnemonic,ins.op_str,isw))
print('insns=%d  distinct targets=%d'%(n,len(hits)))
for tgt in sorted(hits):
    rows=hits[tgt]
    wr=[r for r in rows if r[4]]; rd=[r for r in rows if not r[4]]
    tag=''
    if tgt==HDR: tag=' <== HDRGLOBAL'
    if tgt==BODY: tag=' <== BODYBASE'
    print('')
    print('## 0x%X%s  refs=%d (writes=%d, reads=%d)'%(tgt,tag,len(rows),len(wr),len(rd)))
    for r in (wr+rd)[:40]:
        print('   %s 0x%X  %-20s %s %s'%('W' if r[4] else 'R',r[0],r[1],r[2],r[3]))
    if len(rows)>40: print('   ... +%d more'%(len(rows)-40))
