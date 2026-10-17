import struct, json
from collections import defaultdict
from capstone import *
from capstone.x86 import *

d=open('/home/yangsanyi/kuna_in/710/YuanShen.exe','rb').read()
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
HDR=0x145ad62b8; BODY=0x145ad62c0
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
REG=[X86_REG_RAX,X86_REG_RCX,X86_REG_RDX,X86_REG_RBX,X86_REG_RSP,X86_REG_RBP,X86_REG_RSI,X86_REG_RDI,
     X86_REG_R8,X86_REG_R9,X86_REG_R10,X86_REG_R11,X86_REG_R12,X86_REG_R13,X86_REG_R14,X86_REG_R15]

sites=[]
i=0; n=len(T)
while True:
    j=T.find(b'\x8b',i)
    if j<2: break
    i=j+1
    rex=T[j-1]
    if rex in (0x48,0x4c) and j+6<n:
        modrm=T[j+1]
        if modrm&0xC7==0x05:
            va=sva+j-1
            disp=struct.unpack('<i',T[j+2:j+6])[0]
            tgt=va+7+disp
            if tgt in (HDR,BODY):
                regid=(modrm>>3&7)|((rex&4)>>2<<3)
                sites.append((va,tgt,REG[regid]))
print('sites: hdr=%d body=%d'%(sum(1 for s in sites if s[1]==HDR),sum(1 for s in sites if s[1]==BODY)))

records=[]
for va,tgt,hreg in sites:
    if tgt!=HDR: continue
    breg=set()
    if va-sva>=0x30:
        for ins in md.disasm(T[va-sva-0x30:va-sva],va-0x30):
            if ins.mnemonic=='mov' and len(ins.operands)==2:
                o0,o1=ins.operands
                if o0.type==X86_OP_REG and o1.type==X86_OP_MEM and o1.mem.base==X86_REG_RIP:
                    if ins.address+ins.size+o1.mem.disp==BODY: breg.add(o0.reg)
    hdrreg={hreg}
    pend=[]; cnt=0
    for ins in md.disasm(T[va-sva:va-sva+0x150],va):
        cnt+=1
        if cnt==1: continue
        ops=ins.operands
        if ins.mnemonic in ('mov','movsxd','movzx') and len(ops)==2:
            o0,o1=ops
            if o0.type==X86_OP_REG and o1.type==X86_OP_MEM:
                if o1.mem.base==X86_REG_RIP:
                    if ins.address+ins.size+o1.mem.disp==BODY: breg.add(o0.reg)
                    continue
                if o1.mem.base in hdrreg:
                    disp=o1.mem.disp
                    if 0<=disp<0x210:
                        pend.append({'slot':disp,'va':ins.address,'dst':ins.reg_name(o0.reg),'dstreg':o0.reg,
                                     'op':None,'imm':None,'body':False,'stride':None,
                                     'w':{1:1,2:2,4:4,8:8}.get(o1.size,4),'k':0})
                    continue
            if o0.type==X86_OP_REG and o1.type==X86_OP_REG:
                if o1.reg in hdrreg: hdrreg.add(o0.reg)
                continue
        for r in pend:
            if r['k']>10: continue
            r['k']+=1
            if r['op'] is None and ins.mnemonic in ('xor','add','sub') and len(ops)==2:
                o0,o1=ops
                if o0.type==X86_OP_REG and o0.reg==r['dstreg'] and o1.type==X86_OP_IMM:
                    r['op']=ins.mnemonic; r['imm']=o1.imm
            if ins.mnemonic=='add' and len(ops)==2:
                o1=ops[1]
                if o1.type==X86_OP_REG and o1.reg in breg: r['body']=True
                if o1.type==X86_OP_MEM and o1.mem.base==X86_REG_RIP and ins.address+ins.size+o1.mem.disp==BODY: r['body']=True
            if ins.mnemonic=='imul' and len(ops)==3 and ops[2].type==X86_OP_IMM and 0<ops[2].imm<=0x1000:
                r['stride']=ops[2].imm
        if cnt>45: break
    records.extend(pend)
print('slot records=%d'%len(records))
agg=defaultdict(list)
for r in records: agg[(r['slot'],r['op'],r['imm'])].append(r)
print('distinct (slot,op,imm)=%d'%len(agg))
for k in sorted(agg,key=lambda k:(k[0],str(k[1]))):
    rows=agg[k]
    nb=sum(1 for r in rows if r['body'])
    st=sorted(set(r['stride'] for r in rows if r['stride']))
    print('slot=0x%-4X %-4s imm=%-12s n=%-3d body+=%-3d stride=%-14s first=0x%X'%(k[0],str(k[1]),hex(k[2]) if k[2] is not None else '-',len(rows),nb,str(st),rows[0]['va']))
json.dump([{kk:(hex(vv) if kk=='imm' and vv is not None else vv) for kk,vv in r.items() if kk!='dstreg'} for r in records],open('/tmp/tblre/slotrec3.json','w'))
print('saved')
