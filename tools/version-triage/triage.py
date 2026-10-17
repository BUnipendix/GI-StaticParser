#!/usr/bin/env python3
"""Cross-version GI metadata triage v2 (memory-bounded).

Two-stage design (peak RSS ~= exe+dat bytes + small windows):
  S1: pure byte-scan of .text for 'mov r64,[rip+d32]' -> all global load sites
  S2: capstone windows (0x150B) around load sites of the busiest globals only
      -> slot records (both operand orders), transforms, body adds, strides
  B : locate MHY\0 header blob by plausibility scoring
  C : discover typeDef table via row-invariant sentinel column (no hardcoded consts)
No hardcoded VA/constant/stride. Output JSON to stdout.
"""
import struct, sys, json
from collections import defaultdict
from capstone import *
from capstone.x86 import *

def parse_pe(d):
    e=struct.unpack('<I',d[0x3C:0x40])[0]
    nsec=struct.unpack('<H',d[e+6:e+8])[0]; optsz=struct.unpack('<H',d[e+20:e+22])[0]
    ib=struct.unpack('<Q',d[e+24+24:e+24+32])[0]
    secs=[]
    for i in range(nsec):
        o=e+24+optsz+40*i
        nm=d[o:o+8].rstrip(b'\x00').decode('latin1')
        vsz,va,rsz,ro=struct.unpack('<IIII',d[o+8:o+24])
        secs.append((nm,ib+va,max(vsz,rsz),ro,rsz))
    return ib,secs

def main():
    exe_path,dat_path=sys.argv[1],sys.argv[2]
    d=open(exe_path,'rb').read()
    dat=open(dat_path,'rb').read()
    body=dat[0x210:]
    ib,secs=parse_pe(d)
    txt=[s for s in secs if s[0]=='.text']
    if not txt:
        print(json.dumps({'error':'no .text'})); return
    _,sva,_,ro,rsz=txt[0]
    T=d[ro:ro+rsz]
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    REG=[X86_REG_RAX,X86_REG_RCX,X86_REG_RDX,X86_REG_RBX,X86_REG_RSP,X86_REG_RBP,X86_REG_RSI,X86_REG_RDI,
         X86_REG_R8,X86_REG_R9,X86_REG_R10,X86_REG_R11,X86_REG_R12,X86_REG_R13,X86_REG_R14,X86_REG_R15]
    # ---- Stage 1: byte scan for mov r64,[rip] (REX.W + 8B + modrm 00rrr101 + disp32)
    by_target=defaultdict(list)   # target -> [(va, regid)]
    i=1; n=len(T)
    while True:
        j=T.find(b'\x8b',i)
        if j<1: break
        i=j+1
        rex=T[j-1]
        if rex&0xF0!=0x40 or not (rex&8): continue
        if j+6>n: break
        modrm=T[j+1]
        if modrm&0xC7!=0x05: continue
        va=sva+j-1
        disp=struct.unpack('<i',T[j+2:j+6])[0]
        tgt=va+7+disp
        regid=(modrm>>3&7)|((rex&4)>>2<<3)
        by_target[tgt].append((va,regid))
    ranked=sorted(by_target.items(),key=lambda kv:-len(kv[1]))
    # ---- Stage 2: window mining around load sites of the busiest globals
    cand=[t for t,_ in ranked[:60]]
    candset=set(cand)
    recs=[]
    for tgt in cand:
        for (va,regid) in by_target[tgt]:
            hreg=REG[regid]
            breg_src={}; immreg={}; regbind={}
            # small backward window for body-reg binding (pure disasm, discard)
            if va-sva>=0x30:
                for ins in md.disasm(T[va-sva-0x30:va-sva],va-0x30):
                    if ins.mnemonic=='mov' and len(ins.operands)==2:
                        o0,o1=ins.operands
                        if o0.type==X86_OP_REG and o1.type==X86_OP_MEM and o1.mem.base==X86_REG_RIP:
                            t2=ins.address+ins.size+o1.mem.disp
                            if t2 in candset: breg_src[o0.reg]=t2
            hdrreg={hreg}
            pend=[]; cnt=0
            for ins in md.disasm(T[va-sva:va-sva+0x150],va):
                cnt+=1
                if cnt==1: continue
                ops=ins.operands; m=ins.mnemonic
                if m=='mov' and len(ops)==2:
                    o0,o1=ops
                    if o1.type==X86_OP_IMM and o0.type==X86_OP_REG:
                        immreg[o0.reg]=o1.imm; regbind.pop(o0.reg,None); continue
                    if o0.type==X86_OP_REG and o1.type==X86_OP_MEM and o1.mem.base==X86_REG_RIP:
                        t2=ins.address+ins.size+o1.mem.disp
                        if t2 in candset: breg_src[o0.reg]=t2
                        regbind.pop(o0.reg,None); immreg.pop(o0.reg,None)
                        continue
                    if o0.type==X86_OP_REG and o1.type==X86_OP_MEM and o1.mem.base in hdrreg and 0<=o1.mem.disp<0x210:
                        imm=o0.reg and immreg.get(o0.reg)  # may be None
                        pend.append({'slot':o1.mem.disp,'va':ins.address,'dst':o0.reg,'op':None,'imm':None,
                                     'gb':None,'stride':None,'k':0,'src':tgt})
                        regbind.pop(o0.reg,None); immreg.pop(o0.reg,None)
                        continue
                    if o0.type==X86_OP_REG and o1.type==X86_OP_REG:
                        if o1.reg in hdrreg: hdrreg.add(o0.reg)
                        continue
                if m in ('mov','movsxd','movzx') and len(ops)==2 and ops[0].type==X86_OP_REG and ops[1].type==X86_OP_MEM and ops[1].mem.base in hdrreg:
                    disp=ops[1].mem.disp
                    if 0<=disp<0x210:
                        pend.append({'slot':disp,'va':ins.address,'dst':ops[0].reg,'op':None,'imm':None,
                                     'gb':None,'stride':None,'k':0,'src':tgt})
                    continue
                if m in ('xor','add','sub') and len(ops)==2 and ops[0].type==X86_OP_REG and ops[1].type==X86_OP_MEM and ops[1].mem.base in hdrreg:
                    disp=ops[1].mem.disp
                    iv=immreg.get(ops[0].reg)
                    if 0<=disp<0x210 and iv is not None:
                        pend.append({'slot':disp,'va':ins.address,'dst':ops[0].reg,'op':m,'imm':iv,
                                     'gb':None,'stride':None,'k':11,'src':tgt})
                    continue
                for r in pend:
                    if r['k']>10: continue
                    r['k']+=1
                    if r['op'] is None and m in ('xor','add','sub') and len(ops)==2:
                        o0,o1=ops
                        if o0.type==X86_OP_REG and o0.reg==r['dst'] and o1.type==X86_OP_IMM:
                            r['op']=m; r['imm']=o1.imm
                    if m=='add' and len(ops)==2:
                        o1=ops[1]
                        if o1.type==X86_OP_REG and o1.reg in breg_src: r['gb']=breg_src[o1.reg]
                        if o1.type==X86_OP_MEM and o1.mem.base==X86_REG_RIP:
                            t3=ins.address+ins.size+o1.mem.disp
                            if t3 in candset: r['gb']=t3
                    if m=='imul' and len(ops)==3 and ops[2].type==X86_OP_IMM and 0<ops[2].imm<=0x400:
                        r['stride']=ops[2].imm
                if cnt>45: break
            recs.extend([r for r in pend if r['gb'] is not None])
    # aggregate: hdr = global whose sites produced most slot records
    hist=defaultdict(int)
    for r in recs: hist[r['src']]+=1
    hdr_global=max(hist,key=lambda g:hist[g]) if hist else None
    body_hist=defaultdict(int)
    for r in recs:
        if r['src']==hdr_global and r['gb'] is not None: body_hist[r['gb']]+=1
    body_global=max(body_hist,key=lambda g:body_hist[g]) if body_hist else None
    slots={}
    for r in recs:
        if r['src']!=hdr_global: continue
        k=(r['slot'],r['op'],r['imm'])
        e=slots.setdefault(k,{'n':0,'body':0,'strides':set(),'va':r['va']})
        e['n']+=1
        if r['gb']==body_global: e['body']+=1
        if r['stride']: e['strides'].add(r['stride'])
    out={'exe':exe_path,'hdr_global':hdr_global,'body_global':body_global,'recs':len(recs),
         'slots':{'0x%X|%s|%s'%(k[0],k[1],hex(k[2]) if k[2] is not None and k[2]>=0 else str(k[2])):
                  {'n':e['n'],'body':e['body'],'strides':sorted(e['strides']),'va':e['va']} for k,e in slots.items()}}
    # ---- Phase B: header blob
    def read(va,nn):
        for (nm,ssv,vsz,sro,srsz) in secs:
            if ssv<=va<ssv+vsz: return d[sro+(va-ssv):sro+(va-ssv)+nn]
        return None
    cands=[]
    for (nm,ssv,vsz,sro,srsz) in secs:
        if nm=='.text': continue
        reg=d[sro:sro+srsz]
        pos=0
        while True:
            ii=reg.find(b'MHY\x00',pos)
            if ii<0: break
            pos=ii+1
            blob=reg[ii:ii+0x210]
            if len(blob)<0x210: break
            ok=tot=0
            for (slot,op,immv),e in slots.items():
                if op is None or immv is None: continue
                raw=struct.unpack('<I',blob[slot:slot+4])[0]
                tot+=1
                v=raw
                if op=='xor': v=raw^(immv&0xFFFFFFFF)
                elif op=='add': v=(raw+immv)&0xFFFFFFFF
                elif op=='sub': v=(raw-immv)&0xFFFFFFFF
                if 0<=v<len(body): ok+=1
            cands.append({'va':ssv+ii,'score':[ok,tot]})
    cands.sort(key=lambda c:-c['score'][0])
    out['blob_cands']=cands[:4]
    blob_va=None
    if cands and cands[0]['score'][1]>0 and cands[0]['score'][0]/cands[0]['score'][1]>=0.8:
        blob_va=cands[0]['va']
    # ---- Phase C: typeDef via row-invariant sentinel
    if blob_va is not None:
        hdr=read(blob_va,0x210)
        def u32b(b,o): return struct.unpack('<I',b[o:o+4])[0]
        def dec(slot,op,immv):
            raw=u32b(hdr,slot)
            if op=='xor': return raw^(immv&0xFFFFFFFF)
            if op=='add': return (raw+immv)&0xFFFFFFFF
            if op=='sub': return (raw-immv)&0xFFFFFFFF
            return raw
        tdefs=[]
        for (slot,op,immv),e in slots.items():
            if e['body']<1 or op is None or immv is None: continue
            for S in (e['strides'] or []):
                if S<8 or S>0x200: continue
                base=dec(slot,op,immv)
                if base+4*S>len(body): continue
                best=None
                NS=2048
                for dd in range(0,S-3,4):
                    lim=min(NS,(len(body)-base-dd)//S)
                    if lim<1500: continue
                    from collections import Counter
                    cc=Counter(u32b(body,base+i2*S+dd) for i2 in range(lim))
                    (mv,mc),=cc.most_common(1)
                    if best is None or mc>best[1]: best=(dd,mc,mv,lim)
                if best and best[1]>=0.55*best[3]:
                    tdefs.append({'slot':'0x%X'%slot,'op':op,'imm':hex(immv&0xFFFFFFFF),'stride':S,
                                  'base':hex(base),'sentinel_off':best[0],'maj':best[1],'lim':best[3],
                                  'sentinel_raw':hex(best[2]),'sites':e['n']})
        tdefs.sort(key=lambda t:(-t['sites'],-t['maj']))
        # per-column majority profile for the top candidates
        for t in tdefs[:2]:
            base=int(t['base'],16); S=t['stride']; prof={}
            for dd in range(0,S-3,4):
                lim=min(1024,(len(body)-base-dd)//S)
                if lim<512: continue
                cc=Counter(u32b(body,base+i2*S+dd) for i2 in range(lim))
                (mv,mc),=cc.most_common(1)
                if mc>=0.5*lim: prof['0x%X'%dd]=[round(mc/lim,3),hex(mv)]
            t['col_profile']=prof
        out['typedef_tables']=tdefs[:6]
    print(json.dumps(out,indent=1))

if __name__=='__main__': main()
