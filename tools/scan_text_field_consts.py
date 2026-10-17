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
def off2va(o):
    for nm,vsz,va2,rsz,ro in secs:
        if ro<=o<ro+rsz: return IB+va2+(o-ro)
    return None
CONSTS={
 'td_field_start_c':1919057927,
 'td_field_count_c16':39531,
 'fields_sub':492068044,
 'fd_name_c':293038614,
 'fd_type_c16':9103,
}
text=next(s for s in secs if s[0]=='.text')
nm,vsz,va2,rsz,ro=text
d=exe[ro:ro+rsz]
print('scanning .text size', hex(rsz))
for name,c in CONSTS.items():
    if name.endswith('16'):
        pat=struct.pack('<H',c & 0xFFFF)
    else:
        pat=struct.pack('<I',c)
    hits=[]; pos=0
    while True:
        i=d.find(pat,pos)
        if i<0: break
        va=off2va(ro+i)
        if va: hits.append(va)
        pos=i+1
        if len(hits)>=12: break
    print(name, hex(c), 'raw-imm hits:', len(hits), [hex(h) for h in hits[:8]])
# also displacement 0x158 references are too common; check imul 0xa patterns later
md=Cs(CS_ARCH_X86, CS_MODE_64)
for name,c in list(CONSTS.items())[:3]:
    if name.endswith('16'): pat=struct.pack('<H',c & 0xFFFF)
    else: pat=struct.pack('<I',c)
    pos=0; shown=0
    while shown<2:
        i=d.find(pat,pos)
        if i<0: break
        va=off2va(ro+i)
        if va:
            start=va-0x20; o=va-0x20-IB
            print(f'== {name} near {hex(va)}')
            for insn in md.disasm(exe[o:o+0x60], start):
                print(f'  {insn.address:#x}: {insn.mnemonic:8s} {insn.op_str}')
            shown+=1
        pos=i+1
