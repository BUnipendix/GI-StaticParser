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
up=next(s for s in secs if s[0]=='.upx0')
nm,vsz,va2,rsz,ro=up
d=exe[ro:ro+rsz]
md=Cs(CS_ARCH_X86, CS_MODE_64)
CS={1919057927:'td_field_start_c',39531:'td_field_count_c',492068044:'fields_sub',293038614:'fd_name_c',9103:'fd_type_c',0x9A6B:'fc16'}
hits=[]
for insn in md.disasm(d, IB+va2):
    op=insn.op_str
    for c,name in CS.items():
        if hex(c) in op or str(c) in op:
            hits.append((insn.address,name,insn.mnemonic,op))
print('hits in .upx0:', len(hits))
for h in hits[:40]: print(f'{h[0]:#x} {h[1]}  {h[2]} {h[3]}')
