
import sys
body=open(sys.argv[1],'rb').read()[0x210:]
base=0x48F3FD8; stride=0x46
def u32(o): return int.from_bytes(body[o:o+4],'little')
M1=0xB33E40427D5668C0; X1=0x6D8C4AAB00FE8E27; X2=0x30EE5B43130FE0CD; M4=0x0889EEEA326AFB36
strsec=0x3C58E68
M=(1<<64)-1
def key(o): return ((((o*M1)&M)+X1)&M)^X2
def dec(idx):
    off=idx&0xFFFFFF; ln=(idx>>24)&0xFF
    if ln==0: return ''
    k=key(off); out=b''
    for i in range((ln+7)//8):
        v=int.from_bytes(body[strsec+off+8*i:strsec+off+8*i+8],'little')^k
        out+=v.to_bytes(8,'little'); k=(k+M4)&M
    out=out[:ln]
    z=out.find(b'\0')
    return out[:z].decode('latin1') if z>=0 else out.decode('latin1')
for i in [0,1,2,3,100,1000]:
    rec=base+stride*i
    cols=[(o,u32(rec+o)) for o in range(0,0x46-3,2)]
    name=dec((u32(rec+0x14)+0xE811F779)&0xFFFFFFFF)
    ns=dec(u32(rec+0x18)^0x666769B5)
    print('row %d rec=0x%X name=%r ns=%r'%(i,rec,name,ns))
    print('   ', ' '.join('%02X:%08X'%(o,v) for o,v in cols))

