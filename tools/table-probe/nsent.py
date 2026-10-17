
import sys
body=open(sys.argv[1],'rb').read()[0x210:]
base=0x48F3FD8; st=0x46
def u32(o): return int.from_bytes(body[o:o+4],'little')
sent=0x17EE0886
n=0
vals={}
for i in range(88904):
    v=u32(base+st*i+0x14)
    if v==sent: n+=1
    vals[v]=vals.get(v,0)+1
print('rows with td_name_sentinel raw=0x%08X: %d / 88904'%(sent,n))
print('distinct name-raw values:',len(vals))

