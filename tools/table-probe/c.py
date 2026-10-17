
import numpy as np, sys
body=np.fromfile(sys.argv[1],dtype=np.uint8,offset=0x210)
u32=body[:len(body)//4*4].view(np.uint32)
for name,v in [('td_magic',0xDEBA5049),('mhy',0x004448594D)]:
    n=int((u32==np.uint32(v)).sum())
    print(name,hex(v),'count',n)
pos=np.flatnonzero(u32==np.uint32(0xDEBA5049))
print('first positions', [hex(int(x)) for x in pos[:10]])

