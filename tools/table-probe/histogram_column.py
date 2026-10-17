
import numpy as np, sys, collections
body=np.fromfile(sys.argv[1],dtype=np.uint8,offset=0x210)
base=0x48F3FD8; stride=0x46
vals=[]
for i in range(88904):
    o=base+0x1C+stride*i
    vals.append(int.from_bytes(body[o:o+4],'little'))
c=collections.Counter(vals)
print('distinct values in +0x1C column:',len(c))
for v,n in c.most_common(6): print('  0x%08X  %d  (%.1f%%)'%(v,n,100*n/88904))

