
import numpy as np
buf=np.fromfile('/home/yangsanyi/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/global-metadata.dat',dtype=np.uint8,offset=0x210)
base=0x48F3FD8; stride=0x46
def u32(o): return int.from_bytes(buf[o:o+4].tobytes(),'little')
for off in [0x00,0x08]:
  print('=== off=0x%02X ==='%off)
  r=[u32(base+stride*i+off) for i in range(32)]
  for shift in [19,20,21]:
    from collections import Counter
    c=Counter(x>>shift for x in r)
    print('  shift=%d  hi counts=%s'%(shift,dict(c)))
    best=c.most_common(1)[0][0]
    comp=[x for x in r if (x>>shift)!=best]
    print('     complement distinct=%d %s'%(len(set(comp)), [hex(x) for x in sorted(set(comp))[:5]]))
  # over the whole run
  allr=[u32(base+stride*i+off) for i in range(0,88904,97)]
  for shift in [19,20]:
    from collections import Counter
    c=Counter(x>>shift for x in allr)
    best=c.most_common(1)[0][0]
    comp=set(x for x in allr if (x>>shift)!=best)
    print('  whole-run shift=%d distinct complement=%d %s'%(shift,len(comp),[hex(x) for x in list(comp)[:4]]))

