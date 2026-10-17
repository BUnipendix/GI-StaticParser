import sys
want = [0x14,0x1c,0x38,0x50,0x106,0x153,0x16b,0x1de,0x1f0,0x2fc2,0x20974,0x9bcd2,0x0,0x8]
m = {}
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.rstrip("\n")
    if "\t" not in line: continue
    a, t = line.split("\t", 1)
    try: m[int(a, 16)] = t
    except ValueError: pass
print("entries:", len(m))
for o in want:
    print("  0x%06X -> %r" % (o, m.get(o, "<missing>")))
