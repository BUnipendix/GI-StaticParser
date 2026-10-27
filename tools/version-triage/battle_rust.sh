#!/usr/bin/env bash
# R78/R79 battle: run the full Rust zero-touch chain per version and, where an
# official oracle dump exists, compare every engine-decoded method name against
# it. Records failures and keeps going; writes a summary at the end.
# Usage: battle_rust.sh <outdir>
set -u
OUT="${1:-/tmp/battle}"
REPO=/home/yangsanyi/Documents/git-repo/GI-StaticParser
MHY=$REPO/target/release/mhydump
# Full single-binary chain: sites + derive + strings all produced by mhydump
# itself (R80); the Python loadsites artifacts are byte-compatible fallbacks.
SITES="$OUT/sites"
SEED=~/gire/out/zero-touch/seed_6.7.0.json
SEEDS="$OUT/sites/6.7.0.json"
SEEDD="$OUT/6.7.0.derive.json"
mkdir -p "$SITES"
[ -s "$SEEDS" ] || "$MHY" loadsites --exe ~/gire/sample/gi/6.7.0/YuanShen.exe --out "$SEEDS" > /dev/null
[ -s "$SEEDD" ] || "$MHY" derive --exe ~/gire/sample/gi/6.7.0/YuanShen.exe --metadata ~/gire/sample/gi/6.7.0/YuanShen_Data/Managed/Metadata/global-metadata.dat --out "$SEEDD" 2>&1 | tail -1
mkdir -p "$OUT"
: > "$OUT/summary.txt"

declare -A ROWS=( [6.0]=475151 [6.1]=597083 [6.2]=603291 [6.3]=625077 [6.5]=655240 [6.6]=640000 )
declare -A ORACLE=( [6.0]=6.0Dump.cs [6.1]=6.1Dump.cs [6.2]=6.2Dump.cs [6.3]=6.3Dump.cs [6.5]=6.5Dump.cs )

for V in 6.0 6.1 6.2 6.3 6.5 6.6; do
  EXE=~/gire/sample/gi/$V.0/YuanShen.exe
  DAT=~/gire/sample/gi/$V.0/YuanShen_Data/Managed/Metadata/global-metadata.dat
  LOG="$OUT/$V.log"
  echo "=== $V ===" | tee -a "$OUT/summary.txt"
  {
    if [ ! -s "$SITES/$V.0.json" ]; then
      "$MHY" loadsites --exe "$EXE" --out "$SITES/$V.0.json" 2>&1 | tail -1
    fi
    if [ ! -f "$OUT/$V.strings.txt" ]; then
      "$MHY" strings --exe "$EXE" --metadata "$DAT" --min-len 3 --out "$OUT/$V.strings.txt" 2>&1 | sed -n '1,3p'
    else
      echo "strings cache reused: $(wc -l < "$OUT/$V.strings.txt") entries"
    fi
    if [ ! -s "$OUT/$V.strings.txt" ]; then
      echo "RESULT $V strings FAILED (no heap)"; exit 0
    fi
    "$MHY" auto-tables \
      --exe "$EXE" --metadata "$DAT" \
      --sites "$SITES/$V.0.json" \
      --seed "$SEED" --seed-sites "$SEEDS" --seed-derive "$SEEDD" \
      --strings "$OUT/$V.strings.txt" \
      --solve-method --solve-td --rows "${ROWS[$V]}" \
      --out "$OUT/$V.auto.json" \
      --profile-out "$OUT/$V.profile.json" \
      --names-out "$OUT/$V.names.tsv" \
      --verify-rows 256
    echo "auto-tables exit=$?"
  } > "$LOG" 2>&1

  # solve verdict from the artifact (not from exit codes alone)
  python3 - "$OUT/$V.auto.json" "$V" >> "$OUT/summary.txt" << 'PYEOF'
import json, sys
try:
    a = json.load(open(sys.argv[1]))
    mt = a.get('method_table')
    if not mt or not mt.get('name'):
        print(f"{sys.argv[2]}: SOLVE FAILED (no method_table/name)")
    else:
        st = (mt.get('starts') or [{}])[0]
        print(f"{sys.argv[2]}: solve name={mt['name']['family']} c={hex(mt['name']['c'])} "
              f"ok={mt['name']['ok_rows']} idrate={mt['name']['idrate']} "
              f"start c={hex(st.get('c',0))} bad={st.get('chain_bad')} sum={st.get('sum_counts')}")
except Exception as e:
    print(f"{sys.argv[2]}: ARTIFACT ERROR {e}")
PYEOF
  grep -E "engine verify|note: WEAK" "$LOG" | sed 's/^/  /' >> "$OUT/summary.txt"

  # oracle lockstep compare
  if [ -n "${ORACLE[$V]:-}" ] && [ -s "$OUT/$V.names.tsv" ]; then
    python3 - "$OUT/$V.names.tsv" ~/gire/out/oracle/"${ORACLE[$V]}" "$V" >> "$OUT/summary.txt" << 'PYEOF'
import sys, re
mine = [l.split('\t', 1)[1].rstrip('\n') for l in open(sys.argv[1], encoding='utf-8', errors='replace')]
pat = re.compile(r'\((.*?)\)\s*\{')
orc = []
for line in open(sys.argv[2], encoding='utf-8', errors='replace'):
    s = line.strip()
    if '{ }' in s and '(' in s and (') { }' in s):
        head = s[:s.find('(')].split()
        orc.append(head[-1] if head else '')
i = j = match = mismatch = skipped = 0
bad = []
while i < len(mine) and j < len(orc):
    if not mine[i] or len(mine[i]) > 120:
        i += 1; j += 1; skipped += 1; continue
    if mine[i] == orc[j]:
        match += 1
    else:
        mismatch += 1
        if len(bad) < 5: bad.append((i, mine[i][:40], orc[j][:40]))
    i += 1; j += 1
tot = match + mismatch
print(f"{sys.argv[3]}: oracle compared={tot} match={match} ({100.0*match/max(tot,1):.2f}%) "
      f"mismatch={mismatch} skipped={skipped} tail_uncmp=my{len(mine)-i}/orc{len(orc)-j} bad={bad}")
PYEOF
  fi
done
echo "=== battle done ===" >> "$OUT/summary.txt"
cat "$OUT/summary.txt"
