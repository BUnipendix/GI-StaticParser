#!/bin/bash
# Run triage across all sampled GI versions (bounded: -P2, ulimit 2.5GB each).
export BASE=/home/yangsanyi/gire/sample/gi
export OUT=/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage/out
export TRI=/home/yangsanyi/Documents/git-repo/GI-StaticParser/tools/version-triage/triage.py
mkdir -p "$OUT"
ls "$BASE" | sort -V | xargs -P 2 -I{} bash -c '
  v="{}"
  exe="$BASE/$v/YuanShen.exe"
  dat="$BASE/$v/YuanShen_Data/Managed/Metadata/global-metadata.dat"
  if [ -f "$exe" ] && [ -f "$dat" ]; then
    if [ ! -s "$OUT/$v.json" ]; then
      ulimit -v 2500000
      timeout 420 python3 "$TRI" "$exe" "$dat" > "$OUT/$v.json" 2> "$OUT/$v.err"
      echo "$v exit=$?"
    else
      echo "$v cached"
    fi
  else
    echo "$v missing-files"
  fi'
