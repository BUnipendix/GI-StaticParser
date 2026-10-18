#!/usr/bin/env bash
# Rebuild every 7.1 static-unpack artifact and assert the documented counts/sizes.
# Usage: tools/final_verify.sh [out_dir]
# Env:   WITH_LITERALS=1   also re-run the external string-literal recovery tool.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${1:-"$HOME/gire/out/71"}
EXE=${EXE:-"$HOME/gire/sample/gi/7.1.0/YuanShen.exe"}
DAT=${DAT:-"$HOME/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/global-metadata.dat"}
mkdir -p "$OUT"

cargo build --release
./target/release/mhydump dump-gen --exe "$EXE" --metadata "$DAT" \
  --out "$OUT/dump.cs" --attributes-out "$OUT/attributes.json" \
  --images-out "$OUT/images.json" --dummy-out "$OUT/dummy.jsonl"

( cd tools/dummygen && dotnet build -c Release >/dev/null && \
  dotnet bin/Release/net10.0/dummygen.dll "$OUT/dummy.jsonl" "$OUT/DummyDll.dll" )

if [ "${WITH_LITERALS:-0}" = "1" ]; then
  tools/recover-literals.sh "$DAT" "$EXE" "$OUT/literals.json"
fi

python3 tools/final_verify.py "$OUT"
