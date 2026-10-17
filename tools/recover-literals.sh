#!/usr/bin/env bash
# Recover IL2CPP string literals from a MHY-obfuscated global-metadata.dat.
#
# Uses the external tool gi-stringliteral (version-independent: it extracts the
# literal keystream + table decode arithmetic from the game .exe), then writes a
# JSON array of {"index", "value"} entries.
#
# Provenance: https://github.com/kuma-dayo/gi-stringliteral (tested commit 1008fd7,
# "support OSRELWin6.7.0"). Not vendored: clone it next to the other repos, e.g.
#   git clone https://github.com/kuma-dayo/gi-stringliteral ~/Documents/git-repo/gi-stringliteral
#
# Usage:
#   tools/recover-literals.sh <global-metadata.dat> [YuanShen.exe] [out.json]
# Env:
#   GI_STRINGLITERAL  path to the gi-stringliteral checkout (default ~/Documents/git-repo/gi-stringliteral)
set -euo pipefail

DAT=${1:?usage: recover-literals.sh <global-metadata.dat> [exe] [out.json]}
EXE=${2:-}
OUT=${3:-}
TOOL=${GI_STRINGLITERAL:-$HOME/Documents/git-repo/gi-stringliteral}

if [ ! -f "$TOOL/recover_string_literals.py" ]; then
    echo "gi-stringliteral not found at $TOOL" >&2
    echo "clone it: git clone https://github.com/kuma-dayo/gi-stringliteral \"$TOOL\"" >&2
    exit 1
fi
python3 -c 'import capstone' 2>/dev/null || { echo "missing dependency: pip install capstone" >&2; exit 1; }
[ -n "$OUT" ] || OUT="${DAT%.dat}.literals.json"

args=("$DAT")
[ -n "$EXE" ] && args+=("$EXE")
python3 "$TOOL/recover_string_literals.py" "${args[@]}" -o "$OUT"
