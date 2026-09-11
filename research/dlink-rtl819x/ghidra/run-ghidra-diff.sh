#!/usr/bin/env bash
# =============================================================================
# Headless Ghidra decompilation diff for the DIR-816L cgibin silent-fix (P2.1).
# Imports OLD + NEW cgibin as MIPS:BE:32, runs analysis, exports the decompiled
# C of the access()/HNAP/.php functions from each, and diffs them.
#
# Requires: a local Ghidra install (11.x, JDK 17+). Point GHIDRA_HOME at it:
#   GHIDRA_HOME=/opt/ghidra_11.x_PUBLIC research/dlink-rtl819x/ghidra/run-ghidra-diff.sh
#
# Optional: pass a different anchor set or symbol as $1 (comma-separated).
# Outputs (git-ignored) under diff-out/ghidra/:
#   old_205b02.c, new_206b01.c, cgibin_access.diff
# =============================================================================
set -u -o pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SELF/../../.." && pwd)"
: "${GHIDRA_HOME:?set GHIDRA_HOME to your Ghidra install dir (the one containing support/analyzeHeadless)}"
HL="$GHIDRA_HOME/support/analyzeHeadless"
[ -x "$HL" ] || { echo "analyzeHeadless not found/executable at $HL" >&2; exit 1; }

OLD="$REPO/work/rootfs_205b02/htdocs/cgibin"
NEW="$REPO/work/rootfs_206b01/htdocs/cgibin"
for f in "$OLD" "$NEW"; do [ -f "$f" ] || { echo "missing $f — run extract-and-diff.sh first" >&2; exit 1; }; done

ANCHORS="${1:-access(,.php,GetDeviceSettings,SOAPAction,HNAP,getcfg}"
OUT="$REPO/diff-out/ghidra"; mkdir -p "$OUT"
PROJ="$(mktemp -d)"; trap 'rm -rf "$PROJ"' EXIT

run() { # <binary> <tag>
  local bin="$1" tag="$2"
  echo "[ghidra] analysing $tag ($(basename "$bin")) — this can take a couple of minutes..."
  "$HL" "$PROJ" "gp_$tag" \
    -import "$bin" \
    -processor "MIPS:BE:32:default" \
    -scriptPath "$SELF" \
    -postScript export_callers.java "$OUT/$tag.c" "$ANCHORS" \
    -deleteProject 2>&1 | grep -Ei 'export_callers|ERROR|Exception' || true
}

run "$OLD" old_205b02
run "$NEW" new_206b01

echo
echo "[ghidra] diffing decompiled C..."
diff -u "$OUT/old_205b02.c" "$OUT/new_206b01.c" > "$OUT/cgibin_access.diff" || true
echo "  OLD C  : $OUT/old_205b02.c"
echo "  NEW C  : $OUT/new_206b01.c"
echo "  diff   : $OUT/cgibin_access.diff"
echo "  -> Read the diff: the function that gains the access() call (and the"
echo "     sprintf(...,\"%s/%s.php\",...) above it) is the fix. Trace where the"
echo "     name half comes from (HNAP action? form field?) to prove the source."
