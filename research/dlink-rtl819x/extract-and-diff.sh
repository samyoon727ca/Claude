#!/usr/bin/env bash
# =============================================================================
# Turnkey step-2 runner for the DIR-816L Rev B patch-diff (Track 1 / P1.1).
#
# Carves + extracts the squashfs rootfs from the acquired firmware images, runs
# the firmware-triage funnel on each, and diffs an OLD->NEW pair into a ranked
# candidate list. Meant to run on Linux / WSL2 (needs sasquatch: the Realtek
# images are squashfs v4.0 + LZMA(2), which stock unsquashfs rejects).
#
# The blobs are NOT hardcoded by offset: the rootfs is located by its squashfs
# magic and carved for exactly `bytes_used` bytes from the superblock, so this
# works across all six versions, not just the fingerprinted pair.
#
# Usage:
#   research/dlink-rtl819x/extract-and-diff.sh                 # default pair 205b02 -> 206b01
#   research/dlink-rtl819x/extract-and-diff.sh 203b03 205b02   # any OLD NEW pair
#   research/dlink-rtl819x/extract-and-diff.sh --all           # extract+triage all 6, no diff
#   FORCE=1 research/dlink-rtl819x/extract-and-diff.sh ...     # re-extract even if present
#
# Known version tags: 200b01 201b03 203b03 205b02 206b01 206b09
# Outputs (all git-ignored): work/{tag}.squashfs, work/rootfs_{tag}/,
#   triage-out/{tag}/*, diff-out/{diff-candidates.csv,added,removed,changed}.txt
# =============================================================================
set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FWDIR="$ROOT/firmware/DIR-816L-REVB"
WORK="$ROOT/work"; TRIAGE="$ROOT/triage-out"; DIFF="$ROOT/diff-out"
SKILLS="$ROOT/.claude/skills"
TRIAGE_SH="$SKILLS/firmware-triage/scripts/triage.sh"
SINK_PY="$SKILLS/firmware-triage/scripts/sink_scan.py"
DIFF_PY="$SKILLS/binary-diff/scripts/fw_diff.py"
FORCE="${FORCE:-0}"

log()  { printf '[extract-diff] %s\n' "$*" >&2; }
die()  { printf '[extract-diff] ERROR: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# tag -> inner .bin filename (as extracted from the vendor ZIPs)
bin_for() {
  case "$1" in
    200b01) echo "DIR-816L_REVB1_FW_v2.00b01.bin" ;;
    201b03) echo "DIR816L_FW201b03.bin" ;;
    203b03) echo "DIR816L_FW203b03.bin" ;;
    205b02) echo "DIR816L_FW205b02.bin.bin" ;;
    206b01) echo "DIR-816L_FIRMWARE_206b01.bin" ;;
    206b09) echo "DIR816L_REVB_FW_2_06_b09_beta.bin" ;;
    *) return 1 ;;
  esac
}

check_deps() {
  have python3 || die "python3 not found."
  [ -f "$TRIAGE_SH" ] || die "missing $TRIAGE_SH (run from inside the repo)."
  [ -f "$SINK_PY" ]   || die "missing $SINK_PY."
  [ -f "$DIFF_PY" ]   || die "missing $DIFF_PY."
  if ! have sasquatch; then
    cat >&2 <<'MSG'
[extract-diff] ERROR: `sasquatch` not found — required for Realtek squashfs4.0/LZMA.
  setup-tools.sh installs its build deps (build-essential, zlib1g-dev, liblzma-dev)
  but not sasquatch itself. Build it once:
    git clone https://github.com/devttys0/sasquatch
    cd sasquatch && ./build.sh          # installs the `sasquatch` binary
  (also run: bash .claude/skills/firmware-triage/scripts/setup-tools.sh)
MSG
    exit 1
  fi
  have readelf || log "note: readelf missing -> sink/diff symbol reads use the weaker string-scrape fallback. (apt install binutils-multiarch, or the MIPS toolchain, for precise symbols.)"
}

# Carve the squashfs out of a SEAMA firmware image using the superblock.
# args: <image> <out.squashfs> ; prints "offset bytes_used comp ver" on success.
carve_squashfs() {
  python3 - "$1" "$2" <<'PY'
import sys, struct
img, out = sys.argv[1], sys.argv[2]
data = open(img, "rb").read()
off = data.find(b"hsqs")          # squashfs LE magic
if off < 0:
    sys.exit("no squashfs (hsqs) magic found in " + img)
comp,  = struct.unpack_from("<H", data, off + 0x14)
vmaj,  = struct.unpack_from("<H", data, off + 0x1c)
vmin,  = struct.unpack_from("<H", data, off + 0x1e)
used,  = struct.unpack_from("<Q", data, off + 0x28)
if used <= 0 or off + used > len(data):
    used = len(data) - off        # fall back to end-of-image
open(out, "wb").write(data[off:off + used])
print(f"{off} {used} {comp} {vmaj}.{vmin}")
PY
}

extract_one() {
  local tag="$1" bin rootfs sq meta
  bin="$(bin_for "$tag")" || die "unknown version tag: $tag"
  [ -f "$FWDIR/$bin" ] || die "image not found: $FWDIR/$bin (extract the ZIP first)"
  rootfs="$WORK/rootfs_$tag"; sq="$WORK/$tag.squashfs"
  mkdir -p "$WORK"
  if [ -d "$rootfs" ] && [ "$FORCE" != "1" ]; then
    log "$tag: rootfs already extracted ($rootfs) — skip (FORCE=1 to redo)"
  else
    log "$tag: carving squashfs from $bin"
    meta="$(carve_squashfs "$FWDIR/$bin" "$sq")" || die "$tag: carve failed"
    log "$tag: squashfs @offset=$(echo "$meta" | awk '{print $1}') bytes=$(echo "$meta" | awk '{print $2}') comp=$(echo "$meta" | awk '{print $3}') ver=$(echo "$meta" | awk '{print $4}')"
    rm -rf "$rootfs"
    log "$tag: sasquatch -> $rootfs"
    sasquatch -d "$rootfs" "$sq" >"$WORK/$tag.sasquatch.log" 2>&1 || \
      log "$tag: sasquatch returned nonzero (ownership/xattr warnings are normal as non-root); continuing"
    [ -n "$(ls -A "$rootfs" 2>/dev/null)" ] || die "$tag: extraction produced no files (see $WORK/$tag.sasquatch.log)"
  fi
  log "$tag: triage -> $TRIAGE/$tag"
  mkdir -p "$TRIAGE/$tag"
  bash "$TRIAGE_SH" "$rootfs" "$TRIAGE/$tag" >/dev/null || log "$tag: triage.sh nonzero; continuing"
  python3 "$SINK_PY" "$rootfs" --out "$TRIAGE/$tag/sinks.csv" >/dev/null 2>&1 || log "$tag: sink_scan nonzero; continuing"
}

main() {
  check_deps
  if [ "${1:-}" = "--all" ]; then
    for t in 200b01 201b03 203b03 205b02 206b01 206b09; do extract_one "$t"; done
    log "all six extracted + triaged. Run again with an OLD NEW pair to diff."
    return 0
  fi
  local OLD="${1:-205b02}" NEW="${2:-206b01}"
  bin_for "$OLD" >/dev/null || die "unknown OLD tag: $OLD"
  bin_for "$NEW" >/dev/null || die "unknown NEW tag: $NEW"
  extract_one "$OLD"
  extract_one "$NEW"
  mkdir -p "$DIFF"
  log "diff $OLD -> $NEW"
  python3 "$DIFF_PY" "$WORK/rootfs_$OLD" "$WORK/rootfs_$NEW" \
      --out "$DIFF" --reachable "$TRIAGE/$NEW/services.txt"
  echo
  log "DONE. Ranked candidates: $DIFF/diff-candidates.csv"
  log "Changed files (small list expected — rootfs delta was tiny): $DIFF/changed.txt"
  log "For the 205b02->206b01 silent fix, focus rows under /bin /sbin /www and cgi-bin."
}
main "$@"
