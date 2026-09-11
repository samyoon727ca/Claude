#!/usr/bin/env bash
# firmware-triage: extract + inventory a firmware image or extracted rootfs.
# Usage: triage.sh <firmware_image|rootfs_dir> [output_dir]
# Produces in output_dir: inventory.txt, sensitive.txt, services.txt, binaries.txt
# No exotic deps. Uses binwalk if extracting; file/readelf/strings/find opportunistically.
set -u -o pipefail

INPUT="${1:-}"
OUTDIR="${2:-triage-out}"

if [[ -z "$INPUT" ]]; then
  echo "usage: $0 <firmware_image|rootfs_dir> [output_dir]" >&2
  exit 2
fi

log() { printf '[triage] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

mkdir -p "$OUTDIR"
ROOTFS=""

# ---- 1. Resolve the rootfs (extract if given an image) -------------------
if [[ -d "$INPUT" ]]; then
  ROOTFS="$INPUT"
  log "input is a directory; treating as extracted rootfs: $ROOTFS"
elif [[ -f "$INPUT" ]]; then
  if have sha256sum; then
    log "image sha256: $(sha256sum "$INPUT" | awk '{print $1}')"
  fi
  if ! have binwalk; then
    cat >&2 <<'MSG'
[triage] binwalk not found. Install it, or pre-extract and pass the rootfs dir.
         Debian/Ubuntu: sudo apt-get install binwalk
         pip:           pipx install binwalk
         See reference/binwalk-notes.md for extraction gotchas.
MSG
    exit 3
  fi
  EXDIR="$OUTDIR/_extracted"
  mkdir -p "$EXDIR"
  log "extracting with binwalk (this can take a minute)..."
  # -e extract known types, -M recurse (matryoshka). Directory chosen with -C.
  binwalk -e -M -C "$EXDIR" "$INPUT" >"$OUTDIR/binwalk.log" 2>&1 || \
    log "binwalk returned nonzero; continuing with whatever extracted"
  # Pick the most plausible rootfs: prefer squashfs-root, else largest dir with /bin or /etc.
  CAND="$(find "$EXDIR" -type d \( -name 'squashfs-root*' -o -name 'cpio-root' \) 2>/dev/null | head -n1)"
  if [[ -z "$CAND" ]]; then
    CAND="$(find "$EXDIR" -type d -name bin -exec dirname {} \; 2>/dev/null | head -n1)"
  fi
  if [[ -z "$CAND" ]]; then
    CAND="$(find "$EXDIR" -maxdepth 3 -type d -name '_*.extracted' 2>/dev/null | head -n1)"
  fi
  ROOTFS="${CAND:-$EXDIR}"
  log "using rootfs: $ROOTFS"
else
  echo "[triage] not a file or directory: $INPUT" >&2
  exit 2
fi

# ---- 2. inventory.txt ----------------------------------------------------
{
  echo "# Firmware Triage Inventory"
  echo "# rootfs: $ROOTFS"
  echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "## File count"
  find "$ROOTFS" -type f 2>/dev/null | wc -l | sed 's/^/total files: /'
  echo
  echo "## Version / banner strings"
  for f in etc/version etc/openwrt_version etc/*release* etc/issue etc/banner \
           etc/motd www/version.txt; do
    for m in "$ROOTFS"/$f; do
      [[ -f "$m" ]] && { echo "== $m =="; sed -n '1,5p' "$m"; }
    done
  done 2>/dev/null
  echo
  echo "## ELF architecture histogram"
  if have file; then
    find "$ROOTFS" -type f 2>/dev/null -exec file {} + 2>/dev/null \
      | grep -a ELF \
      | sed -E 's/.*ELF (32|64)-bit (LSB|MSB)[^,]*, ([^,]+),.*/\1-bit \2 \3/' \
      | sort | uniq -c | sort -rn
  else
    echo "(file(1) not available; see binaries.txt via readelf)"
  fi
} > "$OUTDIR/inventory.txt" 2>/dev/null
log "wrote inventory.txt"

# ---- 3. sensitive.txt ----------------------------------------------------
{
  echo "# Sensitive files & credentials (LEADS, verify each)"
  echo
  echo "## Private keys (PEM headers)"
  grep -rIl -e '-----BEGIN .*PRIVATE KEY-----' "$ROOTFS" 2>/dev/null | sort -u
  echo
  echo "## Certs / key material by extension"
  find "$ROOTFS" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.key' \
       -o -name '*.der' -o -name '*.p12' \) 2>/dev/null | sort
  echo
  echo "## passwd / shadow / htpasswd"
  find "$ROOTFS" -type f \( -name 'passwd' -o -name 'shadow' -o -name '.htpasswd' \
       -o -name 'passwd.bak' \) 2>/dev/null | sort
  echo
  echo "## Hardcoded-credential greps (high false positive; triage manually)"
  grep -rIn -E '(admin|root|telnet|password|passwd|secret)[[:space:]]*[:=]' "$ROOTFS" 2>/dev/null \
    | grep -avE '\.po:|/usr/share/' | head -n 200
  echo
  echo "## SUID/SGID binaries"
  find "$ROOTFS" -type f -perm -4000 2>/dev/null | sort
  find "$ROOTFS" -type f -perm -2000 2>/dev/null | sort
  echo
  echo "## World-writable files"
  find "$ROOTFS" -type f -perm -0002 2>/dev/null | sort | head -n 100
} > "$OUTDIR/sensitive.txt" 2>/dev/null
log "wrote sensitive.txt"

# ---- 4. services.txt -----------------------------------------------------
{
  echo "# Reachable services & startup (the attack surface)"
  echo
  echo "## Web servers"
  find "$ROOTFS" -type f \( -name 'httpd' -o -name 'lighttpd' -o -name 'uhttpd' \
       -o -name 'mini_httpd' -o -name 'goahead' -o -name 'boa' -o -name 'nginx' \
       -o -name 'micro_httpd' \) 2>/dev/null | sort
  echo
  echo "## CGI / web handlers"
  find "$ROOTFS" -type f \( -name '*.cgi' -o -name '*.php' -o -path '*cgi-bin*' \) 2>/dev/null | sort | head -n 200
  echo
  echo "## Network daemons"
  find "$ROOTFS" -type f \( -name 'telnetd' -o -name 'dropbear' -o -name 'sshd' \
       -o -name 'dnsmasq' -o -name 'upnpd' -o -name 'miniupnpd' -o -name 'tr069*' \
       -o -name 'ftpd' -o -name 'samba' -o -name 'smbd' \) 2>/dev/null | sort
  echo
  echo "## Init / startup scripts"
  find "$ROOTFS" \( -path '*/etc/init.d/*' -o -name 'rcS' -o -name 'rc.local' \
       -o -path '*/etc/rc.d/*' \) -type f 2>/dev/null | sort
} > "$OUTDIR/services.txt" 2>/dev/null
log "wrote services.txt"

# ---- 5. binaries.txt (feeds sink_scan.py) --------------------------------
{
  echo "# ELF binaries (arch/endianness)"
  if have file; then
    find "$ROOTFS" -type f 2>/dev/null -exec sh -c '
      for f do
        if head -c4 "$f" 2>/dev/null | grep -aq ELF; then
          printf "%s\t%s\n" "$f" "$(file -b "$f" 2>/dev/null | cut -c1-80)"
        fi
      done' sh {} +
  else
    find "$ROOTFS" -type f 2>/dev/null | while read -r f; do
      head -c4 "$f" 2>/dev/null | grep -aq ELF && echo "$f"
    done
  fi
} > "$OUTDIR/binaries.txt" 2>/dev/null
log "wrote binaries.txt"

log "done. Review $OUTDIR/*.txt then run sink_scan.py on: $ROOTFS"
echo "$ROOTFS"
