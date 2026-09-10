#!/usr/bin/env bash
# Provision the firmware extraction toolchain the triage/diff skills expect.
# Idempotent; prints what it did. Debian/Ubuntu apt path is fully automated;
# other platforms get guidance. Run once per machine (or per fresh environment).
set -u
log() { printf '[setup] %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
  log "Non-Linux ($OS). Install via your package manager + pip:"
  log "  brew install binwalk squashfs jefferson qemu   # macOS (Homebrew)"
  log "  pip install jefferson ubi_reader"
  exit 0
fi

SUDO=""; [ "$(id -u)" -ne 0 ] && have sudo && SUDO="sudo"

if have apt-get; then
  log "apt: installing base extraction + emulation tooling"
  $SUDO apt-get update -qq
  # binwalk, squashfs-tools (unsquashfs), jefferson deps, ubi tools, QEMU user-mode,
  # plus common compressors binwalk shells out to.
  $SUDO apt-get install -y -qq \
    binwalk squashfs-tools sleuthkit p7zip-full \
    liblzma-dev liblzo2-dev zlib1g-dev \
    mtd-utils python3-pip qemu-user qemu-user-static \
    build-essential zlib1g-dev liblzma-dev 2>/dev/null
else
  log "No apt-get; install binwalk, squashfs-tools, mtd-utils, qemu-user via your PM."
fi

# Python extractors (JFFS2 / UBIFS) — pip works even where apt lacks them.
if have pip3 || have pip; then
  PIP="$(command -v pip3 || command -v pip)"
  log "pip: jefferson (JFFS2) + ubi_reader (UBIFS)"
  $PIP install --quiet --upgrade jefferson ubi_reader 2>/dev/null \
    || log "pip install had issues; retry manually if JFFS2/UBIFS extraction is needed"
fi

# sasquatch — vendor-mangled SquashFS that stock unsquashfs cannot read.
# Not packaged; built from source. Only needed for some vendor images.
if ! have sasquatch; then
  log "sasquatch not present (needed for some vendor-mangled SquashFS)."
  log "  Build: git clone https://github.com/devttys0/sasquatch && cd sasquatch && ./build.sh"
fi

echo
log "verification:"
for t in binwalk unsquashfs jefferson ubireader_extract_files qemu-mips-static sasquatch; do
  printf '  %-26s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo MISSING)"
done
log "done. MISSING sasquatch/qemu are only needed for vendor-mangled FS / emulation."
