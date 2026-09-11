# Binwalk & Extraction Notes

Extraction is where triage most often stalls. Common situations and what to do.

## Normal case
`binwalk -e -M <image>` extracts nested compressed blobs and filesystems. Look
for `squashfs-root/` (most SOHO routers), `cpio-root/`, or a `_<name>.extracted/`
tree containing `/bin` and `/etc`. `triage.sh` auto-selects the most plausible one.

## Vendor header / trailer
Many images have a vendor header (magic, model, checksum) before the real payload
(e.g. TRX, uImage, Netgear `.chk`, D-Link `SHRS`/`AGE`). Symptoms: binwalk finds
the filesystem at a non-zero offset, or only after `dd` past the header.
- Identify the header with `binwalk` (entropy + signature scan) and `xxd | head`.
- `dd if=image of=payload.bin bs=1 skip=<offset>` then re-run binwalk if needed.

## Encrypted / obfuscated images
Symptom: flat high entropy across the whole file, no signatures. The vendor
encrypts firmware.
- Look for an **older** firmware version that shipped **unencrypted** — the
  decryption key/routine often lives in that earlier image or in the bootloader.
- Extract the key from the updater binary or U-Boot, or find a public teardown.
- If undecryptable without hardware, pivot to a different model/version. Do not
  spend the session brute-forcing.

## Non-standard / newer filesystems
- **UBI/UBIFS** (NAND): `ubireader_extract_files` (ubi_reader) instead of raw binwalk.
- **JFFS2**: `jefferson`.
- **cramfs/romfs**: dedicated unpackers; binwalk usually handles these.

## Sanity checks after extraction
- `find <rootfs> -maxdepth 1` shows a Unix layout (`bin etc lib sbin usr www`).
- `file <rootfs>/bin/busybox` (or the web server) confirms arch + endianness —
  record this; it drives Ghidra's language choice and the QEMU target.

## Never
- Never commit extracted filesystems or the firmware blob (see `.gitignore`).
- Never run extracted binaries directly on your host — emulate (QEMU/FirmAE).
