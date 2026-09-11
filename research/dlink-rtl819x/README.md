# Research — D-Link RTL819x (Track 1 first target)

Working area for the first Track 1 assessment. **Paperwork only is tracked here**
(acquisition log, hashes, notes). Firmware blobs and extracted filesystems are
git-ignored and never committed (vendor copyright + provenance hygiene).

- Procedure: `docs/track1-acquisition-runbook.md`
- Target rationale: `docs/track1-target-selection.md`
- Objective: CVE volume + portfolio strength (credit-only); coordinated
  disclosure per `docs/disclosure-policy.md`.

## Tracked paperwork here
- `acquisition-log.md` — **model DIR-816L Rev B locked; SoC confirmed from the image**
  (Realtek RTL819x, MIPS32 **big-endian**, Linux 2.6.30.9; SEAMA→LZMA kernel→squashfs4.0/LZMA).
  6 firmware releases (2.00B01 → 2.06.B09) + planned diff pairs.
- `hashes.txt` — SHA-256 of every acquired ZIP and inner `.bin`.
- `extract-and-diff.sh` — turnkey step-2 runner (Linux/WSL2): carves the rootfs by
  squashfs superblock, `sasquatch`-extracts, runs triage + `fw_diff.py` on an
  OLD→NEW pair. Default pair `205b02 → 206b01` (the silent-fix window).

## Acquisition status
Firmware acquired + fingerprinted 2026-09-10. Blobs live in `firmware/DIR-816L-REVB/`
(git-ignored). Next: run `extract-and-diff.sh` on an unrestricted host with
`sasquatch` (Realtek squashfs4.0/LZMA needs it — stock `unsquashfs` won't do).

Working dirs created at runtime (ignored): `work/`, `triage-out/`, `diff-out/`.
