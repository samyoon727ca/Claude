---
name: firmware-triage
description: >-
  Triage an embedded/IoT firmware image into a structured, ranked report before
  deep reversing. Use when the user has a firmware image (.bin/.trx/.chk/.img or
  an already-extracted rootfs) from a router, camera, or other embedded device
  and wants to unpack it, inventory sensitive files (keys, certs, credentials,
  SUID binaries, startup scripts), fingerprint binary architecture/endianness,
  and get a ranked list of binaries that call dangerous C sinks worth reversing.
  Triggers: "triage this firmware", "unpack firmware", "what's the attack surface
  of this image", "find the interesting binaries", "binwalk", "firmware analysis",
  "extract the filesystem". First stage of the firmware assessment funnel; its
  output feeds binary-diffing and vulnerability-report skills.
---

# Firmware Triage

Turn a raw firmware image (or extracted rootfs) into a structured triage report
that tells the analyst **where to look first**. This automates the funnel
(extract, inventory, sink-scan, rank); it does **not** automate judgment — the
analyst confirms bugs in Ghidra/emulation and writes the final assessment.

## When to use
- A new firmware image needs unpacking and first-pass attack-surface mapping.
- You want a ranked candidate list of binaries before opening Ghidra.
- You are comparing versions and need a per-version inventory to diff later.

## Scope guardrail (read first)
Only triage firmware that is in scope per `docs/disclosure-policy.md`: publicly
downloadable images or images from a device the user owns. Do not proceed on an
image whose provenance the user cannot state. Never commit the firmware blob or
extracted filesystem to git (see `.gitignore`).

## Prerequisites
- `binwalk` (extraction). Run `scripts/setup-tools.sh` once to install the full
  extraction toolchain (binwalk, squashfs-tools, jefferson, ubi_reader, QEMU). If
  `binwalk` is still missing, `scripts/triage.sh` prints guidance and inventories
  an already-extracted rootfs anyway.
- Standard binutils (`file`, `readelf`, `strings`, `find`) — used opportunistically.
- `scripts/sink_scan.py` needs only Python 3 stdlib; it uses `readelf` if present
  for accurate dynamic-symbol reads, else falls back to `strings`.

## Workflow

1. **Confirm scope + record provenance.** Note vendor, model, version, and
   SHA-256 of the image. Put these in the report header.

2. **Extract + inventory.** Run:
   ```
   scripts/triage.sh <firmware.bin|extracted_rootfs_dir> <output_dir>
   ```
   This extracts (binwalk) if given an image, then produces in `<output_dir>`:
   - `inventory.txt` — filesystem type, ELF arch/endianness histogram, version
     strings, and counts.
   - `sensitive.txt` — candidate keys, certs, `.htpasswd`/`passwd`/`shadow`,
     hardcoded-credential greps, SUID/SGID binaries, world-writable files.
   - `services.txt` — web servers, init/startup scripts, and network daemons
     (the reachable attack surface).
   - `binaries.txt` — every ELF with its arch/endianness (feeds the sink scan).

3. **Rank sinks.** Run:
   ```
   scripts/sink_scan.py <extracted_rootfs_dir> --out <output_dir>/sinks.csv
   ```
   Produces a ranked CSV: each binary scored by which dangerous sinks it imports
   (`system`, `popen`, `exec*`, `strcpy`, `sprintf`, `memcpy`, `gets`, ...) and,
   for scripts/CGI, command-injection patterns. Higher score = review sooner.
   See `reference/sink-catalog.md` for what each sink implies.

4. **Populate the report.** Copy `templates/triage-report.md`, fill it from the
   four inventory files + `sinks.csv`, and write the **analyst's first-look
   priorities**: the top 5-10 candidates and *why* (network-reachable + unsafe
   sink + parses untrusted input = top priority). Use
   `reference/triage-checklist.md` so nothing is skipped.

5. **Hand off.** The report's ranked list is the input to Ghidra review and, if
   diffing versions, to the binary-diff skill. Do not assert a vulnerability from
   triage signal alone — a `strcpy` xref is a *lead*, not a finding.

## What "good" looks like
- Every network-facing binary that handles untrusted input is on the ranked list.
- Sensitive-file findings (hardcoded creds, private keys, backdoor accounts) are
  called out explicitly even if they aren't "sinks."
- The report says what to reverse first and why, in one screen.

## Bundled files
- `scripts/triage.sh` — extraction + inventory.
- `scripts/sink_scan.py` — ranked dangerous-sink scan.
- `reference/triage-checklist.md` — the manual checklist the scripts implement.
- `reference/sink-catalog.md` — dangerous sinks and what each implies.
- `reference/binwalk-notes.md` — extraction gotchas (encrypted/obfuscated images,
  vendor headers, non-standard filesystems).
- `templates/triage-report.md` — output report template.
