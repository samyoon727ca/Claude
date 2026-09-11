# Escalating a Candidate to a Function-Level Diff

`fw_diff.py` hands you a ranked list of changed binaries and the likely
vulnerable version. This is how to pinpoint the exact changed function.

## Option A — Diaphora (open-source, recommended)
Diaphora diffs two IDBs/Ghidra programs by function heuristics and shows changed
functions side by side.

1. Import each version's binary into Ghidra (match the arch/endianness recorded
   during triage — e.g. MIPS 32 big-endian for RTL819x).
2. Export a Diaphora `.sqlite` for each (Diaphora's Ghidra plugin, or run it
   under IDA if that is what you have).
3. Diff old-vs-new. Focus on functions marked **partial match** with changed
   pseudocode — the silently-patched function is almost always here.
4. Cross-check against `fw_diff.py`'s `syms_added`/`syms_removed` for the same
   binary (a newly-added `validate()`-style helper is a strong pointer).

## Option B — Ghidra headless + BinExport/BinDiff
1. Headless-analyze both binaries:
   ```
   $GHIDRA/support/analyzeHeadless <projdir> diffproj \
       -import <binary> -postScript BinExportGhidra.java <out>.BinExport
   ```
2. Diff the two `.BinExport` files in BinDiff; sort by low similarity /
   changed-basic-block count.

## Reading the function diff
- **Added bounds check / length compare before a copy** -> the OLD version's
  copy was unbounded. Confirm the source is attacker-controlled.
- **`strcpy`/`sprintf` replaced by bounded form** -> classic overflow fix; find
  the buffer size and the max attacker-controlled length.
- **New sanitization of shell metacharacters before `system()`** -> command
  injection fix in the OLD version.
- **Nothing security-relevant** -> drop the candidate; move to the next row.

## Confirm before writing up
Prove the taint path in the vulnerable version, then reproduce in emulation
(QEMU user-mode for a single binary, FirmAE for a full-system boot). A diff
signal plus a Ghidra hypothesis is a *lead*; a reproduced crash/RCE is a finding.

## Never
- Never run the extracted vendor binary on your host — emulate it.
- Never publish a working full-chain exploit before the vendor has fixed it
  (see `docs/disclosure-policy.md`).
