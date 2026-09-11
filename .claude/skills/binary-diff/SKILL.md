---
name: binary-diff
description: >-
  Diff two firmware versions to find silently-patched or newly-introduced bugs,
  producing a ranked candidate list of which binaries/functions to reverse and
  which version likely holds the bug. Use when the user has two extracted rootfs
  trees (an older and a newer firmware release of the same device) and wants to
  know what changed in a security-relevant way: added/removed/changed files,
  dangerous-sink deltas per binary, new error-string "silent fix" tells, and a
  prioritized list pointing to Ghidra/Diaphora. Triggers: "diff these firmware
  versions", "what changed between v1 and v2", "find the silent patch", "binary
  diff", "patch diffing", "n-day", "which version has the bug". Vendor-agnostic;
  consumes firmware-triage output and feeds vulnerability-report writing.
---

# Binary Diff (version-to-version candidate list)

Compare an **older** and a **newer** extracted firmware rootfs to surface the
security-relevant changes, then rank them so the analyst knows exactly where to
point a heavy diff tool (Ghidra + Diaphora/BinDiff). This is the
"binary-diff-to-candidate-list" stage of the funnel. It automates *finding the
changed surface*; it does **not** decide whether a change is a vulnerability —
the analyst confirms that in Ghidra and reproduces in emulation.

## When to use
- Two firmware versions of the same device are extracted and you want the diff.
- You suspect a **silent security patch** and want to locate the fixed function
  (the bug then lives in the *older* version — a clean, low-risk n-day to study).
- You want to catch a **regression** (a sink newly introduced in the newer version).

## Core idea: read the direction of the change
- **Dangerous-sink count went DOWN in the newer binary** (e.g. `strcpy`->`strncpy`,
  a `system()` call removed) -> likely a **silent fix**; the bug is in the OLDER version.
- **A new bounds/validation error string appeared** ("invalid length", "too long",
  "malformed") -> same signal: something was hardened; the bug is in the OLDER version.
- **Dangerous-sink count went UP in the newer binary** -> possible **regression**;
  the bug may be in the NEWER version.
- A changed binary with heavy function churn but no sink/string signal is lower
  priority (feature change, not obviously security).

## Prerequisites
- Two extracted rootfs directories (use the `firmware-triage` skill first on each;
  its `services.txt` also feeds the `--reachable` boost below).
- `readelf` if present (accurate symbol deltas); the script falls back to a
  string-scrape when it is absent. Python 3 stdlib only otherwise.

## Workflow

1. **Triage both versions** with `firmware-triage` so you have per-version
   inventories and the reachable-service list.

2. **Run the diff:**
   ```
   scripts/fw_diff.py <rootfs_OLD> <rootfs_NEW> --out diff-out \
       [--reachable diff-out-or-triage/services.txt]
   ```
   Produces in `diff-out/`:
   - `added.txt` / `removed.txt` — files that appeared/disappeared (new CGI, new
     daemon = new attack surface; removed binary = retired surface).
   - `changed.txt` — files present in both with different content.
   - `diff-candidates.csv` — ranked: `path, kind, score, likely_bug_side,
     sink_delta, syms_added, syms_removed, notable_new_strings, reachable`.

3. **Read the ranked list.** Top rows are changed, reachable binaries with a
   sink or security-string delta. `likely_bug_side` tells you which version to
   open first.

4. **Escalate the top candidates to a real function diff.** `fw_diff.py` finds
   *which binary* changed and *why it looks security-relevant*; it does not do
   function-level matching. For each top candidate, run Ghidra headless on both
   versions and diff with Diaphora (or BinDiff) to pinpoint the changed function.
   See `reference/ghidra-diff-notes.md`.

5. **Confirm + write up.** Prove the bug in the identified version (Ghidra taint +
   emulation), then hand to the finding-to-report / CVE-writeup skills. Populate
   `templates/diff-report.md`.

## What "good" looks like
- Every silently-patched function is reachable from the ranked candidate list.
- New CGI/daemon files (fresh attack surface) are called out from `added.txt`.
- The report names the target function, the likely-vulnerable version, and the
  taint hypothesis — not just "these files changed".

## Bundled files
- `scripts/fw_diff.py` — the file/symbol/sink/string diff engine + ranker.
- `reference/diff-method.md` — the full methodology and how to read the signals.
- `reference/ghidra-diff-notes.md` — escalating a candidate to Ghidra + Diaphora/BinDiff.
- `templates/diff-report.md` — output report template.
