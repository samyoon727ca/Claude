# Patch-Diff Methodology

The goal is not "what changed" — it is "what changed **that a bug hides behind**,
and which version holds it." Work in three passes; the script does passes 1-2.

## Pass 1 — File-level (structural) diff
`fw_diff.py` builds a `{path: sha256}` map for each rootfs and reports:
- **added** — new files in the newer version. New CGI/daemon = **new attack
  surface**; review these fresh even without a diff partner.
- **removed** — retired files. Rarely a bug source; note for completeness.
- **changed** — same path, different content = the diff candidates.

## Pass 2 — Per-binary security signal (the ranker)
For each changed ELF/script, `fw_diff.py` computes:
- **sink delta** — change in the count of distinct dangerous sinks referenced
  (`system`, `strcpy`, `sprintf`, vendor `*System` wrappers, ...). This is the
  strongest single signal.
- **symbol churn** — added/removed FUNC symbols (magnitude of code change; capped
  so a big feature refactor does not drown out a small security fix).
- **new "silent-fix" strings** — bounds/validation strings present in the newer
  binary but not the older (`invalid`, `too long`, `overflow`, `truncat`,
  `sanitiz`, `bounds`, ...). Their appearance is a classic patch tell.
- **reachability** — if a `--reachable` list (firmware-triage `services.txt`) is
  supplied, network-reachable binaries are boosted.

### Reading the direction (`likely_bug_side`)
| Signal | Meaning | Where the bug is |
|--------|---------|------------------|
| sink delta **< 0** (fewer sinks in new) | a dangerous call was removed/replaced | **OLD** version (silent fix) |
| new bounds/validation string in new | input handling was hardened | **OLD** version (silent fix) |
| sink delta **> 0** (more sinks in new) | a dangerous call was introduced | **NEW** version (regression) |
| heavy churn, no sink/string signal | feature change | lower priority |

The common, high-value case is a **silent fix**: the vendor quietly hardened a
function; the *older* release is a clean n-day to study and reproduce.

## Pass 3 — Function-level diff (manual / heavy tooling)
`fw_diff.py` finds the **binary** and says **why it looks security-relevant**. It
does **not** match functions — that needs a real diff engine. For each top
candidate, load both versions in Ghidra (headless) and diff with Diaphora or
BinDiff to pinpoint the exact changed function. See `ghidra-diff-notes.md`.

Then:
1. Open the identified function in the version `likely_bug_side` names.
2. Trace whether attacker-controlled input reaches the sink (taint path).
3. Reproduce in emulation (QEMU/FirmAE) before writing anything up.

## Cautions
- A sink delta is a **lead**. `strcpy`->`strncpy` can be cosmetic; confirm the
  dest-buffer/length relationship actually changed.
- Compiler/toolchain changes between releases add noise (inlining, reordered
  functions, changed symbol names). Weight *semantic* signals (sinks, strings)
  over raw churn.
- Stripped binaries yield no symbol delta; rely on sink/string deltas and let the
  function-level diff tool do structural matching.
