# DrayTek Vigor — Target Notes (Track 1, run 3)

**Why DrayTek (vs. D-Link run 1, Zyxel run 2).** DrayTek is the only candidate that
clears the **acquisition-feasibility gate**: it publishes an open, browsable,
versioned firmware archive at `fw.draytek.com.tw` — *every* release including current
security patches — so the fix is provenance-acquirable and diffable. It is also an
active CNA with 2024–2026 CVEs, and its business CPE is less Mirai-swarmed than
consumer D-Link/TP-Link (novelty headroom). See
[`docs/track1-target-selection.md`](../../docs/track1-target-selection.md) §Re-pick.

## Primary model: Vigor300B (Linux CPE, `mainfunction.cgi` lineage)
Verified public archive (2026-09-14): index at
`https://fw.draytek.com.tw/Vigor300B/Firmware/` lists 13 versions (v1.0.8.2 →
v1.5.1.7), each a real ~31 MB ZIP. **Confirm SoC/arch from the image** (DrayTek Linux
CPE are MIPS/ARM — do not trust the spec sheet).

## The CVE-relevant chain (all public → diffable)
| Version | Status | Source URL (fw.draytek.com.tw/Vigor300B/Firmware/…) |
|---------|--------|------------------------------------------------------|
| v1.5.1.4 | Vulnerable — CVE-2024-12987 (`mainfunction.cgi` OS cmd injection) | `v1.5.1.4/Vigor300B_v1.5.1.4.zip` |
| v1.5.1.5 | Fix #1 | `v1.5.1.5/Vigor300B_v1.5.1.5.zip` |
| v1.5.1.6 | Still vulnerable per a Feb-2026 cmd-injection report | `v1.5.1.6/Vigor300B_v1.5.1.6.zip` |
| v1.5.1.7 | Latest (likely the Feb-2026 fix) — **freshest window** | `v1.5.1.7/Vigor300B_v1.5.1.7.zip` |

Pull **≥3 releases spanning a fix** (minimum `1.5.1.4`, `1.5.1.6`, `1.5.1.7`); record
SHA-256 **before** analysis in [`acquisition-log.md`](acquisition-log.md) + a
`hashes.txt`, same discipline as the D-Link run.

## Diff strategy — the novel-finding play
The prize is a **silent or incomplete fix**, not re-confirming assigned CVEs:
1. Diff across the public chain (extract → `fw_diff.py`), priority **`1.5.1.6 → 1.5.1.7`**
   (freshest), then `1.5.1.4 → 1.5.1.5` (the CVE-2024-12987 fix + any siblings fixed
   alongside it), then `1.5.1.5 → 1.5.1.6`.
2. Focus changed CGIs **around** the patched area — `mainfunction.cgi` and sibling
   CGIs/daemons touched in the same bump. **Incomplete-fix bugs adjacent to a known
   CVE are a common source of NEW CVEs.**
3. **Dedup every candidate** against NVD + DrayTek advisories before claiming novelty
   (runbook §6). Maps to CVE-2024-12987 / a 2026 CVE → n-day; silent/unassigned → novel.

## Tooling note (re-fingerprint; don't blind-reuse the D-Link runner)
The funnel (`firmware-triage`, `binary-diff`, `finding-to-*`, `security-dataviz`) is
vendor-agnostic and reusable as-is. But `research/dlink-rtl819x/extract-and-diff.sh` is
**D-Link-specific** (SEAMA + squashfs-LZMA carve). DrayTek `.zip` packaging differs
(typically a `.all`/`.rst` firmware payload; FS likely squashfs or cramfs — confirm) —
so **fingerprint the image first** (`binwalk`; then `sasquatch`/`unsquashfs` or the FS
extractor the image dictates) and write a DrayTek extract step, or generalize the
runner, once the exact container/FS is known. The Ghidra headless diff
(`research/dlink-rtl819x/ghidra/`) is reusable — set the correct `-processor` for the
confirmed arch/endianness.

## Disclosure (active CNA, coordinated)
Novel finding → `finding-to-vendor-report` (CVSS + PSIRT report) → DrayTek PSIRT /
security advisory contact → coordinated disclosure → `finding-to-cve-writeup` post-fix.
Handle personal COI/disclosure obligations per
[`docs/disclosure-policy.md`](../../docs/disclosure-policy.md) first.
