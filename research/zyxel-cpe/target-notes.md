# Zyxel CPE — Next-Run Target Notes (Track 1, run 2)

**Why Zyxel (vs. D-Link run 1).** Per [`docs/track1-target-selection.md`](../../docs/track1-target-selection.md),
Zyxel is the only candidate that is **fresh + still-patched + not-yet-swarmed**, with
an **active CNA** (Zyxel PSIRT `security@zyxel.com.tw`, CNA since 2021). Credit-only
(no cash bounty), but a *novel* finding here earns a real CVE — unlike D-Link's EOL
line, which only yields n-day reproductions.

## Live surface to diff (as of 2026-09)
- **Zyxel advisory 2026-02-24** — null-pointer dereference + command injection across
  certain 4G LTE/5G NR CPE, DSL/Ethernet CPE, Fiber ONTs, Security Routers, and
  Wireless Extenders.
- **CVE-2026-1459** — *post-auth* OS command injection in the **TR-369 certificate-
  download CGI** of certain DSL/Ethernet CPE. Admin-authenticated; WAN off by default.
  Patches rolling out ~March 2026.

## Candidate model bracket — CONFIRM SoC FROM THE IMAGE (never the spec sheet)
Start from advisory models that have a public firmware ladder:
`EMG3525-T50B`, `EMG5523-T50B`, `VMG3625-T50B`, `VMG8623-T50B`, `DX5401-B1`.

**SoC caveat:** Zyxel DSL/Ethernet CPE mix **Realtek / Econet-Airoha (EN75xx) /
Broadcom**. Under target-selection decision **(B)** ("Realtek **or** the vendor's
actively-patched SOHO line"), these qualify even if not Realtek — but confirm the SoC
from the image and record it. A confirmed **Realtek RTL8xxx** model also fits the
MIPS-reversing specialization cleanly and is the preferred pick if available.

## Firmware acquisition
- Zyxel Download Library: https://www.zyxel.com/global/en/support/download (per model)
- Some model firmware folders on `ftp://ftp.zyxel.fr/`; `portal.myzyxel.com` for others.
- Pull **≥3 releases spanning the 2026 security patch**; record SHA-256 **before** analysis
  in [`acquisition-log.md`](acquisition-log.md) + a `hashes.txt` (same discipline as the D-Link run).

## Diff strategy — the novel-finding play
The prize is a **silent or incomplete fix**, not re-confirming the assigned CVE-2026-1459:
1. Diff pre-2026-patch vs 2026-patched firmware (extract → `fw_diff.py`).
2. Focus the changed CGIs **around** the patched area — the TR-369 cert-download CGI and
   any sibling CGIs touched in the same patch. **Incomplete-fix bugs adjacent to a known
   CVE are a common source of NEW CVEs.**
3. **Dedup every candidate** against NVD + Zyxel advisories before claiming novelty
   (runbook §6). Maps to CVE-2026-1459 → n-day; silent/unassigned → novel CVE candidate.

## Tooling note (don't blindly reuse the D-Link runner)
The funnel (`firmware-triage`, `binary-diff`, `finding-to-*`, `security-dataviz`) is
vendor-agnostic and reusable as-is. But `research/dlink-rtl819x/extract-and-diff.sh` is
**D-Link-specific** (hardcoded DIR-816L image names + a SEAMA/squashfs-LZMA carve). Zyxel
packaging will differ (likely different header/FS; DSL CPE often isn't SEAMA) — so
**re-fingerprint the image first** (`binwalk` + `sasquatch`/`jefferson`/`ubi_reader` as
the FS dictates) and write a Zyxel extract step, or generalize the runner, once the exact
container/FS is known. The Ghidra headless diff (`research/dlink-rtl819x/ghidra/`) is
reusable — just set the correct `-processor` for the confirmed arch/endianness.

## Disclosure (credit-only, active CNA)
Novel finding → `finding-to-vendor-report` (CVSS + PSIRT report) → Zyxel PSIRT
(`security@zyxel.com.tw`) → coordinated disclosure → `finding-to-cve-writeup` post-fix.
Handle personal COI/disclosure obligations per [`docs/disclosure-policy.md`](../../docs/disclosure-policy.md) first.
