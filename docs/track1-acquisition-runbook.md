# Track 1 — P1.1 Acquisition Runbook (D-Link RTL819x)

Turnkey procedure to acquire firmware, confirm the SoC, and run the triage +
diff funnel to a first candidate list. Objective per the reorder: **CVE volume +
portfolio strength**, credit-only, coordinated disclosure per
`docs/disclosure-policy.md`.

## Why this runs on your machine, not the remote sandbox
This session's environment is locked down: the network policy **blocks vendor
firmware hosts** (`support.dlink.com`, `legacyfiles.us.dlink.com`,
`tsd.dlink.com.tw` all return `403 CONNECT tunnel failed`), archive.org and
OpenWrt are blocked too, and squashfs extractors (`binwalk`, `sasquatch`,
`unsquashfs`) are not installed. Only GitHub + pypi/npm are reachable. Pulling
vendor firmware off a random GitHub mirror would violate the provenance rule in
our disclosure policy, so acquisition is done on an unrestricted host. Everything
*up to* acquisition (target lock, tooling, procedure, dedup discipline) is ready.

## 0. One-time toolchain setup
Run `.claude/skills/firmware-triage/scripts/setup-tools.sh` (installs binwalk +
sasquatch + jefferson + ubi_reader; QEMU for later emulation). Verify:
```
binwalk --help >/dev/null && unsquashfs -v && echo OK
```

## 1. Pick the model + enumerate firmware versions
Candidate bracket (all reported RTL819x/MIPS; **confirm from the image**, never
the spec sheet):

| Model | Notes | SDK / diff fuel |
|-------|-------|-----------------|
| **DIR-816L** (primary) | RTL8196/RTL819x, multiple hw revs (A1/A2/B1) | rtl819x-SDK v3.2/v3.4 lineage |
| **DIR-850L** (alt) | RTL819x on some revs; large firmware history | good version depth |
| **DIR-820L** (alt) | RTL819x; known-vuln-rich lineage (study/dedup carefully) | deep history |

Pull each model's **full firmware release list** from D-Link's support/legacy
site. Prefer **>=3 releases** spanning a security update (that update is the
silent-patch you diff). Record every version in the acquisition log.

## 2. Download + record provenance
For each release: download, then record SHA-256 in the log **before** touching it.
```
sha256sum <file>.bin | tee -a research/dlink-rtl819x/hashes.txt
```
Never commit the blob (`.gitignore` blocks `*.bin`, `firmware/`, `work/`).

## 3. Confirm the SoC (this selects/validates the model)
```
binwalk <newest>.bin                      # signatures, offsets, FS type
binwalk -e -M -C work/ <newest>.bin       # extract
# Confirm Realtek from the image:
grep -rao -E 'RTL8[0-9]{3}|Realtek|rtl819x|rlx|lx4' work/ | sort -u | head
file work/**/bin/busybox                  # arch + endianness (expect MIPS, note LE/BE)
```
Record: SoC string evidence, arch/endianness, filesystem type. If it is **not**
Realtek, drop to the next candidate (or, under decision (B), keep it only if it is
an actively-patched line worth the volume play).

## 4. Triage each version  (firmware-triage skill)
```
.claude/skills/firmware-triage/scripts/triage.sh work/<rootfs> triage-out/<ver>
.claude/skills/firmware-triage/scripts/sink_scan.py work/<rootfs> --out triage-out/<ver>/sinks.csv
```

## 5. Diff across versions  (binary-diff skill)
```
.claude/skills/binary-diff/scripts/fw_diff.py \
    work/<rootfs_OLD> work/<rootfs_NEW> --out diff-out \
    --reachable triage-out/<NEW>/services.txt
```
Read `diff-out/diff-candidates.csv`. Rows with `likely_bug_side = OLD (silent
fix)` + a sink/security-string delta are the silent-patch leads.

## 6. Dedup — the discipline that makes "CVE volume" real
A find only counts if it is **novel**. For each candidate, before any deep work:
1. Search NVD for the model + component (`site:nvd.nist.gov DIR-816L <function>`).
2. Check D-Link's security bulletins / SAP advisories for the same version range.
3. Check the RTL819x SDK CVEs (SDK bugs recur across many vendors/models).
4. If already assigned -> it becomes an **n-day study** (portfolio writeup), not a
   new CVE. If silent/unassigned -> proceed as a CVE candidate.
Log the verdict per candidate in the acquisition log.

## 7. Confirm + fan-out + disclose
- Confirm the taint path in Ghidra; reproduce in emulation (QEMU user-mode for a
  single binary, FirmAE for full-system). A diff signal is a lead; a reproduced
  crash/RCE is a finding.
- **Fan-out (the volume multiplier):** an SDK-level root cause -> grep the same
  vulnerable pattern across other D-Link RTL819x models -> each confirmed model is
  a distinct affected product (potentially distinct CVEs). Record the model list.
- Report to D-Link PSIRT; request CVE(s); publish sanitized writeup post-fix per
  `docs/disclosure-policy.md`.

## Output of P1.1
- `research/dlink-rtl819x/acquisition-log.md` filled: model, versions, hashes,
  confirmed SoC.
- `triage-out/<ver>/` and `diff-out/` (git-ignored working data).
- A shortlist of deduped, novel silent-patch candidates ready for Ghidra.
