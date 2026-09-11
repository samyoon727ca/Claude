# Binary Diff Report — <VENDOR> <MODEL>: <VER_OLD> -> <VER_NEW>

| Field | Value |
|-------|-------|
| Device / model / HW rev | |
| Old version / SHA-256 | |
| New version / SHA-256 | |
| Arch / endianness | |
| Analyst / date | |

## 1. Summary
> 2-3 sentences: the most security-relevant change and which version holds the bug.

## 2. Structural changes
- **Added files (new attack surface):**
- **Removed files:**
- **Changed files of interest:**

## 3. Ranked candidates (from diff-candidates.csv)
| Rank | Binary | Score | likely_bug_side | sinkΔ | Notable new strings | Reachable |
|------|--------|-------|-----------------|-------|---------------------|-----------|
| 1 | | | | | | |

## 4. Function-level diff result
> For the top candidate(s): the exact changed function (name/address in each
> version), what changed (added bounds check, sink replaced, sanitization added),
> and therefore where the bug is.

## 5. Vulnerability hypothesis
> The taint path in the vulnerable version: source (untrusted input) -> ... -> sink.
> Preconditions (pre/post-auth, default-on?). Severity sketch (CVSS vector draft).

## 6. Reproduction plan / result
> Emulation setup (QEMU user-mode / FirmAE) and the observed crash/RCE, or the
> plan to get there. A diff + hypothesis is a lead; a reproduced result is a finding.

## 7. Next
> Hand-off to finding-to-vendor-report; disclosure per docs/disclosure-policy.md.
