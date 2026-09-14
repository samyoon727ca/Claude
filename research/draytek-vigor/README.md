# Research — DrayTek Vigor (Track 1, third target)

Working area for the third Track 1 assessment — rotating to a target that clears the
**acquisition-feasibility gate** the first two runs exposed: the *patched* firmware
must be publicly downloadable to diff the fix under our provenance rule.

- D-Link (run 1): public but EOL/saturated → **n-day** case study
  ([`writeups/dir-816l-hnap-soapaction-cmdinjection.md`](../../writeups/dir-816l-hnap-soapaction-cmdinjection.md)).
- Zyxel (run 2): fresh but recent CPE firmware is **ISP-gated** → 2026 fix not
  acquirable, blocked at acquisition ([`../zyxel-cpe/`](../zyxel-cpe/)).
- **DrayTek (run 3): fresh + fully public archive + active CNA + less-swarmed.**

**Paperwork only is tracked here** (acquisition log, hashes, notes). Firmware blobs
and extracted filesystems are git-ignored and never committed.

- Target rationale: [`docs/track1-target-selection.md`](../../docs/track1-target-selection.md)
  — see the 2026-09-14 re-pick (acquisition-feasibility gate → DrayTek).
- Procedure: [`docs/track1-acquisition-runbook.md`](../../docs/track1-acquisition-runbook.md)
  — the funnel is vendor-agnostic; the *extract* step is re-fingerprinted per target
  (DrayTek packaging differs from D-Link's SEAMA/squashfs-LZMA).
- Objective: a **novel** finding with a real CVE (DrayTek is an active CNA; coordinated
  disclosure per [`docs/disclosure-policy.md`](../../docs/disclosure-policy.md)).
- Plan + diff strategy: [`target-notes.md`](target-notes.md).

Working dirs created at runtime (ignored): `work/`, `triage-out/`, `diff-out/`.
