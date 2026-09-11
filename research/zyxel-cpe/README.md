# Research — Zyxel CPE (Track 1, second target)

Working area for the second Track 1 assessment — rotating from D-Link (which
produced an **n-day** case study, CVE-2015-2051 class; see
[`writeups/dir-816l-hnap-soapaction-cmdinjection.md`](../../writeups/dir-816l-hnap-soapaction-cmdinjection.md))
to a **fresher, still-patched, credit-eligible** target.

**Paperwork only is tracked here** (acquisition log, hashes, notes). Firmware blobs
and extracted filesystems are git-ignored and never committed.

- Target rationale: [`docs/track1-target-selection.md`](../../docs/track1-target-selection.md)
  — Zyxel is the only candidate that is fresh + still-patched + active-CNA-credit.
- Procedure: [`docs/track1-acquisition-runbook.md`](../../docs/track1-acquisition-runbook.md)
  — the funnel is vendor-agnostic; the *extract* step is re-fingerprinted per target
  (Zyxel packaging differs from D-Link's SEAMA/squashfs-LZMA).
- Objective: a **novel** finding with a real CVE (Zyxel PSIRT is an active CNA; credit-only, no bounty).
- Next-run plan: [`target-notes.md`](target-notes.md).

Working dirs created at runtime (ignored): `work/`, `triage-out/`, `diff-out/`.
