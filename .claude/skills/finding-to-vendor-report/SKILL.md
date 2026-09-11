---
name: finding-to-vendor-report
description: >-
  Turn a confirmed vulnerability finding into a vendor-ready (PSIRT-ready)
  disclosure report with a correct CVSS v3.1 score, CWE mapping, reproduction
  steps, impact narrative, and suggested remediation. Use when a firmware/embedded
  (or any) vulnerability has been confirmed and reproduced and now needs to be
  written up for the vendor and/or a CVE request. Triggers: "write up this
  finding", "vendor report", "disclosure report", "PSIRT report", "CVSS score for
  this bug", "severity justification", "how bad is this vuln", "draft the
  disclosure email". Consumes the output of the firmware-triage / binary-diff
  skills; produces the report that feeds coordinated disclosure and the
  CVE-writeup skill. Automates drafting + scoring, not the analyst's judgment.
---

# Finding -> Vendor Report

Assemble a professional vulnerability report from a confirmed finding. The score
is computed with the exact CVSS v3.1 equations (matches NVD), and the report
structure matches how PSIRTs intake. This automates the **drafting and scoring**;
the analyst supplies the confirmed reproduction and reviews the report before it
is sent.

## When to use
- A vulnerability is **confirmed and reproduced** (in emulation or on an owned
  device) and needs a report for the vendor.
- You need a defensible CVSS v3.1 vector + severity, and a CWE.
- You need the coordinated-disclosure cover email.

## Do NOT use this to
- Score a bug you have not reproduced (a crash is not RCE — see the honesty
  guardrails in `reference/severity-and-impact.md`).
- Draft anything for an out-of-scope target (see `docs/disclosure-policy.md`).

## Workflow

1. **Score the finding.** Build the CVSS v3.1 vector using
   `reference/cvss-guide.md` (the router-specific metric guidance — AV:A vs AV:N,
   PR pre/post-auth, S:U vs S:C are where scores get disputed). Check it:
   ```
   scripts/cvss.py "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
   ```

2. **Fill the finding file.** Copy `templates/finding.json` and complete it:
   products + affected versions + firmware SHA-256, CWE, component, the vector
   from step 1, description, numbered repro steps, impact, remediation, discovery
   method, disclosure dates. Pick the CWE with `reference/severity-and-impact.md`.

3. **Validate + assemble the report:**
   ```
   scripts/make_report.py finding.json --validate           # check completeness + vector
   scripts/make_report.py finding.json --out report.md      # render the report
   ```
   `make_report.py` recomputes the CVSS score from the vector (so the report can
   never disagree with the calculator), resolves the CWE name, and builds the
   affected-products table and repro list.

4. **Write the two prose pieces the tool cannot.** The `description` and `impact`
   fields are yours: the taint path (source -> sink) and the 3-layer impact
   narrative (technical -> operational -> conditional reach). Attach the
   per-metric CVSS rationale from `reference/severity-and-impact.md`.

5. **Draft the outreach.** Render the cover email against the same finding:
   ```
   scripts/make_report.py finding.json --template templates/disclosure-email.md --out email.txt
   ```
   Find the security contact and send per `reference/disclosure-outreach.md`
   (security.txt -> PSIRT -> bounty platform). Keep detail embargoed.

6. **Hand off.** After a fix ships, the sanitized report feeds the
   finding-to-CVE-writeup skill for the public writeup.

## What "good" looks like
- The CVSS vector matches the reproduction exactly; AV/PR/S are defensible.
- Every repro step actually reproduces (the vendor will run them).
- Impact is legible to a non-specialist; conditional (WAN) reach is stated as a
  condition, not baked into the base score unless it is the default.
- For an SDK-level bug, the affected-products table enumerates the model fan-out.

## Bundled files
- `scripts/cvss.py` — CVSS v3.1 base calculator (self-test: `--selftest`).
- `scripts/make_report.py` — finding.json -> filled report (+ `--validate`).
- `templates/finding.json` — finding intake schema (worked example).
- `templates/vendor-report.md` — the report template.
- `templates/disclosure-email.md` — coordinated-disclosure cover email.
- `reference/cvss-guide.md` — router-specific CVSS scoring + archetype vectors.
- `reference/severity-and-impact.md` — severity rationale, CWE choice, impact narrative.
- `reference/disclosure-outreach.md` — finding the contact + disclosure process.
