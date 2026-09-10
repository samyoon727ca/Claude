# Embedded & Firmware Security Research

A working portfolio of firmware/embedded-security assessment, reusable analysis
tooling, and milestone-style security engineering documentation. Everything here
is built on **open-source, commercial, or academic targets** and is intended to
demonstrate transferable systems-security-engineering skills.

> **Scope & ethics.** UNCLASSIFIED, publicly-available targets only. All firmware
> is acquired from vendors' public support sites. No proprietary, classified, or
> export-controlled (ITAR/EAR) technical data is reproduced or generated here.
> Vulnerability research follows coordinated disclosure — see
> [`docs/disclosure-policy.md`](docs/disclosure-policy.md). Firmware binaries are
> never redistributed in this repository (see `.gitignore`).

## What's here

This repo is organized around three tracks:

| Track | Focus | What lands here |
|-------|-------|-----------------|
| **1 — Vulnerability research** | Commercial embedded devices (SOHO routers) | Sanitized public writeups, CVEs, and the tooling that produced them |
| **2 — Security engineering docs** | Open embedded platforms | Threat models, hardening writeups, architecture + anti-tamper docs in USG methodology language |
| **3 — Reusable tooling** | Repeatable workflows | Claude Code Skills, Ghidra scripts, emulation configs, chart/diagram generators |

The full deliverable plan, with each artifact mapped to a named Systems Security
Engineer competency, is in [`docs/artifact-plan.md`](docs/artifact-plan.md) and
[`docs/qualification-map.md`](docs/qualification-map.md).

## Repository map

```
docs/
  artifact-plan.md            Concrete plan across all three tracks
  qualification-map.md        Every artifact -> a specific SSE competency
  track1-target-selection.md  Target choice: rubric + freshness pass + CVE-volume reorder
  track1-acquisition-runbook.md  Turnkey P1.1: acquire -> confirm SoC -> triage -> diff -> dedup
  disclosure-policy.md        Coordinated disclosure + legal/ethics scope
research/
  dlink-rtl819x/              First-target working area (paperwork only; blobs git-ignored)
.claude/skills/
  firmware-triage/            Skill: acquire -> unpack -> inventory -> first-pass sink scan
    scripts/                  triage.sh + sink_scan.py (no exotic deps)
  binary-diff/                Skill: diff two firmware versions -> ranked candidate list
    scripts/                  fw_diff.py (file/symbol/sink/string delta + ranker)
  firmware-triage/scripts/setup-tools.sh   One-command extraction-toolchain install
  finding-to-vendor-report/   Skill: confirmed finding -> CVSS-scored PSIRT report
    scripts/                  cvss.py (v3.1, NVD-verified) + make_report.py
```

## Reusable tooling (Claude Code Skills)

These Skills encode a repeatable firmware-assessment funnel so each analysis is
faster and more consistent than the last. They are plain, auditable
files — Markdown instructions plus small scripts with no exotic dependencies.

- **firmware-triage** — Turn a firmware image into a structured triage report:
  extract the filesystem, inventory sensitive files (keys/creds/certs/SUID),
  fingerprint binary architecture and endianness, and produce a ranked list of
  binaries that call dangerous C sinks. First stage of the funnel.
- **binary-diff** — Diff an older and newer firmware version to surface
  silently-patched or newly-introduced bugs: added/removed/changed files,
  dangerous-sink deltas per binary, "silent-fix" error-string tells, and a ranked
  candidate list that names which version likely holds the bug (points Ghidra/
  Diaphora at the right function). Vendor-agnostic; consumes triage output.
- **finding-to-vendor-report** — Turn a confirmed finding into a PSIRT-ready
  report: a CVSS v3.1 calculator (verified against NVD vectors), CWE mapping, a
  report assembler that fills the template from a finding file, and a
  coordinated-disclosure cover email. Automates scoring + drafting, not judgment.

## Status

Early build-out. The **firmware-triage** and **binary-diff** Skills plus the
planning / target-selection / disclosure docs are in place and the tooling is
verified end-to-end on synthetic fixtures. The **finding-to-vendor-report**
Skill (CVSS v3.1 scoring + PSIRT report assembly) is built and verified too.
Remaining Skills (finding-to-CVE-writeup, data-visualization) and the research
writeups follow the artifact plan.

## License

Tooling and documentation in this repository are MIT-licensed (see `LICENSE`).
