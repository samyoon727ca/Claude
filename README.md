# Embedded & Firmware Security Research

A working portfolio of firmware/embedded-security assessment, reusable analysis
tooling, and milestone-style security engineering documentation. Everything here
is built on **open-source, commercial, or academic targets** and is intended to
demonstrate transferable systems-security-engineering skills.

![Portfolio blueprint: three tracks, the reusable-skill funnel engine, and per-deliverable status](docs/portfolio-blueprint.svg)

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
docs/track2/
  secure-boot-root-of-trust.md  Reference explainer: RoT, verified/measured boot, keys, AT
  uas-autopilot-threat-model.md NIST SP 800-160 threat model (ArduPilot/PX4 + MAVLink)
  embedded-hardening-writeup.md Hardening a real Linux node -> 800-53/CMMC controls map
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
  finding-to-cve-writeup/     Skill: disclosed finding -> CVE JSON 5.1 + public writeup
    scripts/                  make_cve.py + sanitize_check.py (publish gate)
  security-dataviz/           Skill: analysis output -> briefing charts + diagrams
    scripts/                  chart.py (SVG) + diagram.py (mermaid)
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
- **finding-to-cve-writeup** — Turn a disclosed finding into a submittable CVE
  JSON 5.1 record (reusing the same finding file and CVSS score) and a
  methodology-forward public writeup, with a sanitization linter that blocks key
  material, unfilled placeholders, and weaponized payloads before publishing.
- **security-dataviz** — Briefing-grade, dependency-free visuals from analysis
  output: theme-aware SVG bar charts (ranked candidates; findings colored by CVSS
  band) and native mermaid diagrams (taint paths, disclosure timelines), plus a
  one-page briefing template. Defers palette/design theory to the `dataviz` skill.

## Status

Early build-out. The **firmware-triage** and **binary-diff** Skills plus the
planning / target-selection / disclosure docs are in place and the tooling is
verified end-to-end on synthetic fixtures. The **finding-to-vendor-report**
Skill (CVSS v3.1 scoring + PSIRT report assembly) is built and verified too.
Three Track 2 engineering docs are published in `docs/track2/`: a **secure-boot /
hardware root-of-trust explainer**, a **NIST SP 800-160 threat model** of the open
UAS autopilot stack, and an **embedded hardening writeup** mapping a real node's
controls to NIST 800-53 / CMMC. Remaining: the milestone + anti-tamper doc, and
the research writeups + UAS capstone, per the artifact plan.

## License

Tooling and documentation in this repository are MIT-licensed (see `LICENSE`).
