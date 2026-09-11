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
  artifact-plan.md            Concrete plan across all three tracks (built/planned status)
  qualification-map.md        Every artifact -> a specific SSE competency + coverage snapshot
  portfolio-blueprint.svg     One-image end-state blueprint (the banner above)
  disclosure-policy.md        Coordinated disclosure + legal/ethics scope
  track1-target-selection.md  Target choice: rubric + freshness pass + CVE-volume reorder
  track1-acquisition-runbook.md  Turnkey P1.1: acquire -> confirm SoC -> triage -> diff -> dedup
  track2/
    secure-boot-root-of-trust.md                        RoT, verified/measured boot, keys, anti-tamper
    uas-autopilot-threat-model.md                       NIST SP 800-160 threat model (ArduPilot/PX4 + MAVLink)
    embedded-hardening-writeup.md                       Hardening a real Linux node -> 800-53/CMMC controls
    milestone-security-architecture-and-anti-tamper.md  SRR->PRR gates, MBSE, DoD anti-tamper
.claude/skills/                Reusable Claude Code Skills (the assessment funnel)
  firmware-triage/             extract -> inventory -> sink-scan  (triage.sh, sink_scan.py, setup-tools.sh)
  binary-diff/                 version-to-version diff -> ranked candidates  (fw_diff.py)
  finding-to-vendor-report/    confirmed finding -> CVSS-scored PSIRT report  (cvss.py, make_report.py)
  finding-to-cve-writeup/      disclosed finding -> CVE JSON 5.1 + writeup  (make_cve.py, sanitize_check.py)
  security-dataviz/            analysis output -> briefing charts + diagrams  (chart.py, diagram.py)
tools/
  mavlink-sectest/             MAVLink security test harness for ArduPilot/PX4 SITL (P5.1 T&E)
  run-checks.sh                Repo verification: lints, self-tests, SVG/mermaid/link checks
research/
  dlink-rtl819x/               First-target working area (paperwork only; blobs git-ignored)
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

A standalone tool supports the UAS capstone:

- **mavlink-sectest** (`tools/`) — a pymavlink test harness that runs the threat
  model's requirements as automated T&E against ArduPilot/PX4 SITL (signing,
  command injection, replay, cleartext telemetry, failsafe), benign and
  simulation-first. Its output feeds the report and dataviz skills.

## Status

The tooling funnel and the engineering-document set are **built and verified on
fixtures**; what remains is hands-on execution that needs an unrestricted host.

**Built**
- **Track 3 — six reusable Skills** (firmware-triage, binary-diff,
  finding-to-vendor-report, finding-to-cve-writeup, security-dataviz) plus the
  **mavlink-sectest** harness — the full acquire → triage → diff → report → CVE →
  visualize funnel, each verified end-to-end on synthetic fixtures.
- **Track 2 — four engineering documents**: the secure-boot / root-of-trust
  explainer, the NIST SP 800-160 UAS threat model, the 800-53 / CMMC hardening
  writeup, and the milestone security architecture + anti-tamper approach — giving
  SSE competencies 1–7 real artifact coverage (see the blueprint above).

**Remaining** (needs an unrestricted environment / owned hardware)
- **Track 1** — the live firmware run: acquire → confirm SoC → diff → confirm →
  disclose a real CVE (the only income path; the runbook is turnkey).
- **P5.1** — the hands-on UAS capstone assessment (threat model + test harness ready).

This session's environment blocks vendor firmware hosts and lacks squashfs
extractors, so Track 1 acquisition runs on your machine — see
[`docs/track1-acquisition-runbook.md`](docs/track1-acquisition-runbook.md).

## License

Tooling and documentation in this repository are MIT-licensed (see `LICENSE`).
