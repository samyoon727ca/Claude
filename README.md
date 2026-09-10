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
  track1-target-selection.md  How the first research target was chosen (rubric + shortlist)
  disclosure-policy.md        Coordinated disclosure + legal/ethics scope
.claude/skills/
  firmware-triage/            Skill: acquire -> unpack -> inventory -> first-pass sink scan
    SKILL.md
    scripts/                  Runnable triage.sh + sink_scan.py (no exotic deps)
    reference/                Triage checklist, unsafe-sink catalog, binwalk notes
    templates/                Triage-report output template
```

## Reusable tooling (Claude Code Skills)

These Skills encode a repeatable firmware-assessment funnel so each analysis is
faster and more consistent than the last. They are plain, auditable
files — Markdown instructions plus small scripts with no exotic dependencies.

- **firmware-triage** — Turn a firmware image into a structured triage report:
  extract the filesystem, inventory sensitive files (keys/creds/certs/SUID),
  fingerprint binary architecture and endianness, and produce a ranked list of
  binaries that call dangerous C sinks. This is the first stage of the funnel;
  binary-diffing and report-generation Skills build on its output.

## Status

Early build-out. The triage Skill and the planning/selection/disclosure docs are
in place; research writeups and additional Skills (binary-diff-to-candidate-list,
finding-to-report, data-visualization) follow the sequence in the artifact plan.

## License

Tooling and documentation in this repository are MIT-licensed (see `LICENSE`).
