# CLAUDE.md — working notes for this repo

Embedded/firmware security portfolio. Start with [`README.md`](README.md) for the
map, [`docs/artifact-plan.md`](docs/artifact-plan.md) for the plan (including the
role-alignment / re-prioritization section), and
[`docs/NEXT-SESSION.md`](docs/NEXT-SESSION.md) for restart paths.

## Canonical environment: WSL (Ubuntu), not Git Bash

The tooling is Linux-native (binwalk, squashfs-tools, QEMU) and the scripts call
`python3` + `bash`. Run everything inside **WSL Ubuntu**, where the repo is at
`/mnt/c/Users/samyo/Desktop/Claude`:

```bash
wsl -e bash -lc 'cd /mnt/c/Users/samyo/Desktop/Claude && bash tools/run-checks.sh'
```

**Git Bash gotcha (Windows):** in Git Bash, `python3` resolves to the Microsoft
Store *App Execution Alias* stub, not a real interpreter — so `run-checks.sh` and
every `python3` script fail with "Python was not found". The real interpreter is
`C:\Users\samyo\AppData\Local\Programs\Python\Python312\python.exe` (invoke it as
`python`, or `py -3`). Prefer WSL; if you must use Git Bash, either call `python`
explicitly or disable the `python3` alias under Settings → Apps → Advanced app
settings → App execution aliases.

## Verification

`tools/run-checks.sh` is the deterministic gate (Python/shell parse, self-tests,
SVG/mermaid/link checks, funnel smoke test). A fully-provisioned WSL reports
**26 passed, 0 failed**. Deps needed to reach that (one-time, needs sudo):

```bash
sudo apt update && sudo apt install -y build-essential python3-dev python3-venv
python3 -m venv .venv && . .venv/bin/activate
pip install -r tools/mavlink-sectest/requirements.txt   # pymavlink
```

Note: on Python 3.14 there is no prebuilt `pymavlink` wheel, so pip compiles its
`dfindexer` C extension — that needs `build-essential` (provides `libc6-dev` /
`stdint.h`) and `python3-dev` (`Python.h`). `gcc` alone fails with
`fatal error: stdint.h: No such file or directory`. Re-activate the venv
(`. .venv/bin/activate`) in new shells before running the mavlink harness.

For the Track 1 firmware toolchain (binwalk, sasquatch, jefferson, ubi_reader,
QEMU), run `.claude/skills/firmware-triage/scripts/setup-tools.sh`.

## Running the pieces

```bash
# Assessment funnel (Track 3 skills)
.claude/skills/firmware-triage/scripts/triage.sh   <rootfs> triage-out/<ver>
.claude/skills/firmware-triage/scripts/sink_scan.py <rootfs> --out sinks.csv
.claude/skills/binary-diff/scripts/fw_diff.py       <old_rootfs> <new_rootfs> --out diff-out
.claude/skills/finding-to-vendor-report/scripts/make_report.py finding.json --validate
.claude/skills/finding-to-cve-writeup/scripts/make_cve.py       finding.json
.claude/skills/security-dataviz/scripts/chart.py bars --csv sinks.csv --label path --value score --out c.svg

# UAS harness (Track 1 / P5.1) — logic self-test needs no SITL
python3 tools/mavlink-sectest/mavlink_sectest.py --selftest
```

## Track 1 working state

Live research lives under `research/` (git-ignored blobs; paperwork committed) and
public writeups under `writeups/`. As of the last sync: DIR-816L Rev B was
acquired + fingerprinted (BE MIPS), and its first cross-version candidate
(`cgibin` HNAP SOAPAction command injection) **deduped as an n-day** — written up
as a case study, not a new CVE. A **Zyxel CPE** run is scaffolded under
`research/zyxel-cpe/` as the next shot at a *novel* finding. See
`research/dlink-rtl819x/acquisition-log.md` and the target-selection dossier.

## Guardrails (see [`docs/disclosure-policy.md`](docs/disclosure-policy.md))

- Unclassified, publicly-available targets only; no ITAR/EAR technical data.
- Firmware blobs are **never committed** (see `.gitignore`); record hashes in the
  acquisition log, not the binaries.
- Vulnerability work follows **coordinated disclosure**. Downloading vendor
  firmware and any outbound disclosure contact are user-confirmed steps.

## Doc-consistency note

Cert/clearance state appears in three places that must stay in sync:
`docs/qualification-map.md` §8, the `docs/artifact-plan.md` clearance/cert
section, and `docs/portfolio-blueprint.svg` cell 8. Current: **TS/SCI + SAP
eligibility (held)**, **Security+** and **CASP+ / SecurityX** held, **CISSP** in
progress (USAF-funded). The SVG banner cell lists certs only (`Sec+ · CASP+ ·
CISSP`); the markdown docs also carry the clearance line — decide deliberately
whether the public banner should surface clearance too.
