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
SVG/mermaid/link checks, funnel smoke test). A fully-provisioned WSL on a **clean
checkout** reports **26 passed, 0 failed**. (The SVG check scans the whole working
tree, so after a live firmware extraction the git-ignored `work/` tree adds its own
SVGs — the DrayTek rootfs contributes two `glyphicons-halflings-regular.svg`, giving
**28 passed**. The extra count is expected; only *failures* matter.) Deps needed to
reach that (one-time, needs sudo):

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
public writeups under `writeups/`. Three Track 1 runs so far:

- **Run 1 — D-Link DIR-816L Rev B** (BE MIPS): acquired + fingerprinted; first
  cross-version candidate (`cgibin` HNAP SOAPAction command injection) **deduped as
  an n-day** — written up as a case study, not a new CVE
  (`research/dlink-rtl819x/`, `writeups/dir-816l-hnap-soapaction-cmdinjection.md`).
- **Run 2 — Zyxel CPE**: **blocked at acquisition** — 2026 patched CPE firmware is
  ISP-gated, so the fix is not provenance-acquirable to diff (`research/zyxel-cpe/`).
  This exposed the acquisition-feasibility gate that drove the run-3 re-pick.
- **Run 3 — DrayTek Vigor300B** (ARM-LE, Comcerto): confirmed at the code level, then
  **deduped as an n-day — NOT novel.** Diffing the public `1.5.1.6 → 1.5.1.7` window found
  the silent hardening of a `download_ovpn` OS command injection in `mainfunction.cgi` — an
  incomplete-blocklist sanitizer *bypass* that runs as **root** (post-auth operator/admin).
  On live re-check (2026-09-18) the endpoint proved to be **CVE-2024-45890** (DrayTek
  Vigor**3900**, `mainfunction.cgi` `action=download_ovpn`, post-auth, CVSS 8.0, pub.
  2024-11-04); the earlier "no matching CVE / novel" claim was a **dedup miss** (the check
  was scoped to the `vigor300b_firmware` list; the CVE is filed under `vigor3900_firmware`).
  The 300B is not in that CVE's CPE list, so residual value is (a) a methodology case study
  — **published** at `writeups/draytek-vigor300b-download_ovpn-cmdinjection.md` — and (b) a
  CPE coverage-gap note to DrayTek/MITRE (affected-product extension, **not** a new CVE) —
  **drafted** as `research/draytek-vigor/vendor-report.md` + `disclosure-email.txt` (held;
  sending is a user-confirmed step). The new-CVE paperwork was retired: `finding.json`
  reclassified n-day, the held writeup stubbed, the RESERVED CVE record deleted. Ghidra
  decompile+disasm evidence under git-ignored `diff-out-dt/ghidra/`. **A genuinely new CVE
  could now only come from the fan-out to a still-supported, out-of-CPE, unpatched model.**
  See `research/draytek-vigor/finding-openvpn-cmdinjection.md` and `acquisition-log.md`.

See also the target-selection dossier (`docs/track1-target-selection.md`) — it carries
the 2026-09-14 re-pick rationale (acquisition-feasibility gate → DrayTek).

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
