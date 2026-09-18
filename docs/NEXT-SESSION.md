# Next Session — Restart Paths

Everything buildable in a locked-down cloud sandbox is **done and verified**
(5 skills + the mavlink-sectest harness, 4 Track 2 docs, the briefing artifact,
the blueprint). What remains is **hands-on execution** that needs an unrestricted
host or owned/simulated hardware. This note is the frictionless restart.

## 0. Confirm state first (30 seconds)
```
git checkout main                                   # tooling branches are merged
tools/run-checks.sh                                 # clean checkout: 26 passed, 0 failed
                                                    # (local work/ extraction adds SVGs -> 28; only failures matter)
```
Read [`docs/artifact-plan.md`](artifact-plan.md) for the plan and
[`docs/qualification-map.md`](qualification-map.md) for competency coverage.

## Why these run locally, not in the cloud sandbox
The cloud environment's network policy blocks vendor firmware hosts (403) and
lacks squashfs extractors; SITL wants a real build. Both paths assume a normal
workstation (or an environment provisioned with a permissive network policy).

---

## Path A — Track 1 live firmware run (the income path)
Goal: acquire → confirm SoC → diff → confirm → disclose a **real CVE**. Only this
path pays. Full procedure: [`docs/track1-acquisition-runbook.md`](track1-acquisition-runbook.md).

> **Status (3 runs in):**
> - **Run 1 — D-Link DIR-816L Rev B:** funnel confirmed an unauth HNAP `SOAPAction`
>   command injection, dedup'd as an **n-day** (CVE-2015-2051 class); case study in
>   [`writeups/`](../writeups/dir-816l-hnap-soapaction-cmdinjection.md).
> - **Run 2 — Zyxel CPE:** **blocked at acquisition** — the 2026 patched CPE firmware is
>   ISP-gated, so the fix is not provenance-acquirable to diff. Notes:
>   [`research/zyxel-cpe/target-notes.md`](../research/zyxel-cpe/target-notes.md).
> - **Run 3 — DrayTek Vigor300B: confirmed at the code level, then deduped as an n-day.** A
>   `download_ovpn` OS command injection in `mainfunction.cgi` (incomplete-blocklist
>   sanitizer bypass, runs as **root**, post-auth) — confirmed via Ghidra decompile + disasm,
>   but on live re-check (2026-09-18) it is **CVE-2024-45890** (same bug on the sibling
>   Vigor3900); the initial "no matching CVE" was a dedup miss (scoped to the 300B CVE list).
>   **Not a new CVE.** What remains: a methodology case study, an optional CPE coverage-gap
>   note, and the fan-out to a still-supported/unpatched model (the only new-CVE path). See
>   [`research/draytek-vigor/finding-openvpn-cmdinjection.md`](../research/draytek-vigor/finding-openvpn-cmdinjection.md).
>
> **Next action on this path = the run-3 fan-out** (grep the `download_ovpn` /
> `create_client_conf.sh` pattern across other Vigor models for a still-supported,
> out-of-CPE, unpatched one — the only remaining new-CVE path) plus a case-study writeup.
> A fresh target is equally reasonable now that run 3 is an n-day. The numbered steps below
> are the vendor-agnostic procedure.

1. **Tools:** `.claude/skills/firmware-triage/scripts/setup-tools.sh`
   (binwalk, squashfs-tools, jefferson, ubi_reader, QEMU).
2. **Acquire** 2–3 firmware versions of the locked target — D-Link RTL819x,
   **DIR-816L** primary (see [`docs/track1-target-selection.md`](track1-target-selection.md));
   record SHA-256 in [`research/dlink-rtl819x/acquisition-log.md`](../research/dlink-rtl819x/acquisition-log.md).
3. **Confirm the SoC from the image** (binwalk + bootloader strings) — do not
   trust spec sheets.
4. **Triage** each version → **diff** across versions:
   ```
   .claude/skills/firmware-triage/scripts/triage.sh  <rootfs> triage-out/<ver>
   .claude/skills/binary-diff/scripts/fw_diff.py      <old_rootfs> <new_rootfs> --out diff-out \
       --reachable triage-out/<new>/services.txt
   ```
5. **Confirm** a silent-patch candidate in Ghidra; reproduce in emulation
   (QEMU/FirmAE). **Dedup against NVD before claiming novelty** (runbook §6) — and search
   **every sibling model that shares the codebase, not just the target's own CPE list**
   (the run-3 lesson: the `download_ovpn` bug was already CVE-2024-45890, filed under the
   Vigor3900, and a 300B-scoped search missed it).
6. **Report + disclose:** `finding.json` → `finding-to-vendor-report` (CVSS +
   PSIRT report) → coordinated disclosure → `finding-to-cve-writeup` (public
   writeup + CVE JSON). Chart findings with `security-dataviz`.
> Disclosure obligation: before publishing under your name or accepting any
> payout, handle personal disclosure/COI reporting first (disclosure-policy §5).

---

## Path B — P5.1 UAS capstone (portfolio, no income)
Goal: the hands-on autopilot assessment. Analytical foundation is already written:
[`docs/track2/uas-autopilot-threat-model.md`](track2/uas-autopilot-threat-model.md).

1. **Install + simulate** (open source):
   ```
   pip install -r tools/mavlink-sectest/requirements.txt
   # ArduPilot: Tools/autotest/sim_vehicle.py -v ArduCopter --out=udp:127.0.0.1:14550
   # or PX4:    make px4_sitl jmavsim
   ```
2. **Run the T&E harness** against SITL:
   ```
   python3 tools/mavlink-sectest/mavlink_sectest.py --connect udp:127.0.0.1:14550 \
       --out report.json --csv findings.csv
   ```
   (Verify the harness itself anytime with `--selftest`, no SITL needed.)
3. **Visualize + write up:** `findings.csv` →
   `security-dataviz/scripts/chart.py` (severity chart); a confirmed finding →
   `finding-to-vendor-report`. Fold results into the capstone assessment,
   structured by the threat model and the milestone architecture doc.

---

## Pointers
- Front door / repo map: [`README.md`](../README.md)
- Scope & ethics: [`docs/disclosure-policy.md`](disclosure-policy.md)
- Engineering docs: [`docs/track2/`](track2/)
- Reusable skills: `.claude/skills/`  ·  Tools: `tools/`
