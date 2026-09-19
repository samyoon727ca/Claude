# Next Session — Restart Paths

This round closed out **breadth**: every SSE competency (1–8) plus the systems-language
qual now has an artifact — the Track 3 skill funnel + the mavlink-sectest harness, the
Track 2 engineering-doc set (now including the FPGA security reference), the **P5.1 UAS
capstone** (with a measured signing before/after), the **P6.2** Rust MAVLink-signing module,
and the leadership brief. The **next round is depth** (see below); the one thing still gating
external validation is a genuinely new CVE from a live Track 1 run (Path A). This note is the
frictionless restart.

## 0. Confirm state first (30 seconds)
```
git checkout main                                   # tooling branches are merged
tools/run-checks.sh                                 # clean checkout: 27 passed, 0 failed
                                                    # (local work/ extraction adds SVGs -> 29; only failures matter)
```
Read [`docs/artifact-plan.md`](artifact-plan.md) for the plan and
[`docs/qualification-map.md`](qualification-map.md) for competency coverage.

## Next round — depth (recommended)
Breadth is done; the marginal hour now buys **depth**, not more artifacts. Two thrusts —
propose a plan, then pick one to execute.

**Thrust A — UAS capstone depth** (extend the find → build → prove arc; the infra already stands):
1. **GNSS spoofing (T2)** — the threat model's #1 risk (9.0) and untested. Inject a spoofed GPS
   position into ArduPilot SITL, test multi-sensor consistency + the failsafe response, and
   write it up like the [capstone](track2/uas-capstone-assessment.md). Most defense-relevant
   single addition.
2. **Telemetry encryption (T4)** — stand up an encrypted transport (WireGuard/DTLS) GCS↔companion,
   re-run `mavlink-sectest` through it, show telemetry is no longer cleartext: the *applied*
   control for the [hardening writeup](track2/uas-mavlink-hardening.md)'s T4 row.
3. **P6.2 → inline proxy** — make the Rust signing module enforce signing on the wire, proven
   end-to-end by the harness.

**Thrust B — hands-on FPGA** (convert [P6.1](track2/fpga-security-reference.md) from reference to demonstrated):
1. **Simulation (no hardware):** a security RTL core (AES-GCM / HMAC bitstream-auth checker / PUF
   model) in Verilog/VHDL with a Verilator or cocotb testbench + known-answer tests; wire its run
   into `tools/run-checks.sh` (guarded, like the gcc/cargo steps) if a toolchain is present.
2. **Hardware (if a board / ChipWhisperer is on hand):** a DPA power-analysis key-recovery lab
   (directly demonstrates the P6.1 side-channel threat), or bitstream encryption + secure boot
   on a real FPGA.

**Still the credibility frontier:** a genuinely **new CVE** from a fresh Track 1 target (Path A) —
the DrayTek 300B surface is fully CVE'd, so it's the other-model fan-out or a new device. No depth
work substitutes for one real new disclosure. **The next live run pivots this to the UAS / autonomy
domain (PX4 re-anchor + a ROS 2 / DDS novel-CVE hunt) — see
[`track1-uas-run-plan.md`](track1-uas-run-plan.md).**

Guardrails unchanged: WSL for the gate (keep it green), a new branch — never `main`, coordinated
disclosure / no committed blobs, the held DrayTek CVE-2024-45890 coverage-gap email stays HELD, and
keep the docs (README map, qualification-map, artifact-plan, this file) consistent on any status change.

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
> **Next action (updated 2026-09-18):** the DrayTek 300B novel-CVE path is **closed** — a
> secondary dedup found the whole `mainfunction.cgi` command-injection surface is an
> exhaustively-CVE'd family (CVE-2024-45884…45893, incl. `doOpenVPN`/`download_ovpn`). **The
> active priority is now Path B (P5.1 UAS capstone).** A DrayTek new CVE could only come from
> the same pattern on a still-supported, out-of-CPE, unpatched *other* Vigor model
> (background; needs downloads), or a fresh Track 1 target. The numbered steps below are the
> vendor-agnostic procedure for either.

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

## Path B — P5.1 UAS capstone (portfolio, no income) — COMPLETE
Goal: the hands-on autopilot assessment. Analytical foundation is already written:
[`docs/track2/uas-autopilot-threat-model.md`](track2/uas-autopilot-threat-model.md).

> **Status (2026-09-18): done.** SITL run + signing before/after complete — stock link
> **4 FAIL / 1 PASS** (T1/T4/T5 unmet as the threat model predicted); the signing-enabled
> re-run clears the T1/T5 cluster; the **P6.2** Rust signing module
> ([`../tools/mavlink-signing/`](../tools/mavlink-signing/SPEC.md), 7/7 cargo tests incl.
> pymavlink interop) gives the deterministic proof. Written up in
> [`track2/uas-capstone-assessment.md`](track2/uas-capstone-assessment.md) +
> [`track2/uas-mavlink-hardening.md`](track2/uas-mavlink-hardening.md), briefed in
> [`track2/uas-security-brief.html`](track2/uas-security-brief.html). **Next named gap = P6.1
> (FPGA).** The steps below reproduce the run.

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
- Next live run (UAS/autonomy): [`track1-uas-run-plan.md`](track1-uas-run-plan.md)
- Latest audit + consolidated roadmap: [`audit-2026-09-18.md`](audit-2026-09-18.md)
- Scope & ethics: [`docs/disclosure-policy.md`](disclosure-policy.md)
- Engineering docs: [`docs/track2/`](track2/)
- Reusable skills: `.claude/skills/`  ·  Tools: `tools/`
