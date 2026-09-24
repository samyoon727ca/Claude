# Phase 0 — UAS/Autonomy Known-Territory Map

*The dedup gate for [Run 4](../../docs/track1-uas-run-plan.md). Before any deep RE in
Phase 1 (PX4 re-anchor) or Phase 2 (DDS novel-CVE hunt), a candidate finding is checked
against this map so effort aims only at **unclaimed** surface. Built to answer one
question per layer: **is this already CVE'd / published (cite it) or genuinely
under-reviewed (hunt it)?***

> **Status: LIVE MAP — swept 2026-09-21.** This is working-area paperwork
> (`research/uas-autonomy/`; blobs git-ignored per `.gitignore`). Re-run the sweep before
> each candidate goes deep — the landscape moves (the 2026 PX4 cluster below all landed
> this year). Sources in §7; every claim is dated and linked.

## 1. Method & scope

Swept **NVD / OpenCVE / CISA ICS advisories / GitHub Security Advisories / vendor release
notes / arXiv + ACM** for: `PX4/PX4-Autopilot`, `ArduPilot/ardupilot`,
`eProsima/Fast-DDS`, `eProsima/Fast-CDR`, `eProsima/Micro-XRCE-DDS(-Agent)`, `ros2`,
`SROS2 / DDS-Security`. Verdicts are one of:

- **MINED** — obvious surface already CVE'd/published → **cite, do not claim novelty.**
- **PARTIAL** — some coverage; logic/edge cases may remain → hunt with a specific angle.
- **THIN** — little public coverage → **most plausible novel-CVE headroom.**

## 2. Known-territory by layer

### 2.1 PX4 MAVLink — link auth + message parsing → **MINED (2026 cluster)**
| CVE | What | Note |
|-----|------|------|
| **CVE-2026-1579** | MAVLink 2 signing off (default) ⇒ unauthenticated `SERIAL_CONTROL` = interactive shell ⇒ RCE. CWE-306. **CVSS 3.1 9.8 / 4.0 9.3.** Pub 2026-03-31; **CISA ICSA-26-090-02**. Affects PX4 **v1.16.0 SITL**. | **The T1/T5 anchor.** Same class as the [capstone](../../docs/track2/uas-capstone-assessment.md) signing/`cmd_injection` findings — Phase 1 **cites & reproduces**, never claims. |
| CVE-2026-32743 | Stack buffer overflow in `MavlinkLogHandler`, via MAVLink log requests | MAVLink parsing actively fuzzed |
| CVE-2026-32724 | Heap use-after-free in `MavlinkShell::available()` (RX thread vs telemetry-sender race) | Shell/threading surface covered |
| CVE-2026-86097 | NULL-ptr deref in `param_set_default_file()` / `param_set_backup_file()` (through **1.17.0**) → crash | Param surface covered |
| CVE-2026-84698 | Heap buffer overflow in `sd_bench` (CVSS 6.5) | Command surface covered |

**Verdict:** the PX4 MAVLink link-auth, parser, shell, and param surfaces are being
actively fuzzed and CVE'd *through 2026*. **Low novel headroom** on the obvious MAVLink
surface. This is exactly why Phase 1 is framed as reproduce-and-cite (zero dedup risk),
not discovery.

### 2.2 Fast-DDS core RTPS / CDR wire parsing → **MINED (memory-safety DoS)**
| CVE | What |
|-----|------|
| CVE-2024-28231 | DATA submessage handling → heap overflow → remote process kill |
| CVE-2024-30258 | Malformed RTPS ⇒ crash on `pthread` create (DoS) |
| CVE-2024-30259 | Malformed RTPS ⇒ heap buffer overflow on subscriber (DoS) |
| CVE-2023-39945/39946/39948 | fastcdr `BadParamException` uncaught; `PID_PROPERTY_LIST` crafted-CDR heap overflow; remote crash |
| CVE-2025-62603 | Parser reads whole `DataHolderSeq` (not a minimal peek) ⇒ OOM out-of-bounds read (CVSS 7.5) |

**Verdict:** the "malformed RTPS/CDR ⇒ crash/DoS" shape is **heavily mined** across 2023–2025.
**High n-day risk** — deprioritize as a novelty bet unless a *genuinely new* code path is
identified through the gate.

### 2.3 DDS-Security / SROS2 — auth, permissions, governance → **PARTIAL**
| Source | What |
|--------|------|
| **"On the (In)Security of Secure ROS 2"**, ACM CCS 2022 | Formal verification found **4** SROS2 vulns (unauthorized permissions / info theft); acknowledged by ROS 2 and **fixed** in latest SROS2 |
| Alias Robotics (cited by CISA) | ~**15** vulns across the top-6 DDS implementations; open-source detection tooling contributed to SROS2 |
| CVE-2025-62599 | Fast-DDS **security-mode** SPDP: tampering the length field in `readPropertySeq` of `PID_IDENTITY_TOKEN` / `PID_PERMISSION_TOKEN` ⇒ integer overflow ⇒ OOM |

**Verdict:** the SROS2 permissions/governance *logic* had a formal-methods pass (4 found,
fixed) — not virgin, but **implementation-specific policy/handshake edge cases** still
yield bugs (2025-62599 in the security-mode token parser). Hunt with a *specific* angle
(a particular impl's governance/permissions parser, a cross-impl policy mismatch), not a
generic "is SROS2 secure?".

### 2.4 micro-XRCE-DDS Agent — PX4 `uXRCE-DDS` bridge → **THIN (best headroom)**
| CVE | What |
|-----|------|
| CVE-2025-63547 | Crafted **MTU length** field ⇒ DoS (CVSS 7.5), Agent v3.0.1 |
| CVE-2025-63548 | Non-valid value in **any Boolean field** ⇒ improper validation ⇒ internal exception ⇒ resource exhaustion (DoS, CVSS 7.5), Agent v3.0.1 |

**Verdict:** **only two public CVEs, both simple field-validation DoS.** This is the
**least-audited layer** and the plan's primary novel-CVE target. The two knowns imply the
XRCE input-validation surface is shallowly tested; untouched publicly: **deeper XRCE
submessage parsing, the client↔agent trust boundary / session & privilege handling, and
the PX4-specific integration seam** (how PX4 configures and exposes the Agent). This is
where Phase 2 should aim first.

### 2.5 ArduPilot → **PARTIAL (active academic RE) — cross-validator, not the bet**
- **arXiv 2512.01164** — *Reverse Engineering and Control-Aware Security Analysis of the
  ArduPilot UAV Framework* — active, published RE-for-security. Plus a broad MAVLink
  academic corpus (MAVSec, refined session-type MAVLink monitors, etc.).

**Verdict:** ArduPilot security RE is being actively published ⇒ keep ArduPilot as the
**cross-stack validation** target (demonstrate a weakness+fix on both stacks), **not** the
novelty bet. Matches the Run 4 licensing rationale (PX4 BSD-3 is the primary/build stack).

## 3. Where the novel-CVE headroom actually is (Phase 2 aim, ranked)

1. **micro-XRCE-DDS Agent — beyond field-validation DoS (§2.4).** Deeper XRCE parsing,
   session/privilege handling, client↔agent trust boundary. Thinnest coverage; newest code.
2. **PX4 ↔ uXRCE-DDS integration seam.** The Agent-in-isolation has 2 CVEs; the *PX4
   configuration* of the bridge (topics exposed, privilege inheritance ROS 2 → flight
   stack) is essentially untested publicly and is the most Lattice-flavored surface.
3. **DDS-Security implementation policy/handshake edge cases (§2.3).** Specific-impl
   governance/permissions parsing or a cross-impl policy mismatch — not generic SROS2.
4. *(De-prioritized)* Fast-DDS core RTPS/CDR memory-safety DoS — mined (§2.2); pursue only
   a demonstrably new code path.

## 4. Phase 1 dedup citations (keep the existing UAS work clean)

The [capstone](../../docs/track2/uas-capstone-assessment.md),
[threat model](../../docs/track2/uas-autopilot-threat-model.md), and
[brief](../../docs/track2/uas-security-brief.html) must **cite** these so the T1/T5 story
reads as reproduce-and-anchor, not implicit discovery:
- **CVE-2026-1579** — the T1/T5 signing/injection anchor (severity = CVSS 9.8).
- The 2026 PX4 MAVLink cluster (32743 / 32724 / 86097 / 84698) — evidence the MAVLink
  surface is actively CVE'd, i.e. the *reason* the capstone frames itself as T&E of a
  known-weak default, not a new bug.
- The [GNSS spoofing plan](../../docs/track2/uas-gnss-spoofing-test-plan.md) targets **T2
  (position integrity)** — *not* covered by 1579 or the cluster above, so it stays
  **dedup-clean** as depth work. Confirm no GNSS/EKF-specific PX4/ArduPilot CVE lands on
  the same claim before writing it up.

## 5. Disclosure channels (confirm before any outbound — do not send yet)

- **PX4 / Dronecode:** security policy + GitHub Security Advisories on `PX4/PX4-Autopilot`;
  hardening guidance at `docs.px4.io/main/en/mavlink/security_hardening`.
- **eProsima (Fast-DDS / Fast-CDR / Micro-XRCE-DDS):** repo `SECURITY.md` / GHSA advisory
  process on the respective GitHub repos.
- Per [`disclosure-policy.md`](../../docs/disclosure-policy.md) §5, personal COI /
  outside-activity reporting precedes any outbound contact; coordinated disclosure only.

## 6. The dedup gate (reusable — every candidate passes this before deep time)

1. Exact-match the component + code path against **NVD + OpenCVE + GHSA** (both the library
   repo *and* every downstream that vendors it — the run-3 lesson: search siblings, not just
   the target's own CPE list).
2. Search **CISA ICS advisories** and vendor release notes for a silent fix.
3. Search **arXiv / ACM / vendor blogs** (Alias Robotics, ROS 2 security WG) for a published
   (non-CVE) disclosure of the same class.
4. Classify: **MINED** (cite) / **PARTIAL** (hunt with a named angle) / **THIN** (hunt).
5. Only **THIN**/angled-**PARTIAL** candidates earn deep RE time.

## 7. Sources (swept 2026-09-21)

- CVE-2026-1579 (PX4 MAVLink → SERIAL_CONTROL RCE): <https://app.opencve.io/cve/CVE-2026-1579> · CISA ICSA-26-090-02: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-090-02>
- PX4 CVE list (OpenCVE): <https://app.opencve.io/cve/?product=px4-autopilot&vendor=px4> — incl. CVE-2026-32743, CVE-2026-32724, CVE-2026-86097, CVE-2026-84698
- PX4 security hardening guide: <https://docs.px4.io/main/en/mavlink/security_hardening>
- Fast-DDS CVE list (Vulners): <https://vulners.com/search/vendors/eprosima/products/fast%20dds> — incl. CVE-2024-28231/30258/30259, CVE-2023-39945/39946/39948, CVE-2025-62603/62599
- Micro-XRCE-DDS Agent CVEs: <https://app.opencve.io/cve/?product=micro-xrce-dds_agent&vendor=eprosima> — CVE-2025-63547, CVE-2025-63548
- "On the (In)Security of Secure ROS 2" (ACM CCS 2022): <https://dl.acm.org/doi/abs/10.1145/3548606.3560681>
- Alias Robotics — DDS/ROS 2 vulnerabilities: <https://news.aliasrobotics.com/alias-robotics-dds-ros2-vulnerabilities/>
- ArduPilot RE & control-aware security analysis (arXiv 2512.01164): <https://www.arxiv.org/pdf/2512.01164>
