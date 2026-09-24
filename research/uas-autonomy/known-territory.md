# Known-Territory Map — UAS / Autonomy (Run 4 Phase 0 dedup gate)

> **Status: LIVE GATE (swept 2026-09-24).** This is the Phase 0 deliverable required by
> [`track1-uas-run-plan.md`](../../docs/track1-uas-run-plan.md) §3. Every candidate finding
> in Phases 1–2 passes through this map **before** deep RE time is spent. Three straight
> router runs deduped as n-days and the run-3 lesson (a `download_ovpn` bug was already
> CVE-2024-45890, filed under a *sibling* model a scoped search missed) is the reason this
> gate exists. **Re-run the sweep at claim time** — this is a snapshot, not a substitute for
> the primary NVD/GHSA check the moment a candidate looks novel.

> **Scope & ethics (unchanged).** Unclassified, open-source targets (PX4, ArduPilot, ROS 2,
> DDS). Simulation-first. Coordinated disclosure; no committed blobs. See
> [`disclosure-policy.md`](../../docs/disclosure-policy.md). This file is working-area
> paperwork (committed); firmware/binary blobs stay git-ignored.

---

## 0. How to use this gate

Before spending deep RE hours on any candidate, answer three questions against the tables
below:

1. **Is the exact bug already a CVE/GHSA?** → n-day. Reproduce as a *demonstration*, don't
   claim novelty.
2. **Is the bug *class* on this *component* already claimed?** (the run-3 miss) → treat as
   almost-certainly-dup; search siblings and the whole codebase family, not just one CPE
   list, before spending time.
3. **Is this documented default behavior the vendor already tells users to harden?** →
   hardening / negative-result finding, not a CVE. Still ships (the DrayTek ethos), framed
   honestly.

Only a candidate that clears all three earns deep time. **The dedup verdict column is the
output of the gate.**

---

## 1. PX4 — MAVLink surface (Phase 1 anchor; treat as demonstration, not novelty)

The MAVLink receiver / FTP / shell parsing surface is being **actively mined in 2026** — a
dense cluster of memory-safety and logic CVEs landed this year. Reproducing any one is a
strong Phase-1 demonstration; finding a *new* one here is low-probability given current
attention.

| CVE / advisory | Class | Affected / fixed | Sev (as reported) | Dedup verdict |
|---|---|---|---|---|
| **CVE-2026-1579** | Unauth command incl. `SERIAL_CONTROL` shell → RCE when MAVLink 2 signing is off (**the default**) | ≤ v1.16.0 SITL noted; protocol-level | **9.8** v3.1 / 9.3 v4.0, CWE-306; pub. 2026-03-31; **CISA ICSA-26-090-02** | **ANCHOR.** Documented default; PX4 now ships a *MAVLink Security Hardening* guide. Our capstone T1/T5 = reproduction of this class. **Zero novelty — cite, don't claim.** |
| CVE-2026-32743 | Stack buffer overflow, `MavlinkLogHandler` (`LogEntry.filepath` 60 B, `sscanf` no width) via MAVLink log request after deep-dir create over MAVLink FTP | ≤ 1.17.0-rc2; fixed `616b25a2` | stack overflow / DoS | Reproduce-only. MAVLink parse surface is hot. |
| CVE-2026-32724 | Heap use-after-free `MavlinkShell::available()` — receiver/telemetry thread race | recent | UAF | Reproduce-only. |
| CVE-2026-32713 | MAVLink FTP session-validation logic error (`&&` vs `||`) → ops on invalid session/closed fd | recent | ~6.5 | Reproduce-only. |
| CVE-2026-32709 | Path traversal | recent | ~6.8 | Reproduce-only. |
| GHSA-55wq-2hgm-75m4 | Stack buffer overflow in `mavlink_receiver.cpp` (refuses to execute) | — | DoS | Reproduce-only. |

**Implication for Phase 1:** the plan's re-anchor is correct and dedup-risk is **zero** —
we are explicitly *citing* CVE-2026-1579 and reproducing the T1/T5 cluster, not claiming it.

---

## 2. eProsima Fast-DDS — RTPS / CDR wire parsing (the Phase 2 "novelty bet" — now crowded)

This is the surface Phase 2 hoped a novel CVE would live in. **It is also being actively
mined in 2025–2026.** A naive "fuzz the DDS wire, report a crash" plan is now **high-collision
and trends to low-value DoS**.

| CVE | Class | Fixed in | Verdict |
|---|---|---|---|
| **CVE-2026-22590** | OOB read processing RTPS `DATA_FRAG` (large sample size + small payload), CWE-125 | 2.6.12 / 2.14.6 / 3.2.4 / 3.3.1 / 3.4.2 | Critical; recent. RTPS submessage parsing is claimed ground. |
| CVE-2025-64438 | OOM DoS via RTPS `GAP` under RELIABLE QoS (tiny GAP + huge range → unbounded `processGapMsg()` loop) | 3.4.1 / 3.3.1 / 2.6.11 | DoS. |
| CVE-2025-62602 | Heap overflow modifying `DATA` submessage in an SPDP packet **when security mode is enabled** | 3.4.1 / 3.3.1 / 2.6.11 | Note: touches the *secure* path. |
| CVE-2025-62599 / CVE-2025-62603 | CDR parser deserializes entire `DataHolderSeq` in `ParticipantGenericMessage` → OOM / remote termination | 2025 batch | CDR/Fast-CDR parse dup. |
| CVE-2024-30259 | Heap overflow on subscriber from malformed RTPS packet | ≤ 2.14.1 / 2.13.5 / 2.10.4 / 2.6.8 | Prior art for "malformed RTPS → subscriber crash". |

---

## 3. Micro-XRCE-DDS-Agent — the *exact* component the probe touches

This is the bridge the Phase 2 probe (`xrce_probe.md`, this dir) exercises. **The agent's malformed-field
parsing is already claimed** — two 2025-series CVEs are precisely the "send a bad field, crash
the agent" shape on this exact component.

| CVE | Class | Version | Sev | Verdict |
|---|---|---|---|---|
| **CVE-2025-63547** | Malformed **MTU length field** → agent drops packets / error state | v3.0.1 | 7.5 v3.1; pub. 2026-05-01 | Exact component + class the probe's parser path would hit. |
| **CVE-2025-63548** | **Invalid Boolean field** value → internal exception → resource-exhaustion DoS, CWE-241 | v3.0.1 | 7.5 | Same. |

**Implication:** a raw parser-crash finding against the agent is now almost certainly a dup
of, or same-class as, 63547/63548. **Confirm the agent version PX4 actually pins** and re-check
these two before spending time on any malformed-XRCE-field candidate.

---

## 4. ROS 2 / SROS2 / DDS-Security — logic & authorization surface

Less memory-safety, more design/authz. Documented design flaws exist; this is where a *logic*
finding (not a parser crash) could plausibly still live.

- **CCS'22, "On the (In)Security of Secure ROS 2"** — V1 inadequate permission revocation
  (revoked cert keeps access), V2 inadequate namespace isolation (cross-domain leak), V3
  discovery protocol leaks topology to a passive attacker. Root cause: DDS QoS/access-control
  policies only settable at participant init; a node can refuse the update. **Design-level,
  documented.**
- **2025 supply-chain PoC** — trojaned `sros2` CLI exfiltrates keystore/enclave credentials
  during creation. Not our attack surface (build-time trust), noted for completeness.
- **Correctness gaps (2025, Alias Robotics / community):** discovery-encryption + topic-level
  protection enabled together stops endpoints matching; **incomplete privilege inheritance**
  has produced real security bugs.

---

## 5. ArduPilot — cross-stack validator (Phase 1 second data point)

| CVE | Class | Affected | Sev | Verdict |
|---|---|---|---|---|
| CVE-2026-36522 | Unauth **NaN injection** via MAVLink `PARAM_SET` → silent flight-critical-param corruption on production HW (FP exceptions off); abort on SITL | ArduPlane 4.0.1 | 9.1, CWE-1287 | Cross-stack reproduction candidate; already a CVE. |
| CVE-2026-38971 | OOB read in `GCS_serial_control.cpp` `handle_serial_control()` | ≤ Plane-4.6.3 | OOB read | Cross-stack; already a CVE. |

Reinforces §2 of the run plan: ArduPilot is the **cross-validation** target (its RE-for-security
is actively published), **not** the novelty bet.

---

## 6. Synthesis — what this gate changes about the plan

1. **The "unauthenticated command / no-auth default" thesis is fully claimed territory.**
   CVE-2026-1579 (9.8, CISA advisory, PX4 hardening guide) is the flagship, and MAVLink
   signing-off is documented default behavior. The `xrce_probe` (this dir) clause-1/2
   observations (unauth session, cleartext telemetry) are a **demonstration / hardening**
   result — **not a CVE.** This matches the probe's own honest caveat.

2. **The DDS/XRCE wire-parsing surface — the plan's stated novelty bet — is now crowded.**
   Fast-DDS RTPS/CDR (§2) and, critically, the **Micro-XRCE-DDS-Agent itself** (§3) are being
   actively mined in 2025–2026, including the exact component and bug-class the probe would
   explore. A "fuzz the agent → report a crash" plan is high-collision and trends to
   low-value DoS.

3. **The MAVLink receiver/FTP/shell surface (PX4 + ArduPilot) is a hot 2026 cluster** (§1, §5).
   Reproduce for Phase 1; do not expect a new bug there.

4. **If an unclaimed corner exists, it is more likely logic / trust-boundary / authorization
   than raw memory-safety.** The probe's *partial* result is the tell: the interesting
   question is **not** "the default bridge has no auth" (known, §1) but **"what can an
   unauthenticated peer's entities actually do against a security-*enabled* deployment — can a
   rogue XRCE client's participant/writer match PX4's FMU readers, and with what
   privileges?"** That is an **authorization / entity-ownership / matching** question (§4
   territory: privilege inheritance, policy desync), not a parser question — and it is the one
   corner this sweep did **not** find directly claimed.

### Re-scoped Phase 2 aim (recommendation)

- **Bias the hunt toward the client↔agent trust boundary and the security-enabled config:**
  privilege inheritance / entity-ownership across the XRCE bridge, matching behavior under
  SROS2 governance/permissions, cross-domain isolation — the logic corner, not the wire crash.
- **Treat any DDS/XRCE parser DoS as presumptively a dup** (§2/§3); only pursue with a fresh
  primary-source check confirming it is not 22590 / 64438 / 62602 / 62599/62603 / 63547 /
  63548 and not a same-class variant.
- **Keep the rigorous negative-result writeup as the guaranteed-value floor** (the plan's
  DrayTek ethos): a clean security assessment of the middleware trust model ships regardless.

---

## 7. Candidate → gate checklist (paste into each finding note)

```
[ ] Exact bug already a CVE/GHSA?              (§1–§5 + fresh NVD/GHSA search)
[ ] Bug class already claimed on THIS component? (run-3 lesson: check the whole family)
[ ] Documented default the vendor tells users to harden?  (=> hardening finding, not CVE)
[ ] Searched sibling models / versions, not just one CPE list?
[ ] If it clears all four: re-run the primary NVD/GHSA sweep the day the claim is made.
```

---

## 8. Coverage & method (honesty about this snapshot)

- **Swept 2026-09-24** via NVD/OpenCVE/OSV, GitHub Security Advisories, CISA ICS advisories,
  and academic/vendor disclosure sources, across the components the run plan §3 names:
  `PX4/PX4-Autopilot`, `ArduPilot/ardupilot`, `eProsima/Fast-DDS`, `eProsima/Fast-CDR`,
  `eProsima/Micro-XRCE-DDS-Agent`, `ros2` / SROS2 / DDS-Security.
- **Known residual gaps:** (a) this is not an exhaustive NVD enumeration — CVSS/version detail
  is as reported by aggregators and must be confirmed against primary records at claim time;
  (b) the **agent version PX4 actually pins** must be verified against the pinned submodule
  before §3 is applied; (c) GHSA advisories on the eProsima and PX4 repos should be re-pulled
  the day a candidate is escalated (advisories are added continuously).
- **The gate is only as good as its freshness.** Re-run before any novelty claim; the run-3
  dedup miss happened because a check was scoped too narrowly.

---

## 9. Sources

- CVE-2026-1579 (PX4 MAVLink signing → `SERIAL_CONTROL` RCE): <https://app.opencve.io/cve/CVE-2026-1579> · CISA ICS advisory: <https://www.cisa.gov/news-events/ics-advisories/icsa-26-090-02> · PX4 hardening guide: <https://docs.px4.io/main/en/mavlink/security_hardening>
- PX4 security advisories (GHSA index): <https://github.com/PX4/PX4-Autopilot/security/advisories> · CVE-2026-32743: <https://app.opencve.io/cve/CVE-2026-32743> · CVE-2026-32713: <https://osv.dev/vulnerability/CVE-2026-32713> · CVE-2026-32724: <https://osv.dev/vulnerability/CVE-2026-32724> · GHSA-55wq-2hgm-75m4: <https://github.com/PX4/PX4-Autopilot/security/advisories/GHSA-55wq-2hgm-75m4>
- Fast-DDS CVE-2026-22590: <https://osv.dev/vulnerability/CVE-2026-22590> · CVE-2025-64438: <https://app.opencve.io/cve/CVE-2025-64438> · CVE-2025-62602: <https://nvd.nist.gov/vuln/detail/cve-2025-62602> · Fast-DDS CVE list: <https://vulners.com/search/vendors/eprosima/products/fast%20dds> · CVE-2024-30259: <https://nvd.nist.gov/vuln/detail/CVE-2023-50257>
- Micro-XRCE-DDS-Agent CVE-2025-63547: <https://app.opencve.io/cve/CVE-2025-63547> · CVE-2025-63548: <https://app.opencve.io/cve/CVE-2025-63548> · product CVE list: <https://app.opencve.io/cve/?product=micro-xrce-dds_agent&vendor=eprosima>
- SROS2 / DDS-Security — "On the (In)Security of Secure ROS 2" (CCS'22): <https://tianweiz07.github.io/Papers/22-ccs-2.pdf> · Alias Robotics DDS/ROS 2: <https://news.aliasrobotics.com/alias-robotics-dds-ros2-vulnerabilities/> · SROS2 keystore-exfil PoC (2025): <https://www.researchgate.net/publication/397231318_Supply_Chain_Exploitation_of_Secure_ROS_2_Systems_A_Proof-of-Concept_on_Autonomous_Platform_Compromise_via_Keystore_Exfiltration>
- ArduPilot CVE-2026-36522: <https://github.com/deepwoodssec/CVE-2026-36522> · CVE-2026-38971: <https://app.opencve.io/cve/CVE-2026-38971>
- PX4 uXRCE-DDS bridge (architecture / default config): <https://docs.px4.io/main/en/middleware/uxrce_dds>
