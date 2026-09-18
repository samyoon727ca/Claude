# Qualification Map

Reverse index: each named Systems Security Engineer competency, the artifacts in
this portfolio that evidence it, and *how* they evidence it. Artifact IDs refer
to [`artifact-plan.md`](artifact-plan.md).

Legend: **[built]** exists now · **[building]** partially built / in progress ·
**[planned]** in the sequence · credentials: **[held]** / **[in progress]**.

---

### 1. Security architecture across the product lifecycle; deriving/decomposing security requirements from threat intel
- **P4.3** UAS autopilot threat model in NIST SP 800-160 language — derives
  verifiable security requirements from a STRIDE/ATT&CK threat register. **[built]**
- **P5.2** Milestone-style security architecture document (SRR->CDR) — shows
  requirements decomposed and traced across lifecycle gates. **[planned]**
- **P5.1** Autopilot assessment — architecture-level attack-surface reasoning on
  a real system. **[planned]**

### 2. Security-relevant embedded HW / FPGA features: secure boot, key management, anti-tamper
- **P4.2** Secure-boot / hardware-root-of-trust reference explainer — RoT
  functions, verified vs measured boot, key hierarchy, lifecycle/anti-tamper,
  attack decomposition, and threat->requirement->T&E traceability. **[built]**
- **P4.4** Hardening writeup — verified boot + key handling applied on a real
  Linux embedded node, mapped to controls. **[built]**
- **P4.2** Lifecycle + anti-tamper section (tamper-resistant key storage, secure
  debug, zeroization, passive/active AT). **[built]**
- **P5.2** Dedicated anti-tamper approach + process documentation. **[planned]**
- **P6.1** FPGA security reference artifact — bitstream authentication/encryption, eFUSE
  vs BBRAM keying, PUF-derived keys, DPA/side-channel + anti-tamper, and the RoT extended
  into programmable logic ([`track2/fpga-security-reference.md`](track2/fpga-security-reference.md)). **[built]**

### 3. Firmware / application / network / IoT / embedded security assessment
- **P0.3** `firmware-triage` Skill — the assessment funnel itself. **[built]**
- **P4.4** Hardening writeup — assessment-to-hardening on a real Linux embedded node. **[built]**
- **P5.1 (remediation)** UAS MAVLink hardening writeup — the hardening counterpart to the
  capstone: signing + anti-replay **applied**, telemetry encryption / companion segmentation
  **recommended**, each with a verification method
  ([`track2/uas-mavlink-hardening.md`](track2/uas-mavlink-hardening.md)). **[built]**
- **P1.2 / P1.4** Triage + cross-version diff reports — run on real firmware across
  three targets (D-Link, Zyxel, DrayTek). **[built]**
- **P2.1** Ghidra decompilation review — on DrayTek Vigor300B it **confirmed a root OS
  command injection** (`download_ovpn` sanitizer bypass) at the code level and resolved the
  auth gate; on live re-check it **deduped as an n-day (CVE-2024-45890)**, the same bug on
  the sibling Vigor3900. **[built]**
- **P2.3 / P2.5** PoC + vendor report — runtime PoC and PSIRT report for the DrayTek
  finding; the remaining step to make the assessment lifecycle externally *proven*. **[planned]**
- **P3.3** Public writeup / CVE — DIR-816L n-day case study published; the DrayTek run 3
  writes up as a second n-day case study (CVE-2024-45890). A genuinely new CVE depends on
  the fan-out to a still-supported / unpatched Vigor model. **[building]**
- **P5.1** UAS autopilot + MAVLink assessment — IoT/embedded on a defense-relevant
  class of system; **mavlink-sectest** run vs ArduPilot SITL: stock link **4 FAIL / 1 PASS**
  (T1/T4/T5 unmet as predicted), the signing before/after clears the T1/T5 cluster, and the
  P6.2 module gives the deterministic proof — see
  [`track2/uas-capstone-assessment.md`](track2/uas-capstone-assessment.md) +
  [`track2/uas-mavlink-hardening.md`](track2/uas-mavlink-hardening.md). **[built]**

### 4. USG cyber methodology fluency (vocabulary to document around)
- **NIST SP 800-160** — P4.3 threat model is structured in its language. **[planned]**
- **Cyber T&E Guidebook** — P2.2 emulation harness + P1.4/P2.5 test-and-evaluation
  framing of findings. **[planned]**
- **NIST SP 800-193/147/155** — P4.2 firmware-resiliency/measurement vocabulary in use. **[built]**
- **NIST SP 800-160/154/30 + Cyber Survivability + ATT&CK-ICS** — P4.3 threat model. **[built]**
- **Cyber T&E** — mavlink-sectest harness runs threat-model requirements as automated tests. **[built]**
- **CMMC / NIST 800-53 Rev.5 / 800-171** — P4.4 controls-mapping table (12 measures). **[built]**
- **JSIG / ICD 503 / Cyber Survivability** — vocabulary applied in P5.2 milestone
  doc and P4.3 threat model. **[planned]**

### 5. Milestone security docs (SRR/PDR/CDR/TRR/PRR); MBSE; SCRM; Software Assurance; Configuration Management
- **P5.2** Milestone security architecture doc — SRR->PRR gate table + MBSE
  traceability golden thread. **[built]**
- **P0.2** Target-selection dossier — SCRM reasoning (vendor SoC/supply chain). **[built]**
- **P0.3 / P1.3** Triage + diff Skills — Software Assurance (silent-patch and
  unsafe-sink detection) and Configuration Management (version/hash tracking). **[built]**
- **P4.4** Hardening writeup — Config Mgmt (baseline/least-functionality) + supply-chain
  assurance (reproducible build, SBOM, SR controls). **[built]**

### 6. Anti-tamper process and associated documentation
- **P4.2** RoT explainer §6 covers the tamper-resistance primitives AT relies on
  (lifecycle states, secure debug, zeroization, passive/active AT). **[built]**
- **P5.2** Dedicated anti-tamper approach — CPI -> plan -> implement -> AT&E
  process (DoDI 5200.39 / DoDD 5200.47E), architecture level. **[built]**

### 7. Briefing complex security concepts (visual + written — weighted heavily)
- **P4.1** `security-dataviz` Skill — theme-aware SVG charts + mermaid taint/
  timeline diagrams from analysis output. **[built]**
- **P2.4** `finding-to-vendor-report` Skill — CVSS-scored PSIRT reports +
  disclosure email; **[built]**. **P3.1** `finding-to-cve-writeup` Skill —
  CVE JSON 5.1 record + sanitized public writeup + publish linter; **[built]**.
- **P3.3** Public writeup — externally visible written + visual communication. **[planned]**
- **P6.3** Program-leadership security brief — a 12-slide leadership deck synthesizing
  the CVE work + the UAS threat→gap→fix story, the form the JD weights:
  [`track2/uas-security-brief.html`](track2/uas-security-brief.html). **[built]**

### 8. Clearance & certifications / DoD 8140
- **Clearance: TS/SCI with SAP eligibility — held.** Clears the hard gate on most
  SSE / defense-embedded roles (which require at minimum a final Secret + SAP
  eligibility). The single strongest line in the profile. **[held]**
- **Security+ — held.** DoD 8140/8570 baseline for IAT/IAM cyber roles. **[held]**
- **CASP+ / SecurityX — held.** Advanced 8140 baseline (IAT III / IASAE). **[held]**
- **CISSP — in progress (USAF-funded).** Higher IAM/IASAE alignment for an
  architecture-leaning SSE role. **[in progress]**

---

## Coverage snapshot

| Competency | Evidenced now | After planned build |
|-----------|:-------------:|:-------------------:|
| 1. Security architecture / requirements | strong | strong |
| 2. Embedded HW: secure boot / keys / AT | strong | strong |
| 3. Firmware / embedded assessment | strong (two n-days confirmed at code level; method proven) | proven (live CVE) |
| 4. USG methodology fluency | strong | strong |
| 5. Milestone docs / MBSE / SCRM / SwA / CM | strong | strong |
| 6. Anti-tamper | moderate (process) | moderate (process) |
| 7. Briefing (visual + written) | strong | strong |
| 8. Clearance & certs / 8140 | held (TS/SCI+SAP · Sec+ · CASP+) | + CISSP (in progress) |

State: all four Track 2 engineering docs (P4.2/P4.3/P4.4/P5.2) are built, giving
competencies **1-7** real artifact coverage (6 at the unclassified process ceiling;
8 is the clearance + certs, held out-of-band — TS/SCI+SAP, Security+, CASP+). Track 1
run 3 (DrayTek Vigor300B) **confirmed a root command injection at the code level**, then
deduped it as an n-day (CVE-2024-45890) — strong hands-on evidence of *method*, though not a
new discovery. What would convert the portfolio to a *proven*, externally-validated **new**
CVE is the fan-out to a still-supported / unpatched Vigor model out of that CVE's CPE scope;
run 3 itself closes out as a second n-day case study (substantiated by a runtime PoC), plus
the P5.1 UAS capstone. Those are the remaining substantive items in the plan.
