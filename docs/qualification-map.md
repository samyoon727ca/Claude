# Qualification Map

Reverse index: each named Systems Security Engineer competency, the artifacts in
this portfolio that evidence it, and *how* they evidence it. Artifact IDs refer
to [`artifact-plan.md`](artifact-plan.md).

Legend: **[built]** exists now · **[planned]** in the sequence · **[cert]** credential.

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

### 3. Firmware / application / network / IoT / embedded security assessment
- **P0.3** `firmware-triage` Skill — the assessment funnel itself. **[built]**
- **P4.4** Hardening writeup — assessment-to-hardening on a real Linux embedded node. **[built]**
- **P1.2 / P1.4** Triage + cross-version diff reports. **[planned]**
- **P2.1 / P2.3 / P2.5** Ghidra review, PoC, vendor report — full assessment
  lifecycle on a commercial device. **[planned]**
- **P3.3** Public writeup / CVE — externally validated assessment result. **[planned]**
- **P5.1** UAS autopilot + MAVLink assessment — IoT/embedded on a defense-relevant
  class of system. **[planned]**

### 4. USG cyber methodology fluency (vocabulary to document around)
- **NIST SP 800-160** — P4.3 threat model is structured in its language. **[planned]**
- **Cyber T&E Guidebook** — P2.2 emulation harness + P1.4/P2.5 test-and-evaluation
  framing of findings. **[planned]**
- **NIST SP 800-193/147/155** — P4.2 firmware-resiliency/measurement vocabulary in use. **[built]**
- **NIST SP 800-160/154/30 + Cyber Survivability + ATT&CK-ICS** — P4.3 threat model. **[built]**
- **CMMC / NIST 800-53 Rev.5 / 800-171** — P4.4 controls-mapping table (12 measures). **[built]**
- **JSIG / ICD 503 / Cyber Survivability** — vocabulary applied in P5.2 milestone
  doc and P4.3 threat model. **[planned]**

### 5. Milestone security docs (SRR/PDR/CDR/TRR/PRR); MBSE; SCRM; Software Assurance; Configuration Management
- **P5.2** Milestone-structured security architecture doc with MBSE hooks. **[planned]**
- **P0.2** Target-selection dossier — SCRM reasoning (vendor SoC/supply chain). **[built]**
- **P0.3 / P1.3** Triage + diff Skills — Software Assurance (silent-patch and
  unsafe-sink detection) and Configuration Management (version/hash tracking). **[built]**
- **P4.4** Hardening writeup — Config Mgmt (baseline/least-functionality) + supply-chain
  assurance (reproducible build, SBOM, SR controls). **[built]**

### 6. Anti-tamper process and associated documentation
- **P4.2** RoT explainer §6 covers the tamper-resistance primitives AT relies on
  (lifecycle states, secure debug, zeroization, passive/active AT). **[built]**
- **P5.2** Dedicated anti-tamper approach writeup with process documentation. **[planned]**

### 7. Briefing complex security concepts (visual + written — weighted heavily)
- **P4.1** `security-dataviz` Skill — theme-aware SVG charts + mermaid taint/
  timeline diagrams from analysis output. **[built]**
- **P2.4** `finding-to-vendor-report` Skill — CVSS-scored PSIRT reports +
  disclosure email; **[built]**. **P3.1** `finding-to-cve-writeup` Skill —
  CVE JSON 5.1 record + sanitized public writeup + publish linter; **[built]**.
- **P3.3** Public writeup — externally visible written + visual communication. **[planned]**

### 8. Certifications / DoD 8140
- **Security+** — DoD 8140 baseline for IAT/IAM cyber roles. **[cert]**
- **CISSP** — higher IAM/IASAE alignment for architecture-leaning SSE. **[cert]**

---

## Coverage snapshot

| Competency | Evidenced now | After planned build |
|-----------|:-------------:|:-------------------:|
| 1. Security architecture / requirements | building | strong |
| 2. Embedded HW: secure boot / keys / AT | building | strong |
| 3. Firmware / embedded assessment | building | strong |
| 4. USG methodology fluency | building | strong |
| 5. Milestone docs / MBSE / SCRM / SwA / CM | building | strong |
| 6. Anti-tamper | building | moderate |
| 7. Briefing (visual + written) | partial | strong |
| 8. Certs / 8140 | out-of-band | out-of-band |

Gaps closing: the P4.2 secure-boot/RoT explainer now gives competencies **2**,
**4**, and **6** their first artifact (previously empty). The remaining depth for
**4** (JSIG/ICD 503/CMMC) and **6** (dedicated AT process doc) comes with the
P4.3 threat model, P4.4 hardening writeup, and P5.2 milestone/AT doc — the
difference between "strong bug-finder" and "systems security *engineer*."
