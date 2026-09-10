# Qualification Map

Reverse index: each named Systems Security Engineer competency, the artifacts in
this portfolio that evidence it, and *how* they evidence it. Artifact IDs refer
to [`artifact-plan.md`](artifact-plan.md).

Legend: **[built]** exists now · **[planned]** in the sequence · **[cert]** credential.

---

### 1. Security architecture across the product lifecycle; deriving/decomposing security requirements from threat intel
- **P4.3** Threat model in NIST SP 800-160 language — derives security
  requirements directly from an enumerated threat set. **[planned]**
- **P5.2** Milestone-style security architecture document (SRR->CDR) — shows
  requirements decomposed and traced across lifecycle gates. **[planned]**
- **P5.1** Autopilot assessment — architecture-level attack-surface reasoning on
  a real system. **[planned]**

### 2. Security-relevant embedded HW / FPGA features: secure boot, key management, anti-tamper
- **P4.2** Secure-boot / hardware-root-of-trust reference explainer — teardown of
  a real RoT chain (verified boot, key hierarchy, fuses). **[planned]**
- **P4.4** Hardening writeup — documents the secure-boot chain and key handling on
  a real device. **[planned]**
- **P5.2** Anti-tamper approach section — process + documentation for AT. **[planned]**

### 3. Firmware / application / network / IoT / embedded security assessment
- **P0.3** `firmware-triage` Skill — the assessment funnel itself. **[built]**
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
- **CMMC / NIST 800-53** — P4.4 controls mapping. **[planned]**
- **JSIG / ICD 503 / Cyber Survivability** — vocabulary applied in P5.2 milestone
  doc and P4.3 threat model. **[planned]**

### 5. Milestone security docs (SRR/PDR/CDR/TRR/PRR); MBSE; SCRM; Software Assurance; Configuration Management
- **P5.2** Milestone-structured security architecture doc with MBSE hooks. **[planned]**
- **P0.2** Target-selection dossier — SCRM reasoning (vendor SoC/supply chain). **[built]**
- **P0.3 / P1.3** Triage + diff Skills — Software Assurance (silent-patch and
  unsafe-sink detection) and Configuration Management (version/hash tracking). **[built/planned]**

### 6. Anti-tamper process and associated documentation
- **P5.2** Dedicated anti-tamper approach writeup with process documentation. **[planned]**
- **P4.2** RoT explainer covers the tamper-resistance primitives AT relies on. **[planned]**

### 7. Briefing complex security concepts (visual + written — weighted heavily)
- **P4.1** `data-visualization` Skill — briefing-grade charts and architecture
  diagrams from analysis output. **[planned]**
- **P2.4 / P3.1** report + CVE-writeup Skills — standardized, senior-reading
  written communication. **[planned]**
- **P3.3** Public writeup — externally visible written + visual communication. **[planned]**

### 8. Certifications / DoD 8140
- **Security+** — DoD 8140 baseline for IAT/IAM cyber roles. **[cert]**
- **CISSP** — higher IAM/IASAE alignment for architecture-leaning SSE. **[cert]**

---

## Coverage snapshot

| Competency | Evidenced now | After planned build |
|-----------|:-------------:|:-------------------:|
| 1. Security architecture / requirements | partial | strong |
| 2. Embedded HW: secure boot / keys / AT | — | strong |
| 3. Firmware / embedded assessment | building | strong |
| 4. USG methodology fluency | — | strong |
| 5. Milestone docs / MBSE / SCRM / SwA / CM | partial | strong |
| 6. Anti-tamper | — | moderate |
| 7. Briefing (visual + written) | partial | strong |
| 8. Certs / 8140 | out-of-band | out-of-band |

The gap to close first: competencies **4** and **6** have no artifact yet. They
are covered by Phase 4-5 docs, which is why those phases matter even though they
generate no income — they are the difference between "strong bug-finder" and
"systems security *engineer*."
