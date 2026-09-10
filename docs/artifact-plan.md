# Artifact Plan

A concrete, sequenced set of deliverables across the three tracks. Every artifact
is mapped to a named Systems Security Engineer (SSE) competency — the reverse
index (competency -> artifacts) lives in [`qualification-map.md`](qualification-map.md).

## Honesty ledger — what actually pays

- **Only Track 1 can generate income**, and only at the report/disclosure stage
  (T1-F/T1-G), and only *if* the vendor pays. Most SOHO-router disclosure yields
  **CVE credit + occasional bounty**, not reliable cash. Treat Track 1 as
  income-*capable*, not a salary.
- **Track 2 and Track 3 pay nothing.** They are portfolio evidence and reusable
  leverage. Their return is hiring signal and lower cost-per-analysis, not money.
- **Track 3 tooling reduces token/analyst cost** on every later Track 1 run. That
  is the compounding lever — build the Skill before the third time you'd do a
  task by hand.

## Build sequence (dependencies interleave Track 1 and Track 3)

### Phase 0 — Foundations (in progress)
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P0.1 | Disclosure policy + research scope | — | Committed | Software Assurance; program discipline |
| P0.2 | Track 1 target-selection dossier **[built]** | 1 | Rubric + freshness re-scoring + revised pick committed | Firmware assessment; SCRM |
| P0.3 | `firmware-triage` Skill | 3 | Runs end-to-end on a sample image | Firmware assessment; Software Assurance |

### Phase 1 — First candidate list (Track 1 primary begins)
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P1.1 | Acquire 2-3 firmware versions of the D-Link RTL819x target **[runbook ready; runs on unrestricted host]** | 1 | Hashes recorded; SoC confirmed from image | Firmware assessment; Config Mgmt |
| P1.2 | Triage report per version (via P0.3) | 1 | Inventories + sink candidates produced | Firmware assessment |
| P1.3 | `binary-diff` Skill **[built]** | 3 | Diffs two rootfs; ranks by sink/string delta; names likely-vulnerable version. Verified on synthetic silent-patch | Software Assurance; Config Mgmt |
| P1.4 | First cross-version diff report | 1 | Silently-changed functions flagged | Firmware assessment; Cyber T&E |

### Phase 2 — Confirm a bug -> vendor report (income attempt #1)
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P2.1 | Ghidra decompilation review of top candidates | 1 | Unsafe sinks confirmed/rejected with notes | Embedded reversing; assessment |
| P2.2 | Emulation harness (QEMU/FirmAE) for the target | 1/3 | Target service reachable in emulation | Cyber T&E; assessment |
| P2.3 | Hand-built PoC on a confirmed candidate | 1 | Minimal, reliable repro (you build this) | Assessment |
| P2.4 | `finding-to-vendor-report` Skill **[built]** | 3 | finding.json -> CVSS-scored PSIRT report + cover email; CVSS v3.1 calc verified vs NVD | Communication (written) |
| P2.5 | First vendor-ready vulnerability report (private) | 1 | CVSS vector + impact narrative; submitted | Assessment; Communication; Cyber T&E |

### Phase 3 — Disclose + publish
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P3.1 | `finding-to-CVE-writeup` Skill | 3 | Report -> sanitized public writeup | Communication |
| P3.2 | Coordinated disclosure + CVE request | 1 | Vendor engaged; CVE ID sought | Program discipline |
| P3.3 | Sanitized public writeup / CVE | 1 | Published post-fix; on GitHub | Assessment; Communication; hiring signal |

### Phase 4 — Portfolio docs + briefing polish (parallel; no income)
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P4.1 | `data-visualization` Skill (briefing-grade charts/diagrams) | 3 | Produces theme-consistent charts + arch diagrams | Communication (visual, weighted) |
| P4.2 | Secure-boot / hardware-root-of-trust reference explainer | 2 | Diagrammed teardown of a real RoT/secure-boot chain | Embedded HW features; secure boot; comms |
| P4.3 | Full threat model of an open embedded platform (NIST SP 800-160) | 2 | Requirements derived from threats, 800-160 structure | Security architecture; 800-160 |
| P4.4 | End-to-end hardening writeup on a real embedded target | 2 | Secure-boot chain + attack-surface reduction + controls map | Secure boot; controls mapping (800-53/CMMC) |

### Phase 5 — Capstone (UAS autopilot) + milestone doc
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P5.1 | ArduPilot/PX4 + MAVLink firmware & protocol assessment | 1 | Attack surface of MAVLink + autopilot boot posture | Embedded/IoT assessment; security architecture |
| P5.2 | Milestone-style security architecture doc + anti-tamper approach | 2 | SRR/PDR/CDR-structured; anti-tamper section; MBSE hooks | Milestone docs; anti-tamper; MBSE; architecture |

## Certification note (DoD 8140 / role alignment)
- **Security+** satisfies DoD 8140 baseline for many IAT/IAM/cyber roles and is
  the fast credential to hold first.
- **CISSP** maps to higher IAM/IASAE levels and is the stronger long-term signal
  for an architecture-leaning SSE role.
- These are tracked separately from artifacts; note them on the resume line, not
  as repo deliverables.

## Cost discipline (tokens vs. outcomes)
- Automate the **funnel** (triage, diffing, drafting, charts) via Skills; never
  automate the **judgment** (exploitation, severity calls, final report review).
- Each Skill should make the next session cheaper and more consistent — build one
  the third time you'd otherwise repeat a task by hand.
- Flag any track that stops earning its cost. As of Phase 0, Track 1 is the only
  track with a payout path; Tracks 2-3 are justified by hiring signal + leverage,
  not revenue.
