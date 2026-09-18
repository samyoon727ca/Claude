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

## Role alignment & re-prioritization (living — updated 2026-09-14)

**Target role.** Product-facing Systems Security Engineer for defense embedded
systems: own security end-to-end — derive/decompose security requirements from
customer needs and threat intel, design architectures, implement security features,
run security T&E at multiple integration levels across SRR->PDR->CDR->TRR->PRR, and
brief government customers and program leadership. Explicitly **not** an ISSO/ISSM
compliance role — the work is engineering, not authorization paperwork. This repo is
deliberately structured against that competency set (reverse index in
[`qualification-map.md`](qualification-map.md)).

**The hard gate is already cleared.** TS/SCI with SAP eligibility (held) plus the
DoD-8140 certs (Security+, CASP+; CISSP USAF-funded, in progress) clear the
clearance + eligibility filter that gates most of these roles outright. That
*reframes what this portfolio is for*: not proving eligibility or methodology
vocabulary (already strong), but evidencing transferable **hands-on** depth that a
clearance line alone doesn't show.

**Declare the doc set done.** The Track 2 documents (P4.2-P4.4, P5.2) and the Track 3
skill funnel already give competencies 1, 2, 4, 5, 7 credible, well-structured
coverage. Another Track 2 doc has hit diminishing returns — **freeze it.** The risk
of *more* prose is that a strong interviewer reads a stack of structured docs as
survey material rather than earned depth.

**Shift the marginal hour from "tell" to "show."** Written docs are "tell"; what
converts the portfolio into evidence you *are* an SSE is externally verifiable
"show." Reprioritize, in order:
1. **A new CVE from the DrayTek fan-out** (Track 1, run 3: P1.x -> P3.x). Run 3 itself is
   **confirmed at the code level but deduped as an n-day** — the `download_ovpn` root OS
   command injection in Vigor300B `mainfunction.cgi` (sanitizer bypass) is already
   **CVE-2024-45890** (same bug on the sibling Vigor3900; the initial "no matching CVE" was
   a 300B-scoped dedup miss). The remaining new-CVE upside is the **fan-out** to a
   still-supported, out-of-CPE, unpatched Vigor model; run 3 itself closes out as a
   methodology case study (+ optional CPE coverage-gap note), substantiated by a runtime
   PoC. Even as an n-day it advances firmware/embedded assessment (competency 3) from
   *partial* toward *proven* on method. Top item. (Zyxel, the prior run-2 pick, is blocked
   at acquisition — ISP-gated patched firmware.)
2. **Execute the UAS T&E** (P5.1). Run `mavlink-sectest` against real SITL and fold
   the results into the capstone — turns the harness from self-test into real result.
3. **FPGA security artifact** (P6.1). Fills the one *named* JD requirement with zero
   coverage today (embedded HW **/ FPGA** secure boot, key management). Extends P4.2.
4. **One systems-language build** (P6.2). Rust or C, not Python glue — proves you
   build in the languages embedded security actually runs on.
5. **One real brief** (P6.3). A slide deck or recorded talk, not a markdown doc — the
   JD weights briefing government customers heavily and no *brief* exists yet.

**Re-scope UAS toward Group 3+.** ArduPilot/PX4 stays as the lab, but the P4.3 threat
model and P5.1 capstone framing should target Group 3+ characteristics (BLOS/SATCOM
C2, encrypted datalinks, GPS-denied / spoofing resilience, the ground control station
as attack surface, multi-vehicle) — the class the target market actually fields,
rather than hobby-class autopilot defaults.

**Parallelize — but split by cognitive mode.** Serialize the deep proof path;
parallelize the additive gap-fillers so a stall in one never blocks the others:
- **Track A (serial, deep flow):** DrayTek diff -> Ghidra confirm -> dedup **[done]** ->
  runtime PoC -> fan-out -> coordinated disclosure -> CVE, *then* execute the UAS T&E.
  Do not parallelize work that needs uninterrupted flow.
- **Track B (parallel, different modes):** FPGA doc (writing), Rust/C artifact
  (building), briefing deck (synthesis of existing work), CISSP progress (study).
  These fill named gaps *between* reversing sessions without diluting Track A.

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
| P1.1 | Acquire 2-3 firmware versions of the locked target **[done: D-Link DIR-816L + DrayTek Vigor300B]** | 1 | Hashes recorded; SoC confirmed from image | Firmware assessment; Config Mgmt |
| P1.2 | Triage report per version (via P0.3) **[done on both runs]** | 1 | Inventories + sink candidates produced | Firmware assessment |
| P1.3 | `binary-diff` Skill **[built]** | 3 | Diffs two rootfs; ranks by sink/string delta; names likely-vulnerable version. Verified on synthetic silent-patch | Software Assurance; Config Mgmt |
| P1.4 | First cross-version diff report **[done: DrayTek 1.5.1.6→1.5.1.7 silent-fix flagged]** | 1 | Silently-changed functions flagged | Firmware assessment; Cyber T&E |

### Phase 2 — Confirm a bug -> vendor report (income attempt #1)
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P2.1 | Ghidra decompilation review of top candidates **[done: DrayTek download_ovpn confirmed at code level + auth resolved; deduped as n-day CVE-2024-45890]** | 1 | Unsafe sinks confirmed/rejected with notes | Embedded reversing; assessment |
| P2.2 | Emulation harness (QEMU/FirmAE) for the target | 1/3 | Target service reachable in emulation | Cyber T&E; assessment |
| P2.3 | Hand-built PoC on a confirmed candidate | 1 | Minimal, reliable repro (you build this) | Assessment |
| P2.4 | `finding-to-vendor-report` Skill **[built]** | 3 | finding.json -> CVSS-scored PSIRT report + cover email; CVSS v3.1 calc verified vs NVD | Communication (written) |
| P2.5 | First vendor-ready vulnerability report (private) | 1 | CVSS vector + impact narrative; submitted | Assessment; Communication; Cyber T&E |

### Phase 3 — Disclose + publish
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P3.1 | `finding-to-cve-writeup` Skill **[built]** | 3 | finding.json -> CVE JSON 5.1 record + sanitized writeup; publish linter verified | Communication |
| P3.2 | Coordinated disclosure + CVE request | 1 | Vendor engaged; CVE ID sought | Program discipline |
| P3.3 | Sanitized public writeup / CVE | 1 | Published post-fix; on GitHub | Assessment; Communication; hiring signal |

### Phase 4 — Portfolio docs + briefing polish (parallel; no income)
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P4.1 | `security-dataviz` Skill **[built]** | 3 | Theme-aware SVG charts + mermaid taint/timeline from analysis CSVs; sample rendered | Communication (visual, weighted) |
| P4.2 | Secure-boot / hardware-root-of-trust reference explainer **[built]** | 2 | 243-line explainer: chain-of-trust + key-hierarchy + lifecycle diagrams, threat->requirement->T&E traceability, NIST 800-193/147/155/160 | Embedded HW features; secure boot; comms |
| P4.3 | UAS autopilot threat model (NIST SP 800-160) **[built]** | 2 | 220-line data-centric model: DFD+trust boundaries, STRIDE/ATT&CK-ICS register, 800-30 risk chart, 9 threat->requirement->T&E rows, survivability map | Security architecture; 800-160 |
| P4.4 | Embedded hardening writeup (Linux UAS companion computer) **[built]** | 2 | Defense-in-depth from baseline; 12-row controls map (800-53 r5 + CMMC/800-171); before/after surface; realizes P4.3 threats | Secure boot; controls mapping (800-53/CMMC) |

### Phase 5 — Capstone (UAS autopilot) + milestone doc
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P5.1 | ArduPilot/PX4 + MAVLink assessment **[T&E harness built; hands-on pending]** | 1 | mavlink-sectest runs the threat-model reqs vs SITL; hands-on assessment on owned/sim | Embedded/IoT assessment; security architecture; Cyber T&E |
| P5.2 | Milestone security architecture + anti-tamper approach **[built]** | 2 | SRR->PRR gate table, MBSE traceability, DoD AT process (5200.39/47E), SCRM/SwA/CM; synthesizes P4.2/4.3/4.4 | Milestone docs; anti-tamper; MBSE; architecture |

### Phase 6 — Role-alignment gap-fillers (JD-driven; parallel Track B)
| ID | Deliverable | Track | DoD | Competency |
|----|-------------|-------|-----|------------|
| P6.1 | FPGA security reference artifact **[planned]** | 2 | Bitstream authentication/encryption, eFUSE key provisioning, secure configuration, DPA/side-channel exposure, PUF-based keying; RoT extended into programmable logic; threat->requirement->T&E rows | Embedded HW **/ FPGA** features (named JD gap) |
| P6.2 | One systems-language embedded-security build (Rust or C) **[planned]** | 3 | A real, minimal artifact — e.g. memory-safe firmware-container parser, MAVLink v2 signing implementation, or a C PoC for a confirmed finding; builds + tests | Rust/Go/C/C++ (preferred qual); Software Assurance |
| P6.3 | Program-leadership security brief **[planned]** | 2 | A slide deck or recorded ~10-min talk translating the UAS threat model (or a CVE) for government / leadership audiences | Briefing gov customers (weighted) |

## Clearance & certifications (role gate — held)
- **Clearance: TS/SCI with SAP eligibility — active/held.** This is the hard gate on
  most SSE / defense-embedded roles (typical JDs require *at minimum* a final Secret +
  SAP eligibility, plus TS obtainability). Holding TS/SCI + SAP clears that filter
  outright and is the single strongest line in the profile.
- **DoD 8140 baseline: Security+ (held), CASP+ / SecurityX (held).** Satisfy the
  8140/8570 baseline through the advanced (IAT III / IASAE) tier for cyber-workforce
  coding of these roles.
- **CISSP: in progress (USAF-funded).** Maps to higher IAM/IASAE levels and is the
  stronger long-term signal for an architecture-leaning SSE role.
- Clearance + certs are resume-line facts, tracked here for strategy rather than as
  repo deliverables. Their existence is *why* the build priority above shifts to
  proof artifacts instead of more eligibility or methodology-vocabulary signaling.

## Cost discipline (tokens vs. outcomes)
- Automate the **funnel** (triage, diffing, drafting, charts) via Skills; never
  automate the **judgment** (exploitation, severity calls, final report review).
- Each Skill should make the next session cheaper and more consistent — build one
  the third time you'd otherwise repeat a task by hand.
- Flag any track that stops earning its cost. As of Phase 0, Track 1 is the only
  track with a payout path; Tracks 2-3 are justified by hiring signal + leverage,
  not revenue.
