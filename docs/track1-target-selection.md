# Track 1 — Target Selection Dossier

**Purpose.** Document *why* the first firmware-research target was chosen, using a
repeatable rubric. Target selection is itself a supply-chain-risk-management
(SCRM) exercise: choosing what to assess, and defending that choice, is part of
the engineering.

**Constraint recap.** UNCLASSIFIED, US/allied vendor, Realtek-based SOHO router,
publicly downloadable firmware, coordinated disclosure only.

## Selection rubric

Each candidate is scored 1-5 on five weighted criteria:

| Criterion | Why it matters | Weight |
|-----------|----------------|:------:|
| **Firmware version depth** | Binary diffing across versions is the core funnel; need many public releases to find silently-patched bugs | ×3 |
| **Payout path** | Track 1 is the income track; a real paid bounty beats credit-only | ×3 |
| **Realtek fit + MIPS/ARM match** | Must actually be Realtek SoC; matches the MIPS/ARM reversing specialization | ×2 |
| **Attack surface freshness** | Less picked-over targets yield novel findings, not duplicates | ×2 |
| **Clearance-safety narrative** | US vendor > allied for the "obviously-not-a-foreign-adversary-product" story | ×1 |

## Candidate scoring

| Candidate | Ver. depth ×3 | Payout ×3 | Realtek fit ×2 | Freshness ×2 | Narrative ×1 | **Total** |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|
| **Netgear (US)** | 5 (15) | 4 (12) | 3 (6) | 3 (6) | 5 (5) | **44** |
| **D-Link (Taiwan)** | 5 (15) | 2 (6) | 5 (10) | 2 (4) | 3 (3) | **38** |
| **Zyxel (Taiwan/NL)** | 4 (12) | 3 (9) | 4 (8) | 4 (8) | 3 (3) | **40** |

Notes on the scores:
- **Netgear** wins on payout (Bugcrowd) and narrative (US vendor). Realtek fit is
  "3" not "5" because Netgear's lineup is mixed (Broadcom/Qualcomm/MediaTek as
  well as Realtek) — the specific model must be chosen *for* its Realtek SoC.
- **D-Link** has the most reliable Realtek fit and deepest history, but is
  heavily researched (duplicate risk) and typically credits rather than pays.
- **Zyxel** is a strong middle option: fresher surface, responsive PSIRT, real
  (if modest) payout — a good secondary if Netgear leads go cold.

## Decision

- **Primary vendor: Netgear (US).** Highest weighted score, only reliably-paid
  path, cleanest clearance narrative.
- **Secondary / volume: D-Link DIR series (Realtek RTL819x, MIPS).** The
  CVE-count farm when a Netgear lead is a duplicate or dead end.
- **Held in reserve: Zyxel.** Rotate in for freshness if both above stall.

## Model selection — confirm the SoC from the firmware, not the spec sheet

Vendor spec pages and Wikipedia are unreliable for SoC identification, and the
same model number often ships multiple hardware revisions with different chips.
**The first hands-on step selects the exact model by confirming Realtek silicon
from the image itself**, not from marketing:

1. Pull the candidate model's **firmware version history** from Netgear's public
   support/download site; prefer a model with **3+ downloadable releases** (diff
   fuel). Record every version + SHA-256.
2. `binwalk` the newest image; extract the root filesystem.
3. Confirm Realtek by evidence in the image:
   - bootloader / U-Boot strings mentioning `rtl`, `RTL8`, `Realtek`, `rlx`, or
     an `lx` (lexra) MIPS core;
   - kernel `bcm`/`ath`/`mtk` strings *absent*, Realtek SDK paths present;
   - ELF `e_machine` = MIPS (RTL819x) or ARM (newer RTL SoCs), endianness noted.
4. Confirm **attack surface exists**: web admin (`httpd`/`goahead`/`mini_httpd`),
   UPnP, custom CGI, `nvram`/`acos_service`-style daemons — the usual SOHO-router
   RCE surface.
5. Only then lock the model and record it here as the working target.

This step is intentionally deferred to hands-on work because it depends on
current firmware availability and must be verified from the binary. It is also a
portfolio artifact in its own right: it demonstrates SCRM reasoning and the
discipline of trusting evidence over documentation.

## Working target

- **Status:** vendor locked (Netgear primary); exact model to be fixed at P1.1 by
  the procedure above, then recorded here with version list + hashes.
