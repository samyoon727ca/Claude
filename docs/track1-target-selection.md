# Track 1 — Target Selection Dossier

**Purpose.** Document *why* the first firmware-research target was chosen, using a
repeatable rubric. Target selection is itself a supply-chain-risk-management
(SCRM) exercise: choosing what to assess, and defending that choice, is part of
the engineering.

**Constraint recap.** UNCLASSIFIED, US/allied vendor, Realtek-based SOHO router,
publicly downloadable firmware, coordinated disclosure only.

## Base rubric (archive-depth + payout + fit)

Each candidate is scored 1-5 on five weighted criteria:

| Criterion | Why it matters | Weight |
|-----------|----------------|:------:|
| **Firmware version depth** | Binary diffing across versions is the core funnel; need many public releases | ×3 |
| **Payout path** | Track 1 is the income track; a paid bounty beats credit-only | ×3 |
| **Realtek fit + MIPS/ARM match** | Must actually be Realtek SoC; matches the reversing specialization | ×2 |
| **Attack surface freshness** | Less picked-over targets yield novel findings | ×2 |
| **Clearance-safety narrative** | US vendor > allied for the "not-a-foreign-adversary-product" story | ×1 |

| Candidate | Ver. depth ×3 | Payout ×3 | Realtek fit ×2 | Freshness ×2 | Narrative ×1 | **Total** |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|
| Netgear (US) | 5 (15) | 4 (12) | 3 (6) | 3 (6) | 5 (5) | **44** |
| D-Link (Taiwan) | 5 (15) | 2 (6) | 5 (10) | 2 (4) | 3 (3) | **38** |
| Zyxel (Taiwan/NL) | 4 (12) | 3 (9) | 4 (8) | 4 (8) | 3 (3) | **40** |

The base rubric leaned Netgear on payout + narrative. But "payout path" and
"archive depth" say nothing about whether the **Realtek-specific** surface is
still alive, still patched, or already picked clean. That is what the freshness
pass below tests — and it partly reverses the lean.

## Freshness re-scoring (2026-09) — the correction to the Netgear lean

Freshness sub-signals, scored **Realtek-scoped**, not vendor-wide:
1. **Last-CVE recency** on models that actually use Realtek silicon.
2. **Patch liveness** — does a finding here still get a fix + credit/payout, or is the model EOL?
3. **Inverse saturation** — novelty headroom (a model already swarmed by Mirai/n-day is picked clean).

| Candidate (Realtek-scoped) | Last CVE on Realtek models | Patch liveness (payout viability) | Saturation / novelty | **Freshness 0-5** |
|---|---|---|---|:---:|
| Netgear Realtek entry-tier | **Stale** — 2026 CVEs cluster on Broadcom/Qualcomm Nighthawk/Orbi, not Realtek models | Low — Realtek models largely EOL | Moderate | **2** |
| D-Link DIR (RTL819x) | **Very recent** — CVE-2026-0625 (CVSS 9.3), active exploitation since Nov 2025 | Low — EOL, "no patches" (D-Link SAP10253) | Very low — Mirai/AryStinger already weaponized | **2** |
| Zyxel DSL/Ethernet CPE (Realtek-capable) | **Very recent** — CVE-2026-1459, advisory 2026-04-28 | **High** — active PSIRT still shipping patches | Moderate — less swarmed than D-Link | **4** |

### What freshness changes
- **Netgear's freshness is on the wrong silicon.** Its live CVE stream
  (CVE-2026-0403 Orbi RCE, CVE-2026-11814 Nighthawk/Orbi, CVE-2025-12945 R7000P)
  is Broadcom/Qualcomm. The Realtek Netgear models that satisfy the constraint
  are mostly EOL, so the Bugcrowd payout that made Netgear "primary" likely
  **does not cover them**. The base payout=4 was too generous for the Realtek subset.
- **D-Link Realtek is fresh in the wrong way.** High feed activity here is
  *exploitation*, not headroom — EOL + botnet-saturated = near-zero novel-finding
  and payout yield. Still excellent *diff fuel*.
- **Zyxel is the only fresh + still-patched + not-yet-swarmed option** — the best
  first target for landing a *new* finding with a live credit/payout path.

### Revised recommendation (freshness-adjusted)
1. **First fresh-finding target: Zyxel** — *conditional on confirming Realtek
   silicon in the specific model's firmware* (Zyxel CPE mix Realtek/Econet/
   Broadcom; confirm from the image per the SoC rule below). Only candidate with
   fresh surface + live vendor process + novelty headroom.
2. **Diff/learning + portfolio target: D-Link DIR (RTL819x)** — reframed from
   "volume income farm" to a **patch-diff / n-day-reproduction** target. EOL means
   no payout and duplicate risk, but it is superb diff fuel and a clean public
   writeup is still strong hiring signal. This is where the binary-diff Skill
   earns its keep first (vendor-agnostic, so it is built regardless).
3. **Demoted: Netgear-Realtek** — the payout narrative does not survive the
   freshness cut for EOL Realtek models.

### Constraint tension to flag (your call)
"Realtek-based" and "fresh + paid" pull in opposite directions: RTL819x lives
mostly in **older/EOL** gear (great diff fuel + learning, poor payout), while the
freshest actively-patched SOHO lines tend to run other silicon. Two resolutions,
your decision — I did **not** relax the stated constraint on my own:
- **(A) Hold Realtek strict** → the realistic first *income* shot is Zyxel-if-Realtek;
  D-Link-Realtek is a portfolio/patch-diff play, not a payout. Track 1 income
  expectation drops accordingly — stated honestly.
- **(B) Relax to "Realtek OR the vendor's actively-patched SOHO line"** → chase
  Zyxel/Netgear fresh models for payout, keep Realtek RTL819x as the reversing
  capstone. Better income odds, bends the constraint.

## Model selection — confirm the SoC from the firmware, not the spec sheet

Vendor spec pages are unreliable for SoC ID, and one model number often ships
multiple hardware revisions with different chips. The first hands-on step selects
the exact model by **confirming the silicon from the image itself** (applies to
Zyxel and D-Link alike):

1. Pull the model's public firmware version history; prefer **3+ releases** (diff fuel).
   Record every version + SHA-256.
2. `binwalk` the newest image; extract the rootfs.
3. Confirm the SoC from evidence in the image: bootloader/U-Boot strings (`rtl`,
   `RTL8`, `Realtek`, `rlx`/`lx` MIPS core), Realtek SDK paths, ELF `e_machine`
   (MIPS RTL819x vs ARM on newer RTL SoCs), endianness.
4. Confirm attack surface exists (`httpd`/`goahead`/`mini_httpd`, UPnP, custom
   CGI, TR-069, vendor daemons).
5. Only then lock the model and record it below.

## Working target

- **Vendor decision:** pending your (A)/(B) constraint call above.
- **Immediate diff-fuel target (tooling shakedown, no payout expectation):**
  a D-Link DIR RTL819x model with 3+ public releases — used to prove the
  binary-diff Skill and to produce the first patch-diff writeup while the
  Zyxel-vs-constraint decision is made.
- **Exact model:** fixed at P1.1 by the procedure above; recorded here with
  version list + hashes once acquired.

## Freshness evidence (as of 2026-09)

Public advisories / trackers consulted for the freshness pass (data, not endorsements):
- Netgear security advisories (Aug 2026, Dec 2025) — kb.netgear.com; CVE-2026-0403,
  CVE-2026-11814, CVE-2025-12945 (Nighthawk/Orbi — non-Realtek).
- D-Link: SAP10253 (Realtek RTL8xxx SDK), CVE-2026-0625 (dnscfg.cgi, exploited
  since 2025-11-27 per Shadowserver), CVE-2025-29635 (Mirai/D-Link), CVE-2019-16920.
- Zyxel: advisory 2026-04-28 (CPE command injection), CVE-2026-1459, CVE-2025-13943,
  CVE-2025-11845..11848.
