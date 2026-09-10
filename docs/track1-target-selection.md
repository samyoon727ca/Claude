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

## Objective reorder (user directive, 2026-09): CVE volume + portfolio over payout

Constraint decision **(B)** is adopted: "Realtek **or** the vendor's actively-
patched SOHO line." And the first target is now optimized for **CVE volume +
portfolio strength**, not payout path. That reorders the ranking:

- **Payout drops out.** Confirmed: **Zyxel runs no bug bounty - credit only**
  (PSIRT `security@zyxel.com.tw`, CNA since 2021). D-Link is likewise credit /
  Hall-of-Thanks, no cash on consumer gear. Under the reordered objective this is
  fine: the first target is explicitly **not** an income play - credit + writeups.
- **Saturation becomes the enemy** (a picked-clean model yields duplicates, not
  CVEs); **CVE-assignment cadence + novel surface become the prize.**

### First target: **D-Link** (primary CVE-volume engine)
- **Why volume:** ~245 severe D-Link router CVEs over a decade (~2 serious
  remotely-exploitable/month), and a prolific CNA still assigning through 2026.
  No other US/allied SOHO vendor converts findings->CVEs at this rate.
- **Why portfolio:** Realtek RTL819x = MIPS, squarely the stated specialization;
  deep SDK firmware history (`rtl819x-SDK v3.2.x -> v3.4T-CT`) = excellent diff fuel.
- **The volume lever that beats saturation:** RTL819x bugs live in the shared
  **Realtek SDK**, so one silently-patched root cause commonly spans *many*
  D-Link models -> one finding can map to multiple affected models / CVEs. That
  is how an EOL, well-researched platform still yields net-new assignments: hunt
  **silent (unassigned) SDK-level fixes** via diffing, then enumerate the fan-out.
- **Honest caveat:** the confirmed-Realtek D-Link models (DIR-816L, DIR-850L,
  DIR-820L, DIR-818Lx, DIR-817Lx, DWR-118) are EOL and heavily researched.
  Duplicate risk is real -> every candidate goes through a mandatory
  **NVD/advisory dedup check** before it counts as novel (see the runbook). That
  discipline is what keeps a "volume" strategy honest.

### Complement: **Zyxel** (novelty, cleaner CVEs)
Fresher, less-swarmed, active CNA credit. Lower total volume than D-Link but
higher *novel* yield per finding. Rotate in when D-Link candidates dedup as
known. Under (B), also the route to actively-patched surface off RTL819x.

### Demoted: Netgear
Its cash bounty is irrelevant to the reordered objective, and its fresh surface
is non-Realtek. Off the first-target board.

## Working target (locked)

- **Vendor:** D-Link (primary), Zyxel (novelty complement). Both credit-only.
- **Model bracket (confirm SoC from image):** a D-Link RTL819x model with 3+
  public firmware releases - **DIR-816L** primary candidate, **DIR-850L** /
  **DIR-820L** alternates - for the funnel shakedown + first SDK-level patch-diff.
  Exact model fixed at P1.1 acquisition.
- **Execution note:** P1.1 hands-on acquisition/extraction runs on an
  unrestricted host - this remote sandbox's network policy blocks vendor firmware
  hosts (403) and lacks squashfs extractors. See
  `track1-acquisition-runbook.md`; version list + hashes + confirmed SoC land in
  `research/dlink-rtl819x/acquisition-log.md`.

## Freshness evidence (as of 2026-09)

Public advisories / trackers consulted for the freshness pass (data, not endorsements):
- Netgear security advisories (Aug 2026, Dec 2025) — kb.netgear.com; CVE-2026-0403,
  CVE-2026-11814, CVE-2025-12945 (Nighthawk/Orbi — non-Realtek).
- D-Link: SAP10253 (Realtek RTL8xxx SDK), CVE-2026-0625 (dnscfg.cgi, exploited
  since 2025-11-27 per Shadowserver), CVE-2025-29635 (Mirai/D-Link), CVE-2019-16920.
- Zyxel: advisory 2026-04-28 (CPE command injection), CVE-2026-1459, CVE-2025-13943,
  CVE-2025-11845..11848.
