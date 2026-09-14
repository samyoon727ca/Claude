# Acquisition Log — DrayTek Vigor

Fill during the run. One row per firmware release acquired. Hashes recorded BEFORE
analysis. SoC confirmed from the image, not the spec sheet. See
[`target-notes.md`](target-notes.md) for the model + diff strategy.

## Model
- Model / hardware rev: **Vigor300B** (primary; Linux CPE, `mainfunction.cgi` lineage)
- SoC (confirmed from image): _pending extraction_
- Arch / endianness: _pending extraction (DrayTek Linux CPE = MIPS/ARM — confirm)_
- Filesystem type / container: _pending (DrayTek `.zip` → `.all`/`.rst` payload; FS TBD)_
- Web server / attack-surface daemons observed: _pending_

## Firmware releases
Public archive: `https://fw.draytek.com.tw/Vigor300B/Firmware/` (index browsable;
13 versions v1.0.8.2 → v1.5.1.7). URLs + sizes below verified 2026-09-14 by HEAD
request. Record inner-payload SHA-256 after download, before analysis.

| Version | Status | Source URL | ZIP size (B) | SHA-256 | SoC confirmed? |
|---------|--------|------------|-------------:|---------|:--------------:|
| v1.5.1.4 | vuln (CVE-2024-12987) | fw.draytek.com.tw/Vigor300B/Firmware/v1.5.1.4/Vigor300B_v1.5.1.4.zip | 31,085,457 | _pending_ | pending |
| v1.5.1.5 | fix #1 | .../v1.5.1.5/Vigor300B_v1.5.1.5.zip | 31,082,482 | _pending_ | pending |
| v1.5.1.6 | still-vuln (Feb-2026 report) | .../v1.5.1.6/Vigor300B_v1.5.1.6.zip | 31,085,211 | _pending_ | pending |
| v1.5.1.7 | latest (likely Feb-2026 fix) | .../v1.5.1.7/Vigor300B_v1.5.1.7.zip | 31,184,319 | _pending_ | pending |

(Earlier versions v1.0.8.2 … v1.5.1.3 also public if wider baseline drift is wanted.)

## Diff pairs run
| Old ver | New ver | diff-candidates top lead | likely_bug_side | notes |
|---------|---------|--------------------------|-----------------|-------|
| ▶ 1.5.1.6 | 1.5.1.7 |                          |                 | Freshest window (Feb-2026 fix) — highest novelty priority |
| 1.5.1.4 | 1.5.1.5 |                          |                 | CVE-2024-12987 fix + any siblings fixed alongside |
| 1.5.1.5 | 1.5.1.6 |                          |                 | Mid-window drift |

## Candidate dedup ledger (novelty gate)
| Candidate (binary:function) | Existing CVE? | Source checked | Verdict (novel / n-day) |
|-----------------------------|---------------|----------------|-------------------------|
|                             |               |                |                         |

## Fan-out (volume multiplier)
| Vulnerable pattern | Other DrayTek Vigor models sharing it | Confirmed? |
|--------------------|---------------------------------------|:----------:|
|                    |                                       |            |
