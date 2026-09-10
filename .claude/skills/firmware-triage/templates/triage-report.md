# Firmware Triage Report — <VENDOR> <MODEL> <VERSION>

| Field | Value |
|-------|-------|
| Vendor / model / HW rev | |
| Firmware version | |
| Image SHA-256 | |
| Source (public URL) | |
| SoC / arch / endianness | (confirmed from image) |
| Filesystem type | |
| Analyst / date | |

## 1. Summary (one screen)
> 2-4 sentences: what this device is, what the reachable attack surface looks
> like, and the single most promising lead.

## 2. Confirmed sensitive-file findings
> Facts from the image, not leads. Hardcoded creds, fleet-wide TLS/private keys,
> backdoor accounts, world-writable sensitive files. Note severity implication.

| Finding | Path | Why it matters |
|---------|------|----------------|
| | | |

## 3. Reachable attack surface
> From services.txt. Which daemons start at boot and are network-reachable by
> default; which are pre-auth vs post-auth.

| Service | Binary | Default-on? | Pre-auth? |
|---------|--------|-------------|-----------|
| | | | |

## 4. Ranked reverse-engineering candidates
> From sinks.csv, cross-referenced with the reachable surface. Top 5-10 only.

| Rank | Binary/script | Score | Sinks | Reachable? | Why review first |
|------|---------------|-------|-------|-----------|------------------|
| 1 | | | | | |

## 5. Analyst first-look plan
> The ordered plan: what to open in Ghidra, what taint path to prove, what to set
> up in emulation. This is the judgment layer the scripts do not produce.

## 6. Notes for diffing / next version
> Anything to compare against another firmware version (changed daemons, new CGI,
> removed strings) for the binary-diff skill.
