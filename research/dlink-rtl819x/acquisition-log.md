# Acquisition Log — D-Link RTL819x

Fill during P1.1. One row per firmware release acquired. Hashes recorded BEFORE
analysis. SoC confirmed from the image, not the spec sheet.

## Model
- Model / hardware rev: **DIR-816L Rev B** (locked as P1.1 first target)
- SoC (confirmed from image): **Realtek RTL819x family** — kernel exports `rtl865x_*`
  (RTL819x switch/VLAN/ACL) and `rtl8192cd_*` (WiFi); CPU reports `RLX 32BIT`
  (Realtek Lexra-derived MIPS core). Confirmed from the decompressed kernel, not the spec sheet.
- Arch / endianness: **MIPS32, big-endian (MSB) · o32 ABI · MIPS1/R3000** — confirmed from
  the userspace ELFs post-extraction (`readelf -h htdocs/cgibin` → `Data: 2's complement,
  big endian`, `Machine: MIPS R3000`). NOTE: the rootfs squashfs magic `hsqs` is **not** an
  endianness signal — squashfs 4.0 is always little-endian on-disk regardless of target CPU;
  an earlier LE call (inferred from `hsqs`) was **corrected to BE** once the binaries were extracted.
  ⇒ Ghidra `MIPS:BE:32`; emulation `qemu-mips-static` (big-endian).
- Filesystem type: **SEAMA container** (magic `0x5ea3a417`, meta
  `signature=wrgac14_dlob.hans_dir816l`) → **LZMA-alone kernel @0x70** (Linux 2.6.30.9,
  Realtek gcc 4.4.5) → **squashfs v4.0, compression id 2 = LZMA @0x180090**. NOTE: squashfs
  4.0 + LZMA(2) is the *non-standard* Realtek/firmware-mod-kit variant → stock `unsquashfs`
  will reject it; **`sasquatch` required** for rootfs extraction.
- Flash map (from kernel cmdline): `root=/dev/mtdblock7 mtdparts=flash_bank_1:64k(u-boot)ro,
  64k(mfcdata),64k(devconf),128k(langpack),64k(caldata),512k(mydlink),15296k(upgrade),16m@0(rootfs)ro`
- Web server / attack-surface daemons observed: _pending rootfs extraction_ (compressed inside squashfs)
- Fingerprint method: SEAMA/LZMA/squashfs parsed + LZMA kernel decompressed in Python
  (no binwalk/sasquatch on the acquisition host); see `docs/track1-acquisition-runbook.md` §3.

## Firmware releases
Acquired 2026-09-10 from D-Link's public legacy server over plain HTTP; validated
by byte-count vs. directory listing + ZIP/PDF magic + `unzip -t`. Full SHA-256
manifest (acquired ZIP **and** inner `.bin`): [`hashes.txt`](hashes.txt).
Source date = server Last-Modified (upload proxy, not original release date).

| Version | Src date | Official source URL | Inner .bin (SHA-256, short) | SoC confirmed? | Notes |
|---------|----------|---------------------|-----------------------------|:--------------:|-------|
| 2.00B01 | 2019-06-18 | legacyfiles.us.dlink.com/DIR-816L/REVB/FIRMWARE/DIR-816L_REVB_FIRMWARE_2.00B01.ZIP | `fa13f443` (7,426,192 B) | pending | Earliest release available here |
| 2.01B03_WW | 2019-06-18 | .../FIRMWARE/DIR-816L_REVB_FIRMWARE_2.01B03_WW.ZIP | `84fc9a3d` (7,422,096 B) | pending | WW (worldwide) build |
| 2.03B03 | 2019-06-18 | .../FIRMWARE/DIR-816L_REVB_FIRMWARE_2.03B03.ZIP | `3854089a` (7,532,688 B) | pending | |
| 2.05.B02 | 2019-06-18 | .../FIRMWARE/DIR-816L_REVB_FIRMWARE_2.05.B02.ZIP | `89b4a76d` (7,536,784 B) | **yes ✓** | Last non-"patch" firmware; inner file named `.bin.bin` (vendor quirk). Kernel build `#1 2014-09-11` |
| 2.06.B01 (patch) | 2020-02-07 | .../SECURITY_PATCHES/DIR-816L_REVB_FIRMWARE_PATCH_2.06.B01.ZIP | `fccdbdbd` (7,536,784 B) | **yes ✓** | **Security patch. Same image size as 2.05.B02, different hash → surgical in-place fix.** Kernel build `#2 2015-03-10` |
| 2.06.B09 (patch) | 2020-02-07 | .../SECURITY_PATCHES/DIR-816L_REVB_FIRMWARE_PATCH_2.06.B09.ZIP | `8a3ead65` (7,557,264 B) | pending | Later security patch; `_beta` build |

Vendor release/patch notes (the *claimed* changelog, for silent-fix cross-check)
downloaded to `firmware/DIR-816L-REVB/notes/` — 6 PDFs (1.00B09, 2.01B03, 2.03B03,
2.05.B02, and patch notes 2.06.B01 / 2.06.B09). Hashes in `hashes.txt`.

## Diff pairs run
Planned pairs (▶ = highest-priority silent-fix lead). Fill results after `fw_diff.py`.

| Old ver | New ver | diff-candidates top lead | likely_bug_side | notes |
|---------|---------|--------------------------|-----------------|-------|
| ▶ 2.05.B02 | 2.06.B01 | **`cgibin!hnap_main`** | OLD (silent fix) | **CONFIRMED (Ghidra headless, MIPS:BE:32).** OLD does `system("sh /etc/templates/hnap/<method>.sh > /dev/console")` where `<method>` = tail of the attacker-controlled `HTTP_SOAPACTION` header (text after last `/`); the `GetDeviceSettings` substring (matched by `strstr`) **bypasses auth** → **unauthenticated blind OS command injection (CWE-78)**. NEW fixes it by adding `access("/etc/templates/hnap/<method>.php")` and only proceeding if that template exists. Surfaced by: new `access()` import + `"%s/%s.php"` + HNAP URL; `.text` +144 B. Dedup ↓ = **n-day (CVE-2015-2051 class)**. |
| 2.06.B01 | 2.06.B09 | **`htdocs/cgibin`** (score 18) | OLD (silent fix) | b09 adds SOAP/multipart + SSDP validation to the HNAP handler (new strings `Got illegal Soap request from %s!!`, `MPFD_INVALID_CONTENT`, `invalid M-SEARCH request`; +8 syms) and client-side login encryption (`+htdocs/phplib/encrypt.php`, `+web/js/AES.js`, `+etc/defnodes/S90sessions_privatekey.php`). Hardening of request parsing around the same cgibin that held the HNAP n-day. Dedup pending; b09 is a beta. Likely n-day/hardening. |
| 2.03B03 | 2.05.B02 | **`htdocs/phplib/fatlady/DDNS4.INF.php`** (score 15) | OLD (silent fix) | 2.05.B02 adds `verify_ddns4_url()` — a char-allowlist validator on the DDNS **provider** URL that 2.03B03 lacks; provider is consumed by `usr/sbin/ddnsd` (builds HTTP update requests; refs `system`). Shape of a silently-fixed DDNS provider injection; `tools_ddns.php` UI also changed. Dedup pending — D-Link DDNS is a CVE-dense class → likely n-day. |
| 2.00B01 | 2.03B03 | `usr/sbin/dnsmasq` (53), `usr/bin/minidlna` (42) | OLD (nominal) | Top rows are **upstream package version bumps** (recompiled/stripped: 247 / 346 syms removed) — upstream-CVE territory, not D-Link-authored fixes. D-Link-side changes are fatlady/service PHP (`ACCESSCTRL.php`, `DNS.php`, UPnP `AddPortMapping`) — low signal. No strong D-Link silent-fix lead in this window. |

**Sweep summary (2026-09-14):** all four planned diff pairs are now run. Beyond the
confirmed HNAP n-day (2.05.B02→2.06.B01), the sweep surfaces two further D-Link-authored
silent fixes — the **DDNS provider URL validator** (2.03B03→2.05.B02) and **cgibin SOAP/SSDP
hardening** (2.06.B01→2.06.B09) — plus upstream package bumps (noise). Both remaining leads
fit known DIR-series bug classes on an EOL line; novelty is unconfirmed and the base rate is
n-day. Per the target-selection re-prioritization, the **novel-CVE** effort belongs on the
Zyxel run; these D-Link leads are portfolio / n-day-study material unless dedup shows otherwise.

## Candidate dedup ledger (novelty gate)
| Candidate (binary:function) | Existing CVE? | Source checked | Verdict (novel / n-day) |
|-----------------------------|---------------|----------------|-------------------------|
| `cgibin!hnap_main` — HNAP `SOAPAction` → `system()` cmd injection (unauth via `GetDeviceSettings`) | **Yes — CVE-2015-2051 class** (HNAP GetDeviceSettings cmd injection). Metasploit `exploit/linux/http/dlink_hnap_header_exec_noauth`; Mirai/Goldoon-weaponized; D-Link HNAP advisory 2015-04-13 | NVD (CVE-2015-2051), D-Link SAP10169 + 2015 HNAP advisory, Rapid7/Exploit-DB (37171), Tenable/Nessus 84086 | **n-day** — known class, not novel. Portfolio/n-day-reproduction only; no new CVE. |

## SDK fan-out (volume multiplier)
| Vulnerable pattern | Other D-Link RTL819x models sharing it | Confirmed? |
|--------------------|----------------------------------------|:----------:|
|                    |                                        |            |
