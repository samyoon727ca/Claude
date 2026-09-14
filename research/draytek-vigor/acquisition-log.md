# Acquisition Log — DrayTek Vigor

One row per firmware release acquired. Hashes recorded BEFORE analysis. SoC confirmed
from the image, not the spec sheet. See [`target-notes.md`](target-notes.md) for the
model + diff strategy.

## Model
- Model / hardware rev: **Vigor300B** (Linux CPE; `www/cgi-bin/mainfunction.cgi` on lighttpd)
- SoC (confirmed from image): **Mindspeed/Freescale Comcerto 1000** — from `ipkg`
  package `base-files-comcerto1000`, `/boot/uImage`, `lib/modules/2.6.33.5/*`.
- Arch / endianness: **ARM, ELF32, little-endian** — `readelf -h mainfunction.cgi` →
  `Class ELF32 · Data 2's complement little endian · Machine ARM`. ⇒ Ghidra `ARM:LE:32`.
- Kernel: **Linux 2.6.33.5**.
- Filesystem / container: DrayTek `.all` = 40 MB flash image; 0x30-byte DrayTek header
  (model `V3000`, version string e.g. `1.5.1.7_RC1`) then **UBI** (`UBI#` PEB headers at
  0x30, then every 0x20000) wrapping **UBIFS** volume `rootfs`. Extract: carve from
  offset 0x30 → `ubireader_extract_files` (pip `ubi_reader`, no sudo). ~2556 files.
- Web / attack surface: `lighttpd`; CGIs `www/cgi-bin/mainfunction.cgi`, `activate.cgi`;
  OpenVPN web config (`/etc/openvpn/create_client_conf.sh`), langs upload, apm upload.

## Firmware releases
Public archive: `https://fw.draytek.com.tw/Vigor300B/Firmware/` (index browsable; 13
versions v1.0.8.2 → v1.5.1.7). Acquired 2026-09-14 over HTTPS from that archive;
acquired-ZIP SHA-256 in [`hashes.txt`](hashes.txt). Each ZIP holds one `.all` (40,239,152 B).

| Version | Status | Source URL | ZIP size (B) | SoC confirmed? |
|---------|--------|------------|-------------:|:--------------:|
| v1.5.1.4 | vuln (CVE-2024-12987, apm) | fw.draytek.com.tw/Vigor300B/Firmware/v1.5.1.4/Vigor300B_v1.5.1.4.zip | 31,085,457 | pending extract |
| v1.5.1.5 | fix (apm) | .../v1.5.1.5/Vigor300B_v1.5.1.5.zip | 31,082,482 | pending extract |
| v1.5.1.6 | vuln (CVE-2026-3040, langs) | .../v1.5.1.6/Vigor300B_v1.5.1.6.zip | 31,085,211 | **yes ✓** (ARM/Comcerto) |
| v1.5.1.7 | latest (2026-09-03 build) | .../v1.5.1.7/Vigor300B_v1.5.1.7.zip | 31,184,319 | **yes ✓** (ARM/Comcerto) |

## Diff pairs run
| Old ver | New ver | diff-candidates top lead | likely_bug_side | notes |
|---------|---------|--------------------------|-----------------|-------|
| ▶ 1.5.1.6 | 1.5.1.7 | **`www/cgi-bin/mainfunction.cgi`** (score 13, reachable) | OLD (silent fix) | **String-diff shows command-injection hardening**: user args to `system()`-style commands changed from unquoted `%s` to single-quoted `'%s'` at multiple sites — `/etc/openvpn/create_client_conf.sh %s×5`, `/etc/init.d/openvpn disconnect_from_web %s×3`, `mv %s /www/langs/%s`, apm paths, and the `passwd admin` helper (`"%s"`→`'%s'`). `activate.cgi` also changed. Rest of changed.txt = lib rebuilds + ipkg/md5 metadata (noise). Ghidra confirm pending. |
| 1.5.1.4 | 1.5.1.5 | _pending_ | _pending_ | CVE-2024-12987 apm fix window |
| 1.5.1.5 | 1.5.1.6 | _pending_ | _pending_ | mid-window |

## Candidate dedup ledger (novelty gate)
| Candidate (binary:endpoint) | Existing CVE? | Source checked | Verdict |
|-----------------------------|---------------|----------------|---------|
| `mainfunction.cgi` **langs** — `uploadlangs`/File → `mv %s /www/langs/%s` cmd injection | **Yes — CVE-2026-3040** (Vigor300B ≤1.5.1.6, `cgiGetFile`/uploadlangs, published 2026-02-23, CVSS 4.7; vendor "EoL, won't fix" — yet silently quoted in 1.5.1.7) | NVD, OpenCVE, cyberstrike | **n-day** |
| `mainfunction.cgi` **apm** — apmcfgupload/apmcfgupptim/session | Yes — CVE-2024-12986/12987 (1.5.1.4→fixed 1.5.1.5) | OpenCVE | **n-day** |
| `mainfunction.cgi` **OpenVPN** — action **`download_ovpn`** / `FUN_0001e9d8` @0x1e9d8: `create_client_conf.sh %s×5` → `system()`; 5 web params (`remote_ip`,`protocal`,`config_name`,`auto_dialout`,`redirect_gw`) each run through the sanitizer `FUN_0000ad8c` (blocklist replaces `` ;%`\|>space'"$\t\n\r `` + `&&` with `+`) — **incomplete blocklist, bypassable** via single `&`/`<`/`{cmd,arg}` (space-less injection); silently single-quoted in 1.5.1.7 | **None found** — no OpenVPN/create_client_conf/download_ovpn CVE across NVD/OpenCVE (vigor300b_firmware full list)/DrayTek advisories (known 300B mainfunction.cgi CVEs cover langs, apm, action, cvmcfgupload, query-string only) | NVD, OpenCVE, DrayTek advisories, master-abc/cve | **CONFIRMED (code-level) + NOVEL** — Ghidra decompile+disasm (see [`finding-openvpn-cmdinjection.md`](finding-openvpn-cmdinjection.md)). **Auth RESOLVED: post-auth, operator(4)/admin/root(7), level>3; runs as root** (lighttpd no priv-drop). Sev ~7.2 High (`PR:H`). Corrections vs first pass: action is `download_ovpn` not `doOpenVPN`; a sanitizer IS present (bypass, not "unfiltered"). PoC + fan-out + vendor report pending. |

## Fan-out (volume multiplier)
| Vulnerable pattern | Other DrayTek Vigor models sharing it | Confirmed? |
|--------------------|---------------------------------------|:----------:|
| OpenVPN web-config → `create_client_conf.sh` unquoted args in `mainfunction.cgi` | Vigor OpenVPN web config is broad across the Linux line (2960/3900/165x/…); many still supported (≠ EoL 300B) → higher-impact, fixable, CVE-worthy | pending (grep the same CGI across models' public firmware) |

## Next steps
1. ~~**Ghidra decompile-diff** `mainfunction.cgi` 1.5.1.6 vs 1.5.1.7 + confirm the auth gate.~~
   **DONE (run 3).** Command built by `FUN_0001e9d8` (`download_ovpn`); 5 web params confirmed;
   guarded by the sanitizer `FUN_0000ad8c` (not `cgiEscape`) — an **incomplete blocklist that is
   bypassable**; **auth = post-auth `operator`/`admin` (level > 3)**; runs as **root**. See
   [`finding-openvpn-cmdinjection.md`](finding-openvpn-cmdinjection.md) and `diff-out-dt/ghidra/`.
2. **PoC** a bypass payload (e.g. `remote_ip=x&reboot`, or benign `&{touch,/tmp/poc}`) on an
   owned/emulated ≤1.5.1.6 device; confirm 1.5.1.7 neutralizes it. (Static analysis only so far.)
3. **Fan-out** grep the same pattern across other Vigor models' public firmware (needs downloads —
   user-confirmed); then `finding-to-vendor-report` (CVSS + PSIRT) → DrayTek coordinated disclosure
   (COI / outside-activity disclosure obligations handled FIRST, per `docs/disclosure-policy.md`).
