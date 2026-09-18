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
| `mainfunction.cgi` **OpenVPN** — action **`download_ovpn`** / `FUN_0001e9d8` @0x1e9d8: `create_client_conf.sh %s×5` → `system()`; 5 web params (`remote_ip`,`protocal`,`config_name`,`auto_dialout`,`redirect_gw`) each run through the sanitizer `FUN_0000ad8c` (blocklist replaces `` ;%`\|>space'"$\t\n\r `` + `&&` with `+`) — **incomplete blocklist, bypassable** via single `&`/`<`/`{cmd,arg}` (space-less injection); silently single-quoted in 1.5.1.7 | **YES — CVE-2024-45890** (DrayTek Vigor**3900** 1.5.1.3, `mainfunction.cgi` `action=download_ovpn`, post-auth OS cmd injection, CVSS 8.0, pub. 2024-11-04). **Missed in the 2026-09-14 check** because that check was scoped to the `vigor300b_firmware` list and this CVE is filed under `vigor3900_firmware`. Corrected live 2026-09-18. | NVD, OpenCVE (vigor300b **and vigor3900**), DrayTek advisories, master-abc/cve, exploit-intel | **CONFIRMED (code-level) but n-day — NOT novel.** Same endpoint/class as CVE-2024-45890 on the sibling 3900. The 300B is not in that CVE's CPE list ⇒ **CPE coverage gap** (report as affected-product extension, not a new CVE). **Auth: post-auth, operator(4)/admin/root(7), level>3; runs as root** (lighttpd no priv-drop). Ghidra decompile+disasm in `diff-out-dt/ghidra/`; see [`finding-openvpn-cmdinjection.md`](finding-openvpn-cmdinjection.md). Real new-CVE path is now only the fan-out to still-supported, out-of-CPE, unpatched models. |
| `mainfunction.cgi` **OpenVPN disconnect** — `/etc/init.d/openvpn disconnect_from_web %s×3` (built by the OpenVPN web handler; single-quoted in 1.5.1.7 alongside `download_ovpn`) | **Yes — CVE-2024-45887** (Vigor3900 1.5.1.3, `mainfunction.cgi` **`action=doOpenVPN`**, post-auth OS cmd injection, CVSS 8.0, pub. 2024-11-04) | NVD/cyberstrike (CVE-2024-45887), OpenCVE | **n-day** — the OpenVPN handler surface is CVE'd via both `doOpenVPN` (45887) and `download_ovpn` (45890). |
| `mainfunction.cgi` **passwd helper** — `passwd admin "%s"` → `'%s'` in 1.5.1.7 | Within the `mainfunction.cgi` **action= command-injection family** exhaustively CVE'd 2024-11-04 (CVE-2024-45884…45893). Also cf. login CVE-2022-50994 (`formpassword`). | NVD/cyberstrike batch enum (45884–45893) | **n-day-class** — no differentiated novel-CVE survives; not individually pursued. |
| `activate.cgi` — changed in the 1.5.1.6→1.5.1.7 diff | **Yes — CVE-2020-10826** (`/cgi-bin/activate.cgi` remote cmd injection, DEBUG-mode; pre-1.5.1 surface) | NVD (CVE-2020-10826) | **n-day / pre-existing surface** — separate CGI with a prior CVE; not a novel lead. |

### Secondary dedup pass — 2026-09-18 (post run-3 close-out)
After capping run 3 as an n-day, the *other* silently-hardened `system()` sites in the
1.5.1.6→1.5.1.7 batch were deduped to test for residual novel headroom on the 300B.
Result: the DrayTek `mainfunction.cgi` post-auth command-injection surface is an
**exhaustively-enumerated CVE family** — CVE-2024-45884 through 45893 (Vigor3900 1.5.1.3,
each a distinct `action=`: setSWMGroup, autodiscovery_clear, doOpenVPN, set_ap_map_config,
commandTable, download_ovpn, delete_wlan_profile, setSWMOption, …; all CVSS 8.0, all pub.
2024-11-04) — which DrayTek closed by single-quoting the whole family. The OpenVPN sites
(`doOpenVPN` 45887, `download_ovpn` 45890), the WLAN/AP-map/SWM actions, and `activate.cgi`
(CVE-2020-10826) are all covered. **No novel-CVE lead survives on the 300B.** A new CVE
could still only come from the same pattern on a **still-supported, out-of-CPE, unpatched**
*other* Vigor model (background option; needs downloads) — not from the 300B itself.

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
