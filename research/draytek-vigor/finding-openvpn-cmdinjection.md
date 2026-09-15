# Finding (candidate CVE) — DrayTek Vigor300B `mainfunction.cgi` `download_ovpn` OS command injection (sanitizer bypass)

**Status:** confirmed at the code level via patch-diff + decompilation + disassembly.
Auth level and sanitizer behavior **resolved** (see the two corrections below). Novel —
no assigned CVE found for this endpoint (dedup below). PoC pending device/emulation.

> **Two corrections to the initial (pre-verification) write-up — verified this run:**
> 1. **Action name is `download_ovpn`, not `doOpenVPN`.** The action-dispatch table has
>    *both*: `doOpenVPN` (idx 37, handler `0x1e8b0`) is a different, unrelated handler.
>    The command-injection handler `FUN_0001e9d8` @ `0x1e9d8` is the target of action
>    **`download_ovpn`** (idx 41). The prompt/title had this right; the earlier finding
>    body mislabeled it.
> 2. **There IS a shell-metacharacter sanitizer.** The five params are *not* passed raw —
>    each is run through the in-place sanitizer `FUN_0000ad8c` before `system()`. The bug
>    is therefore an **incomplete-blocklist sanitizer bypass**, not an "unfiltered"
>    injection. This changes the mechanism and the severity story (see below).

## Summary
The `download_ovpn` handler in `www/cgi-bin/mainfunction.cgi` builds a shell command from
five user-supplied web parameters and passes it to `system()`. Each parameter is first run
through a shell-metacharacter sanitizer (`FUN_0000ad8c`) that replaces a **blocklist** of
characters with `+`. The blocklist is **incomplete** — it omits single `&`, `<`, `(`, `)`,
`{`, `}`, `,`, and `\` — which permits **space-less OS command injection** via `&` command
chaining and `{cmd,arg}` brace expansion. An attacker with a **valid authenticated
operator/admin session** executes arbitrary OS commands **as root** — **OS command
injection (CWE-78)**.

- **Vendor / product:** DrayTek Vigor300B (Linux/Comcerto, ARM:LE:32).
- **Component:** `www/cgi-bin/mainfunction.cgi`, action **`download_ovpn`**, handler `FUN_0001e9d8` @ `0x1e9d8`.
- **Injected parameters:** `remote_ip`, `protocal` (sic), `config_name`, `auto_dialout`, `redirect_gw`.
- **Sink:** `system("/etc/openvpn/create_client_conf.sh %s %s %s %s %s")` via `snprintf`.
- **Sanitizer:** `FUN_0000ad8c` @ `0xad8c` (in-place; see blocklist below).
- **Runs as:** **root** — `lighttpd` does not drop privileges (`server.username`/`server.groupname`
  are commented out in `etc/lighttpd/lighttpd.conf`).
- **Auth:** **post-authentication**, requires session privilege **level ≥ 4** (`operator` or `admin`/`root`).
- **Affected:** ≤ **v1.5.1.6** (bypassable). **Fixed:** **v1.5.1.7** — silently, by single-quoting the five `%s`.

## Evidence — the handler (v1.5.1.6, decompiled + disassembled)
`diff-out-dt/ghidra/action_table_1516.c`, `asm_sanitizer_1516.txt`.
```c
// FUN_0001e9d8  (handler for action "download_ovpn")
if (3 < FUN_00019164()) {                          // <-- AUTH GATE: session level > 3
    cgiGetValue(ctx,"remote_ip");     r8  = FUN_0000ad8c(val);   // sanitize IN PLACE, returns start ptr
    cgiGetValue(ctx,"protocal");      r?  = FUN_0000ad8c(val);
    cgiGetValue(ctx,"config_name");   r5  = FUN_0000ad8c(val);
    cgiGetValue(ctx,"auto_dialout");  r7  = FUN_0000ad8c(val);
    cgiGetValue(ctx,"redirect_gw");   r12 = FUN_0000ad8c(val);
    if (all five non-empty) {
        snprintf(buf, 0x100,
                 "/etc/openvpn/create_client_conf.sh %s %s %s %s %s",   // args already sanitized
                 r8, r?, r5, r7, r12);
        system(buf);                                                    // ← injection (via bypass)
        ...                                                             // then returns /tmp/openvpn/<config_name>
    }
}
```
The asm (`asm_sanitizer_1516.txt`) confirms the dataflow: `cgiGetValue → bl 0xad8c → cpy rN,r0`
for each param, then all five registers are formatted by `snprintf` (`bl 0xaa10`) and the
buffer is handed to `system` (`bl 0xa4b8`). `FUN_0000ad8c` copies its argument into `r2` and
never rewrites `r0`, so it returns the (now sanitized-in-place) original string pointer — i.e.
**the exact bytes passed to `system()` are the sanitized ones.**

## The sanitizer `FUN_0000ad8c` (@ `0xad8c`) and why it is bypassable
In-place; for each byte, if it is one of the **blocklisted** chars it is overwritten with `+`:
```
;  %  `  |  >  (space)  '  "  $  \t  \n  \r        and the two-char sequence  &&
```
**Not** blocklisted (survive to the shell): single `&`, `<`, `(`, `)`, `{`, `}`, `,`, `\`,
`*`, `?`, `[`, `]`, `#`, `~`, `!`. Because **space is blocklisted**, a payload must avoid
spaces — which is exactly what `&` (command separator, no space needed) and `{cmd,arg}`
(brace expansion → space-less arguments) provide.

**Candidate payloads** (any one of the 5 params; static-analysis-derived, PoC pending):
- No-arg command: `x&reboot` → `create_client_conf.sh x` backgrounded, then `reboot` runs.
- Arg-bearing command via brace expansion: `x&{telnetd,-l,/bin/sh,-p,9999}` →
  `telnetd -l /bin/sh -p 9999`.
- Because `'` is blocklisted, the **v1.5.1.7 single-quoting fix closes this**: inside `'...'`
  the surviving metacharacters are literal, and the only escape (`'`) is already replaced by `+`.

## Auth gate — RESOLVED: post-authentication (operator/admin, level ≥ 4)
`diff-out-dt/ghidra/auth_classify_1516.c`, `roles_1516.c`.

- The dispatcher (`FUN_000239b4`, `PATH_INFO==NULL` branch) reads the `action` CGI param,
  looks it up in a **137-entry × 12-byte action table** (`{name_ptr, handler, prolog}`, base
  `0x4440c`) via `FUN_0000b5cc`, then calls `prolog()` then `handler()`. **The dispatcher
  performs no auth check** — the gate is *inside* each handler.
- `download_ovpn`'s handler gates on `if (3 < FUN_00019164())`. `FUN_00019164` is the
  **session privilege resolver**, not an argument counter (the earlier misread):
  - reads `HTTP_COOKIE` (`SESSION_ID_VIGOR=<34 hex>`) and `REMOTE_ADDR`;
  - validates the session (`FUN_00018dd0` → `FUN_00018c90`, against `/var/session.json`);
  - returns the session's stored integer **`level`** (`FUN_00018590`).
  - Returns `1` in web-UI **"demo" mode** (`FUN_0000dd94`, matches uci `wui.system.mode == demo`),
    `-10` if no cookie, `-1` if the session is invalid. None of these satisfy `> 3`.
- **Privilege levels** are assigned at login (`FUN_0002c15c`) by role string:
  `root`/`admin` → **7**, `operator` → **4**, `user` → **1**, `sslvpnuser` → **3**.
- `download_ovpn` requires **level > 3**, i.e. **`operator` (4) or `admin`/`root` (7)** —
  a privileged, authenticated management account. `user` (1) and `sslvpnuser` (3) cannot reach it.

Contrast (confirms the gate is a real auth boundary): the pre-auth `captcha` handler
(`FUN_0000eec8`) contains **no** `FUN_00019164` gate at all; `login` calls it only *after*
establishing the session. The earlier "shares a prolog with captcha ⇒ maybe unauth" lead was
wrong — captcha's prolog is `0x12774`; `download_ovpn`'s `0xaff4` is shared with the
*download/backup* family, and the prolog is only a response-header emitter, never auth.

## The fix (v1.5.1.7)
Format string changed to `"/etc/openvpn/create_client_conf.sh '%s' '%s' '%s' '%s' '%s'"`
(single-quoted). Combined with the pre-existing `'`-in-blocklist, this neutralizes the
bypass. This is the security-relevant delta for this site in the `1.5.1.6 → 1.5.1.7` diff
(same single-quoting hardening also applied to the other `system()` sites — langs `mv`, apm,
`openvpn disconnect_from_web`, `passwd admin`).

## Severity (CVSS v3.1)
Post-auth, network-reachable, deterministic, root RCE:
`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2 (High)**.
- `PR:H`: requires an authenticated `operator`/`admin` management session (level ≥ 4).
- Sensitivity: if `operator` is argued to be a low-privilege role → `PR:L` = **8.8**; if the
  web→OS transition is scored `S:C` → higher still. Primary score **7.2**.

## Novelty (dedup gate)
No CVE found for the OpenVPN / `create_client_conf` / `download_ovpn` path across NVD,
OpenCVE (full `vigor300b_firmware` list), and DrayTek advisories. Known Vigor300B
`mainfunction.cgi` command-injection CVEs cover **different** endpoints:
`uploadlangs`/File (CVE-2026-3040), `apmcfgupload`/`apmcfgupptim`/session
(CVE-2024-12986/12987), `action` (CVE-2024-43027), `cvmcfgupload`/query-string
(CVE-2020-8515 / -15415 / 2021-43118). The reclassification (sanitizer *bypass*, post-auth)
does not match any of these. ⇒ **plausibly novel.**

## Validation (2026-09-14, re-verified from the shipped binaries)
Independently re-confirmed this run, not trusting the earlier decompile notes:
- **Sink delta** (binary `strings`): v1.5.1.6 `create_client_conf.sh %s %s %s %s %s`
  (unquoted) → v1.5.1.7 `'%s' '%s' '%s' '%s' '%s'`. The `openvpn disconnect_from_web`
  args were likewise unquoted→quoted, while `gretunnel`/`ssltunnel` were *already*
  quoted in 1.5.1.6 — the OpenVPN path was the un-hardened outlier.
- **Sanitizer blocklist** decoded byte-for-byte from the ARM disassembly of
  `FUN_0000ad8c`: blocks `; % ` `| > space ' " $ \t \n \r` and `&&`; a **single `&`**
  (and `< ( ) { } , \`) survives. Bypass confirmed at the instruction level.
- **Runs as root**: `server.username`/`server.groupname` commented out in
  `etc/lighttpd/lighttpd.conf`.
- **Novelty re-checked live** (NVD full Vigor300B list, OpenCVE, `master-abc/cve`):
  no CVE on the `download_ovpn`/`create_client_conf` path. Holds.
- Component hashes: vuln CGI `821d539c…`, fixed CGI `b5085e80…` (see `finding.json`).

## Open items before disclosure
1. **PoC on owned/emulated device.** Confirm one bypass payload (e.g. `remote_ip=x&reboot`,
   or a benign `&{touch,/tmp/poc}`) actually executes on ≤1.5.1.6 and is neutralized on
   1.5.1.7. Static analysis is strong but not a runtime demonstration. **[in progress —
   QEMU/FirmAE emulation]**
2. **Fan-out.** Grep the same `download_ovpn` + `create_client_conf.sh %s…` + `FUN_0000ad8c`
   pattern across other Vigor models' public firmware (2960 / 3900 / 165x / …). Many are
   **still supported** → higher impact, fixable, distinct affected products / CVEs. (Needs
   firmware downloads — a user-confirmed step.)
3. **`finding.json`** → `finding-to-vendor-report` (CVSS + PSIRT report) → DrayTek coordinated
   disclosure → `finding-to-cve-writeup` post-fix. **[DRAFTED this run]** — `finding.json`,
   `vendor-report.md` (7.2 High), `disclosure-email.txt`, `CVE-…RESERVED.json`, and the held
   `writeup-download_ovpn.md` are all in this directory. COI/outside-activity: cleared
   (independent, unattributed research; no disclosure bar). **Next human step: send the
   terse first contact to DrayTek PSIRT (`info@draytek.co.uk`), then the full report to the
   assigned contact (PGP).**

## Reproduction data (working, git-ignored under `diff-out-dt/`)
- `ghidra/action_table_1516.c` — full 137-entry action table + `download_ovpn` handler + session chain.
- `ghidra/auth_classify_1516.c` — `login` level assignment, `captcha` (pre-auth) contrast, session validator, `/var/session.json` model.
- `ghidra/roles_1516.c` — resolved role strings (`root`/`admin`/`operator`/`user`/`sslvpnuser`) and level constants.
- `ghidra/asm_sanitizer_1516.txt` — ARM disassembly proving the sanitizer is applied to the exact bytes reaching `system()`.
- `ghidra/{old_1516.c,new_1517.c,mainfunction_openvpn.diff}` — decompiled C + the 1.5.1.6→1.5.1.7 unified diff.
- Reusable headless scripts: `research/draytek-vigor/ghidra/{auth_probe,dump_action_table,dump_asm}.java`.
- Firmware provenance + hashes: `hashes.txt` / `acquisition-log.md`.
