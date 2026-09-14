# Finding (candidate CVE) — DrayTek Vigor300B `mainfunction.cgi` `doOpenVPN` OS command injection

**Status:** confirmed at the code level via patch-diff + decompilation; **auth gate pending**
final confirmation (dispatcher). Novel — no assigned CVE found (dedup below).

## Summary
The `doOpenVPN` handler in `www/cgi-bin/mainfunction.cgi` (the OpenVPN client-config
download feature) builds a shell command from five user-supplied web parameters and
passes it to `system()` **without any escaping, quoting, or metacharacter filtering**.
An attacker who can reach this action executes arbitrary OS commands as the CGI user
(root) — **OS command injection (CWE-78)**.

- **Vendor / product:** DrayTek Vigor300B (Linux/Comcerto, ARM).
- **Component:** `www/cgi-bin/mainfunction.cgi`, action `doOpenVPN`, handler `FUN_0001e9d8` @ `0x1e9d8`.
- **Injected parameters:** `remote_ip`, `protocal` (sic), `config_name`, `auto_dialout`, `redirect_gw`.
- **Sink:** `/etc/openvpn/create_client_conf.sh <p1> <p2> <p3> <p4> <p5>` via `snprintf`→`system()`.
- **Affected:** ≤ **v1.5.1.6** (present unquoted). **Fixed:** **v1.5.1.7** (2026-09-03 build) — silently, by single-quoting the five `%s`.

## Evidence (decompiled, v1.5.1.6 — vulnerable)
```c
// FUN_0001e9d8  (handler for action "doOpenVPN")
iVar2 = FUN_00019164();                       // arg count / presence
if (3 < iVar2) {
    cgiGetValue(*ctx, "remote_ip");     iVar3 = value();
    cgiGetValue(*ctx, "protocal");      iVar4 = value();
    cgiGetValue(*ctx, "config_name");   iVar5 = value();
    cgiGetValue(*ctx, "auto_dialout");  iVar6 = value();
    cgiGetValue(*ctx, "redirect_gw");   iVar7 = value();
    if (all five non-empty) {
        snprintf(buf, 0x100,
                 "/etc/openvpn/create_client_conf.sh %s %s %s %s %s",   // UNQUOTED
                 iVar3, iVar4, iVar5, iVar6, iVar7);
        system(buf);                                                    // ← injection
        ...
        snprintf(fn, 0x40, "/tmp/openvpn/%s", iVar5);   // config_name also here
        // then returns the generated file as an attachment
    }
}
```
No `cgiEscape()` (which is HTML-only anyway) and no shell-metachar filtering is applied
to any of the five values before `system()`. A value such as `config_name` containing a
shell metacharacter breaks out of the command.

## The fix (v1.5.1.7)
Format string changed to `"/etc/openvpn/create_client_conf.sh '%s' '%s' '%s' '%s' '%s'"`
(single-quoted). This is the entire security-relevant delta for this site in the
`1.5.1.6 → 1.5.1.7` diff (confirmed by string + decompilation diff).

## Novelty (dedup gate)
No CVE found for the OpenVPN / `create_client_conf` / `doOpenVPN` path across NVD,
OpenCVE (full `vigor300b_firmware` list), and DrayTek advisories. Known Vigor300B
`mainfunction.cgi` command-injection CVEs cover **different** endpoints:
`uploadlangs`/File (CVE-2026-3040), `apmcfgupload`/`apmcfgupptim`/session
(CVE-2024-12986/12987), `action` (CVE-2024-43027), `cvmcfgupload`/query-string
(CVE-2020-8515 / -15415 / 2021-43118). ⇒ **plausibly novel.**

## Open items before disclosure
1. **Auth gate (severity driver).** Locate the dispatcher that routes `doOpenVPN` →
   `FUN_0001e9d8` and confirm whether a valid session is required. `mainfunction.cgi`
   has both unauth and post-auth actions historically. Unauth → CVSS ~9.8 (critical);
   post-auth admin → ~7.2 (high) / medium, like CVE-2026-3040. (Ghidra xref pass on
   `FUN_0001e9d8`.)
2. **Fan-out.** Grep the same `doOpenVPN` + `create_client_conf.sh %s…` pattern across
   other Vigor models' public firmware (2960 / 3900 / 165x / …). Many are **still
   supported** (unlike EoL 300B) → higher impact, fixable, and distinct affected
   products / CVEs.
3. **PoC** (owned/emulated device only) and **`finding.json`** → `finding-to-vendor-report`
   (CVSS + PSIRT report) → DrayTek coordinated disclosure → `finding-to-cve-writeup`.

## Reproduction data (working, git-ignored)
`diff-out-dt/ghidra/{old_1516.c,new_1517.c,mainfunction_openvpn.diff}` — decompiled C
and the unified diff. Firmware provenance + hashes in `hashes.txt` / `acquisition-log.md`.
