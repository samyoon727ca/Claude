# Coverage-gap notice: CVE-2024-45890 also affects DrayTek Vigor300B (`mainfunction.cgi` `download_ovpn` OS command injection)

**To:** DrayTek PSIRT (and, for the affected-product record, the CVE's assigning CNA)
**Researcher:** Samuel Yoon (contact: samyoon727ca@gmail.com)
**Existing CVE:** **CVE-2024-45890** — `cgi-bin/mainfunction.cgi` `action=download_ovpn`, post-authentication OS command injection (published 2024-11-04, assigned on DrayTek Vigor3900)
**Vulnerability type:** OS command injection via incomplete-blocklist sanitizer bypass (CWE-78; contributing CWE-184)

> **This is NOT a new-vulnerability disclosure.** The bug is already public as
> CVE-2024-45890 and is already fixed. This notice reports an **affected-product /
> CPE coverage gap**: the same `download_ovpn` command injection is present on the
> **Vigor300B** (≤ 1.5.1.6, fixed 1.5.1.7), which does not appear in CVE-2024-45890's
> affected-products list. Because the bug is public and patched, there is no embargo.
> The requested action is to extend the existing CVE's affected list — not to assign
> a new CVE.

## What is being reported
CVE-2024-45890 documents a post-authentication OS command injection in DrayTek's
`mainfunction.cgi` reachable via `action=download_ovpn`, assigned against the
**Vigor3900**. The Vigor300B / Vigor2960 / Vigor3900 share the same `mainfunction.cgi`
codebase. Patch-diffing the Vigor300B's public firmware chain confirms the **same bug
on the Vigor300B**, silently fixed in v1.5.1.7 — but the 300B is not listed on the CVE.
This notice supplies the code-level confirmation so the affected-products record can
be corrected.

## Affected products (proposed correction to CVE-2024-45890)

| Model | Status in CVE-2024-45890 today | Reality (this analysis) |
|-------|-------------------------------|-------------------------|
| Vigor3900 | listed (affected) | affected — original CVE target |
| **Vigor300B** | **not listed** | **affected ≤ 1.5.1.6; fixed 1.5.1.7** (Linux/Comcerto, ARM ELF32 LE) — vulnerable CGI SHA-256 `821d539ccab6c90aa5d39d859a6526c2da2cca92c6f551acfa91fccc9430b958`, fixed CGI SHA-256 `b5085e80b797bad690abd5866178f06c1f56ff6b817ecfe355aada5ae176a3ec` |
| Vigor2960 | not listed | shares the codebase — worth the vendor confirming (not analyzed here) |

## Technical confirmation (Vigor300B v1.5.1.6)
The `download_ovpn` handler (`FUN_0001e9d8` @ `0x1e9d8`) constructs a shell command
from five attacker-controlled HTTP parameters — `remote_ip`, `protocal` (vendor
spelling), `config_name`, `auto_dialout`, `redirect_gw` — via `snprintf` into
`"/etc/openvpn/create_client_conf.sh %s %s %s %s %s"` and executes it with `system()`.
Each parameter first passes through an in-place sanitizer (`FUN_0000ad8c` @ `0xad8c`)
that replaces a blocklist of shell metacharacters — `` ; % ` | > space ' " $ `` tab
newline CR and the two-character sequence `&&` — with `+`. The blocklist is
**incomplete**: a single `&` and the characters `< ( ) { } , \` survive to the shell
(decoded directly from the ARM disassembly). Because the space character *is* blocked,
injection uses `&` (a separator needing no space) and brace expansion `{cmd,arg}`
(space-less arguments). `lighttpd` does not drop privileges
(`server.username`/`server.groupname` commented out in `etc/lighttpd/lighttpd.conf`),
so injected commands run as **root**. The handler is gated on session privilege
`level > 3` — an authenticated **operator (4)** or **admin/root (7)** session.

## Steps to reproduce (Vigor300B ≤ 1.5.1.6)
1. Authenticate to the web-management interface with an operator- or admin-level
   account (session privilege level ≥ 4).
2. Submit `action=download_ovpn` to `/cgi-bin/mainfunction.cgi` with all five
   parameters (`remote_ip`, `protocal`, `config_name`, `auto_dialout`, `redirect_gw`)
   non-empty.
3. Place a space-less **benign** payload in any of the five, e.g.
   `remote_ip=x&{touch,/tmp/poc}`.
4. The sanitizer preserves the `&` and the brace group; `snprintf` builds the command
   and `system()` executes it as root (creates root-owned `/tmp/poc`).
5. On v1.5.1.7 the identical input is inert — the five `%s` are single-quoted and `'`
   is already in the sanitizer blocklist.

## Severity
This 300B instance scores **7.2 (High)** — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
(post-authentication operator/admin → root). For reference, CVE-2024-45890's assigner
scores the Vigor3900 instance at 8.0; the affected-product correction does not change
the vulnerability class or root cause.

## Suggested action
1. Add **Vigor300B ≤ 1.5.1.6 (fixed 1.5.1.7)** to CVE-2024-45890's affected-products
   list, and confirm/deny the **Vigor2960** on the same basis.
2. Defense-in-depth beyond the applied single-quoting fix: replace `system()`/shell
   with an `execv()`-style call (no shell); allowlist each parameter by type rather
   than denylisting metacharacters; run the CGI under a non-root least-privilege
   account; and audit the sibling `system()` sites hardened in v1.5.1.7
   (`openvpn disconnect_from_web`, the langs `mv`, the `passwd` helper) for
   completeness across the Vigor line.

## Discovery
Version-to-version binary diff of the public firmware chain (v1.5.1.6 → v1.5.1.7,
acquired over HTTPS from `fw.draytek.com.tw`) flagged the silent single-quoting of the
`create_client_conf.sh` command line; the vulnerable v1.5.1.6 path was confirmed via
Ghidra decompilation + ARM disassembly (the incomplete blocklist decoded from
`FUN_0000ad8c`). An initial 300B-scoped dedup missed CVE-2024-45890 (filed under
`vigor3900_firmware`); a wider re-check on 2026-09-18 mapped the finding to that CVE —
hence this coverage-gap notice rather than a new-CVE request. Full case study:
`writeups/draytek-vigor300b-download_ovpn-cmdinjection.md`.

---
*Reported as an affected-product correction to a public, already-fixed CVE. No embargo;
happy to provide the decompilation/disassembly evidence on request.*
