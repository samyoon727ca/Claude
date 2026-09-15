# Vulnerability Report: Post-authentication OS command injection in DrayTek Vigor300B web interface (OpenVPN client-config download, incomplete-blocklist sanitizer bypass)

**Vendor:** DrayTek
**Researcher:** Samuel Yoon (contact: samyoon727ca@gmail.com)
**Vulnerability type:** OS command injection (sanitizer bypass) (CWE-78 — OS Command Injection)
**Affected component:** www/cgi-bin/mainfunction.cgi (action download_ovpn)
**Severity:** 7.2 (High), `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
**Preconditions:** Network-reachable web-management interface; post-authentication with session privilege level >= 4 (operator, or admin/root). Web CGI runs as root (lighttpd does not drop privileges: server.username/server.groupname commented out in etc/lighttpd/lighttpd.conf).

> Coordinated disclosure. This report is confidential until a fix is available or
> the agreed disclosure window closes. Reported pending (not yet sent); requested public
> disclosure target: 90 days from report.

## Affected products

| Model | HW rev | Affected versions | Fixed in | Firmware SHA-256 |
|-------|--------|-------------------|----------|------------------|
| Vigor300B | Linux/Comcerto (ARM, ELF32 LE) | <= 1.5.1.6 (all prior on the Linux firmware line) | 1.5.1.7 | 7f3fa8e26be2abcf61c62dbeb785f607910f45efb376b0827835cf3098babece |

## Summary

The download_ovpn action of the web-management CGI www/cgi-bin/mainfunction.cgi (handler FUN_0001e9d8 @ 0x1e9d8) constructs a shell command from five attacker-controlled HTTP parameters -- remote_ip, protocal (vendor spelling), config_name, auto_dialout, redirect_gw -- via snprintf into the format string "/etc/openvpn/create_client_conf.sh %s %s %s %s %s" and executes it with system(). Each parameter is first passed through an in-place sanitizer (FUN_0000ad8c @ 0xad8c) that replaces a blocklist of shell metacharacters -- ; % ` | > space ' " $ tab newline CR and the two-character sequence && -- with '+'. The blocklist is incomplete: a single '&' and the characters < ( ) { } , \ survive to the shell (confirmed by decoding the sanitizer's comparison chain from the ARM disassembly). Because the space character IS blocked, an attacker uses '&' (a command separator that needs no space) and brace expansion {cmd,arg} (space-less arguments) to inject arbitrary commands. The injected command executes even though /etc/openvpn/create_client_conf.sh may be absent at runtime, because system() hands the whole line to the shell. Since lighttpd does not drop privileges, injected commands run as root. The root weakness is an incomplete denylist (CWE-184) feeding an OS command construction (CWE-78). Component binaries: vulnerable CGI SHA-256 821d539ccab6c90aa5d39d859a6526c2da2cca92c6f551acfa91fccc9430b958 (v1.5.1.6); fixed CGI SHA-256 b5085e80b797bad690abd5866178f06c1f56ff6b817ecfe355aada5ae176a3ec (v1.5.1.7).

## Steps to reproduce

1. [CONFIRMATION STATUS: Verified by static analysis -- Ghidra decompilation + ARM disassembly of mainfunction.cgi v1.5.1.6 (SHA-256 821d539c...) -- and independently corroborated by the vendor's silent single-quoting fix in v1.5.1.7. A runtime PoC on an emulated/owned device is in progress; the steps below are the derived exploitation procedure.]
2. Authenticate to the web-management interface with an operator- or admin-level account (session privilege level >= 4).
3. Invoke the OpenVPN client-config download: submit action=download_ovpn to /cgi-bin/mainfunction.cgi with all five parameters (remote_ip, protocal, config_name, auto_dialout, redirect_gw) non-empty.
4. Place a space-less injection payload in any of the five parameters, e.g. remote_ip=x&reboot (benign availability test) or remote_ip=x&{touch,/tmp/poc} (benign file-creation proof).
5. The sanitizer preserves the single '&' and the brace-expansion payload; snprintf builds the command and system() executes it as root (e.g. /tmp/poc is created owned by uid 0).
6. Confirm the fix: on v1.5.1.7 the identical input is inert -- the five %s are single-quoted and ' is already in the sanitizer blocklist, so no metacharacter escapes the quotes.

## Impact

Technical: an authenticated operator/admin session yields arbitrary OS command execution as root -- full compromise of the device control plane. Operational: root on a broadband/VPN edge router permits interception and redirection of all traversing traffic, theft of VPN/PKI key material and stored credentials, persistent firmware-level implantation, and pivoting into the LAN or the site-to-site/remote-access VPN the device terminates. Conditional reach: the management interface is network-reachable; where it is exposed to the WAN (common on business CPE with remote management enabled), the vulnerability is remotely exploitable by any actor holding or obtaining operator-level credentials (default/weak/reused credentials, phishing, or a chained authentication bypass).

## Severity justification (CVSS v3.1)

Base score **7.2 (High)** — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`.
The vector reflects the preconditions above; see the per-metric rationale the
researcher provides with this report.

## Suggested remediation

The vendor's v1.5.1.7 fix -- single-quoting all five %s in the create_client_conf.sh command line -- closes the bypass, because ' is already replaced by the sanitizer. Recommended defense-in-depth beyond the applied fix: (1) replace the system()/shell invocation with an execv()-style call that passes arguments as a vector and never spawns a shell; (2) validate/allowlist each parameter against its expected type (IP address, protocol enum, config-name charset) before use rather than relying on a metacharacter blocklist; (3) run the web CGI under a non-root least-privilege account (enforce server.username/server.groupname) so any residual injection is not root-equivalent; (4) audit the sibling system() call sites that received the same single-quoting change in v1.5.1.7 (openvpn disconnect_from_web, langs 'mv', the passwd helper) and other Vigor models sharing the OpenVPN web-config code for equivalent completeness.

## Discovery

Version-to-version binary diff of the public firmware chain (v1.5.1.6 -> v1.5.1.7, acquired over HTTPS from the vendor's public archive fw.draytek.com.tw) flagged a silent hardening of mainfunction.cgi: the create_client_conf.sh command line changed from unquoted %s to single-quoted '%s'. The vulnerable path in v1.5.1.6 was confirmed via Ghidra decompilation and ARM disassembly (the incomplete blocklist was decoded directly from the disassembly of FUN_0000ad8c). Novelty was verified against NVD, OpenCVE (full vigor300b_firmware list), and DrayTek security advisories -- no existing CVE covers the download_ovpn / create_client_conf.sh path (known Vigor300B mainfunction.cgi CVEs cover apmcfgupload/apmcfgupptim, uploadlangs, cvmcfgupload, and query-string paths only). A runtime PoC in emulation is in progress.

---
*Reported under coordinated disclosure. Please acknowledge receipt and provide a
tracking identifier. The researcher is available to verify a candidate fix.*
