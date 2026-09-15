# Finding an incomplete-blocklist command injection in DrayTek Vigor by patch-diffing (CVE-2026-XXXXX)

> **DRAFT — held for coordinated disclosure.** Publish only after the vendor is
> engaged and a fix window closes / a CVE is assigned. Replace `CVE-2026-XXXXX`,
> the reported/published dates, and the advisory URL, then re-run
> `sanitize_check.py` (must be clean) before publishing.

**Severity:** 7.2 (High) — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
**Affected:** DrayTek Vigor300B, firmware ≤ 1.5.1.6
**Fixed in:** 1.5.1.7
**Class:** OS command injection via incomplete-blocklist sanitizer bypass (CWE-78; contributing CWE-184)
**Researcher:** Samuel Yoon

## TL;DR
> The `download_ovpn` action of DrayTek's `mainfunction.cgi` builds a shell command
> from five web parameters and runs it with `system()`. A per-parameter sanitizer
> tries to strip shell metacharacters, but its blocklist is incomplete — a single
> `&` survives — so an authenticated operator/admin can inject commands that run as
> **root**. DrayTek silently closed it in v1.5.1.7 by single-quoting the arguments;
> no CVE covered this path, so it was found by diffing the public firmware chain.

## The target
The DrayTek Vigor300B is a Linux-based broadband/VPN edge router (Comcerto SoC,
ARM ELF32 little-endian; kernel 2.6.33.5). Its web management runs on `lighttpd`,
with the bulk of the application logic in `www/cgi-bin/mainfunction.cgi`. DrayTek
publishes a fully versioned, browsable firmware archive at `fw.draytek.com.tw`,
which makes the line an ideal patch-diffing substrate: every release — including
current security patches — is publicly downloadable. The version pair analyzed
here is **v1.5.1.6 → v1.5.1.7**, both acquired over HTTPS from that archive.

## How it was found (methodology)
This is the point of the writeup: the bug fell out of a repeatable funnel, not a
lucky guess.

1. **Triage + fingerprint.** Each `.all` image is a DrayTek-headered UBI/UBIFS
   container; carving from offset `0x30` and extracting the `rootfs` volume yields
   ~2,500 files. `readelf` on `mainfunction.cgi` confirms the SoC/arch from the
   image itself (ARM, ELF32, little-endian) rather than trusting the spec sheet.
2. **Version-to-version binary diff.** Diffing the two rootfs trees ranks changed
   binaries by security relevance. `mainfunction.cgi` floated to the top, and the
   **string delta** was the tell: several `system()`-style command templates
   changed from unquoted `%s` to single-quoted `'%s'` between 1.5.1.6 and 1.5.1.7 —
   a classic **silent command-injection hardening** signature.
3. **Isolate the un-hardened outlier.** Most of the changed templates (e.g.
   `gretunnel`/`ssltunnel disconnect_from_web '%s'`) were *already* quoted in
   1.5.1.6. The OpenVPN path was the one that was still unquoted and got quoted:
   `/etc/openvpn/create_client_conf.sh %s %s %s %s %s` → `'%s' '%s' '%s' '%s' '%s'`.
4. **Ghidra confirmation.** Decompiling the 1.5.1.6 handler (`FUN_0001e9d8`, the
   target of action `download_ovpn`) shows five `cgiGetValue()` reads, each passed
   through an in-place sanitizer (`FUN_0000ad8c`) before `snprintf` builds the
   command and `system()` runs it.
5. **Decode the sanitizer from the disassembly.** Rather than trust the decompiler,
   the sanitizer's comparison chain was read straight from the ARM disassembly — a
   byte-by-byte blocklist (see Root cause). That is what proved the bypass.
6. **Dedup gate.** The path was checked against NVD, OpenCVE's full
   `vigor300b_firmware` list, and DrayTek's advisories. Known `mainfunction.cgi`
   command-injection CVEs cover *other* endpoints (`apmcfgupload`/`apmcfgupptim`,
   `uploadlangs`, `cvmcfgupload`, query-string) — none the OpenVPN path. Novel.

## Root cause
Source → sink: `cgiGetValue("remote_ip" | "protocal" | "config_name" |
"auto_dialout" | "redirect_gw")` → `FUN_0000ad8c` (sanitizer) → `snprintf(buf,
0x100, "/etc/openvpn/create_client_conf.sh %s %s %s %s %s", …)` → `system(buf)`.

The sanitizer walks each byte and replaces a **blocklist** with `+`. Decoded from
the disassembly, the blocklist is:

```
;  %  `  |  >  (space)  '  "  $  \t  \n  \r        and the two-char sequence  &&
```

The list is incomplete. A **single `&`** — and `<`, `(`, `)`, `{`, `}`, `,`, `\` —
is not filtered and reaches the shell. Two facts make this decisive:

- **Space is blocked**, so a naive `; cmd arg` payload can't work. But `&` needs no
  space to separate commands, and brace expansion `{cmd,arg}` supplies arguments
  with no spaces — so a space-less payload injects freely.
- The command runs **as root**: `lighttpd` never drops privileges
  (`server.username`/`server.groupname` are commented out in its config).

The v1.5.1.7 fix works precisely because `'` is *already* in the blocklist:
single-quoting the arguments means every surviving metacharacter becomes literal,
and the only quote-escape (`'`) is replaced with `+` before it ever reaches the
shell.

## Impact
- **Technical:** an authenticated operator/admin session → arbitrary OS command
  execution as root; full control-plane compromise.
- **Operational:** root on a VPN edge router enables traffic interception/redirection,
  theft of VPN and PKI key material, persistent implantation, and pivoting into the
  LAN or the tunnels the device terminates.
- **Conditional reach:** the management interface is network-reachable; where it is
  WAN-exposed (common on business CPE with remote management enabled), any actor
  who holds or obtains operator-level credentials can reach it remotely.

## Proof of concept (sanitized)
The injection point is any of the five parameters to `action=download_ovpn`. Because
the surviving `&` is the separator, a **benign** proof needs nothing more than:

```
remote_ip=x&{touch,/tmp/poc}
```

The sanitizer preserves `&` and the brace group, `snprintf` assembles the line, and
`system()` runs `create_client_conf.sh x` followed by `touch /tmp/poc` — creating a
root-owned file. On v1.5.1.7 the same input is inert. (A weaponized chain is
deliberately omitted; this is enough to understand and test the flaw.)

## Remediation
DrayTek fixed this in **v1.5.1.7** by single-quoting the five arguments. Users on
≤ 1.5.1.6 should update. Beyond the applied fix, the durable fixes are to pass
arguments via an `execv()`-style call (no shell), allowlist each parameter by type
instead of denylisting metacharacters, and run the CGI as a non-root account so a
residual injection is not root-equivalent.

## Disclosure timeline
| Date | Event |
|------|-------|
| (pending) | Reported to DrayTek PSIRT |
|  | Vendor acknowledged / tracking ID |
| 2026-09-03 | Fix released (v1.5.1.7) — silent |
|  | CVE assigned (CVE-2026-XXXXX) |
| (pending) | Public disclosure |

## References & credit
- CVE-2026-XXXXX (NVD) — *pending assignment*
- Vendor advisory: *pending*
- Researcher: Samuel Yoon
