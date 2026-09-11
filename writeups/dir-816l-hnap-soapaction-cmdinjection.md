# Rediscovering an n-day by patch-diffing: D-Link DIR-816L Rev B HNAP `SOAPAction` command injection (CVE-2015-2051 class)

**Severity:** 9.8 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**Affected:** D-Link DIR-816L Rev B, firmware ≤ 2.05.B02
**Fixed in:** 2.06.B01 (security patch, 2020-02)
**Class:** Unauthenticated OS command injection (CWE-78)
**Maps to:** CVE-2015-2051 (D-Link HNAP `SOAPAction` command-injection class)
**Researcher:** samyoon727ca

## TL;DR
> The DIR-816L Rev B web CGI passes the tail of the attacker-controlled
> `SOAPAction` HTTP header into `system()` when handling HNAP requests, and the
> `GetDeviceSettings` action is exempt from authentication — so an unauthenticated
> attacker on the LAN can run arbitrary shell commands as root. This is the
> decade-old D-Link HNAP command-injection class (CVE-2015-2051). This writeup is
> not a new disclosure; it is a **patch-diff case study** that rediscovers the bug
> by diffing two public firmware images and shows the method end to end.

## The target
- **Device:** D-Link DIR-816L Rev B (SOHO Wi-Fi router), End-of-Life.
- **SoC / arch:** Realtek RTL819x, **MIPS32 big-endian**, Linux 2.6.30.9 (confirmed
  from the image, not the datasheet).
- **Firmware pair analyzed:** `2.05.B02` (last standard firmware, vulnerable) vs
  `2.06.B01` (the first "security patch", fixed). Both were downloaded from D-Link's
  public legacy file server; SHA-256 of every archive and inner image was recorded
  before analysis.
- **Container:** SEAMA header → LZMA-compressed kernel → squashfs 4.0 (Realtek's
  LZMA variant, which stock `unsquashfs` rejects — extraction needs `sasquatch`).

## How it was found (methodology)
The point of this writeup is the repeatable funnel, not the bug.

1. **Acquire + fingerprint.** Pulled the full DIR-816L Rev B firmware ladder from
   the vendor's public server. Fingerprinting the image (not the spec sheet)
   established Realtek RTL819x / MIPS **big-endian** / Linux 2.6.30.9 — the
   endianness matters, and a common trap is to infer it from the squashfs magic
   (`hsqs`), which is *always* little-endian on disk in squashfs 4.0 regardless of
   CPU. The ELF headers are authoritative: they are `MSB`.

2. **Diff across the security patch.** A same-size firmware image with a different
   hash is the classic silent-fix tell: `2.05.B02` and the `2.06.B01` patch have
   byte-identical image sizes but differ. Unpacking both root filesystems and
   diffing them ranked exactly one interesting changed binary: **`htdocs/cgibin`**
   (the monolithic web CGI). The kernel was unchanged bar its build timestamp.

3. **Read the patch signature before opening a disassembler.** `readelf`/`strings`
   on the old vs new `cgibin` showed the entire change in three tells: the patched
   build adds **one** new imported symbol — `access()` — and three new strings:
   `access`, `"%s/%s.php"`, and `"http://purenetworks.com/HNAP1/GetDeviceSettings"`.
   A new `access()` call plus a request-built `.php` path is a strong "path/OS
   interaction was hardened here" signal. `.text` grew only ~144 bytes: a surgical fix.

4. **Confirm in Ghidra.** Loading both binaries as `MIPS:BE:32` and diffing the
   decompilation of the function that gained the `access()` call landed directly on
   `hnap_main`. The old version reaches `system()` with attacker-controlled data;
   the new version gates it. Root cause confirmed statically (below).

The whole chain — acquire → silent-diff → symbol/string triage → targeted Ghidra
diff — took one working session because each step narrowed the next.

## Root cause
`hnap_main` handles HNAP (Home Network Administration Protocol) requests. It reads
the `SOAPAction` request header, decides whether the action needs authentication,
derives a "method name" from it, and dispatches. In the **vulnerable** `2.05.B02`
(annotated decompile):

```c
soap = getenv("HTTP_SOAPACTION");            // fully attacker-controlled header
if (soap == NULL) soap = ".../GetDeviceSettings";
else if (strstr(soap, "http://purenetworks.com/HNAP1/GetDeviceSettings") == 0
         && auth_check(getenv("HTTP_AUTHORIZATION")) < 0) {
    return unauthorized();                   // 401 ONLY if auth fails
}
// ── reachable UNAUTHENTICATED whenever `soap` merely CONTAINS the GDS URL ──
method = strrchr(soap, '/') + 1;             // method = text after the last '/'
...
sprintf(cmd, "sh %s%s.sh > /dev/console", "/etc/templates/hnap/", method);
system(cmd);                                 // ← attacker data reaches the shell
```

Two mistakes combine:

- **Authentication bypass by substring.** The auth gate uses `strstr` — *contains*,
  not *equals*. Any `SOAPAction` that merely **contains** the `GetDeviceSettings`
  URL skips authentication entirely. An attacker appends their payload **after**
  that URL and remains unauthenticated.
- **Unsanitized command construction.** `method` is whatever follows the final `/`
  in the header, copied verbatim into `sh /etc/templates/hnap/<method>.sh` and run
  via `system()`. The method cannot contain `/`, but shell metacharacters (`;`,
  `` ` ``, `$()`, `&`) pass straight through — so `<method>` breaks out of the
  intended command and runs arbitrary shell as root.

## The fix (what 2.06.B01 changed)
The patched `hnap_main` closes both halves:

```c
// exact match now (two literal forms), not a substring:
if (strcmp(soap, ".../GetDeviceSettings") != 0
    && strcmp(soap, "\".../GetDeviceSettings\"") != 0
    && auth_check(...) < 0) return unauthorized();
...
snprintf(path, 0x100, "%s/%s.php", "/etc/templates/hnap/", method);
if (access(path, 0) == 0) {                  // NEW: only proceed if the template exists
    ... dispatch ...
}
```

`strstr → strcmp` removes the substring auth bypass (an exact `GetDeviceSettings`
leaves no room to append a payload), and the `access()` check requires `method` to
name a real template file — which a metacharacter-laden payload never does. Either
change alone breaks the exploit; together they close it cleanly.

## Impact
An unauthenticated attacker who can reach the device's web service executes
arbitrary commands as root: full device compromise — credential and configuration
theft, traffic interception/redirection (DNS, routes), persistence, and recruitment
into a botnet. In the default configuration HNAP is exposed on the LAN web
interface, so the practical attacker position is the local network (or any device
already on it); the canonical CVE scores it `AV:N` (9.8) because remote management,
where enabled, exposes it to the WAN. This bug class has been actively weaponized by
Mirai-derived botnets (e.g., Goldoon) for years.

## Proof of concept (sanitized)
The trigger is a single HNAP `POST` whose `SOAPAction` header (a) contains the
`GetDeviceSettings` URL to bypass authentication and (b) carries a shell
metacharacter and a benign test command after the final `/`:

```
POST /HNAP1/ HTTP/1.1
Host: 192.168.0.1
SOAPAction: "http://purenetworks.com/HNAP1/GetDeviceSettings/x;COMMAND;"
Content-Type: text/xml
Content-Length: 0
```

Here `COMMAND` stands in for a **benign** verification command (for example, one
that writes a marker file the tester can then read back); the payload is
deliberately not a weaponized chain. A working, fully-weaponized module for this
class is already public (Metasploit `dlink_hnap_header_exec_noauth`), so no new
offensive capability is disclosed here — the intent is to show the injection point
and let a defender reproduce and test on hardware they own.

## Remediation
Update to firmware **2.06.B01 or later**, which fixes the handler. The DIR-816L is
End-of-Life across all hardware revisions; D-Link's guidance for EOL devices is to
retire and replace them. Defensively: do not expose the router's web/HNAP interface
to the WAN, and segment untrusted LAN clients away from the management interface.

## Timeline (n-day context — not a new disclosure)
| Date | Event |
|------|-------|
| 2015-04 | Original class disclosed publicly (CVE-2015-2051, D-Link HNAP `SOAPAction`); Metasploit module released |
| 2020-02 | D-Link ships DIR-816L Rev B security patch **2.06.B01** fixing `hnap_main` |
| 2026-09 | This patch-diff analysis independently rediscovers and confirms the fix on DIR-816L Rev B |

## References & credit
- CVE-2015-2051 — https://nvd.nist.gov/vuln/detail/CVE-2015-2051
- D-Link HNAP advisory (2015-04-13) — https://www.dlink.com/uk/en/support/support-news/2015/april/13/hnap-privilege-escalation-command-injection
- Metasploit `exploit/linux/http/dlink_hnap_header_exec_noauth` — https://www.rapid7.com/db/modules/exploit/linux/http/dlink_hnap_header_exec_noauth/
- Exploit-DB 37171; Tenable/Nessus plugin 84086
- Method + tooling: this repository's firmware-triage / binary-diff funnel
- Researcher: samyoon727ca
