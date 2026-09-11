# CVSS v3.1 Scoring for SOHO / Embedded Bugs

Score with `scripts/cvss.py "<vector>"`. The metrics below are where router
findings are most often mis-scored — get these right and the vendor won't
down-rate your report.

## The three metrics that decide a router score

**AV — Attack Vector (the #1 overclaim).**
- `AV:N` (Network) only if the vulnerable service is **reachable from the WAN /
  internet by default**, or via a default-on remote-management feature.
- `AV:A` (Adjacent) for the typical SOHO case: the admin web UI / LAN service is
  reachable only from the local network. Most "pre-auth router RCE" is `AV:A`,
  not `AV:N`. Claiming `AV:N` for a LAN-only bug is the fastest way to get your
  severity disputed.
- `AV:L` local shell/console; `AV:P` physical (UART/JTAG).

**PR — Privileges Required (pre- vs post-auth).**
- `PR:N` pre-authentication.
- `PR:H` requires the device admin login (router admin ≈ high privilege on device).
- `PR:L` requires a normal/low-priv account (uncommon on SOHO gear).

**S — Scope (don't inflate).**
- `S:U` (Unchanged) for "root on the router" — the router is both the vulnerable
  and the impacted component. This is the correct default for device RCE.
- `S:C` (Changed) only when impact crosses a security boundary the vulnerable
  component controls — e.g., the bug lets you break out and affect components
  beyond the router's own authority. Reserve it; unjustified `S:C` reads as
  padding.

`UI:R` only if exploitation needs a victim action (e.g., CSRF-delivered).

## Archetype vectors (computed with scripts/cvss.py)

| Archetype | Vector | Score |
|-----------|--------|:-----:|
| Pre-auth **WAN** command injection -> root | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 Critical** |
| Pre-auth **LAN** command injection -> root | `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **8.8 High** |
| Post-auth (admin) **LAN** command injection -> root | `AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | **6.8 Medium** |
| Pre-auth **LAN** config/credential disclosure | `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **6.5 Medium** |
| Pre-auth **LAN** DoS / forced reboot only | `AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **6.5 Medium** |
| CSRF-delivered command injection -> root | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **8.8 High** |

Note the honest gap: moving one bug from `AV:A` to `AV:N` is 8.8 -> 9.8. State
the default exposure accurately and let the score follow; if remote management is
off by default, score `AV:A` and *note* the `AV:N` case as a conditional.

## Impact metrics (C/I/A)
- Root RCE: `C:H/I:H/A:H`.
- Read-only config/secret disclosure: `C:H/I:N/A:N` (raise I/A only if the same
  bug also writes/kills).
- Reboot/crash with no code exec: `C:N/I:N/A:H`.

## CVSS 4.0
Vendors and NVD still accept 3.1, so this tool scores 3.1. CVSS 4.0 base scoring
uses FIRST's MacroVector lookup tables (not a closed-form equation); if a vendor
wants 4.0, build the vector and score it with the official FIRST calculator
rather than approximating it here.
