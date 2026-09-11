# Coordinated Vulnerability Disclosure & Research Scope

This document governs all vulnerability research in this portfolio. It exists for
two reasons: it is the ethical baseline for responsible security work, and it is
the guardrail that keeps this work publishable and clearance-safe.

## 1. Target scope (what is in bounds)

**In scope**
- Commercial, consumer, or academic devices and their **publicly downloadable**
  firmware, acquired directly from the vendor's public support/download site.
- Devices I personally own, or emulated instances of publicly available firmware.
- Open-source firmware and software (e.g. autopilot stacks, RTOS, bootloaders).

**Out of scope (never)**
- Any employer system, or any system I am not authorized to test.
- Classified material, or any government/defense system.
- Export-controlled (ITAR/EAR) technical data — this portfolio demonstrates
  *transferable skills on open targets*; it does not reproduce or generate
  controlled defense technical data.
- Live third-party infrastructure, cloud accounts, or other people's devices.
- Denial-of-service, mass-exploitation, or any test that degrades a service
  others rely on.

## 2. Legal posture

- Firmware is analyzed statically or in **emulation** (QEMU / FirmAE) wherever
  possible, so testing happens against my own environment, not the vendor's.
- Firmware binaries are **not redistributed** here. Writeups reference version
  strings and hashes so others can obtain the same image from the vendor.
- Research stays within good-faith security-research norms (e.g. the kind of
  activity covered by DOJ's good-faith-research policy and safe-harbor language
  in modern vendor VDPs). When a target's firmware license or DMCA posture is
  ambiguous, I confirm the vendor has a VDP/safe harbor before deep work.
- Nothing in a public writeup includes another party's personal data, secrets,
  or non-public infrastructure detail.

## 3. Disclosure process

1. **Confirm** the finding with a reliable, minimized reproduction (ideally in
   emulation) and assess severity with a documented CVSS vector.
2. **Report privately** to the vendor via their published security contact:
   PSIRT, security.txt, VDP portal, or bug-bounty platform. Include affected
   versions + hashes, reproduction, impact, and a suggested remediation.
3. **Embargo** all public detail during remediation. Draft writeups live under
   `drafts/private/` (git-ignored) until cleared.
4. **Coordinate a timeline.** Default target is 90 days to public disclosure,
   extended by mutual agreement if the vendor is engaging in good faith, and
   shortened only if a fix ships earlier or the bug is being exploited in the
   wild.
5. **Request a CVE** (via the vendor CNA or MITRE) and coordinate credit.
6. **Publish a sanitized writeup** after a fix is available or the coordinated
   window closes: root cause, methodology, and defensive lessons — enough to be
   useful to defenders, without a turnkey weapon.

## 4. What gets published vs. held

| Published | Held / never published |
|-----------|------------------------|
| Vulnerability class, root cause, affected versions | Reliable full-chain exploit / weaponized PoC before a fix |
| Methodology and tooling (diffing, triage, emulation) | Any target outside section 1 scope |
| CVSS reasoning and defensive remediation | Personal data or non-public infrastructure detail |
| Redacted, minimal proof-of-concept once patched | Firmware binaries themselves |

## 5. Disclosure obligations (personal)

Sustained security research and any associated income can trigger personal
disclosure or conflict-of-interest reporting obligations. Before publishing under
my name or accepting a bounty payout, I check whether the activity or income
level requires disclosure to my employer or a clearance authority, and I handle
that first. This is tracked out-of-band, not in this repository.
