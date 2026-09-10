# Writing the Severity Justification & Impact Narrative

The report's credibility lives in two places: a defensible CVSS vector and an
impact narrative that a non-specialist decision-maker understands. Both must be
true to the reproduction — never to the score you wish you had.

## Per-metric rationale (attach to every report)
For each CVSS metric, one line saying *why* that value, tied to evidence:
- **AV:** "Admin HTTP service is LAN-only; remote management off by default ->
  AV:A." (Or: "reachable from WAN by default -> AV:N.")
- **PR:** "The `ping.cgi` handler is reachable before authentication -> PR:N."
- **S:** "Impact is confined to the device (root on the router) -> S:U."
- **C/I/A:** "Arbitrary command execution as root -> C:H/I:H/A:H."
This pre-empts the vendor re-scoring you downward, and it demonstrates rigor.

## CWE selection
Pick the most specific CWE that matches the root cause, not the symptom:
- Shell metacharacters into `system()`/`doSystem()` -> **CWE-78** (OS command injection).
- Unbounded `strcpy`/`sprintf` into a fixed buffer -> **CWE-121** (stack overflow)
  or **CWE-787** (out-of-bounds write) — use the more precise one.
- Format string from untrusted input -> **CWE-134**.
- Hardcoded account/key in firmware -> **CWE-798 / CWE-321**.
- Endpoint reachable without auth that should require it -> **CWE-306**.
`make_report.py` maps common CWEs to names; verify at cwe.mitre.org.

## Impact narrative (3 layers)
1. **Technical:** what the attacker gets (e.g., root command execution).
2. **Operational:** what that enables (traffic interception, persistence,
   pivoting to LAN hosts, botnet enrollment).
3. **Conditional reach:** "If remote management is enabled/exposed, this is
   exploitable from the internet" — state it as a condition, do not fold it into
   the base score unless it is the default.

## Honesty guardrails (what gets reports rejected)
- Do not claim `AV:N` for a LAN-only service.
- Do not claim `S:C` without a real crossed boundary.
- Do not claim RCE from a crash you have not turned into code execution — if you
  have a crash but not control, score it as DoS (`A:H`) and say so.
- Every repro step must actually reproduce; a vendor will run them.
- Reproduce in **emulation** or on a device you own; never against someone else's
  equipment (see `docs/disclosure-policy.md`).
