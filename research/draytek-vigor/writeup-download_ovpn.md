# Retired draft — superseded by the published n-day case study

> **This held-for-disclosure draft has been retired.** It was written on the premise
> that the `download_ovpn` command injection was a *novel* finding awaiting a new CVE.
> A wider dedup re-check (2026-09-18) established that the bug is already
> **CVE-2024-45890** (assigned on the sibling Vigor3900), so it is an **n-day**, not a
> new disclosure — there is no CVE to reserve and no embargo to hold for.

The public methodology case study now lives at:

- **[`writeups/draytek-vigor300b-download_ovpn-cmdinjection.md`](../../writeups/draytek-vigor300b-download_ovpn-cmdinjection.md)**

The affected-product / CPE coverage-gap notice to DrayTek/MITRE (the only outbound
artifact still worth sending) is:

- [`vendor-report.md`](vendor-report.md) — "CVE-2024-45890 also affects Vigor300B"
- [`disclosure-email.txt`](disclosure-email.txt) — its cover email

See [`finding-openvpn-cmdinjection.md`](finding-openvpn-cmdinjection.md) for the
code-level finding and the dedup history.
