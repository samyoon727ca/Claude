# Disclosure Outreach

How to get the report into the right hands, per `docs/disclosure-policy.md`.

## Find the security contact (in order)
1. `https://<vendor>/.well-known/security.txt` (RFC 9116) — canonical contact.
2. Vendor PSIRT / "report a vulnerability" page (e.g. Zyxel: `security@zyxel.com.tw`).
3. Bug-bounty platform if the vendor runs one (Netgear: Bugcrowd). Most SOHO
   vendors are **credit-only** — set expectations accordingly.
4. If unresponsive: a coordinator CERT (e.g. CERT/CC) can mediate.

## First contact
- Send the assembled report (`make_report.py` output) as the body or a PGP-
  encrypted attachment if the vendor publishes a key.
- Ask for: receipt acknowledgement, a tracking ID, and a fix ETA.
- State your disclosure timeline (default 90 days) and that you will coordinate.
- Offer to verify a candidate fix.

## During the embargo
- Keep all detail private (drafts under `drafts/private/`, git-ignored).
- Do not publish a weaponized PoC before a fix ships.
- Track dates in the finding's `disclosure` block for the public timeline.

## Requesting the CVE
- If the vendor is a CNA (D-Link, Zyxel), they assign the CVE — ask them to.
- Otherwise request via MITRE. Coordinate credit ("<researcher>").
- For an SDK-level bug affecting multiple models, enumerate every affected model;
  this is where one root cause becomes several affected products.

## Publishing (post-fix)
- Sanitized writeup: root cause, methodology, defensive lessons; redact any
  turnkey exploit. This is the public portfolio artifact (feeds the CVE-writeup skill).
