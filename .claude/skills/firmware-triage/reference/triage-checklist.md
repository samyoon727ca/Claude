# Firmware Triage Checklist

The scripts automate the mechanical passes; this checklist is the full funnel,
including the judgment steps a script cannot do. Work top to bottom.

## 0. Scope & provenance
- [ ] Target is in scope per `docs/disclosure-policy.md` (public firmware or owned device).
- [ ] Recorded vendor, model, hardware rev, firmware version, and SHA-256.

## 1. Extract
- [ ] `triage.sh <image> <out>` (or pass an already-extracted rootfs dir).
- [ ] Extraction actually produced a rootfs (has `/bin`, `/etc`). If not, see
      `binwalk-notes.md` — the image may be encrypted, headered, or a non-standard FS.
- [ ] Confirmed SoC/arch from the image (endianness matters for Ghidra + emulation).

## 2. Inventory the filesystem (`inventory.txt`, `sensitive.txt`)
- [ ] Version/banner strings captured (needed for the report + diffing).
- [ ] Private keys / certs — are any **shared across the fleet** (baked-in TLS key = finding)?
- [ ] `passwd`/`shadow` — hardcoded or crackable accounts? Backdoor UID 0 accounts?
- [ ] Hardcoded credentials in configs/scripts (triage the grep hits manually).
- [ ] SUID/SGID binaries — local privilege-escalation surface.
- [ ] World-writable files in sensitive paths.

## 3. Map the reachable attack surface (`services.txt`)
- [ ] Web server + every CGI/handler it exposes (pre-auth vs post-auth?).
- [ ] Network daemons started at boot (telnetd, UPnP, TR-069, dnsmasq, SMB).
- [ ] Which services are **network-reachable by default** (the pre-auth surface)?

## 4. Rank sinks (`sinks.csv`)
- [ ] `sink_scan.py <rootfs> --out sinks.csv`.
- [ ] Cross-reference: a binary that is **network-reachable** (in `services.txt`)
      **and** high sink score **and** consumes untrusted input = top priority.
- [ ] `reachable_hint=yes` flags a sink+source combination in the same object.

## 5. Analyst priorities (write these into the report)
- [ ] Top 5-10 candidates, each with a one-line "why this, why now".
- [ ] Separate "confirmed sensitive-file findings" (creds/keys) from "leads to reverse".
- [ ] Note anything for the diff skill (changed daemons across versions).

## 6. Hand off
- [ ] Report populated from `templates/triage-report.md`.
- [ ] Do NOT claim a vulnerability from triage signal alone — confirm in Ghidra/emulation.
