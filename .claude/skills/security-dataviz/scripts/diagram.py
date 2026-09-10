#!/usr/bin/env python3
"""Mermaid diagrams for security briefings. No dependencies. Output is a fenced
```mermaid block (renders natively on GitHub and in Artifacts -- no JS needed).

Subcommands:
  taint     A taint/attack-path flow: source -> ... -> sink (ends highlighted).
  timeline  A coordinated-disclosure timeline from a finding.json disclosure block
            (or explicit date:label pairs).

Usage:
  diagram.py taint "QUERY_STRING host param" "sprintf() cmd buffer" "doSystem() -> /bin/sh"
  diagram.py timeline --finding finding.json
  diagram.py timeline "2026-01-05:Reported" "2026-02-10:Fix released" "2026-03-01:CVE + writeup"
"""
import argparse
import json
import sys


def sanitize(s):
    # Mermaid node text: avoid characters that break the parser.
    return s.replace('"', "'").replace("\n", " ").strip()


def taint(steps):
    if len(steps) < 2:
        sys.exit("taint needs >=2 steps (source ... sink)")
    lines = ["```mermaid", "flowchart LR"]
    ids = [f"n{i}" for i in range(len(steps))]
    for i, (nid, txt) in enumerate(zip(ids, steps)):
        shape = f'{nid}["{sanitize(txt)}"]'
        lines.append(f"    {shape}")
    for a, b in zip(ids, ids[1:]):
        lines.append(f"    {a} --> {b}")
    # Highlight source (untrusted input) and sink (dangerous call).
    lines.append(f"    classDef src fill:#F2555D,stroke:#B4232A,color:#fff;")
    lines.append(f"    classDef sink fill:#C6641B,stroke:#8a410f,color:#fff;")
    lines.append(f"    class {ids[0]} src;")
    lines.append(f"    class {ids[-1]} sink;")
    lines.append("```")
    return "\n".join(lines)


def timeline_from_pairs(pairs):
    lines = ["```mermaid", "timeline", "    title Coordinated disclosure timeline"]
    for p in pairs:
        if ":" not in p:
            sys.exit(f"bad date:label pair: {p!r}")
        date, label = p.split(":", 1)
        lines.append(f"    {sanitize(date)} : {sanitize(label)}")
    lines.append("```")
    return "\n".join(lines)


def timeline_from_finding(path):
    with open(path) as f:
        finding = json.load(f)
    disc = finding.get("disclosure", {})
    vendor = finding.get("vendor", "vendor")
    pairs = []
    if disc.get("reported"):
        pairs.append(f"{disc['reported']}:Reported to {vendor} PSIRT")
    pairs.append("(pending):Vendor acknowledged / tracking ID")
    pairs.append("(pending):Fix released")
    pairs.append("(pending):CVE assigned")
    tp = disc.get("target_public", "")
    pairs.append(f"{tp or '(pending)'}:Public disclosure")
    return timeline_from_pairs(pairs)


def main():
    ap = argparse.ArgumentParser(description="Mermaid diagrams for security briefings.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("taint")
    t.add_argument("steps", nargs="+")
    t.add_argument("--out", default="")
    tl = sub.add_parser("timeline")
    tl.add_argument("pairs", nargs="*")
    tl.add_argument("--finding", default="")
    tl.add_argument("--out", default="")
    args = ap.parse_args()

    if args.cmd == "taint":
        out = taint(args.steps)
    else:
        out = timeline_from_finding(args.finding) if args.finding else timeline_from_pairs(args.pairs)
        if not args.finding and not args.pairs:
            sys.exit("timeline needs --finding or date:label pairs")

    if getattr(args, "out", ""):
        with open(args.out, "w") as f:
            f.write(out + "\n")
        print(f"[diagram] wrote {args.out}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
