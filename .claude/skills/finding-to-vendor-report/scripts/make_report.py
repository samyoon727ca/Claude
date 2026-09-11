#!/usr/bin/env python3
"""Assemble a vendor-ready vulnerability report from a finding's evidence.

Reads a finding JSON (see templates/finding.json), computes the CVSS v3.1 score
from its vector, and fills the report template. Automates the *drafting*; the
analyst still writes the technical description / impact narrative and reviews the
final report before sending. No third-party deps.

Usage:
    make_report.py finding.json [--template templates/vendor-report.md] [--out report.md]
    make_report.py finding.json --validate
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cvss  # noqa: E402  (sibling module)

CWE = {
    "CWE-77": "Command Injection", "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting", "CWE-22": "Path Traversal",
    "CWE-119": "Improper Restriction of Operations within Memory Buffer",
    "CWE-120": "Classic Buffer Overflow", "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow", "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write", "CWE-134": "Uncontrolled Format String",
    "CWE-190": "Integer Overflow or Wraparound", "CWE-306": "Missing Authentication",
    "CWE-798": "Use of Hard-coded Credentials", "CWE-259": "Use of Hard-coded Password",
    "CWE-321": "Use of Hard-coded Cryptographic Key", "CWE-311": "Missing Encryption",
    "CWE-352": "Cross-Site Request Forgery", "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference", "CWE-284": "Improper Access Control",
    "CWE-863": "Incorrect Authorization", "CWE-89": "SQL Injection",
}
REQUIRED = ["title", "vendor", "researcher", "products", "cwe", "vuln_type",
            "component", "cvss_v31_vector", "description", "repro_steps",
            "impact", "remediation"]


def load(path):
    with open(path) as f:
        return json.load(f)


def validate(f):
    errs, warns = [], []
    for k in REQUIRED:
        if not f.get(k):
            errs.append(f"missing required field: {k}")
    cwe = f.get("cwe", "")
    if cwe and cwe not in CWE:
        warns.append(f"CWE {cwe} not in local name map (add it, or verify at cwe.mitre.org)")
    vec = f.get("cvss_v31_vector", "")
    if vec:
        try:
            cvss.score(vec)
        except ValueError as e:
            errs.append(f"invalid CVSS vector: {e}")
    prods = f.get("products", [])
    for i, p in enumerate(prods):
        if not p.get("model") or not p.get("affected_versions"):
            warns.append(f"product[{i}] missing model or affected_versions")
    return errs, warns


def products_table(prods):
    rows = ["| Model | HW rev | Affected versions | Fixed in | Firmware SHA-256 |",
            "|-------|--------|-------------------|----------|------------------|"]
    for p in prods:
        rows.append("| {model} | {hw_rev} | {affected_versions} | {fixed_version} | {sha256} |".format(
            model=p.get("model", ""), hw_rev=p.get("hw_rev", ""),
            affected_versions=p.get("affected_versions", ""),
            fixed_version=p.get("fixed_version", "") or "(unpatched)",
            sha256=p.get("sha256", "") or ""))
    return "\n".join(rows)


def render(f):
    cv = cvss.score(f["cvss_v31_vector"])
    steps = f.get("repro_steps", [])
    repro_md = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
    disc = f.get("disclosure", {})
    vals = {
        "title": f.get("title", ""),
        "vendor": f.get("vendor", ""),
        "researcher": f.get("researcher", ""),
        "contact": f.get("contact", ""),
        "products_table": products_table(f.get("products", [])),
        "cwe": f.get("cwe", ""),
        "cwe_name": CWE.get(f.get("cwe", ""), ""),
        "vuln_type": f.get("vuln_type", ""),
        "component": f.get("component", ""),
        "preconditions": f.get("preconditions", ""),
        "cvss_vector": cv["vector"],
        "cvss_score": f"{cv['base_score']}",
        "cvss_severity": cv["severity"],
        "description": f.get("description", ""),
        "repro_steps_md": repro_md,
        "impact": f.get("impact", ""),
        "remediation": f.get("remediation", ""),
        "discovery_method": f.get("discovery_method", ""),
        "reported_date": disc.get("reported", ""),
        "target_public": disc.get("target_public", "90 days from report"),
    }
    return vals


def fill(template, vals):
    missing = set()

    def sub(m):
        key = m.group(1).strip()
        if key in vals:
            return str(vals[key])
        missing.add(key)
        return m.group(0)

    out = re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", sub, template)
    return out, missing


def main():
    ap = argparse.ArgumentParser(description="Assemble a vendor vulnerability report from a finding JSON.")
    ap.add_argument("finding")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--template", default=os.path.join(here, "..", "templates", "vendor-report.md"))
    ap.add_argument("--out", default="")
    ap.add_argument("--validate", action="store_true")
    args = ap.parse_args()

    f = load(args.finding)
    errs, warns = validate(f)
    for w in warns:
        print(f"[warn] {w}", file=sys.stderr)
    if errs:
        for e in errs:
            print(f"[error] {e}", file=sys.stderr)
        sys.exit(1)
    if args.validate:
        print("[validate] finding OK", file=sys.stderr)
        return

    with open(args.template) as t:
        template = t.read()
    vals = render(f)
    out, missing = fill(template, vals)
    for k in sorted(missing):
        print(f"[warn] template placeholder not provided: {{{{{k}}}}}", file=sys.stderr)
    if args.out:
        with open(args.out, "w") as o:
            o.write(out)
        print(f"[make_report] wrote {args.out}  (CVSS {vals['cvss_score']} {vals['cvss_severity']})",
              file=sys.stderr)
    else:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
