#!/usr/bin/env python3
"""CVSS v3.1 base-score calculator (severity justification for vendor reports).

Implements the official FIRST CVSS v3.1 base-metric equations, including the
exact Roundup used by NVD, so the score in a report matches what the vendor/NVD
will compute. Parse + validate a vector, or build one interactively.

Usage:
    cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cvss.py --selftest
"""
import math
import sys

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# PR depends on Scope: (unchanged, changed)
PR = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)}

ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
CHOICES = {"AV": set("NALP"), "AC": set("LH"), "PR": set("NLH"), "UI": set("NR"),
           "S": set("UC"), "C": set("HLN"), "I": set("HLN"), "A": set("HLN")}


def roundup(x):
    """Official CVSS v3.1 Roundup (matches NVD to 1 decimal)."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def severity(score):
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse(vector):
    v = vector.strip()
    if v.upper().startswith("CVSS:3.1/"):
        v = v[len("CVSS:3.1/"):]
    elif v.upper().startswith("CVSS:3.0/"):
        v = v[len("CVSS:3.0/"):]
    metrics = {}
    for part in v.split("/"):
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"bad metric segment: {part!r}")
        k, val = part.split(":", 1)
        k, val = k.upper(), val.upper()
        metrics[k] = val
    missing = [m for m in ORDER if m not in metrics]
    if missing:
        raise ValueError(f"missing base metrics: {','.join(missing)}")
    for m in ORDER:
        if metrics[m] not in CHOICES[m]:
            raise ValueError(f"invalid value {metrics[m]!r} for {m}")
    return metrics


def score(vector):
    m = parse(vector)
    scope_changed = m["S"] == "C"
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = PR[m["PR"]][1 if scope_changed else 0]
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = roundup(min(impact + exploitability, 10))
    return {
        "vector": "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in ORDER),
        "base_score": round(base, 1),
        "severity": severity(base),
        "impact_subscore": round(impact, 1),
        "exploitability_subscore": round(exploitability, 1),
    }


def selftest():
    cases = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "Low"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
        ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "High"),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "High"),
    ]
    ok = True
    for vec, want_s, want_sev in cases:
        r = score(vec)
        good = (r["base_score"] == want_s and r["severity"] == want_sev)
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] {r['base_score']:>4} {r['severity']:<8} "
              f"(want {want_s} {want_sev})  {vec}")
    print("selftest:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        sys.exit(selftest())
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    try:
        r = score(sys.argv[1])
    except ValueError as e:
        sys.exit(f"error: {e}")
    print(f"Vector:         {r['vector']}")
    print(f"Base score:     {r['base_score']}  ({r['severity']})")
    print(f"  Impact:        {r['impact_subscore']}")
    print(f"  Exploitability:{r['exploitability_subscore']}")


if __name__ == "__main__":
    main()
