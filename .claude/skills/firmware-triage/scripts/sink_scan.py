#!/usr/bin/env python3
"""firmware-triage sink scanner.

Rank binaries and scripts in an extracted rootfs by how much dangerous-sink
surface they expose, so the analyst knows what to reverse first. A hit is a
LEAD, not a bug: an imported `strcpy` only matters if attacker-controlled data
reaches it. Confirm every candidate in Ghidra/emulation.

Usage:
    sink_scan.py <rootfs_dir> [--out sinks.csv] [--min-score N] [--top N]

No third-party deps. Uses `readelf --dyn-syms` when available for accurate
imported-symbol reads; otherwise falls back to `strings`-style symbol scraping.
"""
import argparse
import csv
import os
import re
import subprocess
import sys

# --- Dangerous sinks in native binaries: symbol -> (weight, why) ----------
NATIVE_SINKS = {
    "system": (10, "command execution"),
    "popen": (9, "command execution via shell"),
    "execl": (8, "exec"), "execlp": (8, "exec (PATH)"), "execle": (8, "exec"),
    "execv": (8, "exec"), "execvp": (8, "exec (PATH)"), "execve": (7, "exec"),
    "gets": (10, "unbounded stack read (never safe)"),
    "sprintf": (5, "format into fixed buffer"),
    "vsprintf": (5, "format into fixed buffer"),
    "strcpy": (4, "unbounded copy"), "stpcpy": (4, "unbounded copy"),
    "strcat": (4, "unbounded concat"),
    "sscanf": (3, "%s into buffer risk"), "scanf": (3, "%s into buffer risk"),
    "memcpy": (2, "len-controlled copy (common; low signal)"),
    "strncpy": (1, "off-by-one / no NUL"), "strncat": (1, "misuse-prone"),
    # Router-vendor command wrappers seen across SOHO firmware:
    "doSystem": (9, "vendor system() wrapper"),
    "CsteSystem": (9, "vendor system() wrapper"),
    "twSystem": (9, "vendor system() wrapper"),
    "bcm_system": (9, "vendor system() wrapper"),
}
# Untrusted-input sources: presence raises interest but does not score high.
NATIVE_SOURCES = {"getenv", "recv", "recvfrom", "read", "fgets",
                  "nvram_get", "websGetVar", "webGetVar", "httpd_get"}

# --- Script / CGI command-injection patterns ------------------------------
SCRIPT_EXTS = {".sh", ".cgi", ".php", ".lua", ".py", ".pl", ".asp"}
SCRIPT_SINKS = [
    (re.compile(r"\bsystem\s*\("), 9, "system()"),
    (re.compile(r"\bpopen\s*\("), 9, "popen()"),
    (re.compile(r"\bexec\s*\("), 8, "exec()"),
    (re.compile(r"\bshell_exec\s*\("), 9, "shell_exec()"),
    (re.compile(r"\bpassthru\s*\("), 9, "passthru()"),
    (re.compile(r"\beval\s*\("), 7, "eval()"),
    (re.compile(r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"), 9, "subprocess shell=True"),
    (re.compile(r"os\.system\s*\("), 9, "os.system()"),
    (re.compile(r"`[^`]*`"), 6, "backtick exec"),
    (re.compile(r"\$\([^)]+\)"), 4, "$() command substitution"),
]
SCRIPT_SOURCES = re.compile(r"\$_(GET|POST|REQUEST|COOKIE)|QUERY_STRING|nvram_get|getVar")


def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, IOError):
        return False


def run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=30)
        return out.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


HAVE_READELF = bool(run(["readelf", "--version"]))


def native_symbols(path):
    """Return set of referenced symbol names for an ELF."""
    syms = set()
    if HAVE_READELF:
        txt = run(["readelf", "-W", "--dyn-syms", path])
        for line in txt.splitlines():
            # columns: Num: Value Size Type Bind Vis Ndx Name
            parts = line.split()
            if len(parts) >= 8 and parts[0].rstrip(":").isdigit():
                name = parts[7].split("@")[0]
                if name:
                    syms.add(name)
    if not syms:  # fallback: scrape printable symbol-like tokens
        try:
            with open(path, "rb") as f:
                blob = f.read()
            for tok in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{2,31}", blob):
                syms.add(tok.decode("ascii", "ignore"))
        except (OSError, IOError):
            pass
    return syms


def score_native(path):
    syms = native_symbols(path)
    hits, score = [], 0
    for name, (w, why) in NATIVE_SINKS.items():
        if name in syms:
            score += w
            hits.append(f"{name}({w})")
    srcs = sorted(s for s in NATIVE_SOURCES if s in syms)
    return score, hits, srcs


def score_script(path):
    try:
        with open(path, "r", errors="replace") as f:
            text = f.read()
    except (OSError, IOError):
        return 0, [], []
    hits, score = [], 0
    for rx, w, label in SCRIPT_SINKS:
        n = len(rx.findall(text))
        if n:
            score += w
            hits.append(f"{label}x{n}({w})")
    srcs = ["untrusted-input"] if SCRIPT_SOURCES.search(text) else []
    # A sink plus an untrusted source in the same file is the dangerous combo.
    if hits and srcs:
        score += 5
    return score, hits, srcs


def main():
    ap = argparse.ArgumentParser(description="Rank firmware binaries/scripts by dangerous-sink surface.")
    ap.add_argument("rootfs")
    ap.add_argument("--out", default="sinks.csv")
    ap.add_argument("--min-score", type=int, default=1)
    ap.add_argument("--top", type=int, default=0, help="print top N to stdout (0=all)")
    args = ap.parse_args()

    if not os.path.isdir(args.rootfs):
        sys.exit(f"not a directory: {args.rootfs}")
    if not HAVE_READELF:
        print("[sink_scan] readelf not found; using string-scrape fallback "
              "(less precise).", file=sys.stderr)

    rows = []
    for dirpath, _, files in os.walk(args.rootfs):
        for fn in files:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p):
                continue
            ext = os.path.splitext(fn)[1].lower()
            kind = None
            if is_elf(p):
                kind = "elf"
                score, hits, srcs = score_native(p)
            elif ext in SCRIPT_EXTS or "cgi-bin" in dirpath:
                kind = "script"
                score, hits, srcs = score_script(p)
            else:
                continue
            if score >= args.min_score:
                rows.append({
                    "path": os.path.relpath(p, args.rootfs),
                    "kind": kind,
                    "score": score,
                    "reachable_hint": "yes" if srcs else "",
                    "sinks": " ".join(hits),
                    "sources": " ".join(srcs),
                })

    rows.sort(key=lambda r: r["score"], reverse=True)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["path", "kind", "score",
                                          "reachable_hint", "sinks", "sources"])
        w.writeheader()
        w.writerows(rows)

    shown = rows if args.top == 0 else rows[:args.top]
    print(f"[sink_scan] {len(rows)} candidates -> {args.out}", file=sys.stderr)
    for r in shown[:20]:
        print(f"  {r['score']:>4}  {r['reachable_hint'] or ' ':>3}  "
              f"{r['path']}  [{r['sinks']}]")


if __name__ == "__main__":
    main()
