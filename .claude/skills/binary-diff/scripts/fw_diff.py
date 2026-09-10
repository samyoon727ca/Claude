#!/usr/bin/env python3
"""binary-diff: version-to-version firmware diff -> ranked candidate list.

Compares an OLD and a NEW extracted rootfs and ranks changed binaries/scripts by
security relevance, telling the analyst which version likely holds the bug. Finds
*where* to point Ghidra/Diaphora; it does not do function-level matching itself.

Usage:
    fw_diff.py <rootfs_OLD> <rootfs_NEW> [--out diff-out] [--reachable services.txt]
               [--min-score N]

No third-party deps. Uses `readelf` when present for accurate symbol deltas;
otherwise falls back to a string-scrape. A hit is a LEAD, not a bug.
"""
import argparse
import csv
import hashlib
import os
import re
import subprocess
import sys

# Dangerous native sinks (compact; mirrors firmware-triage/sink-catalog).
NATIVE_SINKS = {
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve",
    "gets", "sprintf", "vsprintf", "strcpy", "stpcpy", "strcat", "sscanf",
    "doSystem", "CsteSystem", "twSystem", "bcm_system",
}
SCRIPT_SINK_RX = re.compile(
    r"\bsystem\s*\(|\bpopen\s*\(|\bexec\s*\(|\bshell_exec\s*\(|\bpassthru\s*\("
    r"|\beval\s*\(|os\.system\s*\(|`[^`]*`")
# "Silent fix" tells: bounds/validation strings that tend to appear when a bug
# is patched. Presence of these ADDED in the newer binary => bug likely in OLD.
SECFIX_RX = re.compile(
    r"invalid|overflow|too long|truncat|sanitiz|malformed|illegal|out of range"
    r"|bounds|not permitted|denied|escap", re.IGNORECASE)
SCRIPT_EXTS = {".sh", ".cgi", ".php", ".lua", ".py", ".pl", ".asp"}


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=30).stdout.decode(
            "utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


HAVE_READELF = bool(run(["readelf", "--version"]))


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except (OSError, IOError):
        return None
    return h.hexdigest()


def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, IOError):
        return False


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except (OSError, IOError):
        return b""


def strings_of(blob, minlen=4):
    return set(m.decode("ascii", "ignore")
               for m in re.findall(rb"[\x20-\x7e]{%d,}" % minlen, blob))


def func_symbols(path):
    """Defined + dynamic FUNC symbol names for an ELF (empty if stripped)."""
    syms = set()
    if HAVE_READELF:
        txt = run(["readelf", "-sW", path])
        for line in txt.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[0].rstrip(":").isdigit() and parts[3] == "FUNC":
                name = parts[7].split("@")[0]
                if name and name != "":
                    syms.add(name)
    return syms


def native_sink_names(blob, syms):
    present = set(s for s in NATIVE_SINKS if s in syms)
    if not present:  # fallback: look for the symbol names in raw strings
        text_syms = strings_of(blob, 3)
        present = set(s for s in NATIVE_SINKS if s in text_syms)
    return present


def native_sink_count(blob, syms):
    """Rough count: how many distinct dangerous sinks are referenced."""
    return len(native_sink_names(blob, syms))


def load_tree(root):
    m = {}
    for dp, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dp, fn)
            if os.path.islink(p):
                continue
            rel = os.path.relpath(p, root)
            m[rel] = p
    return m


def basename_set(path):
    out = set()
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.add(os.path.basename(line))
    except (OSError, IOError):
        pass
    return out


def analyze_changed(rel, old_p, new_p, reachable):
    """Return a candidate row dict for a changed file, or None if low interest."""
    old_b, new_b = read_bytes(old_p), read_bytes(new_p)
    kind = "elf" if (is_elf(old_p) or is_elf(new_p)) else (
        "script" if os.path.splitext(rel)[1].lower() in SCRIPT_EXTS
        or "cgi-bin" in rel else "other")
    if kind == "other":
        return None

    score = 2  # a changed binary/script is at least worth noting
    notable = []
    likely = "either (inspect)"

    if kind == "elf":
        old_syms, new_syms = func_symbols(old_p), func_symbols(new_p)
        syms_added = sorted(new_syms - old_syms)
        syms_removed = sorted(old_syms - new_syms)
        old_sc = native_sink_count(old_b, old_syms)
        new_sc = native_sink_count(new_b, new_syms)
        sink_delta = new_sc - old_sc
        score += abs(sink_delta) * 6
        score += min(len(syms_added) + len(syms_removed), 10)  # churn, capped
    else:  # script
        syms_added, syms_removed = [], []
        old_sc = len(SCRIPT_SINK_RX.findall(old_b.decode("utf-8", "replace")))
        new_sc = len(SCRIPT_SINK_RX.findall(new_b.decode("utf-8", "replace")))
        sink_delta = new_sc - old_sc
        score += abs(sink_delta) * 6

    # "Silent fix" string tells: security strings that are new in the NEW file.
    new_secfix = sorted(s for s in (strings_of(new_b) - strings_of(old_b))
                        if SECFIX_RX.search(s))
    if new_secfix:
        score += 8
        notable = new_secfix[:5]

    # Direction of the bug.
    if new_secfix or sink_delta < 0:
        likely = "OLD (silent fix)"
    elif sink_delta > 0:
        likely = "NEW (regression)"

    reach = os.path.basename(rel) in reachable
    if reach:
        score += 5

    return {
        "path": rel, "kind": kind, "score": score, "likely_bug_side": likely,
        "sink_delta": sink_delta,
        "syms_added": len(syms_added), "syms_removed": len(syms_removed),
        "notable_new_strings": " | ".join(notable),
        "reachable": "yes" if reach else "",
    }


def main():
    ap = argparse.ArgumentParser(description="Rank security-relevant changes between two firmware rootfs trees.")
    ap.add_argument("rootfs_old")
    ap.add_argument("rootfs_new")
    ap.add_argument("--out", default="diff-out")
    ap.add_argument("--reachable", default="", help="services.txt of reachable binaries (basenames boosted)")
    ap.add_argument("--min-score", type=int, default=3)
    args = ap.parse_args()

    for d in (args.rootfs_old, args.rootfs_new):
        if not os.path.isdir(d):
            sys.exit(f"not a directory: {d}")
    os.makedirs(args.out, exist_ok=True)
    if not HAVE_READELF:
        print("[fw_diff] readelf not found; symbol deltas use string-scrape "
              "fallback (less precise).", file=sys.stderr)

    old_t, new_t = load_tree(args.rootfs_old), load_tree(args.rootfs_new)
    reachable = basename_set(args.reachable)

    old_keys, new_keys = set(old_t), set(new_t)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    common = old_keys & new_keys

    changed = []
    for rel in sorted(common):
        h_old, h_new = sha256(old_t[rel]), sha256(new_t[rel])
        if h_old != h_new:
            changed.append(rel)

    with open(os.path.join(args.out, "added.txt"), "w") as f:
        f.write("\n".join(added) + ("\n" if added else ""))
    with open(os.path.join(args.out, "removed.txt"), "w") as f:
        f.write("\n".join(removed) + ("\n" if removed else ""))
    with open(os.path.join(args.out, "changed.txt"), "w") as f:
        f.write("\n".join(changed) + ("\n" if changed else ""))

    rows = []
    for rel in changed:
        row = analyze_changed(rel, old_t[rel], new_t[rel], reachable)
        if row and row["score"] >= args.min_score:
            rows.append(row)
    rows.sort(key=lambda r: r["score"], reverse=True)

    cols = ["path", "kind", "score", "likely_bug_side", "sink_delta",
            "syms_added", "syms_removed", "notable_new_strings", "reachable"]
    with open(os.path.join(args.out, "diff-candidates.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    print(f"[fw_diff] +{len(added)} added  -{len(removed)} removed  "
          f"~{len(changed)} changed  ->  {len(rows)} ranked candidates",
          file=sys.stderr)
    print(f"[fw_diff] wrote {args.out}/{{added,removed,changed}}.txt, diff-candidates.csv",
          file=sys.stderr)
    for r in rows[:15]:
        print(f"  {r['score']:>4}  {r['likely_bug_side']:<18} sinkΔ={r['sink_delta']:+d}  "
              f"{r['path']}  {('['+r['notable_new_strings']+']') if r['notable_new_strings'] else ''}")


if __name__ == "__main__":
    main()
