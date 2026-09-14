#!/usr/bin/env bash
# Repository verification: lints, skill/tool self-tests, SVG + mermaid validation,
# internal-link check, and a funnel smoke test. Deterministic; safe to run in CI.
# Usage: tools/run-checks.sh   (run from repo root)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0; pass=0
ok(){ pass=$((pass+1)); printf '  [ok]   %s\n' "$*"; }
bad(){ fail=$((fail+1)); printf '  [FAIL] %s\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# Use the project virtualenv if present, so python-based self-tests run against
# the provisioned deps (e.g. the mavlink harness needs pymavlink) instead of a
# bare system python3. Safe no-op when .venv is absent (e.g. minimal CI) or when
# already inside a venv. set +u around the source: activate scripts predate the
# nounset guard this script runs under.
if [ -z "${VIRTUAL_ENV:-}" ] && [ -f .venv/bin/activate ]; then
  set +u; . .venv/bin/activate; set -u
  echo "[info] activated .venv ($(python3 -V 2>&1))"
fi

echo "== 1. Python parses =="
while IFS= read -r f; do
  if python3 -c "import ast,sys; ast.parse(open('$f').read())" 2>/dev/null; then ok "$f"; else bad "parse $f"; fi
done < <(find .claude tools -name '*.py' | sort)

echo "== 2. Shell syntax =="
while IFS= read -r f; do
  if bash -n "$f" 2>/dev/null; then ok "$f"; else bad "bash -n $f"; fi
done < <(find .claude tools -name '*.sh' | sort)

echo "== 3. Self-tests =="
if python3 .claude/skills/finding-to-vendor-report/scripts/cvss.py --selftest >/dev/null 2>&1; then ok "cvss.py --selftest"; else bad "cvss.py --selftest"; fi
if python3 tools/mavlink-sectest/mavlink_sectest.py --selftest >/dev/null 2>&1; then ok "mavlink_sectest.py --selftest"; else bad "mavlink_sectest.py --selftest"; fi

echo "== 4. SVG well-formed =="
while IFS= read -r f; do
  if python3 -c "import xml.dom.minidom;xml.dom.minidom.parse('$f')" 2>/dev/null; then ok "$f"; else bad "xml $f"; fi
done < <(find . -name '*.svg' -not -path './.git/*' | sort)

echo "== 5. Mermaid blocks balanced =="
python3 - <<'PY' && ok "mermaid blocks" || bad "mermaid blocks"
import re,glob,sys
bad=0
for f in glob.glob("docs/**/*.md",recursive=True):
    for i,b in enumerate(re.findall(r"```mermaid\n(.*?)```",open(f).read(),re.S),1):
        head=b.strip().split()[0]
        bal=(b.count("[")-b.count("]"),b.count("(")-b.count(")"),b.count('"')%2,b.count("{")-b.count("}"))
        if head not in("flowchart","graph","stateDiagram-v2","sequenceDiagram","timeline") or bal!=(0,0,0,0):
            print(f"    bad mermaid in {f} #{i}: head={head} bal={bal}");bad+=1
sys.exit(1 if bad else 0)
PY

echo "== 6. Internal doc links resolve =="
python3 - <<'PY' && ok "internal links" || bad "internal links"
import re,glob,os,sys
missing=0
for f in glob.glob("**/*.md",recursive=True):
    if ".git/" in f: continue
    base=os.path.dirname(f)
    for m in re.findall(r"\]\(([^)]+)\)",open(f).read()):
        link=m.split("#")[0]
        if not link or link.startswith(("http://","https://","mailto:")): continue
        tgt=os.path.normpath(os.path.join(base,link))
        if not os.path.exists(tgt):
            print(f"    {f}: missing -> {link}");missing+=1
sys.exit(1 if missing else 0)
PY

echo "== 7. Funnel smoke test =="
if have gcc; then
  T="$(mktemp -d)"; RF="$T/rootfs"; mkdir -p "$RF/bin" "$RF/www/cgi-bin" "$RF/etc"
  printf '#include <string.h>\n#include <stdlib.h>\nint main(int c,char**v){char b[8];strcpy(b,v[1]);system(b);return 0;}\n' > "$T/v.c"
  gcc -w -o "$RF/bin/httpd" "$T/v.c" 2>/dev/null
  printf '#!/bin/sh\nsystem("ping $QUERY_STRING")\n' > "$RF/www/cgi-bin/p.cgi"
  printf 'admin:x:0:0::/:/bin/sh\n' > "$RF/etc/passwd"
  bash .claude/skills/firmware-triage/scripts/triage.sh "$RF" "$T/out" >/dev/null 2>&1 \
    && [ -f "$T/out/inventory.txt" ] && ok "triage.sh" || bad "triage.sh"
  python3 .claude/skills/firmware-triage/scripts/sink_scan.py "$RF" --out "$T/sinks.csv" >/dev/null 2>&1 \
    && grep -q httpd "$T/sinks.csv" && ok "sink_scan.py" || bad "sink_scan.py"
  cp -r "$RF" "$T/rootfs2"; printf '#!/bin/sh\nsafe_ping "$QUERY_STRING"\n' > "$T/rootfs2/www/cgi-bin/p.cgi"
  python3 .claude/skills/binary-diff/scripts/fw_diff.py "$RF" "$T/rootfs2" --out "$T/diff" >/dev/null 2>&1 \
    && [ -f "$T/diff/diff-candidates.csv" ] && ok "fw_diff.py" || bad "fw_diff.py"
  python3 .claude/skills/security-dataviz/scripts/chart.py bars --csv "$T/sinks.csv" \
    --label path --value score --out "$T/c.svg" >/dev/null 2>&1 \
    && python3 -c "import xml.dom.minidom;xml.dom.minidom.parse('$T/c.svg')" && ok "chart.py" || bad "chart.py"
  rm -rf "$T"
else
  echo "  [skip] gcc absent; funnel ELF smoke test skipped (selftests already cover logic)"
fi
FIND=.claude/skills/finding-to-vendor-report/templates/finding.json
python3 .claude/skills/finding-to-vendor-report/scripts/make_report.py "$FIND" --validate >/dev/null 2>&1 && ok "make_report --validate" || bad "make_report --validate"
python3 .claude/skills/finding-to-cve-writeup/scripts/make_cve.py "$FIND" >/dev/null 2>&1 && ok "make_cve" || bad "make_cve"
python3 .claude/skills/security-dataviz/scripts/diagram.py taint a b c >/dev/null 2>&1 && ok "diagram.py taint" || bad "diagram.py taint"

echo
echo "==== $pass passed, $fail failed ===="
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
