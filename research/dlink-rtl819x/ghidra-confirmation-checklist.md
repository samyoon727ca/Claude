# Ghidra Confirmation Checklist — DIR-816L Rev B (P2.1)

Turn a diff *lead* into a confirmed *mechanism*. Consumes `diff-out/diff-candidates.csv`
from `extract-and-diff.sh`; feeds `finding.json` for the vendor-report skill. A diff
signal is a lead; a traced source→sink path (and, at P2.3, a reproduced crash) is a finding.

**Target facts (confirmed from the extracted binaries):**
- SoC: Realtek RTL819x · **arch/endian: MIPS32 BIG-endian (MSB) · o32 · MIPS1/R3000**
  (`readelf -h htdocs/cgibin` → `2's complement, big endian`). squashfs `hsqs` is NOT an
  endianness signal (sqfs4.0 is always LE on-disk) — the binaries are BE.
- Kernel: Linux 2.6.30.9 · squashfs4.0/LZMA rootfs · `root=/dev/mtdblock7`
- Priority diff pair: **2.05.B02 (OLD) → 2.06.B01 (NEW, security patch)**.

**CONFIRMED CANDIDATE (this run):** `htdocs/cgibin` — the sole ranked `fw_diff` hit.
- Patch signature (readelf/strings): **only new import = `access()`**; new strings =
  `access`, `"%s/%s.php"`, `"http://purenetworks.com/HNAP1/GetDeviceSettings"`.
- `.text` grew +144 B (real added code). `cgibin` base `.text` vaddr `0x00402c00`.
- **Working hypothesis:** path-handling fix (traversal / arbitrary file-or-script access) in
  the HNAP / action-script dispatch — `access()` added to validate a `"%s/%s.php"` path
  built from request-controlled input before it's opened/executed. Confirm or refute below.

---

## 0. Prereqs
- [ ] `extract-and-diff.sh` has run → `work/rootfs_205b02/`, `work/rootfs_206b01/`,
      `diff-out/diff-candidates.csv`, `diff-out/changed.txt` exist.
- [ ] Ghidra 11.x installed (needs JDK 17+). Diaphora *or* Ghidra Version Tracking
      for function-level matching. Optional: `qemu-user-static` for P2.3.

## 1. Pick the candidate (don't skip the cross-check)
- [ ] Open `diff-out/diff-candidates.csv`. Rank by `score`; note `likely_bug_side`
      (want **OLD (silent fix)**), `sink_delta` (want negative in NEW), and
      `notable_new_strings` (bounds/`invalid`/`too long`/`overflow`/`sanitize` tells).
- [ ] Read `diff-out/changed.txt` — with a +108 B rootfs delta this is a *short* list;
      the changed ELF under `/bin /sbin /usr` or a `*.cgi`/`cgi-bin` path is your target.
- [ ] **Cross-check the vendor claim:** open `firmware/DIR-816L-REVB/notes/
      DIR-816L_REVB_FIRMWARE_PATCH_NOTES_2.06.B01_EN.PDF`. If the changed binary is
      NOT explained by the notes → **silent fix** (the whole point). Record that.
- [ ] Confirm reachability: is the file in `triage-out/206b01/services.txt`
      (httpd / goahead / mini_httpd / a CGI)? Attack surface = web-reachable.

## 2. Import both versions into Ghidra (get the language right)
- [ ] New project → import `work/rootfs_205b02/<path>/<bin>` **and** the 2.06.B01 copy.
- [ ] Language: **`MIPS:BE:32:default`** (big-endian — confirmed from the ELF). Compiler `default`.
- [ ] Auto-analyze with defaults **plus**: enable *MIPS Constant Reference Analyzer* and
      *MIPS-0 / GP-relative* handling. If the decompiler shows garbage globals, set the
      `_gp` value: find `gp` load in `_start`/`__start`, then
      *Options → Processor → "Assume default GP register value"* = that address.
- [ ] Most local functions are stripped; **imports survive** (dynamic symbols via PLT).
      You'll name functions by their xrefs to known imports.

## 3. Localize the changed function (OLD vs NEW)
- [ ] Diaphora: export each binary to a `.sqlite`, diff → the "partial/changed matches"
      list. *or* Ghidra Version Tracking: correlators (Exact Symbol, Exact Function
      Bytes, then Reference/Structural) → the function(s) that did **not** match are the patch.
- [ ] Expect a small number (often one). Open OLD and NEW side by side in the decompiler.
- [ ] **Fast path for this candidate:** in NEW, Symbol Tree → imports → **`access`** →
      *Show References To*. There should be ~one caller — that caller **is** the patched
      function. Look just above the `access()` call for the `sprintf`/`snprintf(..., "%s/%s.php",
      dir, name)` that builds the path, and trace where `name` comes from (§5). In OLD, the
      same function opens/uses that path with **no** `access()` guard — that's the bug.

## 4. Classify the patch (what did NEW add?)
Look at the delta in the changed function. Common RTL819x/SOHO fix shapes:

| NEW added… | Bug class (OLD) | CWE |
|---|---|---|
| length/bounds check before a copy | stack/heap buffer overflow | CWE-120/787 |
| `sprintf`→`snprintf`, `strcpy`→`strncpy` | unbounded write | CWE-120 |
| metachar filter / escaping before `system()` | command injection | CWE-78 |
| auth/session check at entry | auth bypass / missing authz | CWE-306/862 |
| bounds on an index/loop | OOB read/write | CWE-125/787 |

## 5. Trace the taint in the OLD (vulnerable) binary
Prove an untrusted **source** reaches a dangerous **sink** *without* the check NEW added.
Symbols to xref (match the sink_scan / fw_diff catalog):
- [ ] **Sources:** `websGetVar` `webGetVar` `nvram_get` `getenv` `recv` `recvfrom`
      `fgets` `read` `httpd_get` · plus HTTP query/`QUERY_STRING`, `Content-Length`, `Cookie`.
- [ ] **Sinks:** `system` `popen` `doSystem` `CsteSystem` `twSystem` `bcm_system`
      `execl*/execv*` `sprintf` `vsprintf` `strcpy` `stpcpy` `strcat` `sscanf` `gets`.
- [ ] In Ghidra: Symbol Tree → the sink import → *Show References To*. Walk each xref back
      to a source. The unbroken source→sink path (present in OLD, gated in NEW) is the bug.
- [ ] Note the exact param name / HTTP endpoint the tainted value arrives on (needed for the PoC and the report).

## 6. Reachability & preconditions (for CVSS)
- [ ] How is the function invoked? Trace from the httpd request dispatch / CGI handler
      table / URL route to this function.
- [ ] Auth required? (unauth pre-auth = higher severity). LAN-only or WAN-exposed by default?
- [ ] Record: attack vector (Network), UI/privs required — these become the CVSS v3.1 vector.

## 7. Record the finding (hand off to the report skill)
Fill these into `finding.json` (`finding-to-vendor-report` template):
- [ ] `component` (binary + function), `cwe`, `attack_vector`, tainted param/endpoint,
      the source→sink path, OLD vs NEW behavior, affected versions (≤2.05.B02; fixed 2.06.B01).
- [ ] Attach the decompiler before/after snippet (sanitized — no working payload pre-disclosure).

## 8. Dedup / novelty gate — DO THIS BEFORE claiming a CVE
DIR-816L is EOL + heavily researched; base rate says **n-day**, not fresh CVE. That's fine —
an n-day reproduction is still a strong public writeup. Confirm which it is:
- [ ] NVD: `DIR-816L <function>` , `DIR-816L <cgi name>` , `site:nvd.nist.gov DIR-816L`
- [ ] D-Link security advisories / SAP bulletins for the 2.0x range (esp. SAP10253 RTL SDK).
- [ ] RTL819x **SDK** CVEs — SDK bugs recur across vendors/models; a match here = n-day.
- [ ] Verdict per candidate → `acquisition-log.md` dedup ledger. Assigned = n-day study;
      silent/unassigned = CVE candidate → then the **fan-out** (grep the same pattern across
      DIR-850L / DIR-820L / DIR-818L; each confirmed model is a distinct affected product).

## 9. Next
Confirmed statically → **P2.2/P2.3**: run the binary under `qemu-mips-static` (big-endian; single CGI) or
FirmAE (full stack), craft the input that reaches the sink, capture the crash/RCE = the PoC.
Then `finding-to-vendor-report` → coordinated disclosure → `finding-to-cve-writeup`.
