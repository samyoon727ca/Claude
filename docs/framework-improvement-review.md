# Framework Improvement Review

_Self-assessment of the assessment framework itself — 2026-09-17._

A review of what the portfolio has built (three Track 1 runs, a six-skill funnel,
four Track 2 docs, the mavlink harness) and where the **process** can be made more
efficient and the **results** more substantial. Grounded in the current code, not
aspiration. Companion to [`artifact-plan.md`](artifact-plan.md); this doc proposes
changes *to the method*, the plan tracks *deliverables*.

## The one-sentence diagnosis

**The framework has automated the cheap 80% (finding leads) and left manual the
expensive 20% (confirming, reproducing, and dedup'ing them) — which is exactly the
part that turns work into externally-verifiable results.** Every stall in the plan
lands in that last mile: run 2 died at acquisition, the DrayTek finding is stuck at
"PoC pending," P5.1 is stuck at "hands-on pending." Both goals the user named —
efficiency *and* substance — are unlocked by pushing automation into the last mile
instead of adding more front-of-funnel breadth.

Concretely, the funnel today is:

```mermaid
flowchart LR
  A[acquire] --> B[triage.sh] --> C[fw_diff.py] --> D[Ghidra by hand] --> E[confirm by hand] --> F[dedup by hand] --> G[report + CVE]
  B -.automated.-> C
  C -.MANUAL GAP.-> D
  D -.MANUAL GAP.-> E
  E -.MANUAL GAP.-> F
```

Steps A, D, E, F are where every run actually spends its time and tokens, and they
are the least tooled. That is the target.

---

## What's working (keep it)

- **The funnel decomposition is right.** triage → diff → report → CVE → viz is the
  correct pipeline, and the "a hit is a LEAD, not a bug" discipline is stated in
  every script and SKILL.md. Don't dilute that.
- **Dependency hygiene is excellent.** stdlib-only Python, `readelf`-optional with
  string-scrape fallback, no exotic deps. This is why the tooling is auditable and
  portable — preserve it.
- **The honesty ledger and dedup discipline** (runbook §6, the run-2 "blocked at
  acquisition" writeup) are the credibility backbone. A framework that records its
  own failures is more convincing than one that only shows wins.
- **The DrayTek finding is real, code-level work.** The auth-gate resolution and
  the byte-for-byte sanitizer blocklist decode are the strongest evidence in the
  portfolio. The improvements below are about reproducing *that depth* faster, not
  replacing it.

---

## Efficiency improvements (ranked by leverage)

### E1 — Promote the per-run Ghidra one-offs into the binary-diff skill *(highest leverage)*
Right now `research/dlink-rtl819x/ghidra/` and `research/draytek-vigor/ghidra/`
each hold bespoke headless scripts (9 in total: `decompile_named`,
`dump_action_table`, `dump_asm`, `find_dispatch`, `export_callers`, …) that were
re-authored per run. We are on **run 3** — this is precisely the "build the Skill
the third time you'd repeat a task by hand" rule from the plan, unapplied.

The `fw_diff.py`→Ghidra handoff is the single biggest manual, token-heavy step in
every run, and it is currently prose ("run Ghidra headless on both versions and
diff with Diaphora"). Fix: add `.claude/skills/binary-diff/scripts/ghidra/` with a
generalized **function-diff stage** that consumes `diff-candidates.csv`, runs
headless decompilation of the changed/reachable functions on *both* versions, and
emits a per-candidate unified C diff. That converts the most expensive step from
"reverse it by hand each time" to "read the auto-generated function diff." The
generic primitives are already written twice — they just need to move up and take
a target argument instead of hardcoded addresses.

### E2 — Score by call-site count and source→sink proximity, not symbol presence
`sink_scan.py::score_native` adds a fixed weight if a sink **symbol is imported**,
regardless of how many times it is called. A binary that calls `system()` once and
one that calls it 40 times score identically on that axis, and `reachable_hint` is
just "does this file mention any source symbol." That produces a lead *set*, not a
usefully *ranked* list. Improvement: weight by relocation/xref *count* per sink,
and (bigger win) score the source→sink **distance** so "untrusted input flows into
a sink in the same function" outranks "both appear somewhere in a 2 MB binary."
This directly shortens the reversing queue.

### E3 — Add a format-string-hardening detector to the diff
The portfolio's best finding was the `%s` → `'%s'` quoting change in DrayTek's
`system()` format string. `fw_diff.py::SECFIX_RX` would **not** have caught that —
it matches English words ("invalid", "overflow"), not quoting deltas. Add an
explicit signal: quotes newly wrapping `%s` inside a `system`/`popen`/`exec*`
format string across the version pair. This is a literal generalization of the
pattern that produced the novel CVE candidate — it should be a first-class
detector, not something we noticed by luck.

### E4 — A persistent per-binary fingerprint + pattern cache
Every funnel invocation re-hashes and re-reads the whole tree. A small JSON/SQLite
cache keyed on sha256 lets the funnel skip unchanged binaries — but the real payoff
is **fan-out**: store each confirmed finding's structural pattern (sink + sanitizer
signature + endpoint) so it can be matched against other models automatically. The
DrayTek "grep the same pattern across 2960/3900/165x" step (finding §Open-items 2)
is currently manual; a pattern DB turns one finding into a model-family sweep, which
is the highest *substance*-per-token multiplier available.

### E5 — Model the CGI dispatch table, not just the binary
The DrayTek finding hinged on the 137-entry action-dispatch table (`action=` →
handler). The funnel's notion of "reachable" is `services.txt` basename matching
(`fw_diff.py::basename_set`), which says "this binary is a service," not "this
*endpoint* reaches this sink." A reusable dispatch/endpoint enumerator (already
half-built as the one-off `dump_action_table.java`) would upgrade every lead from
"binary has sinks" to "endpoint X reaches sink Y as role Z" — the exact framing the
vendor report needs anyway.

---

## Substance improvements (ranked)

### S1 — Build the emulation stage as a first-class skill *(the biggest substance gate)*
P2.2 (emulation harness) is `[planned]` and **no emulation tooling exists in the
tree** — it is prose in the runbook. Yet "runtime PoC" is what stands between the
DrayTek finding and a *proven* result, and it's the same wall P5.1 hits. Emulation
is the missing skill in the funnel. Make it as turnkey as `triage.sh`: a
`firmware-emulate` skill wrapping FirmAE / QEMU user-mode with the vendor-specific
nvram/httpd quirks captured as reusable config. Until this exists, every finding
caps at "confirmed at the code level," which is the ceiling the whole portfolio is
currently pressed against.

### S2 — Automate the dedup / novelty gate
Novelty is currently asserted via manual NVD/OpenCVE searches recorded in prose. A
false novelty claim is the single most reputation-damaging failure mode for this
work — so it should be the *most* reproducible step, not the least. Add a
`dedup_check.py` that queries the NVD and OpenCVE APIs for product + component +
CWE, caches the result set, and emits a dated dedup ledger entry. Cheaper per run
*and* it makes the "novel" claim defensible with a reproducible artifact instead of
a sentence.

### S3 — Generate the PoC scaffold from finding.json
The funnel jumps from "confirmed in Ghidra" straight to `finding-to-vendor-report`,
with the PoC (P2.3) left fully manual. But `finding.json` already carries the
endpoint, parameters, and payload. A minimal PoC-scaffold generator (for a CGI
finding: an authenticated HTTP request builder that drops in the endpoint + injected
param + a benign marker payload like `&{touch,/tmp/poc}`) makes the runtime step
faster and produces a reusable, sanitizable artifact. It also closes the loop with
S1: the emulator gives you the target, the scaffold gives you the request.

### S4 — A golden-corpus regression test for the funnel's *detection quality*
`run-checks.sh` §7 confirms `fw_diff.py` **runs** and writes a CSV — it does not
confirm the vulnerable file **ranks first**. So we can't currently tell whether a
change to the scoring (E2, E3) actually *improves detection* or just changes
numbers. Add a small golden corpus: a few synthetic (or fixture) old/new rootfs
pairs modeling real CVE-class patterns (unquoted-`%s` sink, `strcpy`→`strncpy`
fix, added CGI), with an assertion that the true positive lands in top-K. This is
what lets the funnel be *tuned* rather than just *maintained* — the only way to
iterate on substance instead of plumbing.

### S5 — Be honest about the stripped-binary limitation in the SKILL docs
On real embedded targets, binaries are usually stripped and statically linked
(uClibc/musl). In that case `fw_diff.py::func_symbols` returns empty (no FUNC
symbols → `syms_added/removed` churn signal is ~0) and `native_sink_count` falls
back to scraping symbol-name *strings*, which is unreliable for a static libc. So
on the real DrayTek/D-Link case, the **string-delta and file-hash signals carry
the diff**, not the symbol-delta ranking the SKILL.md advertises as "accurate." Two
fixes: (a) state this limitation in `binary-diff/SKILL.md` so the ranking isn't
over-trusted, and (b) add a capstone/xref-based sink counter (disassembly `bl`/call
targets) that works on stripped statics — which is what actually matters here.

---

## Process & strategy

### P1 — Commit the marginal hour to one proof path; stop hedging
The plan already says "declare the doc set done / freeze Track 2" — then still
queues **P6.1 (FPGA doc)** as a Track 2 writing artifact and encourages a parallel
"Track B." That's tension between "stop telling, start showing" and a plan that
still lists things to tell. Recommendation: **serialize hard on closing DrayTek**
(S1→S3: emulate → PoC → disclose → CVE) and explicitly defer *every* additive
artifact until that CVE lands. One proven CVE reprices the whole portfolio; a fifth
doc does not. Track B is a hedge against a stall — but the fix for the stall is S1
(tooling), not more prose in parallel.

### P2 — Separate acquisition-feasibility from target attractiveness in the rubric
Run 2 (Zyxel) was attractive but un-acquirable (ISP-gated firmware) — a full run's
worth of effort spent to learn that. The target-selection rubric should gate on
**"is the patched firmware publicly provenance-acquirable?"** *before* scoring
CVE-volume/freshness, so acquisition-dead targets are filtered at pick time, not at
run time. This is already the de-facto lesson (it drove the run-3 re-pick); make it
an explicit first-pass filter in `track1-target-selection.md`.

### P3 — Make cost visible per run
The plan preaches cost discipline but nothing records actual per-run cost/outcome.
A one-line ledger per run (target, tokens/effort, outcome: n-day / novel / blocked)
would let the "flag any track that stops earning its cost" rule actually fire on
data. Three runs in, this is cheap to start and compounds.

---

## Recommended sequence

Do these in order; each is scoped to be independently shippable.

1. **S1 — emulation skill** (unblocks DrayTek PoC *and* P5.1; the critical path).
2. **E1 — promote Ghidra scripts into binary-diff** (pays back every future run).
3. **S3 — PoC scaffold from finding.json** (pairs with S1 to close DrayTek).
4. **S2 — automated dedup** (de-risks the novelty claim before disclosure).
5. **S4 — golden-corpus test**, then **E2 + E3 + E5** (tune scoring against it —
   the test must exist first so tuning is measurable).
6. **E4 + E5(b) — pattern cache + xref sink counter** (enables DrayTek fan-out).
7. **P1/P2/P3 — plan edits** (fold in alongside; near-zero cost).

Items 1–3 convert the DrayTek finding from "confirmed at code level" to "proven
CVE" — the top-priority outcome in the existing plan. Items 4–6 make the *next*
run meaningfully cheaper and higher-yield than this one, which is the whole point
of a reusable funnel. The rest is bookkeeping that keeps the strategy honest.

---

_Verification: `tools/run-checks.sh` remains the gate. Note S4 — today it proves the
funnel executes, not that it detects; the golden corpus is what closes that gap._
