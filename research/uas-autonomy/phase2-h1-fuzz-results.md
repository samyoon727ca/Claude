# Phase 2 · H1 — Micro-CDR (`ucdr`) decode fuzz: **run results & security assessment**

*The filled run record and the **negative-result assessment** for [H1](phase2-h1-fuzz-harness-spec.md) —
the highest-novelty-headroom hypothesis of the [Phase 2 scope](phase2-micro-xrce-dds-scope.md):
**does the Micro-XRCE-DDS Agent's `ucdr` decode path overrun its buffer on a crafted submessage**,
beyond the two known field-validation DoS CVEs? Outcome: **no — the length-prefixed invariant holds**
under ~693 M coverage-guided, sanitizer-instrumented executions at a documented plateau. Per the
[spec §8 / brief §9](phase2-h1-fuzz-harness-spec.md#8-deliverable--dod-p72--value-ships-either-way)
and the DrayTek ethos, a rigorous negative result is a first-class deliverable.*

> **Status: COMPLETE — negative result (ucdr decode).** Run date **2026-10-01**, WSL Ubuntu 26.04.
> No memory-safety violation found; the harness ships as a reusable CI fuzz target. The residual
> risk is pushed up to the **caller contract** (how the Agent uses `ucdr`) — see §6, which routes
> the next phase to target B / H2–H3, not back to the `ucdr` primitives.

> **Scope, safety & ethics.** UNCLASSIFIED, open-source (eProsima Micro-CDR / Micro-XRCE-DDS,
> Apache-2.0). **DEFENSIVE and OFFLINE:** the harness parses attacker-controlled **bytes in-process**
> — no network, no Agent, no vehicle. No committed blobs/corpora (provenance only). Coordinated
> disclosure; since this is a negative result there is **nothing to disclose** and no outbound
> contact is triggered.

## 1. Outcome in one line

Against **instrumented** Micro-CDR **v2.0.2** (the exact version the current Agent/Client ship),
**~693 million** coverage-guided executions under **ASan + UBSan** reached a **documented coverage
plateau** (163 edges saturated, 948 features) with **zero crashes, OOMs, timeouts, or leaks**. The
`ucdr` length-prefixed decoders (`sequence` / `string` / `array` / `basic`) **upheld the
memory-safety invariant** — a hostile length-prefix is rejected before any copy. H1 resolves as a
**rigorous negative result**, and the dedup sweep confirms the surface was genuinely **unclaimed**.

## 2. Pinned source & version-vs-known-CVE baseline (brief output #1)

| Repo | Pinned | SHA | vs. known CVEs |
|------|--------|-----|----------------|
| `eProsima/Micro-CDR` (`ucdr`) | **v2.0.2** | `99672492c5ef9fc378a8835b0bce9b2f7fa41306` | **no CVE of its own**; this *is* the latest release (tag 2025-09-30) |
| `eProsima/Micro-XRCE-DDS-Agent` | latest **v3.0.2** | tag `a88c712…` (2026-09-03) | CVE-2025-63547/63548 fixed after **v3.0.1** → we fuzz **past** the fix baseline ✓ |
| `eProsima/Micro-XRCE-DDS-Client` | **v3.0.2** | — | pins `microcdr **EXACT 2.0.2**` → confirms 2.0.2 is what the Agent actually ships |

The Agent transitively vendors `ucdr` through the Client superbuild; Client v3.0.2 (and `master`)
hard-pin Micro-CDR **EXACT 2.0.2**. So fuzzing v2.0.2 is faithful to the shipped Agent, and it is at
or newer than the release that fixed the two known DoS CVEs — the known bugs cannot mask a new one.

## 3. Parse-entry map (brief output #2 — first function touching attacker bytes)

```
XRCE peer (unauth, UDP:8888 / TCP / serial)
   → Agent: transport Receiver            (reads frame into a buffer)
   → Agent: Processing thread             (dispatch)
   → Micro-CDR ucdr_init_buffer(...)      (wraps the attacker bytes; no read yet)
   → ucdr_deserialize_uint8_t(...)        ← FIRST ucdr primitive to READ attacker bytes (basic.c)
   → ucdr_deserialize_{string,sequence_*,array_*}(...)   ← the H1 length-prefixed heart
   → submessage handlers (CREATE / WRITE_DATA / ...)
```

The harness (`ucdr_fuzz.c`) reproduces this in-process: `decode_once()` copies the fuzz input into an
**exactly-sized** heap allocation (so a one-byte over-read is a hard ASan `heap-buffer-overflow`,
not a silent read into slack), `ucdr_init_buffer`s it, decodes the XRCE message header, then runs an
opcode-driven body interpreter that drives **every length-prefixed primitive** across all element
widths with attacker-controlled lengths, alignments, and a declared-vs-real length mismatch.

## 4. Run record (brief output #3 — spec §5, filled)

| Field | Value |
|-------|-------|
| Run date / host / OS | 2026-10-01 · WSL Ubuntu **26.04 LTS** · x86-64 |
| Micro-CDR commit | **v2.0.2 / `99672492c5ef9fc378a8835b0bce9b2f7fa41306`** (built **from source, instrumented**) |
| Compiler / engine | **clang 21.1.8**, **libFuzzer** |
| Sanitizers | **ASan + UBSan** (`-fsanitize=fuzzer,address,undefined`, `-fno-sanitize-recover=all`); `ucdr` itself compiled with `address,undefined` + `fuzzer-no-link` (positive control: **63 `__asan` refs** in `libmicrocdr.a`) |
| Corpus / provenance | 66 hand seeds (known-CVE shapes + length-prefix edge cases + op-walks + lie-about-length + random); **no SITL capture needed** (offline byte-fuzzing). Grew to **204-unit** effective corpus (352 files on disk, 64 KB). Bytes git-ignored. |
| Exec/s · total execs · peak RSS | **~176 k/s** single-process; **~739 k/s** aggregate (fork=16). **~693 M** total execs (21.35 M @120 s + ~671.6 M @900 s). Peak RSS **555 MB** (single) / ~40 MB per fork worker. |
| Coverage | **163 edges — saturated from the first second and flat the entire run**; **948 features** (ramped 909→948, then flat across the final hundreds of millions of execs). |
| Crashes (unique, post-min) | **0** (also 0 OOMs / 0 timeouts / 0 leaks — `oom/timeout/crash: 0/0/0` on every status line) |
| Outcome | **Negative result** — `ucdr` decode upholds the memory-safety invariant; see §5. |

**Plateau evidence.** Edge coverage hit **163** immediately and never moved; feature coverage
stopped growing well before the end and held at **948** from ≈exec #584 M through #671 M (the full
sampled tail). A ~15-minute, 16-worker run adding **zero** new coverage over its final hundreds of
millions of executions is a saturated search of the harness-reachable surface — not an early stop.

## 5. Why it holds — the invariant, in the source (makes this an assessment, not just "found nothing")

The H1 bug class is *"attacker length-prefix → copy that many elements → overrun the destination."*
In v2.0.2 that is **structurally defended**. Every `sequence`/`string` decode funnels through one
header routine (`src/c/types/sequence.c`):

```c
inline void ucdr_deserialize_sequence_header(ucdrBuffer* ub, ucdrEndianness e,
                                             size_t capacity, uint32_t* length) {
    ucdr_deserialize_endian_uint32_t(ub, e, length);   // read the attacker length off the wire
    if (*length > capacity) { ub->error = true; }       // ← REJECT before any element is copied
}
// caller: return *length == 0 || ucdr_deserialize_endian_array_X(ub, e, array, *length);
```

Two independent bounds then both hold:

1. **Destination write is bounded** — the header sets `error` when `length > array_capacity`, so the
   element copy never runs with a length exceeding the caller's buffer. (`string.c` is just
   `sequence_char`, so it inherits this; the `+NUL` is included in `length ≤ capacity`.)
2. **Source read is bounded** — the element copy (`ucdr_buffer_to_array`, `array.c`) gates on
   `ucdr_check_buffer_available_for(ub, size)` (`iterator + bytes <= final`) and, on the short path,
   clamps to the remaining buffer via `ucdr_check_final_buffer_behavior_array` → it can only read
   what is actually present, setting `error` otherwise.

So a hostile length can at worst set `ub->error` and stop decoding — the **safe** outcome the harness
was built to confirm. ~693 M executions found no input that defeats this, consistent with the code.

## 6. Coverage-gap note (brief output — honest "what was and wasn't exercised")

A negative result is only as good as its scope statement. What this run **does** and **does not** cover:

- **Exercised (edge-saturated):** the XRCE message-header decode; all 12 `basic` scalar decoders;
  `string`; `sequence_char` / `sequence_uint8_t` / `sequence_uint16_t` (the 1-byte and multi-byte +
  alignment paths); `array_uint8_t` / `array_char`; the declared-vs-real `submessage_len` mismatch.
- **Not directly driven, but same template:** `sequence_`/`array_` for `uint32/uint64/int*/float/
  double` are macro-generated from the **identical** code as the covered `uint16`/`char` instances,
  differing only in `TYPE_SIZE`. The distinct logic (header check, alignment, clamp) is covered; the
  uncovered instantiations are parameter clones, not new paths.
- **Out of scope for H1 (the real residual risk → next phase):** the invariant in §5 is **contingent
  on the caller passing the true destination capacity**. The raw `ucdr_deserialize_array_*` API takes
  an attacker-influenced element `size` with **no capacity check** and computes `size * TYPE_SIZE` for
  the buffer check (a potential `size_t` multiply/pointer overflow for a caller that forwards a huge
  size). `ucdr` itself never calls that path with an unchecked wire length — but **the Agent might**.
  That moves the exposure up to **how the Agent wires `ucdr` into its submessage handlers / entity
  representation / FRAGMENT reassembly** — i.e. **target B (Agent parse entry), H2 (FRAGMENT), and
  H3 (entity XML/binary rep)**, not the `ucdr` primitives. That is where Phase 2 should point next.

## 7. Dedup verdict (brief output #4 — no candidate crashes; surface confirmed unclaimed)

With zero crashes there is no per-crash dedup, but the mandatory re-sweep (refreshed **2026-10-01**,
4 parallel sources — see [`known-territory.md` §2.4/§8](known-territory.md)) confirms H1 was aimed at
genuinely open ground, and the landscape **has not moved** since the 2026-09-21 baseline:

- **No CVE** exists beyond CVE-2025-63547 / 63548 for the Agent, and **Micro-CDR has none of its own**
  (its GHSA page: *"There aren't any published security advisories"*); the Client has none. Both known
  CVEs are **Agent-side** (C++ MTU alloc; Fast-CDR boolean exception) — **not** the `ucdr` decoder.
- **Silent-fix check (strongest anchor):** `sequence.c / string.c / array.c / basic.c / common.c`
  have had **no commits since 2021-11-25** — no post-v2.0.2 hardening of any bound or alignment. The
  only on-topic historical prior art is PR #54 (2020, zero-length-sequence alignment), long shipped.
- The newest eProsima CVEs (Fast-DDS 2026-22590 OOB read, 2026-22591 SQL-filter DoS) are **Fast-DDS
  RTPS/CDR**, a different codebase, and predate the baseline. No CISA ICS advisory names the Agent/CDR.
- Academic/blog sweep: all ucdr-adjacent literature is generic Fast-DDS/RTPS; the only `ucdr`-specific
  hit was **this project's own** prior work — i.e. **no external prior art** on the decode path.

Classification per [`known-territory.md` §6](known-territory.md): the `ucdr` decode surface was
**THIN** (correctly hunted); the result is a **clean negative**, not a MINED re-report.

## 8. Deliverables & break/build symmetry (brief output #5 / spec §7)

- **The harness is the durable control.** [`ucdr_fuzz/`](ucdr_fuzz/) now builds **Micro-CDR from
  source, instrumented** (FetchContent pinned to v2.0.2, ASan/UBSan + libFuzzer coverage *inside* the
  library) instead of linking a prebuilt archive that would hide the very OOB being hunted. It is a
  drop-in **OSS-Fuzz-style `LLVMFuzzerTestOneInput`** target — a reusable CI fuzz target so the parser
  stays fuzzed. The two known-CVE shapes are baked in as `--selftest` regression seeds.
- **No upstream patch is warranted** — the invariant already holds; proposing a "fix" would be noise.
  The engineering value is (a) the CI fuzz target above and (b) the §6 pointer that the real residual
  risk is the **caller contract**, which is the Agent's job, not `ucdr`'s.
- **Deployment posture (carried from H5):** bind the Agent to loopback / a segmented interface and
  require DDS-Security, so the decoder is never exposed to arbitrary peers in the first place.

## 9. Reproduce

```bash
# one-time: clang for libFuzzer
sudo apt install -y clang
# persistent local pin (offline-reusable)
git clone --depth 1 --branch v2.0.2 https://github.com/eProsima/Micro-CDR.git ~/src/Micro-CDR
# build (instrumented ucdr + libFuzzer) and fuzz
cd research/uas-autonomy/ucdr_fuzz
CC=clang cmake -B build -DFETCHCONTENT_SOURCE_DIR_MICROCDR=~/src/Micro-CDR
cmake --build build -j"$(nproc)"
./build/ucdr_fuzz_standalone --selftest                       # deterministic logic check
mkdir -p corpus && cp seeds/*.bin corpus/
./build/ucdr_fuzz -max_len=4096 -fork="$(nproc)" -max_total_time=900 corpus/   # plateau run
./build/ucdr_fuzz -runs=0 corpus/                             # final coverage snapshot
```

## 10. Sources

- Spec / methodology: [`phase2-h1-fuzz-harness-spec.md`](phase2-h1-fuzz-harness-spec.md) · harness [`ucdr_fuzz/`](ucdr_fuzz/)
- Dedup basis (re-swept 2026-10-01): [`known-territory.md`](known-territory.md)
- The H5 pivot that elevated H1: [`phase2-h5-test-results.md`](phase2-h5-test-results.md) §8
- Micro-CDR v2.0.2 decoders: `src/c/types/{sequence,string,array,basic}.c`, `src/c/common.c` (commit `99672492…`)
- CVE-2025-63547 / 63548 (Agent DoS, v3.0.1): <https://app.opencve.io/cve/CVE-2025-63547> · <https://app.opencve.io/cve/CVE-2025-63548>
- OMG DDS-XRCE wire spec: <https://www.omg.org/spec/DDS-XRCE>
