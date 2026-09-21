# `ucdr_fuzz` — Micro-CDR (`ucdr`) decode fuzz harness (Phase 2 · H1)

In-process libFuzzer/AFL++ harness for **eProsima Micro-CDR** — the `ucdr` deserialize
primitives the Micro-XRCE-DDS Agent reaches when it decodes an XRCE submessage body. It feeds
attacker-controlled bytes through an XRCE-shaped header + an opcode-driven body decoder that
drives every length-prefixed primitive (`string` / `sequence_*` / `array_*`), under
**ASan + UBSan**, to prove `ucdr` clamps hostile lengths instead of overrunning its buffer.

This is the tool behind the H1 line of work (the "most likely clean CVE" bet — the thin parser
Phase 0 flagged with only two field-validation DoS CVEs):

- **Spec / methodology:** [`../phase2-h1-fuzz-harness-spec.md`](../phase2-h1-fuzz-harness-spec.md)
- **Target scope & ranking (H1):** [`../phase2-micro-xrce-dds-scope.md`](../phase2-micro-xrce-dds-scope.md)
- **Dedup / prior art:** [`../known-territory.md`](../known-territory.md)

> **⚠️ Scope & safety — DEFENSIVE, in-process, no network.** This parses **bytes**, not
> packets: no vehicle, no Agent, no traffic. Any live seed capture is **loopback-only** on a
> host you own. Research / defensive use under coordinated disclosure; see
> [`../../../docs/disclosure-policy.md`](../../../docs/disclosure-policy.md). Blobs and corpora
> are git-ignored — commit hashes and provenance go in the paperwork, never the bytes.

## Build

Requires **Micro-CDR** installed (provides the `microcdr` CMake package + `ucdr/microcdr.h`).
It ships as a submodule of the Micro-XRCE-DDS-Client superbuild, or standalone:

```bash
# standalone Micro-CDR (pin the commit; record the hash in ../phase2-h1-fuzz-harness-spec.md §2)
git clone https://github.com/eProsima/Micro-CDR.git ~/Micro-CDR
cd ~/Micro-CDR && cmake -B build && cmake --build build -j"$(nproc)" \
  && sudo cmake --install build && sudo ldconfig
```

Then build the harness (Clang gives you the libFuzzer target; any compiler gives the standalone):

```bash
CC=clang cmake -B build && cmake --build build -j"$(nproc)"
```

## Self-test first (no fuzzing engine needed)

```bash
./build/ucdr_fuzz_standalone --selftest
# SELFTEST PASS — harness decoded 6 seeds without crashing.
```

The self-test runs built-in edge shapes (empty, all-zero, header-only, an oversized
string-length that MUST clamp, plus the two known-CVE shapes — invalid-boolean 2025-63548 and
zero-length-body 2025-63547) as a deterministic regression check on the harness logic itself.

## Fuzz (SITL not required — this is offline byte-fuzzing)

```bash
# libFuzzer (primary): seed from real loopback XRCE traffic — see spec §4.
mkdir -p corpus && ./build/ucdr_fuzz -max_len=4096 corpus/ seeds/

# reproduce a crash the fuzzer saved:
./build/ucdr_fuzz crash-<hash>
#   or, instrumented, with the portable driver:
./build/ucdr_fuzz_standalone crash-<hash>
```

For coverage-guided AFL++ instead of libFuzzer: configure with `CC=afl-clang-fast`, then
`afl-fuzz -i seeds -o out -- ./build/ucdr_fuzz_standalone @@`.

Recommended sanitizer env for triage:

```bash
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:strict_string_checks=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
```

## Notes

- The harness calls the length-prefixed decoders (`ucdr_deserialize_string`,
  `ucdr_deserialize_sequence_char/uint8_t/uint16_t`, `ucdr_deserialize_array_*`) against a
  **bounded 256-byte destination**. A correct `ucdr` sets `mb.error` when the wire length
  exceeds capacity; an OOB write there is exactly the H1 finding, and ASan turns it into a
  recorded crash. Confirm the exact signatures against your pinned Micro-CDR commit — a
  version skew is a one-line fix (the same caveat the [`../xrce_probe`](../xrce_probe) probe
  notes for the 4-arg transport).
- Every crash is a **candidate**, not a finding: minimize (`-minimize_crash=1`), root-cause in
  source, then run it through the **Phase 0 dedup gate** (spec §6) before any novelty claim.
- A `sequence`/`string` that merely returns `false` (error set) on a hostile length is the
  **safe** outcome — that is `ucdr` doing its job, and it is the negative result the assessment
  writes up if fuzzing stays clean.
