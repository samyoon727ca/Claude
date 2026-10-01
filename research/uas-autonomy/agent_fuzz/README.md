# `agent_fuzz` — Micro-XRCE-DDS **Agent** XRCE message-parse fuzz harness (Phase 2 · target B)

In-process libFuzzer harness for the **Agent-side** XRCE parse entry: the C++ `InputMessage` class +
the generated `dds::xrce::*` type deserializers, driven by **Fast-CDR** (XCDRv1). Where
[`../ucdr_fuzz`](../ucdr_fuzz) fuzzed the client's `ucdr` C decoders (H1), this fuzzes the broker's
own deserializer — the first code to touch attacker bytes once a frame arrives on the (unauthenticated
by default) transport — and reaches **H3** (entity-representation parsing) via `CREATE`.

- **Results / assessment:** [`../phase2-targetB-agent-parse-results.md`](../phase2-targetB-agent-parse-results.md)
- **Spec (target B row):** [`../phase2-h1-fuzz-harness-spec.md`](../phase2-h1-fuzz-harness-spec.md)
- **Dedup / prior art:** [`../known-territory.md`](../known-territory.md)

> **⚠️ Scope & safety — DEFENSIVE, in-process, no network.** Parses **bytes**, not packets: no Agent
> process, no DDS domain, no vehicle. Research / defensive use under coordinated disclosure; see
> [`../../../docs/disclosure-policy.md`](../../../docs/disclosure-policy.md). Blobs/corpora git-ignored.

## What it builds (and why it's light)

Only the **Fast-CDR-dependent** Agent parse objects are compiled —
`src/cpp/types/{XRCETypes,MessageHeader,SubMessageHeader}.cpp` — plus **Fast-CDR built from source and
instrumented**. `TopicPubSubType.cpp` (the only Fast-DDS dependency) is excluded, and
`InputMessage::log_error()` is stubbed in the harness so `InputMessage.cpp` (→ Logger/spdlog/generated
`config.hpp`) is not needed. So the rig needs **Fast-CDR only, not all of Fast-DDS**.

- Agent    **v3.0.2** (`a88c712…`) — the parse objects
- Fast-CDR **v2.3.1** (`c931bde…`) — the deserializer the Agent declares

## Build

```bash
git clone --depth 1 --branch v3.0.2 https://github.com/eProsima/Micro-XRCE-DDS-Agent.git ~/src/Micro-XRCE-DDS-Agent
git clone --depth 1 --branch v2.3.1 https://github.com/eProsima/Fast-CDR.git           ~/src/Fast-CDR

# Clang -> libFuzzer target (primary) + instrumented standalone; any c++ -> standalone only
CC=clang CXX=clang++ cmake -B build \
  -DAGENT_SRC=~/src/Micro-XRCE-DDS-Agent \
  -DFETCHCONTENT_SOURCE_DIR_FASTCDR=~/src/Fast-CDR
cmake --build build -j"$(nproc)"
```

Positive control (instrumentation really inside the libs):
`nm $(find build -name 'libfastcdr*.a') | grep -c __asan` → non-zero.

## Self-test, then fuzz

```bash
./build/agent_fuzz_standalone --selftest          # deterministic logic check; no engine needed

mkdir -p corpus && cp seeds/*.bin corpus/
./build/agent_fuzz -max_len=4096 -dict=xrce.dict -fork="$(nproc)" -max_total_time=900 corpus/
./build/agent_fuzz -runs=0 -print_coverage=1 corpus/   # which decoders are covered (see results §5/§6)
```

`xrce.dict` is a committed libFuzzer dictionary of XRCE union/parse gating constants (ObjectKind and
RepresentationFormat discriminators, the `XRCE` cookie, small XCDRv1 lengths).

## Notes

- The harness mirrors `Processor::process_submessage`: it dispatches each submessage to the correct
  `get_payload<T>()` by submessage-id, so it fuzzes the **real** Agent parse dispatch (incl. the
  `CREATE` → `ObjectVariant` → representation path = H3). Fast-CDR exceptions are caught by
  `InputMessage` (the safe outcome); ASan/UBSan catch memory-safety bugs.
- Every crash is a **candidate** — minimize (`-minimize_crash=1`), root-cause, then run the
  [dedup gate](../known-territory.md) before any novelty claim.
- **Known coverage gap** (results §6): the `REPRESENTATION_IN_BINARY` QoS sub-decoders
  (`OBJK_*_Binary` / `*_QosBinary`, PL-CDR member-header structures) are input-reachable but not
  reached by the byte mutator — the recommended next step is a grammar-aware / serialize-generated
  seed set for that path.
