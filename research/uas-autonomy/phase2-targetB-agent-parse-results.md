# Phase 2 · target B — Agent XRCE message-parse fuzz: **run results & assessment**

*The run record and **negative-result assessment** for [target B](phase2-h1-fuzz-harness-spec.md#2-target--system-under-test)
— the fidelity complement to [H1](phase2-h1-fuzz-results.md). Where H1 fuzzed the **client-side** `ucdr`
C decoders, target B fuzzes the **Agent-side** XRCE message-parse entry: the C++ `InputMessage` +
the generated `dds::xrce::*` type deserializers, driven by **Fast-CDR** (XCDRv1). This is the first
code that touches attacker bytes on the broker once a frame arrives on the (unauthenticated,
by-default) transport — and it reaches **H3** (entity-representation parsing) from the same rig.
Outcome: **no memory-safety violation** across ~736 M coverage-guided executions at a documented
plateau; the reached parse surface holds, with one precise coverage gap called out for the next run.*

> **Status: COMPLETE — negative result (Agent XRCE parse), with a documented coverage gap.**
> Run date **2026-10-01**, WSL Ubuntu 26.04. Harness: [`agent_fuzz/`](agent_fuzz/) (reusable CI target).

> **Scope, safety & ethics.** UNCLASSIFIED, open-source (eProsima Micro-XRCE-DDS-Agent / Fast-CDR,
> Apache-2.0). **DEFENSIVE and OFFLINE:** the harness parses attacker-controlled **bytes in-process**
> — no network, no Agent process, no DDS domain, no vehicle. No committed blobs/corpora. Negative
> result → nothing to disclose.

## 1. Outcome in one line

Against **instrumented** Fast-CDR **v2.3.1** + the real Agent XRCE type deserializers (Agent
**v3.0.2**), **~736 million** coverage-guided executions under **ASan + UBSan** reached a documented
plateau (**366 edges**, flat across both runs) with **zero crashes, OOMs, timeouts, or leaks**. All
**9 dispatched submessage payload types** and the XML/reference **entity-representation** paths (H3)
are covered and clean. The one input-reachable surface **not** exercised — the
`REPRESENTATION_IN_BINARY` QoS sub-decoders — is documented as the precise next target.

## 2. Pinned source & version baseline

| Repo | Pinned | Role |
|------|--------|------|
| `eProsima/Micro-XRCE-DDS-Agent` | **v3.0.2** / `a88c712b41a01e92583f4723f7f4f686863cf657` | parse objects under test (InputMessage + XRCETypes) |
| `eProsima/Fast-CDR` | **v2.3.1** / `c931bdefefcecb6f852ef7be02369f9d740d6929` | the Agent's XRCE deserializer — built from source + instrumented |

The Agent parses incoming XRCE with **Fast-CDR** (`eprosima::fastcdr::Cdr`, XCDRv1), *not* the
client's `ucdr`; it declares Fast-CDR 2.3.1. The two known Agent CVEs (2025-63547/63548) are v3.0.1
field-validation DoS and are fixed in the 3.0.2 line — we fuzz past that baseline.

## 3. Target & harness (first function to touch attacker bytes)

```
XRCE peer (unauth, UDP:8888 / TCP / serial)
   → Agent transport Receiver → Processing thread
   → InputMessage(buf,len)                 ← wraps bytes in FastBuffer+Cdr; deserializes MessageHeader
   → prepare_next_submessage()             ← reads SubmessageHeader (aligned)
   → get_payload<T>()  / get_raw_payload() ← Fast-CDR deserialize of the per-id XRCE payload type
       └─ dds::xrce::*::deserialize(Cdr&)  ← the generated type decoders (incl. entity rep = H3)
```

The harness ([`agent_fuzz.cpp`](agent_fuzz/agent_fuzz.cpp)) mirrors `Processor::process_submessage`:
build `InputMessage` from fuzz bytes, then walk submessages and deserialize each payload **by
submessage-id** exactly as the Agent dispatch does (CREATE → `CREATE_Payload` → `ObjectVariant`
union → representation decoders; the default path exercises `get_raw_payload`). It stops at **parse**
— no ProxyClient, no DDS. Fast-CDR's own exceptions are caught by `InputMessage` (the Agent's defense,
and the *safe* outcome); ASan/UBSan catch the memory-safety bugs. Only the Fast-CDR-dependent parse
objects are compiled (`XRCETypes/MessageHeader/SubMessageHeader.cpp`); `InputMessage::log_error()` is
stubbed to avoid pulling in Logger/spdlog/`config.hpp`, and `TopicPubSubType.cpp` (the sole Fast-DDS
dependency) is excluded — so the rig needs **only Fast-CDR**, not all of Fast-DDS.

## 4. Run record

| Field | Value |
|-------|-------|
| Run date / host / OS | 2026-10-01 · WSL Ubuntu 26.04 · x86-64 |
| Compiler / engine | clang 21.1.8, **libFuzzer** (fork=16) |
| Sanitizers | ASan + UBSan; Fast-CDR **and** the XRCE type objects compiled with the sanitizers + coverage (positive control: 145 `__asan` in `libfastcdr.a`, 185 in `libagent_parse.a`) |
| Corpus / provenance | 191 hand seeds (XCDRv1 header forms × 9 submessage ids × length edges + the H1 ucdr seeds) → evolved to **~685 units** (157 KB); offline, bytes git-ignored |
| Run 1 (no dict) | ~**320 M** execs, ~352 k/s aggregate, cov **366 edges / 2073 ft**, peak RSS ~52 MB, **0 crashes/OOMs/timeouts** |
| Run 2 (+`xrce.dict`) | +~**416 M** execs, ~456 k/s, cov **366 edges / 2080 ft** (unchanged ⇒ plateau robust to union-discriminator hints), **0 crashes/OOMs/timeouts** |
| **Total** | **~736 M** executions · coverage **366 edges**, flat across the final hundreds of millions of execs · **1406 functions covered** |
| Crashes (post-min) | **0** (also 0 OOMs / 0 timeouts / 0 leaks — `oom/timeout/crash: 0/0/0` throughout) |
| Outcome | **Negative result** on the reached parse surface; one documented coverage gap (§6). |

## 5. What is covered — the parse surface actually exercised (`-print_coverage=1`)

All nine dispatched submessage payload decoders are **covered and clean**:

`CREATE_CLIENT_Payload` · `CREATE_Payload` · `GET_INFO_Payload` · `DELETE_Payload` ·
`WRITE_DATA_Payload_Data` · `READ_DATA_Payload` · `ACKNACK_Payload` · `HEARTBEAT_Payload` ·
`TIMESTAMP_Payload`.

So are the entity-representation paths that make this reach **H3**:
`ObjectVariant::deserialize` (the `OBJK_*` union) · `CLIENT/AGENT/APPLICATION/PARTICIPANT/SUBSCRIBER
_Representation` · **`Formats::xml_string_representation`** (XML entity rep) · the reference rep ·
the outer **`Formats::binary_representation`** · `DataRepresentation` · `_deserialize_member_header`
(the XCDRv2 PL-CDR member-header reader). No input in ~736 M executions drove any of these to an OOB,
UB, over-allocation, or uncaught non-CDR exception.

**Why it holds (source):** Fast-CDR's read path gates every read on `remaining >= size_needed`
(`(end_ - offset_) >= n`) and throws `NotEnoughMemoryException` otherwise — caught by `InputMessage`.
Sequence/string decoders check the length against the remaining buffer **before** reading, so the
OOB-read class is structurally defended; the resize-to-attacker-length OOM class did **not** fire
(`oom/.../... : 0/0/0`), consistent with Fast-CDR bounding the allocation against the buffer.

## 6. Coverage gap — honest boundary (what was NOT exercised)

`-print_coverage=1` shows the input-reachable decoders the fuzzer did **not** reach: the inner
**`REPRESENTATION_IN_BINARY` QoS sub-structures** —
`OBJK_DomainParticipant_Binary`, `OBJK_{DataReader,DataWriter,Publisher,Subscriber,Topic}_Binary`,
`OBJK_{PUBLISHER,SUBSCRIBER,Endpoint}_QosBinary`, `OBJK_{Requester,Replier}_Binary`,
`OBJK_DOMAIN_Representation`, `OBJK_Representation3_Base`, plus `PackedSamples`/`Sample` (WRITE_DATA
sample sub-formats). These sit behind a valid binary-rep discriminator **and** XCDRv2 PL-CDR member
headers (length-delimited members) — exactly the length-handling code where an H3 bug would most
plausibly live. The mutator (even with `xrce.dict`) couldn't synthesize the nested member-header
structure to reach them.

The remaining uncovered `::deserialize` are **output/response types** the parse path never
deserializes (`STATUS_*`, `BaseObjectReply`, `DATA_Payload_*`, `INFO_Payload`, `ResultStatus`,
`*ActivityInfo`, `ObjectInfo`) — correctly out of scope for an input-parse harness.

**Recommended next step (the real residual H3 headroom):** a **grammar-aware** harness or
**captured seeds** for the binary-representation path — either a seed-generator that uses the Agent's
own `serialize` to emit valid `CREATE`+`REPRESENTATION_IN_BINARY` objects (so Fast-CDR encodes the
PL-CDR member headers correctly, giving the fuzzer a template), or a loopback capture of a real
client creating binary-rep entities. That targets the `OBJK_*_Binary` decoders directly.

## 7. Dedup verdict

No candidate crashes to dedup. The 2026-10-01 re-sweep ([`known-territory.md`](known-territory.md))
confirms the Agent-side **deep submessage/entity parsing** is unclaimed: the only two Agent CVEs are
v3.0.1 field-validation DoS (not the type deserializers), no Agent commit since baseline touches the
parse path, and the Fast-DDS OOB/OOM CVEs are a different codebase (Fast-DDS RTPS/CDR, not the Agent's
XRCE Fast-CDR parse). THIN surface; clean negative on the reached part.

## 8. Deliverables & build/break symmetry

- **The harness is the durable control.** [`agent_fuzz/`](agent_fuzz/) builds Fast-CDR from source
  (instrumented) + the Agent's real XRCE parse objects into a drop-in **libFuzzer CI target**, with
  a `--selftest` standalone and a committed `xrce.dict`. It fuzzes the Agent's unauthenticated parse
  surface with no network and no Fast-DDS build.
- **No patch warranted** on the reached surface (invariants hold). The engineering value is the CI
  target + the §6 pointer to the binary-rep sub-decoders as the next, grammar-aware refinement.
- **Deployment posture (from H5):** bind the Agent to loopback / a segmented interface and require
  DDS-Security so the parser is not exposed to arbitrary peers.

## 9. Reproduce

```bash
sudo apt install -y clang cmake
git clone --depth 1 --branch v3.0.2 https://github.com/eProsima/Micro-XRCE-DDS-Agent.git ~/src/Micro-XRCE-DDS-Agent
git clone --depth 1 --branch v2.3.1 https://github.com/eProsima/Fast-CDR.git           ~/src/Fast-CDR
cd research/uas-autonomy/agent_fuzz
CC=clang CXX=clang++ cmake -B build -DAGENT_SRC=~/src/Micro-XRCE-DDS-Agent -DFETCHCONTENT_SOURCE_DIR_FASTCDR=~/src/Fast-CDR
cmake --build build -j"$(nproc)"
./build/agent_fuzz_standalone --selftest
mkdir -p corpus && cp seeds/*.bin corpus/
./build/agent_fuzz -max_len=4096 -dict=xrce.dict -fork="$(nproc)" -max_total_time=900 corpus/
./build/agent_fuzz -runs=0 -print_coverage=1 corpus/   # which decoders are covered
```

## 10. Sources

- Harness: [`agent_fuzz/`](agent_fuzz/) · spec target-B row: [`phase2-h1-fuzz-harness-spec.md`](phase2-h1-fuzz-harness-spec.md)
- Sibling result (client ucdr): [`phase2-h1-fuzz-results.md`](phase2-h1-fuzz-results.md)
- Scope & hypotheses (H3): [`phase2-micro-xrce-dds-scope.md`](phase2-micro-xrce-dds-scope.md) · dedup: [`known-territory.md`](known-territory.md)
- Agent parse: `src/cpp/message/InputMessage.cpp`, `src/cpp/processor/Processor.cpp`, `src/cpp/types/XRCETypes.cpp` (Agent `a88c712…`)
- Fast-CDR read bounds: `src/cpp/Cdr.cpp` (Fast-CDR `c931bde…`)
