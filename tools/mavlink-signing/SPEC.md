# P6.2 — MAVLink v2 signing module (Rust)

> **Status: built (2026-09-18) — core 7/7 `cargo test` green**, including two interop tests
> against a real pymavlink-signed frame (Rust *verifies* it, and Rust *sign* reproduces it
> byte-for-byte) and a SHA-256 known-answer test. **Extended (2026-10-01) with an inline
> signing-enforcement gateway** that puts the verifier *on the wire* (`src/gateway.rs` + the
> `mavlink-signing-proxy` binary), proven end-to-end over real localhost UDP sockets in
> `tests/wire.rs`. **17/17 green** (13 lib/unit + 4 on-the-wire integration), clippy-clean,
> wired into `tools/run-checks.sh` (guarded on `cargo`). Crate: `Cargo.toml` + `src/lib.rs` +
> `src/gateway.rs` + `src/bin/proxy.rs` (zero external dependencies). This file is both the
> design spec and the module's README.

**Role.** A memory-safe implementation of MAVLink v2 message signing (sign + verify +
anti-replay) — the *control* that closes the capstone's T1/T5 gap. It gives a
**deterministic before/after** (unsigned → rejected, signed → accepted, replayed →
rejected) without depending on ArduPilot's per-channel signing quirks, and it satisfies
the "systems language (Rust/C)" preferred qual. Feeds back into
[`../../docs/track2/uas-capstone-assessment.md`](../../docs/track2/uas-capstone-assessment.md)
(§6 before/after) and the [threat model](../../docs/track2/uas-autopilot-threat-model.md)
requirements for **T1** (command authenticity) and **T5** (anti-replay).

**Why Rust.** Signing sits on a parser/crypto boundary handling untrusted bytes off the
wire — the exact place memory-safety matters. Rust also maps to the JD's preferred
languages. (C is an acceptable alternative; the spec is language-neutral below.)

## Protocol (what "correct" means)
MAVLink v2 signing (per the MAVLink spec):
- A signed frame sets `incompat_flags` bit `0x01` (`MAVLINK_IFLAG_SIGNED`) and appends
  **13 bytes** after the payload CRC: `link_id` (1) + `timestamp` (6) + `signature` (6).
- `signature` = the first **48 bits** of `SHA-256( secret_key ‖ header ‖ payload ‖ CRC ‖
  link_id ‖ timestamp )`, where `secret_key` is **32 bytes**. (A truncated keyed hash —
  MAVLink's scheme; the threat model's "HMAC-SHA256" is the informal label.)
- `timestamp` is a 48-bit count of **10 µs** units since 2015-01-01 UTC, and MUST be
  strictly monotonic per `(sysid, compid, link_id)`; a receiver rejects a frame whose
  timestamp is `<=` the last accepted one → **anti-replay**.

## API (Rust sketch)
```rust
pub struct SigningKey([u8; 32]);
pub enum Verdict { Valid, Unsigned, BadSignature, Replay, BadTimestamp }

/// Append link_id + monotonic timestamp + 6-byte signature to a serialized v2 frame.
pub fn sign_frame(frame: &mut Vec<u8>, key: &SigningKey, link_id: u8, ts: u64);

/// Verify a received v2 frame against the key and the per-peer last-timestamp store.
pub fn verify_frame(frame: &[u8], key: &SigningKey, state: &mut ReplayState) -> Verdict;
```
Policy layer: `require_signed: bool` (reject `Unsigned` when true) — this is the "signing
enforced" switch the before/after toggles.

## Test plan (deterministic; no SITL, no network)
Known-answer + interop tests (`cargo test`):
1. **Unsigned → `Unsigned`** (rejected when `require_signed`).
2. **Correctly signed → `Valid`.**
3. **Tampered payload → `BadSignature`.**
4. **Replayed (ts ≤ last) → `Replay`.**
5. **Interop KAT vs pymavlink** — the repo already depends on pymavlink: sign a frame with
   this module, verify it with `pymavlink`'s signing; and sign with pymavlink, verify here.
   Cross-verification is the proof the implementation is spec-correct, not just
   self-consistent.

## Tie-back to the capstone (the clean before/after)
Report the control's behavior as the T1/T5 remediation evidence:

| Check | Unsigned input | Signed input | Replayed |
|-------|:--------------:|:------------:|:--------:|
| module verdict | `Unsigned`/reject | `Valid` | `Replay`/reject |

That table is the before/after the SITL channel fiddliness can't reliably give — measured
by `cargo test`, cross-checked against pymavlink. The KAT/interop proof stands on its own.

## Inline enforcement gateway (the control *on the wire*)
The verifier is wrapped as a one-way MAVLink v2 relay (`src/gateway.rs`) that enforces the
signing policy inline on the command-ingress link:

```text
    GCS ──unsigned/forged/replayed──▶  [ mavlink-signing-proxy ]  ──only Valid──▶  autopilot
```

- **`Gateway`** — the pure, I/O-free decision engine. `filter_datagram(&[u8]) -> Vec<u8>`
  splits a datagram into back-to-back v2 frames, runs each through `verify_frame`, and
  returns only the bytes that pass policy, tallying `Stats` (forwarded / passed_unsigned /
  dropped_{unsigned,bad_sig,replay,malformed}). The crypto core stays free of network and
  filesystem; this layer only decides.
- **`UdpGateway`** — the thin UDP shell (recv on the listen socket, forward passing bytes to
  the protected side from a dedicated upstream socket).
- **`mavlink-signing-proxy`** — the runnable binary:
  ```
  cargo run --bin mavlink-signing-proxy -- \
      --listen 127.0.0.1:14560 --forward 127.0.0.1:14550 --key-file mav.key
  # add --allow-unsigned to pass cleartext through (forged/replayed are still rejected)
  ```

**Policy semantics.** `require_signed` (default on) governs *unsigned* frames only; a signed
frame is always signature-checked and replay-checked, so tampering and replay are rejected
even with `--allow-unsigned`. That is the deployable T1/T5 control, not just a test verdict.

**End-to-end proof (`tests/wire.rs`).** Real localhost UDP, bytes through the proxy:

| Sent by "GCS"              | Reaches "autopilot"? | Gateway stat        |
|----------------------------|:--------------------:|---------------------|
| correctly signed           | yes, byte-for-byte   | `forwarded`         |
| unsigned (require-signed)  | no                   | `dropped_unsigned`  |
| tampered signed (1 bit)    | no                   | `dropped_bad_sig`   |
| replayed (ts ≤ last)       | no                   | `dropped_replay`    |
| unsigned (`--allow-unsigned`) | yes               | `passed_unsigned`   |

A `run()`-loop test also drives the exact forward loop the binary uses, in a background
thread, to confirm the loop (not just `pump_once`) relays over a live socket.

## Acceptance criteria
- All five tests pass under `cargo test`; interop KAT round-trips with pymavlink.
- No `unsafe`; no network or filesystem in the core; key handling zeroized on drop.
- A short results table lands in the capstone §6 before/after, replacing the placeholder.

## Build
```
# needs the Rust toolchain (rustup); if absent:
#   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo test        # runs the KAT + pymavlink interop suite
```
Crate lives here (`tools/mavlink-signing/`). Keep it dependency-light: a SHA-256 crate
(`sha2`) + std; no async, no network.
