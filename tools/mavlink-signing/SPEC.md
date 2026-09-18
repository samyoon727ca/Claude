# P6.2 — MAVLink v2 signing module (Rust)

> **Status: built (2026-09-18) — 7/7 `cargo test` green**, including two interop tests
> against a real pymavlink-signed frame (Rust *verifies* it, and Rust *sign* reproduces it
> byte-for-byte) and a SHA-256 known-answer test. Crate: `Cargo.toml` + `src/lib.rs`
> (zero external dependencies). This file is both the design spec and the module's README.

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
by `cargo test`, cross-checked against pymavlink. Optionally wrap the verifier as a small
proxy in front of the harness link later; the KAT/interop proof stands on its own.

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
