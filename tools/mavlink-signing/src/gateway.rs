//! Inline signing-enforcement gateway (P6.2 depth) — puts [`verify_frame`] on the wire.
//!
//! A one-way MAVLink v2 relay that forwards only frames satisfying the signing policy
//! (signed + valid signature + fresh timestamp) and drops everything else: unsigned frames
//! (when signing is required), bad-signature frames (tampered / forged), replayed frames,
//! and malformed bytes. This is the *applied* T1 (command authenticity) / T5 (anti-replay)
//! control from the capstone, enforced inline on the command-ingress link:
//!
//! ```text
//!     GCS  ──unsigned/forged/replayed──▶  [ gateway ]  ──only Valid──▶  autopilot
//! ```
//!
//! The decision logic ([`Gateway`]) is pure and does no I/O, so it unit-tests without a
//! socket. [`UdpGateway`] is the thin UDP shell around it, exercised end-to-end over real
//! localhost sockets in `tests/wire.rs`.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::{verify_frame, ReplayState, SigningKey, Verdict};
use crate::{IFLAG_SIGNED, MAGIC_V2, SIG_BLOCK_LEN, V2_HEADER_LEN};

/// Signing policy for the gateway.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Reject frames that carry no signature. When `false`, unsigned frames pass through —
    /// but signed frames are *always* signature-checked, so tampering and replay are
    /// rejected regardless of this flag.
    pub require_signed: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_signed: true,
        }
    }
}

/// Running tally of the gateway's decisions — the raw numbers behind the before/after table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Signed, valid, fresh — forwarded.
    pub forwarded: u64,
    /// Unsigned, forwarded because `require_signed` was off.
    pub passed_unsigned: u64,
    /// Unsigned, dropped because `require_signed` was on.
    pub dropped_unsigned: u64,
    /// Signed but signature mismatch (tampered / forged) — dropped.
    pub dropped_bad_sig: u64,
    /// Signature valid but timestamp not newer than last accepted — dropped.
    pub dropped_replay: u64,
    /// Not a well-formed v2 frame / truncated — dropped.
    pub dropped_malformed: u64,
}

impl Stats {
    /// Total frames (and trailing-junk events) the gateway refused to forward.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_unsigned + self.dropped_bad_sig + self.dropped_replay + self.dropped_malformed
    }
}

/// Pure, I/O-free signing-enforcement decision engine.
///
/// Owns the signing key and the per-peer replay state. Feed it datagrams with
/// [`Gateway::filter_datagram`]; it returns the bytes that pass policy, ready to forward.
pub struct Gateway {
    key: SigningKey,
    policy: Policy,
    state: ReplayState,
    stats: Stats,
}

impl Gateway {
    /// Build a gateway for `key` under `policy`, with empty replay state.
    pub fn new(key: SigningKey, policy: Policy) -> Self {
        Self {
            key,
            policy,
            state: ReplayState::default(),
            stats: Stats::default(),
        }
    }

    /// A snapshot of the decision counters so far.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Filter one received datagram (which may hold one or more back-to-back v2 frames) and
    /// return the concatenated bytes that pass policy, in order. Updates stats and the
    /// anti-replay state as a side effect. A datagram that fully fails policy returns an
    /// empty `Vec` — i.e. nothing is forwarded.
    pub fn filter_datagram(&mut self, datagram: &[u8]) -> Vec<u8> {
        let (frames, trailing_junk) = split_frames(datagram);
        let mut out = Vec::with_capacity(datagram.len());
        for f in frames {
            match verify_frame(f, &self.key, &mut self.state) {
                Verdict::Valid => {
                    out.extend_from_slice(f);
                    self.stats.forwarded += 1;
                }
                Verdict::Unsigned => {
                    if self.policy.require_signed {
                        self.stats.dropped_unsigned += 1;
                    } else {
                        out.extend_from_slice(f);
                        self.stats.passed_unsigned += 1;
                    }
                }
                Verdict::BadSignature => self.stats.dropped_bad_sig += 1,
                Verdict::Replay => self.stats.dropped_replay += 1,
                Verdict::Malformed => self.stats.dropped_malformed += 1,
            }
        }
        if trailing_junk {
            self.stats.dropped_malformed += 1;
        }
        out
    }
}

/// Total on-wire length of the v2 frame at the start of `buf`, or `None` if the start is not
/// a v2 magic byte or the full frame is not yet present.
pub(crate) fn frame_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < V2_HEADER_LEN || buf[0] != MAGIC_V2 {
        return None;
    }
    let payload = buf[1] as usize;
    let signed = buf[2] & IFLAG_SIGNED != 0;
    let total = V2_HEADER_LEN + payload + 2 + if signed { SIG_BLOCK_LEN } else { 0 };
    if buf.len() < total {
        None
    } else {
        Some(total)
    }
}

/// Split a datagram into consecutive v2 frames. Returns the frames parsed and a flag that is
/// `true` if any un-parseable trailing bytes remained (treated by the gateway as malformed).
pub fn split_frames(buf: &[u8]) -> (Vec<&[u8]>, bool) {
    let mut frames = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        match frame_len(&buf[i..]) {
            Some(n) => {
                frames.push(&buf[i..i + n]);
                i += n;
            }
            None => return (frames, true),
        }
    }
    (frames, false)
}

/// Thin UDP shell around a [`Gateway`]: receive on `listen`, forward passing bytes to
/// `forward_to` from a dedicated ephemeral `upstream` socket.
pub struct UdpGateway {
    gw: Gateway,
    listen: UdpSocket,
    upstream: UdpSocket,
    forward_to: SocketAddr,
}

impl UdpGateway {
    /// Bind the listen socket at `listen_addr` and an ephemeral upstream socket (on the same
    /// IP), forwarding passing frames to `forward_to`.
    pub fn bind(listen_addr: SocketAddr, forward_to: SocketAddr, gw: Gateway) -> io::Result<Self> {
        let listen = UdpSocket::bind(listen_addr)?;
        let upstream = UdpSocket::bind((listen_addr.ip(), 0))?;
        Ok(Self {
            gw,
            listen,
            upstream,
            forward_to,
        })
    }

    /// The actual address the listen socket is bound to (useful when `listen_addr` used port 0).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listen.local_addr()
    }

    /// A snapshot of the underlying gateway's decision counters.
    pub fn stats(&self) -> Stats {
        self.gw.stats()
    }

    /// Set a read timeout on the listen socket so [`UdpGateway::run`] can poll its stop flag.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.listen.set_read_timeout(dur)
    }

    /// Receive one datagram, filter it, and forward the passing bytes. Returns the number of
    /// bytes forwarded (`0` if the datagram was fully dropped). Blocks until a datagram
    /// arrives or the read timeout elapses (surfaced as a `WouldBlock`/`TimedOut` error).
    pub fn pump_once(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 65535];
        let (n, _src) = self.listen.recv_from(&mut buf)?;
        let passed = self.gw.filter_datagram(&buf[..n]);
        if passed.is_empty() {
            Ok(0)
        } else {
            self.upstream.send_to(&passed, self.forward_to)?;
            Ok(passed.len())
        }
    }

    /// Run the forward loop until `stop` is set. Requires a read timeout (set via
    /// [`UdpGateway::set_read_timeout`]) so the loop can observe `stop` between datagrams;
    /// read timeouts are swallowed, any other I/O error ends the loop.
    pub fn run(&mut self, stop: &AtomicBool) -> io::Result<()> {
        while !stop.load(Ordering::Relaxed) {
            match self.pump_once() {
                Ok(_) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_frame;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn test_key() -> SigningKey {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8; // 00 01 .. 1f — same vector as the lib interop tests
        }
        SigningKey(k)
    }
    // The pymavlink interop vectors (key = 00..1f, link_id = 7, ts = 0x0102030405):
    const SIGNED: &str = "fd090100000101000000000000000203000303a8a307050403020100828f8b8e1c6b";
    const BASE: &str = "fd090100000101000000000000000203000303a8a3";

    #[test]
    fn frame_len_signed_and_unsigned() {
        // signed: 10 header + 9 payload + 2 crc + 13 sig = 34
        assert_eq!(frame_len(&unhex(SIGNED)), Some(34));
        // unsigned base is header + payload + crc only, and its signed flag is set in the
        // vector, so as-is it looks "signed" and is therefore short -> None (incomplete).
        let mut unsigned = unhex(BASE);
        unsigned[2] &= !IFLAG_SIGNED; // clear signed flag -> 10 + 9 + 2 = 21 bytes, complete
        assert_eq!(frame_len(&unsigned), Some(21));
    }

    #[test]
    fn split_frames_handles_back_to_back_and_junk() {
        let mut two = unhex(SIGNED);
        two.extend_from_slice(&unhex(SIGNED));
        let (frames, junk) = split_frames(&two);
        assert_eq!(frames.len(), 2);
        assert!(!junk);

        let mut with_junk = unhex(SIGNED);
        with_junk.extend_from_slice(&[0x00, 0x11, 0x22]); // not a v2 frame
        let (frames, junk) = split_frames(&with_junk);
        assert_eq!(frames.len(), 1);
        assert!(junk);
    }

    #[test]
    fn enforces_signed_forwards_only_valid() {
        let mut gw = Gateway::new(test_key(), Policy { require_signed: true });
        let out = gw.filter_datagram(&unhex(SIGNED));
        assert_eq!(out, unhex(SIGNED)); // forwarded intact
        assert_eq!(gw.stats().forwarded, 1);
    }

    #[test]
    fn enforces_signed_drops_unsigned() {
        let mut unsigned = unhex(BASE);
        unsigned[2] &= !IFLAG_SIGNED;
        let mut gw = Gateway::new(test_key(), Policy { require_signed: true });
        let out = gw.filter_datagram(&unsigned);
        assert!(out.is_empty());
        assert_eq!(gw.stats().dropped_unsigned, 1);
    }

    #[test]
    fn allow_unsigned_passes_it_through() {
        let mut unsigned = unhex(BASE);
        unsigned[2] &= !IFLAG_SIGNED;
        let mut gw = Gateway::new(test_key(), Policy { require_signed: false });
        let out = gw.filter_datagram(&unsigned);
        assert_eq!(out, unsigned); // passed through
        assert_eq!(gw.stats().passed_unsigned, 1);
        assert_eq!(gw.stats().forwarded, 0);
    }

    #[test]
    fn drops_tampered_and_replayed() {
        let key = test_key();
        let base = unhex(BASE);
        let f1 = sign_frame(&base, &key, 7, 0x0102030405);
        let f2 = sign_frame(&base, &key, 7, 0x0102030406);

        let mut gw = Gateway::new(test_key(), Policy { require_signed: true });
        assert_eq!(gw.filter_datagram(&f1), f1); // fresh -> forwarded
        assert_eq!(gw.filter_datagram(&f2), f2); // newer -> forwarded
        assert!(gw.filter_datagram(&f1).is_empty()); // old ts -> replay, dropped

        let mut tampered = f2.clone();
        tampered[12] ^= 0x01; // flip a byte inside the signed region
        assert!(gw.filter_datagram(&tampered).is_empty());

        let s = gw.stats();
        assert_eq!(s.forwarded, 2);
        assert_eq!(s.dropped_replay, 1);
        assert_eq!(s.dropped_bad_sig, 1);
    }
}
