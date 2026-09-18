//! MAVLink v2 message signing (P6.2) — the control that closes the capstone's T1/T5 gap.
//!
//! Implements sign / verify / anti-replay per the MAVLink v2 signing convention:
//! a signed frame sets `incompat_flags` bit 0x01 and appends 13 bytes after the payload
//! CRC — `link_id` (1) + `timestamp` (6, little-endian) + `signature` (6). The signature
//! is the first 48 bits of `SHA-256( secret_key || frame_without_signature )`, where
//! `frame_without_signature` is the whole v2 frame from the magic through the appended
//! link_id + timestamp. The 48-bit timestamp (10 µs units) must be strictly monotonic per
//! `(sysid, compid, link_id)` — that is the anti-replay.
//!
//! No external dependencies (SHA-256 is implemented inline and known-answer tested), and
//! the sign/verify path is cross-checked against a real pymavlink-signed frame (see tests).
#![forbid(unsafe_code)]

use std::collections::HashMap;

pub const KEY_LEN: usize = 32;
const MAGIC_V2: u8 = 0xFD;
const IFLAG_SIGNED: u8 = 0x01;
const SIG_LEN: usize = 6;
const SIG_BLOCK_LEN: usize = 13; // link_id(1) + timestamp(6) + signature(6)
const V2_HEADER_LEN: usize = 10; // magic,len,incompat,compat,seq,sysid,compid,msgid(3)

/// A 32-byte MAVLink signing key.
pub struct SigningKey(pub [u8; KEY_LEN]);

/// Result of verifying a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Signed, signature valid, timestamp fresh.
    Valid,
    /// Frame does not carry the signed flag (policy may reject when signing is required).
    Unsigned,
    /// Signed flag set but the signature does not match the key.
    BadSignature,
    /// Signature valid but the timestamp is not greater than the last accepted one.
    Replay,
    /// Not a well-formed v2 frame / too short to hold a signature block.
    Malformed,
}

/// Per-peer last-accepted timestamp store, keyed by (sysid, compid, link_id).
#[derive(Default)]
pub struct ReplayState {
    last: HashMap<(u8, u8, u8), u64>,
}

fn compute_sig(key: &SigningKey, frame_without_sig: &[u8]) -> [u8; SIG_LEN] {
    let mut input = Vec::with_capacity(KEY_LEN + frame_without_sig.len());
    input.extend_from_slice(&key.0);
    input.extend_from_slice(frame_without_sig);
    let h = sha256::digest(&input);
    let mut out = [0u8; SIG_LEN];
    out.copy_from_slice(&h[..SIG_LEN]);
    out
}

/// Sign a v2 frame `base` that already carries the signed flag and a correct CRC
/// (magic .. CRC), by appending `link_id` + `timestamp` + signature. Returns the full frame.
pub fn sign_frame(base: &[u8], key: &SigningKey, link_id: u8, timestamp: u64) -> Vec<u8> {
    let mut f = base.to_vec();
    f.push(link_id);
    f.extend_from_slice(&timestamp.to_le_bytes()[..6]); // 48-bit little-endian
    let sig = compute_sig(key, &f);
    f.extend_from_slice(&sig);
    f
}

/// Verify a received frame's signature and freshness, updating the replay state on success.
pub fn verify_frame(frame: &[u8], key: &SigningKey, state: &mut ReplayState) -> Verdict {
    if frame.len() < V2_HEADER_LEN || frame[0] != MAGIC_V2 {
        return Verdict::Malformed;
    }
    if frame[2] & IFLAG_SIGNED == 0 {
        return Verdict::Unsigned;
    }
    // header + 2-byte CRC + 13-byte signing block is the minimum for a signed frame
    if frame.len() < V2_HEADER_LEN + 2 + SIG_BLOCK_LEN {
        return Verdict::Malformed;
    }
    let n = frame.len();
    let expect = compute_sig(key, &frame[..n - SIG_LEN]);
    if frame[n - SIG_LEN..] != expect {
        return Verdict::BadSignature;
    }
    let sysid = frame[5];
    let compid = frame[6];
    let link_id = frame[n - SIG_BLOCK_LEN];
    let mut ts = 0u64;
    for (i, b) in frame[n - SIG_BLOCK_LEN + 1..n - SIG_LEN].iter().enumerate() {
        ts |= (*b as u64) << (8 * i); // 48-bit little-endian timestamp
    }
    let last = state.last.entry((sysid, compid, link_id)).or_insert(0);
    if ts <= *last {
        return Verdict::Replay;
    }
    *last = ts;
    Verdict::Valid
}

// ------------------------------------------------------------------------------------
// Self-contained SHA-256 (FIPS 180-4). Known-answer tested below; no external crates.
// ------------------------------------------------------------------------------------
mod sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn digest(msg: &[u8]) -> [u8; 32] {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let bit_len = (msg.len() as u64).wrapping_mul(8);
        let mut data = msg.to_vec();
        data.push(0x80);
        while data.len() % 64 != 56 {
            data.push(0);
        }
        data.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in data.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
    fn test_key() -> SigningKey {
        let mut k = [0u8; 32];
        for i in 0..32 {
            k[i] = i as u8; // 00 01 .. 1f — matches the pymavlink vector below
        }
        SigningKey(k)
    }

    // Interop vector generated with pymavlink (key = 00..1f, link_id = 7, ts = 0x0102030405):
    // a signed v2 HEARTBEAT frame and its base (magic..CRC, signed flag set, no signing block).
    const SIGNED: &str =
        "fd090100000101000000000000000203000303a8a307050403020100828f8b8e1c6b";
    const BASE: &str = "fd090100000101000000000000000203000303a8a3";

    #[test]
    fn sha256_known_answer() {
        // FIPS 180-4 example: SHA-256("abc")
        assert_eq!(
            hex(&sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verifies_pymavlink_signed_frame() {
        let mut st = ReplayState::default();
        assert_eq!(
            verify_frame(&unhex(SIGNED), &test_key(), &mut st),
            Verdict::Valid
        );
    }

    #[test]
    fn sign_reproduces_pymavlink_frame() {
        let out = sign_frame(&unhex(BASE), &test_key(), 7, 0x0102030405);
        assert_eq!(hex(&out), SIGNED); // byte-for-byte interop with pymavlink
    }

    #[test]
    fn tampered_payload_is_bad_signature() {
        let mut f = unhex(SIGNED);
        f[12] ^= 0x01; // flip a byte inside the signed region
        let mut st = ReplayState::default();
        assert_eq!(verify_frame(&f, &test_key(), &mut st), Verdict::BadSignature);
    }

    #[test]
    fn replayed_frame_is_rejected() {
        let f = unhex(SIGNED);
        let mut st = ReplayState::default();
        assert_eq!(verify_frame(&f, &test_key(), &mut st), Verdict::Valid); // first: fresh
        assert_eq!(verify_frame(&f, &test_key(), &mut st), Verdict::Replay); // second: stale
    }

    #[test]
    fn unsigned_frame_is_flagged() {
        let mut f = unhex(BASE);
        f[2] &= !IFLAG_SIGNED; // clear the signed flag
        let mut st = ReplayState::default();
        assert_eq!(verify_frame(&f, &test_key(), &mut st), Verdict::Unsigned);
    }

    #[test]
    fn newer_timestamp_after_valid_is_accepted() {
        let key = test_key();
        let base = unhex(BASE);
        let mut st = ReplayState::default();
        let f1 = sign_frame(&base, &key, 7, 0x0102030405);
        let f2 = sign_frame(&base, &key, 7, 0x0102030406); // ts + 1
        assert_eq!(verify_frame(&f1, &key, &mut st), Verdict::Valid);
        assert_eq!(verify_frame(&f2, &key, &mut st), Verdict::Valid);
        assert_eq!(verify_frame(&f1, &key, &mut st), Verdict::Replay); // old ts now stale
    }
}
