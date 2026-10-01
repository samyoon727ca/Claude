//! End-to-end proof that the signing gateway enforces policy *on the wire*.
//!
//! These tests stand up a real UDP `UdpGateway` on localhost, push frames through it from a
//! "GCS" socket, and assert what arrives at the "autopilot" socket on the far side. This is
//! the before/after the plan calls for: the same signing control proven not just by unit
//! verdicts but by bytes traversing actual sockets through the proxy.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mavlink_signing::gateway::{Gateway, Policy, UdpGateway};
use mavlink_signing::{sign_frame, SigningKey};

// pymavlink interop vectors (key = 00..1f, link_id = 7, ts = 0x0102030405).
const SIGNED: &str = "fd090100000101000000000000000203000303a8a307050403020100828f8b8e1c6b";
const BASE: &str = "fd090100000101000000000000000203000303a8a3";
const IFLAG_SIGNED: u8 = 0x01;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn test_key() -> SigningKey {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    SigningKey(k)
}

/// Bind the three parties: an autopilot (protected) socket, the gateway, and a GCS sender.
fn setup(policy: Policy) -> (UdpSocket, UdpGateway, UdpSocket, SocketAddr) {
    let autopilot = UdpSocket::bind("127.0.0.1:0").unwrap();
    autopilot
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let autopilot_addr = autopilot.local_addr().unwrap();

    let gw = Gateway::new(test_key(), policy);
    let proxy = UdpGateway::bind("127.0.0.1:0".parse().unwrap(), autopilot_addr, gw).unwrap();
    let proxy_addr = proxy.local_addr().unwrap();

    let gcs = UdpSocket::bind("127.0.0.1:0").unwrap();
    (autopilot, proxy, gcs, proxy_addr)
}

/// Send one datagram GCS -> proxy, pump the proxy once, and report whether the autopilot
/// received anything (and, if so, the exact bytes).
fn push(
    gcs: &UdpSocket,
    proxy: &mut UdpGateway,
    proxy_addr: SocketAddr,
    autopilot: &UdpSocket,
    datagram: &[u8],
) -> Option<Vec<u8>> {
    gcs.send_to(datagram, proxy_addr).unwrap();
    proxy.pump_once().unwrap();
    let mut buf = [0u8; 65535];
    match autopilot.recv_from(&mut buf) {
        Ok((n, _)) => Some(buf[..n].to_vec()),
        Err(_) => None, // read timeout -> nothing forwarded
    }
}

#[test]
fn require_signed_forwards_valid_drops_the_rest() {
    let (autopilot, mut proxy, gcs, paddr) = setup(Policy {
        require_signed: true,
    });

    // 1. A correctly-signed frame reaches the autopilot byte-for-byte.
    let signed = unhex(SIGNED);
    assert_eq!(
        push(&gcs, &mut proxy, paddr, &autopilot, &signed),
        Some(signed.clone()),
        "signed frame must be forwarded intact"
    );

    // 2. An unsigned frame is blocked before the autopilot.
    let mut unsigned = unhex(BASE);
    unsigned[2] &= !IFLAG_SIGNED;
    assert_eq!(
        push(&gcs, &mut proxy, paddr, &autopilot, &unsigned),
        None,
        "unsigned frame must be dropped under require_signed"
    );

    // 3. A tampered signed frame (one flipped byte in the signed region) is blocked.
    let mut tampered = signed.clone();
    tampered[12] ^= 0x01;
    assert_eq!(
        push(&gcs, &mut proxy, paddr, &autopilot, &tampered),
        None,
        "forged/tampered frame must be dropped"
    );

    // 4. Replay of the already-accepted frame #1 is blocked (same timestamp).
    assert_eq!(
        push(&gcs, &mut proxy, paddr, &autopilot, &signed),
        None,
        "replayed frame must be dropped"
    );

    let s = proxy.stats();
    assert_eq!(s.forwarded, 1);
    assert_eq!(s.dropped_unsigned, 1);
    assert_eq!(s.dropped_bad_sig, 1);
    assert_eq!(s.dropped_replay, 1);
}

#[test]
fn monotonic_timestamps_pass_in_order() {
    let (autopilot, mut proxy, gcs, paddr) = setup(Policy {
        require_signed: true,
    });
    let key = test_key();
    let base = unhex(BASE);
    let f1 = sign_frame(&base, &key, 7, 0x0102030405);
    let f2 = sign_frame(&base, &key, 7, 0x0102030406);

    assert_eq!(push(&gcs, &mut proxy, paddr, &autopilot, &f1), Some(f1.clone()));
    assert_eq!(push(&gcs, &mut proxy, paddr, &autopilot, &f2), Some(f2));
    // f1 again is now stale.
    assert_eq!(push(&gcs, &mut proxy, paddr, &autopilot, &f1), None);
    assert_eq!(proxy.stats().forwarded, 2);
    assert_eq!(proxy.stats().dropped_replay, 1);
}

#[test]
fn allow_unsigned_passes_cleartext_through() {
    let (autopilot, mut proxy, gcs, paddr) = setup(Policy {
        require_signed: false,
    });
    let mut unsigned = unhex(BASE);
    unsigned[2] &= !IFLAG_SIGNED;
    assert_eq!(
        push(&gcs, &mut proxy, paddr, &autopilot, &unsigned),
        Some(unsigned.clone()),
        "with require_signed off, unsigned traffic passes"
    );
    // ...but a tampered *signed* frame is still rejected even in pass-through mode.
    let mut tampered = unhex(SIGNED);
    tampered[12] ^= 0x01;
    assert_eq!(push(&gcs, &mut proxy, paddr, &autopilot, &tampered), None);
    assert_eq!(proxy.stats().passed_unsigned, 1);
    assert_eq!(proxy.stats().dropped_bad_sig, 1);
}

#[test]
fn run_loop_forwards_over_real_socket() {
    // Exercise the actual `run()` loop the binary uses, in a background thread.
    let autopilot = UdpSocket::bind("127.0.0.1:0").unwrap();
    autopilot
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let autopilot_addr = autopilot.local_addr().unwrap();

    let gw = Gateway::new(test_key(), Policy { require_signed: true });
    let mut proxy =
        UdpGateway::bind("127.0.0.1:0".parse().unwrap(), autopilot_addr, gw).unwrap();
    proxy
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        proxy.run(&stop_thread).unwrap();
    });

    let gcs = UdpSocket::bind("127.0.0.1:0").unwrap();
    let signed = unhex(SIGNED);
    gcs.send_to(&signed, proxy_addr).unwrap();

    let mut buf = [0u8; 65535];
    let (n, _) = autopilot
        .recv_from(&mut buf)
        .expect("run() loop should forward the signed frame");
    assert_eq!(&buf[..n], &signed[..]);

    stop.store(true, Ordering::Relaxed);
    handle.join().unwrap();
}
