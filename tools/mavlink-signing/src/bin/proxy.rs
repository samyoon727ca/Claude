//! `mavlink-signing-proxy` — an inline MAVLink v2 signing-enforcement gateway.
//!
//! Sits on the command-ingress link and forwards only frames that satisfy the signing
//! policy, dropping unsigned (unless `--allow-unsigned`), forged, replayed, and malformed
//! traffic. This is the P6.2 signing control applied *on the wire* rather than only proven
//! by `cargo test`.
//!
//!     GCS ──▶ (127.0.0.1:14560) [mavlink-signing-proxy] ──▶ autopilot (:14550)
//!
//! Example:
//!     mavlink-signing-proxy --listen 127.0.0.1:14560 --forward 127.0.0.1:14550 \
//!         --key-file /run/secrets/mav.key
//!
//! No external crates; filesystem touched only to read the key file, network only to relay.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use mavlink_signing::gateway::{Gateway, Policy, Stats, UdpGateway};
use mavlink_signing::{SigningKey, KEY_LEN};

const USAGE: &str = "\
mavlink-signing-proxy — inline MAVLink v2 signing-enforcement gateway

USAGE:
    mavlink-signing-proxy --listen <ADDR> --forward <ADDR> (--key <HEX> | --key-file <PATH>) [options]

REQUIRED:
    --listen <ADDR>      UDP address to receive from (the untrusted / GCS side), e.g. 127.0.0.1:14560
    --forward <ADDR>     UDP address to forward passing frames to (the protected / autopilot side)
    --key <HEX>          32-byte signing key as 64 hex chars
    --key-file <PATH>    read the 64-hex-char key from a file instead (keeps it out of `ps`)

OPTIONS:
    --allow-unsigned     pass unsigned frames through (signed frames are still checked); default: reject unsigned
    --quiet              do not print periodic stats
    --help               show this help
";

struct Args {
    listen: SocketAddr,
    forward: SocketAddr,
    key: SigningKey,
    allow_unsigned: bool,
    quiet: bool,
}

fn parse_key_hex(s: &str) -> Result<SigningKey, String> {
    let s = s.trim();
    if s.len() != KEY_LEN * 2 {
        return Err(format!(
            "key must be {} hex chars ({} bytes), got {}",
            KEY_LEN * 2,
            KEY_LEN,
            s.len()
        ));
    }
    let mut k = [0u8; KEY_LEN];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("invalid hex in key at byte {}", i))?;
    }
    Ok(SigningKey(k))
}

fn parse_args() -> Result<Args, String> {
    let mut listen: Option<SocketAddr> = None;
    let mut forward: Option<SocketAddr> = None;
    let mut key: Option<SigningKey> = None;
    let mut allow_unsigned = false;
    let mut quiet = false;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--allow-unsigned" => allow_unsigned = true,
            "--quiet" => quiet = true,
            "--listen" => {
                let v = it.next().ok_or("--listen needs an address")?;
                listen = Some(v.parse().map_err(|e| format!("bad --listen address: {e}"))?);
            }
            "--forward" => {
                let v = it.next().ok_or("--forward needs an address")?;
                forward = Some(v.parse().map_err(|e| format!("bad --forward address: {e}"))?);
            }
            "--key" => {
                let v = it.next().ok_or("--key needs a value")?;
                key = Some(parse_key_hex(&v)?);
            }
            "--key-file" => {
                let p = it.next().ok_or("--key-file needs a path")?;
                let contents =
                    std::fs::read_to_string(&p).map_err(|e| format!("reading {p}: {e}"))?;
                key = Some(parse_key_hex(&contents)?);
            }
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }

    Ok(Args {
        listen: listen.ok_or("missing --listen")?,
        forward: forward.ok_or("missing --forward")?,
        key: key.ok_or("missing --key or --key-file")?,
        allow_unsigned,
        quiet,
    })
}

fn print_stats(s: &Stats) {
    eprintln!(
        "[stats] forwarded={} passed_unsigned={} dropped: unsigned={} bad_sig={} replay={} malformed={} (total dropped={})",
        s.forwarded,
        s.passed_unsigned,
        s.dropped_unsigned,
        s.dropped_bad_sig,
        s.dropped_replay,
        s.dropped_malformed,
        s.dropped_total(),
    );
}

fn run(args: Args) -> std::io::Result<()> {
    let policy = Policy {
        require_signed: !args.allow_unsigned,
    };
    let gw = Gateway::new(args.key, policy);
    let mut proxy = UdpGateway::bind(args.listen, args.forward, gw)?;
    proxy.set_read_timeout(Some(Duration::from_millis(500)))?;

    eprintln!(
        "mavlink-signing-proxy: {} -> {} | policy: {}",
        proxy.local_addr()?,
        args.forward,
        if args.allow_unsigned {
            "pass unsigned, reject forged/replayed"
        } else {
            "require signing (reject unsigned/forged/replayed)"
        }
    );

    let mut last = Stats::default();
    let mut last_print = Instant::now();
    loop {
        match proxy.pump_once() {
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
        let now = proxy.stats();
        if !args.quiet && now != last && last_print.elapsed() >= Duration::from_secs(1) {
            print_stats(&now);
            last = now;
            last_print = Instant::now();
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fatal: {e}");
            ExitCode::FAILURE
        }
    }
}
