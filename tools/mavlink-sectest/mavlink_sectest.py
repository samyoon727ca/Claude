#!/usr/bin/env python3
"""MAVLink security test harness — automated T&E for the UAS threat model.

Operationalizes the requirements derived in
docs/track2/uas-autopilot-threat-model.md as repeatable tests against a live
MAVLink endpoint, intended for **ArduPilot / PX4 SITL** (simulation). Each test
maps to a threat (T1/T4/T5/T6) and reports PASS / FAIL / INFO against the derived
SHALL requirement.

SAFETY / SCOPE (read docs/disclosure-policy.md):
  * Default endpoint is SITL on localhost. Testing a real vehicle requires
    --allow-nonsim AND a vehicle you own, on the bench, props off.
  * The harness sends ONLY benign, non-actuating commands (it requests a message
    and telemetry streams). It never arms, takes off, changes flight mode, or
    writes params.

Usage:
  mavlink_sectest.py --connect udp:127.0.0.1:14550 --out report.json --csv findings.csv
  mavlink_sectest.py --selftest        # offline logic + pymavlink roundtrip
"""
import argparse
import csv
import hashlib
import json
import sys
import time

# --- Test catalogue: id -> (threat, requirement, risk-if-failing) ------------
CATALOGUE = {
    "signing":       ("T1/T5", "Autopilot SHALL reject unsigned MAVLink commands", 8.5),
    "cmd_injection": ("T1",    "Unauthenticated command SHALL NOT be accepted",    8.5),
    "replay":        ("T5",    "Replayed frames SHALL be rejected (anti-replay)",  5.5),
    "telemetry":     ("T4",    "Mission telemetry SHALL be encrypted in transit",  6.0),
    "failsafe":      ("T6",    "A link-loss failsafe SHALL be configured",         7.0),
}
TELEMETRY_TYPES = {"GLOBAL_POSITION_INT", "ATTITUDE", "VFR_HUD", "GPS_RAW_INT",
                   "MISSION_ITEM_INT", "BATTERY_STATUS"}
MAVLINK_IFLAG_SIGNED = 0x01

# =============================================================================
# Pure decision logic (offline-testable; live layer only gathers the inputs)
# =============================================================================
def verdict_signing(frames_total, frames_signed):
    """PASS only if every observed frame was signed."""
    if frames_total == 0:
        return "INFO", "no frames observed"
    if frames_signed == frames_total:
        return "PASS", f"all {frames_total} frames signed"
    return "FAIL", f"{frames_total - frames_signed}/{frames_total} frames unsigned"


def verdict_command_injection(accepted):
    """FAIL if an unsigned command was accepted by the vehicle."""
    if accepted is None:
        return "INFO", "no COMMAND_ACK observed"
    return ("FAIL", "unsigned command ACCEPTED") if accepted else \
           ("PASS", "unsigned command rejected")


def verdict_telemetry_plaintext(decoded_telemetry_types):
    """FAIL if recognizable telemetry decoded from cleartext."""
    if not decoded_telemetry_types:
        return "INFO", "no telemetry decoded"
    return "FAIL", "cleartext telemetry: " + ", ".join(sorted(decoded_telemetry_types))


def verdict_failsafe(params):
    """INFO/PASS/FAIL from failsafe params (config check, non-intrusive)."""
    if not params:
        return "INFO", "failsafe params not readable"
    enabled = any(v not in (0, None) for v in params.values())
    detail = ", ".join(f"{k}={v}" for k, v in params.items())
    return ("PASS", f"failsafe configured ({detail})") if enabled else \
           ("FAIL", f"failsafe disabled ({detail})")


def fetch_param(conn, tsys, tcomp, name, timeout=3.0):
    """Read ONE parameter by name, matching on param_id.

    param_request_read_send does not guarantee the *next* PARAM_VALUE is the one we
    asked for: a GCS/MAVProxy sharing the link streams the whole parameter table, so a
    bare recv_match(type="PARAM_VALUE") can return an unrelated param (e.g. STAT_RUNTIME).
    Match on param_id and drain non-matching values until the deadline. Returns the value,
    or None if the named parameter never arrives.
    """
    want = name.decode() if isinstance(name, (bytes, bytearray)) else name
    conn.mav.param_request_read_send(tsys, tcomp, name, -1)
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        pv = conn.recv_match(type="PARAM_VALUE", blocking=True, timeout=remaining)
        if pv is None:
            return None
        pid = pv.param_id
        if isinstance(pid, (bytes, bytearray)):
            pid = pid.decode(errors="replace")
        if pid.rstrip("\x00") == want:
            return pv.param_value


class ReplayDetector:
    """Tracks frame identities; .seen(key) is True if key was already presented."""
    def __init__(self):
        self._seen = set()

    @staticmethod
    def key(raw_bytes):
        return hashlib.sha256(raw_bytes).hexdigest()

    def seen(self, raw_bytes):
        k = self.key(raw_bytes)
        if k in self._seen:
            return True
        self._seen.add(k)
        return False


# =============================================================================
# Live layer (pymavlink)
# =============================================================================
def _is_sim(url):
    u = url.lower()
    return "127.0.0.1" in u or "localhost" in u or u.startswith("udpin:127") \
        or ":14550" in u and ("127.0.0.1" in u or "localhost" in u)


def run_live(url, observe_s, allow_nonsim):
    from pymavlink import mavutil

    if not _is_sim(url) and not allow_nonsim:
        sys.exit(f"refusing non-simulation endpoint {url!r} without --allow-nonsim "
                 "(and a vehicle you own, on the bench). See docs/disclosure-policy.md")

    print(f"[sectest] connecting to {url} ...", file=sys.stderr)
    conn = mavutil.mavlink_connection(url, source_system=255, source_component=190)
    if conn.wait_heartbeat(timeout=15) is None:
        sys.exit("no heartbeat; is SITL running and the endpoint correct?")
    tsys, tcomp = conn.target_system, conn.target_component
    print(f"[sectest] heartbeat from system {tsys} component {tcomp}", file=sys.stderr)

    # Ask the vehicle to stream telemetry (benign, read-only): a raw serial/UDP
    # channel gets no ATTITUDE/GLOBAL_POSITION_INT unless requested, which otherwise
    # leaves the confidentiality check (T4) with nothing to inspect. Non-actuating.
    try:
        conn.mav.request_data_stream_send(
            tsys, tcomp,
            getattr(mavutil.mavlink, "MAV_DATA_STREAM_ALL", 0), 2, 1)  # ~2 Hz, start
    except Exception:
        pass

    # --- observe frames: signing + telemetry ---
    total = signed = 0
    telem = set()
    replay = ReplayDetector()
    t_end = time.time() + observe_s
    while time.time() < t_end:
        msg = conn.recv_match(blocking=True, timeout=1)
        if msg is None:
            continue
        total += 1
        hdr = msg.get_header()
        if getattr(hdr, "incompat_flags", 0) & MAVLINK_IFLAG_SIGNED:
            signed += 1
        if msg.get_type() in TELEMETRY_TYPES:
            telem.add(msg.get_type())

    results = []

    def add(tid, verdict, detail):
        threat, req, risk = CATALOGUE[tid]
        results.append({"id": tid, "threat": threat, "requirement": req,
                        "verdict": verdict, "detail": detail, "risk": risk})

    v, d = verdict_signing(total, signed); add("signing", v, d)
    v, d = verdict_telemetry_plaintext(telem); add("telemetry", v, d)

    # --- benign unsigned command injection: request AUTOPILOT_VERSION (msgid 148) ---
    REQUEST_MESSAGE = getattr(mavutil.mavlink, "MAV_CMD_REQUEST_MESSAGE", 512)
    ACCEPTED = getattr(mavutil.mavlink, "MAV_RESULT_ACCEPTED", 0)
    cmd = conn.mav.command_long_encode(tsys, tcomp, REQUEST_MESSAGE, 0,
                                       148, 0, 0, 0, 0, 0, 0)
    raw = cmd.pack(conn.mav)
    conn.write(raw)
    ack = conn.recv_match(type="COMMAND_ACK", blocking=True, timeout=5)
    accepted = None if ack is None else (ack.result == ACCEPTED)
    v, d = verdict_command_injection(accepted); add("cmd_injection", v, d)

    # --- replay: resend identical bytes; note absence of anti-replay ---
    replay.seen(raw)                 # first presentation
    conn.write(raw)                  # verbatim replay
    ack2 = conn.recv_match(type="COMMAND_ACK", blocking=True, timeout=5)
    if ack2 is not None and (ack2.result == ACCEPTED):
        add("replay", "FAIL", "identical replayed frame accepted again")
    elif accepted:
        add("replay", "FAIL", "no signing/timestamp -> replay not preventable")
    else:
        add("replay", "INFO", "replayed frame not accepted")

    # --- failsafe config (non-intrusive param read) ---
    params = {}
    for name in (b"FS_THR_ENABLE", b"NAV_RCL_ACT"):   # ArduPilot / PX4 respectively
        try:
            val = fetch_param(conn, tsys, tcomp, name)
            if val is not None:
                params[name.decode()] = val
        except Exception:
            pass
    v, d = verdict_failsafe(params); add("failsafe", v, d)
    return results


# =============================================================================
# Reporting
# =============================================================================
def print_report(results):
    print(f"\n{'TEST':<14}{'VERDICT':<8}{'THREAT':<8}DETAIL")
    print("-" * 72)
    for r in results:
        print(f"{r['id']:<14}{r['verdict']:<8}{r['threat']:<8}{r['detail']}")
    fails = [r for r in results if r["verdict"] == "FAIL"]
    print("-" * 72)
    print(f"{len(fails)} FAIL, "
          f"{sum(1 for r in results if r['verdict']=='PASS')} PASS, "
          f"{sum(1 for r in results if r['verdict']=='INFO')} INFO")


def write_outputs(results, out_json, out_csv):
    if out_json:
        with open(out_json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[sectest] wrote {out_json}", file=sys.stderr)
    if out_csv:
        # findings CSV compatible with security-dataviz (--color-by severity)
        with open(out_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["finding", "risk"])
            for r in results:
                if r["verdict"] == "FAIL":
                    w.writerow([f"{r['id']} ({r['threat']})", r["risk"]])
        print(f"[sectest] wrote {out_csv} (failing tests, for charting)", file=sys.stderr)


# =============================================================================
# Offline self-test
# =============================================================================
def selftest():
    ok = True

    def check(name, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] {name}: {got!r}")

    check("signing all-signed", verdict_signing(10, 10)[0], "PASS")
    check("signing some-unsigned", verdict_signing(10, 3)[0], "FAIL")
    check("signing none", verdict_signing(0, 0)[0], "INFO")
    check("cmd accepted", verdict_command_injection(True)[0], "FAIL")
    check("cmd rejected", verdict_command_injection(False)[0], "PASS")
    check("telemetry plaintext", verdict_telemetry_plaintext({"ATTITUDE"})[0], "FAIL")
    check("telemetry none", verdict_telemetry_plaintext(set())[0], "INFO")
    check("failsafe on", verdict_failsafe({"FS_THR_ENABLE": 1.0})[0], "PASS")
    check("failsafe off", verdict_failsafe({"FS_THR_ENABLE": 0})[0], "FAIL")

    rd = ReplayDetector()
    b = b"\x01\x02\x03"
    check("replay first-seen", rd.seen(b), False)
    check("replay second-seen", rd.seen(b), True)

    # real pymavlink encode/decode roundtrip
    try:
        from pymavlink.dialects.v20 import common as mav
        link = mav.MAVLink(None, srcSystem=1, srcComponent=1)
        hb = link.heartbeat_encode(mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        buf = hb.pack(link)
        parser = mav.MAVLink(None); parser.robust_parsing = True
        msgs = parser.parse_buffer(buf) or []
        got = [m.get_type() for m in msgs]
        check("pymavlink roundtrip", "HEARTBEAT" in got, True)
    except Exception as e:
        ok = False
        print(f"  [FAIL] pymavlink roundtrip raised: {e}")

    print("selftest:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="MAVLink security test harness (SITL).")
    ap.add_argument("--connect", default="udp:127.0.0.1:14550",
                    help="MAVLink endpoint (default SITL GCS port)")
    ap.add_argument("--observe", type=int, default=5, help="seconds to observe frames")
    ap.add_argument("--allow-nonsim", action="store_true",
                    help="permit a non-localhost endpoint (owned vehicle, bench only)")
    ap.add_argument("--out", default="", help="write JSON report")
    ap.add_argument("--csv", default="", help="write failing-tests CSV (for security-dataviz)")
    ap.add_argument("--selftest", action="store_true", help="run offline logic tests and exit")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    print("=" * 72)
    print(" MAVLink security test harness  |  SITL / owned-vehicle bench use only")
    print(" Benign commands only; maps to docs/track2/uas-autopilot-threat-model.md")
    print("=" * 72)
    results = run_live(args.connect, args.observe, args.allow_nonsim)
    print_report(results)
    write_outputs(results, args.out, args.csv)
    sys.exit(1 if any(r["verdict"] == "FAIL" for r in results) else 0)


if __name__ == "__main__":
    main()
