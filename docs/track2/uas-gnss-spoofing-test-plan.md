# UAS GNSS-Spoofing Cyber T&E Test Plan (T2)

*The next depth increment on the [UAS capstone](uas-capstone-assessment.md): it executes
the highest-ranked threat in the [threat model](uas-autopilot-threat-model.md) — **T2 GNSS
spoofing (risk 9.0)** — as automated, simulation-only test-and-evaluation. Where the capstone
tested the MAVLink command/telemetry link (T1/T4/T5/T6), this plan tests **position-solution
integrity**: does an open ArduPilot build detect a spoofed GNSS fix via multi-sensor
consistency and enter a defined safe state, or does it fly the false position?*

> **Status: PLAN — pending SITL execution.** This document is the test design; §9 is the
> results table to fill on the run. The harness extension in §7 ships its **pure decision
> logic** with an offline `--selftest` (like the MAVLink harness) so it is verifiable before
> any SITL is stood up.

> **Scope, safety & legality — read before running.** UNCLASSIFIED, open-source stack
> (ArduPilot + public MAVLink). **SITL-ONLY, and more strictly than the MAVLink harness:**
> this test *arms and flies the simulated vehicle* and *injects sensor faults*, so it **MUST
> NOT** be pointed at real hardware — there is deliberately **no `--allow-nonsim` path** for it.
> The spoof is modeled entirely as **in-simulator sensor injection** (SITL `SIM_GPS*`
> parameters); **no RF is transmitted.** Radiating a real spoofed GNSS signal (HackRF/USRP +
> `gps-sdr-sim`) is a licensed-spectrum / legal matter and is **out of scope** here by design —
> the SITL sensor-injection path is the safe, fully-publishable analogue. No
> proprietary/classified/ITAR data. See [`docs/disclosure-policy.md`](../disclosure-policy.md).

## 1. Objective & framing

Execute, as Cyber T&E, the threat model's **T2** requirement (§8):

> *The system SHALL detect GNSS spoofing via multi-sensor consistency (IMU/baro/flow) and
> enter a safe, defined state.* — Control: **Detect + Recover**; gated at **CDR/TRR**.

Two clauses, tested independently:
1. **Detect** — the estimator flags a GNSS/EKF anomaly when the reported position
   desynchronizes from the inertial/barometric solution.
2. **Recover** — on detection the vehicle enters a *defined* failsafe (per `FS_EKF_ACTION`)
   rather than silently navigating to the attacker-chosen position.

**Key difference from T1.** MAVLink signing is a binary "off by default → FAIL." T2 is not:
ArduPilot's EKF3 already runs GPS innovation gating and glitch logic, so the honest result is
a **detection-envelope characterization** — *at what spoof magnitude and ramp-rate does the
estimator reject the spoof vs. follow it, and does it safe-state?* The deliverable is that
curve, not a single verdict. The defense-relevant finding lives at the slow, sub-gate end.

## 2. System under test

| Item | Value |
|------|-------|
| Autopilot stack | ArduPilot **ArduCopter SITL** |
| Simulator | `sim_vehicle.py -v ArduCopter --console --map` (or `-w` for a clean param reset) |
| Flight mode under test | **LOITER** (GPS-dependent position hold — where a spoof bites) |
| Estimator | **EKF3** (default); GPS is the default XY position source |
| Injection surface | SITL simulated-GPS params (`SIM_GPS*`) — desynchronizes GPS from true IMU/baro physics |
| Endpoint | `udp:127.0.0.1:14550` (GCS port) + MAVProxy for param injection |
| Harness | `tools/mavlink-sectest/gnss_spoof_test.py` (new; §7) — `--selftest` green offline |
| Ground truth | SITL `SIMSTATE` / `SIM_STATE` (true position) — lets us measure actual estimator error |
| Run date | *pending* |

## 3. Injection method (how the spoof is modeled)

A GNSS spoofer makes the receiver report an attacker-chosen position/time while the vehicle's
**inertial (IMU) and barometric** sensors keep reporting physical reality. We reproduce exactly
that desynchronization inside SITL by perturbing only the simulated GPS while the sim's true
physics (which drive IMU/baro) are untouched.

**Primary — SITL GPS glitch/offset injection.** Drive a controlled offset into the simulated
GPS fix with the `SIM_GPS*` glitch parameters:

- Modern ArduPilot (≈4.3+): `SIM_GPS1_GLTCH_X`, `_Y`, `_Z` (with `SIM_GPS1_ENABLE=1`).
- Legacy: `SIM_GPS_GLITCH_X`, `_Y`, `_Z` (and `SIM_GPS_DISABLE`).

> **Confirm names/units on your build first:** `param show SIM_GPS*`. The SIM-GPS parameter
> set was renamed around 4.3, and X/Y are a lat/lon offset (degrees) while Z is altitude
> (metres). Rule of thumb: **1° lat ≈ 111 km**, so a 500 m horizontal spoof ≈ `0.0045` in X/Y;
> a 50 m altitude spoof ≈ `50` in Z. Set the value you compute for your target magnitude.

**Injection profiles** (the independent variable — this is what the matrix in §5 sweeps):
- **Teleport** — one large step (offset jumps to target in a single set).
- **Walk** — small offset increments applied every ~1 s to synthesize a drift rate (m/s),
  each step deliberately *below* the innovation gate — the case that defeats naive gating.

**Alternative — on-the-wire GPS injection (documented, not primary).** With `GPS_TYPE`/`GPS1_TYPE`
= MAV, an attacker feeds `GPS_INPUT` MAVLink messages. That models an injected/MAVLink-GPS setup
but overlaps T1 (link injection); the `SIM_GPS*` path is primary because it cleanly breaks the
GPS↔IMU/baro consistency that the T2 SHALL's named control depends on.

## 4. Detection instrumentation (what the harness observes)

| Signal (MAVLink msg) | What it tells us |
|----------------------|------------------|
| `GPS_RAW_INT` | The **spoofed** raw GPS lat/lon/alt/fix/sats (attacker's claim) |
| `GLOBAL_POSITION_INT` | The **EKF-fused** estimate — does it follow the spoof or resist it? |
| `SIMSTATE` / `SIM_STATE` | SITL **ground truth** — lets us compute true estimator error (were we actually fooled?) |
| `EKF_STATUS_REPORT` | `pos_horiz_variance`, `velocity_variance`, flags — the innovation/variance breach |
| `STATUSTEXT` | Human-readable tells: `"EKF variance"`, `"GPS Glitch"`, `"EKF primary changed"` |
| `SYS_STATUS` | Onboard sensor-health bitmask — GPS health bit clearing |
| `HEARTBEAT.custom_mode` | Flight-mode change → the failsafe/recover action actually firing |

Two derived metrics:
- **Spoof-follow error** = haversine(`GLOBAL_POSITION_INT`, `SIMSTATE` truth). Growing → the
  estimate is being pulled off truth (the spoof is working).
- **GPS-reject divergence** = haversine(`GPS_RAW_INT`, `GLOBAL_POSITION_INT`). Growing while the
  fused estimate stays near truth → the estimator is *rejecting* the spoof (good).

## 5. Test matrix (spoof profile → expected estimator response)

| # | Profile | Injection | Detect signal watched | Expected (hypothesis — confirm on run) | Verdict maps to |
|---|---------|-----------|-----------------------|-----------------------------------------|-----------------|
| S1 | **Horizontal teleport** | X/Y offset ≈ 500 m, single step | EKF variance breach + `GPS Glitch` | **Detected** — innovation gate rejects; fused holds near truth | Detect ✓ |
| S2 | **Slow horizontal walk** | X/Y drift ≈ 1–3 m/s for 60 s (sub-gate steps) | Spoof-follow error vs truth | **Likely undetected** — sub-gate steps walk the EKF; estimate drifts → *the finding* | Detect ✗ (candidate) |
| S3 | **Consistent-velocity spoof** | Walk + matching velocity terms | variance + follow-error | Harder to detect than S2; characterize | Detect ? |
| S4 | **Altitude spoof** | Z offset ≈ 50 m | baro cross-check → fast variance breach | **Detected fastest** — baro is the independent cross-sensor the SHALL names | Detect ✓ |
| S5 | **Jam-then-spoof** | drop GPS (sats→0 / `SIM_GPS*_JAM`) then reintroduce offset fix | mode change + `EKF primary` | EKF should degrade to non-GPS/failsafe, not swallow the returning false fix | Detect + Recover |
| S6 | **Pre-arm spoof** | offset injected before arming | `PreArm:` STATUSTEXT / arm refusal | Arming GPS-consistency check should refuse | Detect (arming gate) |

For **Recover (clause 2)**, every case that detects is additionally scored on whether the
vehicle enters a *defined* safe state: with `FS_EKF_ACTION` set, a mode change to
LAND/ALTHOLD (or position-hold abandoned) — vs. silently continuing toward the spoofed point.

## 6. Pass / fail criteria

Per case, against a fixed observation window (default **T_detect = 10 s**):

- **Detect = PASS** if the autopilot raises a GNSS/EKF anomaly within T_detect — any of:
  `EKF_STATUS_REPORT.pos_horiz_variance` > `FS_EKF_THRESH`; a `GPS Glitch`/`EKF variance`
  `STATUSTEXT`; the GPS `SYS_STATUS` health bit clearing; **or** the fused estimate demonstrably
  rejecting the spoof (GPS-reject divergence grows while spoof-follow error stays < 50 m).
- **Detect = FAIL** if the spoof-follow error (fused vs. truth) exceeds **50 m sustained** with
  no anomaly raised — the estimator was silently walked.
- **Recover = PASS** if, on detection, `HEARTBEAT.custom_mode` transitions to the configured
  failsafe (or position hold is abandoned); **FAIL** if it keeps navigating to the false fix.
- **INFO** if the spoof was too small to move the estimator (record the magnitude — it bounds
  the detection envelope from below).

The headline output is the **detection envelope**: the smallest offset/ramp-rate that is
detected, per axis (horizontal vs. vertical). That single curve is the assessment's finding.

## 7. Harness extension — `gnss_spoof_test.py`

Follows the existing harness's **pure-logic / live-layer split** so it self-tests offline and
plugs into `tools/run-checks.sh` like `mavlink_sectest.py`:

- **Pure decision logic** (offline-testable; no pymavlink needed to test):
  - `haversine_m(lat1, lon1, lat2, lon2)` — metres between two fixes.
  - `verdict_gnss_detect(follow_err_series, reject_div_series, ekf_variance_series, statustexts, thresh)`
    → `PASS/FAIL/INFO` implementing §6 clause 1.
  - `verdict_gnss_recover(mode_before, mode_after, detected)` → §6 clause 2.
  - `SpoofProfile` — yields the offset schedule for teleport/walk (deterministic, unit-tested).
- **Live layer** (pymavlink, SITL-only — hard-refuses any non-localhost endpoint, no override):
  - Arm + take off to a hover in **LOITER** (SITL only; benign in sim).
  - Inject the profile via `param_set` on `SIM_GPS*` (SITL params are settable over MAVLink).
  - Observe the §4 signal set for the window; compute both derived metrics against `SIMSTATE`.
  - Emit `report.json` + `findings.csv` in the **same schema** the capstone already charts with
    `security-dataviz` and reports with `finding-to-vendor-report`.
- **`--selftest`** exercises `haversine_m` against known distances, both verdict functions
  across PASS/FAIL/INFO, and the `SpoofProfile` schedules — green with no SITL, wired into the
  gate.

Self-test-first mirrors `mavlink_sectest.py`: the logic is provable before the SITL run, so the
run only supplies live inputs to already-verified deciders.

## 8. Before / after — proving the control (mirrors the capstone arc)

**Before:** stock EKF3 defaults. Run S1–S6; expect S2 (slow walk) to expose the sub-gate gap.

**After (hardening = the T2 control, then re-run):**
- Tighten innovation gates: `EK3_POS_I_GATE`, `EK3_VEL_I_GATE`, GPS glitch radius `EK3_GLITCH_RAD`.
- Set a real recover action: `FS_EKF_ACTION` (LAND/ALTHOLD) with a sane `FS_EKF_THRESH`.
- Configure **multi-source consistency** — an EKF source set with a non-GPS fallback
  (`EK3_SRCn_*`: optical flow / beacon / wheel-odom), so a GPS-only spoof is cross-checked.
- Confirm arming GPS-consistency checks are on (`ARMING_CHECK`).

Re-run and show the slow-walk (S2) spoof now **detected and safe-stated** — the same
find → build → prove structure as the MAVLink signing before/after, one threat up the risk
ranking.

## 9. Results — *pending SITL execution*

Fill verbatim from `report.json` on the run (schema-compatible with the capstone's assets):

| Case | Detect | Recover | Follow-err (m) | First tell | Envelope note |
|------|:------:|:-------:|:--------------:|-----------|---------------|
| S1 teleport | _pending_ | _pending_ | | | |
| S2 slow walk | _pending_ | _pending_ | | | |
| S3 consistent-v | _pending_ | _pending_ | | | |
| S4 altitude | _pending_ | _pending_ | | | |
| S5 jam-then-spoof | _pending_ | _pending_ | | | |
| S6 pre-arm | _pending_ | _pending_ | | | |

Then: chart the failing cases with `security-dataviz`, and if S2 (or any) is a clean FAIL,
write it up through `finding-to-vendor-report` and fold the detection-envelope curve into the
capstone assessment as the T2 result.

## 10. Reproduction

```bash
# 1. Bring up SITL (WSL), clean params, console + map:
sim_vehicle.py -v ArduCopter -w --console --map --out=udp:127.0.0.1:14550

# 2. In MAVProxy: confirm the SIM GPS params on THIS build, then take off to LOITER:
#    param show SIM_GPS*
#    mode GUIDED ; arm throttle ; takeoff 20 ; mode LOITER

# 3. Verify the harness logic offline (no SITL needed):
python3 tools/mavlink-sectest/gnss_spoof_test.py --selftest

# 4. Run a spoof case (harness injects SIM_GPS* and scores detect/recover):
python3 tools/mavlink-sectest/gnss_spoof_test.py --connect udp:127.0.0.1:14550 \
    --profile walk --rate 2 --duration 60 --out report.json --csv findings.csv
```

(Manual injection, if driving it by hand instead of the harness: in MAVProxy
`param set SIM_GPS1_GLTCH_X 0.0045` for a ~500 m east step, and watch
`STATUSTEXT` / `EKF_STATUS_REPORT` in the console.)

## 11. Risk framing & competencies

- **Threat:** T2 GNSS spoofing, **risk 9.0 — the model's #1** — ATT&CK-ICS **T0856 Spoof
  Reporting Message**, trust boundary **TB1**. Loss scenario: vehicle flown to an
  attacker-chosen location / failsafe abused — a cyber-physical (safety) event.
- **Competencies:** hands-on embedded/cyber-physical assessment; Cyber T&E with
  requirements-as-tests; **sensor-fusion / estimator security** (EKF innovation gating,
  multi-sensor consistency) — a distinct, defense-relevant skill from the link-layer work;
  simulation-first, reproducible, legally-clean (no RF emission); briefing via the same funnel.

---

### Follow-on (after this lands)
The remaining out-of-harness threats become the next depth candidates: T3 signed-firmware
negative test (bootloader), T7 companion-computer segmentation. T2 is done first because it is
the highest-ranked risk and the most defense-relevant single addition (see
[`NEXT-SESSION.md`](../NEXT-SESSION.md) Thrust A).
