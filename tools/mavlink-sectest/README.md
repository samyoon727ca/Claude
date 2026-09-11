# mavlink-sectest — MAVLink security test harness

Automated test-and-evaluation for the requirements derived in
[`docs/track2/uas-autopilot-threat-model.md`](../../docs/track2/uas-autopilot-threat-model.md).
It connects to a MAVLink endpoint (built for **ArduPilot / PX4 SITL**) and checks,
per threat, whether the link and vehicle actually enforce the SHALL requirements.

## Scope & safety
- **Simulation-first.** The default endpoint is SITL on `localhost`. Pointing it
  at a real vehicle requires `--allow-nonsim` **and** a vehicle you own, on the
  bench, with props off — per [`docs/disclosure-policy.md`](../../docs/disclosure-policy.md).
- **Non-destructive.** The harness sends only a benign, non-actuating command (it
  *requests a message*). It never arms, takes off, changes flight mode, or writes
  parameters.

## What it tests (→ threat-model requirement)
| Test | Threat | Requirement checked |
|------|:------:|---------------------|
| `signing` | T1/T5 | Frames are MAVLink v2 **signed** (unsigned commands rejectable) |
| `cmd_injection` | T1 | An **unsigned** command is **not** accepted (benign REQUEST_MESSAGE) |
| `replay` | T5 | A verbatim **replayed** frame is not re-accepted (anti-replay) |
| `telemetry` | T4 | Mission telemetry is **not** readable in cleartext |
| `failsafe` | T6 | A **link-loss failsafe** parameter is configured (non-intrusive read) |

Each test reports PASS / FAIL / INFO with the mapped requirement.

## Install
```
pip install -r requirements.txt        # pymavlink
```

## Run against SITL
Start a simulator (open-source), e.g. ArduPilot:
```
# in the ardupilot checkout
Tools/autotest/sim_vehicle.py -v ArduCopter --out=udp:127.0.0.1:14550
```
or PX4 (`make px4_sitl jmavsim`), then:
```
python3 mavlink_sectest.py --connect udp:127.0.0.1:14550 \
    --out report.json --csv findings.csv
```
`report.json` is the full result; `findings.csv` lists the failing tests with a
risk score and is directly chartable by the **security-dataviz** skill
(`chart.py bars --csv findings.csv --label finding --value risk --color-by severity`).
A FAIL feeds the **finding-to-vendor-report** skill via its `finding.json`.

## Verify the harness itself (no SITL needed)
```
python3 mavlink_sectest.py --selftest
```
Exercises the decision logic and a real pymavlink encode/decode roundtrip.

## Where it fits
This is the T&E instrument for the P5.1 UAS capstone: the threat model says what
must hold, this harness measures whether it does, and its output flows into the
reporting and visualization skills — closing the loop from threat → requirement →
test → finding → report.
