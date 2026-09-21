# Phase 2 · H5 — PX4 uXRCE-DDS bridge: unauthenticated command-injection test procedure

*The executable test procedure for **H5** of the
[Phase 2 scope](phase2-micro-xrce-dds-scope.md) — the highest-impact, most Lattice-flavored
hypothesis: **does PX4's default uXRCE-DDS bridge let an unauthorized DDS/XRCE peer read and
command the flight stack, with no authentication?** It is the DDS-layer analog of the MAVLink
T1 / [CVE-2026-1579](known-territory.md) story — missing authentication for a critical function,
one layer up — and it runs on the same **PX4 SITL** already stood up for
[Phase 1](../../docs/track1-uas-run-plan.md).*

> **Status: PROCEDURE (drafted 2026-09-21).** No exploitation yet; §5 is the results table to
> fill on the run. Every candidate outcome passes the **dedup gate (§6) before any novelty
> claim** — H5 may well be a *documented default*, in which case it ships as a rigorous
> negative-result / hardening assessment (the DrayTek ethos: value ships either way).

> **Scope, safety & ethics.** UNCLASSIFIED, open-source (PX4, Micro-XRCE-DDS-Agent, ROS 2 /
> Fast-DDS — all public). **SITL-ONLY and loopback-ONLY:** the vehicle is simulated, the DDS
> domain is on `localhost`, and no traffic touches a network you don't own. Command effects are
> observed in simulation only — never real hardware. Coordinated disclosure; personal COI /
> outside-activity reporting **before** any outbound contact
> ([`disclosure-policy.md`](../../docs/disclosure-policy.md) §5). No committed blobs.

## 1. Claim under test (SHALL-style)

Derived from the threat model's authentication requirement, applied to the DDS bridge:

> *The flight stack SHALL NOT accept flight-critical commands (arm, mode change, setpoints)
> from an **unauthenticated / unauthorized** DDS or XRCE peer; and SHALL NOT disclose vehicle
> state to one.*

**Two clauses, tested independently** (mirrors the capstone's integrity + confidentiality split):
1. **Integrity/command (the high-impact clause):** an unauthorized peer publishes to a `/fmu/in/`
   command topic and PX4 **acts on it** (arms / changes mode / follows setpoints in SITL).
2. **Confidentiality:** an unauthorized peer subscribes to `/fmu/out/` and reads vehicle
   position/status with no credentials — the DDS-side analog of the capstone's cleartext-telemetry
   (T4) finding.

**Why this is the missing-auth pattern, not just "offboard works."** PX4 *intends* companion/ROS 2
offboard control — but by default the bridge runs with **no DDS-Security** (no authentication,
no access control, no encryption). So the command capability is exposed to *any* peer that can
join the DDS domain or reach the Agent socket, not only the intended companion. The test measures
**who is allowed to command**, not whether commanding is possible.

## 2. System under test

| Item | Value |
|------|-------|
| Flight stack | **PX4 SITL** (v1.18.0-beta1, `make px4_sitl gz_x500`) — the Phase 1 rig |
| Bridge client | PX4 `uxrce_dds_client` (auto-started in SITL; connects to `127.0.0.1:8888`) |
| Bridge agent | `MicroXRCEAgent udp4 -p 8888` (eProsima Micro-XRCE-DDS-Agent) |
| DDS middleware | Fast-DDS (rmw_fastrtps), **default domain 0**, **DDS-Security OFF (default)** |
| Legit peer (baseline) | a ROS 2 node with `px4_msgs` (the intended companion) |
| **Attacker peer** | a **separate, unauthorized** participant — see §3 (three variants by trust boundary) |
| Command topics (`/fmu/in/`) | `vehicle_command`, `offboard_control_mode`, `trajectory_setpoint`, `vehicle_attitude_setpoint`, `vehicle_rates_setpoint` |
| Telemetry topics (`/fmu/out/`) | `vehicle_status`, `vehicle_local_position`, `vehicle_global_position`, `sensor_combined` |
| Run date | *pending* |

## 3. Attacker-peer variants (by trust boundary — from the scope doc)

The "attacker" is a peer with **no credentials** and no legitimate relationship to the vehicle.
Three variants map to the scope doc's trust boundaries; run whichever the environment allows:

- **P-DDS (TB-X2) — rogue DDS participant on the domain.** A Fast-DDS/ROS 2 process joins
  **domain 0** on the host and publishes/subscribes directly to `/fmu/*`. Models any peer already
  on the shared DDS bus. *Cleanest to build with ROS 2 + `px4_msgs`.*
- **P-XRCE (TB-X1) — rogue XRCE client to the Agent.** A second `Micro-XRCE-DDS-Client` (or raw
  XRCE frames) connects to `MicroXRCEAgent udp4 -p 8888` and creates its own entities. Models a
  network-adjacent attacker who only reaches the Agent's UDP socket. *Most faithful to the H5
  "reach the Agent" threat.*
- **P-NET — off-host reach (characterize only).** Note whether the Agent binds `0.0.0.0:8888`
  (reachable off-box) vs loopback; do **not** send cross-network traffic — record the binding as a
  reachability finding.

## 4. Test matrix

| # | Peer | Action | Clause | Expected (hypothesis — confirm on run) |
|---|------|--------|:------:|-----------------------------------------|
| A1 | P-DDS | Subscribe `/fmu/out/vehicle_local_position` + `/fmu/out/vehicle_status` | Confid. | **Reads** position/status, no creds → clause 2 **FAIL** (safe, read-only — run first) |
| A2 | P-DDS | Publish `VehicleCommand` `VEHICLE_CMD_COMPONENT_ARM_DISARM` (400, param1=1) | Integrity | Vehicle **arms** in SITL → clause 1 **FAIL** |
| A3 | P-DDS | Publish `OffboardControlMode` + `TrajectorySetpoint` ≥2 Hz, then `DO_SET_MODE`(176, offboard) + arm | Integrity | Vehicle **enters offboard and flies** the attacker's setpoints in SITL → clause 1 **FAIL** (full control) |
| A4 | P-XRCE | Connect to Agent :8888, `CREATE` a participant/topic, `WRITE_DATA` to a command topic | Integrity | Same effect via TB-X1 (only the Agent socket needed) |
| A5 | P-DDS | Publish a malformed/oversized `VehicleCommand` or spoof `source_system`/`target_system` | Integrity | Characterize input validation / addressing checks on the command path |

Run **A1 first** (read-only, safest). A2/A3 arm/fly the **simulated** vehicle — safe because it is
pure SITL; never against hardware.

## 5. Pass / fail criteria & results — *pending run*

- **Clause 1 (command) = FAIL** if an unauthorized peer's `/fmu/in/` publish produces the
  flight-stack effect (arm / mode change / setpoint following), observed via `/fmu/out/vehicle_status`
  (`arming_state`, `nav_state`) or the SITL/`pxh>` console. **PASS** only if PX4 rejects it.
- **Clause 2 (confidentiality) = FAIL** if an unauthorized peer decodes `/fmu/out/` state.
- Record the **weakest attacker** that succeeds (P-DDS vs P-XRCE vs off-host binding) — that bounds
  the real exposure.

| Case | Peer | Result | Observation (arming_state / nav_state / data read) |
|------|------|:------:|-----------------------------------------------------|
| A1 | P-DDS | _pending_ | |
| A2 | P-DDS | _pending_ | |
| A3 | P-DDS | _pending_ | |
| A4 | P-XRCE | _pending_ | |
| A5 | P-DDS | _pending_ | |

## 6. Dedup gate — run BEFORE any novelty claim (the crux of H5)

H5's headline risk is **claiming a documented default as novel.** PX4 documents DDS-Security as
*optional* and offboard-via-ROS 2 as a feature, so the finding is specifically **"no authentication
on flight-critical topics in the default config, exploitable by an unrelated peer."** Before
`finding.json`:

1. **NVD / OpenCVE / GHSA** on `PX4/PX4-Autopilot`, `eProsima/Micro-XRCE-DDS-Agent`, and
   `ros2`/`rmw_fastrtps` for: "uXRCE-DDS", "DDS bridge", "offboard authentication",
   "unauthenticated command", "ROS 2 PX4". (Phase 0 found the PX4↔uXRCE-DDS *integration seam*
   essentially unexamined — re-confirm at run time.)
2. **CISA ICS advisories** and **PX4/Dronecode security policy + docs** — does PX4 already
   document this as a known risk with the "enable DDS-Security" mitigation? If yes → it is a
   **hardening/negative-result** result (still shippable), **not** a fresh CVE.
3. **arXiv / Alias Robotics / ROS 2 security WG** for a published (non-CVE) description of the same
   class.
4. Classify per [`known-territory.md`](known-territory.md) §6: **MINED** (documented → hardening
   writeup) / **PARTIAL** (angle it) / **THIN** (candidate for coordinated disclosure to
   PX4/Dronecode). Cite [CVE-2026-1579](known-territory.md) as the *MAVLink analog / pattern
   reference*, **not** as coverage of the DDS bridge.

## 7. Build side — the remediation (break/build symmetry)

Whichever way the dedup lands, the engineering deliverable is the fix, framed for the Group 3+
class the market fields:
- **DDS-Security + SROS2:** stand up a keystore/enclaves with `ros2 security`, an authenticated
  identity per participant, and `permissions.xml` / `governance.xml` so **only authorized enclaves**
  may publish to `/fmu/in/*` (and read `/fmu/out/*`), with encryption on. Re-run the matrix → the
  unauthorized peer is now rejected (the "after").
- **Bridge lockdown:** restrict PX4's `dds_topics.yaml` so the default bridge does **not** expose
  writable command topics without explicit opt-in; document a least-privilege topic allowlist.
- **Deployment note:** bind the Agent to loopback / a segmented interface; never `0.0.0.0` on a
  reachable network.

This mirrors Phase 1's P6.2 signing module: find the missing-auth gap, then ship the adoptable
control.

## 8. Reproduction (loopback / SITL only)

```bash
# 1. PX4 SITL (Phase 1 rig) — starts uxrce_dds_client automatically:
cd ~/PX4-Autopilot && HEADLESS=1 make px4_sitl gz_x500

# 2. Agent (second shell) — the bridge the client connects to:
MicroXRCEAgent udp4 -p 8888        # (build from eProsima/Micro-XRCE-DDS-Agent if not installed)

# 3. Confirm the bridge is up (ROS 2 shell with px4_msgs sourced):
ros2 topic list | grep /fmu        # /fmu/in/* and /fmu/out/* should appear

# 4a. A1 confidentiality (read-only, safest first):
ros2 topic echo /fmu/out/vehicle_local_position

# 4b. A2/A3 command injection — from an UNRELATED node (no creds), in SITL only:
#     publish OffboardControlMode + TrajectorySetpoint >=2 Hz, then VehicleCommand
#     (DO_SET_MODE offboard, then COMPONENT_ARM_DISARM) and watch the sim vehicle.
#     Observe effect: ros2 topic echo /fmu/out/vehicle_status   # arming_state / nav_state
```

> ROS 2 on Ubuntu 26.04 (resolute) may not have binaries yet — build `px4_msgs` from source, use a
> ROS 2 container, or the **P-XRCE** variant (a raw `Micro-XRCE-DDS-Client` to the Agent) to avoid
> the ROS 2 install entirely. The procedure defines *what* to test; the peer rig is an execution
> choice.

## 9. Deliverable / DoD (P7.2 — value ships either way)

- **(a) Novel gap** → the default bridge accepts unauthorized commands *and* dedup shows it is not
  already CVE'd/documented → minimal repro → `finding.json` →
  [`finding-to-vendor-report`](../../.claude/skills/finding-to-vendor-report/SKILL.md) (CVSS) →
  coordinated disclosure to **PX4/Dronecode** (the integration seam) → CVE writeup, **plus** the §7
  DDS-Security build.
- **(b) Documented default** → a rigorous **security assessment**: the exposure measured, the
  weakest successful attacker, the §7 hardening proven as an "after," and a coverage note back to
  [`known-territory.md`](known-territory.md). Still a credible product-security artifact.

## 10. Connect-the-work

- Hypothesis source & ranking: [`phase2-micro-xrce-dds-scope.md`](phase2-micro-xrce-dds-scope.md) (H5).
- Dedup basis & disclosure channels: [`known-territory.md`](known-territory.md).
- The MAVLink analog (same missing-auth pattern, one layer down): the
  [capstone](../../docs/track2/uas-capstone-assessment.md) T1 finding + CVE-2026-1579.
- Run plan / Phase 2 (P7.2): [`track1-uas-run-plan.md`](../../docs/track1-uas-run-plan.md).
