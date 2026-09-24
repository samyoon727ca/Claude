# `xrce_probe` — unauthenticated Micro-XRCE-DDS peer (Phase 2 · H5)

Minimal C client that connects to PX4's default Micro-XRCE-DDS Agent with **no credentials**,
creates DDS entities, and attempts to publish a `VehicleCommand` (ARM) to
`rt/fmu/in/vehicle_command`. It measures whether the **default** uXRCE-DDS bridge accepts
flight-critical commands from an unrelated peer.

This is the tool behind the H5 line of work:

- **Procedure:** [`../phase2-h5-test-procedure.md`](../phase2-h5-test-procedure.md)
- **Run results:** [`../phase2-h5-test-results.md`](../phase2-h5-test-results.md)
- **Dedup / prior art:** [`../known-territory.md`](../known-territory.md)

> **⚠️ Scope & safety — SITL and loopback ONLY.** The vehicle is **simulated**, the DDS domain
> is on `127.0.0.1`, and no traffic touches a network you do not own. It arms a **simulated**
> airframe only — never point this at a real flight controller or physical vehicle. Research /
> defensive use under coordinated disclosure; see
> [`../../../docs/disclosure-policy.md`](../../../docs/disclosure-policy.md).

## Build

Requires the Micro-XRCE-DDS **Client** library installed system-wide (provides
`microxrcedds_client` + the `ucdr` / Micro-CDR headers):

```bash
git clone --recurse-submodules https://github.com/eProsima/Micro-XRCE-DDS-Client.git ~/Micro-XRCE-DDS-Client
cd ~/Micro-XRCE-DDS-Client && cmake -B build -DUCLIENT_SUPERBUILD=ON \
  && cmake --build build -j"$(nproc)" && sudo cmake --install build && sudo ldconfig
```

Then build the probe:

```bash
cmake -B build && cmake --build build
```

## Run (SITL only)

```bash
# 1. PX4 SITL (starts uxrce_dds_client automatically)
cd ~/PX4-Autopilot && HEADLESS=1 make px4_sitl gz_x500
# 2. The Agent (bridge) in a second shell, verbose for entity-match debugging
MicroXRCEAgent udp4 -p 8888 -v 6
# 3. The probe
./build/xrce_probe            # defaults to 127.0.0.1:8888
```

Observe the effect in the PX4 `pxh>` console (`listener vehicle_command_ack`,
`listener vehicle_status`). Usage: `xrce_probe [ip] [port]`.

## Notes

- `VehicleCommand` field order is hand-serialized (`param5`/`param6` are `float64` — the classic
  CDR gotcha). If the `<dataType>` string or field layout does not match this PX4's
  `VehicleCommand.msg`, the datawriter will not match; prefer PX4's generated `px4_msgs` type
  support for a byte-exact match. See the results doc §8 for the current entity-creation blocker
  (`publisher 0x80 DDS_ERROR`).
- Installed API note: this uses the **four-argument** `uxr_init_udp_transport(transport,
  ip_protocol, ip, port)` exposed by the current Client release.
