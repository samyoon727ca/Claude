# Phase 2 · H5 — PX4 uXRCE-DDS bridge: unauthenticated command-injection **run results**

*The run record for the [H5 test procedure](phase2-h5-test-procedure.md) — the first
execution of the minimal unauthenticated Micro-XRCE-DDS peer against PX4 SITL. This is the
"§5 results" the procedure left pending: what actually happened when the probe ran, decoded
honestly against the [dedup gate](phase2-h5-test-procedure.md) and the
[known-territory map](known-territory.md).*

> **Status: RESULTS — INITIAL RUN (2026-09-21).** First interoperability/security pass.
> **Command injection is NOT demonstrated:** the probe's DDS *publisher* creation failed
> (`0x80 DDS_ERROR`) before any sample could reach PX4, so no ARM was delivered or executed.
> What *is* established is narrower and recorded below (unauthenticated session accepted;
> participant + topic created). Every claim here is held to the procedure's §11 evidence
> discipline — session ≠ publisher ≠ delivery ≠ execution.

> **Scope, safety & ethics (unchanged).** UNCLASSIFIED, open-source (PX4, Micro-XRCE-DDS-Agent,
> ROS 2 / Fast-DDS — all public). **SITL-ONLY and loopback-ONLY:** simulated vehicle, DDS domain
> on `127.0.0.1`, no traffic on any network the researcher does not own. Command effects observed
> in simulation only, never real hardware. Coordinated disclosure; personal COI / outside-activity
> reporting **before** any outbound contact
> ([`disclosure-policy.md`](../../docs/disclosure-policy.md) §5). No committed blobs.

**Environment.** WSL Ubuntu · project `~/xrce_probe` · target PX4 SITL + local Micro-XRCE-DDS
Agent · transport UDP/IPv4 · agent `127.0.0.1:8888`. The probe (`xrce_probe.c`, the exact peer
listed in the [procedure](phase2-h5-test-procedure.md)) is a minimal unauthenticated XRCE client:
open session → participant → topic → publisher → datawriter on `rt/fmu/in/vehicle_command`, then
publish a `VehicleCommand` ARM (command 400) and observe the effect in `pxh>`.

---

## 1. Build result — an API-shape interop finding

The initial compile failed: the installed Micro-XRCE-DDS Client exposes a **four-argument**
`uxr_init_udp_transport()`, not the five-argument (`+ uxrUDPPlatform*`) form:

```text
error: incompatible type for argument 2 of 'uxr_init_udp_transport'
error: too many arguments to function 'uxr_init_udp_transport'
```

Installed signature:

```c
uxr_init_udp_transport(uxrUDPTransport* transport, uxrIpProtocol ip_protocol,
                       const char* ip, const char* port);
```

Dropping the `&platform` argument compiled cleanly. (Left-over: the now-unused
`uxrUDPPlatform platform;` local should be removed from `main()` for a clean artifact.)

## 2. Probe execution — observed output

```text
[+] session with agent 127.0.0.1:8888 established (no credentials)
[!] entity status: 0 0 128 132 (type/topic may not match PX4 — check agent -v6)
[+] sent UNSIGNED VehicleCommand ARM (#1, 54 bytes)
... (#2–#5, 54 bytes each)
[i] done — check the effect in pxh> (see procedure §5)
```

## 3. XRCE entity-status decode

Per the installed headers (`UXR_STATUS_*`), `entity status: 0 0 128 132` decodes to:

| Entity      | Status |    Hex | Meaning                            |
| ----------- | -----: | -----: | ---------------------------------- |
| Participant |      0 | `0x00` | `UXR_STATUS_OK`                    |
| Topic       |      0 | `0x00` | `UXR_STATUS_OK`                    |
| Publisher   |    128 | `0x80` | `UXR_STATUS_ERR_DDS_ERROR`         |
| DataWriter  |    132 | `0x84` | `UXR_STATUS_ERR_UNKNOWN_REFERENCE` |

**Interpretation.** Participant and topic were created. The **publisher creation returned a DDS
error**; the datawriter then failed with *unknown reference* — a downstream consequence of the
publisher never existing, since the datawriter is created against the publisher's object
reference. No PX4-compatible publisher or datawriter was created; the `54-byte` sends left the
client but had no matched writer behind them.

## 4. PX4 observation — the ACK is *not* evidence of injection

`listener vehicle_command_ack` in `pxh>` showed:

```text
command: 211   target_system: 0   from_external: False
```

The probe's serialized command was `command 400 · target_system 1 · from_external true`
(COMPONENT_ARM_DISARM). The observed ACK (**211**, `target_system 0`, `from_external false`) is
PX4's own internal traffic and is **unrelated** to the probe's attempted ARM. It must **not** be
read as acceptance or execution of the injected command.

## 5. Separate observation — PX4's own XRCE client disconnected

During the test window PX4 logged:

```text
ERROR [uxrce_dds_client] No ping response, disconnecting
INFO  [uxrce_dds_client] session disconnected, attempting to reconnect...
```

Cause **not established** — temporal correlation only, no causation. Flagged as a candidate
*availability* line of inquiry (an unauthorized peer perturbing the flight stack's live DDS
bridge would be a more interesting effect than the ARM), to be tested in isolation before any
claim. See §8.

## 6. Evidence matrix

| Test question                                        | Result                          | Evidence                       |
| ---------------------------------------------------- | ------------------------------- | ------------------------------ |
| Can the probe reach the local Agent?                 | **Yes**                         | XRCE session established       |
| Does the session require credentials?                | **No creds supplied; accepted** | Probe output                   |
| Create a participant?                                | **Yes**                         | Status `0x00`                  |
| Create the topic?                                    | **Yes**                         | Status `0x00`                  |
| Create the publisher?                                | **No / failed**                 | Status `0x80` DDS error        |
| Create the datawriter?                               | **No**                          | Status `0x84` unknown ref      |
| Did the datawriter match PX4?                        | **Not demonstrated**            | No writer created              |
| Did PX4 receive the probe's `VehicleCommand`?        | **Not demonstrated**            | No matched writer              |
| Did PX4 execute ARM?                                 | **Not demonstrated**            | Observed ACK was 211, not 400  |
| Did the probe cause PX4's XRCE disconnect?           | **Unknown**                     | Temporal correlation only      |

Mapped to the procedure's §5 clauses: **Clause 1 (command) — not demonstrated** (blocked at
publisher creation, upstream of any flight-stack effect). **Clause 2 (confidentiality)** — not
yet run in this pass (the read-only `tcpdump`/A1 capture is the next low-risk step).

## 7. Conclusion of the initial run

> An unauthenticated XRCE client established a session with the local Micro-XRCE-DDS Agent and
> created a participant and topic. Publisher creation failed with
> `UXR_STATUS_ERR_DDS_ERROR (0x80)` and datawriter creation with
> `UXR_STATUS_ERR_UNKNOWN_REFERENCE (0x84)`. The run **does not demonstrate command injection
> into PX4**, publication to `rt/fmu/in/vehicle_command`, or execution of ARM.

The gating unknown is the **publisher `0x80 DDS_ERROR`**: participant + topic succeed while the
publisher fails, which means the Agent's underlying Fast-DDS rejected the entity during creation
from the probe's XML.

## 8. Analysis & next steps

1. **Debug the `0x80` before sending any more commands** (procedure §5/§10). Capture the Agent
   `-v6` log around the *publisher* CREATE:
   ```bash
   MicroXRCEAgent udp4 -p 8888 -v 6 2>&1 | tee ~/xrce-agent.log
   grep -Ei 'error|dds|create|publisher|datawriter|vehicle_command|participant|topic|reference' ~/xrce-agent.log
   ```
   Likeliest cause: the hand-rolled inline profile/type XML does not match what the Agent expects.
   Stop hand-rolling — use PX4's generated `px4_msgs` type support / a reference profile (mirror
   `dds_topics.yaml`), or diff the CREATE against a known-good `PublisherHelloWorld` example.
2. **Dedup framing (procedure §6) — the prize is mis-aimed.** PX4 documents DDS-Security as
   *optional / off by default*, so even a fully working unauthenticated ARM on the loopback bridge
   is most likely a **documented default → hardening / negative-result** finding, not a novel CVE
   (it is the architectural gap SROS2 / DDS-Security exists to close; see
   [known-territory.md](known-territory.md), MINED/PARTIAL buckets). The genuine novel headroom
   sits where this run is already stalling: the **Agent's entity-creation parser** — the THIN
   surface the Phase 0 map named (only two field-validation DoS CVEs, 2025-63547/63548). Pivot the
   effort from "does PX4 execute my ARM" to "can malformed XRCE CREATE_* input crash/hang the
   Agent."
3. **Isolate the §5 disconnect** as its own availability test (clean before/after timing), rather
   than attributing it to the probe without evidence.

## 9. Experimental distinctions (carried from procedure §11)

These are **not** interchangeable, and each stage needs independent evidence:
`XRCE session accepted` ≠ `DDS publisher accepted`;
`uxr_prepare_output_stream() succeeded` ≠ `DDS sample delivered to PX4`;
`VehicleCommand bytes transmitted` ≠ `PX4 executed VehicleCommand`.

---

*All testing here is PX4 SITL · localhost / 127.0.0.1 · simulated vehicle · controlled
Micro-XRCE-DDS Agent. No real flight controller or physical vehicle is involved.*
