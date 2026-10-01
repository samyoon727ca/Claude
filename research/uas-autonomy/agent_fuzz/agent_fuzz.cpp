// agent_fuzz.cpp — Phase 2 / target B: in-process fuzz harness for the eProsima
// Micro-XRCE-DDS **Agent**'s XRCE message-parse entry.
//
// Where H1 fuzzed the *client-side* `ucdr` C decoders, target B fuzzes the **Agent-side**
// path: the C++ `InputMessage` class + the generated `dds::xrce::*` types, deserialized with
// **Fast-CDR** (XCDRv1). This is the first code that touches attacker bytes on the broker once
// a frame arrives on the transport (UDP:8888 / TCP / serial) — the network-reachable,
// unauthenticated TB-X1 surface, one layer up from `ucdr`.
//
// The harness mirrors Processor::process_submessage: construct InputMessage(bytes), then walk
// submessages, deserializing each payload type by submessage-id exactly as the Agent dispatch
// does (CREATE -> CREATE_Payload reaches the entity-representation union = H3; the default/raw
// path exercises get_raw_payload). We stop at PARSE — no ProxyClient, no DDS domain, no
// network, no vehicle. ASan/UBSan turn any OOB / UB inside Fast-CDR or the type deserializers
// into a recorded crash; Fast-CDR's own exceptions are caught by InputMessage (the Agent's
// defense) and are the *safe* outcome.
//
// DEFENSIVE research harness. Parses bytes in-process only. See ../phase2-h1-fuzz-harness-spec.md
// (target B row) and ../phase2-micro-xrce-dds-scope.md.
//
// Two build modes (see CMakeLists.txt):
//   * libFuzzer  : clang -fsanitize=fuzzer,address,undefined   -> LLVMFuzzerTestOneInput
//   * standalone : -DAGENT_FUZZ_STANDALONE                      -> main(): --selftest / replay
#include <uxr/agent/message/InputMessage.hpp>
#include <uxr/agent/types/XRCETypes.hpp>

#include <cstdint>
#include <cstddef>
#include <vector>

// InputMessage's only out-of-line member is log_error() (defined in InputMessage.cpp, which
// pulls in Logger/spdlog + the generated config.hpp). We stub it so the harness links against
// just Fast-CDR + the parse objects. Logging is irrelevant to memory safety.
namespace eprosima {
namespace uxr {
void InputMessage::log_error() {}
} // namespace uxr
} // namespace eprosima

using eprosima::uxr::InputMessage;

// Deserialize one XRCE payload of type T for the current submessage (drives its Fast-CDR path).
template <class T>
static bool pull(InputMessage& msg)
{
    T data;
    return msg.get_payload(data);
}

static void decode_once(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 4096)
    {
        return;
    }

    // InputMessage copies the buffer internally; hand it a mutable, exactly-sized copy.
    std::vector<uint8_t> buf(data, data + size);
    InputMessage msg(buf.data(), buf.size());   // ctor: deserialize MessageHeader + count submessages
    if (!msg.is_valid_xrce_message())
    {
        return;
    }

    // Mirror Processor::process_submessage: walk submessages, decode each payload type by id.
    // Faithful traversal: stop when a submessage fails to parse (as the real while-loop does).
    int guard = 0;
    while (msg.prepare_next_submessage() && guard++ < 64)
    {
        bool ok;
        switch (msg.get_subheader().submessage_id())
        {
            case ::dds::xrce::CREATE_CLIENT: ok = pull< ::dds::xrce::CREATE_CLIENT_Payload>(msg); break;
            case ::dds::xrce::CREATE:        ok = pull< ::dds::xrce::CREATE_Payload>(msg);        break; // H3: entity rep
            case ::dds::xrce::GET_INFO:      ok = pull< ::dds::xrce::GET_INFO_Payload>(msg);      break;
            case ::dds::xrce::DELETE_ID:     ok = pull< ::dds::xrce::DELETE_Payload>(msg);        break;
            case ::dds::xrce::WRITE_DATA:    ok = pull< ::dds::xrce::WRITE_DATA_Payload_Data>(msg); break;
            case ::dds::xrce::READ_DATA:     ok = pull< ::dds::xrce::READ_DATA_Payload>(msg);     break;
            case ::dds::xrce::ACKNACK:       ok = pull< ::dds::xrce::ACKNACK_Payload>(msg);       break;
            case ::dds::xrce::HEARTBEAT:     ok = pull< ::dds::xrce::HEARTBEAT_Payload>(msg);     break;
            case ::dds::xrce::TIMESTAMP:     ok = pull< ::dds::xrce::TIMESTAMP_Payload>(msg);     break;
            default:
            {
                // Unknown id (incl. FRAGMENT, which the Agent reassembles in Session — H2, a
                // deeper target). Exercise the raw-copy path against a bounded destination.
                uint8_t raw[1024];
                ok = msg.get_raw_payload(raw, sizeof(raw));
                break;
            }
        }
        if (!ok)
        {
            break;
        }
    }
}

#ifdef AGENT_FUZZ_STANDALONE
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int run_file(const char* path)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "open failed: %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); long n = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (n < 0) { fclose(fp); return 1; }
    std::vector<uint8_t> buf((size_t)n ? (size_t)n : 1);
    size_t got = fread(buf.data(), 1, (size_t)n, fp);
    fclose(fp);
    decode_once(buf.data(), got);
    return 0;
}

// Deterministic logic check: edge shapes that must not crash the HARNESS (an invalid XRCE
// message is the correct, safe early-return). Proves the harness + parse objects link and run.
static int selftest()
{
    const uint8_t empty[]    = { 0 };
    const uint8_t hdr_only[] = { 0x81, 0x00, 0x01, 0x00 };                         // header, no submessage
    const uint8_t with_sub[] = { 0x81, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00,  // CREATE_CLIENT subheader
                                 0xde, 0xad, 0xbe, 0xef };                          // 4-byte body
    struct { const uint8_t* p; size_t n; const char* name; } seeds[] = {
        { empty,    sizeof(empty),    "empty" },
        { hdr_only, sizeof(hdr_only), "header-only" },
        { with_sub, sizeof(with_sub), "header+create_client-sub" },
    };
    for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); ++i)
    {
        decode_once(seeds[i].p, seeds[i].n);
        printf("  ok  %s\n", seeds[i].name);
    }
    printf("SELFTEST PASS — agent parse harness decoded %zu seeds without crashing.\n",
           sizeof(seeds) / sizeof(seeds[0]));
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2 || strcmp(argv[1], "--selftest") == 0) { return selftest(); }
    int rc = 0;
    for (int i = 1; i < argc; ++i) { rc |= run_file(argv[i]); }
    printf("replayed %d input(s) without a harness-side abort.\n", argc - 1);
    return rc;
}
#else
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    decode_once(data, size);
    return 0;
}
#endif // AGENT_FUZZ_STANDALONE
