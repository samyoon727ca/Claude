// ucdr_fuzz.c — Phase 2 / H1 in-process fuzz harness for eProsima Micro-CDR (`ucdr`).
//
// Target: the deserialize path that the Micro-XRCE-DDS Agent reaches when it decodes an
// XRCE submessage body — the "most likely clean CVE" surface from the Phase 2 scope (H1):
// OOB read/write on crafted sequence/string/array length + alignment. Beyond the two known
// field-validation DoS CVEs (2025-63547 MTU=0, 2025-63548 bad boolean), the length-prefixed
// primitives are the classic bounds-check gap.
//
// This is a DEFENSIVE research harness. It parses only attacker-controlled BYTES in-process
// (no network, no vehicle, no Agent) and exists to prove ucdr rejects hostile lengths instead
// of overrunning its buffer, under ASan/UBSan. See ../phase2-h1-fuzz-harness-spec.md.
//
// Two build modes (see CMakeLists.txt):
//   * libFuzzer  : clang -fsanitize=fuzzer,address,undefined  -> defines LLVMFuzzerTestOneInput
//   * standalone : any cc -DUCDR_FUZZ_STANDALONE               -> main(): --selftest / file repro
//
#include <ucdr/microcdr.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>   // malloc/free — decode_once uses them outside the STANDALONE block
#include <string.h>
#include <stdbool.h>

// Bounded destination capacities model a real caller: ucdr must refuse a length-prefix that
// exceeds the destination, setting mb->error rather than writing past `dst`. ASan turns any
// miss of that check into a crash the fuzzer records.
#define UCDR_FUZZ_DST_CAP 256u

// Decode one XRCE-shaped message from `data`/`size`.
//
// Layout mirrors DDS-XRCE: message header (sessionId u8, streamId u8, sequenceNr u16, optional
// clientKey u32), then a stream of submessages. Each submessage BODY is decoded by an
// opcode-driven mini-interpreter whose opcode stream is the body bytes themselves — every path
// drives a real ucdr primitive with attacker-controlled bytes, lengths and alignment, exactly
// as the Agent's Processing thread does. A real parser stops on the first decode error, so we
// break when mb.error is set (this also bounds the loop).
static void decode_once(const uint8_t* data, size_t size) {
    if (size == 0) return;

    // ucdr_init_buffer wants a mutable buffer; copy so the allocation is EXACTLY `size` bytes,
    // making any over-read past the frame an ASan heap-buffer-overflow (a right-sized copy is
    // the point — a padded static buffer would hide the very bug we hunt).
    uint8_t* buf = (uint8_t*)malloc(size);
    if (!buf) return;
    memcpy(buf, data, size);

    ucdrBuffer mb;
    ucdr_init_buffer(&mb, buf, (size_t)size);

    // ---- XRCE message header ----
    uint8_t session_id = 0, stream_id = 0;
    uint16_t seq_nr = 0;
    ucdr_deserialize_uint8_t(&mb, &session_id);
    ucdr_deserialize_uint8_t(&mb, &stream_id);
    ucdr_deserialize_uint16_t(&mb, &seq_nr);
    // Client key present when the session id is in the "with key" range (top bit clear). This
    // keeps the known-CVE fields (session/boolean/MTU-shaped) on the decoded path.
    if (!(session_id & 0x80u)) {
        uint32_t client_key = 0;
        ucdr_deserialize_uint32_t(&mb, &client_key);
    }

    // ---- submessages ----
    // 8-byte aligned so the multi-byte sequence/array casts below ((uint16_t*)dst, ... up to
    // uint64_t/double) are well-defined — a bare char[] gives no alignment guarantee and would
    // let UBSan flag a *harness-side* misaligned store as UB, masking real ucdr findings.
    _Alignas(8) char dst[UCDR_FUZZ_DST_CAP];
    uint8_t  u8;  int8_t  i8;  uint16_t u16; int16_t i16;
    uint32_t u32; int32_t i32; uint64_t u64; int64_t i64;
    float f; double d; char c; bool b;
    uint32_t seq_len = 0;

    while (!mb.error && ucdr_buffer_remaining(&mb) > 0) {
        uint8_t submessage_id = 0, flags = 0;
        uint16_t submessage_len = 0;
        if (!ucdr_deserialize_uint8_t(&mb, &submessage_id)) break;
        if (!ucdr_deserialize_uint8_t(&mb, &flags))         break;
        if (!ucdr_deserialize_uint16_t(&mb, &submessage_len)) break;

        // Body opcode loop: each byte selects one primitive. submessage_len is attacker-
        // controlled and intentionally NOT trusted to bound the body — that mismatch between a
        // declared length and the real remaining buffer is the bug class we want ucdr to survive.
        uint16_t budget = submessage_len;
        while (!mb.error && budget-- > 0 && ucdr_buffer_remaining(&mb) > 0) {
            uint8_t op = 0;
            if (!ucdr_deserialize_uint8_t(&mb, &op)) break;
            switch (op % 25u) {
                case 0:  ucdr_deserialize_bool(&mb, &b);      break;
                case 1:  ucdr_deserialize_char(&mb, &c);      break;
                case 2:  ucdr_deserialize_uint8_t(&mb, &u8);  break;
                case 3:  ucdr_deserialize_int8_t(&mb, &i8);   break;
                case 4:  ucdr_deserialize_uint16_t(&mb, &u16);break;
                case 5:  ucdr_deserialize_int16_t(&mb, &i16); break;
                case 6:  ucdr_deserialize_uint32_t(&mb, &u32);break;
                case 7:  ucdr_deserialize_int32_t(&mb, &i32); break;
                case 8:  ucdr_deserialize_uint64_t(&mb, &u64);break;
                case 9:  ucdr_deserialize_int64_t(&mb, &i64); break;
                case 10: ucdr_deserialize_float(&mb, &f);     break;
                case 11: ucdr_deserialize_double(&mb, &d);    break;
                // Length-prefixed forms — the H1 heart. ucdr reads an attacker-controlled length,
                // then must clamp the copy to the element capacity. The WIDEST element types are
                // covered too: `length * sizeof(element)` is where an integer overflow could slip
                // a huge length past a bounds check. Bounded dst + ASan/UBSan verify the clamp.
                case 12: ucdr_deserialize_string(&mb, dst, UCDR_FUZZ_DST_CAP); break;
                case 13: ucdr_deserialize_sequence_char(&mb, dst, UCDR_FUZZ_DST_CAP, &seq_len); break;
                case 14: ucdr_deserialize_sequence_uint8_t(&mb, (uint8_t*)dst, UCDR_FUZZ_DST_CAP, &seq_len); break;
                case 15: ucdr_deserialize_sequence_uint16_t(&mb, (uint16_t*)dst, UCDR_FUZZ_DST_CAP / sizeof(uint16_t), &seq_len); break;
                case 16: ucdr_deserialize_sequence_uint32_t(&mb, (uint32_t*)dst, UCDR_FUZZ_DST_CAP / sizeof(uint32_t), &seq_len); break;
                case 17: ucdr_deserialize_sequence_uint64_t(&mb, (uint64_t*)dst, UCDR_FUZZ_DST_CAP / sizeof(uint64_t), &seq_len); break;
                case 18: ucdr_deserialize_sequence_float(&mb, (float*)dst, UCDR_FUZZ_DST_CAP / sizeof(float), &seq_len); break;
                case 19: ucdr_deserialize_sequence_double(&mb, (double*)dst, UCDR_FUZZ_DST_CAP / sizeof(double), &seq_len); break;
                // Fixed-count arrays whose element count is itself attacker-derived (models an
                // upstream length field feeding an array read without re-validation). The count is
                // bounded to dst's per-type element capacity so the *destination* never overflows
                // by construction — any overrun that fires is ucdr reading past the input frame.
                case 20: { size_t n = (size_t)(op ^ flags) % UCDR_FUZZ_DST_CAP;
                           ucdr_deserialize_array_uint8_t(&mb, (uint8_t*)dst, n); break; }
                case 21: { size_t n = (size_t)op % (UCDR_FUZZ_DST_CAP / sizeof(uint16_t));
                           ucdr_deserialize_array_uint16_t(&mb, (uint16_t*)dst, n); break; }
                case 22: { size_t n = (size_t)op % (UCDR_FUZZ_DST_CAP / sizeof(uint32_t));
                           ucdr_deserialize_array_uint32_t(&mb, (uint32_t*)dst, n); break; }
                case 23: { size_t n = (size_t)op % (UCDR_FUZZ_DST_CAP / sizeof(uint64_t));
                           ucdr_deserialize_array_uint64_t(&mb, (uint64_t*)dst, n); break; }
                default: ucdr_deserialize_array_char(&mb, dst, (size_t)op % UCDR_FUZZ_DST_CAP); break;
            }
        }
    }

    free(buf);
    (void)stream_id; (void)seq_nr;
}

// libFuzzer entry point.
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Cap oversized inputs so the corpus stays fast; real XRCE frames are well under this.
    if (size > 4096) size = 4096;
    decode_once(data, size);
    return 0;  // Non-crashing return; ASan/UBSan abort on any memory-safety / UB violation.
}

#ifdef UCDR_FUZZ_STANDALONE
// No-engine driver: `--selftest` runs built-in seeds (deterministic logic check, no fuzzer
// needed — the analog of mavlink_sectest --selftest); file args replay corpus/crash inputs
// (works as an AFL++ target: `afl-fuzz -i seeds -o out -- ./ucdr_fuzz_standalone @@`).
#include <stdio.h>
#include <stdlib.h>

static int run_file(const char* path) {
    FILE* fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "open failed: %s\n", path); return 1; }
    fseek(fp, 0, SEEK_END); long n = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (n < 0) { fclose(fp); return 1; }
    uint8_t* buf = (uint8_t*)malloc((size_t)n ? (size_t)n : 1);
    size_t got = fread(buf, 1, (size_t)n, fp);
    fclose(fp);
    LLVMFuzzerTestOneInput(buf, got);
    free(buf);
    return 0;
}

// Built-in seeds: edge shapes that must decode without crashing the HARNESS (they may set
// mb.error — that is the correct, safe outcome). This proves the harness logic itself is sound
// before a single fuzzing cycle, and pins the two known-CVE shapes as regression seeds.
static int selftest(void) {
    const uint8_t empty[]      = { 0 };
    const uint8_t zeros[16]    = { 0 };
    const uint8_t hdr_only[]   = { 0x81, 0x00, 0x01, 0x00 };                   // header, no body
    const uint8_t big_seqlen[] = { 0x01,0,1,0, 0,0,0,0,  0x0c,0x00,0x08,0x00,  // submsg -> string
                                   0xff,0xff,0xff,0xff, 'A','B','C','D' };      // len=0xffffffff (must clamp)
    const uint8_t bad_bool[]   = { 0x81,0x00,0x01,0x00, 0x01,0x00,0x02,0x00, 0x00, 0x7f }; // non-0/1 bool (63548 shape)
    const uint8_t mtu_zeroish[]= { 0x81,0x00,0x00,0x00, 0x0c,0x00,0x00,0x00 };  // zero-length body (63547 shape)

    struct { const uint8_t* p; size_t n; const char* name; } seeds[] = {
        { empty,       sizeof(empty),       "empty" },
        { zeros,       sizeof(zeros),       "zeros" },
        { hdr_only,    sizeof(hdr_only),    "header-only" },
        { big_seqlen,  sizeof(big_seqlen),  "oversized-string-length" },
        { bad_bool,    sizeof(bad_bool),    "invalid-boolean(63548)" },
        { mtu_zeroish, sizeof(mtu_zeroish), "zero-length-body(63547)" },
    };
    for (size_t i = 0; i < sizeof(seeds)/sizeof(seeds[0]); ++i) {
        LLVMFuzzerTestOneInput(seeds[i].p, seeds[i].n);
        printf("  ok  %s\n", seeds[i].name);
    }
    printf("SELFTEST PASS — harness decoded %zu seeds without crashing.\n",
           sizeof(seeds)/sizeof(seeds[0]));
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2 || strcmp(argv[1], "--selftest") == 0) return selftest();
    int rc = 0;
    for (int i = 1; i < argc; ++i) rc |= run_file(argv[i]);
    printf("replayed %d input(s) without a harness-side abort.\n", argc - 1);
    return rc;
}
#endif  // UCDR_FUZZ_STANDALONE
