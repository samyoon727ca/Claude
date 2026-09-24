cmake_minimum_required(VERSION 3.16)
project(ucdr_fuzz C)
set(CMAKE_C_STANDARD 11)

# ---------------------------------------------------------------------------------------------
# H1 targets eProsima Micro-CDR (`ucdr`) — the length-prefixed decode primitives.
#
# CRITICAL (spec §3, review finding #1): the library under test MUST be built WITH the same
# sanitizers as the harness. ASan only checks memory accesses in *instrumented* code, and the
# OOB read/write H1 hunts happens INSIDE ucdr — so a prebuilt, un-instrumented Micro-CDR would
# let a real overflow go UNDETECTED (a false-negative bug hunt) and give libFuzzer no coverage
# feedback from inside the library (blind fuzzing). We therefore build Micro-CDR from source and
# instrument it. `find_package` is retained only as an explicit, loudly-degraded fallback.
# ---------------------------------------------------------------------------------------------

option(UCDR_FUZZ_SYSTEM_MICROCDR
  "Link a prebuilt system Micro-CDR via find_package instead of building it from source. DEGRADED: ASan cannot see OOB inside the library and libFuzzer gets no coverage from it (spec §3, finding #1)."
  OFF)
set(UCDR_FUZZ_MICROCDR_TAG "master" CACHE STRING
  "Micro-CDR git tag/commit to fetch and build from source. PIN this to a specific commit for a real run and record the resolved hash in phase2-h1-fuzz-harness-spec.md §5.")

# Shared instrumentation. -fno-sanitize-recover=all makes UBSan abort on first hit (fuzzing).
set(BASE_FLAGS -g -O1 -fno-omit-frame-pointer -fno-sanitize-recover=all)
set(SAN_FLAGS  -fsanitize=address,undefined)

# Coverage into dependencies (Clang only): lets libFuzzer see edges INSIDE Micro-CDR. Compiling
# the library with fuzzer-no-link emits coverage counters without pulling in a libFuzzer main;
# the libFuzzer harness (-fsanitize=fuzzer) then consumes them, and the standalone driver links
# fuzzer-no-link so those same counters resolve (to no-ops) without a fuzzer main.
set(COV_FLAGS "")
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(COV_FLAGS -fsanitize=fuzzer-no-link)
endif()

# --- Micro-CDR under test -------------------------------------------------------------------
if(UCDR_FUZZ_SYSTEM_MICROCDR)
  message(WARNING
    "ucdr_fuzz: using a prebuilt system Micro-CDR (find_package). It is NOT instrumented, so "
    "ASan cannot detect OOB accesses inside the library and libFuzzer gets no coverage from it. "
    "Prefer the default (build-from-source, instrumented) for a real hunt. See spec §3, finding #1.")
  find_package(microcdr REQUIRED)
  set(UCDR_LIB microcdr)
else()
  include(FetchContent)
  message(STATUS
    "ucdr_fuzz: building Micro-CDR from source (tag='${UCDR_FUZZ_MICROCDR_TAG}') with "
    "${SAN_FLAGS} ${COV_FLAGS} so overflows inside the library are actually detected and fuzzed. "
    "PIN the tag and record the resolved commit hash for the run (spec §5).")
  # Disable Micro-CDR's superbuild so the real `microcdr` library target is defined IN THIS
  # build tree (superbuild builds it via ExternalProject, out of scope, and we could not then
  # add sanitizer flags to it). BUILD_TESTING off keeps its tests/examples out of our build.
  set(UCDR_SUPERBUILD OFF CACHE BOOL "" FORCE)
  set(BUILD_TESTING   OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(microcdr
    GIT_REPOSITORY https://github.com/eProsima/Micro-CDR.git
    GIT_TAG ${UCDR_FUZZ_MICROCDR_TAG})
  FetchContent_MakeAvailable(microcdr)
  # Instrument the library under test — the core of finding #1.
  target_compile_options(microcdr PRIVATE ${BASE_FLAGS} ${SAN_FLAGS} ${COV_FLAGS})
  set(UCDR_LIB microcdr)
endif()

# --- Target 1: libFuzzer (Clang only) — the primary fuzzing rig -----------------------------
# clang -fsanitize=fuzzer,address,undefined provides main(); flags go on compile AND link.
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_executable(ucdr_fuzz ucdr_fuzz.c)
  target_compile_options(ucdr_fuzz PRIVATE ${BASE_FLAGS} ${SAN_FLAGS} -fsanitize=fuzzer)
  target_link_options(ucdr_fuzz    PRIVATE ${SAN_FLAGS} -fsanitize=fuzzer)
  target_link_libraries(ucdr_fuzz  ${UCDR_LIB})
  message(STATUS "ucdr_fuzz: libFuzzer target enabled (Clang detected)")
else()
  message(STATUS "ucdr_fuzz: libFuzzer target skipped (need Clang); build the standalone target")
endif()

# --- Target 2: standalone driver (any compiler) — self-test, crash replay, AFL++ ------------
# ASan/UBSan but no fuzzing engine, so `--selftest` and file replay run instrumented anywhere.
# COV_FLAGS here only lets it link against a coverage-instrumented Micro-CDR (Clang); it adds no
# fuzzer main. For coverage-guided AFL++: set CC=afl-clang-fast before configuring, then
#   afl-fuzz -i seeds -o out -- ./ucdr_fuzz_standalone @@
add_executable(ucdr_fuzz_standalone ucdr_fuzz.c)
target_compile_definitions(ucdr_fuzz_standalone PRIVATE UCDR_FUZZ_STANDALONE)
target_compile_options(ucdr_fuzz_standalone PRIVATE ${BASE_FLAGS} ${SAN_FLAGS} ${COV_FLAGS})
target_link_options(ucdr_fuzz_standalone    PRIVATE ${SAN_FLAGS} ${COV_FLAGS})
target_link_libraries(ucdr_fuzz_standalone  ${UCDR_LIB})
