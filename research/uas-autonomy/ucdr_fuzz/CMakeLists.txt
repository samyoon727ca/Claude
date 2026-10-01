cmake_minimum_required(VERSION 3.16)
project(ucdr_fuzz C)

# ---------------------------------------------------------------------------
# Micro-CDR under test — built FROM SOURCE and INSTRUMENTED.
#
# Spec §3 / brief §6: ASan/UBSan only see code they instrumented, so we must NOT
# link a prebuilt libmicrocdr.a — an OOB *inside* a ucdr decode primitive would
# be invisible. We compile ucdr itself with the sanitizers so a miss of a bounds
# check in sequence.c / string.c / array.c becomes a hard, recorded crash.
#
# Pinned to the EXACT version the current Micro-XRCE-DDS Agent/Client ship:
#   Micro-CDR v2.0.2  = commit 99672492c5ef9fc378a8835b0bce9b2f7fa41306
#   (Client v3.0.2 pins microcdr EXACT 2.0.2; Agent v3.0.2 -> Client >=3.0.1;
#    Agent CVEs 2025-63547/63548 are v3.0.1-era, so 2.0.2 is >= the fix baseline.)
# For an offline build, point -DFETCHCONTENT_SOURCE_DIR_MICROCDR=<local clone>.
# ---------------------------------------------------------------------------
include(FetchContent)
set(UCDR_PIN_TAG "v2.0.2" CACHE STRING "Micro-CDR git tag/commit to fuzz")
FetchContent_Declare(microcdr
  GIT_REPOSITORY https://github.com/eProsima/Micro-CDR.git
  GIT_TAG        ${UCDR_PIN_TAG}
)
# Build Micro-CDR as a plain static subproject (no superbuild / isolated install).
set(UCDR_SUPERBUILD       OFF CACHE BOOL "" FORCE)
set(UCDR_ISOLATED_INSTALL OFF CACHE BOOL "" FORCE)
set(UCDR_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
set(UCDR_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS     OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(microcdr)

set(CMAKE_C_STANDARD 11)
set(SAN_FLAGS -g -O1 -fno-omit-frame-pointer -fno-sanitize-recover=all)

# Instrument the ucdr library itself — the whole point of building from source.
# Under Clang also embed SanitizerCoverage edges (-fsanitize=fuzzer-no-link) so
# libFuzzer gets coverage feedback from INSIDE the decoders, not just the harness.
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  target_compile_options(microcdr PRIVATE ${SAN_FLAGS} -fsanitize=address,undefined -fsanitize=fuzzer-no-link)
else()
  target_compile_options(microcdr PRIVATE ${SAN_FLAGS} -fsanitize=address,undefined)
endif()

# --- Target 1: libFuzzer (Clang only) — the primary fuzzing rig -------------------------
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_executable(ucdr_fuzz ucdr_fuzz.c)
  target_compile_options(ucdr_fuzz PRIVATE ${SAN_FLAGS} -fsanitize=fuzzer,address,undefined)
  target_link_options(ucdr_fuzz    PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(ucdr_fuzz  microcdr)
  message(STATUS "ucdr_fuzz: libFuzzer target enabled (Clang) + instrumented Micro-CDR ${UCDR_PIN_TAG}")
else()
  message(STATUS "ucdr_fuzz: libFuzzer target skipped (need Clang); standalone target is still instrumented")
endif()

# --- Target 2: standalone driver (any compiler) — self-test, crash replay, AFL++ --------
# ASan/UBSan but no fuzzing engine, so `--selftest` and file replay run instrumented anywhere.
# For coverage-guided AFL++: set CC=afl-clang-fast before configuring, then
#   afl-fuzz -i seeds -o out -- ./ucdr_fuzz_standalone @@
add_executable(ucdr_fuzz_standalone ucdr_fuzz.c)
target_compile_definitions(ucdr_fuzz_standalone PRIVATE UCDR_FUZZ_STANDALONE)
target_compile_options(ucdr_fuzz_standalone PRIVATE ${SAN_FLAGS} -fsanitize=address,undefined)
target_link_options(ucdr_fuzz_standalone    PRIVATE -fsanitize=address,undefined)
target_link_libraries(ucdr_fuzz_standalone  microcdr)
