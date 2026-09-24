cmake_minimum_required(VERSION 3.16)
project(ucdr_fuzz C)

# H1 targets eProsima Micro-CDR (`ucdr`) directly — the length-prefixed decode primitives.
# Installed by the Micro-XRCE-DDS-Client superbuild, or standalone from eProsima/Micro-CDR.
find_package(microcdr REQUIRED)

set(CMAKE_C_STANDARD 11)
set(SAN_FLAGS -g -O1 -fno-omit-frame-pointer -fno-sanitize-recover=all)

# --- Target 1: libFuzzer (Clang only) — the primary fuzzing rig -------------------------
# clang -fsanitize=fuzzer,address,undefined provides main(); flags go on compile AND link.
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_executable(ucdr_fuzz ucdr_fuzz.c)
  target_compile_options(ucdr_fuzz PRIVATE ${SAN_FLAGS} -fsanitize=fuzzer,address,undefined)
  target_link_options(ucdr_fuzz    PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(ucdr_fuzz  microcdr)
  message(STATUS "ucdr_fuzz: libFuzzer target enabled (Clang detected)")
else()
  message(STATUS "ucdr_fuzz: libFuzzer target skipped (need Clang); build the standalone target")
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
