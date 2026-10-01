cmake_minimum_required(VERSION 3.16)
project(agent_fuzz CXX)

# ---------------------------------------------------------------------------
# Phase 2 target B: fuzz the Micro-XRCE-DDS **Agent**'s XRCE message-parse entry
# (InputMessage + the generated dds::xrce::* types), the C++/Fast-CDR deserializer
# that first touches attacker bytes on the broker. DEFENSIVE, in-process, offline.
#
# We compile only the Fast-CDR-dependent parse objects from an Agent v3.0.2 checkout
# (XRCETypes/MessageHeader/SubMessageHeader.cpp) — NOT TopicPubSubType.cpp (pulls
# Fast-DDS) and NOT InputMessage.cpp (pulls Logger/spdlog/config.hpp; its only member,
# log_error(), is stubbed in the harness). Fast-CDR is built FROM SOURCE and
# INSTRUMENTED so ASan/UBSan see inside the deserializers.
#   Agent    v3.0.2  (a88c712...)  -> parses XRCE with Fast-CDR
#   Fast-CDR v2.3.1  (c931bde...)  -> the version the Agent declares
# Point -DAGENT_SRC=<checkout> and optionally -DFETCHCONTENT_SOURCE_DIR_FASTCDR=<clone>.
# ---------------------------------------------------------------------------
set(AGENT_SRC "$ENV{HOME}/src/Micro-XRCE-DDS-Agent" CACHE PATH "Micro-XRCE-DDS-Agent v3.0.2 checkout")
if(NOT EXISTS "${AGENT_SRC}/src/cpp/types/XRCETypes.cpp")
  message(FATAL_ERROR "AGENT_SRC='${AGENT_SRC}' has no src/cpp/types/XRCETypes.cpp. "
                      "Clone: git clone --depth 1 --branch v3.0.2 "
                      "https://github.com/eProsima/Micro-XRCE-DDS-Agent.git ${AGENT_SRC}")
endif()

include(FetchContent)
set(FASTCDR_PIN_TAG "v2.3.1" CACHE STRING "Fast-CDR git tag/commit to fuzz")
FetchContent_Declare(fastcdr
  GIT_REPOSITORY https://github.com/eProsima/Fast-CDR.git
  GIT_TAG        ${FASTCDR_PIN_TAG})
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING     OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(fastcdr)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SAN_FLAGS -g -O1 -fno-omit-frame-pointer -fno-sanitize-recover=all)

# Sanitizer set applied to the libraries. Under Clang also embed SanitizerCoverage
# (-fsanitize=fuzzer-no-link) so libFuzzer gets edges from INSIDE Fast-CDR and the type
# deserializers; its runtime (fuzzer_no_main) also resolves the sancov hooks when the
# standalone links without the libFuzzer driver.
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(SAN -fsanitize=address,undefined -fsanitize=fuzzer-no-link)
else()
  set(SAN -fsanitize=address,undefined)
endif()

# Instrument Fast-CDR itself (built from source via FetchContent).
target_compile_options(fastcdr PRIVATE ${SAN_FLAGS} ${SAN})

# Agent XRCE parse objects (the Fast-CDR-only subset), instrumented.
add_library(agent_parse STATIC
  ${AGENT_SRC}/src/cpp/types/XRCETypes.cpp
  ${AGENT_SRC}/src/cpp/types/MessageHeader.cpp
  ${AGENT_SRC}/src/cpp/types/SubMessageHeader.cpp)
target_include_directories(agent_parse PUBLIC ${AGENT_SRC}/include)
target_link_libraries(agent_parse PUBLIC fastcdr)
target_compile_options(agent_parse PRIVATE ${SAN_FLAGS} ${SAN})

# --- Target 1: libFuzzer (Clang only) — the primary fuzzing rig ---
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_executable(agent_fuzz agent_fuzz.cpp)
  target_link_libraries(agent_fuzz PRIVATE agent_parse fastcdr)
  target_compile_options(agent_fuzz PRIVATE ${SAN_FLAGS} -fsanitize=fuzzer,address,undefined)
  target_link_options(agent_fuzz    PRIVATE -fsanitize=fuzzer,address,undefined)
  message(STATUS "agent_fuzz: libFuzzer target enabled (Clang) + instrumented Fast-CDR ${FASTCDR_PIN_TAG}")
else()
  message(STATUS "agent_fuzz: libFuzzer target skipped (need Clang); standalone target still instrumented")
endif()

# --- Target 2: standalone driver (any compiler) — self-test / crash replay ---
add_executable(agent_fuzz_standalone agent_fuzz.cpp)
target_compile_definitions(agent_fuzz_standalone PRIVATE AGENT_FUZZ_STANDALONE)
target_link_libraries(agent_fuzz_standalone PRIVATE agent_parse fastcdr)
target_compile_options(agent_fuzz_standalone PRIVATE ${SAN_FLAGS} ${SAN})
target_link_options(agent_fuzz_standalone    PRIVATE ${SAN})
