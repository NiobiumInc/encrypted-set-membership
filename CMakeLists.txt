cmake_minimum_required(VERSION 3.18)
project(fhe-string-matcher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Self-contained SDK build (customer flow) ──────────────────────────
# Build against the niobium-client's OWN bundled OpenFHE + libnbfhetch (no
# compiler checkout); enabled by scripts/build_task.sh. See
# NIOBIUM_INTEGRATION.md.
option(NIOBIUM_SDK_BUILD "Self-contained build against the niobium-client SDK" OFF)
if(NIOBIUM_SDK_BUILD)
  set(NB_CLIENT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/niobium-client")
  set(NB_FHETCH_DIR "${NB_CLIENT_DIR}/vendor/niobium-fhetch")

  find_package(OpenFHE CONFIG REQUIRED)      # from CMAKE_PREFIX_PATH = client's vendor/lib/openfhe
  message(STATUS "SDK build: OpenFHE ${OpenFHE_INCLUDE}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenFHE_CXX_FLAGS} -Wno-error")

  include_directories(
    ${OpenFHE_INCLUDE} ${OpenFHE_INCLUDE}/core ${OpenFHE_INCLUDE}/pke ${OpenFHE_INCLUDE}/binfhe
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${NB_FHETCH_DIR}/include                            # niobium/compiler.h (SDK)
    ${NB_FHETCH_DIR}/vendor/json/single_include)        # nlohmann/json (if vendored there)
  link_directories(${OpenFHE_LIBDIR})

  find_library(NBFHETCH_LIB NAMES nbfhetch
    PATHS "${NB_CLIENT_DIR}/build/vendor/niobium-fhetch"
          "${NB_CLIENT_DIR}/build/_deps/niobium-fhetch-build" NO_DEFAULT_PATH)
  if(NOT NBFHETCH_LIB)
    message(FATAL_ERROR "libnbfhetch not found — run 'make -C niobium-client release' first")
  endif()
  message(STATUS "SDK build: nbfhetch ${NBFHETCH_LIB}")
  get_filename_component(NBFHETCH_DIR "${NBFHETCH_LIB}" DIRECTORY)
  set(CMAKE_BUILD_RPATH "${OpenFHE_LIBDIR};${NBFHETCH_DIR}")

  # zlib is OPTIONAL here: the client's bundled OpenFHE .so already pulls in
  # libz at runtime (DT_NEEDED), so the app needs no explicit zlib. Link it only
  # if the dev package is present (some fog hosts have runtime libz but not the
  # -dev headers, so find_package(ZLIB REQUIRED) would wrongly fail the build).
  find_package(ZLIB QUIET)
  set(SDK_ZLIB "")
  if(ZLIB_FOUND)
    set(SDK_ZLIB ZLIB::ZLIB)
  endif()

  # libnbfhetch defers its OpenFHE (lbcrypto) symbols to the final link; keep
  # OpenFHE in DT_NEEDED so the default --as-needed can't drop it (else
  # matcher_compute_sdk fails with "undefined reference to lbcrypto::...").
  if(UNIX AND NOT APPLE)
    add_link_options(-Wl,--no-as-needed -Wl,--disable-new-dtags)
  endif()

  # Client stages: plain OpenFHE; link nbfhetch to resolve the instrumented-
  # OpenFHE globals (they never call the recording API themselves).
  foreach(stage matcher_keygen matcher_encode_dataset matcher_encrypt_query matcher_decrypt_result)
    add_executable(${stage} src/${stage}.cpp src/fhe_string_matcher.cpp)
    target_link_libraries(${stage} ${OpenFHE_SHARED_LIBRARIES} ${NBFHETCH_LIB} ${SDK_ZLIB})
  endforeach()

  # SDK-linked server: record/replay via libnbfhetch → the FHETCH transport.
  # OPENFHE_CPROBES is REQUIRED so evaluate()'s ct·ct EvalMult hooks fire; without
  # it the recorded trace has no multiplications. Kernel compiled fresh here
  # with the niobium-fhetch include first so its niobium::compiler() = the SDK.
  add_executable(matcher_compute_sdk src/matcher_compute_sdk.cpp src/fhe_string_matcher.cpp)
  target_compile_definitions(matcher_compute_sdk PRIVATE NIOBIUM_COMPILER OPENFHE_CPROBES)
  target_link_libraries(matcher_compute_sdk ${OpenFHE_SHARED_LIBRARIES} ${NBFHETCH_LIB} ${SDK_ZLIB})

  # Phonetic unit tests: pure functions in phonetic.h, no FHE and no Niobium.
  # Defined here as well as below so the self-contained build can run them;
  # OpenFHE is linked only to resolve the OpenMP symbols its CXX flags bring in.
  enable_testing()
  add_executable(test_phonetic tests/test_phonetic.cpp)
  target_link_libraries(test_phonetic ${OpenFHE_SHARED_LIBRARIES} ${NBFHETCH_LIB})
  add_test(NAME phonetic_unit_tests COMMAND test_phonetic)
  set_tests_properties(phonetic_unit_tests PROPERTIES TIMEOUT 30)

  return()   # self-contained: nothing below applies
endif()

# The niobium-client submodule is the only OpenFHE source here; there is no
# other build flavor. scripts/build_task.sh configures with the option ON.
message(FATAL_ERROR
  "configure with -DNIOBIUM_SDK_BUILD=ON - use scripts/build_task.sh")
