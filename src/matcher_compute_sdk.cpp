// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// matcher_compute_sdk — Stage 4, the compute stage.
//
// Runs FHEStringMatcher::evaluate linked against the niobium-client
// SDK's libnbfhetch, so replay() ships the trace over HTTP to a
// nbcc_fhetch_replay_server when NBCC_FHETCH_SERVER is set. Explicit niobium-fhetch
// API (capture_crypto_context / tag_input / tag_keys). Records the trace once on a
// cache miss, in hollow mode, then ALWAYS replays to produce the result.
//
// Runs on the SERVER machine, so it refuses a key directory holding sk.bin:
// it needs the context and the evaluation keys and never the secret key.
// See NIOBIUM_INTEGRATION.md.

#include "fhe_string_matcher.h"

#ifdef NIOBIUM_COMPILER
#include <niobium/compiler.h>   // resolved from niobium-fhetch/include (SDK version)
#endif
#include "ciphertext-ser.h"


#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

static void usage(const char* prog) {
    std::cerr <<
"Usage: " << prog << " --mode exact|soundex --keydir <dir>\n"
"                                  --encoded-dataset <dir> --query-dir <dir>\n"
"                                  --result <result.ct>\n"
"                                  [--target <target>] [--opt-level O0|O1|O2|O3]\n"
"\n"
"  --target      replay backend: local, or FOG for an FPGA over the Fog.\n"
"  --opt-level   forwarded to the backend; FPGA targets need O3. Spell it this\n"
"                way: a bare -O3 is accepted and ignored, leaving the backend\n"
"                at its own default.\n";
}

int main(int argc, char* argv[]) try {
#ifdef NIOBIUM_COMPILER
    // init() consumes --target / -O; the target drives HW format (no --niobium_hw).
    niobium::compiler().init(argc, argv);
    // Cooperative mode: this program keeps the record/replay decisions, and
    // replay reads the project from disk. Must run before the crypto context
    // is loaded.
    niobium::compiler().enable_auto_tagging();
    // The program name is the trace directory's name
    // (matcher_compute_mode_<mode>_batches_<n>), so changing it orphans every
    // recorded trace and forces a re-record, so it is fixed here rather than
    // tracking the binary's own name.
    niobium::compiler().set_program_info(
        "matcher_compute", "1.0",
        "Set-membership: squared-distance + iterated-squaring indicator (SDK)");
    niobium::compiler().set_build_info(__FILE__, __LINE__, __TIMESTAMP__);
#else
#error "matcher_compute_sdk.cpp must be built with NIOBIUM_COMPILER"
#endif

    std::string keyDir, encodedDir, queryDir, resultPath;
    strfhe::MatchMode mode = strfhe::MatchMode::EXACT_CASE_INSENSITIVE;
    bool modeSet = false, keyDirSet = false, encSet = false,
         querySet = false, resultSet = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            std::string m = argv[++i];
            if (m == "soundex" || m == "fuzzy")
                mode = strfhe::MatchMode::SOUNDEX_FUZZY;
            else if (m == "exact")
                mode = strfhe::MatchMode::EXACT_CASE_INSENSITIVE;
            else { std::cerr << "Unknown mode: " << m << "\n"; return 1; }
            modeSet = true;
        } else if (arg == "--keydir"          && i + 1 < argc) { keyDir     = argv[++i]; keyDirSet = true; }
          else if (arg == "--encoded-dataset" && i + 1 < argc) { encodedDir = argv[++i]; encSet    = true; }
          else if (arg == "--query-dir"       && i + 1 < argc) { queryDir   = argv[++i]; querySet  = true; }
          else if (arg == "--result"          && i + 1 < argc) { resultPath = argv[++i]; resultSet = true; }
          else if (arg == "--niobium_hw")  { /* no-op: target drives HW format */ }
          else if (arg == "--target" && i + 1 < argc) { ++i; /* consumed by init() */ }
          // opt level (-O3 or --opt-level O3): consumed by init(); no-op here.
          else if (arg == "--opt-level" && i + 1 < argc) { ++i; /* consumed by init() */ }
          else if (arg.size() == 3 && arg.substr(0, 2) == "-O") { /* consumed by init() */ }
          else if (arg == "--help" || arg == "-h") { usage(argv[0]); return 0; }
          else { std::cerr << "Unknown argument: " << arg << "\n"; usage(argv[0]); return 1; }
    }
    if (!modeSet || !keyDirSet || !encSet || !querySet || !resultSet) {
        usage(argv[0]); return 1;
    }

    using Clock = std::chrono::steady_clock;
    auto t_total = Clock::now();

    // ── Load keys + encoded dataset (server-side state) ──────────────
    // Trust boundary: this stage is the server. It needs the context and the
    // evaluation keys, never the secret key, and loadKeys would deserialize one
    // that happened to be here. Refuse rather than hold it.
    if (std::filesystem::exists(std::filesystem::path(keyDir) / "sk.bin")) {
        std::cerr << "SERVER ABORT: secret key present in the compute key directory ("
                  << keyDir << "/sk.bin). The server must never hold the secret key. "
                  << "Remove it and re-provision.\n";
        return 2;
    }

    strfhe::FHEStringMatcher matcher(mode);
    if (!matcher.loadKeys(keyDir))
        throw std::runtime_error("cannot load keys from " + keyDir);
    if (!matcher.loadEncodedDataset(encodedDir))
        throw std::runtime_error("cannot load encoded dataset from " + encodedDir);
    // Zero batches means the encoding holds no names. The evaluate loop has
    // nothing to reduce over and would read past the end of the column vectors.
    if (matcher.getNumBatches() <= 0)
        throw std::runtime_error("encoded dataset in " + encodedDir +
                                 " holds no names (numBatches=0); re-run "
                                 "matcher_encode_dataset on a non-empty list");
    auto cc = matcher.getCryptoContext();

    // ── Load encrypted query (nameLen position ciphertexts) ──────────
    int nameLen = matcher.getNameLen();
    std::vector<Ciphertext<DCRTPoly>> encQuery(nameLen);
    for (int i = 0; i < nameLen; ++i) {
        auto qf = std::filesystem::path(queryDir) /
                  ("query_pos_" + std::to_string(i) + ".ct");
        if (!Serial::DeserializeFromFile(qf.string(), encQuery[i], SerType::BINARY))
            throw std::runtime_error("cannot load " + qf.string());
    }

    std::cout << "[compute-sdk] ring=" << cc->GetRingDimension()
              << " nameLen=" << nameLen
              << " mode=" << (mode == strfhe::MatchMode::SOUNDEX_FUZZY ? "soundex" : "exact")
              << std::endl;

    // ── Niobium (SDK) setup ──────────────────────────────────────────
    std::string modeStr = (mode == strfhe::MatchMode::SOUNDEX_FUZZY)
                             ? "soundex" : "exact";
    // The batch count is the trace's loop bound, so it has to be part of the
    // cache key: without it a run at one instance size replays the trace
    // recorded at another.
    niobium::Compiler::CacheParameters cacheParams = {
        {"mode",    modeStr},
        {"batches", std::to_string(matcher.getNumBatches())},
    };
    niobium::compiler().cache_parameters(cacheParams);

    // Tag in mult-server order: context, query ciphertexts, then keys. The
    // dataset/constant plaintexts are tagged inline by evaluate().
    niobium::compiler().capture_crypto_context(cc);
    for (int i = 0; i < nameLen; ++i)
        niobium::compiler().tag_input("query_pos_" + std::to_string(i), encQuery[i]);
    niobium::compiler().tag_keys(cc);

    Ciphertext<DCRTPoly> result;
    double compute_ms = 0.0;
    double record_ms  = 0.0;

    if (!niobium::compiler().is_cache_valid()) {
        // Record the trace once. In hollow mode the FHE math is skipped, so the
        // value left in `result` is not the answer -- the replay below produces
        // it. A cache hit records nothing and runs no FHE ops.
        std::cout << "[compute-sdk] recording trace (first run)...\n";
        niobium::compiler().start();
        niobium::compiler().enable_hollow_mode(true);

        // evaluate() runs inside the recording; it tags its own plaintexts.
        auto t_rec = Clock::now();
        result = matcher.evaluate(encQuery);
        record_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        Clock::now() - t_rec).count();

        niobium::compiler().enable_hollow_mode(false);  // must be OFF for probe/stop
        niobium::compiler().probe("result", result);
        niobium::compiler().stop();
        std::cout << "[compute-sdk] record done (" << record_ms << " ms)\n";
    }

    // Always replay to obtain the result: hollow recording computed nothing
    // usable, and a cache hit ran no FHE at all. replay() dispatches on
    // --target (local in-process simulator, or a backend over the transport);
    // result() reconstructs the output ciphertext.
    std::cout << "[compute-sdk] replaying (target from --target)...\n";
    auto t_replay = Clock::now();
    if (!niobium::compiler().replay()) {
        std::cerr << "[compute-sdk] replay failed\n"; return 1;
    }
    if (!niobium::compiler().result(cc, "result", result) || !result) {
        std::cerr << "[compute-sdk] result() failed\n"; return 1;
    }
    compute_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     Clock::now() - t_replay).count();
    std::cout << "[compute-sdk] replay done (" << compute_ms << " ms)\n";

    // ── Serialize the result ciphertext for matcher_decrypt_result ───
    if (!Serial::SerializeToFile(resultPath, result, SerType::BINARY))
        throw std::runtime_error("failed to serialize " + resultPath);

    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        Clock::now() - t_total).count();
    std::cout << "[compute-sdk] result -> " << resultPath
              << "  total=" << total_ms << " ms\n";

    return 0;
} catch (const std::exception& e) {
    std::cerr << "[compute-sdk] error: " << e.what() << std::endl;
    return 1;
}
