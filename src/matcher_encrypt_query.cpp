// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// matcher_encrypt_query — Stage 3 of the multi-binary set-membership pipeline.
//
// Runs on the CLIENT machine. Loads the public key, encrypts the query into
// nameLen ciphertexts (one per character position, value broadcast across
// SIMD slots), writes them to <out-dir>/. The server never sees the
// plaintext query — only these ciphertexts cross the trust boundary.
//
// Usage:
//   matcher_encrypt_query --mode exact|soundex --keydir <dir>
//                         --query <name> --out <query-dir>

#include "fhe_string_matcher.h"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "ciphertext-ser.h"

static void usage(const char* prog) {
    std::cerr <<
"Usage: " << prog << " --mode exact|soundex --keydir <dir>\n"
"                              --query <name> --out <query-dir>\n"
"\n"
"Encrypts a query name into nameLen ciphertexts (one per character\n"
"position) and writes them to <query-dir>/query_pos_<i>.ct.\n";
}

int main(int argc, char* argv[]) {
    std::string keyDir, queryName, queryDir;
    strfhe::MatchMode mode = strfhe::MatchMode::EXACT_CASE_INSENSITIVE;
    bool modeSet = false, keyDirSet = false, querySet = false, outSet = false;

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
        } else if (arg == "--keydir" && i + 1 < argc) { keyDir    = argv[++i]; keyDirSet = true; }
          else if (arg == "--query"  && i + 1 < argc) { queryName = argv[++i]; querySet  = true; }
          else if (arg == "--out"    && i + 1 < argc) { queryDir  = argv[++i]; outSet    = true; }
          else if (arg == "--help" || arg == "-h") { usage(argv[0]); return 0; }
          else { std::cerr << "Unknown argument: " << arg << "\n"; usage(argv[0]); return 1; }
    }
    if (!modeSet || !keyDirSet || !querySet || !outSet) {
        usage(argv[0]); return 1;
    }

    strfhe::FHEStringMatcher matcher(mode);
    if (!matcher.loadKeys(keyDir, /*requireEvalKeys=*/false))
        throw std::runtime_error("cannot load keys from " + keyDir);

    std::filesystem::create_directories(queryDir);

    auto t0 = std::chrono::steady_clock::now();
    auto encQuery = matcher.encryptQuery(queryName);
    for (size_t i = 0; i < encQuery.size(); ++i) {
        auto fname = std::filesystem::path(queryDir) /
                     ("query_pos_" + std::to_string(i) + ".ct");
        if (!Serial::SerializeToFile(fname.string(), encQuery[i],
                                     SerType::BINARY))
            throw std::runtime_error("failed to serialize " + fname.string());
    }
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    std::cout << "[encrypt] query=\"" << queryName << "\""
              << "  cts=" << encQuery.size()
              << "  out=" << queryDir
              << "  time=" << ms << " ms\n";
    return 0;
}