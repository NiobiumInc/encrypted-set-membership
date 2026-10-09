// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// matcher_decrypt_result — Stage 5 of the multi-binary set-membership pipeline.
//
// Runs on the CLIENT machine. Loads the secret key, deserializes the result
// ciphertext produced by matcher_compute_sdk, decrypts to a single aggregate
// score, and prints MATCH / NO MATCH.
//
// Usage:
//   matcher_decrypt_result --mode exact|soundex --keydir <dir>
//                          --result <result.ct>

#include "fhe_string_matcher.h"

#include <chrono>
#include <iostream>
#include <string>

#include "ciphertext-ser.h"

static void usage(const char* prog) {
    std::cerr <<
"Usage: " << prog << " --mode exact|soundex --keydir <dir>\n"
"                              --result <result.ct>\n"
"\n"
"Decrypts the aggregate match score and prints MATCH / NO MATCH.\n"
"Exit code: 0 = match, 1 = no match (suitable for shell pipelines).\n";
}

int main(int argc, char* argv[]) {
    std::string keyDir, resultPath;
    strfhe::MatchMode mode = strfhe::MatchMode::EXACT_CASE_INSENSITIVE;
    bool modeSet = false, keyDirSet = false, resultSet = false;

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
        } else if (arg == "--keydir" && i + 1 < argc) { keyDir     = argv[++i]; keyDirSet = true; }
          else if (arg == "--result" && i + 1 < argc) { resultPath = argv[++i]; resultSet = true; }
          else if (arg == "--help" || arg == "-h") { usage(argv[0]); return 0; }
          else { std::cerr << "Unknown argument: " << arg << "\n"; usage(argv[0]); return 1; }
    }
    if (!modeSet || !keyDirSet || !resultSet) { usage(argv[0]); return 1; }

    strfhe::FHEStringMatcher matcher(mode);
    if (!matcher.loadKeys(keyDir, /*requireEvalKeys=*/false))
        throw std::runtime_error("cannot load keys from " + keyDir);

    Ciphertext<DCRTPoly> result;
    if (!Serial::DeserializeFromFile(resultPath, result, SerType::BINARY))
        throw std::runtime_error("cannot deserialize " + resultPath);

    auto t0 = std::chrono::steady_clock::now();
    bool matched = matcher.decryptResult(result);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    std::cout << (matched ? "MATCH FOUND" : "NO MATCH")
              << "  (" << ms << " ms)\n";
    return matched ? 0 : 1;
}