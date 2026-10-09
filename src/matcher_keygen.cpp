// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// matcher_keygen — Stage 1 of the multi-binary set-membership pipeline.
//
// Runs on the CLIENT machine. Generates the CKKS crypto context, key pair,
// EvalMult key, and rotation keys for slot summation. Writes the context, the
// public key and the secret key to <keydir>/, and with --server-keydir the
// context and the evaluation keys to that directory instead, so the server
// never holds the secret key.
//
// Usage:
//   matcher_keygen --mode exact|soundex --keydir <dir> [--server-keydir <dir>]

#include "fhe_string_matcher.h"

#include <chrono>
#include <iostream>
#include <string>

static void usage(const char* prog) {
    std::cerr <<
"Usage: " << prog << " --mode exact|soundex --keydir <dir>\n"
"                        [--server-keydir <dir>]\n"
"\n"
"Generates CKKS crypto context + keys for the set-membership matcher\n"
"and writes them to <keydir>/. Run once per (mode, parameter set).\n"
"\n"
"Files written to --keydir:\n"
"  cc.bin   crypto context\n"
"  pk.bin   public key (used by matcher_encrypt_query)\n"
"  sk.bin   secret key (CLIENT KEEPS PRIVATE - used by matcher_decrypt_result)\n"
"  mk.bin   eval mult key (used by matcher_compute_sdk)\n"
"  rk.bin   eval rotation keys (used by matcher_compute_sdk)\n"
"\n"
"With --server-keydir, cc.bin and the two evaluation keys are written there\n"
"instead, and --keydir keeps the context, the public key and the secret key.\n"
"The server then has no copy of the secret key, and nothing is duplicated.\n";
}

int main(int argc, char* argv[]) {
    std::string keyDir, serverKeyDir;
    strfhe::MatchMode mode = strfhe::MatchMode::EXACT_CASE_INSENSITIVE;
    bool modeSet = false, keyDirSet = false;

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
        } else if (arg == "--keydir" && i + 1 < argc) {
            keyDir = argv[++i];
            keyDirSet = true;
        } else if (arg == "--server-keydir" && i + 1 < argc) {
            serverKeyDir = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            usage(argv[0]); return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            usage(argv[0]); return 1;
        }
    }
    if (!modeSet || !keyDirSet) { usage(argv[0]); return 1; }

    auto t0 = std::chrono::steady_clock::now();
    strfhe::FHEStringMatcher matcher(mode);
    matcher.generateKeys();
    matcher.saveKeys(keyDir, serverKeyDir);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    std::cout << "[keygen] mode=" << (mode == strfhe::MatchMode::SOUNDEX_FUZZY
                                        ? "soundex" : "exact")
              << "  ringDim=" << matcher.getCryptoContext()->GetRingDimension()
              << "  multDepth=" << matcher.getMultDepth()
              << "  K=" << matcher.getKSquarings()
              << "  time=" << ms << " ms\n";
    return 0;
}