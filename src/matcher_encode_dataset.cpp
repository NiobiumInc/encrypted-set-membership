// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// matcher_encode_dataset — Stage 2 of the multi-binary set-membership pipeline.
//
// Runs on the SERVER machine. Reads a dataset (one name per line) and the
// crypto context produced by matcher_keygen. Produces the column-major
// CKKS plaintext encoding of the dataset and writes it to <encoded-dir>/.
//
// Run once per (mode, dataset) pair. Independent of any specific query —
// The compute stage reuses the encoded dataset across queries.
//
// Usage:
//   matcher_encode_dataset --mode exact|soundex --keydir <dir>
//                          --dataset <names.txt> --out <encoded-dir>

#include "fhe_string_matcher.h"
#include "phonetic.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void usage(const char* prog) {
    std::cerr <<
"Usage: " << prog << " --mode exact|soundex --keydir <dir>\n"
"                              --dataset <names.txt> --out <encoded-dir>\n"
"\n"
"Encodes a name list into column-major CKKS plaintexts (one Plaintext\n"
"per character position per batch). Writes them to <encoded-dir>/.\n";
}

static std::vector<std::string> loadNames(const std::string& path) {
    std::vector<std::string> names;
    std::ifstream in(path);
    if (!in.is_open())
        throw std::runtime_error("cannot open dataset file: " + path);
    std::string line;
    while (std::getline(in, line)) {
        auto start = line.find_first_not_of(" \t\r\n");
        auto end   = line.find_last_not_of(" \t\r\n");
        if (start != std::string::npos)
            names.push_back(line.substr(start, end - start + 1));
    }
    return names;
}

int main(int argc, char* argv[]) try {
    std::string keyDir, datasetPath, encodedDir;
    strfhe::MatchMode mode = strfhe::MatchMode::EXACT_CASE_INSENSITIVE;
    bool modeSet = false, keyDirSet = false, datasetSet = false, outSet = false;

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
        } else if (arg == "--keydir"  && i + 1 < argc) { keyDir      = argv[++i]; keyDirSet  = true; }
          else if (arg == "--dataset" && i + 1 < argc) { datasetPath = argv[++i]; datasetSet = true; }
          else if (arg == "--out"     && i + 1 < argc) { encodedDir  = argv[++i]; outSet     = true; }
          else if (arg == "--help" || arg == "-h") { usage(argv[0]); return 0; }
          else { std::cerr << "Unknown argument: " << arg << "\n"; usage(argv[0]); return 1; }
    }
    if (!modeSet || !keyDirSet || !datasetSet || !outSet) {
        usage(argv[0]); return 1;
    }

    strfhe::FHEStringMatcher matcher(mode);
    if (!matcher.loadKeys(keyDir))
        throw std::runtime_error("cannot load keys from " + keyDir);

    auto names = loadNames(datasetPath);
    // An empty list encodes to zero batches, which the compute stage cannot
    // evaluate. Refuse here, where the cause is still visible.
    if (names.empty())
        throw std::runtime_error("no names in " + datasetPath +
                                 ": the dataset needs at least one line with a letter");
    std::cout << "[encode] " << names.size() << " names from " << datasetPath << "\n";

    auto t0 = std::chrono::steady_clock::now();
    matcher.encodeDataset(names);
    matcher.saveEncodedDataset(encodedDir);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::steady_clock::now() - t0).count();

    std::cout << "[encode] mode=" << (mode == strfhe::MatchMode::SOUNDEX_FUZZY
                                        ? "soundex" : "exact")
              << "  numBatches=" << matcher.getNumBatches()
              << "  batchSize=" << matcher.getBatchSize()
              << "  time=" << ms << " ms\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "[encode] error: " << e.what() << std::endl;
    return 1;
}