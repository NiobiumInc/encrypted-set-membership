// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// fhe_string_matcher.h — Homomorphic string set-membership test (CKKS)
//
// Architecture overview (top-down)
// ================================
//
// GOAL: Given a client's private name and a server's private dataset of N
//       names, determine whether the name appears in the dataset, without
//       revealing the query to the server or the dataset to the client.
//
// WHY CKKS, NOT BFV:
//   This workload is built on CKKS.  CKKS operates over approximate
//   real numbers, so we cannot rely on exact modular arithmetic.  In
//   particular, the BFV-style equality polynomial  eq(x) = ∏(x²-k²)/f(0)
//   is numerically unstable in CKKS — intermediate products reach ~10^14,
//   drowning the ≈0 factor meant to signal a match.
//
// CKKS-FRIENDLY COMPARISON CIRCUIT:
//   Instead of exact equality testing, we compute a *squared Euclidean
//   distance* between the encoded query and each dataset name, then apply
//   an *iterated-squaring* approximation of a near-zero indicator.
//
//   For each SIMD slot j (one name per slot):
//
//     1. diff_i  = query[i] − dataset[j][i]          per character position
//     2. S_j     = Σ_i  diff_i²                      squared distance
//     3. s_j     = S_j / C                            normalise to [0, 1]
//     4. t_j     = 1 − s_j                            match ≈ 1, non-match < 1
//     5. t_j     = t_j ^ {2^K}                        iterated squaring
//                                                      • match ≈ 1   (stays near 1)
//                                                      • non-match → 0 (exponential decay)
//     6. sum     = Σ_j  t_j                            aggregate across names
//
//   The client decrypts sum; if > threshold → MATCH.
//
// DEPTH ANALYSIS:
//   Step 2: 1 level   (one ciphertext × ciphertext multiplication)
//   Step 3: 1 level   (ciphertext × plaintext-scalar multiplication)
//   Step 4: 0 levels  (subtraction only)
//   Step 5: K levels  (K repeated squarings)
//   ──────────────────
//   Total:  2 + K
//
//   K is chosen so that (1 − 1/C)^{2^K} < ε (a small threshold):
//     Soundex mode (C =  2 704): K = 14  →  depth 16
//     Exact mode   (C = 13 520): K = 16  →  depth 18
//
// PRIVACY:
//   • Client's query is encrypted — server never sees it.
//   • Server's dataset is in plaintext on the server — client never sees it.
//   • Client receives only the aggregate match score (≈ number of matches).
//   • For boolean output, client thresholds at 0.5.

#pragma once

#include "openfhe.h"
#include "phonetic.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace strfhe {

class FHEStringMatcher {
public:
    explicit FHEStringMatcher(MatchMode mode = MatchMode::EXACT_CASE_INSENSITIVE);

    // ── Setup (both parties) ──────────────────────────────────────────
    void generateKeys();

    // Persist and reload crypto context + all key material to/from disk.
    // loadKeys() returns false if the key directory doesn't exist yet.
    // With a server directory, the evaluation keys are written there and the
    // secret key stays in keyDir. Without one, everything lands together.
    void saveKeys(const std::filesystem::path& keyDir,
                  const std::filesystem::path& serverKeyDir = {}) const;
    // The client stages encrypt and decrypt but never evaluate, so they pass
    // requireEvalKeys=false and read none of the evaluation key material.
    bool loadKeys(const std::filesystem::path& keyDir, bool requireEvalKeys = true);

    // ── Server side ───────────────────────────────────────────────────
    void encodeDataset(const std::vector<std::string>& names);

    // Persist / reload the encoded dataset (column-major plaintexts).
    // Layout on disk: <dir>/dataset_meta.json holds {numNames, numBatches,
    // nameLen, batchSize, mode}. Per-(pos, batch) plaintexts are stored in
    // <dir>/col_<pos>_batch_<b>.pt files.
    void saveEncodedDataset(const std::filesystem::path& dir) const;
    bool loadEncodedDataset(const std::filesystem::path& dir);

    // Server-side homomorphic evaluation (EvalSub / EvalMult / EvalAdd /
    // EvalNegate / evalSumSlots).
    //
    // When called inside a Niobium recording window, every plaintext
    // referenced (the 1/C and 1.0 constants and each dataset column) is
    // registered with the recorder via the pause / tag_input
    // / resume idiom, which is how they reach the replay: an untagged
    // plaintext is not captured into the recording.
    Ciphertext<DCRTPoly> evaluate(
        const std::vector<Ciphertext<DCRTPoly>>& encryptedQuery) const;

    // ── Client side ───────────────────────────────────────────────────
    std::vector<Ciphertext<DCRTPoly>> encryptQuery(const std::string& name) const;
    bool decryptResult(const Ciphertext<DCRTPoly>& encryptedResult) const;

    // ── Accessors ─────────────────────────────────────────────────────
    CryptoContext<DCRTPoly>  getCryptoContext() const { return cc_; }
    int                      getMultDepth()     const { return multDepth_; }
    int                      getKSquarings()    const { return kSquarings_; }
    int                      getNameLen()       const { return nameLen_; }
    int                      getNumBatches()    const { return numBatches_; }
    int                      getBatchSize()     const { return batchSize_; }

private:
    // ── Configuration ─────────────────────────────────────────────────
    MatchMode  mode_;
    int        nameLen_;          // L: encoded name length
    int        multDepth_;        // total multiplicative depth budget
    int        kSquarings_;       // K: iterated-squaring rounds
    double     normConst_;        // C: max possible squared distance
    int        batchSize_;        // CKKS SIMD slots (ring dim / 2)

    // CKKS encoding parameters
    static constexpr usint SCALING_MOD_SIZE = 50;   // bits per level
    static constexpr usint FIRST_MOD_SIZE   = 60;   // first modulus bits

    // ── Crypto objects ────────────────────────────────────────────────
    CryptoContext<DCRTPoly> cc_;
    KeyPair<DCRTPoly>       keyPair_;

    // ── Encoded dataset (column-major plaintexts) ─────────────────────
    //    datasetColumns_[pos][batch] — Plaintext whose slot j holds
    //    character-code at position `pos` of name (batch*batchSize_ + j).
    std::vector<std::vector<Plaintext>> datasetColumns_;
    // Parallel raw-doubles cache. Persisted to disk by saveEncodedDataset
    // and reloaded by loadEncodedDataset, then re-fed into
    // MakeCKKSPackedPlaintext to rebuild datasetColumns_. We persist raw
    // doubles instead of serializing Plaintexts directly because OpenFHE's
    // cereal registration doesn't cover CKKSPackedEncoding.
    std::vector<std::vector<std::vector<double>>> datasetColumnsRaw_;
    int numNames_;
    int numBatches_;

    // ── Helpers ───────────────────────────────────────────────────────
    Ciphertext<DCRTPoly> evalSumSlots(const Ciphertext<DCRTPoly>& ct) const;
};

}  // namespace strfhe
