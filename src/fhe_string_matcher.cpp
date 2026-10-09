// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// fhe_string_matcher.cpp — CKKS implementation of homomorphic string matching
//
// See fhe_string_matcher.h for the full architectural overview.
//
// Key difference from BFV:
//   CKKS works over approximate reals, so we cannot use exact equality
//   polynomials.  Instead we compute the squared Euclidean distance
//   between encoded name vectors and apply iterated squaring to
//   approximate a near-zero indicator function.

#include "fhe_string_matcher.h"

#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#ifdef NIOBIUM_COMPILER
#include <niobium/compiler.h>
#endif

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace strfhe {

// ════════════════════════════════════════════════════════════════════════
//  Construction
// ════════════════════════════════════════════════════════════════════════

FHEStringMatcher::FHEStringMatcher(MatchMode mode)
    : mode_(mode),
      nameLen_(nameLength(mode)),
      multDepth_(0),
      kSquarings_(0),
      normConst_(0.0),
      batchSize_(0),
      numNames_(0),
      numBatches_(0)
{
    // C = MAX_CHAR_VAL^2 * L — the largest possible squared distance
    // between any two encoded names.
    normConst_ = static_cast<double>(MAX_CHAR_VAL) * MAX_CHAR_VAL * nameLen_;

    // K (iterated-squaring rounds) is chosen so that the minimum
    // non-match indicator  (1 − 1/C)^{2^K}  falls below a small ε.
    //
    //   (1 − 1/C)^{2^K}  ≈  exp(−2^K / C)  <  ε
    //   =>  2^K  >  C · ln(1/ε)
    //
    // We target ε = 0.01 for comfortable discrimination.
    double targetExp = normConst_ * std::log(1.0 / 0.01);  // C * ln(100)
    kSquarings_ = static_cast<int>(std::ceil(std::log2(targetExp)));
    // Clamp to a reasonable range.
    kSquarings_ = std::max(kSquarings_, 4);
    kSquarings_ = std::min(kSquarings_, 25);

    // Total depth: 1 (squaring) + 1 (normalisation scalar mult) + K
    // iterated squarings = 2 + K. Same as main.
    multDepth_ = 2 + kSquarings_;
}

// ════════════════════════════════════════════════════════════════════════
//  Key generation
// ════════════════════════════════════════════════════════════════════════

void FHEStringMatcher::generateKeys() {
    // ── CKKS parameters ─────────────────────────────────────────────
    CCParams<CryptoContextCKKSRNS> params;
    params.SetMultiplicativeDepth(multDepth_);
    params.SetScalingModSize(SCALING_MOD_SIZE);
    params.SetFirstModSize(FIRST_MOD_SIZE);
    params.SetSecurityLevel(HEStd_128_classic);
    // FLEXIBLEAUTO works for inline ct·pt EvalSub when paired with the
    // plaintext-tagging pattern in evaluate(); see NIOBIUM_INTEGRATION.md.
    params.SetScalingTechnique(FLEXIBLEAUTO);

    cc_ = GenCryptoContext(params);
    cc_->Enable(PKE);
    cc_->Enable(KEYSWITCH);
    cc_->Enable(LEVELEDSHE);

    // ── Key generation ──────────────────────────────────────────────
    keyPair_ = cc_->KeyGen();
    cc_->EvalMultKeyGen(keyPair_.secretKey);

    // CKKS batch size = ring dimension / 2.
    batchSize_ = static_cast<int>(cc_->GetRingDimension() / 2);

    // Rotation keys for slot summation (powers of 2).
    std::vector<int32_t> rotIdx;
    for (int32_t r = 1; r < batchSize_; r *= 2)
        rotIdx.push_back(r);
    cc_->EvalRotateKeyGen(keyPair_.secretKey, rotIdx);

    std::cout << "[setup] CKKS ring dim = " << cc_->GetRingDimension()
              << ", batch size = " << batchSize_
              << ", mult depth = " << multDepth_
              << " (K=" << kSquarings_ << " squarings)\n";
    std::cout << "[setup] norm constant C = " << normConst_
              << ", worst-case indicator ≈ "
              << std::pow(1.0 - 1.0 / normConst_,
                          std::pow(2.0, kSquarings_))
              << "\n";
}

// ════════════════════════════════════════════════════════════════════════
//  Server: encode the dataset into column-major plaintexts
// ════════════════════════════════════════════════════════════════════════

void FHEStringMatcher::encodeDataset(const std::vector<std::string>& names) {
    numNames_   = static_cast<int>(names.size());
    numBatches_ = (numNames_ + batchSize_ - 1) / batchSize_;

    // Encode every name into a fixed-length integer vector, then promote
    // to double for CKKS plaintext encoding.
    std::vector<std::vector<int64_t>> encoded(numNames_);
    for (int j = 0; j < numNames_; ++j)
        encoded[j] = encodeName(names[j], mode_);

    // Build column-major plaintext packing. Keep both the Plaintext (for
    // FHE eval) and the raw doubles (for save/load round-trips, since
    // OpenFHE doesn't register CKKSPackedEncoding for cereal).
    datasetColumns_.resize(nameLen_);
    datasetColumnsRaw_.resize(nameLen_);
    for (int pos = 0; pos < nameLen_; ++pos) {
        datasetColumns_[pos].resize(numBatches_);
        datasetColumnsRaw_[pos].resize(numBatches_);
        for (int b = 0; b < numBatches_; ++b) {
            int start = b * batchSize_;
            int count = std::min(batchSize_, numNames_ - start);

            std::vector<double> col(batchSize_, 0.0);
            for (int j = 0; j < count; ++j)
                col[j] = static_cast<double>(encoded[start + j][pos]);

            datasetColumns_[pos][b]    = cc_->MakeCKKSPackedPlaintext(col);
            datasetColumnsRaw_[pos][b] = std::move(col);
        }
    }

    std::cout << "[server] encoded " << numNames_ << " names across "
              << numBatches_ << " batch(es)\n";
}

// ════════════════════════════════════════════════════════════════════════
//  Client: encrypt the query name
// ════════════════════════════════════════════════════════════════════════

std::vector<Ciphertext<DCRTPoly>>
FHEStringMatcher::encryptQuery(const std::string& name) const {
    if (!keyPair_.publicKey)
        throw std::runtime_error(
            "no public key loaded: this stage needs a key directory containing pk.bin");

    auto enc = encodeName(name, mode_);

    std::vector<Ciphertext<DCRTPoly>> cts(nameLen_);
    for (int pos = 0; pos < nameLen_; ++pos) {
        std::vector<double> rep(batchSize_, static_cast<double>(enc[pos]));
        auto pt = cc_->MakeCKKSPackedPlaintext(rep);
        cts[pos] = cc_->Encrypt(keyPair_.publicKey, pt);
    }
    return cts;
}

// ════════════════════════════════════════════════════════════════════════
//  Rotate-and-sum across SIMD slots
// ════════════════════════════════════════════════════════════════════════

Ciphertext<DCRTPoly>
FHEStringMatcher::evalSumSlots(const Ciphertext<DCRTPoly>& ct) const {
    auto acc = ct;
    for (int32_t r = 1; r < batchSize_; r *= 2) {
        auto rotated = cc_->EvalRotate(acc, r);
        acc = cc_->EvalAdd(acc, rotated);
    }
    return acc;
}

// ════════════════════════════════════════════════════════════════════════
//  Server: full homomorphic evaluation
// ════════════════════════════════════════════════════════════════════════
//
//  For each batch of names packed into SIMD slots:
//
//    1. Per-position difference:      diff_i   = query[i] − dataset[j][i]
//    2. Squared difference:           sq_i     = diff_i²            [depth 1]
//    3. Sum across positions:         S        = Σ sq_i             [depth 1]
//    4. Normalise:                    s        = S · (1/C)          [depth 2]
//    5. Complement:                   t        = 1 − s              [depth 2]
//    6. Iterated squaring (K rounds): t        = t^{2^K}           [depth 2+K]
//    7. Aggregate across slots:       sum      = Σ_j  t_j          [no depth]

// Server-side homomorphic evaluation: sum-of-squared-diffs → normalise →
// complement → K iterated squarings → slot-sum → cross-batch accumulate.
// Total depth = 2 + K.
//
// When called inside a Niobium recording window, every plaintext we
// reference must be registered with the recorder via the
// pause / tag_input / resume pattern:
//
//   niobium::compiler().pause();
//   auto pt = cc->MakeCKKSPackedPlaintext(...);
//   niobium::compiler().tag_input("name", pt);  // tags the PLAINTEXT
//   niobium::compiler().resume();
//   ... use pt in FHE math ...
//
// pause/resume keeps the construction itself out of the trace; tag_input
// registers the plaintext with the recorder so subsequent uses reference
// it as a tagged input. This is how the dataset reaches the replay: an
// untagged plaintext is not captured, so the recording would have no
// dataset to run against. See NIOBIUM_INTEGRATION.md.
Ciphertext<DCRTPoly>
FHEStringMatcher::evaluate(
        const std::vector<Ciphertext<DCRTPoly>>& encQuery) const {

    if (static_cast<int>(encQuery.size()) != nameLen_)
        throw std::invalid_argument("encrypted query has wrong number of positions");
    if (datasetColumns_.empty())
        throw std::runtime_error("dataset not loaded");

    // Build constant plaintexts via the pause/resume + tag_input pattern.
    // Construction happens outside the recording (pause), the plaintext is
    // tagged as a recording input (tag_input), then we resume. Skipped in
    // the client stages, which build without the recorder.
#ifdef NIOBIUM_COMPILER
    niobium::compiler().pause();
#endif
    std::vector<double> normVec(batchSize_, 1.0 / normConst_);
    auto normPt = cc_->MakeCKKSPackedPlaintext(normVec);
#ifdef NIOBIUM_COMPILER
    niobium::compiler().tag_input("evaluate_normPt", normPt);
#endif
    std::vector<double> onesVec(batchSize_, 1.0);
    auto onesPt = cc_->MakeCKKSPackedPlaintext(onesVec);
#ifdef NIOBIUM_COMPILER
    niobium::compiler().tag_input("evaluate_onesPt", onesPt);
    niobium::compiler().resume();
#endif

    // Tag the (kept) dataset column plaintexts as recording inputs too.
    // Same pattern: pause, tag, resume — so the recorder knows about
    // them as named inputs rather than encountering them inline. No-op in
    // the client stages.
#ifdef NIOBIUM_COMPILER
    niobium::compiler().pause();
    for (int pos = 0; pos < nameLen_; ++pos) {
        for (int b = 0; b < numBatches_; ++b) {
            auto tag = "evaluate_col_" + std::to_string(pos) +
                       "_batch_" + std::to_string(b);
            niobium::compiler().tag_input(tag, datasetColumns_[pos][b]);
        }
    }
    niobium::compiler().resume();
#endif

    Ciphertext<DCRTPoly> totalSum;
    bool first = true;

    for (int b = 0; b < numBatches_; ++b) {
        // First position
        Plaintext pt0 = datasetColumns_[0][b];
        auto diff0 = cc_->EvalSub(encQuery[0], pt0);
        auto S = cc_->EvalMult(diff0, diff0);

        // Remaining positions
        for (int pos = 1; pos < nameLen_; ++pos) {
            Plaintext ptPos = datasetColumns_[pos][b];
            auto diff = cc_->EvalSub(encQuery[pos], ptPos);
            auto sq   = cc_->EvalMult(diff, diff);
            S = cc_->EvalAdd(S, sq);
        }

        // Normalise: ct·pt mult with full-width plaintext (not size-1).
        auto s = cc_->EvalMult(S, normPt);
        // Complement: 1 - s, with full-width "1" plaintext (not size-1).
        auto t = cc_->EvalAdd(cc_->EvalNegate(s), onesPt);

        for (int round = 0; round < kSquarings_; ++round) {
            t = cc_->EvalMult(t, t);
        }

        auto batchSum = evalSumSlots(t);

        if (first) { totalSum = batchSum; first = false; }
        else        totalSum = cc_->EvalAdd(totalSum, batchSum);
    }

    return totalSum;
}

// ════════════════════════════════════════════════════════════════════════
//  Client: decrypt and interpret result
// ════════════════════════════════════════════════════════════════════════

bool FHEStringMatcher::decryptResult(
        const Ciphertext<DCRTPoly>& encResult) const {
    if (!keyPair_.secretKey)
        throw std::runtime_error(
            "no secret key loaded: decryption runs on the client, so this stage "
            "needs a key directory containing sk.bin");

    Plaintext pt;
    cc_->Decrypt(keyPair_.secretKey, encResult, &pt);
    pt->SetLength(1);

    auto vals = pt->GetRealPackedValue();
    double score = vals[0];

    std::cout << "[client] raw aggregate score = " << score << "\n";

    // After iterated squaring, each matching name contributes ≈ 1.0 to
    // the sum, and each non-match contributes ≈ 0.  A threshold of 0.5
    // comfortably separates "at least one match" from "no matches".
    return score > 0.5;
}

void FHEStringMatcher::saveKeys(const std::filesystem::path& keyDir,
                                const std::filesystem::path& serverKeyDir) const {
    std::filesystem::create_directories(keyDir);
    // The evaluation keys are the server's, and they are by far the largest
    // files. Writing them straight to the server's directory keeps the secret
    // key and the evaluation keys apart without copying either.
    const auto evalDir = serverKeyDir.empty() ? keyDir : serverKeyDir;
    if (!serverKeyDir.empty()) {
        std::filesystem::create_directories(evalDir);
        if (!Serial::SerializeToFile((evalDir / "cc.bin").string(), cc_, SerType::BINARY))
            throw std::runtime_error("saveKeys: failed to serialize crypto context");
    }

    if (!Serial::SerializeToFile((keyDir / "cc.bin").string(), cc_, SerType::BINARY))
        throw std::runtime_error("saveKeys: failed to serialize crypto context");
    if (!Serial::SerializeToFile((keyDir / "pk.bin").string(), keyPair_.publicKey, SerType::BINARY))
        throw std::runtime_error("saveKeys: failed to serialize public key");
    if (!Serial::SerializeToFile((keyDir / "sk.bin").string(), keyPair_.secretKey, SerType::BINARY))
        throw std::runtime_error("saveKeys: failed to serialize secret key");

    std::ofstream mk_out(evalDir / "mk.bin", std::ios::binary);
    if (!cc_->SerializeEvalMultKey(mk_out, SerType::BINARY))
        throw std::runtime_error("saveKeys: failed to serialize eval mult key");

    std::ofstream rk_out(evalDir / "rk.bin", std::ios::binary);
    if (!cc_->SerializeEvalAutomorphismKey(rk_out, SerType::BINARY))
        throw std::runtime_error("saveKeys: failed to serialize eval rotation keys");

    std::cout << "[keys] Saved to " << keyDir << "\n";
}

bool FHEStringMatcher::loadKeys(const std::filesystem::path& keyDir,
                               bool requireEvalKeys) {
    if (!std::filesystem::exists(keyDir / "cc.bin"))
        return false;

    if (!Serial::DeserializeFromFile((keyDir / "cc.bin").string(), cc_, SerType::BINARY))
        return false;
    cc_->Enable(PKE);
    cc_->Enable(KEYSWITCH);
    cc_->Enable(LEVELEDSHE);

    // The public and secret keys are loaded only if present. The server stages
    // need neither: encode uses the context, compute uses the evaluation keys,
    // and nothing server-side decrypts. Requiring sk.bin here would force the
    // secret key onto a machine that must never hold it, so a server-side key
    // directory can ship without it.
    Serial::DeserializeFromFile((keyDir / "pk.bin").string(), keyPair_.publicKey, SerType::BINARY);
    Serial::DeserializeFromFile((keyDir / "sk.bin").string(), keyPair_.secretKey, SerType::BINARY);

    // Only the compute stage evaluates. The client stages encrypt with the
    // public key and decrypt with the secret key, so they never read these.
    if (requireEvalKeys) {
        std::ifstream mk_in(keyDir / "mk.bin", std::ios::binary);
        if (!cc_->DeserializeEvalMultKey(mk_in, SerType::BINARY))
            return false;

        std::ifstream rk_in(keyDir / "rk.bin", std::ios::binary);
        if (!cc_->DeserializeEvalAutomorphismKey(rk_in, SerType::BINARY))
            return false;
    }

    batchSize_ = static_cast<int>(cc_->GetRingDimension() / 2);
    std::cout << "[keys] Loaded from " << keyDir
              << " (ring dim=" << cc_->GetRingDimension() << ")\n";
    return true;
}

// ════════════════════════════════════════════════════════════════════════
//  Encoded dataset persistence
// ════════════════════════════════════════════════════════════════════════
//
// Layout on disk:
//   <dir>/dataset_meta.txt              key=value: numNames, numBatches,
//                                       nameLen, batchSize, mode (0|1)
//   <dir>/col_<pos>_batch_<batch>.pt    one Plaintext per (pos, batch)
//
// Many small files — supports
// lazy per-batch loading on the Niobium replay path.

void FHEStringMatcher::saveEncodedDataset(const std::filesystem::path& dir) const {
    if (datasetColumnsRaw_.empty())
        throw std::runtime_error("saveEncodedDataset: dataset not loaded");

    std::filesystem::create_directories(dir);

    {
        std::ofstream meta(dir / "dataset_meta.txt");
        if (!meta.is_open())
            throw std::runtime_error("saveEncodedDataset: cannot open meta file");
        meta << "numNames=" << numNames_ << "\n"
             << "numBatches=" << numBatches_ << "\n"
             << "nameLen=" << nameLen_ << "\n"
             << "batchSize=" << batchSize_ << "\n"
             << "mode=" << static_cast<int>(mode_) << "\n";
    }

    // Persist raw doubles, not Plaintexts. OpenFHE doesn't register
    // CKKSPackedEncoding for cereal polymorphic save; loadEncodedDataset
    // re-encodes via cc_->MakeCKKSPackedPlaintext (cheap, ~ms per column).
    for (int pos = 0; pos < nameLen_; ++pos) {
        for (int b = 0; b < numBatches_; ++b) {
            auto fname = dir / ("col_" + std::to_string(pos) +
                                "_batch_" + std::to_string(b) + ".col");
            std::ofstream out(fname, std::ios::binary);
            if (!out.is_open())
                throw std::runtime_error(
                    "saveEncodedDataset: cannot open " + fname.string());
            const auto& col = datasetColumnsRaw_[pos][b];
            out.write(reinterpret_cast<const char*>(col.data()),
                      static_cast<std::streamsize>(col.size() * sizeof(double)));
        }
    }

    std::cout << "[dataset] Saved " << (nameLen_ * numBatches_)
              << " columns (" << numNames_ << " names, "
              << numBatches_ << " batches) to " << dir << "\n";
}

bool FHEStringMatcher::loadEncodedDataset(const std::filesystem::path& dir) {
    auto metaPath = dir / "dataset_meta.txt";
    if (!std::filesystem::exists(metaPath))
        return false;

    int loadedMode = -1;
    {
        std::ifstream meta(metaPath);
        std::string line;
        while (std::getline(meta, line)) {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            auto key = line.substr(0, eq);
            auto val = line.substr(eq + 1);
            if      (key == "numNames")   numNames_   = std::stoi(val);
            else if (key == "numBatches") numBatches_ = std::stoi(val);
            else if (key == "nameLen")    nameLen_    = std::stoi(val);
            else if (key == "batchSize")  batchSize_  = std::stoi(val);
            else if (key == "mode")       loadedMode  = std::stoi(val);
        }
    }

    if (loadedMode != static_cast<int>(mode_))
        throw std::runtime_error(
            "loadEncodedDataset: mode mismatch (file mode=" +
            std::to_string(loadedMode) + ", matcher mode=" +
            std::to_string(static_cast<int>(mode_)) + ")");

    datasetColumns_.assign(nameLen_,
        std::vector<Plaintext>(numBatches_));
    datasetColumnsRaw_.assign(nameLen_,
        std::vector<std::vector<double>>(numBatches_));

    // Read raw doubles per (pos, batch) and re-encode via the matcher's
    // crypto context. Both the Plaintext and the raw cache are populated
    // so the dataset can be re-saved later if needed.
    for (int pos = 0; pos < nameLen_; ++pos) {
        for (int b = 0; b < numBatches_; ++b) {
            auto fname = dir / ("col_" + std::to_string(pos) +
                                "_batch_" + std::to_string(b) + ".col");
            std::ifstream in(fname, std::ios::binary);
            if (!in.is_open()) return false;

            std::vector<double> col(batchSize_);
            in.read(reinterpret_cast<char*>(col.data()),
                    static_cast<std::streamsize>(col.size() * sizeof(double)));
            if (in.gcount() !=
                static_cast<std::streamsize>(col.size() * sizeof(double)))
                return false;

            datasetColumns_[pos][b]    = cc_->MakeCKKSPackedPlaintext(col);
            datasetColumnsRaw_[pos][b] = std::move(col);
        }
    }

    std::cout << "[dataset] Loaded " << (nameLen_ * numBatches_)
              << " plaintexts (" << numNames_ << " names, "
              << numBatches_ << " batches) from " << dir << "\n";
    return true;
}

}  // namespace strfhe
