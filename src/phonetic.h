// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// phonetic.h — Soundex encoding and name-to-integer-vector utilities
//
// This header provides the preprocessing layer that sits between raw name
// strings and the FHE comparison circuit.  Two matching modes are supported:
//
//   EXACT_CASE_INSENSITIVE  — lowercase the name, encode each character
//                             as an integer 1-26, pad to fixed length.
//   SOUNDEX_FUZZY           — compute the Soundex phonetic hash (4 chars),
//                             encode each character as an integer, giving a
//                             short fixed-length vector that groups names
//                             that "sound alike."
//
// In both modes, the output is a fixed-length vector of int64_t values in
// [0, 26] suitable for packing into BFV SIMD plaintext slots.

#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace strfhe {

// ── Matching mode ──────────────────────────────────────────────────────

enum class MatchMode {
    EXACT_CASE_INSENSITIVE,
    SOUNDEX_FUZZY
};

// ── Constants ──────────────────────────────────────────────────────────

constexpr int EXACT_MAX_LEN  = 20;   // max encoded name length (exact mode)
constexpr int SOUNDEX_LEN    = 4;    // Soundex codes are always 4 chars
constexpr int MAX_CHAR_VAL   = 26;   // largest encoded character value

// The equality polynomial's f(0) sign depends on MAX_CHAR_VAL parity.
static_assert(MAX_CHAR_VAL % 2 == 0,
              "MAX_CHAR_VAL must be even for the equality polynomial scalar");

// ── String helpers ─────────────────────────────────────────────────────

inline std::string toLower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return r;
}

// Strip everything except ASCII letters.
inline std::string lettersOnly(const std::string& s) {
    std::string r;
    for (char c : s)
        if (std::isalpha(static_cast<unsigned char>(c)))
            r += c;
    return r;
}

// ── Soundex ────────────────────────────────────────────────────────────

inline char soundexCode(char c) {
    switch (std::toupper(static_cast<unsigned char>(c))) {
        case 'B': case 'F': case 'P': case 'V':                         return '1';
        case 'C': case 'G': case 'J': case 'K':
        case 'Q': case 'S': case 'X': case 'Z':                         return '2';
        case 'D': case 'T':                                              return '3';
        case 'L':                                                         return '4';
        case 'M': case 'N':                                              return '5';
        case 'R':                                                         return '6';
        default:                                                          return '0';
    }
}

// Standard Soundex: uppercase letter + 3 digits (e.g. "Robert" -> "R163").
inline std::string soundex(const std::string& name) {
    std::string alpha = lettersOnly(name);
    if (alpha.empty()) return "A000";

    std::string result;
    result += static_cast<char>(std::toupper(static_cast<unsigned char>(alpha[0])));

    char prev = soundexCode(alpha[0]);
    for (size_t i = 1; i < alpha.size() && result.size() < 4; ++i) {
        char code = soundexCode(alpha[i]);
        if (code != '0' && code != prev) {
            result += code;
        }
        prev = code;
    }

    while (result.size() < 4) result += '0';
    return result;
}

// ── Character encoding ─────────────────────────────────────────────────
//
// Maps characters to integers in [0, 26]:
//   letters a-z / A-Z  ->  1 .. 26
//   digits  0-9         ->  0 .. 9   (used only for Soundex digit positions)
//   everything else     ->  0        (also used as the padding sentinel)
//
// The key invariant is that the first character of any real name always
// encodes to a value in [1, 26], so padding slots (all zeros) can never
// produce a false match against a non-empty query.

inline int64_t encodeChar(char c) {
    if (c >= 'a' && c <= 'z') return static_cast<int64_t>(c - 'a' + 1);
    if (c >= 'A' && c <= 'Z') return static_cast<int64_t>(c - 'A' + 1);
    if (c >= '0' && c <= '9') return static_cast<int64_t>(c - '0');
    return 0;
}

// ── Name encoding ──────────────────────────────────────────────────────
//
// Returns a fixed-length vector of encoded character values suitable for
// column-major SIMD packing.

inline int nameLength(MatchMode mode) {
    return (mode == MatchMode::EXACT_CASE_INSENSITIVE) ? EXACT_MAX_LEN
                                                        : SOUNDEX_LEN;
}

inline std::vector<int64_t> encodeName(const std::string& name, MatchMode mode) {
    int len = nameLength(mode);
    std::string processed;

    if (mode == MatchMode::EXACT_CASE_INSENSITIVE) {
        processed = toLower(lettersOnly(name));
    } else {
        processed = soundex(name);
    }

    std::vector<int64_t> encoded(len, 0);
    for (int i = 0; i < std::min(static_cast<int>(processed.size()), len); ++i) {
        encoded[i] = encodeChar(processed[i]);
    }
    return encoded;
}

}  // namespace strfhe
