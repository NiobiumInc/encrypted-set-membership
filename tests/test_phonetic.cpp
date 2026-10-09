// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// test_phonetic.cpp — Unit tests for phonetic encoding (no FHE).
//
// These tests verify the deterministic transformations applied before
// any FHE math — Soundex hashing and the integer encoding used to feed
// CKKS plaintext encoding. They run in milliseconds and require no
// crypto context, so they run anywhere the binary builds.
//
// Coverage:
//   - soundex(): equivalence classes (Robert/Rupert/Robbrt → R163)
//   - soundex(): empty input edge case
//   - encodeName(EXACT): length, character mapping, zero padding
//   - encodeName(SOUNDEX): length, first-letter mapping
//
// Exit code: 0 = all pass, 1 = any failure.

#include "phonetic.h"

#include <iostream>
#include <string>

// ── Minimal test harness ──────────────────────────────────────────────────

static int g_passed = 0;
static int g_failed = 0;

#define TEST_ASSERT(cond, msg)                                          \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::cerr << "  FAIL: " << (msg) << "\n";                   \
            ++g_failed;                                                 \
        } else {                                                        \
            std::cout << "  PASS: " << (msg) << "\n";                   \
            ++g_passed;                                                 \
        }                                                               \
    } while (0)

// ── Soundex equivalence classes ───────────────────────────────────────────

static void testSoundexEquivalence() {
    std::cout << "\n[Soundex equivalence classes]\n";

    TEST_ASSERT(strfhe::soundex("Robert") == "R163", "soundex(Robert) == R163");
    TEST_ASSERT(strfhe::soundex("Rupert") == "R163", "soundex(Rupert) == R163");
    TEST_ASSERT(strfhe::soundex("Robbrt") == "R163", "soundex(Robbrt) == R163");
    TEST_ASSERT(strfhe::soundex("Smith")  == "S530", "soundex(Smith) == S530");
    TEST_ASSERT(strfhe::soundex("Smythe") == "S530", "soundex(Smythe) == S530");
}

static void testSoundexEdgeCases() {
    std::cout << "\n[Soundex edge cases]\n";

    TEST_ASSERT(strfhe::soundex("") == "A000", "soundex('') == A000");
}

// ── Integer encoding ──────────────────────────────────────────────────────

static void testExactEncoding() {
    std::cout << "\n[Exact-mode encoding]\n";

    auto enc = strfhe::encodeName("abc",
                                  strfhe::MatchMode::EXACT_CASE_INSENSITIVE);
    TEST_ASSERT(enc.size() == 20, "exact encoding pads to length 20");
    TEST_ASSERT(enc[0] == 1 && enc[1] == 2 && enc[2] == 3,
                "exact encoding: a=1, b=2, c=3");
    TEST_ASSERT(enc[3] == 0,  "exact encoding: position 3 is zero-padded");
    TEST_ASSERT(enc[19] == 0, "exact encoding: position 19 is zero-padded");
}

static void testSoundexEncoding() {
    std::cout << "\n[Soundex-mode encoding]\n";

    auto enc = strfhe::encodeName("Robert", strfhe::MatchMode::SOUNDEX_FUZZY);
    TEST_ASSERT(enc.size() == 4,  "soundex encoding has length 4");
    TEST_ASSERT(enc[0] == 18,     "soundex encoding: R -> 18");
}

// ── Main ──────────────────────────────────────────────────────────────────

int main() {
    std::cout << "========================================\n"
              << " Phonetic encoding — Unit Tests\n"
              << "========================================\n";

    testSoundexEquivalence();
    testSoundexEdgeCases();
    testExactEncoding();
    testSoundexEncoding();

    std::cout << "\n========================================\n"
              << " Results: " << g_passed << " passed, "
              << g_failed << " failed\n"
              << "========================================\n";

    return g_failed == 0 ? 0 : 1;
}