# Design Specification: CKKS Private Set Membership for Names

## 1. Problem Statement

We need an application where a **client** holds a private name (the query) and a **server** holds a private dataset of names. The system must determine whether the query name appears in the dataset and return a Boolean result, without revealing the query to the server or the dataset to the client.

The system must support datasets of at least 10,000 names and scale beyond that as processing time allows, tolerate minor misspellings through phonetic matching, and operate under the **CKKS** FHE scheme.

Two limits qualify the first two of those. Phonetic matching is supported at the toy tier only, for the reasons in §3.2, and the aggregate carries match counts below 512, as §5.4 describes.

## 2. Architecture Overview

The system is organized in four layers, from the top down:

```
┌──────────────────────────────────────────────────────┐
│  Layer 4: Protocol                                   │
│  Client encrypts query → Server evaluates circuit    │
│  → Client decrypts boolean result                    │
├──────────────────────────────────────────────────────┤
│  Layer 3: Homomorphic Circuit                        │
│  Squared-distance computation + iterated-squaring    │
│  indicator + SIMD aggregation                        │
├──────────────────────────────────────────────────────┤
│  Layer 2: SIMD Data Layout                           │
│  Column-major packing: one ciphertext per character  │
│  position, one SIMD slot per dataset name            │
├──────────────────────────────────────────────────────┤
│  Layer 1: Name Encoding                              │
│  Phonetic hashing (Soundex) or case-insensitive      │
│  letter encoding → fixed-length integer vectors      │
└──────────────────────────────────────────────────────┘
```

## 3. Layer 1: Name Encoding

### 3.1 Character Encoding - Client-side, NOT in FHE

Every name is first reduced to a fixed-length vector of integers. Letters a–z are mapped to integers 1–26 (case-insensitive), digits 0–9 map to 0–9 (used only in Soundex codes), and all other characters (spaces, hyphens, etc.) are stripped. The result is zero-padded to a fixed length.

The invariant here is that the first character of any real name always encodes to a value in [1, 26], so zero-padded unused SIMD slots (all zeros) can never produce a false match against a non-empty query.

### 3.2 Matching Modes

**Exact mode** (`EXACT_CASE_INSENSITIVE`): The name is lowercased, non-letters are stripped, and the result is encoded character-by-character into a vector of length L = 20. Names shorter than 20 characters are zero-padded; names longer than 20 are truncated. Two names match if and only if their encoded vectors are identical.

**Soundex mode** (`SOUNDEX_FUZZY`): Before encoding, the name is run through the standard Soundex phonetic hash, producing a 4-character code (one uppercase letter followed by three digits). For example, "Robert", "Rupert", and "Robbrt" all produce `R163`. The Soundex code is then encoded into a vector of length L = 4 using the same character-to-integer mapping.

Soundex mode is supported at the toy tier only. A 4-character code space holds roughly 8,900 codes, so on a larger list many names share a code and many more sit one digit apart. The indicator returns a small non-zero value for those near misses, and summing it over a large dataset leaves the match count unrecoverable while eroding the margin under the 0.5 threshold. Exact mode compares 20 characters, which keeps non-matching names far enough apart for the indicator to stay near zero, so it carries every tier.

Soundex reduces fuzzy string matching to exact matching on short hash codes. This is the mechanism by which the system tolerates misspellings — it doesn't compare the raw strings at all in fuzzy mode, it compares their phonetic fingerprints. The tradeoff is that Soundex is a lossy hash: phonetically similar but semantically different names (e.g., "Robert" and "Rupert") will match. For the name-matching use case, this is acceptable.

### 3.3 Why Soundex and Not Edit Distance

We considered implementing Levenshtein (edit) distance directly in FHE. A recent paper (Legiest et al., "Leuvenshtein," USENIX Security 2025) achieves efficient encrypted edit distance, but their approach fundamentally depends on TFHE-specific features: programmable bootstrapping lookup tables for the min-of-three operation, delta encoding with exact ternary arithmetic, and data-dependent control flow. None of these are available in CKKS, which operates over approximate real numbers with no branching or exact comparison primitives. Adapting their technique to CKKS would require replacing every core building block, and the resulting circuit depth would be prohibitive.

Soundex sidesteps the problem entirely by moving the fuzzy-matching logic into a plaintext preprocessing step that runs before encryption, then reducing the encrypted computation to exact matching on short fixed-length codes.

## 4. Layer 2: SIMD Data Layout

CKKS supports **SIMD (Single Instruction, Multiple Data)** batching: a single ciphertext contains up to N/2 independent "slots," where N is the polynomial ring dimension. With N = 2^16 = 65,536, each ciphertext holds 32,768 slots.

We use **column-major packing**: for a dataset of names, each ciphertext holds one character position across all names. Specifically:

- `datasetColumns[pos][batch]` is a plaintext whose slot `j` holds the encoded character at position `pos` of name `(batch * batchSize + j)`.

For L character positions and B batches, the server holds L × B plaintexts. The client encrypts L ciphertexts (one per character position of the query, with the query value replicated across all slots).

This layout means that a single ciphertext-plaintext subtraction computes the per-character difference for all 32,768 names in a batch simultaneously, which is the key to making large datasets tractable.

### 4.1 Multi-Batch Handling

A single CKKS ciphertext at ring dimension N = 2^16 holds 32,768 SIMD slots. For datasets larger than 32,768 names, the system automatically splits the dataset into ceil(N_names / 32768) batches. The homomorphic circuit runs independently on each batch, and the per-batch aggregate scores are summed (a single ciphertext addition per extra batch). Nothing in the layout itself limits the batch count, so a 100K-name dataset simply uses 4 batches. The aggregate those batches feed does have limits, and §5.4 describes them: the indicator is summed over every name, so its residue grows with the dataset, and the sum carries counts below 512.

## 5. Layer 3: Homomorphic Comparison Circuit

### 5.1 Why Not the BFV Equality Polynomial

The standard approach for exact equality testing in BFV is the Fermat-style polynomial:

```
eq(x) = 1 − x^(p-1) mod p
```

or the product polynomial:

```
eq(x) = ∏_{k=1}^{M} (x² − k²) / f(0)
```

These rely on exact modular arithmetic: the polynomial evaluates to exactly 0 or exactly 1 in Z_p. In CKKS, arithmetic is approximate — every operation introduces a small noise term. For the product polynomial with M = 26, intermediate products reach magnitudes of approximately 10^14, which completely drowns the CKKS noise floor (approximately 10^-7). The near-zero value that should signal a match becomes indistinguishable from accumulated noise. This is a fundamental incompatibility, not a tuning issue.

### 5.2 Squared Euclidean Distance

Instead of testing equality character-by-character, we compute the **squared Euclidean distance** between the encoded query vector and each dataset name vector:

```
S_j = Σ_{i=0}^{L-1} (query[i] − dataset[j][i])²
```

where the sum runs over all L character positions and j indexes names (SIMD slots).

If the query matches name j, then every character difference is zero, so S_j = 0. If they differ in even one position, S_j ≥ 1 (since character codes are integers). The minimum nonzero distance is 1 (one character off by one position).

This choice of distance function is not conventional for string matching — edit distance is the usual metric. But squared Euclidean distance has a critical advantage in CKKS: it requires only one level of multiplicative depth (one ciphertext × ciphertext multiplication for the squaring, plus additions which are free). Edit distance, by contrast, requires min operations and data-dependent branching that have no efficient CKKS realization.

The tradeoff is that squared Euclidean distance is not robust to insertions or deletions — "SMITH" and "SMITH " (with a trailing space) would have distance 0 after stripping, but "SMTH" (missing the I) would not match "SMITH" in exact mode. This is why we pair it with Soundex for fuzzy matching: Soundex absorbs the phonetic variations, and the distance computation handles the rest as an exact comparison on short codes.

### 5.3 Iterated-Squaring Indicator

After computing the normalized distance s_j = S_j / C (where C = MAX_CHAR_VAL² × L is the maximum possible squared distance), we need to map:

- s_j = 0 (match) → output ≈ 1
- s_j > 0 (non-match) → output ≈ 0

We compute:

```
t_j = (1 − s_j)^{2^K}
```

through K rounds of iterated squaring (t ← t × t). This works because:

- For a match: s_j = 0, so t_j = 1^{2^K} = 1. The value is exactly preserved.
- For the closest non-match: s_j = 1/C, so t_j = (1 − 1/C)^{2^K}. By choosing K large enough, this decays exponentially toward 0.

The required K is determined by the constraint:

```
(1 − 1/C)^{2^K} < ε
```

Using the approximation (1 − 1/C) ≈ exp(−1/C):

```
2^K > C · ln(1/ε)
K > log₂(C · ln(1/ε))
```

With ε = 0.01 (comfortable margin below the 0.5 threshold):

| Mode    | L  | C      | K  | Depth (2+K) | Worst non-match indicator |
|---------|----|--------|----|-------------|---------------------------|
| Soundex | 4  | 2,704  | 14 | 16          | 0.0023                    |
| Exact   | 20 | 13,520 | 16 | 18          | 0.0079                    |

In both cases, the worst-case non-match indicator is well below 0.5, giving clear separation from the match value of ≈ 1.0.

Those bounds are per name. The aggregate sums the indicator over every name in the dataset, so what reaches the threshold is the sum of N non-match contributions, not a single one. The bound is loose enough that exact mode is unaffected: at 1,048,576 names the measured total residue is 0.0079, which is the per-name bound spread across the whole list rather than multiplied by it.

Soundex is where this binds. A 4-character code space leaves many names one digit from the query, and those near misses contribute far more than distant ones, so the sum grows with the number of nearby codes. Measured on the committed lists, a true match count of 1 reads 2.56 at 65,536 names and the aggregate wraps above 512, which is why Soundex mode is limited to the toy tier.

### 5.4 Full Circuit Summary

For each SIMD batch:

| Step | Operation | Depth cost |
|------|-----------|------------|
| 1 | diff_i = query[i] − dataset[j][i] (per position) | 0 (subtraction) |
| 2 | S = Σ_i diff_i² | 1 (one ct × ct multiply) |
| 3 | s = S / C | 1 (ct × scalar multiply) |
| 4 | t = 1 − s | 0 (subtraction) |
| 5 | t = t^{2^K} via K squarings | K |
| 6 | sum = Σ_j t_j via rotate-and-sum | 0 (rotations + additions) |

Total multiplicative depth: **2 + K**.

After processing all batches, the per-batch sums are added together (one ciphertext addition per extra batch, no additional depth).

The aggregate is a plaintext-domain count, and the encoding carries values below 512. A count at or above that wraps into the negative half of the range, so a dataset holding more than 512 identical entries reports a wrong total. The committed datasets are deduplicated under exact identity, so exact mode never approaches the limit.

## 6. Layer 4: Protocol Flow

The protocol splits a two-party computation across five binaries, which pass files
through `io/`. The calls below are the library API each one drives:

**Client side:**
1. Construct `FHEStringMatcher` with desired mode.
2. Call `generateKeys()` to create the CKKS crypto context, key pair, and rotation keys.
3. Call `encryptQuery(name)` to produce L ciphertexts (one per character position), each with the query's character value replicated across all SIMD slots.
4. Send the encrypted query and the evaluation keys to the server. The public key stays with the client stages, which are the only ones that encrypt.

**Server side:**
1. Call `encodeDataset(names)` to build column-major plaintext arrays from the name list.
2. Call `evaluate(encryptedQuery)` to run the homomorphic circuit and produce a single result ciphertext.
3. Return the result ciphertext to the client.

**Client side (continued):**
4. Call `decryptResult(encryptedResult)` to decrypt, read slot 0, and threshold at 0.5.
5. If the score exceeds 0.5, at least one name matched.

### 6.1 Privacy Guarantees

- The client's query is encrypted under CKKS — the server processes it homomorphically and never sees the plaintext name.
- The server's dataset remains in plaintext on the server side (encoded into CKKS plaintexts but never encrypted). The client receives only the aggregate match score (approximately equal to the number of matching names), not individual dataset entries.
- For boolean output, the client thresholds at 0.5 and learns only "match" or "no match."

## 7. CKKS Parameter Selection

### 7.1 Ring Dimension

We use N = 2^16 = 65,536, which provides 128-bit security under the HEStd_128_classic standard. This gives 32,768 SIMD slots per ciphertext.

We considered N = 2^15 (which would halve memory and speed up operations), but at depth 18 (exact mode) with SCALING_MOD_SIZE = 50 bits per level, the total modulus chain is approximately 60 + 18 × 50 = 960 bits. The CKKS security estimator requires a ring dimension large enough to maintain 128-bit security for a modulus of this size. At N = 2^15, the achievable security level drops below 128 bits for a ~960-bit modulus. OpenFHE enforces this automatically — if you set HEStd_128_classic with depth 18 and N = 2^15, it will promote to N = 2^16 anyway.

### 7.2 Scaling Parameters

- **FIRST_MOD_SIZE = 60 bits**: The first (largest) modulus in the RNS chain, providing headroom for the initial encryption.
- **SCALING_MOD_SIZE = 50 bits**: Each subsequent level uses a 50-bit scaling factor, giving approximately 15 decimal digits of precision per level. This is comfortably above the precision needed for our circuit, where the critical values are integers and small rationals.
- **Scaling technique: FLEXIBLEAUTO**: OpenFHE's automatic rescaling mode, which inserts rescale operations as needed to keep ciphertext levels aligned.

### 7.3 Depth Budget

The multiplicative depth budget is 2 + K, where K depends on the matching mode. The constructor computes K automatically from the formula K = ceil(log₂(C × ln(1/ε))) with ε = 0.01, clamped to [4, 25].

## 8. Performance Characteristics

Soundex mode is faster than exact mode because it operates on 4-character vectors (vs. 20 for exact mode) and requires fewer iterated-squaring rounds (K=14 vs. K=16), resulting in a shallower circuit and fewer ciphertext multiplications.

Key generation dominates a single run: the evaluation keys are sized by the ring dimension, so they cost the same at every instance size. Dataset encoding, query encryption and decryption are small beside it.

For larger datasets, evaluation time scales linearly with the number of batches: a 100K-name dataset would use ~4 batches and take roughly 4× the single-batch evaluation time.

## 9. Threat Model and Security Analysis

### 9.1 Adversary Model

The system assumes an **honest-but-curious (semi-honest)** adversary: both client and server follow the protocol correctly, but each attempts to learn as much as possible about the other party's private input from the messages exchanged during protocol execution.

The two assets under protection are the client's query name and the server's dataset of names. The intended output — a Boolean match/no-match result — is deliberately revealed to the client. Everything else should remain private to its owner.

### 9.2 Client Query Confidentiality

The client's query is encrypted under CKKS with parameters targeting 128-bit classical security (HEStd_128_classic, ring dimension N = 2^16). Key switching is HYBRID, so the modulus the security estimate applies to is the ciphertext chain together with the auxiliary one: 1,380 bits in exact mode (960 over 19 moduli plus 420 over 7) and 1,220 in soundex (860 over 17 plus 360 over 6). The server receives only ciphertexts and performs all computation homomorphically, never decrypting at any point.

**Security reduction:** Under the Ring Learning With Errors (RLWE) assumption with the stated parameters, the server gains no information about the query beyond what is computable from the protocol output. This is the standard semantic security guarantee of the CKKS scheme.

The server does not hold the secret key and has no mechanism to decrypt the query ciphertexts or any intermediate ciphertexts produced during evaluation.

This is enforced, not assumed. `matcher_keygen --server-keydir` writes the evaluation keys to the server's directory and leaves the secret key in the client's, so the two halves are never in the same place and neither is a copy of the other. The client stages encrypt and decrypt but never evaluate, so they read no evaluation key material at all.

`matcher_compute_sdk` exits 2 with `SERVER ABORT` if it finds `sk.bin` in the directory it was given, and the harness exercises that path on every run by planting the secret key, requiring the refusal, and removing it again.

### 9.3 Server Dataset Confidentiality

The server's dataset is encoded as CKKS plaintexts (never encrypted) and combined with the client's ciphertexts during homomorphic evaluation. The client receives only the final aggregate score — a single real number approximating the count of matching names. The reference client thresholds that score to a Boolean, though the value it decrypts is the count itself; §9.4 covers what that discloses.

However, the dataset is not protected by a cryptographic assumption in the same way the query is. Its confidentiality relies on the structure of the protocol output:

- The client sees only Σ_j t_j (the sum of all per-name indicators), not individual t_j values. There is no mechanism within the protocol for the client to decompose this sum into per-name scores.
- The rotate-and-sum aggregation (step 6 of the circuit) collapses the SIMD vector into a single scalar before the client decrypts, so individual slot values are destroyed.

### 9.4 Information Leakage

**Intentional leakage (the protocol output):**

- The Boolean match/no-match result. This is the defined output of the protocol.

**Incidental leakage to the client:**

- **Approximate dataset size.** The number of CKKS batches is observable from the protocol structure (the number of ciphertext additions in the aggregation step). Each batch holds up to 32,768 names, so the client can infer the dataset size to within that granularity. Mitigation: pad the dataset with dummy names (zero-encoded padding slots already cannot false-match, so padding is safe).
- **Timing.** Evaluation time is proportional to the number of batches. This leaks approximate dataset size to a timing observer. Mitigation: pad to a fixed number of batches regardless of actual dataset size.
- **Raw aggregate score.** If the raw score is exposed (rather than just the Boolean), the client could potentially infer the number of matching names (each contributes ≈ 1.0 to the sum). In the current implementation, the raw score is printed for diagnostic purposes but the API returns only the Boolean. In a production deployment, the raw score should not be revealed to the client.

**Incidental leakage to the server:**

- The server learns that a query was made (metadata), but nothing about its content.
- The timing of the client's encryption step is constant regardless of the query, so no information leaks through timing.

### 9.5 Threats NOT Addressed

**Malicious adversaries.** If either party deviates from the protocol, the security guarantees do not hold. A malicious server could craft specially chosen plaintexts (e.g., identity matrices in specific slot positions) to extract individual bits of the encrypted query through the aggregate result. Defending against this would require verifiable computation or zero-knowledge proofs layered on top of the FHE protocol, which is beyond the current scope.

**Side-channel attacks.** The implementation does not defend against timing side channels, power analysis, cache attacks, or other physical/microarchitectural side channels on either party's machine.

**Soundex preprocessing.** In Soundex mode, the client computes the phonetic hash in plaintext before encryption. If an attacker can observe the client's machine (e.g., through a compromised OS or physical access), the query is visible in the clear before it enters the FHE pipeline. This is inherent to the architecture — Soundex is a client-side preprocessing step, not an encrypted operation.

**Exhaustive query attacks.** An adversary with the ability to submit many queries can probe the dataset by testing names one at a time and observing the output, which carries a count rather than only a Boolean. Over enough queries, the dataset could be partially or fully reconstructed. Mitigation would require application-level controls: query rate limiting, query budgets, or audit logging. These are outside the scope of the cryptographic protocol.

**Collusion.** If client and server collude, all privacy is trivially lost. The protocol is designed for two mutually distrustful parties.

**Outsourced evaluation.** The model above has exactly two parties, and it assumes the server evaluates the circuit itself. If the server instead offloads evaluation to a remote accelerator, that accelerator receives the same inputs the server would hold locally: the query ciphertexts, the evaluation keys, and the dataset plaintexts of §9.3. Query confidentiality is unaffected, since the secret key never leaves the client and the accelerator only ever handles ciphertext for the query and the result. Dataset confidentiality against the *client* is likewise unaffected. What changes is that the server's dataset is disclosed to the accelerator operator, so offloading extends the server's own trust boundary rather than preserving it. Treat a remote evaluator as part of the server for the purposes of this analysis, and choose one accordingly. See NIOBIUM_INTEGRATION.md for the offloaded path this repository ships.

### 9.6 Security Summary

| Property | Guarantee | Assumption |
|----------|-----------|------------|
| Query confidentiality (vs. server) | Semantic security | RLWE hardness, 128-bit classical |
| Dataset confidentiality (vs. client) | Output-only leakage | Honest-but-curious client |
| Match result | Revealed to client | Intentional |
| Dataset size | Approximate leakage (batch count) | Mitigable with padding |
| Query existence | Revealed to server (metadata) | Inherent |

## 10. File Map

| File | Role |
|------|------|
| `src/phonetic.h` | Soundex hashing, character encoding, `encodeName()` |
| `src/fhe_string_matcher.h` | `FHEStringMatcher` class declaration, architecture documentation |
| `src/fhe_string_matcher.cpp` | CKKS key generation, dataset encoding, homomorphic evaluation, decryption |
| `src/matcher_keygen.cpp` | Generate CKKS crypto context and keys |
| `src/matcher_encode_dataset.cpp` | Encode the candidate name set into CKKS plaintext columns |
| `src/matcher_encrypt_query.cpp` | Encrypt the query name |
| `src/matcher_compute_sdk.cpp` | Run the FHE matching kernel |
| `src/matcher_decrypt_result.cpp` | Decrypt and report matches |
| `tests/test_phonetic.cpp` | Unit tests for the encoding and Soundex hashing |
| `datasets/sample_names.txt` | Example dataset (188 names) |
