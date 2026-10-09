# Encrypted Set-Membership

Check whether a name appears on a list without either side revealing what it holds.

This demo answers one question under fully homomorphic encryption: is this name in
that dataset? The client encrypts a name, the server compares it against every entry
in its own private list on ciphertext it cannot read, and only the client can decrypt
the score that comes back.

Checking membership in a registry, deduplicating records across organizations, and
reconciling a roster between two parties all have this shape.

The server never sees the query, and only the client stages read the secret key. The
dataset sits with the server as plaintext, so evaluating it on a remote accelerator
discloses it to that operator; [docs/DESIGN.md](docs/DESIGN.md) §9 has the threat
model.

Built on [OpenFHE](https://github.com/openfheorg/openfhe-development) with CKKS. The
encrypted compute runs on the Niobium Fog, a hosted jobs-as-a-service path that
replays a recorded computation on a Niobium FPGA over TLS.

Every run recomputes the answer in the clear for that same query and checks the
decrypted score against it. A sample run is shown below.

## Run it

Prerequisites: a C++17 compiler (Clang 14+ or GCC 11+), CMake 3.16+, OpenMP, Python
3, and a few GB of disk for the keys and traces a run generates.

The Fog path needs an account, and access is gated. Request one at
<https://console.niobium.co/request-account> before the Fog command below.

```bash
# one-time setup: builds OpenFHE, libnbfhetch, the five stages and the unit test
git submodule update --init niobium-client
scripts/build_task.sh

# authenticate once, then run on a real FPGA over the Fog
niobium-client/scripts/fog login -u you@example.com
python3 harness/run_submission.py 0 --target FOG

# the same run replayed in software, to check the hardware result against
python3 harness/run_submission.py 0
```

That leading `0` is the instance size. The four share binaries and CKKS
configuration, differing in how many names the server holds.

| Size | Dataset | Names | Batches |
|---|---|---|---|
| `0` toy | `sample_names.txt` | 188 | 1 |
| `1` small | `small_names.txt` | 65,536 | 2 |
| `2` medium | `medium_names.txt` | 131,072 | 4 |
| `3` large | `large_names.txt` | 1,048,576 | 32 |

A batch is one ciphertext of 32,768 slots, so the batch count drives the trace size
and the upload.

Pass `--query` to search a name of your own. The three larger sizes hold names of
living people from Wikipedia, so many real people are in there.

```bash
python3 harness/run_submission.py 3 --query "Margaret Atwood" --target FOG
python3 harness/run_submission.py 0 --query "Jaymz Smyth" --mode soundex
```

The second matches `James Smith` in the toy set, because soundex compares the phonetic
code rather than the spelling.

## What happened

Five binaries ran in order, all on your machine as separate processes passing files
through `io/`, so you can watch both sides at once. "Runs on" is the role each plays,
and only the client stages are given the secret key.

| Stage | Binary | Runs on | Produces |
|---|---|---|---|
| 1 | `matcher_keygen` | client | crypto context, public, secret, and evaluation keys |
| 2 | `matcher_encode_dataset` | server | the dataset packed into plaintext columns |
| 3 | `matcher_encrypt_query` | client | the encrypted query, one ciphertext per position |
| 4 | `matcher_compute_sdk` | server | the encrypted score |
| 5 | `matcher_decrypt_result` | client | MATCH or NO MATCH, exit code 0 or 1 |

The client and server stages read different key directories. Stage 1 writes each key
to the side that owns it, so the client keeps the context, the public key and the
secret key, while the server gets the context and the evaluation keys.

Nothing is copied or linked between them, and the client stages never read the
evaluation keys. Stage 4 refuses to start if it finds a secret key in its own key
directory, so the split is enforced rather than assumed.

Each binary describes its own arguments under `--help`, so a stage can be re-run by
hand.

Stage 4 is the one that uses Niobium: it records the circuit once, then replays it on
the backend `--target` chooses, a real FPGA over the Fog or the bundled software
simulator for validating a trace. That replay is the only part that leaves your
machine, sent as one Fog job carrying the recorded circuit, the evaluation keys and
the encrypted query.

```console
$ python3 harness/run_submission.py 0 --target FOG
[keys] Loaded from "io/toy/exact/keys" (ring dim=65536)
[encrypt] query="James Smith"  cts=20

[harness] === toy/exact/'James Smith' (target=FOG) ===
[harness] score=1.0 expected=1.0 (tol 0.05) post=1934912530B -> PASS

[harness] ===== summary =====
  PASS      toy     exact   score=1.0          'James Smith'
[harness] 1/1 completed OK
```

`expected` is the cleartext reference recomputed for that query, and `post` is the
size of the recorded program sent to the worker.

Names become fixed-length integer vectors, letters mapped to 1 through 26 with zero
padding. The circuit takes the squared Euclidean distance between the encrypted query
and each entry, then applies iterated squaring to amplify the gap.

A match scores about 1.0 and a non-match about 0.0; the client decrypts and holds it
against a 0.5 threshold.

The first run records the trace, compiles it, and generates the keys, so it prints
more than the one above. Later runs replay the compiled program, and switching
`--target` reuses the same recording.

The compute stage's output goes to the run log, so a Fog run is quiet while the
upload is in flight. A job also has a time limit, so on a slow link the transfer can
run out of it and the job ends without a result.

`niobium-client/scripts/fog list` shows what happened to each job and `fog get <id>`
the detail. Re-running repeats only the transfer.

## More information

- [docs/DESIGN.md](docs/DESIGN.md): the distance function, the depth budget, and the
  threat model in full.
- [NIOBIUM_INTEGRATION.md](NIOBIUM_INTEGRATION.md): the record and replay model, the
  backends, and the transport.
- [Understanding the algorithm](#understanding-the-algorithm): the cleartext
  reference every run is checked against.
- [Match modes and sizes](#match-modes-and-sizes): `exact` and `soundex`.
- [Datasets](#datasets): what ships, and how it was built.
- [Security and parameters](#security-and-parameters): the CKKS configuration.
- [What the build produces](#what-the-build-produces): where the disk goes.
- [Repository layout](#repository-layout): where the code lives.

### Understanding the algorithm

`harness/cleartext_impl.py` computes the same aggregate in the clear. It prints the
encoding, the per-name distances, the indicator and the final score, so you can read
what the encrypted server does on your behalf.

```bash
python3 harness/cleartext_impl.py 0                            # default member, exact mode
python3 harness/cleartext_impl.py 3 --query "Margaret Atwood"  # the query the Fog run above used
```

The harness calls it on every run for the query you asked for and checks the
decrypted score against it. A freshly computed reference catches drift that a tuned
score window would let through.

### Match modes and sizes

`exact` is case-insensitive and compares the full name, up to 20 letters after
stripping non-letter characters. `soundex` hashes phonetically first, so "Robert" and
"Robbrt" both become `R163` and match.

Run one mode at a time with `--mode exact | soundex`, defaulting to `exact`. Soundex is
supported at the toy tier only, and asking for it at a larger size is rejected.

A soundex code is four characters, so above the toy tier the code space collides
heavily. The aggregate then picks up residue from near-miss codes, which leaves the
match count unrecoverable and narrows the margin under the match threshold.

Exact mode compares the name as written, and accented letters are dropped before the
comparison. Search with the name as it appears, rather than an ASCII spelling of it.

Comparison uses the first 20 letters, so two names that agree that far are
indistinguishable to it.

The score is a match count, and the aggregate carries counts below 512. A list holding
more than 512 copies of one name wraps into the negative half of that range, so the
score falls under the match threshold and the name is reported as absent.


### Datasets

All four datasets ship checked in; the sizes table above gives the name counts. The
toy list is a small hand-picked sample, and the other three are frozen, collision-free
snapshots of names from Wikipedia, recorded in [datasets/SOURCES.md](datasets/SOURCES.md).

`scripts/fetch_notable_people.py` deduplicates on the matcher's exact-mode identity,
so the committed datasets are clean under `exact`. Soundex codes still collide in those
lists, which is why soundex is limited to the toy tier.


### Security and parameters

The scheme is CKKS approximate arithmetic in OpenFHE at ring dimension 2^16, with a
128-bit classical security level (`HEStd_128_classic`).

Multiplicative depth is `2 + K`, where K is the iterated-squaring rounds: 16 for
exact and 14 for soundex, giving depth 18 and 16. Both fit a single level budget, and
the 50-bit scaling modulus sits comfortably above the values the circuit carries.

CKKS SIMD packing holds up to 32,768 names per ciphertext, and larger datasets split
across batches that aggregate cleanly.

The OpenFHE `CCParams`, from [src/fhe_string_matcher.cpp](src/fhe_string_matcher.cpp):

```cpp
CCParams<CryptoContextCKKSRNS> params;
params.SetMultiplicativeDepth(multDepth_);        // 2 + K: 18 exact, 16 soundex
params.SetScalingModSize(SCALING_MOD_SIZE);       // 50 bits per level
params.SetFirstModSize(FIRST_MOD_SIZE);           // 60 bits
params.SetSecurityLevel(HEStd_128_classic);
params.SetScalingTechnique(FLEXIBLEAUTO);
```

OpenFHE picks the ring dimension: the smallest that satisfies the security level for
this depth and modulus chain, which here is 2^16.

Decrypted scores match the cleartext reference to within CKKS approximation.
[docs/DESIGN.md](docs/DESIGN.md) has the distance-function rationale and the full
depth and security analysis, and
[NIOBIUM_INTEGRATION.md](NIOBIUM_INTEGRATION.md) the transport specifics.

### What the build produces

`scripts/build_task.sh` builds everything but the compiler and Python from the
`niobium-client` submodule, including its own OpenFHE.

That OpenFHE is Niobium's fork, vendored inside the submodule, carrying the hooks
recording a computation depends on.

Most of the disk a run uses is the evaluation keys under `io/` and the recorded trace
beside them, both sized by the ring dimension. Both regenerate on demand and are safe
to delete.

### Repository layout

```
.
├── README.md
├── NIOBIUM_INTEGRATION.md            # Niobium transport specifics
├── LICENSE.md                        # Apache-2.0
├── NOTICE                            # third-party attribution
├── CONTRIBUTING.md
├── requirements.txt                  # harness is stdlib-only
├── CMakeLists.txt
├── harness/
│   ├── cleartext_impl.py             # plaintext baseline, read this first
│   ├── run_submission.py             # primary entry point
│   ├── params.py                     # instance sizes and dataset paths
│   └── expected_scores.txt           # tuned toy score windows
├── scripts/
│   ├── build_task.sh                 # self-contained Niobium transport build
│   └── fetch_notable_people.py       # dataset fetch with collision-free dedup
├── src/
│   ├── phonetic.h                    # Soundex hashing and name encoding
│   ├── fhe_string_matcher.{h,cpp}    # encode, encrypt, evaluate, decrypt
│   ├── matcher_keygen.cpp            # stage 1
│   ├── matcher_encode_dataset.cpp    # stage 2
│   ├── matcher_encrypt_query.cpp     # stage 3
│   ├── matcher_compute_sdk.cpp       # stage 4
│   └── matcher_decrypt_result.cpp    # stage 5
├── datasets/                         # name lists, with SOURCES.md
├── io/                               # client/server files, created at runtime
├── tests/                            # phonetic unit test
├── docs/                             # DESIGN.md
└── niobium-client/                   # submodule: OpenFHE, libnbfhetch, transport
```

## Acknowledgements

The `small`, `medium` and `large` name lists are names from English Wikipedia
article titles, gathered as demonstration data. Wikipedia publishes them openly, and
they were retrieved through its public API, which serves anyone without an account.

Wikipedia's contributors license their work under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/), and those three lists
remain under that licence. Everything else here is Apache-2.0.

[datasets/SOURCES.md](datasets/SOURCES.md) records the categories, the selection rule
and the fetch provenance.
