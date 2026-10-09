# Set-membership over the niobium-client FHETCH transport

This document describes how `set-membership` runs its server-side
homomorphic evaluation **over the niobium-client FHETCH transport**, the
client-over-HTTP path for shipping a recorded trace to a remote backend. The server's
`replay()` is shipped over HTTP to a `nbcc_fhetch_replay_server`, which `--exec`s
a Niobium replay backend (the released SDK) and returns the result ciphertext.

## What the backend receives

Offloading sends the recorded project to the backend. That project carries the
query ciphertexts, the evaluation keys, and the dataset plaintexts, which is the
same material the server holds when it evaluates locally.

The secret key stays on the client. Only the client stages read `sk.bin`, and the
compute stage runs against a key directory holding `cc.bin`, `mk.bin` and `rk.bin`.

So the query and the result stay confidential from the backend, and only the client
can open the score.

The project also names the client that produced it, as a `producer` block in
`fhetch_replay.json` giving the niobium-client and niobium-fhetch versions. The
compiler reads it to refuse a bundle from a client it no longer supports, and it
describes the build rather than the query or the dataset.

The dataset is a different matter. `docs/DESIGN.md` §9.3 encodes it as CKKS
plaintext rather than ciphertext, which keeps the circuit cheap but discloses it to
whoever operates the backend.

Running remotely extends the server's trust boundary to include that operator, so
treat a remote evaluator as part of the server; `docs/DESIGN.md` §9.5 sets that
against the two-party model.

## How this stage drives niobium-fhetch

`matcher_compute_sdk.cpp` is the only compute stage. It runs
`FHEStringMatcher::evaluate` (squared distance → normalise → complement →
K iterated squarings → slot-sum → cross-batch accumulate) through the
**explicit** niobium-fhetch API, modeled on niobium-client
`examples/mult/server.cpp`. Where a plain compiler application would reach for
the convenience wrappers, this stage does the following instead:

| plain compiler app | this SDK stage (`matcher_compute_sdk`) |
|--------------------------------------|-----------------------------|
| `cached_key(mk.bin, EvalMult)` + `cached_key(rk.bin, EvalAutomorphism)` | `tag_keys(cc)` iterates the keys already loaded in the context |
| `global_key_cache(...)` | dropped. `tag_keys(cc)` registers the evaluation keys from the context already loaded, and they travel with the request |
| `niobium_hw(bool)` / `--niobium_hw` | dropped. The replay `--target` selects the backend (e.g. `FOG`) |
| `if (!cache_valid) {record} else {replay}` | record once on a cache miss, then **always replay** |

`matcher_compute_sdk` records the trace once on a cache miss, with the FHE math
skipped, and then **always replays** to produce the result, so the backend is the
only source of the answer.

Ordering: `capture_crypto_context(cc)` → `tag_input(query_pos_i)` → `tag_keys(cc)`
→ (`start` → `evaluate` → `probe` → `stop`) on a cache miss, then `replay()` +
`result()` on every run. The dataset and constant plaintexts are tagged **inline by
`evaluate()`** via the `pause`/`tag_input`/`resume` idiom.

That code is shared, so the SDK target compiles `fhe_string_matcher.cpp` with the
niobium-fhetch include path first, where its `niobium::compiler()` also resolves to
the SDK.

## Building

`scripts/build_task.sh` builds it the way a customer does: the `niobium-client`
submodule builds its OWN bundled OpenFHE + `libnbfhetch` + the transport
server/forwarder, and the matcher stages build against that (`-DNIOBIUM_SDK_BUILD=ON`).

```bash
git submodule update --init niobium-client
scripts/build_task.sh            # heavy the first time (compiles OpenFHE once)
```

Outputs the five stage binaries and the phonetic unit test in `build/`, plus the transport **server**
(`nbcc_fhetch_replay_server`) and **forwarder** (`nbcc_fhetch_replay`) under
`niobium-client/build/src/fhetch_transport/`, and `libnbfhetch` under
`niobium-client/build/{vendor/niobium-fhetch,_deps/niobium-fhetch-build}`.

## Running it

A single pass records the trace if there is no cache, then replays it on the
backend `--target` names. `--target FOG` takes out a Fog job for the compute
stage and replays there:

```bash
niobium-client/scripts/fog login -u you@example.com   # once
python3 harness/run_submission.py 0 --mode exact --target FOG
```

Success: the forwarder logs `POSTing … bytes → /replay`, the server logs
`unpacked N files`, and the member query decrypts to a score `> 0.5` for a
**MATCH**. Search a name of your own with `--query "Some Name"`.

Setting `NBCC_FHETCH_SERVER` sends the replay to a server you run instead, which
is how to drive a backend of your own or reproduce a Fog run locally:

```bash
SDK=$HOME/niobium-sdk                    # your released SDK
export PATH="$SDK/bin:$PATH" LD_LIBRARY_PATH="$SDK/lib" \
       NIOBIUM_SPEC_DIR="$SDK/share/niobium/devices" ARAL_ROOT="${ARAL_ROOT:-/opt/niobium}"
SERVER=niobium-client/build/src/fhetch_transport/nbcc_fhetch_replay_server
"$SERVER" --port 9443 --bind 127.0.0.1 --exec "$SDK/bin/nbcc_fhetch_replay" &
until curl -sf http://127.0.0.1:9443/healthz >/dev/null 2>&1; do sleep 1; done

NBCC_FHETCH_SERVER=http://127.0.0.1:9443 \
  python3 harness/run_submission.py 0 --mode exact --target FOG
```

## `--opt-level O3` is mandatory for FPGA

The transport sends the opt level as a header and the server defaults to O0 when
it is omitted. A trace this size does not run on an FPGA target at O0, so the
harness passes `--opt-level O3` on every run, which is its default.

**Version note:** opt-level reaches the backend only on a niobium-fhetch that
forwards it (the released dist SDK does); an old pin leaves the flag unforwarded
and the backend replays at its own default.

## Host RAM is the limit, ahead of the transport

Both the forwarder and the server buffer the whole request body in RAM, and
simulator replay is memory-hungry. Validate the small, medium and large tiers on a
big-RAM host.

The `toy` tier (188 names, one batch) has a small payload and is the right first
end-to-end check.