#!/usr/bin/env bash
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
# build_task.sh — self-contained build: niobium-client
# builds its own OpenFHE + libnbfhetch, matcher stages build against that. Run
# from the repo root. See NIOBIUM_INTEGRATION.md.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== [1/3] sync niobium-client (its OpenFHE + niobium-fhetch + cpp-httplib) ==="
git submodule update --init niobium-client
git -C niobium-client submodule update --init --recursive

echo "=== [2/3] build the client's bundled OpenFHE + libnbfhetch + transport (make release) ==="
make -C niobium-client release        # installs OpenFHE to niobium-client/vendor/lib/openfhe

OPENFHE_PREFIX="$ROOT/niobium-client/vendor/lib/openfhe"
[[ -d "$OPENFHE_PREFIX" ]] || { echo "error: client OpenFHE not at $OPENFHE_PREFIX after 'make release'" >&2; exit 1; }

echo "=== [3/3] build matcher stages + SDK server against the client's OpenFHE ==="
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DNIOBIUM_SDK_BUILD=ON \
  -DCMAKE_PREFIX_PATH="$OPENFHE_PREFIX"
cmake --build build -j \
  --target matcher_keygen matcher_encode_dataset matcher_encrypt_query \
           matcher_decrypt_result matcher_compute_sdk test_phonetic

echo "=== done: binaries in $ROOT/build ==="
ls -la build/matcher_keygen build/matcher_encode_dataset build/matcher_encrypt_query \
       build/matcher_decrypt_result build/matcher_compute_sdk