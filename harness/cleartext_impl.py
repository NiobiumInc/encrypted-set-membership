#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
cleartext_impl.py — plaintext reference for set-membership.

The SAME algorithm the FHE circuit computes, but in the clear: no encryption, no
CKKS, no Niobium. Read this first to understand what the encrypted server does on
your behalf — then run the FHE pipeline (harness/run_submission.py) and watch the
SAME score come out of ciphertexts, except the server never sees your query or
its own dataset in the clear.

Each step maps to a stage of the FHE circuit in src/fhe_string_matcher.cpp:

  1. encode    name -> fixed-length integer vector      (matcher_encode_dataset / _encrypt_query)
  2. distance  squared Euclidean distance query vs name  (EvalSub -> EvalMult -> EvalAdd)
  3. indicator distance == 0  ? 1 : 0                     (normalise -> complement -> K iterated squarings)
  4. aggregate sum the indicators over the dataset        (evalSumSlots -> cross-batch add)

The aggregate is the match count: ~1.0 = one match, ~2.0 = two (e.g. a soundex
collision), ~0.0 = not in the set. Here the scores are exact integers; the FHE
version lands near them because CKKS is approximate.

    python3 harness/cleartext_impl.py 0                       # default member, exact mode
    python3 harness/cleartext_impl.py 0 --mode soundex        # phonetic matching
    python3 harness/cleartext_impl.py 0 --query "Ada Lovelace"  # search your own name
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from params import InstanceParams, instance_name, TOY, LARGE

ROOT = Path(__file__).resolve().parent.parent

# ── Encoding: a line-for-line port of src/phonetic.h ─────────────────────
EXACT_MAX_LEN = 20        # max encoded name length (exact mode)
SOUNDEX_LEN = 4           # Soundex codes are always 4 chars
_SOUNDEX = {**dict.fromkeys("BFPV", "1"), **dict.fromkeys("CGJKQSXZ", "2"),
            **dict.fromkeys("DT", "3"), "L": "4", **dict.fromkeys("MN", "5"), "R": "6"}


def letters_only(s: str) -> str:
    return "".join(c for c in s if c.isalpha() and c.isascii())


def soundex(name: str) -> str:
    """Standard Soundex: uppercase letter + 3 digits (e.g. 'Robert' -> 'R163')."""
    alpha = letters_only(name)
    if not alpha:
        return "A000"
    result = alpha[0].upper()
    prev = _SOUNDEX.get(alpha[0].upper(), "0")
    for c in alpha[1:]:
        if len(result) >= 4:
            break
        code = _SOUNDEX.get(c.upper(), "0")
        if code != "0" and code != prev:
            result += code
        prev = code
    return (result + "000")[:4]


def encode_char(c: str) -> int:
    """letters a-z/A-Z -> 1..26, digits 0-9 -> 0..9, everything else -> 0."""
    if "a" <= c <= "z":
        return ord(c) - ord("a") + 1
    if "A" <= c <= "Z":
        return ord(c) - ord("A") + 1
    if "0" <= c <= "9":
        return ord(c) - ord("0")
    return 0


def encode_name(name: str, mode: str) -> tuple:
    """name -> fixed-length integer vector (padded with zeros)."""
    if mode == "exact":
        processed, length = letters_only(name).lower(), EXACT_MAX_LEN
    else:
        processed, length = soundex(name), SOUNDEX_LEN
    vec = [0] * length
    for i, c in enumerate(processed[:length]):
        vec[i] = encode_char(c)
    return tuple(vec)


def sq_dist(a: tuple, b: tuple) -> int:
    return sum((x - y) ** 2 for x, y in zip(a, b))


# ── The workload, in the clear ───────────────────────────────────────────
def run(query: str, dataset: list, mode: str):
    """Returns (aggregate_score, list of (line_no, name) matches)."""
    q = encode_name(query, mode)
    # indicator = (squared distance == 0); aggregate = sum over the dataset.
    matches = [(i + 1, name) for i, name in enumerate(dataset)
               if encode_name(name, mode) == q]
    return float(len(matches)), q, matches


def main() -> int:
    p = argparse.ArgumentParser(description="Plaintext reference for set-membership.")
    p.add_argument("size", type=int, choices=range(TOY, LARGE + 1),
                   help="Instance size (0=toy, 1=small, 2=medium, 3=large)")
    p.add_argument("--mode", choices=["exact", "soundex"], default="exact",
                   help="Match mode (default exact; soundex is supported at the "
                        "toy tier only).")
    p.add_argument("--query", help="Name to search (default: the first dataset entry, a member)")
    args = p.parse_args()

    params = InstanceParams(args.size, ROOT)
    dataset = [ln.strip() for ln in params.dataset().read_text().splitlines() if ln.strip()]
    if args.mode == "soundex" and args.size != TOY:
        sys.exit("error: --mode soundex is supported at the toy tier (size 0) "
                 "only; use --mode exact at larger sizes.")
    if args.query is not None and not re.search(r"[A-Za-z]", args.query):
        sys.exit(f"error: --query {args.query!r} has no letters to encode.")
    query = args.query if args.query is not None else dataset[0]

    score, q_vec, matches = run(query, dataset, args.mode)

    print(f"\n=== plaintext set-membership ({instance_name(args.size)}, mode={args.mode}) ===")
    print(f"dataset      : {len(dataset)} names ({params.dataset().name})")
    print(f"query        : {query!r}")
    print(f"1. encode    : {list(q_vec)}")
    if matches:
        # Show one match with its distance (== 0) as the worked example.
        ln, name = matches[0]
        print(f"2. distance  : sq_dist(query, {name!r}) = "
              f"{sq_dist(q_vec, encode_name(name, args.mode))}  (0 => identical encoding)")
        shown = ", ".join(f"line {ln}: {name!r}" for ln, name in matches[:5])
        more = "" if len(matches) <= 5 else f" (+{len(matches) - 5} more)"
        print(f"3. indicator : {len(matches)} name(s) with distance 0 -> {shown}{more}")
    else:
        print(f"2. distance  : no dataset entry has distance 0 to the query")
        print(f"3. indicator : 0 matches")
    print(f"4. aggregate : score = {score}  (the match count)")
    verdict = "MATCH" if score > 0.5 else "NO MATCH"
    print(f"\nVERDICT: {verdict}  (score {score} vs 0.5 threshold)")
    print("\nThe FHE pipeline computes this SAME score on encrypted data — the server\n"
          f"never sees {query!r} or the dataset. Try it:\n"
          f"    python3 harness/run_submission.py {args.size} --mode {args.mode}"
          + (f" --query {query!r}" if args.query is not None else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())