#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""
Fetch notable people names from English Wikipedia.

Uses the MediaWiki API to pull page titles from well-populated
biographical categories. This avoids the Wikidata SPARQL endpoint,
which frequently times out on large queries.

Usage:
    python3 scripts/fetch_notable_people.py [--count N] [--output PATH]

Options:
    --count N       Number of names to fetch (default: 30000)
    --output PATH   Output file path (default: datasets/notable_people.txt)

Output:
    One name per line, written to the specified output file. The set is
    collision-free under the matcher's exact mode: titles are deduped on
    their exact-mode identity (see exact_identity), so distinct titles that
    encode to the same 20-char form are skipped (the fetch over-fetches to
    reach the requested count of distinct identities).

Sizes (names map to CKKS batch counts,
batchSize = ringDim/2 = 32768):
    toy    : datasets/sample_names.txt (188 names, 1 batch, ships with repo)
    small  : --count 65536   --output datasets/small_names.txt   (2 batches;
             committed as a frozen collision-free snapshot)
    medium : --count 131072  --output datasets/medium_names.txt  (4 batches;
             committed as a frozen collision-free snapshot)
    large  : --count 1048576 --output datasets/large_names.txt   (32 batches;
             committed as a frozen collision-free snapshot)
"""

import argparse
import json
import os
import random
import re
import sys
import time
import urllib.request
import urllib.parse

# Must match src/phonetic.h EXACT_MAX_LEN — the number of leading letters the
# matcher keeps in exact mode after lowercasing and stripping non-letters.
EXACT_MAX_LEN = 20


def strip_disambiguator(title):
    """Drop Wikipedia's trailing "(...)" qualifier, keeping only the name.

    Article titles carry a qualifier when several people share a name, e.g.
    "Aldair (footballer, born 1996)". Those qualifiers state occupation, birth
    year and sometimes religious office or criminal conviction, none of which
    this demo needs, so only the name itself is kept.
    """
    return re.sub(r"\s*\(.*\)\s*$", "", title).strip()


def exact_identity(title):
    """The matcher's exact-mode key: lettersOnly + lowercase, first 20 chars.

    Two titles with the same identity collide in exact mode (e.g. "Adriano
    (footballer, born 1981)" and "...1990)" both -> "adrianofootballerbor"),
    so we dedup on this to guarantee a collision-free exact-mode dataset.
    """
    return re.sub(r"[^A-Za-z]", "", title).lower()[:EXACT_MAX_LEN]

API_URL = "https://en.wikipedia.org/w/api.php"
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "datasets", "notable_people.txt")
DEFAULT_COUNT = 30000

# Large biographical categories on English Wikipedia.
# Each contains thousands of articles about individual people.
CATEGORIES = [
    "Living people",
]

# Subcategories to pull from if "Living people" alone isn't enough
# (it has 1M+ members, so it should be plenty).
BACKUP_CATEGORIES = [
    "20th-century American people",
    "21st-century American people",
    "British people",
    "French people",
    "German people",
]


def fetch_category_members(category, seen, target, cmtype="page"):
    """
    Fetch page titles from a Wikipedia category using the API.
    Returns a list of new (not previously seen) names.
    """
    names = []
    cmcontinue = None

    print(f"  Fetching from \"{category}\"...", file=sys.stderr)

    while len(names) < target:
        params = {
            "action": "query",
            "list": "categorymembers",
            "cmtitle": f"Category:{category}",
            "cmtype": cmtype,
            "cmlimit": "500",  # max per request
            "format": "json",
        }
        if cmcontinue:
            params["cmcontinue"] = cmcontinue

        url = f"{API_URL}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "encrypted-set-membership/1.0 "
                          "(https://github.com/NiobiumInc/encrypted-set-membership)",
        })

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            print(f"    Error: {e}, retrying in 5s...", file=sys.stderr)
            time.sleep(5)
            continue

        members = data.get("query", {}).get("categorymembers", [])
        for member in members:
            title = member["title"]
            # Skip non-article namespaces
            if ":" in title:
                continue
            # Skip disambiguation pages and list articles
            if title.endswith("(disambiguation)") or title.startswith("List of"):
                continue
            # Dedup on the exact-mode identity (not the raw title) so the
            # resulting set is collision-free under the matcher's exact mode.
            # Over-fetches as needed: distinct titles that collapse to the same
            # encoded form are skipped, so we keep pulling until `target` names
            # with *distinct* identities are collected.
            name = strip_disambiguator(title)
            key = exact_identity(name)
            if not key or key in seen:
                continue
            seen.add(key)
            names.append(name)
            if len(names) >= target:
                break

        # Check for continuation token
        cont = data.get("continue", {})
        cmcontinue = cont.get("cmcontinue")
        if not cmcontinue:
            break

        # Print progress every 5000 names
        if len(names) % 5000 < 500:
            print(f"    ... {len(names)} names so far", file=sys.stderr)

        # Be polite to Wikipedia's API
        time.sleep(0.2)

    print(f"    Got {len(names)} new names from \"{category}\"",
          file=sys.stderr)
    return names


def main():
    parser = argparse.ArgumentParser(description="Fetch notable people names from Wikipedia.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT,
                        help=f"Number of names to fetch (default: {DEFAULT_COUNT})")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT,
                        help=f"Output file path (default: {DEFAULT_OUTPUT})")
    args = parser.parse_args()

    target_count = args.count
    output_path = os.path.normpath(args.output)

    print(f"Fetching {target_count} names -> {output_path}", file=sys.stderr)

    all_names = []
    seen = set()

    for category in CATEGORIES:
        remaining = target_count - len(all_names)
        if remaining <= 0:
            break
        batch = fetch_category_members(category, seen, remaining)
        all_names.extend(batch)
        print(f"  Total so far: {len(all_names)}", file=sys.stderr)

    # Fall back to subcategories if needed
    if len(all_names) < target_count:
        for category in BACKUP_CATEGORIES:
            remaining = target_count - len(all_names)
            if remaining <= 0:
                break
            batch = fetch_category_members(category, seen, remaining)
            all_names.extend(batch)
            print(f"  Total so far: {len(all_names)}", file=sys.stderr)

    print(f"\nFetched {len(all_names)} unique names", file=sys.stderr)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for name in all_names:
            f.write(name + "\n")

    print(f"Wrote {len(all_names)} names to {output_path}", file=sys.stderr)

    sample = random.sample(all_names, min(20, len(all_names)))
    print(f"\n20 random names you can use for testing:", file=sys.stderr)
    for name in sample:
        print(f"  {name}", file=sys.stderr)


if __name__ == "__main__":
    main()
