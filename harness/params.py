# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
params.py — instance sizes, dataset paths, and shared score windows for the
set-membership submission harness. Size selects
the dataset (name count); ring dimension is fixed at 2^16.
"""
from pathlib import Path

# ── Instance size enum ──────────────────────────────────────────────────
TOY = 0
SMALL = 1
MEDIUM = 2
LARGE = 3

_NAMES = ["toy", "small", "medium", "large"]
# Name counts for the committed datasets. 32,768 names/batch, so the batch counts
# are toy 1, small 2, medium 4, large 32. run_submission.py derives the batch count
# from these to pick which recorded trace to drop when the keys are regenerated, so
# a count here that disagrees with the file on disk would drop the wrong directory.
_DB_SIZES = [188, 65_536, 131_072, 1_048_576]
_DATASETS = {
    TOY: "sample_names.txt",
    SMALL: "small_names.txt",
    MEDIUM: "medium_names.txt",
    LARGE: "large_names.txt",
}


def instance_name(size: int) -> str:
    if size < TOY or size > LARGE:
        return "unknown"
    return _NAMES[size]


class InstanceParams:
    """Per-size parameters and directory layout."""

    def __init__(self, size: int, rootdir=None):
        if size < TOY or size > LARGE:
            raise ValueError(f"Invalid instance size {size} (expected {TOY}..{LARGE})")
        self.size = size
        self.rootdir = Path(rootdir) if rootdir else Path.cwd()
        self.db_size = _DB_SIZES[size]

    @property
    def name(self) -> str:
        return instance_name(self.size)

    def dataset(self) -> Path:
        return self.rootdir / "datasets" / _DATASETS[self.size]

    def measuredir(self) -> Path:
        return self.rootdir / "measurements" / self.name


def load_expected_scores(rootdir: Path):
    """Parse harness/expected_scores.txt — the single source of truth for the
    tuned toy-dataset score windows. Returns a list of dicts
    {mode, query, description, min, max}. Used by harness/run_submission.py so
    the windows live in exactly one place.
    """
    path = Path(rootdir) / "harness" / "expected_scores.txt"
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 5:
            continue
        mode, query, desc, lo, hi = parts
        rows.append({"mode": mode, "query": query, "description": desc,
                     "min": float(lo), "max": float(hi)})
    return rows