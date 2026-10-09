#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
run_submission.py: drive the set-membership workload.

Single pass per query: (build) -> keygen -> encode -> encrypt -> compute -> decrypt
-> verify. Server-agnostic: matcher_compute_sdk records when there's no cache and
replays over the FHETCH transport iff NBCC_FHETCH_SERVER is set, so the caller runs
it once to record (no server), then again with a transport server up to replay. See
NIOBIUM_INTEGRATION.md for the full record → server → replay flow.

    python3 harness/run_submission.py 0 --mode exact             # record (no server)
    python3 harness/run_submission.py 0 --query "Ada Lovelace"   # search your own name
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from params import (InstanceParams, instance_name, load_expected_scores,
                    TOY, LARGE)
from cleartext_impl import run as cleartext_run

ROOT = Path(__file__).resolve().parent.parent            # repo root
BUILD = ROOT / "build"                                    # scripts/build_task.sh output
CLIENT = ROOT / "niobium-client"
FOG = CLIENT / "scripts" / "fog"                           # jobs-as-a-service CLI
MEMBER_WINDOW = (0.5, 1e9)                                # non-toy member: clears the 0.5 threshold
# Slack allowed between the decrypted score and the plaintext reference. The
# score is a match COUNT, so a genuinely wrong answer is off by a whole unit;
# this only has to absorb CKKS approximation error. Across the supported
# configurations - exact at every tier, soundex at toy - the largest measured
# deviation is 7.9e-3 (exact at large), so 0.05 leaves headroom and still
# separates N from N+-1.
CLEARTEXT_TOL = 0.05


def compute_binary() -> str:
    """The compute stage. Built by scripts/build_task.sh against the SDK."""
    return "matcher_compute_sdk"


def lib_env() -> dict:
    """Runtime env for the stage binaries: the client's OpenFHE and
    libnbfhetch. If a transport server is set, point NBCC_FHETCH_REPLAY at the
    client forwarder so replay() ships over HTTP."""
    env = os.environ.copy()
    libs = [CLIENT / "vendor" / "lib" / "openfhe" / "lib"]
    for d in (CLIENT / "build" / "vendor" / "niobium-fhetch",
              CLIENT / "build" / "_deps" / "niobium-fhetch-build"):
        if d.exists():
            libs.append(d)
    libp = os.pathsep.join(str(x) for x in libs)
    for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        env[var] = libp + (os.pathsep + env[var] if env.get(var) else "")
    if env.get("NBCC_FHETCH_SERVER") and not env.get("NBCC_FHETCH_REPLAY"):
        fwd = CLIENT / "build" / "src" / "fhetch_transport" / "nbcc_fhetch_replay"
        if fwd.exists():
            env["NBCC_FHETCH_REPLAY"] = str(fwd)
    return env


# The two halves of the key material. Stage 1 writes each file directly to the
# side that owns it, so neither is copied and neither is a link to the other.
SERVER_KEYS = ("cc.bin", "mk.bin", "rk.bin")
CLIENT_KEYS = ("cc.bin", "pk.bin", "sk.bin")


def check_keydirs(keydir: Path, srvkeydir: Path) -> None:
    """Verify the split stage 1 produced rather than assume it: the server holds
    the context and the evaluation keys, the client the context and its own two
    keys, and neither directory holds anything else."""
    for d, allowed in ((srvkeydir, SERVER_KEYS), (keydir, CLIENT_KEYS)):
        present = {f.name for f in d.iterdir()}
        missing = [n for n in allowed if n not in present]
        stray = sorted(present - set(allowed))
        if missing:
            raise RuntimeError(f"{d} is missing {', '.join(missing)}")
        if stray:
            raise RuntimeError(f"unexpected files in {d}: {', '.join(stray)}")


def check_secret_key_guard(srvkeydir: Path, keydir: Path, mode: str,
                           encdir: Path, querydir: Path, env: dict) -> None:
    """The server must refuse a key directory holding the secret key. Plant it,
    run the stage, require exit 2, then remove it. Tests the guard every run
    rather than trusting it. The full argument set is passed because the stage
    validates its arguments first; it stops at the guard, before reading any
    of these paths."""
    planted = srvkeydir / "sk.bin"
    shutil.copy(keydir / "sk.bin", planted)
    try:
        g = subprocess.run([str(BUILD / "matcher_compute_sdk"), "--mode", mode,
                            "--keydir", str(srvkeydir),
                            "--encoded-dataset", str(encdir),
                            "--query-dir", str(querydir),
                            "--result", str(srvkeydir / "guard_probe.ct")],
                           capture_output=True, text=True, env=env)
    finally:
        planted.unlink(missing_ok=True)
    if g.returncode != 2 or "SERVER ABORT" not in g.stderr:
        raise RuntimeError("the compute stage ran with the secret key in its key "
                           f"directory (exit {g.returncode})")


def default_member(size: int, mode: str, params: InstanceParams):
    """The representative member query for a (size, mode) + its expected score window.
    Toy uses the first tuned MATCH row (harness/expected_scores.txt); other tiers use
    the dataset head."""
    if size == TOY:
        for r in load_expected_scores(ROOT):
            if r["mode"] == mode and r["min"] >= 0.5:
                return (r["query"], r["min"], r["max"])
        raise RuntimeError(f"no MATCH row for mode={mode} in expected_scores.txt")
    head = params.dataset().read_text().splitlines()[0].strip()
    return (head, *MEMBER_WINDOW)


def parse_output(text: str) -> dict:
    out = {}
    scores = re.findall(r"raw aggregate score\s*=\s*([-\d.eE+]+)", text)
    if scores:
        out["score"] = float(scores[-1])
    for key, pat in (("fpga_ms", r"fpga=(\d+)ms"),
                     ("unpacked_files", r"unpacked (\d+) files")):
        m = re.search(pat, text)
        if m:
            out[key] = int(m.group(1))
    posts = re.findall(r"POSTing (\d+) bytes", text)
    if posts:
        out["post_bytes"] = int(posts[-1])
    return out


def run_query(size: int, mode: str, query: str, args, params: InstanceParams):
    io = ROOT / "io" / instance_name(size) / mode
    keydir, encdir, querydir = io / "keys", io / "encoded", io / "query"
    result = io / "result.ct"
    for d in (keydir, encdir, querydir):
        d.mkdir(parents=True, exist_ok=True)
    env = lib_env()

    def run(name, *a, capture=False, fog=False):
        # A Fog job wraps one stage: `fog submit` provisions the job, sets
        # NBCC_FHETCH_SERVER for the child, and runs it. Keeping the job to the
        # compute stage leaves keygen, encoding and encryption outside its window.
        cmd = [str(BUILD / name), *map(str, a)]
        if fog:
            cmd = [str(FOG), "submit", *cmd]
        return subprocess.run(cmd, check=not capture, capture_output=capture,
                              text=True, env=env)

    # Stages 2 and 4 run on the server and read keys_server: the context and the
    # evaluation keys, no secret key. Stage 1 writes both halves in one pass.
    srvkeydir = io / "keys_server"
    if not (keydir / "cc.bin").exists():
        run("matcher_keygen", "--mode", mode, "--keydir", keydir,
            "--server-keydir", srvkeydir)
        # The recorded trace carries the evaluation keys it was recorded with,
        # so a new key set makes it stale. Drop the cache for this mode and
        # batch count rather than replay a trace built on the old keys.
        nb = -(-params.db_size // 32768)
        stale = Path.cwd() / f"matcher_compute_mode_{mode}_batches_{nb}"
        if stale.is_dir():
            shutil.rmtree(stale, ignore_errors=True)
            print(f"[harness] keys regenerated, dropped the stale trace {stale.name}")
    check_keydirs(keydir, srvkeydir)
    check_secret_key_guard(srvkeydir, keydir, mode, encdir, querydir, env)
    if not (encdir / "dataset_meta.txt").exists():
        run("matcher_encode_dataset", "--mode", mode, "--keydir", srvkeydir,
            "--dataset", params.dataset(), "--out", encdir)
    run("matcher_encrypt_query", "--mode", mode, "--keydir", keydir,
        "--query", query, "--out", querydir)

    # Drop any result from an earlier run. If compute fails, decrypt must find
    # nothing rather than report the previous run's score as this run's answer.
    result.unlink(missing_ok=True)

    t0 = time.time()
    cbin = compute_binary()
    compute_args = ["--mode", mode, "--keydir", srvkeydir, "--encoded-dataset", encdir,
                    "--query-dir", querydir, "--result", result]
    if cbin == "matcher_compute_sdk":          # Niobium: init() forwards these to the backend
        # Spell it "--opt-level O3": that is the form init() forwards to the
        # backend. Large traces do not complete on an FPGA target at O0.
        compute_args += [f"--target={args.target}", "--opt-level", f"O{args.optimization}"]
    cp = run(cbin, *compute_args, capture=True, fog=getattr(args, 'fog', False))
    wall = round(time.time() - t0, 2)
    dp = run("matcher_decrypt_result", "--mode", mode, "--keydir", keydir,
             "--result", result, capture=True)
    log = cp.stdout + cp.stderr + "\n" + dp.stdout + dp.stderr
    m = parse_output(log)
    m["wall_s"] = wall
    # Ground truth for THIS query, recomputed in the clear every run. A fixed
    # score window cannot catch a systematic drift that stays inside it, and
    # --query has no window at all.
    m["expected"], _, _ = cleartext_run(
        query, params.dataset().read_text().splitlines(), mode)
    # A stage that exits non-zero invalidates the run: without this a failed
    # replay still reaches decrypt, and any score parsed from it is reported as
    # if the computation had succeeded.
    if cp.returncode != 0:
        m["error"] = f"{cbin} exited {cp.returncode}"
    elif dp.returncode not in (0, 1):
        # decrypt uses 0/1 to report MATCH / NO MATCH; anything else is a failure.
        m["error"] = f"matcher_decrypt_result exited {dp.returncode}"
    return m, log


def main() -> int:
    p = argparse.ArgumentParser(
        description="Run the set-membership workload.")
    p.add_argument("size", type=int, choices=range(TOY, LARGE + 1),
                   help="Instance size (0=toy, 1=small, 2=medium, 3=large).")
    p.add_argument("--mode", choices=["exact", "soundex"], default="exact",
                   help="Match mode (default exact, valid at every size; soundex is "
                        "supported at the toy tier only, run one mode at a time).")
    p.add_argument("--target", default="local",
                   help="Replay target: local (default; in-process simulator, no "
                        "backend or credentials, runs out of the box) or FOG (real "
                        "FPGA on the Fog, jobs-as-a-service). Any other backend id "
                        "is forwarded to the transport and needs NBCC_FHETCH_SERVER.")
    p.add_argument("-O", "--optimization", type=int, choices=[0, 1, 2, 3], default=3,
                   help="Replay opt level (default 3; FPGA targets need O3).")
    p.add_argument("--query", help="Search a name of your own instead of the default "
                                   "workload query: reports MATCH/NO MATCH by the 0.5 "
                                   "threshold (a name not in the set is a valid result).")
    p.add_argument("--skip-build", action="store_true",
                   help="Skip scripts/build_task.sh (assume build/ is present).")
    args = p.parse_args()

    # A query with no letters encodes to an all-zero vector, which matches
    # nothing. Reject it here rather than reporting NO MATCH for it.
    if args.query is not None and not re.search(r"[A-Za-z]", args.query):
        p.error(f"--query {args.query!r} has no letters to encode.")

    # A Soundex code is 4 characters, so above the toy tier the code space
    # collides heavily. The aggregate then picks up residue from near-miss
    # codes: the match count stops being recoverable and the margin under the
    # 0.5 threshold narrows. Exact mode compares 20 characters and is unaffected.
    if args.mode == "soundex" and args.size != TOY:
        p.error("--mode soundex is supported at the toy tier (size 0) only; "
                "use --mode exact at larger sizes.")

    # Build if needed. build_task.sh is the only build: it fetches the client
    # submodule, builds its bundled OpenFHE and libnbfhetch, and compiles the
    # stages against them.
    if not args.skip_build and not (BUILD / "matcher_compute_sdk").exists():
        print("[harness] building (scripts/build_task.sh) ...")
        subprocess.run(["bash", str(ROOT / "scripts" / "build_task.sh")], check=True)

    # Say which stage is missing and how to get it, rather than letting the first
    # one fail with a bare FileNotFoundError from subprocess.
    missing = [s for s in ("matcher_keygen", "matcher_encode_dataset",
                           "matcher_encrypt_query", "matcher_compute_sdk",
                           "matcher_decrypt_result") if not (BUILD / s).exists()]
    if missing:
        p.error(f"missing from {BUILD}: {', '.join(missing)}. "
                f"Run scripts/build_task.sh, or drop --skip-build to build now.")

    # --target selects the replay backend.
    #   local -> the client's in-tree fhetch_sim worker (NBCC_FHETCH_SIM), no server.
    #   anything else -> a transport server at NBCC_FHETCH_SERVER, which resolves the
    #   target to hardware (FOG is the stable alias for the Fog's pinned FPGA).
    if compute_binary() == "matcher_compute_sdk":
        if args.target == "local":
            sim = next((c for c in (CLIENT / "build" / "vendor" / "niobium-fhetch" / "fhetch_sim",
                                    CLIENT / "build" / "_deps" / "niobium-fhetch-build" / "fhetch_sim")
                        if c.exists()), None)
            if sim is None:
                p.error("--target local needs the fhetch_sim worker from the client "
                        "build; run scripts/build_task.sh first.")
            os.environ["NBCC_FHETCH_SIM"] = str(sim)
        elif not os.environ.get("NBCC_FHETCH_SERVER"):
            # No server named, so take one out per compute stage through the Fog.
            # Needs `fog init` + `fog login` once; anyone pointing
            # NBCC_FHETCH_SERVER at their own replay server keeps that path.
            if not FOG.exists():
                p.error(f"--target {args.target} needs either the Fog CLI at "
                        f"{FOG} (run: git submodule update --init niobium-client) "
                        f"or NBCC_FHETCH_SERVER pointing at your own "
                        f"nbcc_fhetch_replay_server.")
            args.fog = True

    results = []
    for size in [args.size]:
        params = InstanceParams(size, ROOT)
        if not params.dataset().exists():
            print(f"[harness] SKIP {params.name}: dataset missing ({params.dataset()})")
            continue
        # One mode per run (--mode exact|soundex). Soundex is capped at the toy
        # tier in the argument check above.
        for mode in (args.mode,):
            if args.query is not None:           # search: report, don't assert a window
                query, lo, hi = args.query, None, None
            else:
                query, lo, hi = default_member(size, mode, params)
            print(f"\n[harness] === {params.name}/{mode}/{query!r} "
                  f"(target={args.target}) ===")
            metrics, log = run_query(size, mode, query, args, params)
            score = metrics.get("score")
            stage_error = metrics.get("error")
            expected = metrics.get("expected")
            if stage_error:                      # a stage failed: the score, if any, is not this run's
                verdict, ok = "ERROR", False
                win = stage_error
            elif score is None:
                verdict, ok = "ERROR", False
                win = "no score decrypted"
            else:
                # CKKS is approximate, so compare against the plaintext reference
                # with a tolerance rather than for equality. This is the primary
                # check: it holds for any query, including --query, where no
                # tuned window exists.
                ok = abs(score - expected) <= CLEARTEXT_TOL
                verdict = ("MATCH" if score > 0.5 else "NO MATCH") if lo is None else \
                          ("PASS" if ok else "FAIL")
                win = f"expected={expected} (tol {CLEARTEXT_TOL})"
                if lo is not None and ok and not (lo <= score <= hi):
                    # Agrees with the reference but sits outside the tuned window:
                    # the window is stale, not the result.
                    win += f" [outside tuned window {lo}..{hi}]"
                if not ok:
                    verdict = "FAIL"
            metrics.update(size=params.name, mode=mode, query=query, target=args.target,
                           verdict=verdict, passed=ok)
            results.append(metrics)
            md = params.measuredir()
            md.mkdir(parents=True, exist_ok=True)
            safe = re.sub(r"\W+", "_", f"{mode}_{query}")
            (md / f"{safe}.log").write_text(log)
            (md / f"{safe}.json").write_text(json.dumps(metrics, indent=2))
            tail = "" if ok else "\n" + "\n".join(log.strip().splitlines()[-15:])
            # Only the fields this run produced: post_bytes comes from the
            # transport, and fpga_ms from a stage that reports firmware time.
            extra = ""
            if metrics.get("post_bytes") is not None:
                extra += f" post={metrics['post_bytes']}B"
            if metrics.get("fpga_ms") is not None:
                extra += f" fpga={metrics['fpga_ms']}ms"
            print(f"[harness] score={score} {win}{extra} -> {verdict}{tail}")

    print("\n[harness] ===== summary =====")
    nok = sum(1 for r in results if r["passed"])
    for r in results:
        fpga = f"fpga={r['fpga_ms']}ms  " if r.get("fpga_ms") is not None else ""
        print(f"  {r['verdict']:<9} {r['size']:<7} {r['mode']:<7} "
              f"score={r.get('score','?')!s:<12} {fpga}{r['query']!r}")
    print(f"[harness] {nok}/{len(results)} completed OK")
    return 0 if results and nok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
