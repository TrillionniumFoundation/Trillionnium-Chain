#!/usr/bin/env python3
"""Execute independent Rust feedback against an exact head or two-parent merge.

This runner supplies additional execution evidence, not acceptance authority.
The existing required baseline remains authoritative until migration is reviewed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

LANES = ("build", "workspace", "native", "safety-epoch", "node-epoch", "contracts")
MAX_LOG_BYTES = 64 * 1024 * 1024


class LaneError(RuntimeError):
    pass


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True, timeout=30).strip()


def identity(root: Path, mode: str, head: str, base: str, merge: str) -> dict[str, str]:
    for value in (head, base, merge):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise LaneError("missing or malformed independent source pin")
    expected = head if mode == "head" else merge
    if git(root, "rev-parse", "HEAD") != expected:
        raise LaneError("checkout does not match the selected exact source")
    parents = git(root, "show", "-s", "--format=%P", "HEAD")
    if mode == "merge" and parents != f"{base} {head}":
        raise LaneError("merge must have the exact ordered base and head parents")
    if git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise LaneError("source checkout is dirty")
    return {"mode": mode, "source": expected, "tree": git(root, "rev-parse", "HEAD^{tree}"),
            "parents": parents, "head": head, "base": base, "merge": merge}


def commands(lane: str, evidence: Path) -> list[tuple[str, list[str], int]]:
    cargo = ["cargo"]
    manifest = ["--manifest-path", "trillionnium/Cargo.toml"]
    def test(name: str, packages: list[str], extra: list[str], seconds: int = 900):
        return name, cargo + ["test", *manifest, *sum((["-p", p] for p in packages), []), *extra, "--locked"], seconds
    def lint(name: str, packages: list[str], extra: list[str]):
        return name, cargo + ["clippy", *manifest, *sum((["-p", p] for p in packages), []), *extra, "--all-targets", "--locked", "--", "-D", "warnings"], 900
    def shards(suite: str, deadline: int):
        # The original runner retains the complete inventory, original assertions,
        # ignored SIGKILL children and per-case deadlines (including V8/V9).
        return "shards", [sys.executable, "scripts/ci/run_native_candidate_shards_v1.py", "--suite", suite,
                          "--workspace", "trillionnium", "--evidence-dir", str(evidence / "shards"),
                          "--deadline-seconds", str(deadline)], 10800
    if lane == "build":
        return [("format", cargo + ["fmt", *manifest, "--all", "--", "--check"], 300),
                ("check", cargo + ["check", *manifest, "--workspace", "--all-targets", "--locked"], 1800)]
    if lane == "workspace":
        return [test("workspace", [], ["--workspace", "--all-targets"], 3600)]
    if lane == "native":
        packages = ["trnm-consensus-crypto", "trnm-native-execution-v0"]
        return [test("default-targets", packages, ["--all-targets"]),
                test("doctests", packages, ["--doc"]), shards("native", 900),
                lint("strict-clippy", packages, ["--features", "trnm-native-execution-v0/test-fixtures,trnm-native-execution-v0/incremental-epoch-candidate"])]
    if lane == "safety-epoch":
        return [test("core-v2", ["trnm-consensus-core"], ["--no-default-features", "--features", "candidate-epoch-host-v2", "--lib", "candidate_host_v2"], 300),
                test("core-all-features", ["trnm-consensus-core"], ["--all-features"], 300),
                shards("safety-epoch", 900),
                lint("strict-clippy", ["trnm-consensus-core", "trnm-consensus-safety-store"], ["--all-features"])]
    if lane == "node-epoch":
        return [shards("node-epoch", 300),
                test("doctests", ["trnm-poco-node"], ["--features", "epoch-runtime-candidate", "--doc"]),
                lint("strict-clippy", ["trnm-poco-node"], ["--features", "epoch-runtime-test-fixtures"])]
    if lane == "contracts":
        return [(verb, ["cargo", verb, "--manifest-path", "contracts/Cargo.toml", "--workspace", "--all-targets", "--locked"]
                 + (["--", "-D", "warnings"] if verb == "clippy" else []), 900)
                for verb in ("check", "test", "clippy")]
    raise LaneError("unknown lane")


def checkpoint(evidence: Path, summary: dict) -> None:
    temporary = evidence / ".summary.tmp"
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(evidence / "summary.json")


def terminate(process: subprocess.Popen) -> None:
    # Cleanup is restricted to the newly created process group, never a PID
    # provided by the checkout or a name-based pkill across unrelated jobs.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        if sig == signal.SIGTERM:
            time.sleep(0.2)
    process.wait(timeout=5)


def run_command(command: list[str], root: Path, env: dict[str, str], log: Path,
                seconds: int, max_bytes: int = MAX_LOG_BYTES) -> int:
    started = time.monotonic()
    with log.open("xb") as stream:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while True:
                code = process.poll()
                if os.fstat(stream.fileno()).st_size > max_bytes:
                    return 125
                if code is not None:
                    return code if code >= 0 else 128 - code
                if time.monotonic() - started >= seconds:
                    return 124
                time.sleep(0.05)
        finally:
            terminate(process)


def execute(root: Path, evidence: Path, plan: list[tuple[str, list[str], int]],
            confirm, summary: dict) -> int:
    env = os.environ.copy()
    env.pop("RUST_MIN_STACK", None)
    env.update(CI="true", TZ="UTC", LANG="C.UTF-8", LC_ALL="C.UTF-8",
               PYTHONDONTWRITEBYTECODE="1", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never",
               TRNM_EXPECTED_SOURCE_SHA=summary["identity"]["source"])
    expected = summary["identity"]
    rows = [{"name": name, "command": argv, "deadline_seconds": seconds,
             "status": "not-run", "exit_code": None} for name, argv, seconds in plan]
    if not rows or len({row["name"] for row in rows}) != len(rows):
        raise LaneError("empty or duplicate lane command plan")
    summary["commands"] = rows
    checkpoint(evidence, summary)
    failure = 0
    for row in rows:
        if confirm() != expected:
            raise LaneError("source identity changed before command")
        row["status"] = "running"
        checkpoint(evidence, summary)
        started = time.monotonic_ns()
        log = evidence / (row["name"] + ".log")
        try:
            code = run_command(row["command"], root, env, log, row["deadline_seconds"])
        except OSError as error:
            code = 2
            row["error"] = str(error)
        row.update(exit_code=code, status="passed" if code == 0 else "failed",
                   elapsed_ms=(time.monotonic_ns() - started) // 1_000_000)
        if log.exists():
            with log.open("rb") as stream:
                row["log_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        if code and not failure:
            failure = code
        checkpoint(evidence, summary)
        print(f"{row['name']}: exit={code} elapsed_ms={row['elapsed_ms']}", flush=True)
        if confirm() != expected:
            raise LaneError("source identity changed after command")
        # A failed test does not suppress doctests/lint in this independent lane.
    return failure


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=LANES, required=True)
    parser.add_argument("--mode", choices=("head", "merge"), required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--merge", required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    root, evidence = args.root.resolve(), args.evidence_dir.resolve()
    if evidence == root or root in evidence.parents:
        raise LaneError("evidence must be outside the source checkout")
    confirm = lambda: identity(root, args.mode, args.head, args.base, args.merge)
    initial = confirm()
    evidence.mkdir(parents=True, exist_ok=False)
    summary = {"schema": "trnm-independent-rust-lane-v1", "lane": args.lane,
               "identity": initial, "status": "failed", "acceptance_authority": False}
    code = 2
    try:
        code = execute(root, evidence, commands(args.lane, evidence), confirm, summary)
    except (OSError, LaneError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    finally:
        summary.update(status="passed" if code == 0 else "failed", exit_code=code)
        checkpoint(evidence, summary)
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, LaneError, subprocess.SubprocessError) as error:
        print(f"independent Rust lane failed: {error}", file=sys.stderr)
        raise SystemExit(2)
