"""Opt-in local smoke of the named native executable, not an install or CI job."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

from hia.platform.bench.main_build import TARGET_NAME, _REPO, _target_output
from hia.tests.test_bench_main import OUTSIDE, NativeBenchMain, stdout_observation


def need(condition, detail):
    if not condition:
        raise ValueError(detail)


def qualify(output):
    output = _target_output(output)
    output.mkdir(mode=0o700)
    cases = []

    def build(label, bound=False, expected=True):
        destination = output / label
        command = [sys.executable, "-B", "-m", "hia.platform.bench.main_build",
                   "--output", str(destination)]
        if bound:
            command.append("--bind-profile-output")
        result = subprocess.run(command, cwd=_REPO, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=60)
        record = {"name": label, "bound": bound, "exit": result.returncode,
                  "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}
        cases.append(record)
        if not expected:
            need(result.returncode == 2 and not result.stdout and result.stderr,
                 "Named target did not refuse an invalid destination/anchor")
            return
        need(result.returncode == 0 and not result.stderr, "Named target build failed")
        binary = destination / TARGET_NAME
        raw = binary.read_bytes()
        identity = json.loads((destination / "named-target.json").read_text())
        need(binary.lstat().st_nlink == 1 and stat.S_IMODE(binary.lstat().st_mode) == 0o500,
             "Executable is not the private single-link product")
        need(sha256(raw).hexdigest() == identity["elf"]["sha256"] == json.loads(result.stdout)["sha256"],
             "Product and receipts disagree")
        need(not identity["elf"]["dynamic_linker"] and not identity["runtime_rust_or_python_fallback"]
             and not identity["installed"] and not identity["production_entrypoint_activated"],
             "Unexpected runtime or installation claim")
        return binary, identity

    def actual(binary, label, args):
        cwd = output / (label + ".cwd")
        cwd.mkdir(mode=0o700)
        begin = time.time_ns()
        start = time.monotonic_ns()
        result = subprocess.run([os.fsencode(TARGET_NAME), *args], executable=binary,
                                cwd=cwd, env={}, stdin=subprocess.DEVNULL, capture_output=True, timeout=25)
        wall = time.monotonic_ns() - start
        end = time.time_ns()
        need(not list(cwd.iterdir()), "Product wrote outside its bound profile path")
        (output / (label + ".stdout.raw")).write_bytes(result.stdout)
        (output / (label + ".stderr.raw")).write_bytes(result.stderr)
        return result, wall, {"label": label, "realtime_start_ns": begin, "realtime_end_ns": end}

    try:
        first, a = build("first")
        second, b = build("second")
        need(first.read_bytes() == second.read_bytes() and a == b,
             "Two independent unbound builds are not byte-identical")
        build("first", expected=False)
        need(first.read_bytes() == second.read_bytes(), "Refused overwrite changed the executable")
        build("missing-anchor", bound=True, expected=False)
        need(not (output / "isolated-source").exists(), "Build invented a profile anchor")
        args = (b"--txs=19", b"--keys=3", b"--determinism-repeats=2",
                b"--strategy=aggressive-greedy")
        successful = []
        for label, binary in (("first", first), ("second", second)):
            r, wall, _ = actual(binary, label, args)
            need((r.returncode, r.stderr) == (0, b""), "Direct native target failed")
            successful.append(stdout_observation(r.stdout, wall)[1])
        need(successful[0] == successful[1] and b"\ndeterminism.replay_match=true\n" in successful[0],
             "Rebuilt products disagree on deterministic output")
        r, _, _ = actual(first, "unbound-profile", (*args, b"--profile"))
        need((r.returncode, r.stdout, r.stderr) == (2, b"", OUTSIDE),
             "Unbound executable began profile work")
        anchor = output / "isolated-source/trillionnium"
        anchor.mkdir(parents=True, mode=0o700)
        (anchor / "Cargo.lock").write_bytes((_REPO / "trillionnium/Cargo.lock").read_bytes())
        bound, c = build("bound", bound=True)
        need(c["compiled_profile_root"] == str(anchor), "Bound product root mismatch")
        r, wall, event = actual(bound, "bound-profile", (*args, b"--profile"))
        comparator = NativeBenchMain()
        comparator.root, comparator.bench_path, comparator.events = output, anchor / "run/bench", [event]
        report, _, _ = comparator.profile_comparable(r, wall, "file")
        fields = dict(line.split(b"=", 1) for line in report.splitlines() if b"=" in line)
        need(fields[b"strategy"] == b"AggressiveGreedy" and fields[b"determinism.replay_match"] == b"true",
             "Bound direct run did not execute the requested scheduler")
        need(len(list(comparator.bench_path.iterdir())) == 1, "Unexpected bound file roster")
        return {"result": "PASS", "unbound_sha256": a["elf"]["sha256"],
                "bound_sha256": c["elf"]["sha256"], "profile_observation": event}
    finally:
        (output / "build-attempts.json").write_text(json.dumps(cases, indent=2) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    print(json.dumps(qualify(a.output), sort_keys=True))


if __name__ == "__main__":
    main()
