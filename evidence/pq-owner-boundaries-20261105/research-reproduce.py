#!/usr/bin/env python3
"""Reproduce the 13 pure-Python research/component regression suites.

This portable entry point was written AFTER the archived 2026-11-05 run.
It is not the script whose bytes produced that original result. The original
run used research_review_run.py at checkout dbc24913e9c23f2359dd22ff9b01243877a6dd4d.

Example (OUTPUT must not already exist):
    python3 reproduce.py --root /path/to/chain --output /path/to/new-run

The comparison commit must be present in ROOT's local Git object database.
The output is create-only, and a new execution records its own checkout,
runner digest, interpreter, results, and in-process repository read inputs.
Input equality does not qualify native binaries, a complete Chain/Hepta
combination, a QROM theorem, WAN capacity, or an independent deployment.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import subprocess
import sys
import time
import unittest


DEFAULT_COMPARE_COMMIT = "ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155"
FORMAL_SUITES = (
    "test_reversible_components",
    "test_w1_quantum_oracle",
    "test_quantum_oracle_resources",
    "test_quantum_resource_clock",
    "test_quantum_candidate_check_clock",
    "test_quantum_network_sim",
    "test_quantum_adversarial_search",
    "test_quantum_daa_model",
    "test_parallel_variable_ohie",
    "test_w1_quantum_restricted_oracle",
    "test_fast_daa_reference_component",
)
CI_SUITES = ("test_pq_quantum_daa_scenarios", "test_w1_security_budget")


def git(root: pathlib.Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments], text=True
    ).strip()


def write_json_new(path: pathlib.Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True,
                        help="Chain checkout to execute; no build or checkout is performed")
    parser.add_argument("--output", type=pathlib.Path, required=True,
                        help="New output directory; refuses any existing path")
    parser.add_argument("--compare-commit", default=DEFAULT_COMPARE_COMMIT,
                        help="Local commit against which read-input Git blobs are compared")
    args = parser.parse_args()
    try:
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            parser.error("--root must be a directory")
        output = args.output.absolute()
        # Refuse existing symlinks as well as ordinary paths before running tests.
        if os.path.lexists(output):
            parser.error("--output already exists; choose a new create-only directory")
        head = git(root, "rev-parse", "HEAD")
        compared = git(root, "rev-parse", "--verify", args.compare_commit + "^{commit}")
        checkout_status = git(root, "status", "--porcelain", "--untracked-files=no")
        paths = [root / "formal/pon-nakamoto-v1" / (name + ".py")
                 for name in FORMAL_SUITES]
        paths += [root / "scripts/ci" / (name + ".py") for name in CI_SUITES]
        for path in paths:
            if not path.is_file():
                parser.error("required suite is absent: " + str(path))
        # Parents may be prepared by the caller; this refuses accidental reuse.
        output.mkdir(parents=False, exist_ok=False)
    except (OSError, subprocess.CalledProcessError) as error:
        parser.error(str(error))

    runner_bytes = pathlib.Path(__file__).read_bytes()
    opened: set[str] = set()

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if event != "open" or not arguments or not isinstance(arguments[0], (str, bytes)):
            return
        name = os.fsdecode(arguments[0])
        path = pathlib.Path(name)
        if not path.is_absolute():
            path = pathlib.Path.cwd() / path
        try:
            relative = path.resolve().relative_to(root)
        except (OSError, ValueError):
            return
        if ".git" not in relative.parts and "__pycache__" not in relative.parts:
            opened.add(str(relative))

    sys.dont_write_bytecode = True
    sys.path[:0] = [str(root / "formal/pon-nakamoto-v1"), str(root / "scripts/ci")]
    sys.addaudithook(audit)
    suite = unittest.TestSuite()
    for path in paths:
        specification = importlib.util.spec_from_file_location(path.stem, path)
        if specification is None or specification.loader is None:
            raise RuntimeError("cannot load suite: " + str(path))
        module = importlib.util.module_from_spec(specification)
        sys.modules[specification.name] = module
        specification.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))

    started = time.monotonic()
    with (output / "tests.log").open("x", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    seconds = time.monotonic() - started
    inputs = []
    comparisons = []
    # Freeze the audited list before reading inputs to calculate hashes.
    for relative in sorted(opened):
        path = root / relative
        if not path.is_file():
            continue
        raw = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        record = {"path": relative, "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest(), "git_blob": blob}
        inputs.append(record)
        candidate = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", compared + ":" + relative],
            text=True, capture_output=True, check=False,
        )
        compared_blob = candidate.stdout.strip() if candidate.returncode == 0 else None
        comparisons.append({**record, "compared_git_blob": compared_blob,
                            "identical": blob == compared_blob})

    report = {
        "schema": "trnm-research-reproduction-run-v1",
        "checkout_head": head,
        "checkout_status_porcelain": checkout_status,
        "target_research_source": compared,
        "runner_sha256": hashlib.sha256(runner_bytes).hexdigest(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "scope": "13 research and component-budget suites; no native, WAN, QROM theorem or independent deployment acceptance",
        "suite_paths": [str(path.relative_to(root)) for path in paths],
        "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "seconds": seconds,
        "failed_ids": [test.id() for test, _ in result.failures],
        "error_ids": [test.id() for test, _ in result.errors],
        "inputs": inputs,
        "production_qualified": False, "security_theorem": False,
    }
    equivalent = bool(comparisons) and all(row["identical"] for row in comparisons)
    mapping = {
        "schema": "trnm-research-input-equivalence-v1",
        "executed_checkout": head,
        "compared_commit": compared,
        "compared_using": "Local Git commit tree; SHA-1 Git blob and SHA-256 content digests",
        "in_process_read_inputs": len(comparisons),
        "all_listed_inputs_identical": equivalent,
        "scope": "In-process repository read inputs only; interpreter, standard library, native binaries and full transitive environment are not pinned",
        "child_execution_note": "test_quantum_oracle_resources invokes quantum_oracle_resources.py, which is also loaded in the parent suite; no complete subprocess audit is claimed",
        "inputs": comparisons,
    }
    write_json_new(output / "result.json", report)
    write_json_new(output / "source-equivalence.json", mapping)
    print(json.dumps({key: value for key, value in report.items() if key != "inputs"}))
    print(json.dumps({key: value for key, value in mapping.items() if key != "inputs"}))
    # A test pass must not mask failure to establish the requested source mapping.
    return 0 if result.wasSuccessful() and equivalent else 1


if __name__ == "__main__":
    raise SystemExit(main())
