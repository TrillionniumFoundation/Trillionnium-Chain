#!/usr/bin/env python3
"""Execute the bounded operation cases and emit source-bound replay evidence.

The documentation contract gate intentionally performs lexical checks only.  This
runner is the separate behavioral step: it executes the exact Cargo commands
already declared by ``config/documentation-operations-v1.json`` and records
return codes plus output digests.  It never upgrades semantic acceptance,
independent-vector status, specialist appointments, or production authority.

The runner does not invoke a shell.  Commands are reconstructed by the same
source-bound operation validator used by the documentation gate, so a catalog
entry cannot smuggle shell syntax into the replay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

# Allow running this file directly from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_documentation_contracts_v1 as gate  # noqa: E402


CATALOG = gate.ROOT / gate.OPERATIONS
WORKSPACE = gate.ROOT / "trillionnium"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="report path outside the source checkout",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=600.0,
        help="hard deadline for each declared Cargo case",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="execute only the first N cases (for smoke tests; report remains non-acceptance evidence)",
    )
    return parser.parse_args()


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=gate.ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "backslashreplace")).hexdigest()


def validate_inputs() -> tuple[str, str, dict[str, Any], list[dict[str, Any]]]:
    head, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise gate.DocumentationError("DOC-DIRTY", "behavioral replay requires a clean checkout")
    registry = json.loads(
        (gate.ROOT / gate.REGISTRY).read_text(encoding="utf-8"),
        object_pairs_hook=gate.strict_object,
    )
    coverage = gate.tomllib.loads((gate.ROOT / gate.COVERAGE).read_text(encoding="utf-8"))
    catalog_bytes = CATALOG.read_bytes()
    catalog = json.loads(catalog_bytes, object_pairs_hook=gate.strict_object)
    # Validate IDs, paths, features, exact filters, and assertion fragments before
    # any subprocess is spawned.  This remains a source-bound catalog check.
    gate.validate_structure(registry, coverage)
    operation_report, _ = gate.validate_operations(gate.ROOT, catalog, registry, coverage)
    commands = operation_report["replay_commands"]
    return head, tree, {"sha256": hashlib.sha256(catalog_bytes).hexdigest()}, commands


def execute_case(case: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    command = list(case["argv"])
    started = time.monotonic()
    environment = os.environ.copy()
    environment.update(
        {
            "CARGO_TERM_COLOR": "never",
            "RUST_BACKTRACE": "1",
            # The consensus tests contain deeply nested exact fixtures; this
            # avoids a platform-default stack changing replay behavior.
            "RUST_MIN_STACK": environment.get("RUST_MIN_STACK", "33554432"),
        }
    )
    try:
        completed = subprocess.run(
            command,
            cwd=gate.ROOT / case["cwd"],
            env=environment,
            capture_output=True,
            text=True,
            errors="backslashreplace",
            timeout=timeout_seconds,
            check=False,
        )
        stdout, stderr = completed.stdout, completed.stderr
        status = "passed" if completed.returncode == 0 else "failed"
        return {
            "operation_id": case["operation_id"],
            "case_id": case["case_id"],
            "argv": command,
            "status": status,
            "returncode": completed.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stdout_sha256": digest(stdout),
            "stderr_sha256": digest(stderr),
            "stdout_tail": stdout[-4096:],
            "stderr_tail": stderr[-4096:],
        }
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "backslashreplace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "backslashreplace")
        return {
            "operation_id": case["operation_id"],
            "case_id": case["case_id"],
            "argv": command,
            "status": "timeout",
            "returncode": None,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stdout_sha256": digest(stdout),
            "stderr_sha256": digest(stderr),
            "stdout_tail": stdout[-4096:],
            "stderr_tail": stderr[-4096:],
        }


def main() -> int:
    args = parse_args()
    if args.timeout_seconds <= 0:
        raise gate.DocumentationError("DOC-REPLAY-TIMEOUT", "timeout must be positive")
    output = args.output.resolve()
    if output.is_relative_to(gate.ROOT.resolve()):
        raise gate.DocumentationError("DOC-OUTPUT", "report must be outside the source checkout")
    if args.limit is not None and args.limit <= 0:
        raise gate.DocumentationError("DOC-REPLAY-LIMIT", "limit must be positive")

    head, tree, catalog_binding, commands = validate_inputs()
    selected = commands if args.limit is None else commands[: args.limit]
    results: list[dict[str, Any]] = []
    for index, command in enumerate(selected, 1):
        print(f"replay={index}/{len(selected)} case={command['case_id']}", flush=True)
        result = execute_case(command, args.timeout_seconds)
        results.append(result)
        print(f"  status={result['status']} elapsed={result['elapsed_seconds']}s", flush=True)

    passed = sum(result["status"] == "passed" for result in results)
    report = {
        "schema": "trnm-documentation-operation-replay-evidence-v1",
        "source_commit": head,
        "source_tree": tree,
        "catalog": {"path": str(CATALOG.relative_to(gate.ROOT)), **catalog_binding},
        "workspace": str(WORKSPACE.relative_to(gate.ROOT)),
        "selection": {"requested": len(commands), "executed": len(results), "limit": args.limit},
        "result": "PASS" if passed == len(results) else "FAIL",
        "passed": passed,
        "failed_or_timed_out": len(results) - passed,
        "scope": "declared-source-regression-Cargo-replays-only",
        "semantic_acceptance": "not-assessed",
        "independent_golden_vectors": "absent",
        "specialist_acceptance": "absent",
        "production_authority": False,
        "results": results,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in (
        "schema", "source_commit", "selection", "result", "passed",
        "failed_or_timed_out", "semantic_acceptance", "independent_golden_vectors",
        "specialist_acceptance", "production_authority",
    )}, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (gate.DocumentationError, OSError, ValueError, KeyError, TypeError,
            subprocess.CalledProcessError) as error:
        print(
            json.dumps(
                {
                    "result": "FAIL",
                    "code": getattr(error, "code", "DOC-REPLAY-INPUT"),
                    "detail": str(error),
                    "semantic_acceptance": "not-assessed",
                    "production_authority": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2)
