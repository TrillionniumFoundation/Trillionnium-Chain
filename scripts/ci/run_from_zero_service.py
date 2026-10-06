#!/usr/bin/env python3
"""Run finite native controls inside the existing head/merge protocol job.

Keep failed attempts, original deadlines and the existing named-test checker.
A receipt binds local bytes and CI identity; it is not a WAN or hardness claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
TESTS = (
    "cpu_span_cannot_cross_threads_or_turn_unknown_into_zero",
    "from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection",
    "from_zero_service_shares_cpu_with_honest_work_and_reopened_owner",
)
NATIVE_TIMEOUT_SECONDS = 600
CHECK_TIMEOUT_SECONDS = 30
REAP_TIMEOUT_SECONDS = 5
MAX_REPORT_BYTES = 32 * 1024 * 1024


def read_retained(path: Path, maximum: int) -> bytes:
    """Refuse nonregular observations without following a final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > maximum:
            raise ValueError(f"invalid retained file: {path}")
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError(f"retained file exceeds limit: {path}")
        return raw


def unique_json(raw: bytes):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate observation field: {key}")
            value[key] = item
        return value

    def nonfinite(value):
        raise ValueError(f"nonfinite observation value: {value}")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def source_binding(parent: Path) -> dict:
    path = parent / "source.json"
    if not path.exists() and not path.is_symlink():
        if os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("TRNM_EXPECTED_SOURCE_SHA"):
            raise ValueError("hosted native execution requires the existing source.json")
        return {"available": False}  # Standalone execution is not hosted acceptance.
    raw = read_retained(path, 64 * 1024)
    data = unique_json(raw)
    if (type(data) is not dict or data.get("schema") != "trnm-ci-source-v1"
            or data.get("tracked_worktree_verified") is not True):
        raise ValueError("invalid existing source identity")
    for key, ref in (("tested_commit", "HEAD"), ("tested_tree", "HEAD^{tree}")):
        observed = subprocess.check_output(
            ["git", "rev-parse", "--verify", ref], cwd=ROOT,
            timeout=CHECK_TIMEOUT_SECONDS, text=True,
        ).strip()
        if data.get(key) != observed:
            raise ValueError(f"source identity differs from checkout: {key}")
    return {"available": True, "sha256": digest(raw),
            **{key: data.get(key) for key in
               ("tested_commit", "tested_tree", "kind", "candidate", "base")}}


def native_report_binding(output: Path) -> dict:
    raw = read_retained(output / "native/report.json", MAX_REPORT_BYTES)
    data = unique_json(raw)
    if (type(data) is not dict or data.get("schema") != "public-v3-local-from-zero-service-v2"
            or data.get("finite_target_met") is not True
            or data.get("reopen_state_equal") is not True
            or data.get("cpu_domain_retained_across_owner_reopen") is not True):
        raise ValueError("missing or unsuccessful finite native service report")
    for key in ("public_network_ready", "independent_accepted", "work_profile_qualified",
                "resource_fairness_qualified", "physical_power_loss", "production_activation"):
        if data.get(key) is not False:
            raise ValueError(f"native report cannot promote acceptance: {key}")
    return {"path": "native/report.json", "sha256": digest(raw), "bytes": len(raw)}


def run_owned(command: list[str], log: Path, env: dict[str, str], timeout: float) -> dict:
    """On timeout kill the owned POSIX process group before reaping its leader.

    This does not claim containment of descendants that create another session,
    nor that grandchildren were waitpid-reaped by this Python process.
    """
    started = time.monotonic_ns()
    row = {"command": command, "exit_code": None, "error": None, "error_kind": None,
           "timed_out": False, "timeout_seconds": timeout,
           "timeout_group_kill_sent": False, "direct_child_reaped": False}
    with log.open("xb") as stream:
        try:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as exc:
            row.update(error=str(exc), error_kind="launch")
        else:
            try:
                row["exit_code"] = process.wait(timeout=timeout)
                row["direct_child_reaped"] = True
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                row.update(error=str(exc) or "interrupted",
                           error_kind="timeout" if isinstance(exc, subprocess.TimeoutExpired) else "interrupted",
                           timed_out=isinstance(exc, subprocess.TimeoutExpired))
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    row["timeout_group_kill_sent"] = True
                except ProcessLookupError:
                    pass
                except OSError as cleanup:
                    row["cleanup_error"] = str(cleanup)
                try:
                    row["exit_code"] = process.wait(timeout=REAP_TIMEOUT_SECONDS)
                    row["direct_child_reaped"] = True
                except subprocess.TimeoutExpired:
                    row["cleanup_error"] = "direct child was not reaped inside cleanup budget"
    row["elapsed_ns"] = time.monotonic_ns() - started
    # A timeout is never success, even when the child happened to exit zero.
    row["log_sha256"] = digest(log.read_bytes())
    return row


def write_results(output: Path, data: dict) -> None:
    temporary = output / "results.pending"
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(data, indent=2) + "\n")
    os.replace(temporary, output / "results.json")


def main() -> int:
    parent = Path(os.environ.get("TRNM_CI_RECEIPT_DIR", "/tmp/trnm-ci-" + str(os.getpid())))
    parent.mkdir(parents=True, exist_ok=True)
    output = parent / "from-zero-service"
    output.mkdir()  # Preserve the existing create-new campaign contract.
    env = os.environ.copy()
    env["TRNM_PUBLIC_V3_FROM_ZERO_DIR"] = str((output / "native").resolve())
    results: list[dict] = []
    report = {"schema": "native-from-zero-execution-v1", "results": results,
              "complete": False, "result": "INCOMPLETE_OR_FAILED",
              "public_network_qualification": False, "compute_qualification": False,
              "source_before": None, "source_after": None, "native_report": None,
              "runner_context": {key: env.get(key) for key in
                  ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "RUNNER_ARCH")}}
    write_results(output, report)
    try:
        report["source_before"] = source_binding(parent)
        for index, name in enumerate(TESTS):
            command = [
                "cargo", "test", "--offline", "--locked", "--release",
                "--manifest-path", str(ROOT / "trillionnium/Cargo.toml"),
                "-p", "trnm-pon-node", "--test", "maintenance_paired_conformance", name,
                "--", "--exact", "--nocapture", "--test-threads=1",
            ]
            log = output / f"{index:02d}.log"
            row = run_owned(command, log, env, NATIVE_TIMEOUT_SECONDS)
            row.update(test=name, log=log.name, named_execution_check_exit=None,
                       named_execution_check="", passed=False)
            results.append(row)
            if row["exit_code"] == 0 and row["error"] is None:
                checker_log = output / f"{index:02d}.check.log"
                checked = run_owned(
                    [sys.executable, str(ROOT / "scripts/ci/check_required_native_test.py"),
                     str(log), "--test", name], checker_log, env, CHECK_TIMEOUT_SECONDS,
                )
                row.update(named_execution_check_exit=checked["exit_code"],
                           named_execution_check=checker_log.read_text(encoding="utf-8", errors="replace"),
                           named_execution_observation=checked)
                row["passed"] = checked["exit_code"] == 0 and checked["error"] is None
                if checked.get("cleanup_error") or checked["error_kind"] == "interrupted":
                    raise RuntimeError("named checker did not close cleanly; no next native test")
            print(json.dumps(row), flush=True)
            report["complete"] = len(results) == len(TESTS)
            write_results(output, report)
            if row.get("cleanup_error") or row["error_kind"] == "interrupted":
                raise RuntimeError("native owner did not close cleanly; no next native test")
        report["native_report"] = native_report_binding(output)
        # Finalize only against the same recorded source and the retained logs.
        report["source_after"] = source_binding(parent)
        if report["source_before"] != report["source_after"]:
            raise ValueError("source identity changed during native execution")
        for row in results:
            if digest((output / row["log"]).read_bytes()) != row["log_sha256"]:
                raise ValueError("native log changed after command completion")
        if report["complete"] and all(row["passed"] for row in results):
            report["result"] = "PASS"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report["error"] = str(exc)
    finally:
        write_results(output, report)
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
