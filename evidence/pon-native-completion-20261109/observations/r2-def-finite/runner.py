#!/usr/bin/env python3
"""Run only the frozen nine-suite finite-model roster on an explicit R2 source.

The runner and evidence live outside the source tree. A passing report never
changes D/E/F production qualification. No Cargo/target/model/network command
is launched by this runner; the original repository preflight is retained.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import traceback


SOURCE = Path("/data/chain-abg-70ae-20261108/source")
EVIDENCE = Path("/data/chain-abg-70ae-20261108/evidence/r2-def-finite")
MANIFEST_SHA256 = "91dba3636dbdcdbcfb6adbd1e32250e705ceecdb8ecddcc255752b7200c86d9b"
ROSTER = (
    ("test_cost_envelope_contract_v1", 29),
    ("test_branch_time_daa_v1", 31),
    ("test_lifecycle_cost_v1", 31),
    ("test_credit_envelope_contract", 40),
    ("test_normalized_search_cost", 37),
    ("test_fixed_probability_contract", 16),
    ("test_credit_feasibility", 31),
    ("test_amortized_cost_potential", 34),
    ("test_amortized_cost_potential_independent", 6),
)
ENV_OVERRIDES = {
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
}
CONCURRENT_LOAD = (
    "Same-host B static gates and root native/strict-Clippy development checks "
    "run concurrently. The original fixed-host pressure contract is not exercised."
)


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def check(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


class Recorder:
    def __init__(self, evidence: Path, commit: str, tree: str):
        self.evidence = evidence
        self.commit = commit
        self.tree = tree
        self.environment = os.environ.copy()
        self.environment.update(ENV_OVERRIDES)
        self.commands: list[dict] = []

    def run(self, label: str, argv: list[str], timeout: float = 120) -> dict:
        directory = self.evidence / label
        directory.mkdir()
        started = utc()
        specification = {
            "argv": argv,
            "cwd": str(SOURCE),
            "env_overrides": ENV_OVERRIDES,
            "started_utc": started,
            "timeout_seconds": timeout,
            "expected_source_commit": self.commit,
            "expected_source_tree": self.tree,
        }
        save_json(directory / "command.json", specification)
        begin = time.monotonic()
        timed_out = False
        launch_error = None
        returncode = None
        with (directory / "stdout").open("xb") as stdout, (
            directory / "stderr"
        ).open("xb") as stderr:
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=SOURCE,
                    env=self.environment,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                try:
                    returncode = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    # Signal only this runner's own freshly created child group.
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        returncode = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        returncode = process.wait()
            except OSError as error:
                launch_error = repr(error)
        stdout_data = (directory / "stdout").read_bytes()
        stderr_data = (directory / "stderr").read_bytes()
        result = {
            **specification,
            "label": label,
            "finished_utc": utc(),
            "elapsed_seconds": time.monotonic() - begin,
            "outer_process_exit": returncode,
            "timed_out": timed_out,
            "launch_error": launch_error,
            "stdout": {"bytes": len(stdout_data), "sha256": sha256(stdout_data)},
            "stderr": {"bytes": len(stderr_data), "sha256": sha256(stderr_data)},
            "logs_directory": str(directory),
        }
        save_json(directory / "result.json", result)
        self.commands.append(result)
        return result

    def identity(self, label: str) -> dict:
        values = {}
        commands = (
            ("commit", ["git", "rev-parse", "--verify", "HEAD"]),
            ("tree", ["git", "rev-parse", "--verify", "HEAD^{tree}"]),
            (
                "status",
                ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            ),
        )
        for key, argv in commands:
            result = self.run(f"{label}-{key}", argv, timeout=60)
            check(result["outer_process_exit"] == 0 and not result["timed_out"],
                  f"{label}: git {key} failed")
            data = (Path(result["logs_directory"]) / "stdout").read_bytes()
            values[key] = data if key == "status" else data.decode("ascii").strip()
        identity = {
            "commit": values["commit"],
            "tree": values["tree"],
            "clean": values["status"] == b"",
            "status_bytes": len(values["status"]),
            "status_sha256": sha256(values["status"]),
            "expected_identity": values["commit"] == self.commit
            and values["tree"] == self.tree,
        }
        save_json(self.evidence / f"{label}.json", identity)
        check(identity["expected_identity"], f"{label}: R2 source identity mismatch")
        check(identity["clean"], f"{label}: R2 source is not clean")
        return identity


def source_pins(commands: list[dict]) -> list[dict]:
    expected = {}
    for item in commands:
        for name in ("test_source", "implementation_source"):
            record = item[name]
            path, blob = record["path"], record["git_blob_sha"]
            check(path not in expected or expected[path] == blob, "conflicting source pin")
            expected[path] = blob
    result = []
    for relative, expected_blob in sorted(expected.items()):
        path = SOURCE / relative
        check(path.is_file() and not path.is_symlink(), f"missing regular source: {relative}")
        raw = path.read_bytes()
        actual_blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        result.append({
            "path": relative,
            "bytes": len(raw),
            "sha256": sha256(raw),
            "git_blob_sha": actual_blob,
            "expected_unchanged_blob_sha": expected_blob,
            "matches": actual_blob == expected_blob,
        })
    return result


def suite_result(command: dict, process: dict) -> dict:
    stderr = (Path(process["logs_directory"]) / "stderr").read_bytes().decode(
        "utf-8", errors="replace"
    )
    counts = re.findall(r"^Ran (\d+) tests? in .+$", stderr, flags=re.MULTILINE)
    terminal = re.findall(r"^(?:OK(?: \(.*\))?|FAILED(?: \(.*\))?)$", stderr,
                          flags=re.MULTILINE)
    actual_count = int(counts[0]) if len(counts) == 1 else None
    # An exact OK excludes skips, expected failures and unexpected successes.
    clean_ok = terminal == ["OK"]
    passed = (
        process["outer_process_exit"] == 0
        and not process["timed_out"]
        and process["launch_error"] is None
        and actual_count == command["expected_test_count"]
        and clean_ok
    )
    return {
        "id": command["id"],
        "expected_tests": command["expected_test_count"],
        "actual_tests": actual_count,
        "unittest_parent_exit": process["outer_process_exit"],
        "terminal_status_lines": terminal,
        "no_skips_or_expected_failures": clean_ok,
        "pass": passed,
        "command_result": process,
        "declared_child_semantics": command.get("module_failure_semantics"),
        "child_exit_scope": (
            "This result is the unittest parent process. Existing child CLI "
            "negative/HOLD exits are asserted inside unchanged tests; no child "
            "exit is substituted for the parent result. Per-child output is "
            "not independently instrumented beyond the suite's raw logs."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--command-manifest", required=True, type=Path)
    args = parser.parse_args()
    check(re.fullmatch(r"[0-9a-f]{40}", args.expected_commit) is not None,
          "an explicit full R2 commit is required")
    check(re.fullmatch(r"[0-9a-f]{40}", args.expected_tree) is not None,
          "an explicit full R2 tree is required")
    check(SOURCE.is_dir() and not SOURCE.is_symlink(), "source root unavailable")
    check(SOURCE not in EVIDENCE.parents, "evidence must be outside source")
    raw_manifest = args.command_manifest.read_bytes()
    check(sha256(raw_manifest) == MANIFEST_SHA256, "frozen command manifest changed")
    manifest = json.loads(raw_manifest)
    commands = manifest["commands"]
    check([(c["id"], c["expected_test_count"]) for c in commands] == list(ROSTER),
          "nine-suite / 255-test roster changed")
    for command in commands:
        expected_argv = [
            "python3", "-B", "-m", "unittest", "discover", "-s",
            "formal/pon-nakamoto-v1", "-p", command["id"] + ".py", "-v",
        ]
        check(command["argv"] == expected_argv, "unexpected suite command")
        check(command["cwd"] == str(SOURCE), "unexpected suite cwd")
        check(command["expected_process_exit"] == 0
              and command["expected_skipped_tests"] == 0, "unexpected suite contract")
    # Refuse to overwrite an earlier attempt, including a failed attempt.
    EVIDENCE.mkdir(parents=True, exist_ok=False)
    (EVIDENCE / "runner.py").write_bytes(Path(__file__).read_bytes())
    (EVIDENCE / "command-manifest.json").write_bytes(raw_manifest)
    recorder = Recorder(EVIDENCE, args.expected_commit, args.expected_tree)
    save_json(EVIDENCE / "invocation.json", {
        "argv": sys.argv,
        "python_executable": sys.executable,
        "python_version": sys.version,
        "source_root": str(SOURCE),
        "expected_commit": args.expected_commit,
        "expected_tree": args.expected_tree,
        "command_manifest_sha256": MANIFEST_SHA256,
        "runner_sha256": sha256(Path(__file__).read_bytes()),
        "started_utc": utc(),
        "scope": "Existing nine-suite finite-model roster only; no production qualification",
        "concurrent_load": CONCURRENT_LOAD,
    })
    source_before = None
    source_after = None
    before_pins = None
    after_pins = None
    preflight = None
    suites = []
    failures = []
    try:
        source_before = recorder.identity("source-before")
        preflight = recorder.run("preflight", ["bash", "scripts/project-preflight.sh"], 120)
        check(preflight["outer_process_exit"] == 0 and not preflight["timed_out"],
              "original project preflight failed")
        before_pins = source_pins(commands)
        save_json(EVIDENCE / "source-pins-before.json", before_pins)
        check(all(x["matches"] for x in before_pins), "finite model source pins changed")
        for number, command in enumerate(commands, 1):
            recorder.identity(f"suite-{number:02d}-source")
            process = recorder.run(command["id"], command["argv"], 180)
            outcome = suite_result(command, process)
            save_json(EVIDENCE / command["id"] / "suite.json", outcome)
            suites.append(outcome)
            print(json.dumps({
                "id": outcome["id"],
                "unittest_parent_exit": outcome["unittest_parent_exit"],
                "actual_tests": outcome["actual_tests"],
                "expected_tests": outcome["expected_tests"],
                "pass": outcome["pass"],
            }), flush=True)
    except Exception as error:
        failures.append({"stage": "execution", "error": repr(error),
                         "traceback": traceback.format_exc()})
    finally:
        try:
            source_after = recorder.identity("source-after")
            after_pins = source_pins(commands)
            save_json(EVIDENCE / "source-pins-after.json", after_pins)
            check(before_pins is not None and after_pins == before_pins,
                  "finite model source bytes changed or before pins unavailable")
        except Exception as error:
            failures.append({"stage": "after", "error": repr(error),
                             "traceback": traceback.format_exc()})
    all_pass = (
        not failures and len(suites) == len(ROSTER)
        and all(suite["pass"] for suite in suites)
        and sum(suite["actual_tests"] or 0 for suite in suites) == 255
        and source_before is not None and source_after is not None
    )
    summary = {
        "schema": "r2-def-finite-evidence-v1",
        "finished_utc": utc(),
        "expected_source_commit": args.expected_commit,
        "expected_source_tree": args.expected_tree,
        "source_before": source_before,
        "source_after": source_after,
        "preflight": preflight,
        "expected_modules": len(ROSTER),
        "actual_modules": len(suites),
        "expected_tests": 255,
        "actual_tests": sum(suite["actual_tests"] or 0 for suite in suites),
        "all_finite_suites_pass": all_pass,
        "suite_results": suites,
        "failures": failures,
        "commands": recorder.commands,
        "production_qualification": "HOLD_NO_GO",
        "concurrent_load": CONCURRENT_LOAD,
        "qualification_scope": (
            "Finite models and declared contract controls only. No all-legal-strategy "
            "lower bound, empirical upper bound, hidden-state premise, physical/quantum "
            "resource bound, original business deadline or mixed-consensus qualification."
        ),
    }
    save_json(EVIDENCE / "summary.json", summary)
    print(json.dumps({
        "summary": str(EVIDENCE / "summary.json"),
        "source_commit": args.expected_commit,
        "source_tree": args.expected_tree,
        "actual_modules": len(suites),
        "actual_tests": summary["actual_tests"],
        "all_finite_suites_pass": all_pass,
        "production_qualification": "HOLD_NO_GO",
    }), flush=True)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
