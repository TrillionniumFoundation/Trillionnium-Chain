#!/usr/bin/env python3
"""Run the original 32 SQLite controls and scoped Clippy on a frozen source.

This driver never edits the checkout or selects a source implicitly. Each command
uses the repository's complete tracked-byte recorder. Retained tests use its
Linux ELF pin and named-libtest checker. Receipt directories are create-only.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def save_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def checked_version(executable, expected, env, cwd):
    result = subprocess.run([str(executable), "--version", "--verbose"],
                            cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.startswith(expected):
        raise ValueError("unexpected tool version: " + str(executable))
    return {"path": str(executable), "sha256": digest(executable),
            "stdout": result.stdout, "stderr": result.stderr}


def checked_clippy(cargo, env, cwd):
    launcher = cargo.parent / "cargo-clippy"
    driver = cargo.parent / "clippy-driver"
    if not launcher.is_file() or not driver.is_file():
        raise ValueError("the explicit Rust 1.95 toolchain must contain Clippy")
    result = subprocess.run([str(cargo), "clippy", "--version"], cwd=cwd, env=env,
                            capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.startswith("clippy 0.1.95 "):
        raise ValueError("Cargo selected a different Clippy toolchain")
    return {"launcher": str(launcher), "launcher_sha256": digest(launcher),
            "driver": str(driver), "driver_sha256": digest(driver),
            "stdout": result.stdout, "stderr": result.stderr}


def validate_focused(log, expected_names):
    text = log.read_text()
    runs = re.findall(r"^running ([0-9]+) tests?$", text, re.MULTILINE)
    names = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\.", text, re.MULTILINE)
    summaries = re.findall(
        r"^test result: (\w+)\. ([0-9]+) passed; ([0-9]+) failed; "
        r"([0-9]+) ignored; ([0-9]+) measured; [0-9]+ filtered out; "
        r"finished in [0-9]+(?:\.[0-9]+)?s$", text, re.MULTILINE)
    count = len(expected_names)
    if runs != [str(count)] or len(names) != count or sorted(names) != sorted(expected_names):
        raise ValueError("missing, duplicated or unexpected focused test identity")
    if summaries != [("ok", str(count), "0", "0", "0")]:
        raise ValueError("focused tests did not all pass with zero ignored/measured")
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("the retained-test executable pin requires Linux")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        parser.error("--source must be the explicit frozen 40-character commit")
    for name in ("repo", "output", "plan", "cargo", "rustc", "cargo_home", "target"):
        if not getattr(args, name).is_absolute():
            parser.error("all paths must be absolute: " + name)
    repo = args.repo.resolve()
    output = args.output.resolve()
    if output.is_relative_to(repo):
        parser.error("records must be outside the source checkout")
    if digest(args.plan) != args.plan_sha256:
        parser.error("plan bytes differ from the supplied hash")
    plan = json.loads(args.plan.read_text())
    if plan["schema"] != "trnm-sqlite-fixed-plan-v1":
        parser.error("unsupported plan schema")
    if sum(len(row["tests"]) for row in plan["focused"]) != 17:
        parser.error("focused roster does not contain 17 tests")
    if sum(len(names) for names in plan["retained"].values()) != 15:
        parser.error("retained roster does not contain 15 tests")
    output.mkdir(parents=True, exist_ok=False)
    summary_path = output / "driver-summary.json"
    summary = {
        "schema": "trnm-sqlite-fixed-run-v1", "status": "running",
        "source_expected": args.source, "repo": str(repo),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "driver_sha256": digest(Path(__file__).resolve()),
        "plan_sha256": args.plan_sha256, "steps": [], "binaries": {},
        "focused_passed": 0, "retained_passed": 0, "strict_clippy_passed": False,
        "acceptance_granted": False, "production_activation": False,
        "whole_chain_quantum_security_qualified": False,
    }
    save_json(summary_path, summary)
    env = os.environ.copy()
    env.update({"RUSTC": str(args.rustc), "CARGO_HOME": str(args.cargo_home),
                "CARGO_TARGET_DIR": str(args.target), "CARGO_BUILD_JOBS": str(args.jobs),
                "CARGO_TERM_COLOR": "never", "PATH": str(args.cargo.parent) + ":" + env["PATH"]})
    summary["environment"] = {key: env.get(key) for key in (
        "RUSTC", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_PROFILE_TEST_OPT_LEVEL",
        "OPENSSL_DIR", "OPENSSL_STATIC", "TRNM_PQ_OPENSSL", "TRNM_PQ_OPENSSL_SHA256")}
    recorder = repo / "scripts/ci/record_pq_native_command.py"
    named_checker = repo / "scripts/ci/check_required_native_test.py"

    def execute(label, argv, executable_pin=None):
        step = {"label": label, "argv": argv, "status": "preflight", "exit_code": None}
        summary["steps"].append(step)
        save_json(summary_path, summary)
        print(json.dumps({"event": "start", "label": label, "source": args.source}), flush=True)
        with (output / (label + ".preflight.log")).open("xb") as stream:
            preflight = subprocess.run(["bash", "scripts/project-preflight.sh"], cwd=repo,
                                       env=env, stdout=stream, stderr=subprocess.STDOUT)
        step["preflight_exit"] = preflight.returncode
        if preflight.returncode != 0:
            step["status"] = "preflight_failed"
            raise ValueError("project preflight failed: " + label)
        wrapper = [sys.executable, str(recorder), "--kind", "head", "--candidate", args.source,
                   "--tested", args.source, "--label", label, "--output", str(output)]
        if executable_pin is not None:
            wrapper += ["--native-executable-sha256", executable_pin]
        wrapper += ["--", *argv]
        step["recorder_argv"] = wrapper
        step["status"] = "command_running"
        save_json(summary_path, summary)
        with (output / (label + ".recorder.stdout")).open("xb") as stdout, \
             (output / (label + ".recorder.stderr")).open("xb") as stderr:
            result = subprocess.run(wrapper, cwd=repo, env=env, stdout=stdout, stderr=stderr)
        step["recorder_exit"] = result.returncode
        receipt_path = output / (label + ".json")
        if not receipt_path.is_file():
            step["status"] = "no_terminal_receipt"
            raise ValueError("recorder did not publish a receipt: " + label)
        receipt = json.loads(receipt_path.read_text())
        step["receipt"] = receipt_path.name
        step["receipt_sha256"] = digest(receipt_path)
        step["exit_code"] = receipt.get("exit_code")
        step["status"] = receipt.get("status", "missing_status")
        save_json(summary_path, summary)
        if result.returncode != 0 or receipt.get("status") != "command_succeeded" or receipt.get("exit_code") != 0:
            raise ValueError("source recorder or actual command failed: " + label)
        if receipt.get("argv") != argv:
            raise ValueError("recorded argv differs: " + label)
        if receipt.get("before") != receipt.get("after"):
            raise ValueError("source changed during command: " + label)
        if receipt["before"].get("tested_commit") != args.source:
            raise ValueError("wrong native source identity: " + label)
        if receipt["before"].get("tracked_worktree_verified") is not True:
            raise ValueError("full tracked-source bytes were not verified: " + label)
        log = output / receipt["log_file"]
        if digest(log) != receipt["log_sha256"] or log.stat().st_size != receipt["log_bytes"]:
            raise ValueError("recorded log bytes differ: " + label)
        if executable_pin is not None and receipt.get("native_execution", {}).get("status") != "PINNED_AND_OBSERVED":
            raise ValueError("native executable was not pinned and observed: " + label)
        print(json.dumps({"event": "command_succeeded", "label": label,
                          "receipt": str(receipt_path)}), flush=True)
        return log

    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        if head != args.source:
            raise ValueError("checkout HEAD differs from explicit frozen source")
        summary["toolchain"] = {
            "cargo": checked_version(args.cargo, "cargo 1.95.0 ", env, repo),
            "rustc": checked_version(args.rustc, "rustc 1.95.0 ", env, repo),
            "clippy": checked_clippy(args.cargo, env, repo),
        }
        save_json(summary_path, summary)
        for item in plan["focused"]:
            package = item["package"]
            argv = [str(args.cargo), "test", "--manifest-path", "trillionnium/Cargo.toml",
                    "--locked", "--offline", "-p", package, "--lib", "sqlite_",
                    "--", "--nocapture", "--test-threads=1"]
            log = execute("sqlite-focused-" + package, argv)
            summary["focused_passed"] += validate_focused(log, item["tests"])
            paths = re.findall(r"Running unittests[^\n]*\(([^)\n]+)\)", log.read_text())
            if len(paths) != 1:
                raise ValueError("expected exactly one current Cargo libtest executable: " + package)
            executable = Path(paths[0])
            if not executable.is_absolute():
                executable = repo / executable
            executable = executable.resolve()
            if not executable.is_relative_to(args.target.resolve()) or not executable.is_file():
                raise ValueError("Cargo executable is outside the selected target: " + package)
            if not re.fullmatch(re.escape(package.replace("-", "_")) + r"-[0-9a-f]{16}", executable.name):
                raise ValueError("unexpected Cargo test executable name: " + package)
            with executable.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    raise ValueError("Cargo test output is not a native ELF: " + package)
            summary["binaries"][package] = {"path": str(executable), "sha256": digest(executable),
                                                "bytes": executable.stat().st_size}
            save_json(summary_path, summary)

        for package, tests in plan["retained"].items():
            binary = summary["binaries"][package]
            executable = Path(binary["path"])
            for index, name in enumerate(tests, start=1):
                if digest(executable) != binary["sha256"]:
                    raise ValueError("compiled ELF changed before retained invocation: " + package)
                label = "sqlite-retained-" + package + "-" + str(index)
                argv = [str(executable), "--exact", name, "--nocapture", "--test-threads=1"]
                log = execute(label, argv, binary["sha256"])
                checker_argv = [sys.executable, str(named_checker), str(log), "--test", name]
                with (output / (label + ".named.stdout")).open("xb") as stdout, \
                     (output / (label + ".named.stderr")).open("xb") as stderr:
                    check = subprocess.run(checker_argv, cwd=repo, env=env, stdout=stdout, stderr=stderr)
                summary["steps"][-1]["named_test"] = name
                summary["steps"][-1]["named_checker_exit"] = check.returncode
                if check.returncode != 0:
                    raise ValueError("exact named execution check failed: " + name)
                summary["retained_passed"] += 1
                save_json(summary_path, summary)

        argv = [str(args.cargo), "clippy", "--manifest-path", "trillionnium/Cargo.toml", "--locked", "--offline"]
        for item in plan["focused"]:
            argv += ["-p", item["package"]]
        argv += ["--all-targets", "--", "-D", "warnings"]
        execute("sqlite-strict-four-package-clippy", argv)
        summary["strict_clippy_passed"] = True
        if summary["focused_passed"] != 17 or summary["retained_passed"] != 15:
            raise ValueError("incomplete native invocation roster")
        summary["status"] = "command_set_succeeded"
        code = 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        summary["status"] = "command_set_failed"
        summary["error"] = str(error)
        code = 1
    except KeyboardInterrupt:
        summary["status"] = "interrupted"
        summary["error"] = "controller interrupted; no completion synthesized"
        code = 130
    finally:
        summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save_json(summary_path, summary)
        print(json.dumps({"event": "finished", "status": summary["status"],
                          "focused_passed": summary["focused_passed"],
                          "retained_passed": summary["retained_passed"],
                          "strict_clippy_passed": summary["strict_clippy_passed"],
                          "summary": str(summary_path), "acceptance_granted": False}), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
