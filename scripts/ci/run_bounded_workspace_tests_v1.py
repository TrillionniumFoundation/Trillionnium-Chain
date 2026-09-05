#!/usr/bin/env python3
"""Run every active Rust workspace package with a hard per-package deadline.

The historical baseline used one opaque `cargo test --workspace --all-targets`
process. A single process-level deadlock could therefore consume the entire job
without identifying the responsible package. This runner preserves full active
workspace coverage while making each package observable and bounded.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import TextIO


@dataclass(frozen=True)
class PackageResult:
    name: str
    status: str
    elapsed_seconds: float
    returncode: int | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workspace-root",
        type=pathlib.Path,
        default=pathlib.Path("trillionnium"),
        help="directory containing the workspace Cargo.toml",
    )
    parser.add_argument(
        "--package-timeout-seconds",
        type=int,
        default=int(os.environ.get("TRNM_PACKAGE_TEST_TIMEOUT_SECONDS", "600")),
        help="hard wall-clock deadline for each package",
    )
    return parser.parse_args()


def workspace_packages(workspace_root: pathlib.Path, cargo: str) -> list[str]:
    command = [cargo, "metadata", "--format-version", "1", "--no-deps", "--locked"]
    completed = subprocess.run(
        command,
        cwd=workspace_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    metadata = json.loads(completed.stdout)
    members = set(metadata["workspace_members"])
    names = [
        package["name"]
        for package in metadata["packages"]
        if package["id"] in members
    ]
    if not names:
        raise RuntimeError("cargo metadata returned no active workspace packages")
    if len(names) != len(set(names)):
        raise RuntimeError("workspace contains duplicate package names")
    return sorted(names)


# A successful Cargo parent is insufficient when descendants still own pipes or
# remain alive. These bounds govern cleanup, not the test's acceptance threshold.
OUTPUT_DRAIN_SECONDS = 2
PROCESS_TERMINATE_SECONDS = 10


def pump_output(stream: TextIO, errors: list[Exception]) -> None:
    try:
        for line in iter(stream.readline, ""):
            sys.stdout.write(line)
            sys.stdout.flush()
    except Exception as error:
        errors.append(error)
    finally:
        try:
            stream.close()
        except Exception as error:
            errors.append(error)


def process_group_exists(process: subprocess.Popen[str]) -> bool:
    if os.name != "posix":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
        return True
    except ProcessLookupError:
        return False


def terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if os.name == "posix":
        # The group is created by start_new_session below. Its leader can have
        # exited while tests/children still hold stdout or ignore termination.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.terminate()

    try:
        process.wait(timeout=PROCESS_TERMINATE_SECONDS)
    except subprocess.TimeoutExpired:
        pass

    if os.name == "posix":
        # Do not return just because the Cargo parent exited on SIGTERM.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()
    process.wait(timeout=PROCESS_TERMINATE_SECONDS)


def run_package(
    workspace_root: pathlib.Path,
    cargo: str,
    package: str,
    timeout_seconds: int,
) -> PackageResult:
    command = [
        cargo,
        "test",
        "--package",
        package,
        "--all-targets",
        "--locked",
        "--no-fail-fast",
    ]
    environment = os.environ.copy()
    environment.setdefault("RUST_BACKTRACE", "1")

    print(f"::group::cargo test package={package} timeout={timeout_seconds}s", flush=True)
    print("command=" + " ".join(command), flush=True)
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=workspace_root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="backslashreplace",
        bufsize=1,
        start_new_session=(os.name == "posix"),
    )
    assert process.stdout is not None
    output_errors: list[Exception] = []
    output_thread = threading.Thread(
        target=pump_output,
        args=(process.stdout, output_errors),
        name=f"output-{package}",
        daemon=True,
    )
    output_thread.start()

    timed_out = False
    leaked_process = False
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        print(
            f"::error title=Rust package test timeout::{package} exceeded "
            f"{timeout_seconds}s; terminating its process group",
            flush=True,
        )
        terminate_process_tree(process)
        returncode = process.returncode
    except BaseException:
        terminate_process_tree(process)
        raise
    finally:
        output_thread.join(timeout=OUTPUT_DRAIN_SECONDS)
        if output_thread.is_alive() or process_group_exists(process):
            leaked_process = True
            print(
                f"::error title=Rust package process leak::{package} left descendants "
                "or an open output pipe after its Cargo parent ended",
                flush=True,
            )
            terminate_process_tree(process)
            output_thread.join(timeout=PROCESS_TERMINATE_SECONDS)
        if output_thread.is_alive():
            output_errors.append(RuntimeError("output pipe did not close after group cleanup"))
        if output_errors:
            print(f"::error title=Rust package output failure::{package}: {output_errors!r}", flush=True)
        print("::endgroup::", flush=True)

    elapsed = time.monotonic() - started
    if timed_out:
        status = "timeout"
    elif leaked_process or output_errors:
        status = "failed"
    elif returncode == 0:
        status = "success"
    else:
        status = "failed"
    return PackageResult(package, status, elapsed, returncode)


def main() -> int:
    args = parse_args()
    workspace_root = args.workspace_root.resolve()
    if args.package_timeout_seconds <= 0:
        raise ValueError("--package-timeout-seconds must be positive")
    if not (workspace_root / "Cargo.toml").is_file():
        raise FileNotFoundError(f"workspace Cargo.toml not found under {workspace_root}")

    cargo = os.environ.get("CARGO", "cargo")
    packages = workspace_packages(workspace_root, cargo)
    print(
        f"bounded_workspace_tests package_count={len(packages)} "
        f"package_timeout_seconds={args.package_timeout_seconds}",
        flush=True,
    )

    results: list[PackageResult] = []
    for index, package in enumerate(packages, start=1):
        print(f"package_progress={index}/{len(packages)} package={package}", flush=True)
        results.append(
            run_package(
                workspace_root,
                cargo,
                package,
                args.package_timeout_seconds,
            )
        )

    print("bounded_workspace_tests_summary", flush=True)
    for result in results:
        print(
            f"package={result.name} status={result.status} "
            f"elapsed_seconds={result.elapsed_seconds:.3f} "
            f"returncode={result.returncode}",
            flush=True,
        )

    failures = [result for result in results if result.status != "success"]
    if failures:
        print(
            "::error title=Rust workspace package failures::"
            + ", ".join(f"{item.name}:{item.status}" for item in failures),
            flush=True,
        )
        return 1

    print(f"bounded_workspace_tests_ok package_count={len(results)}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"::error title=Bounded workspace test runner setup failure::{error}", file=sys.stderr)
        raise SystemExit(2) from error
