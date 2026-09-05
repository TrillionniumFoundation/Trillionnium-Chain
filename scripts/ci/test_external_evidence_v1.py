#!/usr/bin/env python3
"""Run structural-intake and authentication regressions in bounded processes."""
from __future__ import annotations

import os
import pathlib
import signal
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
MODULES = (
    "test_external_evidence_intake_v1",
    "test_external_evidence_authentication_core_v1",
    "test_external_evidence_authentication_policy_v1",
    "test_external_evidence_authentication_artifact_v1",
    "test_external_evidence_authentication_encoding_v1",
)
SUITE_TIMEOUT_SECONDS = 180
DRIVER = r'''
import importlib, os, sys, unittest
module = importlib.import_module(sys.argv[1])
suite = unittest.defaultTestLoader.loadTestsFromModule(module)
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.stdout.flush()
sys.stderr.flush()
os._exit(0 if result.wasSuccessful() else 1)
'''


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def main() -> int:
    started: dict[str, float] = {}
    processes: dict[str, subprocess.Popen[bytes]] = {}
    for module in MODULES:
        print(f"external evidence suite start: {module}", file=sys.stderr, flush=True)
        started[module] = time.monotonic()
        processes[module] = subprocess.Popen(
            [sys.executable, "-c", DRIVER, module],
            cwd=ROOT,
            start_new_session=True,
        )

    failures: list[str] = []
    pending = set(MODULES)
    try:
        while pending:
            for module in tuple(pending):
                process = processes[module]
                returncode = process.poll()
                if returncode is not None:
                    pending.remove(module)
                    if returncode == 0:
                        print(f"external evidence suite passed: {module}", file=sys.stderr, flush=True)
                    else:
                        failures.append(f"{module}: returncode={returncode}")
                    continue
                if time.monotonic() - started[module] > SUITE_TIMEOUT_SECONDS:
                    terminate_group(process)
                    pending.remove(module)
                    failures.append(f"{module}: timed out")
            if pending:
                time.sleep(0.05)
    finally:
        for module in pending:
            terminate_group(processes[module])

    for failure in failures:
        print(f"external evidence suite failed: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
