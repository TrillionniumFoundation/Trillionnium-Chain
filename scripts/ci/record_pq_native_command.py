#!/usr/bin/env python3
"""Record one command and its exact source; successful exit is not PQ acceptance.

The existing source verifier checks every tracked raw byte before and after the
command. Named libtest executions still require check_required_native_test.py.
Abrupt termination leaves an incomplete receipt, never a synthesized success.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from verify_ci_source import ROOT, verify
from pinned_native_process import SCHEMA as NATIVE_PROCESS_SCHEMA, run_pinned


def run(args, root=ROOT):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", args.label):
        raise ValueError("noncanonical command label")
    if not args.command:
        raise ValueError("missing command")
    if (not args.output.is_absolute()
            or args.output.resolve().is_relative_to(root.resolve())):
        raise ValueError("command records must be outside source")
    args.output.mkdir(parents=True, exist_ok=True)
    receipt = args.output / (args.label + ".json")
    log = args.output / (args.label + ".log")
    record = {
        "schema": "trnm-pq-native-command-v1", "status": "running",
        "argv": args.command, "cwd": str(root), "exit_code": None,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "log_file": log.name, "log_sha256": None,
        "whole_chain_quantum_security_qualified": False,
        "environment": {key: os.environ.get(key) for key in (
            "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_TARGET_DIR",
            "RUST_TEST_THREADS", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "OPENSSL_DIR", "OPENSSL_STATIC", "TRNM_PQ_OPENSSL",
            "TRNM_PQ_OPENSSL_SHA256", "TRNM_PQ_OPENSSL_VERSION",
            "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_ARCH")},
    }
    executable_pin = getattr(args, "native_executable_sha256", None)
    if executable_pin is not None:
        record["native_execution"] = {"schema": NATIVE_PROCESS_SCHEMA,
                                      "status": "NOT_STARTED",
                                      "expected_sha256": executable_pin}
    with receipt.open("x", encoding="utf-8") as stream:
        json.dump(record, stream)
    code = 1
    started = time.monotonic_ns()
    try:
        record["before"] = verify(args.kind, args.candidate,
                                  args.base if args.kind == "prospective-merge" else None,
                                  args.tested if args.kind == "prospective-merge" else None,
                                  root)
        if record["before"]["tested_commit"] != args.tested:
            raise ValueError("tested commit differs from requested source")
        with log.open("xb") as stream:
            if executable_pin is None:
                code = subprocess.run(args.command, cwd=root, stdout=stream,
                                      stderr=subprocess.STDOUT, check=False).returncode
            else:
                code, record["native_execution"] = run_pinned(
                    args.command, root, stream, executable_pin)
        record["exit_code"] = code
        with log.open("rb") as stream:
            record["log_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        record["log_bytes"] = log.stat().st_size
        record["after"] = verify(args.kind, args.candidate,
                                 args.base if args.kind == "prospective-merge" else None,
                                 args.tested if args.kind == "prospective-merge" else None,
                                 root)
        if record["before"] != record["after"]:
            raise ValueError("source identity changed during command")
        if (executable_pin is not None
                and record["native_execution"]["status"] != "PINNED_AND_OBSERVED"):
            raise ValueError("native executable identity was not completely observed")
        record["status"] = "command_succeeded" if code == 0 else "command_failed"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record.update(status="record_failed", error=str(error))
        code = code or 1
    finally:
        record["elapsed_ns"] = time.monotonic_ns() - started
        receipt.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"status": record["status"], "receipt": str(receipt),
                      "exit_code": record["exit_code"]}, sort_keys=True))
    return code if code >= 0 else 128 - code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("head", "prospective-merge"), required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--tested", required=True)
    parser.add_argument("--base")
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-executable-sha256",
                        help="opt-in direct Linux ELF pin and live executable observation; not a performance profile")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
