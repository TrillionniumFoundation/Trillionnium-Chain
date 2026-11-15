#!/usr/bin/env python3
"""Qualify full classical request bytes; separately require the original Rust oracle in CI."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-rust-oracle", action="store_true")
    parser.add_argument("--repository", type=Path, default=ROOT,
                        help="Original repository, also used for exact shared helpers")
    parser.add_argument("--components", type=Path,
                        help="Explicit manifest for an isolated promotion overlay; default repository manifest")
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    sys.path[:0] = [str(ROOT), str(repository)]
    from hia.platform.build import new_output, run_native, sha256, write_json
    from hia.platform.transport_request.build import Build
    from hia.platform.transport_request.cases import Fixture, canonical, cases
    from hia.platform.transport_request.rust_oracle import RustOracle
    output = new_output(args.output)
    started = time.monotonic_ns()
    report = {"schema": "trnm.hia.transport-request-qualification.v1", "status": "RUNNING",
        "native_peer_or_socket_owner": False, "durable_replay_owner": False,
        "whole_chain_native": False, "old_stack_can_be_removed": False,
        "response_value_codec": "OPEN", "pq_selection_and_authentication": "OPEN",
        "runtime_host_proxy": False, "request_controls": [], "sha256_stream_controls": [],
        "original_rust_oracle": {"status": "NOT_RUN", "reason":
            "Independent targeted Cargo oracle not requested; no Rust differential claim"}}
    try:
        builder = Build(output / "build", repository, args.components)
        request_image, request_build = builder.kernel("request")
        sha_image, sha_build = builder.kernel("sha256_stream")
        report["request_build"] = request_build
        report["sha256_stream_build"] = sha_build
        # Independent block/length/split controls use the same final HIA stream
        # source that supplies all authority and payload hashing in the kernel.
        sha_rows = report["sha256_stream_controls"]
        sha_cases = []
        for size, step in [(0, 1), (3, 1), (55, 7), (56, 64), (63, 1),
                (64, 65536), (65, 3), (131137, 4093), (2097152, 65536),
                (2098176, 2098176)]:
            payload = bytes((i * 131 + 17) & 255 for i in range(size))
            expected = hashlib.sha256(payload).digest() + struct.pack("<QQ", size, 1)
            sha_cases.append((f"bytes-{size}-step-{step}", struct.pack("<Q", step) + payload, 0, expected))
        sha_cases += [("truncated-step", b"\0" * 7, 101, None),
            ("zero-step", bytes(8), 102, None),
            ("excess-step", struct.pack("<Q", 2098177), 102, None),
            ("excess-total", struct.pack("<Q", 65536) + b"x" * 2098177, 103, None)]
        for index, (name, payload, expected_code, expected) in enumerate(sha_cases):
            raw, receipt = run_native(sha_image, payload, output, f"sha-{index:02d}-{name}")
            code = int.from_bytes(raw[:8], "little") if len(raw) >= 8 else None
            exact = (raw[8:56] == expected and raw[56:] == b"\xa5" * 464
                     if expected is not None else raw[8:] == b"\xa5" * 512)
            good = (not receipt["timed_out"] and receipt["exit_code"] == 0
                    and not receipt["stderr_hex"] and len(raw) == 520
                    and code == expected_code and exact)
            sha_rows.append({"name": name, "status": "PASS" if good else "FAIL",
                "expected_code": expected_code, "actual_code": code,
                "exact_output_and_unchanged_canary": exact, "receipt": receipt})
            if not good:
                raise ValueError("Native incremental SHA256 control failed: " + name)
        oracle = None
        context = None
        if args.require_rust_oracle:
            oracle = RustOracle(repository, output / "original-rust")
            context = oracle.describe()
            fixture = Fixture(context=context)
            golden_requests = [{"op": "head"}, {"op": "submit", "packet": "deadbeef"},
                {"op": "history", "tip": "UPPERCASE", "after": ""},
                {"op": "confirm", "transaction": "x", "block": ""},
                {"op": "confirm_many", "queries": [{"transaction": "x", "block": "y"}]}]
            expected = [canonical(fixture.envelope(request)).hex() for request in golden_requests]
            if context["original_request_goldens"] != expected:
                raise ValueError("Original Rust-generated five-variant wire differs from the independent corpus")
            report["original_settings_context"] = context
        corpus = cases(context=context)
        request_rows = report["request_controls"]
        for index, case in enumerate(corpus):
            raw, receipt = run_native(request_image, case["input"], output,
                f"request-{index:03d}-" + case["name"], timeout=30)
            code = int.from_bytes(raw[:8], "little") if len(raw) >= 8 else None
            exact = (raw[8:392] == case["expected_output"] and raw[392:] == b"\xa5" * 128
                     if case["expected_code"] == 0 else raw[8:] == b"\xa5" * 512)
            good = (not receipt["timed_out"] and receipt["exit_code"] == 0
                    and not receipt["stderr_hex"] and len(raw) == 520
                    and code == case["expected_code"] and exact)
            row = {"name": case["name"], "status": "PASS" if good else "FAIL",
                "expected_code": case["expected_code"], "actual_code": code,
                "exact_output_and_unchanged_canary": exact,
                "original_body_bytes": len(case["body"]), "receipt": receipt}
            request_rows.append(row)
            print(json.dumps({key: row[key] for key in ("name", "status", "actual_code")}), flush=True)
            if not good:
                raise ValueError("Native request control failed: " + case["name"])
        if oracle is not None:
            report["original_rust_oracle"] = oracle.verify(corpus, request_rows)
        report["build"] = builder.receipt()
        report.update(status="PASS" if oracle is not None else "NATIVE_PASS_RUST_NOT_RUN",
            request_controls_passed=len(request_rows), request_controls_failed=0,
            sha256_stream_controls_passed=len(sha_rows), sha256_stream_controls_failed=0,
            elapsed_ns=time.monotonic_ns() - started)
        write_json(output / "report.json", report)
        print(json.dumps({"status": report["status"], "request": len(request_rows),
            "sha256_stream": len(sha_rows), "report": str(output / "report.json")}), flush=True)
        return 0
    except BaseException as error:
        report.update(status="FAIL", failure_type=type(error).__name__, failure=str(error),
                      elapsed_ns=time.monotonic_ns() - started)
        write_json(output / "report.json", report)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
