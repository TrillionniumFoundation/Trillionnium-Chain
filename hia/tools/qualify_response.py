#!/usr/bin/env python3
"""Qualify complete classical response bytes and require the retained Rust oracle in CI."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=ROOT,
        help="Retained original Cargo sources; HIA composition always belongs to this script's source tree")
    parser.add_argument("--require-rust-oracle", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    sys.path.insert(0, str(ROOT))
    from hia.platform.build import new_output, run_native, sha256, write_json
    from hia.platform.transport_response.build import Build, KERNELS
    from hia.platform.transport_response.cases import (
        ResponseFixture, encoding_cases, encoding_negatives, verification_cases, signing_cases,
    )
    from hia.platform.transport_response.numbers import bits, float_cases, number_candidates, number_reference
    from hia.platform.transport_response.values import value_encode_cases, value_wire_cases, value_wire_reference
    from hia.platform.transport_response.rust_oracle import RustOracle
    from hia.platform.transport_request.cases import Fixture, canonical
    from hia.platform.private_stack.deny_cleanup import observe as observe_cleanup_denial
    output = new_output(args.output)
    started = time.monotonic_ns()
    groups = {name: [] for name in ("power", "number", "value_wire", "value_encode", "sign", "encode", "verify", "fixture_guards")}
    report = {"schema": "trnm.hia.transport-response-qualification.v1", "status": "RUNNING",
        "controls": groups, "runtime_host_proxy": False, "python_test_driver": sys.version,
        "whole_chain_native": False, "old_stack_can_be_removed": False,
        "original_rust_oracle": {"status": "NOT_RUN", "reason":
            "Retained targeted Cargo oracle not requested; no Rust differential claim"},
        "boundaries": {"application_dispatch_owner": "OPEN", "socket_and_verified_peer_owner": "OPEN",
            "terminal_commit_and_replay_owner": "OPEN", "private_key_owner": "OPEN",
            "constant_time_machine_code_proof": "OPEN", "raw_signing_kernel_stack_erasure": "FAIL_OBSERVED",
            "pq_selection_and_authentication": "OPEN"}}
    try:
        builder = Build(output / "build", repository)
        images = {name: builder.kernel(name)[0] for name in KERNELS}
        oracle = RustOracle(repository, output / "original-rust") if args.require_rust_oracle else None
        context = oracle.describe() if oracle is not None else None
        if context is not None:
            fixture = Fixture(context=context)
            requests = [{"op": "head"}, {"op": "submit", "packet": "deadbeef"},
                {"op": "history", "tip": "UPPERCASE", "after": ""},
                {"op": "confirm", "transaction": "x", "block": ""},
                {"op": "confirm_many", "queries": [{"transaction": "x", "block": "y"}]}]
            if context["original_request_goldens"] != [canonical(fixture.envelope(request)).hex() for request in requests]:
                raise ValueError("Five original request authorities differ from independent response fixtures")
            report["original_settings_context"] = context
        differential = {name: [] for name in ("number", "value_wire", "value_encode", "sign", "produce", "verify")}
        exclusions = {"number_token_leading_or_trailing_whitespace": [], "new_value_wire_container": [],
            "new_typed_value_container": [], "new_signer_container": [], "new_producer_container": [],
            "new_verifier_context_container": []}

        def check(kernel, group, name, payload, code, expected=b"", *, variable=False):
            raw, receipt = run_native(images[kernel], payload, output, group + "-" + name, timeout=30)
            wanted = struct.pack("<Q", code) + expected
            if not variable:
                wanted += b"\xa5" * (512 - len(expected))
            actual_code = int.from_bytes(raw[:8], "little") if len(raw) >= 8 else None
            good = (raw == wanted and receipt["exit_code"] == 0 and not receipt["timed_out"]
                    and not receipt["stderr_hex"])
            result = raw[8:8 + len(expected)]
            row = {"name": name, "status": "PASS" if good else "FAIL", "expected_code": code,
                "actual_code": actual_code, "input_bytes": len(payload), "input_sha256": sha256(payload),
                "result_bytes": len(result), "result_sha256": sha256(result),
                "exact_output_and_unused_tail": good, "receipt": receipt}
            groups[group].append(row)
            if not good:
                row.update(expected_prefix=wanted[:160].hex(), actual_prefix=raw[:160].hex())
                raise ValueError("Actual native response control failed: " + group + "/" + name)
            return row

        for exponent in range(309):
            payload = b"\1" + struct.pack("<Q", exponent)
            expected = struct.pack("<Q", bits(float("1e" + str(exponent))))
            check("number", "power", str(exponent), payload, 0, expected)
        print("native response: 309 rounded powers PASS", flush=True)
        for index, payload in enumerate(number_candidates()):
            name = f"number-{index:05d}"
            try:
                value, kind, canon, rendered = number_reference(payload)
                code = 0
                expected = struct.pack("<4Q", value, kind, canon, len(rendered)) + rendered.ljust(24, b"\0")
            except (ValueError, UnicodeError):
                code, expected = 102, b""
            check("number", "number", name, b"\0" + payload, code, expected)
            if payload[:1] in (b" ", b"\t", b"\r", b"\n") or payload[-1:] in (b" ", b"\t", b"\r", b"\n"):
                exclusions["number_token_leading_or_trailing_whitespace"].append(name)
            else:
                differential["number"].append(dict(name=name, input=payload, expected_code=code, expected_output=expected))
            if index % 1000 == 0:
                print("native response numbers", index + 1, flush=True)
        for index, payload in enumerate(value_wire_cases()):
            for outer in (0, 1):
                name = f"value-{index:04d}-{outer}"
                code = 101 if not payload or len(payload) > 2097152 else value_wire_reference(payload, outer)
                captured = bytes([outer]) + payload
                check("value_wire", "value_wire", name, captured, code)
                if code >= 100:
                    exclusions["new_value_wire_container"].append(name)
                else:
                    differential["value_wire"].append(dict(name=name, input=captured, expected_code=code, expected_output=b""))
            if index % 500 == 0:
                print("native response Value parse", (index + 1) * 2, flush=True)
        for name, payload, expected in value_encode_cases():
            if isinstance(expected, int):
                code, logical = expected, b""
                exclusions["new_typed_value_container"].append(name)
            else:
                code, logical = len(expected), expected
                differential["value_encode"].append(dict(name=name, input=payload, expected_code=code, expected_output=logical))
            check("value_encode", "value_encode", name, payload, code, logical, variable=True)
        report["finite_f64_values_in_complete_value_array"] = len(float_cases())
        print("native response complete Value encoding", len(groups["value_encode"]), "PASS", flush=True)
        for index, case in enumerate(signing_cases()):
            check("sign", "sign", case["name"], case["input"], 0, case["expected_output"])
            differential["sign"].append(dict(case, expected_code=0))
            if index % 8 == 0:
                print("native response signing vectors", index + 1, flush=True)
        for index, payload in enumerate((b"", b"x" * 31, b"x" * 32, b"x" * 63, b"x" * 65, b"x" * 100)):
            name = f"input-shape-{index}"
            check("sign", "sign", name, payload, 100)
            exclusions["new_signer_container"].append(name)
        positives = encoding_cases(context=context)
        for case in positives:
            frame = case["expected_frame"]
            check("encode", "encode", case["name"], case["input"], len(frame), frame, variable=True)
            differential["produce"].append(dict(name=case["name"], input=case["input"],
                expected_code=len(frame), expected_output=frame, request=case["fixture"].request))
            print("native response framing/signing", case["name"], len(frame), flush=True)
        for case in encoding_negatives(context=context):
            check("encode", "encode", case["name"], case["input"], case["expected_code"], variable=True)
            if case["name"] in {"over-body-limit", "valid-value-over-limit-string", "valid-value-over-limit-dense"}:
                differential["produce"].append(dict(case, expected_output=b"", request={"op": "head"}))
            else:
                exclusions["new_producer_container"].append(case["name"])
        for case in verification_cases(context=context, encoded=positives):
            check("verify", "verify", case["name"], case["input"], case["expected_code"], case["expected_output"] or b"")
            if case["expected_code"] >= 100:
                exclusions["new_verifier_context_container"].append(case["name"])
            else:
                differential["verify"].append(dict(case, expected_output=case["expected_output"] or b""))
        # The intentionally bad kernel is test-only HIA. These observed native
        # refusals validate the adapter's publication guard independently of
        # production kernels choosing not to touch their output on failure.
        for mode, label, exit_code, expected in (
                (0, "valid-one-byte", 0, struct.pack("<Q", 1) + b"X"),
                (1, "error-after-output-write", 70, b""),
                (2, "unused-output-tail-write", 70, b""),
                (3, "invalid-return-length", 70, b"")):
            raw, receipt = run_native(images["fixture_contract"], bytes([mode]), output, "guard-" + label)
            good = raw == expected and receipt["exit_code"] == exit_code and not receipt["timed_out"] and not receipt["stderr_hex"]
            groups["fixture_guards"].append({"name": label, "status": "PASS" if good else "FAIL", "receipt": receipt})
            if not good:
                raise ValueError("Variable output native guard failed: " + label)
        raw, receipt = run_native(images["fixture_contract"], b"\4", output, "guard-actual-bounds-trap")
        good = receipt["exit_code"] == -4 and not receipt["timed_out"] and not raw and not receipt["stderr_hex"]
        groups["fixture_guards"].append({"name": "actual-bounds-trap", "status": "PASS" if good else "FAIL", "receipt": receipt})
        if not good:
            raise ValueError("Actual checked HIA out-of-bounds operation did not refuse")
        image = (builder.output / "fixture_contract.flat").read_bytes()
        raw, receipt = run_native(builder.emitters["variable"], struct.pack("<Q", 2) + image,
            output, "guard-invalid-emitter-profile")
        good = receipt["exit_code"] == 3 and not receipt["timed_out"] and not raw and not receipt["stderr_hex"]
        groups["fixture_guards"].append({"name": "invalid-emitter-profile", "status": "PASS" if good else "FAIL", "receipt": receipt})
        if not good:
            raise ValueError("Unrecognized HIA emitter profile did not refuse")
        # Real OS cleanup failure occurs after the complete producer has signed.
        # Its unchanged outer native fixture must withhold every output byte.
        raw, receipt = observe_cleanup_denial(images["encode"], positives[0]["input"],
            output / "guard-producer-real-cleanup-denial")
        good = (receipt["exit_code"] == 70 and not receipt["timed_out"]
            and not receipt["stderr_hex"] and raw == b"")
        groups["fixture_guards"].append({"name": "producer-real-munmap-denial",
            "status": "PASS" if good else "FAIL", "receipt": receipt})
        if not good:
            raise ValueError("Real producer cleanup denial published output or did not refuse")
        report["producer_private_stack_normal_return"] = "HIA_GUARDED"
        report["producer_late_cleanup_error_output_publication"] = "REFUSED_ACTUAL_OS_DENIAL"
        report["rust_domain_exclusions"] = exclusions
        if oracle is not None:
            for mode, cases in differential.items():
                native_group = "encode" if mode == "produce" else mode
                native = {row["name"]: row for row in groups[native_group]}
                oracle.compare(mode, cases, native)
            report["original_rust_oracle"] = oracle.receipt()
        report["known_failure_observations"] = json.loads(builder.inputs[
            "hia/platform/transport_response/known_failures.json"])
        report["build"] = builder.receipt()
        report.update(status="PASS" if oracle is not None else "NATIVE_PASS_RUST_NOT_RUN",
            counts={name: len(rows) for name, rows in groups.items()}, native_controls_passed=sum(map(len, groups.values())),
            native_controls_failed=0, elapsed_ns=time.monotonic_ns() - started)
        write_json(output / "report.json", report)
        print(json.dumps({"status": report["status"], "counts": report["counts"], "report": str(output / "report.json")}), flush=True)
        return 0
    except BaseException as error:
        report.update(status="FAIL", failure_type=type(error).__name__, failure=str(error), elapsed_ns=time.monotonic_ns() - started)
        write_json(output / "report.json", report)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
