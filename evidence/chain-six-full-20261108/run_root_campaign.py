#!/usr/bin/env python3
"""Exact-source local research checks; preserve failures and original gates.

The current PQ successor retains the original 29 commands and source gates,
and requires all 55 current claim controls by name and fixed source hash. Its
raw-source before record anchors every stage and the final full verification.
The historical runner and incomplete F2 execution remain unchanged evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback

from verify_amortized_independent_roster import SOURCE as AMORTIZED_SOURCE, verify_frame


def read_amortized_independent(row, stdout, stderr, source, expected_count):
    """Bind this fixed stage to its original six identities and two docstrings."""
    row.update(unittest_count=expected_count, named_success_count=0)
    try:
        if type(expected_count) is not int or expected_count != 6:
            raise ValueError("the original amortized independent roster has six tests")
        frame = verify_frame(stdout.read_bytes(), stderr.read_bytes(),
                             row["exit_code"], source.read_bytes())
        row["named_success_count"] = frame["executed_ok"]
        row["named_reader"] = frame
    except Exception as error:
        row["passed"] = False
        row["reader_error"] = {"type": type(error).__name__, "message": str(error)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--head", required=True)
    args = ap.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    assert re.fullmatch(r"[0-9a-f]{40}", args.head)
    assert not out.exists() and not out.is_relative_to(root)
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ)
    prefix = "/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2/build-runtime/trnm-pq-provider-3.5.9.DYf2qEaX/install"
    target = "/home/qian-qi/work/chain-six-settlement-d9fb-target-20261108"
    env.update(
        CARGO_TARGET_DIR=target, CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", RUSTUP_TOOLCHAIN="1.95.0",
        RAYON_NUM_THREADS="2", RUST_TEST_THREADS="1", CARGO_TERM_COLOR="never",
        OPENSSL_DIR=prefix, OPENSSL_STATIC="1", OPENSSL_CONF="/dev/null",
        OPENSSL_MODULES=prefix + "/lib/ossl-modules",
        TRNM_PQ_OPENSSL=prefix + "/bin/openssl",
        TRNM_PQ_OPENSSL_SHA256="8ff7dd91270fd4a8fc377031f0fd2f2cee1cd17a32ce30e4fd773a25730a120f",
        TRNM_PQ_OPENSSL_VERSION="3.5.9", PYTHONDONTWRITEBYTECODE="1",
        PYTHONUNBUFFERED="1",
    )
    env["PATH"] = "/home/qian-qi/.cargo/bin:" + env["PATH"]
    assert hashlib.sha256(Path(env["TRNM_PQ_OPENSSL"]).read_bytes()).hexdigest() == env["TRNM_PQ_OPENSSL_SHA256"]
    # Do not manufacture the hosted CI environment or provision a workstation.
    assert env.get("GITHUB_ACTIONS") != "true"
    py = [sys.executable, "-B"]
    cargo = ["/home/qian-qi/.cargo/bin/cargo", "+1.95.0"]
    manifest = ["--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml"]
    native = cargo + ["test", *manifest, "--release"]
    rows = []
    result = {
        "schema": "chain-six-unified-root-campaign-v3", "expected_head": args.head,
        "scope": "local exact-source research controls and native executions",
        "started_unix_seconds": time.time(), "stages": rows,
        "whole_chain_pq_qualified": False, "quantum_soundness_qualified": False,
        "same_resource_net_gain_qualified": False,
        "independent_operator_qualified": False, "hosted_ci_accepted": False,
        "production_activation": False, "complete_workspace_tests_executed": False,
    }

    def save():
        (out / "campaign.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    def run(label, argv, *, timeout=1800, python_count=None, native_count=None,
            native_ignored=0, native_required=(), require_native=False,
            expected_refusal=None):
        row = {"stage": label, "argv": argv, "started_unix_seconds": time.time()}
        stdout, stderr = out / (label + ".stdout"), out / (label + ".stderr")
        with stdout.open("xb") as so, stderr.open("xb") as se:
            try:
                p = subprocess.run(argv, cwd=root, env=env, stdout=so, stderr=se,
                                   timeout=timeout, check=False)
                row["exit_code"] = p.returncode
            except subprocess.TimeoutExpired:
                row.update(exit_code=124, timed_out=True)
            except OSError as error:
                se.write((repr(error) + "\n").encode())
                row["exit_code"] = 127
        text = stdout.read_text(errors="replace") + "\n" + stderr.read_text(errors="replace")
        row["passed"] = row["exit_code"] == 0
        row["outcome"] = "PASS" if row["passed"] else "FAIL"
        if python_count is not None and label == "amortized-independent":
            read_amortized_independent(row, stdout, stderr, root / AMORTIZED_SOURCE, python_count)
        elif python_count is not None:
            summaries = re.findall(r"^Ran (\d+) tests? in .*?$", text, re.M)
            oks = re.findall(r"^OK(?: \(.*\))?$", text, re.M)
            names = re.findall(r"^(test_\S+) \([^)]+\) \.\.\. ok$", text, re.M)
            row["unittest_count"] = python_count
            row["named_success_count"] = len(names)
            row["passed"] &= summaries == [str(python_count)] and oks == ["OK"] and len(names) == python_count
        if require_native or native_count is not None:
            observed = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", text, re.M)
            parsed = [dict(zip(("result", "passed", "failed", "ignored", "measured", "filtered"),
                               (state, *map(int, counts)))) for state, *counts in observed]
            names = re.findall(r"^test ([^ ]+) \.\.\. ok$", text, re.M)
            ignored_names = re.findall(r"^test ([^ ]+) \.\.\. ignored(?:, .*)?$", text, re.M)
            row.update(native_summaries=parsed, native_passed_names=names,
                       native_original_ignored_names=ignored_names)
            row["passed"] &= bool(parsed) and all(x["result"] == "ok" and x["failed"] == 0 and x["measured"] == 0 for x in parsed)
            row["passed"] &= sum(x["passed"] for x in parsed) > 0
            row["passed"] &= sum(x["ignored"] for x in parsed) == native_ignored
            row["passed"] &= len(names) == sum(x["passed"] for x in parsed) and len(names) == len(set(names))
            row["passed"] &= all(any(n == required or n.endswith("::" + required) for n in names) for required in native_required)
            if native_count is not None:
                row["passed"] &= sum(x["passed"] for x in parsed) == native_count
        if expected_refusal:
            row["passed"] = row["exit_code"] == 1 and expected_refusal in text and not row.get("timed_out", False)
            row["outcome"] = "EXPECTED_REFUSAL" if row["passed"] else "FAIL"
            row["hosted_gate_passed"] = False
        elif not row["passed"]:
            row["outcome"] = "FAIL"
        row["elapsed_seconds"] = time.time() - row["started_unix_seconds"]
        row["artifacts"] = [
            {"path": p.name, "bytes": p.stat().st_size,
             "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in (stdout, stderr)
        ]
        rows.append(row)
        save()
        print(json.dumps({k: row[k] for k in ("stage", "exit_code", "outcome", "elapsed_seconds")}), flush=True)
        return row

    before = None
    try:
        preflight = run("preflight", ["bash", "scripts/project-preflight.sh"])
        if not preflight["passed"]:
            raise RuntimeError("preflight failed")
        pq_out = out / "current-pq-composition"
        nested = run("current-pq-composition-runner", py + [
            "evidence/chain-six-full-20261108/run_pq_composition_current.py",
            "--root", str(root), "--out", str(pq_out), "--expected-head", args.head,
            "--cargo", "/home/qian-qi/.cargo/bin/cargo", "--target", target,
        ], timeout=10800)
        if not (pq_out / "source-before.json").is_file():
            raise RuntimeError("current complete source-before gate did not complete")
        before = json.loads((pq_out / "source-before.json").read_text())
        pq_summary = json.loads((pq_out / "summary.json").read_text())
        nested["nested_result"] = pq_summary["result"]
        nested["passed"] &= pq_summary["result"] == "PASS" and pq_summary["commands_expected"] == pq_summary["commands_completed"] == 29
        if not nested["passed"]:
            nested["outcome"] = "FAIL"
        save()
        run("current-composition-reader-controls", py + ["evidence/chain-six-full-20261108/test_pq_composition_current.py", "-v"], python_count=9)
        credit_row = run("credit-envelope-original-77", py + ["scripts/ci/run_credit_envelope_checks.py", "--output-dir", str(out / "credit-envelope")])
        if credit_row["passed"]:
            credit = json.loads((out / "credit-envelope/test-outcomes.json").read_text())
            completion = json.loads((out / "credit-envelope/completion.json").read_text())
            credit_row["passed"] &= credit["passed"] is True and credit["tests_run"] == credit["distinct_tests"] == completion["distinct_named_tests_passed"] == 77
            credit_row["passed"] &= len(credit["registered_names"]) == len(credit["successful_names"]) == 77 and completion["overall"] == "HOLD"
            credit_row["outcome"] = "PASS" if credit_row["passed"] else "FAIL"
            save()
        for label, directory, filename, count in (
            ("quantum-candidate-clock", "formal/pon-nakamoto-v1", "test_quantum_candidate_check_clock.py", 6),
            ("restricted-quantum-oracle", "formal/pon-nakamoto-v1", "test_w1_quantum_restricted_oracle.py", 12),
            ("fixed-probability", "formal/pon-nakamoto-v1", "test_fixed_probability_contract.py", 16),
            ("credit-feasibility", "formal/pon-nakamoto-v1", "test_credit_feasibility.py", 31),
            ("amortized-potential", "formal/pon-nakamoto-v1", "test_amortized_cost_potential.py", 34),
            ("amortized-independent", "formal/pon-nakamoto-v1", "test_amortized_cost_potential_independent.py", 6),
            ("lifecycle-cost", "formal/pon-nakamoto-v1", "test_lifecycle_cost_v1.py", 31),
            ("cell-lottery-cost", "formal/pon-nakamoto-v1", "test_cell_lottery_cost_audit_v1.py", 3),
            ("service-work-settlement", "formal/pon-nakamoto-v1", "test_service_work_settlement_v1.py", 25),
            ("cell-adoption-reader", "scripts", "test_cell_adoption_readback.py", 26),
            ("learning-iteration-reader", "scripts", "test_cell_learning_iteration_join.py", 25),
            ("learning-completion-reader", "scripts", "test_cell_learning_completion_join.py", 13),
        ):
            run(label, py + ["-m", "unittest", "discover", "-s", directory, "-p", filename, "-v"], python_count=count)
        run("fixed-probability-report", py + ["formal/pon-nakamoto-v1/fixed_probability_contract.py"])
        run("amortized-potential-report", py + ["formal/pon-nakamoto-v1/amortized_cost_potential.py", "--compact"])
        mu1_row = run("actual-mu1-reuse-probe", py + ["formal/pon-nakamoto-v1/fixed_probability_reuse_probe.py", "--check", "--out", str(out / "actual-mu1")])
        if mu1_row["passed"]:
            mu1 = json.loads((out / "actual-mu1/report.json").read_text())
            mu1_row["passed"] &= mu1["result"] == "PASS" and len(mu1["checks"]) == 21 and all(value is True for value in mu1["checks"].values())
            mu1_row["outcome"] = "PASS" if mu1_row["passed"] else "FAIL"
            save()
        run("original-lifecycle-game", py + ["formal/pon-nakamoto-v1/experiments/lifecycle_cost_game_v1.py", "--output", str(out / "lifecycle-game")], timeout=3600)
        required_money = (
            "native_funding_legacy_rejects_late_generation_commit",
            "native_funding_authenticated_rejects_late_generation_commit",
            "native_payment_legacy_rejects_late_generation_commit",
            "native_payment_authenticated_rejects_late_generation_commit",
            "native_funding_rejects_late_context_replacement",
            "native_payment_rejects_late_context_replacement",
        )
        run("native-money-epoch", native + ["-p", "trnm-pon-node", "--lib", "store::funding::tests::", "--", "--test-threads=1"], native_count=11, native_required=required_money)
        for label, package, ignored in (
            ("native-service-settlement", "trnm-service-settlement", 0),
            ("native-checkpoint-store", "trnm-checkpoint-store", 0),
            ("native-release-bundle", "trnm-release-bundle", 0),
            ("native-mvcc-fee", "trnm-mvcc-fee", 9),
        ):
            run(label, native + ["-p", package, "--lib", "--", "--test-threads=1"],
                timeout=3600, require_native=True, native_ignored=ignored)
        for target_name, count in (("funded_service_contract", 4), ("native_task_operation_v2", 4), ("native_active_anchor", 2)):
            run("native-" + target_name, native + ["-p", "trnm-pon-node", "--test", target_name, "--", "--test-threads=1"], native_count=count)
        run("original-hosted-gate-local-refusal", py + [
            "scripts/ci/run_from_zero_host.py", "--", "python3", "scripts/ci/run_from_zero_native.py", "--out", str(out / "original-hosted-only")
        ], timeout=60, expected_refusal="HOSTED_CI_ONLY_NO_LOCAL_PROVISION")
    except BaseException as error:
        result["driver_error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
        traceback.print_exc()
    finally:
        if before is not None:
            try:
                sys.path.insert(0, str(root / "scripts/ci"))
                from verify_ci_source import verify
                after = verify("head", args.head, root=root)
                (out / "source-after-all.json").write_text(json.dumps(after, indent=2, sort_keys=True) + "\n")
                result["source_unchanged_for_complete_campaign"] = before == after
            except BaseException as error:
                result["source_after_error"] = repr(error)
                result["source_unchanged_for_complete_campaign"] = False
        result["failed_stages"] = [row["stage"] for row in rows if not row["passed"]]
        result["completed_stage_count"] = len(rows)
        result["finished_unix_seconds"] = time.time()
        result["result"] = "PASS" if not result.get("driver_error") and not result["failed_stages"] and result.get("source_unchanged_for_complete_campaign") and len(rows) == 29 else "FAIL"
        save()
        print("CAMPAIGN_TERMINAL", json.dumps({k: v for k, v in result.items() if k != "stages"}), flush=True)
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
