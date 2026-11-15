#!/usr/bin/env python3
"""Record the current PQ composition without rewriting historical outcomes.

Retain all 29 historical commands and their 1200-second limits. The current
claim command must execute its fixed, source-pinned roster of 55 controls.
Write outside the checkout; HOLD and all qualification flags remain unchanged.
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


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


# Fixed review contract, independent of runtime discovery and reported totals.
# Original 49: 1d29818ad927f549f43d74a06f51e91771feac70.
# Six added controls: 580d191981537988dde8bd1cc75eeb8a84540563, retained by PR #806.
# See CURRENT_PQ_COMPOSITION.md for immutable log/source provenance.
CLAIM_TEST_PATH = "scripts/ci/test_pq_chain_claim_guard.py"
CLAIM_TEST_SOURCE = {
    "bytes": 28476,
    "sha256": "5a3c2e0d15dbfed68cb7afcc0c7f88a6b5c8620823ea7257e0dc5ef2be570a6f",
}
CURRENT_CLAIM_TEST_IDS = (
    '__main__.ClaimReaderRaceTests.test_checkout_ancestor_symlink_during_read_is_refused',
    '__main__.ClaimReaderRaceTests.test_fifo_substitution_cannot_block_before_fstat',
    '__main__.ClaimReaderRaceTests.test_growth_during_read_is_bounded',
    '__main__.ClaimReaderRaceTests.test_leaf_symlink_between_check_and_open_is_refused',
    '__main__.ClaimReaderRaceTests.test_leaf_symlink_during_read_is_refused',
    '__main__.ClaimReaderRaceTests.test_missing_after_check_is_wrapped_and_fds_close',
    '__main__.ClaimReaderRaceTests.test_parent_replacement_with_identical_leaf_is_refused',
    '__main__.ClaimReaderRaceTests.test_parent_symlink_to_same_leaf_during_read_is_refused',
    '__main__.ClaimReaderRaceTests.test_regular_file_is_returned_unchanged',
    '__main__.ClaimReaderRaceTests.test_same_length_in_place_rewrite_is_refused',
    '__main__.ClaimReaderRaceTests.test_same_length_leaf_replacement_before_open_is_refused',
    '__main__.ClaimReaderRaceTests.test_same_length_leaf_replacement_during_read_is_refused',
    '__main__.ClaimReaderRaceTests.test_same_length_mmap_rewrite_is_refused',
    '__main__.ClaimReaderRaceTests.test_same_length_rewrite_with_restored_mtime_is_refused',
    '__main__.TestClaimGuard.test_added_numeric_whole_chain_probability_refused',
    '__main__.TestClaimGuard.test_added_whole_chain_pq128_claim_refused',
    '__main__.TestClaimGuard.test_budget_cannot_add_self_certification_switch',
    '__main__.TestClaimGuard.test_changed_lifetime_event_owner_source_refused',
    '__main__.TestClaimGuard.test_classical_fallback_refused',
    '__main__.TestClaimGuard.test_corrupt_independent_qualification_refused',
    '__main__.TestClaimGuard.test_duplicate_json_keys_refused',
    '__main__.TestClaimGuard.test_example_cannot_replace_current_research_register',
    '__main__.TestClaimGuard.test_explicit_false_null_and_nested_hold_claims_stay_unqualified',
    '__main__.TestClaimGuard.test_explicit_unknown_claims_keep_hold',
    '__main__.TestClaimGuard.test_false_flag_cannot_launder_numeric_bound',
    '__main__.TestClaimGuard.test_hepta_final_use_claim_refused',
    '__main__.TestClaimGuard.test_history_storage_and_rehearsal_owner_paths_cannot_disappear',
    '__main__.TestClaimGuard.test_hold_is_not_pq_success',
    '__main__.TestClaimGuard.test_missing_authority_surface_inventory_refused',
    '__main__.TestClaimGuard.test_missing_budget_event_owner_source_refused',
    '__main__.TestClaimGuard.test_missing_external_rollback_oracle_refused',
    '__main__.TestClaimGuard.test_missing_lifetime_manifest_refused',
    '__main__.TestClaimGuard.test_missing_lifetime_source_lock_refused',
    '__main__.TestClaimGuard.test_missing_or_non_directory_checkout_root_refused',
    '__main__.TestClaimGuard.test_missing_pq_hepta_verifier_refused',
    '__main__.TestClaimGuard.test_missing_proof_relation_refused',
    '__main__.TestClaimGuard.test_missing_quantum_daa_model_refused',
    '__main__.TestClaimGuard.test_native_witness_and_live_admission_sources_cannot_disappear',
    '__main__.TestClaimGuard.test_nested_lifetime_claim_refused',
    '__main__.TestClaimGuard.test_nonfinite_and_nonstandard_json_numbers_refused',
    '__main__.TestClaimGuard.test_pq_128_guest_promotion_refused',
    '__main__.TestClaimGuard.test_production_activation_refused',
    '__main__.TestClaimGuard.test_quantum_hardness_claim_refused',
    '__main__.TestClaimGuard.test_reserved_boolean_alias_requires_exact_false',
    '__main__.TestClaimGuard.test_reserved_numeric_alias_requires_null_even_for_zero',
    '__main__.TestClaimGuard.test_reserved_numeric_claims_refused_in_every_claim_document',
    '__main__.TestClaimGuard.test_reserved_promotions_cannot_hide_in_nested_mappings_or_lists',
    '__main__.TestClaimGuard.test_reserved_true_claims_refused_in_every_claim_document',
    '__main__.TestClaimGuard.test_rollback_claim_refused',
    '__main__.TestClaimGuard.test_source_reader_helper_cannot_disappear',
    '__main__.TestClaimGuard.test_swapped_lifetime_source_revision_refused',
    '__main__.TestClaimGuard.test_symlink_source_refused',
    '__main__.TestClaimGuard.test_symlinked_checkout_ancestor_refused',
    '__main__.TestClaimGuard.test_symlinked_checkout_root_refused',
    '__main__.TestClaimGuard.test_unbounded_or_unaccepted_candidate_refused',
)


def claim_source_snapshot(root):
    try:
        return digest(root / CLAIM_TEST_PATH)
    except OSError as error:
        return {"error": type(error).__name__ + ": " + str(error)}


def validate_current_claim_run(stdout, stderr, exit_code, source_before, source_after):
    """Require the fixed source and every actual, distinct successful test record.

    This checks a fresh command's captured output. The old F2 log is only an
    adversarial-parser fixture; it is never used as a current campaign result.
    """
    errors = []
    if source_before != CLAIM_TEST_SOURCE or source_after != CLAIM_TEST_SOURCE:
        errors.append("current claim test source hash/length mismatch")
    if exit_code != 0:
        errors.append("claim test process did not exit zero")
    if stdout:
        errors.append("unexpected stdout from fixed claim test command")
    if len(CURRENT_CLAIM_TEST_IDS) != 55 or len(set(CURRENT_CLAIM_TEST_IDS)) != 55:
        errors.append("fixed claim roster is not 55 distinct names")
    # Match the complete unittest verbose record, not a success substring in a
    # failure log. There must be one summary and one exact unqualified OK line.
    frame = re.fullmatch(
        r"(?P<records>(?:[^\n]+\n)+)\n-{70}\n"
        r"Ran (?P<count>[0-9]+) tests in [0-9]+(?:\.[0-9]+)?s\n\nOK\n",
        stderr,
    )
    records = []
    count = None
    if frame is None:
        errors.append("claim log is not one complete verbose unittest success frame")
    else:
        count = int(frame['count'])
        for line in frame['records'].splitlines():
            record = re.fullmatch(
                r"(test_[A-Za-z0-9_]+) \((__main__\.[A-Za-z0-9_]+\.test_[A-Za-z0-9_]+)\) \.\.\. (.+)",
                line,
            )
            if record is None:
                errors.append("unrecognized claim test record")
                continue
            method, test_id, status = record.groups()
            records.append({"id": test_id, "status": status})
            if method != test_id.rsplit('.', 1)[1]:
                errors.append("claim test display name differs from qualified identity")
            if status != 'ok':
                errors.append("claim test did not report exact ok status")
    names = [item['id'] for item in records]
    missing = sorted(set(CURRENT_CLAIM_TEST_IDS) - set(names))
    unexpected = sorted(set(names) - set(CURRENT_CLAIM_TEST_IDS))
    duplicates = sorted({name for name in names if names.count(name) != 1})
    if count != 55 or len(records) != 55:
        errors.append("claim summary and named record counts must both be exactly 55")
    if missing or unexpected or duplicates:
        errors.append("claim records differ from the complete fixed distinct roster")
    return {
        "schema": "trnm-pq-current-claim-roster-validation-v1",
        "passed": not errors, "errors": errors,
        "expected_test_source": CLAIM_TEST_SOURCE,
        "test_source_before": source_before, "test_source_after": source_after,
        "required_ids": list(CURRENT_CLAIM_TEST_IDS), "records": records,
        "reported_count": count, "distinct_count": len(set(names)),
        "missing_ids": missing, "unexpected_ids": unexpected, "duplicate_ids": duplicates,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--cargo", help="Explicit trusted Cargo executable for native checks")
    parser.add_argument("--target", type=Path, help="Isolated Cargo target directory")
    args = parser.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    if out.is_relative_to(root) or out.exists():
        parser.error("use a new output directory outside the source checkout")
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_head) is None:
        parser.error("expected head must be a complete lowercase commit ID")
    if bool(args.cargo) != bool(args.target):
        parser.error("native checks require both --cargo and --target")
    out.mkdir(parents=True)
    env = dict(os.environ)
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1", RUST_TEST_THREADS="1")
    if args.target:
        env["CARGO_TARGET_DIR"] = str(args.target.resolve())
        env["CARGO_BUILD_JOBS"] = "2"
    py = [sys.executable, "-B"]
    guard = py + ["scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", args.expected_head]
    commands = [
        ("preflight", ["bash", "scripts/project-preflight.sh"]),
        ("source-before", guard + ["--output", str(out / "source-before.json")]),
        ("lifetime-tests", py + ["scripts/ci/test_pq_lifetime_budget.py", "-v"]),
        ("claim-tests", py + ["scripts/ci/test_pq_chain_claim_guard.py", "-v"]),
        ("effect-register-tests", py + ["scripts/ci/test_pq_authority_effect_register.py", "-v"]),
        ("root-policy-tests", py + ["-m", "unittest", "discover", "-s", "formal/pon-nakamoto-v1", "-p", "test_pq_root_recovery_policy_v1.py", "-v"]),
        ("lifetime-report", py + ["scripts/ci/pq_lifetime_budget.py"]),
        ("claim-report", py + ["scripts/ci/pq_chain_claim_guard.py"]),
        ("effect-register-report", py + ["scripts/ci/pq_authority_effect_register.py"]),
        ("root-policy-example", py + ["formal/pon-nakamoto-v1/pq_root_recovery_policy_v1.py", "--example"]),
        ("pq-source-integration", py + ["scripts/ci/check_pq_research_integration.py"]),
        ("pq-source-negatives", py + ["scripts/ci/test_pq_research_integration.py", "-v"]),
        ("authority-scanner-negatives", py + ["scripts/ci/test_pq_authority_surface_scan.py", "-v"]),
        ("ci-contract", py + ["scripts/ci/check_ci_contract.py"]),
        ("ci-contract-negatives", py + ["scripts/ci/test_ci_contract.py", "-v"]),
        ("source-integrity-negatives", py + ["scripts/ci/test_ci_source_integrity.py", "-v"]),
        ("repository", py + ["scripts/ci/check_repository.py"]),
        ("repository-negatives", py + ["scripts/ci/test_repository.py", "-v"]),
        ("distributed-inventory", py + ["scripts/refresh_distributed_source_inventory.py", "--check"]),
        ("diff-check", ["git", "diff", "--check"]),
    ]
    if args.cargo:
        cargo = [args.cargo]
        manifest = ["--manifest-path", "trillionnium/Cargo.toml"]
        common = ["--locked", "--offline", *manifest]
        commands += [
            ("cargo-version", cargo + ["--version"]),
            ("metadata-default", cargo + ["metadata", *common, "--format-version", "1"]),
            ("metadata-all-features", cargo + ["metadata", *common, "--all-features", "--format-version", "1"]),
            ("metadata-fuzz", cargo + ["metadata", "--locked", "--offline", "--manifest-path", "tests/fuzz/Cargo.toml", "--format-version", "1"]),
            ("formatting", cargo + ["fmt", *manifest, "--all", "--", "--check"]),
            ("strict-workspace-clippy", cargo + ["clippy", *common, "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]),
            ("native-crypto-default", cargo + ["test", *common, "-p", "trnm-crypto-primitives", "--lib", "--", "--test-threads=1"]),
            ("native-hepta-pq-comparator", cargo + ["test", *common, "-p", "trnm-research-protocol", "--test", "hepta_handoff_pq", "--", "--test-threads=1"]),
        ]
    commands.append(("source-after", guard + ["--output", str(out / "source-after.json")]))
    summary = {"schema": "trnm-pq-current-composition-validation-v1", "expected_head": args.expected_head,
               "root": str(root), "native_checks_requested": bool(args.cargo), "commands": [],
               "runner": digest(Path(__file__)), "started_unix_seconds": time.time(),
               "scope": "current exact-source composition; historical failures retained",
               "qualification": "HOLD_NO_GO",
               "claim_test_source": CLAIM_TEST_SOURCE,
               "claim_test_required_ids": list(CURRENT_CLAIM_TEST_IDS),
               "historical_f2_failure_reinterpreted": False,
               "whole_chain_pq_qualified": False, "production_activation": False,
               "complete_node_suite_executed": False, "hosted_ci_accepted": False}
    save(out / "commands.json", [{"label": name, "argv": argv} for name, argv in commands])
    for label, argv in commands:
        claim_before = claim_source_snapshot(root) if label == "claim-tests" else None
        stdout, stderr = out / (label + ".stdout.txt"), out / (label + ".stderr.txt")
        row = {"label": label, "argv": argv, "started_unix_seconds": time.time()}
        with stdout.open("wb") as output, stderr.open("wb") as error:
            try:
                result = subprocess.run(argv, cwd=root, env=env, stdout=output, stderr=error,
                                        timeout=1200, check=False)
                row["exit_code"] = result.returncode
            except subprocess.TimeoutExpired:
                row["exit_code"] = 124
                row["timeout"] = True
            except OSError as failure:
                row["exit_code"] = 127
                error.write((type(failure).__name__ + ": " + str(failure) + "\n").encode())
        row.update(finished_unix_seconds=time.time(), passed=row["exit_code"] == 0,
                   stdout=digest(stdout), stderr=digest(stderr))
        summaries = re.findall(r"Ran (\d+) tests? in [^\n]+\n\n(OK|FAILED[^\n]*)",
                               stderr.read_text(errors="replace"))
        if summaries:
            row["unittest_summaries"] = [{"tests": int(n), "result": status} for n, status in summaries]
        native = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
                            stdout.read_text(errors="replace"))
        if native:
            row["native_summaries"] = [dict(zip(("result", "passed", "failed", "ignored", "measured", "filtered"),
                                                               (state, *map(int, numbers)))) for state, *numbers in native]
        required_counts = {"lifetime-tests": 58, "claim-tests": 55,
                           "effect-register-tests": 18, "root-policy-tests": 26}
        if label in required_counts and row.get("unittest_summaries") != [
                {"tests": required_counts[label], "result": "OK"}]:
            row["passed"] = False
            row["summary_validation_error"] = "required test count/outcome not observed"
        if label == "claim-tests":
            row["current_claim_validation"] = validate_current_claim_run(
                stdout.read_text(errors="replace"), stderr.read_text(errors="replace"),
                row["exit_code"], claim_before, claim_source_snapshot(root),
            )
            if not row["current_claim_validation"]["passed"]:
                row["passed"] = False
                row["summary_validation_error"] = "fixed current claim source/roster not observed"
        if label.startswith("native-") and not (
                row.get("native_summaries")
                and sum(item["passed"] for item in row["native_summaries"]) > 0
                and all(item["result"] == "ok" and item["failed"] == 0
                        for item in row["native_summaries"])):
            row["passed"] = False
            row["summary_validation_error"] = "native test completion not observed"
        summary["commands"].append(row)
        save(out / "summary.json", summary)
        print(json.dumps({"label": label, "exit_code": row["exit_code"],
                          "elapsed_seconds": row["finished_unix_seconds"] - row["started_unix_seconds"]}), flush=True)
        if label in ("preflight", "source-before") and not row["passed"]:
            break
    summary["finished_unix_seconds"] = time.time()
    summary["commands_expected"] = len(commands)
    summary["commands_completed"] = len(summary["commands"])
    summary["failed_commands"] = [row["label"] for row in summary["commands"] if not row["passed"]]
    summary["result"] = "PASS" if not summary["failed_commands"] and len(summary["commands"]) == len(commands) else "FAIL"
    save(out / "summary.json", summary)
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
