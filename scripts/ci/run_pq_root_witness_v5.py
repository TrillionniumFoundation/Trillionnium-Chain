#!/usr/bin/env python3
"""Execute the complete exact V5 fresh-witness native component suite.

This retains failed commands and full raw logs. It never executes production
root changes or promotes whole-chain, deployment or lifetime qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from verify_ci_source import verify
from ci_observation import run as run_observed
from run_pq_root_native_v3 import checked_result as _checked_result

ROOT = Path(__file__).resolve().parents[2]
WITNESS = (
    'native_witness_v5_complete_binding_and_role_separation_are_required',
    'native_witness_v5_success_is_witnessed_before_pending_is_completed',
    'native_witness_v5_surviving_witness_refuses_common_owner_anchor_restore',
    'native_witness_v5_restoring_every_authority_remains_an_explicit_counterexample',
    'native_witness_v5_unavailable_witness_has_no_static_floor_fallback',
    'native_witness_v5_signed_response_must_bind_the_complete_fresh_request',
    'native_witness_v5_wrong_signature_and_outcome_are_refused',
    'native_witness_v5_another_recovery_epoch_cannot_use_the_same_service_pin',
    'native_witness_v5_lost_ack_retains_pending_and_resumes_without_another_cas',
    'native_witness_v5_pre_cas_disconnect_retries_only_the_verified_witness_transition',
    'native_witness_v5_corrupt_pending_never_advances_the_witness',
    'native_witness_v5_callback_budget_replacement_and_cancellation_remain_fenced',
    'native_witness_v5_context_and_intent_recheck_live_witness_and_latch_failure',
    'native_witness_v5_rotation_cannot_reuse_witness_keys',
    'native_witness_v5_open_checks_retained_root_key_roles',
    'native_witness_v5_unwitnessed_v3_commit_cannot_be_promoted_from_an_ancestor_floor',
    'native_witness_v5_changed_signed_pending_and_anchor_cannot_bypass_role_snapshot',
)

DURABLE = (
    'native_durable_witness_v5_exact_cas_retry_and_cold_reopen_have_dual_family_receipts',
    'native_durable_witness_v5_stale_database_requires_surviving_independent_reopen_pin',
    'native_durable_witness_v5_wrong_predecessor_and_competing_successor_are_mismatches',
    'native_durable_witness_v5_real_sqlite_commit_busy_fences_until_explicit_reopen',
    'native_durable_witness_v5_signing_failure_and_wrong_quorum_preserve_committed_head',
    'native_durable_witness_v5_budget_replacement_on_ok_or_err_and_cancellation_fence',
    'native_durable_witness_v5_unauthenticated_requests_cannot_mutate_or_fence',
    'native_durable_witness_v5_complete_policy_and_live_stored_binding_are_enforced',
    'native_durable_witness_v5_exclusive_lock_and_named_inode_are_required',
    'native_durable_witness_v5_foreign_namespace_and_extra_schema_are_refused',
    'native_durable_witness_v5_signer_callback_cannot_replace_committed_row_before_ack',
    'native_durable_witness_v5_root_lost_ack_cold_recovery_does_not_repeat_cas',
)


def checked_result(raw: str, expected: tuple[str, ...], returncode: int) -> dict:
    result = _checked_result(raw, expected, returncode)
    if result["filtered_out"] != 0:
        raise ValueError("the complete witness integration target cannot filter tests")
    return result


def suites():
    entries = []
    for name, target, required, count in (
        ("fresh-witness", "root_witness_v5_native", WITNESS, 17),
        ("durable-witness", "root_witness_v5_durable_native", DURABLE, 12),
    ):
        if len(required) != count or len(set(required)) != len(required):
            raise ValueError("complete reviewed native witness inventory required: " + name)
        argv = ["cargo", "test", "--locked", "--manifest-path", "trillionnium/Cargo.toml",
                "-p", "trnm-pon-node", "--features", "pq-root-v3",
                "--test", target, "--", "--nocapture", "--test-threads=1"]
        entries.append((name, argv, required))
    return tuple(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    suites()  # Refuse an incomplete inventory before creating output.
    output = args.out or Path(os.environ.get("TRNM_CI_RECEIPT_DIR", "/tmp/trnm-root-v5")) / "root-witness-v5"
    output.mkdir(parents=True, exist_ok=False)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    before = verify("head", head, root=ROOT)
    (output / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    records = []
    for name, argv, expected in suites():
        log = output / (name + ".log")
        start = time.monotonic()
        execution = None
        try:
            # The existing CI owner kills the created process group before
            # reaping its leader and returning a log receipt, even on timeout.
            # This is not a sandbox for descendants that create new sessions.
            execution = run_observed(argv, log, cwd=ROOT, timeout=1200)
            code = execution["exit_code"]
        except OSError as exception:
            code = 127
            with log.open("ab") as stream:
                stream.write((str(exception) + "\n").encode("utf-8"))
        raw = log.read_bytes()
        error = None
        observation = None
        try:
            observation = checked_result(raw.decode("utf-8", errors="strict"), expected, code)
        except (ValueError, UnicodeError) as exception:
            error = str(exception)
        record = {"name": name, "argv": argv, "source": head, "exit_code": code,
                  "elapsed_seconds": time.monotonic() - start,
                  "log": log.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                  "execution": execution, "observation": observation, "error": error}
        records.append(record)
        (output / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(record), flush=True)
    after = verify("head", head, root=ROOT)
    (output / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
    passed = before == after and all(row["error"] is None for row in records)
    report = {"schema": "trnm-pq-root-witness-native-v5", "source": head,
              "component_execution_passed": passed, "commands": records,
              "status": "HOLD", "production_activation": False,
              "actual_lifetime_failure_bound": None, "whole_chain_pq_qualified": False,
              "composition_coverage_proved": False,
              "independent_custody_verified": False, "anchor_independence_verified": False,
              "independent_common_restore_exclusion_proved": False,
              "native_witness_durable_service_verified": False,
              "actual_external_effects_verified": False, "native_m15_production_integration_complete": False,
              "migration_authorized": False}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
