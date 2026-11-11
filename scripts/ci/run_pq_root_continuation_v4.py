#!/usr/bin/env python3
"""Execute exact V4 recovery floor and provider readback component tests.

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
from run_pq_root_native_v3 import checked_result

ROOT = Path(__file__).resolve().parents[2]
FLOOR = (
    'native_floor_v4_exact_signed_ancestor_survives_append_and_reopen',
    'native_floor_v4_complete_enrollment_binding_precedes_storage_and_anchor',
    'native_floor_v4_higher_counter_cannot_replace_exact_signed_ancestry',
    'native_floor_v4_history_below_external_lower_bound_is_refused',
    'native_floor_v4_pending_target_needs_signed_replay_and_explicit_completion',
    'native_floor_v4_pending_bytes_do_not_become_authority_from_head_match',
    'native_floor_v4_fresh_anchor_authentication_remains_required',
    'native_floor_v4_common_restore_contrast_stale_pin_accepts_surviving_pin_rejects',
    'native_floor_v4_invalid_pin_shapes_are_refused',
)
PROVIDER = (
    'native_provider_v4_real_declaration_reopens_without_effect_authority',
    'native_provider_v4_enrollment_requires_floor_complete_bytes_kind_and_attempt',
    'native_provider_v4_lost_and_unknown_reads_keep_original_operation_pending',
    'native_provider_v4_complete_request_and_both_signature_families_are_required',
    'native_provider_v4_callback_cannot_replace_cancel_or_replenish_budget',
    'native_provider_v4_orphan_epochs_require_explicit_same_epoch_reconciliation',
    'native_provider_v4_unknown_does_not_erase_known_outcome_and_conflicts_refuse',
    'native_provider_v4_replays_original_operation_after_authority_rotation',
    'native_provider_v4_later_root_provider_alias_refuses_before_transport',
    'native_provider_v4_foreign_replaced_linked_and_truncated_journals_refuse',
    'native_provider_v4_unresolved_orphan_is_not_replaced_by_new_epoch',
    'native_provider_v4_oversized_journal_refuses_before_lookup',
)


CALLBACK_BUDGET = (
    'native_budget_v4_writer_error_cannot_hide_budget_replacement',
    'native_budget_v4_transport_error_cannot_hide_budget_replacement',
    'native_budget_v4_writer_error_latches_observed_external_cancellation',
    'native_budget_v4_transport_error_latches_observed_external_cancellation',
    'native_budget_v4_unmodified_writer_error_is_preserved',
    'native_budget_v4_unmodified_transport_error_is_preserved',
)


def suites():
    base = ["cargo", "test", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--features", "pq-root-v3"]
    suffix = ["--", "--nocapture", "--test-threads=1"]
    result = (
        ("recovery-floor", base + ["--test", "recovery_floor_v4_native"] + suffix, FLOOR),
        ("provider-readback", base + ["--test", "root_effect_readback_v4_native"] + suffix, PROVIDER),
        ("callback-budget", base + ["--test", "root_budget_v4_native"] + suffix, CALLBACK_BUDGET),
    )
    if any(not required or len(set(required)) != len(required) for _, _, required in result):
        raise ValueError("nonempty exact reviewed test inventory required")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    suites()  # Refuse an incomplete inventory before creating output.
    output = args.out or Path(os.environ.get("TRNM_CI_RECEIPT_DIR", "/tmp/trnm-root-v4")) / "root-continuation-v4"
    output.mkdir(parents=True, exist_ok=False)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    before = verify("head", head, root=ROOT)
    (output / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    records = []
    for name, argv, expected in suites():
        log = output / (name + ".log")
        start = time.monotonic()
        try:
            with log.open("xb") as stream:
                result = subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=1200)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
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
                  "observation": observation, "error": error}
        records.append(record)
        (output / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(record), flush=True)
    after = verify("head", head, root=ROOT)
    (output / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
    passed = before == after and all(row["error"] is None for row in records)
    report = {"schema": "trnm-pq-root-continuation-native-v4", "source": head,
              "component_execution_passed": passed, "commands": records,
              "status": "HOLD", "production_activation": False,
              "actual_lifetime_failure_bound": None, "whole_chain_pq_qualified": False,
              "composition_coverage_proved": False,
              "independent_custody_verified": False, "anchor_independence_verified": False,
              "actual_external_effects_verified": False, "native_m15_production_integration_complete": False,
              "migration_authorized": False}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
