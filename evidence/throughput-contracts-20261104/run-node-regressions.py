#!/usr/bin/env python3
"""Run 50 exact Node regressions sequentially, retaining each process result.

Invoke inside record_pq_native_command.py with the pinned provider and target
folder supplied by the caller. This helper inherits the environment unchanged.
The outer recorder remains responsible for complete before/after source identity.
An existing output directory is refused; this helper never resumes or overwrites.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent / "chain"
EXPECTED_TEST_COUNT = 50
TEST_NAMES = (
    'ingress::public_v3::request_observation::tests::lifecycle_retains_disconnect_until_actual_task_owner_exits',
    'ingress::public_v3::request_observation::tests::lifecycle_keeps_task_and_connection_closure_order_independent',
    'ingress::public_v3::request_observation::tests::lifecycle_unknown_clock_is_not_zero_and_snapshot_cannot_block_closure',
    'ingress::public_v3::request_observation::tests::lifecycle_snapshot_hides_clocks_until_their_close_publication_is_observed',
    'ingress::public_v3::request_observation::tests::error_diagnostics_preserve_typed_identity_origin_and_bounded_utf8',
    'ingress::public_v3::request_observation::tests::dispatch_diagnostic_survives_distinct_terminal_cancellation_without_changing_codes',
    'ingress::public_v3::request_observation::tests::queue_cancellation_keeps_original_identity_and_dropped_wait_interval',
    'ingress::public_v3::request_observation::tests::error_diagnostic_contention_does_not_block_or_reclassify_rejection',
    'ingress::public_v3::request_observation::tests::fixed_phase_slots_never_overwrite_a_previous_failure_with_a_retry',
    'ingress::public_v3::request_observation::tests::submit_phase_outcomes_are_bounded_and_keep_abandoned_measurements_unknown',
    'ingress::public_v3::request_observation::tests::submit_phase_capture_contention_is_optional_and_does_not_block_dispatch',
    'ingress::public_v3::request_observation::tests::observed_native_submit_keeps_rejection_success_and_duplicate_phase_boundaries',
    'ingress::public_v3::request_observation::tests::connection_observation_does_not_wait_for_independent_task_progress',
    'ingress::public_v3::request_observation::tests::task_contention_still_records_unknown_without_blocking_release',
    'ingress::public_v3::request_observation::tests::independent_task_observation_survives_connection_frame_update',
    'ingress::public_v3::request_observation::tests::connection_and_task_close_on_different_threads_complete_once_without_aliasing',
    'ingress::public_v3::request_observation::tests::registry_snapshot_does_not_omit_unrelated_accepted_connections',
    'ingress::public_v3::request_observation::tests::registry_concurrent_connections_are_retained_once_within_capacity',
    'ingress::public_v3::request_observation::tests::coverage_rejects_a_poisoned_record_even_when_retained_records_are_complete',
    'ingress::public_v3::request_observation::tests::bounded_records_and_saturating_counter_overflow_remain_explicit',
    'ingress::public_v3::request_observation::tests::capture_contention_and_arithmetic_overflow_never_block_task_release',
    'ingress::public_v3::request_observation::tests::cpu_clock_intervals_stay_on_the_execution_thread_and_are_nested',
    'ingress::public_v3::intake_domain_tests::shared_domain_cannot_mint_a_second_listener_body_budget',
    'ingress::public_v3::intake_domain_tests::listener_reconstruction_reuses_all_original_pools_and_outstanding_reservations',
    'ingress::public_v3::intake_domain_tests::connections_outputs_and_both_lanes_share_their_original_caps',
    'ingress::public_v3::intake_domain_tests::independent_operator_domains_do_not_accidentally_share_pools',
    'ingress::public_v3::intake_domain_tests::mutation_cannot_spend_shared_read_body_or_control_output_reserve',
    'ingress::public_v3::intake_domain_tests::actual_two_listeners_use_shared_connection_slots_and_release_on_stop',
    'ingress::public_v3::intake_domain_tests::one_plain_node_must_not_accept_independent_cpu_domains_through_two_real_listeners',
    'ingress::public_v3::intake_domain_tests::pinned_normal_node_recovers_same_budget_after_listener_stop_and_key_rotation',
    'ingress::public_v3::intake_domain_tests::one_node_cannot_spawn_a_fifth_worker_queue_service_from_the_same_domain',
    'ingress::public_v3::intake_domain_tests::public_epoch_start_keeps_original_deadline_and_stop_while_owner_is_busy',
    'ingress::public_v3::intake_domain_tests::public_cli_process_cold_start_never_receives_an_instant_fresh_cpu_or_cookie_burst',
    'ingress::public_v3::intake_domain_tests::public_library_external_listener_cannot_bypass_the_fixed_host_kernel_parent',
    'ingress::public_v3::intake_domain_tests::all_public_v3_library_wrappers_reject_external_socket_before_binding_owner_or_workers',
    'store::growth::tests::parallel_preparation::growth_parallel_preparation_preserves_signed_effects_nonce_roots_and_cold_replay',
    'store::growth::tests::parallel_preparation::growth_parallel_preparation_has_only_canonical_witness_access',
    'store::growth::tests::parallel_preparation::growth_parallel_preparation_joins_cancelled_workers_and_rolls_back_then_retries',
    'store::growth::tests::parallel_preparation::growth_parallel_preparation_preserves_signature_rejection_and_worker_limit',
    'store::growth::tests::parallel_preparation::growth_parallel_preparation_keeps_early_state_error_before_late_bad_signature',
    'store::growth::tests::parallel_preparation::growth_parallel_preparation_joins_panicked_workers_and_owner_can_retry',
    'store::operator_continuous_owner::tests::ordinary_public_v3_unclean_open_retains_one_durable_unknown_cpu_epoch',
    'store::operator_continuous_owner::tests::ordinary_public_v3_clean_sole_or_last_listener_removes_original_sqlite_marker',
    'store::operator_continuous_owner::tests::ordinary_public_v3_one_listener_close_while_other_cpu_is_in_flight_does_not_poison_epoch',
    'store::operator_continuous_owner::tests::ordinary_public_v3_unknown_clock_and_corrupt_marker_never_clear_on_restart',
    'store::operator_continuous_owner::tests::continuous_owner_keeps_original_authenticated_journal_not_ordinary_marker',
    'ingress::public_v3::growth::tests::public_growth_v1_real_listener_lost_ack_exact_query_reorg_and_cold_reopen',
    'ingress::public_v3::growth::tests::growth_signed_tcp_uses_paid_parallel_preparation_and_rejects_unknown_child_cpu',
    'store::growth::tests::native_growth_v2_activation_cancellation_precedes_sql_even_for_noop_or_unknown_target',
    'store::growth::tests::native_growth_v2_activation_rechecks_foreign_epoch_after_transaction_begin',

)
CARGO_PREFIX = [
    "cargo", "test", "--locked", "--offline", "--manifest-path",
    "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--all-features", "--lib",
]
CARGO_SUFFIX = [
    "--", "--exact", "--show-output", "--test-threads=1",
    "--format", "pretty", "--color", "never",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_manifest(path: Path, manifest: dict) -> None:
    pending = path.with_suffix(".tmp")
    pending.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n",
                       encoding="utf-8")
    pending.replace(path)


def shell_exit(code: int) -> int:
    return code if code >= 0 else 128 - code


def full_commit_sha(value: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{40}", value) is None:
        raise argparse.ArgumentTypeError("must be a full 40-character hexadecimal commit SHA")
    return value.lower()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True, type=full_commit_sha,
                        help="exact full 40-character hexadecimal source commit SHA")
    parser.add_argument("--output", required=True, type=Path,
                        help="fresh absolute output directory outside the checkout")
    args = parser.parse_args()
    if not args.output.is_absolute():
        parser.error("--output must be absolute")
    output = args.output.resolve()
    if output.is_relative_to(ROOT.resolve()):
        parser.error("--output must be outside the checkout")
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = output / "manifest.json"
    cases = []
    for index, name in enumerate(TEST_NAMES, 1):
        cargo_log = output / f"{index:02d}-cargo.log"
        check_log = output / f"{index:02d}-required-test.log"
        cases.append({
            "index": index,
            "test": name,
            "status": "not_run",
            "cargo_argv": CARGO_PREFIX + [name] + CARGO_SUFFIX,
            "cargo_log": cargo_log.name,
            "cargo_exit_code": None,
            "check_argv": [
                sys.executable, "scripts/ci/check_required_native_test.py",
                str(cargo_log), "--test", name,
            ],
            "check_log": check_log.name,
            "check_exit_code": None,
        })
    manifest = {
        "schema": "trnm-node-regression-run-v1",
        "status": "not_started",
        "expected_head": args.expected_head,
        "observed_head": None,
        "cwd": str(ROOT),
        "intended_count": len(cases),
        "started_utc": utc_now(),
        "cases": cases,
    }
    # Commit the whole denominator before checking source or launching Cargo.
    save_manifest(manifest_path, manifest)
    current = None
    code = 1
    try:
        if len(TEST_NAMES) != EXPECTED_TEST_COUNT or len(set(TEST_NAMES)) != EXPECTED_TEST_COUNT:
            raise ValueError(f"expected exactly {EXPECTED_TEST_COUNT} distinct tests")
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              text=True, capture_output=True, check=True).stdout.strip()
        manifest["observed_head"] = head
        if head != args.expected_head:
            raise ValueError(f"wrong source HEAD: {head}; expected {args.expected_head}")
        manifest["status"] = "running"
        save_manifest(manifest_path, manifest)
        for current in cases:
            current["status"] = "running_cargo"
            current["started_utc"] = utc_now()
            save_manifest(manifest_path, manifest)
            print(f"[{current['index']}/{EXPECTED_TEST_COUNT}] {current['test']}", flush=True)
            with (output / current["cargo_log"]).open("xb") as stream:
                cargo = subprocess.run(current["cargo_argv"], cwd=ROOT,
                                       stdout=stream, stderr=subprocess.STDOUT,
                                       check=False)
            current["cargo_exit_code"] = cargo.returncode
            save_manifest(manifest_path, manifest)
            if cargo.returncode != 0:
                current["status"] = "cargo_failed"
                current["finished_utc"] = utc_now()
                manifest["status"] = "failed"
                code = shell_exit(cargo.returncode)
                break
            # Cargo success alone never counts: zero-match/ignored/wrong-name
            # output must fail the existing required-native-test validator.
            current["status"] = "running_check"
            save_manifest(manifest_path, manifest)
            with (output / current["check_log"]).open("xb") as stream:
                checked = subprocess.run(current["check_argv"], cwd=ROOT,
                                         stdout=stream, stderr=subprocess.STDOUT,
                                         check=False)
            current["check_exit_code"] = checked.returncode
            current["finished_utc"] = utc_now()
            if checked.returncode != 0:
                current["status"] = "required_test_failed"
                manifest["status"] = "failed"
                code = shell_exit(checked.returncode)
                break
            current["status"] = "passed"
            save_manifest(manifest_path, manifest)
        else:
            manifest["status"] = "passed"
            code = 0
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        if current is not None:
            current["status"] = "interrupted"
        code = 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        manifest["status"] = "harness_failed"
        manifest["error"] = str(error)
        if current is not None:
            current["status"] = "harness_failed"
            current["error"] = str(error)
        code = 1
    finally:
        manifest["finished_utc"] = utc_now()
        manifest["passed_count"] = sum(row["status"] == "passed" for row in cases)
        manifest["not_run_count"] = sum(row["status"] == "not_run" for row in cases)
        manifest["helper_exit_code"] = code
        save_manifest(manifest_path, manifest)
    print(json.dumps({"status": manifest["status"], "manifest": str(manifest_path),
                      "passed_count": manifest["passed_count"],
                      "not_run_count": manifest["not_run_count"],
                      "exit_code": code}, sort_keys=True), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
