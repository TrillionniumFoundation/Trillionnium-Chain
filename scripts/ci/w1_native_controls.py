#!/usr/bin/env python3
"""Require every frozen W1 native control and its one successful completion.

The named roster is independent of counts printed by the Rust test harness.
Logs remain execution observations, not proof of work-cost or security claims.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

from pq_source_reader import SourceReadError, read_regular

MAX_LOG_BYTES = 16 * 1024 * 1024
# Current native roster: retains the original controls and names all additions.
# The sole ignored entry is the retained child fixture executed by its SIGKILL
# parent control, not an exemption for an unexecuted required control.
SUITES = {'legal-native-controls': {'passed': ['tests::exact_shards_reject_unfrozen_targets_horizons_and_extra_arguments',
                                      'tests::last_product_mutation_wraps_canonically_and_changes_only_that_word',
                                      'tests::public_dispatch_keeps_complete_bytes_and_all_misses',
                                      'tests::v2_final_sample_keeps_both_legal_producers_and_complete_negative_verification',
                                      'tests::valid_acquisition_and_late_product_refusal_keep_full_statement_identity',
                                      'tests::versions_keep_exact_namespaces_and_eight_new_sample_streams',
                                      'w1_cost_producers::observed_search_tests::complete_observed_stream_matches_retained_wrapper_byte_for_byte',
                                      'w1_cost_producers::observed_search_tests::completion_observer_failure_never_starts_another_attempt',
                                      'w1_cost_producers::observed_search_tests::malformed_generated_proof_has_started_and_failed_record',
                                      'w1_cost_producers::observed_search_tests::native_failure_retains_completed_attempt_and_failed_begin',
                                      'w1_cost_producers::observed_search_tests::observer_begin_refusal_precedes_native_generation',
                                      'w1_material::tests::default_materials_include_exact_continuity_fixture_and_reported_ranks',
                                      'w1_material::tests::material_bytes_require_exact_length_and_canonical_field_values'],
                           'ignored': {}},
 'factorial-kernel-tests': {'passed': ['pon_work::legal_attempt::low_rank::tests::both_inputs_are_fully_validated_before_zero_or_high_rank_shortcuts',
                                       'pon_work::legal_attempt::low_rank::tests::bounded_factorization_reconstructs_exact_full_field_rank_and_pivot_orders',
                                       'pon_work::legal_attempt::low_rank::tests::exact_rank_limit_chooses_left_then_right_and_explicit_paid_dense_fallback',
                                       'pon_work::legal_attempt::low_rank::tests::low_rank_complete_proofs_equal_both_original_kernels_and_verifiers',
                                       'pon_work::legal_attempt::low_rank::tests::misses_still_replay_all_tiles_and_cancelled_retries_preserve_the_same_task',
                                       'pon_work::legal_attempt::tests::boundary_target_is_inclusive_and_zero_target_refuses_before_work',
                                       'pon_work::legal_attempt::tests::changed_challenge_and_task_never_gain_acceptance_from_cached_product',
                                       'pon_work::legal_attempt::tests::checked_rank_one_and_bounded_rank_preparation_share_bytes_but_keep_distinct_domains',
                                       'pon_work::legal_attempt::tests::checked_rank_one_preparation_matches_dense_sparse_and_independent_replay',
                                       'pon_work::legal_attempt::tests::checked_rank_one_preparation_preserves_complete_misses_and_cancellation',
                                       'pon_work::legal_attempt::tests::checked_rank_one_preparation_refuses_other_ranks_and_hidden_malformed_words',
                                       'pon_work::legal_attempt::tests::checked_rank_one_reuse_rejects_changed_challenge_transcript_and_product',
                                       'pon_work::legal_attempt::tests::every_stage_cancellation_returns_no_attempt_and_does_not_poison_retry',
                                       'pon_work::legal_attempt::tests::factorial_kernels_match_independent_reference_for_full_and_structured_fields',
                                       'pon_work::legal_attempt::tests::losing_attempt_still_replays_every_transcript_tile_without_lazy_serialization',
                                       'pon_work::legal_attempt::tests::preparation_never_reduces_noncanonical_fields_or_wrong_shapes',
                                       'pon_work::legal_attempt::tests::sparse_preparation_matches_dense_and_independent_full_field_proofs',
                                       'pon_work::legal_attempt::tests::sparse_preparation_rejects_hidden_noncanonical_words_and_wrong_lengths',
                                       'pon_work::legal_attempt::tests::sparse_setup_keeps_complete_misses_callbacks_and_cancelled_retry'],
                            'ignored': {}},
 'factorial-example-tests': {'passed': ['tests::exact_shards_reject_unfrozen_targets_horizons_and_extra_arguments',
                                        'tests::factorial_search_keeps_every_miss_and_identical_complete_winners',
                                        'tests::last_product_mutation_wraps_canonically_and_changes_only_that_word',
                                        'tests::valid_acquisition_and_late_product_refusal_keep_full_statement_identity',
                                        'w1_cost_producers::observed_search_tests::complete_observed_stream_matches_retained_wrapper_byte_for_byte',
                                        'w1_cost_producers::observed_search_tests::completion_observer_failure_never_starts_another_attempt',
                                        'w1_cost_producers::observed_search_tests::malformed_generated_proof_has_started_and_failed_record',
                                        'w1_cost_producers::observed_search_tests::native_failure_retains_completed_attempt_and_failed_begin',
                                        'w1_cost_producers::observed_search_tests::observer_begin_refusal_precedes_native_generation',
                                        'w1_material::tests::default_materials_include_exact_continuity_fixture_and_reported_ranks',
                                        'w1_material::tests::material_bytes_require_exact_length_and_canonical_field_values'],
                             'ignored': {}},
 'header-binding-tests': {'passed': ['complete_w1_proofs_cannot_move_between_header_fields_or_growth_domains'],
                          'ignored': {}},
 'history-w1-tests': {'passed': ['ingress::history_import::tests::history_w1_checks_host_once_at_every_native_boundary_without_refill',
                                 'ingress::history_import::tests::history_w1_checks_host_once_at_every_real_progress_boundary',
                                 'ingress::history_import::tests::history_w1_host_cancellation_keeps_original_error_deadline_and_paid_account',
                                 'ingress::history_import::tests::history_w1_host_change_at_selected_and_unselected_boundaries_refuses_and_retries',
                                 'ingress::history_import::tests::history_w1_original_deadline_precedes_resource_and_complete_work'],
                      'ignored': {}},
 'history-import-tests': {'passed': ['ingress::history_import::tests::actual_detached_m06_cannot_continue_after_original_cpu_account_is_fenced',
                                     'ingress::history_import::tests::committed_history_keeps_original_deadline_inside_native_activation',
                                     'ingress::history_import::tests::concurrent_false_product_wrong_root_and_honest_history_share_one_account',
                                     'ingress::history_import::tests::deadline_controls::final_resource_completion_preserves_error_priority_and_original_deadline',
                                     'ingress::history_import::tests::deadline_controls::final_resource_expiry_keeps_committed_history_and_settled_cpu',
                                     'ingress::history_import::tests::deadline_controls::history_control_keeps_original_timely_single_resource_observation',
                                     'ingress::history_import::tests::deadline_controls::history_control_preexpired_does_not_invoke_resource',
                                     'ingress::history_import::tests::deadline_controls::history_control_resource_expiry_keeps_original_resource_error',
                                     'ingress::history_import::tests::deadline_controls::history_control_resource_expiry_refuses_late_success',
                                     'ingress::history_import::tests::deadline_controls::history_owner_resource_expiry_never_invokes_exclusive_or_shared_action',
                                     'ingress::history_import::tests::deadline_controls::late_admission_keeps_committed_identity_paid_cpu_and_exact_retry',
                                     'ingress::history_import::tests::deadline_controls::metered_expiry_preserves_native_errors_and_settles_the_original_account',
                                     'ingress::history_import::tests::deadline_controls::scope_expiry_preserves_cleanup_native_error_and_cold_reopen',
                                     'ingress::history_import::tests::detached_budget_controls::shared_detached_history_before_native_completion_keeps_sticky_budget_refusal',
                                     'ingress::history_import::tests::detached_budget_controls::shared_detached_history_continues_from_real_deficit_without_new_credit',
                                     'ingress::history_import::tests::detached_budget_controls::shared_detached_history_refill_cannot_renew_original_deadline',
                                     'ingress::history_import::tests::detached_budget_controls::shared_detached_history_refill_keeps_original_resource_cancellation',
                                     'ingress::history_import::tests::expired_history_never_starts_an_epoch_or_a_cpu_account',
                                     'ingress::history_import::tests::first_history_resource_failure_preserves_cold_account_and_clean_restart',
                                     'ingress::history_import::tests::history_codec_snapshot_preserves_legacy_bytes_identity_and_deferred_profile_errors',
                                     'ingress::history_import::tests::history_decode_cannot_renew_the_original_w1_deadline',
                                     'ingress::history_import::tests::history_host_rejection_keeps_native_boundaries_nonce_and_original_paid_account',
                                     'ingress::history_import::tests::history_page_cannot_decode_past_fixed_tip_before_native_admission',
                                     'ingress::history_import::tests::history_shared_owner_busy_retry_keeps_fresh_host_refusal',
                                     'ingress::history_import::tests::history_shared_owner_checks_host_once_before_each_uncontended_action',
                                     'ingress::history_import::tests::history_w1_checks_host_once_at_every_native_boundary_without_refill',
                                     'ingress::history_import::tests::history_w1_checks_host_once_at_every_real_progress_boundary',
                                     'ingress::history_import::tests::history_w1_host_cancellation_keeps_original_error_deadline_and_paid_account',
                                     'ingress::history_import::tests::history_w1_host_change_at_selected_and_unselected_boundaries_refuses_and_retries',
                                     'ingress::history_import::tests::history_w1_original_deadline_precedes_resource_and_complete_work',
                                     'ingress::history_import::tests::observed_expired_history_keeps_failure_and_unentered_phases_null',
                                     'ingress::history_import::tests::observed_history_retains_complete_native_path_and_real_w1_cancellation',
                                     'ingress::history_import::tests::one_history_close_cannot_clear_another_imports_live_epoch',
                                     'ingress::history_import::tests::pinned_activation_failure_keeps_committed_packet_and_retry_does_not_repeat_w1',
                                     'ingress::history_import::tests::pinned_completion_requires_existing_owner_and_expired_completion_cannot_mint_one',
                                     'ingress::history_import::tests::pinned_final_packet_and_known_completion_keep_one_owner_without_repeating_w1',
                                     'ingress::history_import::tests::real_sigkill_history_cuts_preserve_debt_fence_and_committed_blocks',
                                     'ingress::history_import::tests::shared_admission_owner_wait_observes_control_deadline_and_original_two_second_limit',
                                     'ingress::history_import::tests::shared_history_native_completion_handoff_settles_before_next_packet',
                                     'ingress::history_import::tests::shared_history_paid_deficit_refuses_without_waiting_under_original_writer',
                                     'ingress::history_import::tests::shared_history_refill_full_w1_and_actual_m06_release_the_original_writer'],
                          'ignored': {'ingress::history_import::tests::history_kill_cut_child': 'subprocess fixture: '
                                                                                                'parent selects a real '
                                                                                                'SIGKILL cut'}},
 'cpu-completion-tests': {'passed': ['ingress::public_v3::scalar_cpu::completion_tests::actual_w1_cpu_completion_waits_for_original_refill_and_preserves_balance_identity',
                                     'ingress::public_v3::scalar_cpu::completion_tests::already_running_probe_cannot_spend_beyond_its_original_quantum_during_completion',
                                     'ingress::public_v3::scalar_cpu::completion_tests::complete_actual_w1_blocks_new_probes_without_new_credit_and_releases_once',
                                     'ingress::public_v3::scalar_cpu::completion_tests::completion_identity_survives_cancel_and_unknown_without_invalidating_retry',
                                     'ingress::public_v3::scalar_cpu::completion_tests::completion_keeps_original_cancellation_deadline_and_unknown_clock_fences',
                                     'ingress::public_v3::scalar_cpu::completion_tests::completion_work_claim_is_atomic_across_real_verifiers_and_domain_clones',
                                     'ingress::public_v3::scalar_cpu::completion_tests::exclusive_history_refill_observes_original_resource_cancellation_without_new_credit',
                                     'ingress::public_v3::scalar_cpu::completion_tests::full_completion_registry_keeps_all_markers_and_allows_real_native_admission',
                                     'ingress::public_v3::scalar_cpu::completion_tests::only_fresh_successful_native_w1_promotes_not_false_product_or_existing_packet',
                                     'ingress::public_v3::scalar_cpu::completion_tests::same_valid_w1_native_invalid_packet_cannot_reacquire_completion_priority',
                                     'ingress::public_v3::scalar_cpu::completion_tests::same_verified_w1_with_changed_transaction_body_is_rejected_before_promotion'],
                          'ignored': {}}}

GROUPS = {
    "legal": ("legal-native-controls",),
    "factorial": (
        "factorial-kernel-tests", "factorial-example-tests", "header-binding-tests",
        "history-w1-tests", "history-import-tests", "cpu-completion-tests",
    ),
}
# These two example invocations have no native test selector. Preserve
# the upstream requirement that their complete rosters are unfiltered.
UNFILTERED_SUITES = frozenset(("legal-native-controls", "factorial-example-tests"))
NUMBER = r"(?:0|[1-9][0-9]*)"
HEADER = re.compile(r"running (" + NUMBER + r") tests?")
SUMMARY = re.compile(
    r"test result: ok\. (" + NUMBER + r") passed; 0 failed; (" + NUMBER
    + r") ignored; 0 measured; (" + NUMBER
    + r") filtered out; finished in " + NUMBER + r"(?:\.[0-9]+)?s"
)
START = re.compile(r"test (\S+) \.\.\. (.*)")


class NativeControlError(ValueError):
    pass


def validate_log(suite: str, raw: str) -> dict:
    """Check one serial Rust harness, including --nocapture completion lines."""
    roster = SUITES[suite]
    required = roster["passed"]
    ignored = roster["ignored"]
    expected = set(required) | set(ignored)
    if len(required) != len(set(required)) or set(required) & set(ignored):
        raise NativeControlError(suite + ": invalid required roster")
    started = []
    passed = []
    observed_ignored = {}
    pending = None
    header = None
    summary = None

    def refuse(reason):
        raise NativeControlError(suite + ": " + reason)

    for line in raw.splitlines():
        if line.startswith("running "):
            match = HEADER.fullmatch(line)
            if match is None or header is not None or summary is not None:
                refuse("missing, malformed or repeated harness start")
            header = int(match[1])
        elif line.startswith("test result:"):
            match = SUMMARY.fullmatch(line)
            if match is None or header is None or summary is not None or pending is not None:
                refuse("failed, unfinished, malformed or repeated harness completion")
            summary = (int(match[1]), int(match[2]))
            if suite in UNFILTERED_SUITES and int(match[3]) != 0:
                refuse("unfiltered example reports filtered controls")
        elif line.startswith("test "):
            match = START.fullmatch(line)
            if match is None or header is None or summary is not None or pending is not None:
                refuse("test outside a serial active harness")
            name, status = match.groups()
            if name not in expected or name in started:
                refuse("unexpected or duplicate control: " + name)
            started.append(name)
            if name in ignored:
                if status != "ignored, " + ignored[name]:
                    refuse("retained subprocess fixture status changed: " + name)
                observed_ignored[name] = ignored[name]
            elif status == "ok":
                passed.append(name)
            elif status == "FAILED" or status.startswith("ignored"):
                refuse("required control did not pass: " + name)
            else:
                # --test-threads=1 keeps this name open across its retained
                # --nocapture output until the harness emits its own terminal.
                pending = name
        elif line == "ok":
            if pending is None or summary is not None:
                refuse("orphan or duplicate success terminal")
            passed.append(pending)
            pending = None
        elif line == "FAILED" or line.startswith("ignored"):
            refuse("unsuccessful control terminal")

    if header != len(expected) or summary != (len(required), len(ignored)):
        refuse("exact native count or final summary differs")
    if (pending is not None or Counter(started) != Counter(expected)
            or Counter(passed) != Counter(required) or observed_ignored != ignored):
        refuse("exact started and successfully completed names differ")
    return {
        "suite": suite, "started": sorted(started), "passed": sorted(passed),
        "ignored_subprocess_fixtures": observed_ignored,
        "passed_count": len(passed), "ignored_count": len(observed_ignored),
    }


def check_group(group: str, logs: Path) -> dict:
    observations = []
    for suite in GROUPS[group]:
        raw = read_regular(logs, suite + ".log", MAX_LOG_BYTES)
        observation = validate_log(suite, raw.decode("utf-8", errors="strict"))
        observation.update({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        observations.append(observation)
    return {
        "schema": "trnm-w1-native-control-completion-v1", "group": group,
        "all_required_native_controls_completed": True, "suites": observations,
        "scope": "named serial native harness completion; no cost or security qualification",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", choices=tuple(GROUPS), required=True)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = check_group(args.group, args.logs)
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    except (NativeControlError, SourceReadError, UnicodeError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
