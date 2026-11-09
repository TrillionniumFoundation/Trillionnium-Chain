#!/usr/bin/env python3
"""Adversarial reader controls; all generated records are synthetic, not evidence."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import execution_report as reader
sys.path.insert(0, str(reader.ROOT / "scripts" / "ci"))
from test_run_from_zero_native import simulated_confirmation_report

HEAD, TREE = "1" * 40, "2" * 40
BODY = "ab" * 32


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()


def native_record():
    """An explicitly synthetic v4 timing/census record, never native execution."""
    phases = [dict(phase=name, parent_phase=reader.phases.PHASE_PARENTS_V4.get(name),
                   started=False, completed=False, accepted=None, error_code=None,
                   started_ns=None, ended_ns=None, wall_ns=None, thread_cpu_ns=None)
              for name in reader.phases.PHASES_V4]
    work = next(row for row in phases if row["phase"] == "work")
    work.update(started=True, completed=True, accepted=False, started_ns=20,
                ended_ns=70, wall_ns=50, thread_cpu_ns=4)
    row = dict(complete=True, observation_failed=False, connection_id=1, operation=1,
               body_digest=BODY, connection_closed=True, task_created=True, task_closed=True,
               dispatch_started=True, dispatch_accepted=False, dispatch_error_code=None,
               dispatch_thread_cpu_ns=10, full_work_started=True, full_work_accepted=False,
               full_work_thread_cpu_ns=4, submit_phases=phases, terminal_phase="work",
               terminal_error_code=None, application_bytes_read=100, application_bytes_written=20,
               physical_network_bytes=None,
               lifecycle=dict(schema="public-v3-request-lifecycle-v1", accepted_ns=10,
                              connection_closed_ns=80, task_closed_ns=100,
                              clock_is_observer_local=True, has_control_authority=False))
    for name in reader.phases.WAIT_FIELDS_V4:
        row[name] = dict(started_ns=None, ended_ns=None, wall_ns=None,
                         completed=False, accepted=None, error_code=None)
    return row


def native_observer(rows=None):
    rows = [native_record()] if rows is None else rows
    return dict(schema="public-v3-local-request-resource-observation-v4",
                phase_parent_links_are_inclusive=True, cpu_wait_is_outside_dispatch=True,
                monotonic_epoch_is_observer_local=True,
                cpu_includes_reactor_authentication_or_response_signing=True,
                cpu_includes_reactor_authentication=False, dispatch_cpu_includes_paid_body_decode=True,
                dispatch_cpu_includes_response_signing=True, cpu_intervals_are_nested_not_additive=True,
                submit_phase_cpu_excludes_scoped_workers=True, records=rows,
                capacity=16384, accepted_connections_seen=len(rows), records_not_retained=0,
                measurement_failures=0, counter_overflow=False)


def timed_error_record():
    row = native_record()
    row["error_timing"] = dict(schema="public-v3-request-error-timing-v1",
        first_dispatch_error=dict(observed_ns=60, phase="dispatch", error_code="PUBLIC_CPU_BUDGET"),
        first_terminal_error=dict(observed_ns=75, phase="response", error_code="PUBLIC_REQUEST_CANCELLED"),
        observation_failed=False, clock_is_observer_local=True, has_control_authority=False)
    return row


def cancellation_record():
    """Synthetic timing fixture; it establishes no native stop latency."""
    row = native_record()
    row["cancellation"] = dict(schema=reader.phases.REQUEST_CANCELLATION_SCHEMA,
        observed_signal_calls=2, first_flag_transition=dict(before_ns=30, after_ns=35,
            source="peer_write_closed", phase="work"),
        worker_entered=True, worker_entered_ns=15, worker_returned=True, worker_returned_ns=90,
        observation_failed=False, clock_is_observer_local=True,
        signals_are_request_flag_writes=True, has_control_authority=False)
    return row


def reactor_record():
    row = native_record()
    frames = [dict(phase=phase, calls_returned=0, progressed_calls=0, no_progress_calls=0,
        failed_calls=0, wall_ns=None, wall_ns_known_sum=0, wall_unknown_calls=0,
        thread_cpu_ns=None, thread_cpu_ns_known_sum=0, thread_cpu_unknown_calls=0)
        for phase in ("hello", "challenge", "solution", "ready", "body", "response")]
    frames[0].update(calls_returned=2, progressed_calls=1, no_progress_calls=1,
                     wall_ns=30, wall_ns_known_sum=30, thread_cpu_ns=5, thread_cpu_ns_known_sum=5)
    row["reactor_io"] = dict(schema="public-v3-reactor-frame-io-observation-v1", frames=frames,
        observation_failed=False, calls_are_wrapper_returns=True, includes_read_buffer_preparation=True,
        cpu_is_reactor_thread_only=True, includes_wait_between_calls=False, has_control_authority=False)
    return row


def sql_snapshot():
    zero = dict(calls_started=0, calls_returned=0, calls_succeeded=0, calls_failed=0,
                calls_abandoned=0, calls_unwinding=0, wall_ns=None, cpu_ns=None,
                cpu_ns_known_sum=0, wall_unknown_calls=0, cpu_known_calls=0, cpu_unknown_calls=0)
    return dict(schema="pon-native-sql-commit-call-observation-v1", observation_failed=False,
                has_consensus_authority=False, sites=[dict(site=site, totals=copy.deepcopy(zero), calls_in_flight=0)
                    for site in ("admission_persistence", "atomic", "reorg_step", "reorg_termination")])


def negative_round(index, end=30_000_000_001):
    return dict(round=index, started_ns=10, ended_ns=end,
                confirmed_inside_pressure_window=False, observation={"confirmed": False})


def positive_round(index, end=20):
    return dict(round=index, started_ns=10, ended_ns=end,
                confirmed_inside_pressure_window=True, transaction="a1" * 32,
                included_block="b1" * 32, tip="c1" * 32,
                observation=dict(confirmed=True, reorged=False, finalized=False, execution_authority=False,
                                 transaction="a1" * 32, included_block="b1" * 32,
                                 observed_tip="c1" * 32, included_height=1, observed_height=7, depth=6,
                                 required_work_delta=f"{12:0128x}", work_delta=f"{12:0128x}"))


def campaign_phase(mode, rounds=None):
    return dict(mode=mode, state_backend="authenticated-v1", duration_seconds=30,
                confirmations=[] if rounds is None else rounds,
                all_signed_rounds_confirmed_in_window=False, finite_phase_criteria_met=False,
                submissions=[], history=[], children=[], receiver_observation=native_observer(),
                observer_complete=True, service_outcome={}, final_meter={}, verifier_errors=[],
                receiver_client_state_equal=False, genuine_budget_depletion_observed=False,
                attacker_processes_requested=0 if mode == "baseline" else 24,
                attacker_processes_ready=0, actor_reports_successful_without_cap_or_kill=False,
                whole_parent_phase_cpu_ns=None, whole_parent_phase_wall_ns=None,
                receiver_and_verifier_setup_cpu_ns=None, receiver_and_verifier_setup_wall_ns=None)


def campaign_report():
    return dict(schema="native-public-v3-separate-process-campaign-v2", simulated_control=True,
                state_backend="authenticated-v1", finite_experiment_criteria_met=False,
                economics_complete=False, best_observed_cold_legal_method=None,
                preparation=dict(state_backend="authenticated-v1", actual_signed_seed_transfers=1024,
                                 seed_blocks=4, business_blocks=21, cpu_ns=None, wall_ns=None),
                phases=[campaign_phase(mode) for mode in reader.phases.MODES])


def campaign_result():
    return dict(schema="pon-original-native-campaign-ci-v1", simulated_control=True,
                expected_head=HEAD, expected_tree=TREE, source_kind="head", profile="release",
                toolchain="1.95.0", state_backend="authenticated-v1", planned_complete_runs=3,
                original_inputs=copy.deepcopy(reader.original_campaign.INPUTS),
                build_timeout_seconds=1800, original_campaign_outer_timeout_seconds=600,
                expected_resources=copy.deepcopy(reader.CAMPAIGN_CONTRACT["controller_resources"]),
                complete_success=False, failure="SYNTHETIC_BUILD_OR_RUN_FAILURE",
                finalization_failures=[], attempts=[])


class ReportTests(unittest.TestCase):
    def test_cancellation_report_exposes_bounds_without_replacing_original_unknown_stop(self):
        value = reader.request_metrics(native_observer([cancellation_record()]))["cancellation"]
        self.assertIsNone(value["signal_to_stop_latency_ns"])
        self.assertIsNone(value["effects_reconciled"])
        profile = value["request_flag_observation"]
        group = profile["by_first_signal_source"][0]
        self.assertEqual(group["first_signal_source"], "peer_write_closed")
        self.assertEqual(group["worker_return"]["signal_to_terminal_lower_bound_ns"]["min_known"], 55)
        self.assertEqual(group["worker_return"]["signal_to_terminal_upper_bound_ns"]["max_known"], 60)
        self.assertEqual(group["all_request_owners_closed"]["signal_to_terminal_lower_bound_ns"]["min_known"], 65)
        self.assertIsNone(group["worker_return"]["exact_signal_to_terminal_latency_ns"])
        self.assertIsNone(group["worker_return"]["signal_to_terminal_upper_bound_ns"]["known_only_percentiles"]["p95"])

    def test_cancellation_report_keeps_cleanup_and_unknown_sources_separate(self):
        peer = cancellation_record()
        cleanup = cancellation_record()
        cleanup["cancellation"]["first_flag_transition"].update(source="connection_cleanup", phase="cleanup")
        cleanup["cancellation"]["worker_returned_ns"] = 20
        missing = cancellation_record()
        missing["cancellation"]["first_flag_transition"] = None
        value = reader.request_metrics(native_observer([peer, cleanup, missing, native_record()]))
        groups = {group["first_signal_source"]: group for group in
                  value["cancellation"]["request_flag_observation"]["by_first_signal_source"]}
        self.assertEqual(groups[None]["retained_records"], 2)
        self.assertEqual(groups[None]["worker_return"]["signal_to_terminal_upper_bound_ns"]["unknown_count"], 2)
        self.assertEqual(groups["connection_cleanup"]["worker_return"]["status_counts"],
                         {"already_returned_before_signal_bracket": 1})
        self.assertIsNone(groups["connection_cleanup"]["worker_return"]["signal_to_terminal_upper_bound_ns"]["min_known"])
        self.assertFalse(groups["peer_write_closed"]["worker_return"]["signal_to_terminal_upper_bound_ns"]["cohort_complete"])

    def test_cancellation_report_withholds_complete_tail_for_unfinished_or_lost_workers(self):
        unfinished = cancellation_record()
        unfinished["cancellation"].update(worker_returned=False, worker_returned_ns=None)
        values = [cancellation_record(), unfinished]
        value = reader.request_metrics(native_observer(values))["cancellation"]["request_flag_observation"]
        group = value["by_first_signal_source"][0]
        self.assertEqual(group["worker_return"]["signal_to_terminal_upper_bound_ns"]["unknown_count"], 1)
        self.assertEqual(group["all_request_owners_closed"]["signal_to_terminal_upper_bound_ns"]["unknown_count"], 1)
        self.assertFalse(group["worker_return"]["signal_to_terminal_upper_bound_ns"]["cohort_complete"])
        observation = native_observer([cancellation_record(), cancellation_record()])
        observation.update(accepted_connections_seen=3, records_not_retained=1)
        value = reader.request_metrics(observation)["cancellation"]["request_flag_observation"]
        self.assertFalse(value["by_first_signal_source"][0]["worker_return"]["signal_to_terminal_upper_bound_ns"]["cohort_complete"])

    def test_cancellation_report_minimum_samples_apply_to_bound_percentiles(self):
        values = [cancellation_record() for _ in range(20)]
        value = reader.request_metrics(native_observer(values))["cancellation"]["request_flag_observation"]
        group = value["by_first_signal_source"][0]["worker_return"]
        self.assertEqual(group["signal_to_terminal_upper_bound_ns"]["complete_cohort_percentiles"]["p95"], 60)
        self.assertIsNone(group["signal_to_terminal_upper_bound_ns"]["complete_cohort_percentiles"]["p99"])
        values[-1]["cancellation"]["first_flag_transition"] = None
        value = reader.request_metrics(native_observer(values))["cancellation"]["request_flag_observation"]
        group = next(row for row in value["by_first_signal_source"] if row["first_signal_source"] == "peer_write_closed")
        self.assertFalse(group["worker_return"]["signal_to_terminal_upper_bound_ns"]["cohort_complete"])

    def test_cancellation_report_does_not_change_any_historical_projection_field(self):
        old = reader.request_metrics(native_observer([native_record()]))
        current = reader.request_metrics(native_observer([cancellation_record()]))
        current["cancellation"].pop("request_flag_observation")
        current["original_execution_readback"].pop("request_cancellation")
        self.assertEqual(current, old)
        self.assertNotIn("request_flag_observation", old["cancellation"])

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="trnm-execution-report-control-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def bundle(self, reports=None, *, result_change=None, report_change=None):
        result = campaign_result()
        files = {}
        for index, report in (reports or {}).items():
            report = copy.deepcopy(report)
            if report_change:
                report_change(report)
            name = f"run-{index}-raw/report.json"
            raw = encoded(report)
            files[name] = raw
            result["attempts"].append(dict(number=index, report_directory=f"run-{index}-raw",
                report_sha256=hashlib.sha256(raw).hexdigest(), complete_success=False,
                original_criteria_met=False, report_validation_failure=None,
                step=dict(returncode=101, error=None, outer_stage_timeout_seconds=600)))
        if result_change:
            result_change(result)
        files["results.json"] = encoded(result)
        for name, raw in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        manifest = {"files": [dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                              for name, raw in sorted(files.items())]}
        manifest_raw = encoded(manifest)
        (self.root / "artifact-files.json").write_bytes(manifest_raw)
        return hashlib.sha256(manifest_raw).hexdigest()

    def read(self, pin):
        return reader.read_campaign(self.root, pin, HEAD, TREE)

    def test_absent_evidence_keeps_both_original_plans_and_never_becomes_zero(self):
        report = reader.build_report()
        self.assertEqual(report["qualification"], "HOLD_NO_GO")
        self.assertEqual(report["native_executions_started"], 0)
        host = report["original_host_4s"]
        campaign = report["original_campaign_30s"]
        self.assertEqual(host["contract"]["deadline_ns"], 4_000_000_000)
        self.assertEqual(campaign["contract"]["deadline_ns"], 30_000_000_000)
        self.assertEqual([p["planned_confirmations"] for p in host["phases"]], [1, 1])
        self.assertEqual(campaign["confirmation_denominator"]["planned"], 27)
        self.assertEqual(campaign["confirmation_denominator"]["unknown"], 27)
        self.assertIsNone(campaign["confirmation_denominator"]["total_timely"])
        self.assertFalse(report["scope"]["contracts_combined"])
        self.assertIsNone(report["scope"]["combined_tps"])

    def test_build_failure_retains_all_twenty_seven_unknown_rounds(self):
        value = self.read(self.bundle())
        self.assertEqual(value["original_result"]["failure"], "SYNTHETIC_BUILD_OR_RUN_FAILURE")
        self.assertEqual(value["confirmation_denominator"]["records_present"], 0)
        self.assertEqual(value["confirmation_denominator"]["unknown"], 27)
        self.assertEqual(len(value["runs"]), 3)
        self.assertFalse(value["strict_original_acceptance_reader_executed"])

    def test_failed_report_keeps_missing_runs_and_rounds(self):
        report = campaign_report()
        report["phases"][0]["confirmations"] = [negative_round(0), negative_round(2)]
        value = self.read(self.bundle({1: report}))
        counts = value["confirmation_denominator"]
        self.assertEqual(counts["planned"], 27)
        self.assertEqual(counts["records_present"], 2)
        self.assertEqual(counts["observed_supported_not_timely"], 2)
        self.assertEqual(counts["unknown"], 25)
        self.assertIsNone(counts["total_timely"])
        self.assertEqual(value["runs"][0]["phases"][0]["rounds"][1]["status"], "not_observed")

    def test_startup_failure_is_not_zero_completion_or_missing_denominator(self):
        report = campaign_report()
        report["phases"][0] = dict(mode="baseline", state_backend="authenticated-v1",
                                    startup_or_campaign_error="SYNTHETIC_HOST_REFUSAL")
        value = self.read(self.bundle({1: report}))
        phase = value["runs"][0]["phases"][0]
        self.assertEqual(phase["status"], "startup_or_campaign_error")
        self.assertEqual(len(phase["rounds"]), 3)
        self.assertTrue(all(r["supported_in_window"] is None for r in phase["rounds"]))
        self.assertEqual(value["confirmation_denominator"]["unknown"], 27)

    def test_original_contract_changes_are_rejected_even_if_new_report_claims_success(self):
        changes = [lambda x: x.update(planned_complete_runs=2),
                   lambda x: x["original_inputs"].update(phase_seconds=31),
                   lambda x: x["original_inputs"].update(attacker_processes=[0, 16, 16]),
                   lambda x: x["original_inputs"].update(attacker_processes=[False, 24, 24]),
                   lambda x: x["expected_resources"].update(cpu_max="25000 100000"),
                   lambda x: x.update(expected_head="3" * 40)]
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "identity/resource/window/denominator"):
                    self.read(self.bundle(result_change=change))

    def test_actual_phase_window_and_attack_plan_cannot_be_relaxed(self):
        for change in (lambda x: x["phases"][0].update(duration_seconds=31),
                       lambda x: x["phases"][1].update(attacker_processes_requested=16)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.read(self.bundle({1: campaign_report()}, report_change=change))

    def test_duplicate_run_and_round_cannot_replace_missing_slots(self):
        with self.assertRaisesRegex(ValueError, "duplicate or unplanned run"):
            self.read(self.bundle({1: campaign_report()}, result_change=lambda x:
                                  x["attempts"].append(copy.deepcopy(x["attempts"][0]))))
        with self.assertRaises(ValueError):
            self.read(self.bundle({1: campaign_report()}, report_change=lambda x:
                x["phases"][0].update(confirmations=[negative_round(0), negative_round(0)])))

    def test_missing_listed_file_and_hash_mismatch_do_not_become_valid_unknowns(self):
        pin = self.bundle({1: campaign_report()})
        with self.assertRaisesRegex(ValueError, "file-list SHA256"):
            self.read("0" * 64)
        (self.root / "run-1-raw/report.json").unlink()
        with self.assertRaises(OSError):
            self.read(pin)

    def test_report_missing_from_producer_manifest_preserves_run_record(self):
        def add_attempt(result):
            result["attempts"] = [dict(number=2, report_directory="run-2-raw", report_sha256=None,
                                       complete_success=False, step={"error": "SYNTHETIC_TIMEOUT"})]
        value = self.read(self.bundle(result_change=add_attempt))
        self.assertEqual(value["runs"][1]["report_retention"], "not_listed_by_producer")
        self.assertEqual(value["confirmation_denominator"]["unknown"], 27)

    def test_disconnected_native_identity_cannot_be_counted_as_confirmation(self):
        row = positive_round(0)
        row["observation"]["transaction"] = "f1" * 32
        with self.assertRaisesRegex(ValueError, "native binding"):
            reader.round_slot(0, row)
        row = positive_round(0)
        row["observation"]["work_delta"] = "0" * 128
        with self.assertRaisesRegex(ValueError, "cumulative-work"):
            reader.round_slot(0, row)

    def test_exact_deadline_is_late_and_early_negative_remains_unknown(self):
        with self.assertRaisesRegex(ValueError, "original thirty-second window"):
            reader.round_slot(0, positive_round(0, 30_000_000_000))
        early = reader.round_slot(0, negative_round(0, 100))
        self.assertIsNone(early["supported_in_window"])
        late = positive_round(0, 30_000_000_000)
        late["confirmed_inside_pressure_window"] = False
        self.assertEqual(reader.round_slot(0, late)["status"], "late_native_confirmation")
        late["ended_ns"] = 100
        self.assertEqual(reader.round_slot(0, late)["status"], "contradictory_observation")

    def test_latency_tails_keep_unknown_duration_and_sample_resolution(self):
        small = reader.statistics(range(19), complete=True)
        self.assertIsNone(small["known_only_percentiles"]["p95"])
        sufficient = reader.statistics(list(range(100)), complete=True)
        self.assertEqual(sufficient["complete_cohort_percentiles"]["p99"], 98)
        missing = reader.statistics(list(range(100)) + [None], complete=True)
        self.assertEqual(missing["known_only_percentiles"]["p99"], 98)
        self.assertIsNone(missing["complete_cohort_percentiles"]["p99"])
        self.assertEqual(missing["unknown_count"], 1)
        for invalid in (True, -1, 1.0, 2**64):
            with self.assertRaises(ValueError):
                reader.statistics([invalid])

    def test_repeated_attempts_do_not_fill_planned_submission_slots(self):
        value = reader.call_census([dict(status="error", packet_index=0, elapsed_wall_ns=10)] * 7, planned=7)
        self.assertEqual(value["recorded_attempts"], 7)
        self.assertEqual(value["observed_distinct_planned_slots"], 1)
        self.assertEqual(value["repeated_planned_slot_attempts"], 6)
        self.assertEqual(value["unobserved_or_unbound_planned_slots"], 6)

    def test_owner_lifetime_keeps_late_work_after_socket_close(self):
        row = native_record()
        value = reader.request_metrics(native_observer([row]))
        lifetime = value["per_request_owner_lifetime"]
        self.assertEqual(lifetime["accept_to_all_owners_closed"]["max_known"], 90)
        self.assertEqual(lifetime["original_owner_readback"]["task_ownership_after_connection_close_wall_ns"]["max_ns"], 20)
        self.assertIsNone(value["cancellation"]["signal_to_stop_latency_ns"])
        row.update(complete=False, task_closed=False)
        row["lifecycle"]["task_closed_ns"] = None
        live = reader.request_metrics(native_observer([row]))
        self.assertEqual(live["per_request_owner_lifetime"]["accept_to_all_owners_closed"]["unknown_count"], 1)
        self.assertFalse(live["coverage"]["all_seen_records_closed_and_retained"])

    def test_loss_and_measurement_failures_cannot_qualify_complete_tails(self):
        observer = native_observer([native_record() for _ in range(100)])
        observer.update(accepted_connections_seen=101, records_not_retained=1)
        value = reader.request_metrics(observer)
        self.assertEqual(value["per_request_owner_lifetime"]["accept_to_all_owners_closed"]["known_only_percentiles"]["p99"], 90)
        self.assertIsNone(value["per_request_owner_lifetime"]["accept_to_all_owners_closed"]["complete_cohort_percentiles"]["p99"])
        self.assertIsNone(value["network"]["physical_network_bytes"])
        self.assertIsNone(value["wal"]["bytes"])
        self.assertIsNone(value["cpu"]["whole_request_cpu_ns"])

    def test_ambiguous_body_claim_is_not_an_attributed_malicious_rejection(self):
        call = {"public_request_body_digest": BODY}
        value = reader.request_metrics(native_observer(), role_calls={"attack": [call], "honest": [call]})
        self.assertEqual(value["malicious_rejection"]["ambiguous_role_records"], 1)
        self.assertEqual(value["malicious_rejection"]["retained_attack_claim_records"], 0)
        self.assertIsNone(value["malicious_rejection"]["final_terminal_rejection_latency_ns"])
        value = reader.request_metrics(native_observer(), role_calls={"attack": [call]})
        self.assertEqual(value["malicious_rejection"]["accept_to_last_observed_rejecting_stage_per_request"]["max_known"], 60)
        self.assertIsNone(value["malicious_rejection"]["worst_case_rejection_bound_ns"])

    def test_cancel_after_dispatch_does_not_erase_dispatch_result(self):
        row = native_record()
        row.update(dispatch_accepted=True, full_work_accepted=True, terminal_error_code="PUBLIC_REQUEST_CANCELLED")
        next(slot for slot in row["submit_phases"] if slot["phase"] == "work")["accepted"] = True
        value = reader.request_metrics(native_observer([row]))
        self.assertEqual(value["cancellation"]["records_with_typed_cancel"], 1)
        self.assertEqual(value["original_execution_readback"]["dispatch_outcomes"]["accepted"], 1)
        self.assertIsNone(value["cancellation"]["effects_reconciled"])

    def test_actual_first_errors_are_not_owner_close_or_later_error_codes(self):
        row = timed_error_record()
        row.update(dispatch_error_code="PUBLIC_REQUEST_DEADLINE", terminal_error_code="PUBLIC_EOF")
        measured = reader.request_metrics(native_observer([row]), role_calls={"attack": [{"public_request_body_digest": BODY}]})
        errors = measured["malicious_rejection"]["first_error_latency"]
        self.assertEqual(errors["first_dispatch_error"]["latency"]["max_known"], 50)
        self.assertEqual(errors["first_terminal_error"]["latency"]["max_known"], 65)
        self.assertEqual(measured["per_request_owner_lifetime"]["accept_to_all_owners_closed"]["max_known"], 90)
        self.assertEqual(errors["original_readback"]["first_dispatch_error"]["first_error_code_counts"], {"PUBLIC_CPU_BUDGET": 1})
        self.assertEqual(measured["cancellation"]["typed_dispatch_errors"], {"PUBLIC_REQUEST_DEADLINE": 1})
        self.assertIsNone(errors["first_terminal_error"]["latency"]["known_only_percentiles"]["p99"])
        self.assertIsNone(measured["malicious_rejection"]["worst_case_rejection_bound_ns"])

    def test_error_capture_failure_and_historical_missing_events_withhold_complete_max(self):
        row = timed_error_record()
        row.update(observation_failed=True, complete=False)
        row["error_timing"]["observation_failed"] = True
        value = reader.request_metrics(native_observer([row]))["cancellation"]["all_request_first_errors"]
        self.assertEqual(value["first_dispatch_error"]["latency"]["unknown_count"], 1)
        self.assertIsNone(value["first_dispatch_error"]["max_complete_captured_event_cohort_ns"])
        value = reader.request_metrics(native_observer([timed_error_record(), native_record()]))["cancellation"]["all_request_first_errors"]
        self.assertEqual(value["original_readback"]["historical_records_without_extension"], 1)
        self.assertIsNone(value["first_dispatch_error"]["max_complete_captured_event_cohort_ns"])

    def test_live_owner_keeps_first_event_but_not_complete_error_tail(self):
        row = timed_error_record()
        row.update(complete=False, task_closed=False)
        row["lifecycle"]["task_closed_ns"] = None
        value = reader.request_metrics(native_observer([row]))["cancellation"]["all_request_first_errors"]
        self.assertEqual(value["first_dispatch_error"]["latency"]["max_known"], 50)
        self.assertIsNone(value["first_dispatch_error"]["max_complete_captured_event_cohort_ns"])
        self.assertEqual(value["original_readback"]["incomplete_owner_records"], 1)

    def test_frame_io_wrapper_census_is_not_physical_network_or_per_call_tail(self):
        row = reactor_record()
        value = reader.request_metrics(native_observer([row]))
        frames = value["network"]["reactor_frame_io"]["frames"]
        self.assertEqual(frames[0]["calls_returned"], 2)
        self.assertEqual(frames[0]["no_progress_calls"], 1)
        self.assertEqual(frames[0]["per_record_wall_ns"]["max_ns"], 30)
        self.assertIsNone(value["network"]["physical_network_bytes"])
        row["reactor_io"]["frames"][0]["calls_returned"] = 1
        with self.assertRaisesRegex(ValueError, "outcome denominator"):
            reader.request_metrics(native_observer([row]))

    def test_unfinished_queue_wait_does_not_disappear_from_tail_denominator(self):
        rows = [native_record() for _ in range(101)]
        for row in rows[:-1]:
            row["paid_task_queue_wait"].update(started_ns=10, ended_ns=20, wall_ns=10, completed=True, accepted=True)
        rows[-1]["paid_task_queue_wait"].update(started_ns=10, ended_ns=110, wall_ns=100)
        queue = reader.request_metrics(native_observer(rows))["queue"]["paid_task_queue_wait"]
        self.assertEqual(queue["terminal"], 100)
        self.assertEqual(queue["unfinished"], 1)
        self.assertEqual(queue["terminal_latency"]["known_only_percentiles"]["p99"], 10)
        self.assertIsNone(queue["terminal_latency"]["complete_cohort_percentiles"]["p99"])
        self.assertEqual(queue["unfinished_observed_elapsed"]["max_known"], 100)

    def test_cumulative_sql_observations_never_become_fsync_or_request_tail(self):
        snapshot = sql_snapshot()
        measured = reader.sql_commit_snapshots({"native_history_arithmetic_after": {"sql_commit": snapshot}})
        self.assertEqual(measured["snapshots_observed"], 1)
        self.assertIsNone(measured["per_request_latency_percentiles"])
        self.assertIsNone(measured["physical_fsync_latency_ns"])
        self.assertIsNone(measured["difference_between_snapshots"])
        self.assertIsNone(measured["snapshots"]["native_history_arithmetic_after"]["sites"][0]["totals"]["cpu_ns"])
        snapshot["sites"][0]["totals"]["cpu_ns"] = 0
        with self.assertRaisesRegex(ValueError, "unknown/complete time"):
            reader.sql_commit_snapshots({"native_history_arithmetic_after": {"sql_commit": snapshot}})

    def test_original_four_second_reader_is_reused_and_outputs_stay_separate(self):
        raw = encoded(simulated_confirmation_report())
        path = self.root / "host.json"
        path.write_bytes(raw)
        pin = hashlib.sha256(raw).hexdigest()
        with patch.object(reader.transactions, "read_host_report", wraps=reader.transactions.read_host_report) as existing:
            value = reader.build_report(host_report=path, host_report_sha256=pin)
        existing.assert_called_once()
        self.assertTrue(value["original_host_4s"]["original_readback"]["simulated_control"])
        self.assertEqual([row["observed_confirmations"] for row in value["original_host_4s"]["phases"]], [1, 1])
        self.assertEqual(value["original_campaign_30s"]["confirmation_denominator"]["unknown"], 27)
        self.assertEqual(value["qualification"], "HOLD_NO_GO")

    def test_four_second_window_cannot_be_changed_to_thirty_seconds(self):
        report = simulated_confirmation_report()
        report["phases"][0]["requested_window_ns"] = 30_000_000_000
        raw = encoded(report)
        path = self.root / "host.json"
        path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "ORIGINAL_WINDOW"):
            reader.read_host(path, hashlib.sha256(raw).hexdigest())

    def test_cli_valid_hold_is_one_and_existing_output_is_never_overwritten(self):
        pin = self.bundle()
        output = self.root / "unified.json"
        args = ["--campaign-dir", str(self.root), "--campaign-manifest-sha256", pin,
                "--expected-head", HEAD, "--expected-tree", TREE, "--output", str(output)]
        self.assertEqual(reader.main(args), 1)
        original = output.read_bytes()
        with redirect_stderr(io.StringIO()):
            self.assertEqual(reader.main(args), 2)
        self.assertEqual(output.read_bytes(), original)
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            self.assertEqual(reader.main([]), 2)


if __name__ == "__main__":
    unittest.main()
