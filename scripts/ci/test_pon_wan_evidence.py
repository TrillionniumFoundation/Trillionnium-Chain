#!/usr/bin/env python3
"""Adversarial controls for denominators, never actual WAN observations."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_wan_evidence as W


def fixture():
    start = 1_800_000_000_000
    manifest = dict(schema="trnm-wan-preregistration-v1", start_unix_ms=start,
        end_unix_ms=start+72*3600*1000, confirmation_depth=6,
        chain_source_sha256="1"*64, hepta_source_sha256="2"*64, threat_model_sha256="3"*64,
        operators=[dict(id=f"o{i}",administrator=f"admin{i}",failure_domain=f"zone{i}",endpoint=f"TEST_ONLY:{i}",external_attestation_sha256="4"*64) for i in range(3)],
        cohorts=[dict(id="hostile",max_confirmation_ms=5000,minimum_samples_per_operator=2,minimum_timely_ppm=900000)], schedule=[])
    rows = []
    for i in range(3):
        for j in range(2):
            row=dict(id=f"o{i}-r{j}",operator=f"o{i}",cohort="hostile",operation_sha256=f"{i*2+j:064x}",scheduled_unix_ms=start+j*10000)
            manifest["schedule"].append(row)
            rows.append({k:v for k,v in row.items() if k != "scheduled_unix_ms"} | dict(outcome="confirmed",elapsed_ms=1000,started_unix_ms=row["scheduled_unix_ms"],terminal_unix_ms=row["scheduled_unix_ms"]+1000,cpu_ns=1000000,peak_rss_bytes=1000000,rx_bytes=100,tx_bytes=100,raw_receipt_sha256="a"*64,block_id="b"*64,confirmed_depth=6,observed_chainwork_delta=10))
    return manifest, rows


class Accounting(unittest.TestCase):
    def test_synthetic_success_never_grants_independence_or_wan_acceptance(self):
        report=W.evaluate(*fixture())
        self.assertTrue(report["all_cohort_arithmetic_slos_met"])
        for field in ("independent_accepted","public_network_ready","physical_wan_duration_verified","raw_receipts_cryptographically_verified"):
            self.assertFalse(report[field])

    def test_dropped_timeout_stays_in_original_denominator(self):
        manifest,rows=fixture(); rows.pop()
        report=W.evaluate(manifest,rows)
        self.assertEqual((report["scheduled"],report["recorded"],report["missing"]),(6,5,1))
        self.assertEqual(report["cohorts"][-1]["timely_ppm"],500000)
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_every_failure_outcome_reduces_service_without_dropping_resources(self):
        for outcome in W.OUTCOMES-{"confirmed"}:
            manifest,rows=fixture(); rows[-1]["outcome"]=outcome
            report=W.evaluate(manifest,rows)
            self.assertEqual(report["cohorts"][-1]["timely_ppm"],500000)
            self.assertEqual(report["cohorts"][-1]["resources"]["cpu_ns"],2000000)
            self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_late_success_is_not_timely_success(self):
        manifest,rows=fixture(); rows[-1]["elapsed_ms"]=5001
        rows[-1]["terminal_unix_ms"]=manifest["schedule"][-1]["scheduled_unix_ms"]+5001
        self.assertFalse(W.evaluate(manifest,rows)["all_cohort_arithmetic_slos_met"])

    def test_delayed_send_cannot_reset_confirmation_clock(self):
        manifest,rows=fixture()
        rows[0]["started_unix_ms"]+=10000
        rows[0]["terminal_unix_ms"]+=10000
        with self.assertRaisesRegex(ValueError,"SCHEDULED_TO_TERMINAL"):
            W.evaluate(manifest,rows)
        rows[0]["elapsed_ms"]+=10000
        self.assertFalse(W.evaluate(manifest,rows)["all_cohort_arithmetic_slos_met"])

    def test_repeated_polls_cannot_inflate_unique_operations(self):
        manifest,rows=fixture()
        manifest["schedule"][1]["operation_sha256"]=manifest["schedule"][0]["operation_sha256"]
        rows[1]["operation_sha256"]=rows[0]["operation_sha256"]
        with self.assertRaisesRegex(ValueError,"REPEATED_ORIGINAL_OPERATION"):
            W.evaluate(manifest,rows)

    def test_duplicates_unknown_ids_and_original_operation_swaps_reject(self):
        manifest,rows=fixture()
        for mode in ("duplicate","unknown","operation"):
            bad=copy.deepcopy(rows)
            if mode=="duplicate": bad.append(bad[0])
            elif mode=="unknown": bad[0]["id"]="new-id"
            else: bad[0]["operation_sha256"]="f"*64
            with self.assertRaises(ValueError):W.evaluate(manifest,bad)

    def test_short_campaign_same_admin_and_missing_operator_cohort_reject(self):
        manifest,rows=fixture()
        for mode in ("short","same-admin","empty-cohort"):
            bad=copy.deepcopy(manifest)
            if mode=="short":bad["end_unix_ms"]-=1
            elif mode=="same-admin":bad["operators"][0]["administrator"]="admin1"
            else:bad["schedule"]=bad["schedule"][:-2]
            with self.assertRaises(ValueError):W.evaluate(bad,rows)

    def test_negative_nonfinite_and_duplicate_json_cannot_supply_costs(self):
        manifest,rows=fixture();rows[0]["cpu_ns"]=-1
        with self.assertRaises(ValueError):W.evaluate(manifest,rows)
        for data in ('{"x":NaN}', '{"x":Infinity}', '{"x":1,"x":2}'):
            with self.assertRaises(ValueError):W.decode(data)


def fixture_v2(operator_count=3):
    """Synthetic arithmetic only: no WAN, crypto, replica or clock evidence."""
    start = 1_800_000_000_000
    manifest = dict(schema="trnm-wan-preregistration-v2", preregistered_unix_ms=start-10,
        start_unix_ms=start, end_unix_ms=start+73*3600*1000,
        chain_source_sha256="1"*64, hepta_source_sha256="2"*64,
        chain_binary_sha256="3"*64, hepta_binary_sha256="4"*64,
        threat_model_sha256="5"*64, load_fault_plan_sha256="6"*64,
        operators=[dict(id=f"o{i}", administrator=f"admin{i}", failure_domain=f"zone{i}",
            endpoint=f"SYNTHETIC_ONLY:{i}", external_attestation_sha256="7"*64) for i in range(operator_count)],
        windows=[dict(id="early", start_unix_ms=start, end_unix_ms=start+36*3600*1000,
                      report_by_unix_ms=start+36*3600*1000+5000),
                 dict(id="late", start_unix_ms=start+36*3600*1000, end_unix_ms=start+73*3600*1000,
                      report_by_unix_ms=start+73*3600*1000+5000)],
        cohorts=[], schedule=[])
    criteria = {
        "confirmation": dict(minimum_confirmed_depth=6, minimum_chainwork_delta=10),
        "cell_retrieval": dict(minimum_source_operators=2),
        "replica_repair": dict(minimum_complete_replicas=3, minimum_administrators=3, minimum_failure_domains=3),
        "recovery": dict(mode="reconcile", maximum_redispatched_effects=0, maximum_new_payments=0),
    }
    rows = []
    for kind, success_criteria in criteria.items():
        manifest["cohorts"].append(dict(id=kind, kind=kind, max_completion_ms=5000,
            minimum_samples_per_operator_per_window=2, minimum_timely_ppm=1_000_000,
            tail_quantile_ppm=990_000, minimum_tail_samples_per_operator_per_window=2,
            max_tail_latency_ms=1000, window_resource_limits=dict(cpu_ns=10_000,
                peak_rss_bytes=4096, rx_bytes=1000, tx_bytes=1000, funding_units=0),
            success_criteria=success_criteria))
        for operator in manifest["operators"]:
            for window in manifest["windows"]:
                for index in range(2):
                    sequence = len(rows) + 1
                    at = start + (0 if window["id"] == "early" else W.V2_DURATION_MS) + index*100
                    expected = dict(manifest_sha256="8"*64, payload_sha256="9"*64, payload_bytes=100)
                    if kind == "confirmation":
                        expected = {}
                        result = dict(block_id=f"{sequence+1000:064x}", confirmed_depth=6, observed_chainwork_delta=10)
                    elif kind == "cell_retrieval":
                        expected["forbidden_source_operators"] = ["o2"]
                        result = {name: expected[name] for name in W.V2_CELL_FIELDS} | dict(source_operators=["o0", "o1"])
                    elif kind == "replica_repair":
                        expected["effect_sha256"] = f"{sequence+2000:064x}"
                        result = dict(expected) | dict(complete_replica_operators=["o0", "o1", "o2"])
                    else:
                        expected = dict(effect_sha256=f"{sequence+2000:064x}", target_receipt_sha256=f"{sequence+3000:064x}")
                        result = dict(expected) | dict(mode="reconcile", redispatched_effects=0, new_payments=0)
                    planned = dict(id=f"{kind}-{operator['id']}-{window['id']}-{index}",
                        operator=operator["id"], cohort=kind, window=window["id"],
                        operation_sha256=f"{sequence:064x}", scheduled_unix_ms=at, expected=expected)
                    manifest["schedule"].append(planned)
                    rows.append({name: planned[name] for name in ("id", "operator", "cohort", "window", "operation_sha256")} |
                        dict(outcome=W.V2_SUCCESS[kind], elapsed_ms=500, started_unix_ms=at,
                            terminal_unix_ms=at+500, recorded_unix_ms=at+501,
                            resources=dict(cpu_ns=1000, peak_rss_bytes=1024, rx_bytes=200, tx_bytes=20, funding_units=0),
                            raw_receipt_sha256=f"{sequence+4000:064x}", result=result))
    return manifest, rows


class TypedWindowAccounting(unittest.TestCase):
    def group(self, report, row):
        return next(group for group in report["cohorts"] if all(group[key] == row[key] for key in ("operator", "cohort", "window")))

    def test_typed_synthetic_success_keeps_every_qualification_false(self):
        report = W.evaluate(*fixture_v2())
        self.assertTrue(report["all_cohort_arithmetic_slos_met"])
        self.assertEqual((report["scheduled"], report["recorded"], len(report["cohorts"])), (48, 48, 24))
        self.assertEqual({group["kind"] for group in report["cohorts"]}, set(W.V2_SUCCESS))
        for flag in ("external_operator_attestations_verified", "physical_wan_duration_verified",
                     "raw_receipts_cryptographically_verified", "preregistration_independently_verified",
                     "source_binary_identities_verified", "independent_accepted", "pn5_accepted",
                     "public_network_ready", "production_activation"):
            self.assertIs(report[flag], False)

    def test_start_only_rows_cannot_turn_declared_73_hours_into_coverage(self):
        manifest, rows = fixture_v2()
        manifest["windows"] = [dict(id="whole", start_unix_ms=manifest["start_unix_ms"],
            end_unix_ms=manifest["end_unix_ms"], report_by_unix_ms=manifest["end_unix_ms"]+5000)]
        for index, (planned, row) in enumerate(zip(manifest["schedule"], rows)):
            at = manifest["start_unix_ms"] + index*10
            planned.update(window="whole", scheduled_unix_ms=at)
            row.update(window="whole", started_unix_ms=at, terminal_unix_ms=at+500, recorded_unix_ms=at+501)
        report = W.evaluate(manifest, rows)
        self.assertEqual(report["missing"], 0)
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])
        self.assertTrue(all(not group["minimum_campaign_schedule_span_met"] for group in report["cohorts"]))

    def test_failure_in_one_window_cannot_hide_behind_successful_aggregate(self):
        manifest, rows = fixture_v2()
        for cohort in manifest["cohorts"]:
            cohort["minimum_timely_ppm"] = 950_000
        rows[-1].update(outcome="unavailable", result={})
        report = W.evaluate(manifest, rows)
        self.assertGreaterEqual(sum(group["timely_successful"] for group in report["cohorts"])*1_000_000//48, 950_000)
        failed = self.group(report, rows[-1])
        self.assertEqual((failed["scheduled"], failed["timely_ppm"]), (2, 500_000))
        self.assertFalse(failed["arithmetic_slo_met"])
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_missing_late_and_out_of_window_records_keep_the_frozen_denominator(self):
        for mode in ("missing", "late", "outside"):
            manifest, rows = fixture_v2()
            last = rows[-1]
            if mode == "missing":
                rows.pop()
            elif mode == "late":
                last["recorded_unix_ms"] = manifest["windows"][-1]["report_by_unix_ms"] + 1
            else:
                last["terminal_unix_ms"] = manifest["windows"][-1]["end_unix_ms"] + 1
                last["recorded_unix_ms"] = last["terminal_unix_ms"]
                last["elapsed_ms"] = last["terminal_unix_ms"] - manifest["schedule"][-1]["scheduled_unix_ms"]
            report = W.evaluate(manifest, rows)
            group = self.group(report, last)
            self.assertEqual(group["scheduled"], 2)
            self.assertEqual(group["eligible_success_only_tail_samples"], 1)
            self.assertFalse(group["accounting_complete"])
            self.assertFalse(report["all_cohort_arithmetic_slos_met"])
            self.assertEqual(group["reported_resources"]["cpu_ns"], 1000 if mode == "missing" else 2000)

    def test_missing_scheduled_operator_cohort_window_is_reported_even_without_observations(self):
        manifest, rows = fixture_v2()
        removed = rows[-1]
        ids = {row["id"] for row in rows if all(row[key] == removed[key] for key in ("operator", "cohort", "window"))}
        manifest["schedule"] = [row for row in manifest["schedule"] if row["id"] not in ids]
        rows = [row for row in rows if row["id"] not in ids]
        report = W.evaluate(manifest, rows)
        group = self.group(report, removed)
        self.assertEqual(len(report["cohorts"]), 24)
        self.assertEqual(group["scheduled"], 0)
        self.assertIsNone(group["timely_ppm"])
        self.assertFalse(group["sample_floor_met"])
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_tail_floor_is_independent_of_timely_ratio(self):
        manifest, rows = fixture_v2()
        manifest["cohorts"][-1]["minimum_timely_ppm"] = 500_000
        rows[-1].update(outcome="timeout", result={})
        group = self.group(W.evaluate(manifest, rows), rows[-1])
        self.assertEqual(group["timely_ppm"], 500_000)
        self.assertTrue(group["sample_floor_met"])
        self.assertFalse(group["tail_requirement_met"])
        self.assertFalse(group["arithmetic_slo_met"])

    def test_late_success_and_delayed_send_cannot_reset_the_service_clock(self):
        manifest, rows = fixture_v2()
        last = rows[-1]
        for name in ("started_unix_ms", "terminal_unix_ms", "recorded_unix_ms"):
            last[name] += 5001
        with self.assertRaisesRegex(ValueError, "SCHEDULED_TO_TERMINAL"):
            W.evaluate(manifest, rows)
        last["elapsed_ms"] += 5001
        group = self.group(W.evaluate(manifest, rows), last)
        self.assertEqual(group["timely_ppm"], 500_000)
        self.assertGreater(group["success_only_tail_latency_ms"], 1000)
        self.assertFalse(group["arithmetic_slo_met"])

    def test_duplicate_operation_receipt_observation_and_context_are_rejected(self):
        for mode in ("observation", "operation", "receipt", "window"):
            manifest, rows = fixture_v2()
            if mode == "observation":
                rows.append(copy.deepcopy(rows[0]))
            elif mode == "operation":
                manifest["schedule"][1]["operation_sha256"] = manifest["schedule"][0]["operation_sha256"]
                rows[1]["operation_sha256"] = rows[0]["operation_sha256"]
            elif mode == "receipt":
                rows[1]["raw_receipt_sha256"] = rows[0]["raw_receipt_sha256"]
            else:
                rows[0]["window"] = "late"
            with self.assertRaises(ValueError):
                W.evaluate(manifest, rows)

    def test_confirmation_cannot_impersonate_retrieval_repair_or_recovery(self):
        for kind in ("cell_retrieval", "replica_repair", "recovery"):
            manifest, rows = fixture_v2()
            row = next(row for row in rows if row["cohort"] == kind)
            row.update(outcome="confirmed", result=dict(block_id="a"*64, confirmed_depth=6, observed_chainwork_delta=10))
            with self.assertRaisesRegex(ValueError, "OUTCOME_KIND_MISMATCH"):
                W.evaluate(manifest, rows)

    def test_wrong_cell_and_forbidden_origin_are_failed_results_not_new_successes(self):
        for mode in ("manifest", "payload", "size", "origin"):
            manifest, rows = fixture_v2()
            row = next(row for row in rows if row["cohort"] == "cell_retrieval")
            if mode == "manifest": row["result"]["manifest_sha256"] = "a"*64
            elif mode == "payload": row["result"]["payload_sha256"] = "a"*64
            elif mode == "size": row["result"]["payload_bytes"] += 1
            else: row["result"]["source_operators"] = ["o0", "o2"]
            group = self.group(W.evaluate(manifest, rows), row)
            self.assertEqual((group["scheduled"], group["success_criteria_failures"]), (2, 1))
            self.assertFalse(group["arithmetic_slo_met"])

    def test_repairs_need_three_declared_complete_independent_replicas(self):
        for mode in ("missing", "duplicate", "same-owner", "wrong-effect"):
            manifest, rows = fixture_v2(4)
            manifest["operators"][3].update(administrator="admin0", failure_domain="zone0")
            row = next(row for row in rows if row["cohort"] == "replica_repair")
            if mode == "missing": row["result"]["complete_replica_operators"] = ["o0", "o1"]
            elif mode == "duplicate": row["result"]["complete_replica_operators"] = ["o0", "o1", "o1"]
            elif mode == "same-owner": row["result"]["complete_replica_operators"] = ["o0", "o1", "o3"]
            else: row["result"]["effect_sha256"] = "f"*64
            if mode == "duplicate":
                with self.assertRaisesRegex(ValueError, "REPLICA_OPERATORS"):
                    W.evaluate(manifest, rows)
            else:
                group = self.group(W.evaluate(manifest, rows), row)
                self.assertEqual(group["success_criteria_failures"], 1)
                self.assertFalse(group["arithmetic_slo_met"])

    def test_recovery_cannot_redeliver_or_repay_and_all_modes_bind_exact_state(self):
        for mode, fields in W.V2_RECOVERY_FIELDS.items():
            manifest, rows = fixture_v2()
            manifest["cohorts"][-1]["success_criteria"]["mode"] = mode
            for planned, row in zip(manifest["schedule"], rows):
                if row["cohort"] == "recovery":
                    planned["expected"] = {name: "a"*64 for name in fields}
                    row["result"] = dict(planned["expected"]) | dict(mode=mode, redispatched_effects=0, new_payments=0)
            self.assertTrue(W.evaluate(manifest, rows)["all_cohort_arithmetic_slos_met"])
            for field in ("redispatched_effects", "new_payments", *fields):
                changed = copy.deepcopy(rows)
                changed[-1]["result"][field] = 1 if field in ("redispatched_effects", "new_payments") else "b"*64
                self.assertFalse(self.group(W.evaluate(manifest, changed), changed[-1])["arithmetic_slo_met"])

    def test_failures_retain_full_reported_resource_costs(self):
        manifest, rows = fixture_v2()
        rows[-1].update(outcome="send_failed", result={})
        rows[-1]["resources"].update(cpu_ns=11_000, funding_units=1)
        group = self.group(W.evaluate(manifest, rows), rows[-1])
        self.assertEqual(group["reported_resources"]["cpu_ns"], 12_000)
        self.assertEqual(group["reported_resources"]["funding_units"], 1)
        self.assertFalse(group["resource_limits_met"])

    def test_frozen_thresholds_preregistration_windows_duration_and_operators_are_required(self):
        for mode in ("threshold", "resources", "tail", "posthoc", "gap", "overlap", "short", "same-admin", "same-domain", "authority"):
            manifest, rows = fixture_v2()
            if mode == "threshold": del manifest["cohorts"][0]["max_completion_ms"]
            elif mode == "resources": del manifest["cohorts"][0]["window_resource_limits"]["cpu_ns"]
            elif mode == "tail": del manifest["cohorts"][0]["minimum_tail_samples_per_operator_per_window"]
            elif mode == "posthoc": manifest["preregistered_unix_ms"] = manifest["start_unix_ms"]
            elif mode == "gap": manifest["windows"][1]["start_unix_ms"] += 1
            elif mode == "overlap": manifest["windows"][1]["start_unix_ms"] -= 1
            elif mode == "short": manifest["end_unix_ms"] = manifest["start_unix_ms"] + W.V2_DURATION_MS - 1
            elif mode == "same-admin": manifest["operators"][0]["administrator"] = "admin1"
            elif mode == "same-domain": manifest["operators"][0]["failure_domain"] = "zone1"
            else: manifest["public_network_ready"] = True
            with self.assertRaises(ValueError, msg=mode):
                W.evaluate(manifest, rows)

    def test_bool_negative_and_unbounded_costs_are_not_integers(self):
        for value in (True, -1, 2**64, 0.5):
            manifest, rows = fixture_v2()
            rows[-1]["resources"]["cpu_ns"] = value
            with self.assertRaises(ValueError):
                W.evaluate(manifest, rows)

    def test_same_cli_reports_arithmetic_success_and_failure_without_pn5_acceptance(self):
        manifest, rows = fixture_v2()
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "manifest.json"
            observed = Path(directory) / "observations.jsonl"
            plan.write_text(json.dumps(manifest))
            for missing, expected_status in ((False, 0), (True, 2)):
                selected = rows[:-1] if missing else rows
                observed.write_text("".join(json.dumps(row)+"\n" for row in selected))
                result = subprocess.run([sys.executable, W.__file__, str(plan), str(observed)],
                    capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, expected_status, result.stderr)
                report = json.loads(result.stdout)
                self.assertFalse(report["pn5_accepted"])
                self.assertFalse(report["production_activation"])
                self.assertEqual(len(report["manifest_sha256"]), 64)
                self.assertEqual(len(report["observations_sha256"]), 64)


if __name__=="__main__":unittest.main()
