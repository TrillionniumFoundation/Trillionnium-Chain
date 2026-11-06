#!/usr/bin/env python3
"""Synthetic WAN V3/V4 controls; never independent WAN observations."""
from __future__ import annotations

import copy
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_decentralization_audit as D
import pon_wan_evidence as W
from test_pon_wan_evidence import fixture_v2


def seal(manifest):
    registry = manifest["control_registry"]
    registry["subjects_sha256"] = D.canonical_sha256(registry["subjects"])
    manifest["control_registry_sha256"] = D.canonical_sha256(registry)


def fixture(operator_count=3):
    manifest, rows = fixture_v2(operator_count)
    manifest["schema"] = "trnm-wan-preregistration-v3"
    manifest.update(profile_sha256="a"*64, network_sha256="b"*64,
                    genesis_sha256="c"*64, parameters_sha256="d"*64)
    context = {key: manifest[key] for key in (
        "chain_source_sha256", "hepta_source_sha256", "chain_binary_sha256",
        "hepta_binary_sha256", "profile_sha256", "network_sha256", "genesis_sha256",
        "parameters_sha256")}
    evidence = [dict(sha256=f"{10000+i:064x}", status="current",
        valid_from_unix_ms=manifest["start_unix_ms"]-1000,
        valid_until_unix_ms=manifest["end_unix_ms"]+1000) for i in range(operator_count+1)]
    registry = dict(schema="trnm-control-registry-v1", context=context,
        valid_from_unix_ms=manifest["start_unix_ms"]-1000,
        valid_until_unix_ms=manifest["end_unix_ms"]+1000,
        controllers=[dict(id=f"controller{i}", parents=[], evidence_sha256=evidence[i]["sha256"])
                     for i in range(operator_count)], aliases=[],
        subjects=[dict(id=f"subject{i}", controller=f"controller{i}", key_sha256=None,
                       evidence_sha256=evidence[i]["sha256"]) for i in range(operator_count)],
        evidence=evidence)
    manifest["control_registry"] = registry
    manifest["operator_subjects"] = {f"o{i}": f"subject{i}" for i in range(operator_count)}
    seal(manifest)
    return manifest, rows


def alias(manifest, left, right, *, stale=False):
    registry = manifest["control_registry"]
    evidence = registry["evidence"][-1]
    if stale:
        evidence["valid_until_unix_ms"] = manifest["start_unix_ms"]-1
    registry["aliases"].append(dict(left=f"controller{left}", right=f"controller{right}",
                                    evidence_sha256=evidence["sha256"]))
    seal(manifest)


def fixture_v4(operator_count=3):
    manifest, rows = fixture(operator_count)
    manifest["schema"] = "trnm-wan-preregistration-v4"
    return manifest, rows


def joint_trap(operator_count=5):
    manifest, rows = fixture_v4(operator_count)
    alias(manifest, 0, 1)
    alias(manifest, 1, 2)
    for index in (3, 4):
        manifest["operators"][index]["failure_domain"] = "zone0"
    for row in rows:
        if row["cohort"] == "replica_repair":
            row["result"]["complete_replica_operators"] = [f"o{index}" for index in range(5)]
        if row["cohort"] == "cell_retrieval":
            row["result"]["source_operators"] = ["o3", "o4"]
    return manifest, rows


class ControlDomains(unittest.TestCase):
    def test_distinct_synthetic_declarations_never_grant_external_acceptance(self):
        manifest, rows = fixture()
        before = copy.deepcopy((manifest, rows))
        report = W.evaluate(manifest, rows)
        self.assertEqual((manifest, rows), before)
        self.assertTrue(report["all_cohort_arithmetic_slos_met"])
        self.assertEqual(report["schema"], "trnm-wan-evidence-accounting-v3")
        self.assertEqual(report["declared_control_group_count"], 3)
        self.assertEqual((report["scheduled"], report["recorded"]), (48, 48))
        for flag in ("external_independence_verified", "independent_accepted", "pn5_accepted",
                     "public_network_ready", "production_activation", "physical_wan_duration_verified",
                     "raw_receipts_cryptographically_verified", "external_operator_attestations_verified",
                     "preregistration_independently_verified", "source_binary_identities_verified"):
            self.assertIs(report[flag], False)

    def test_distinct_node_admin_ip_labels_do_not_hide_common_control(self):
        manifest, rows = fixture()
        alias(manifest, 0, 1)
        alias(manifest, 1, 2)
        report = W.evaluate(manifest, rows)
        self.assertEqual(report["declared_control_group_count"], 1)
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])
        self.assertEqual((report["scheduled"], report["recorded"], report["missing"]), (48, 48, 0))
        self.assertEqual(sum(group["reported_resources"]["cpu_ns"] for group in report["cohorts"]), 48000)

    def test_common_parent_and_reused_subject_cannot_increase_domain_count(self):
        for mode in ("parent", "same-subject"):
            manifest, rows = fixture()
            if mode == "parent":
                for controller in manifest["control_registry"]["controllers"][1:]:
                    controller["parents"] = ["controller0"]
            else:
                manifest["operator_subjects"] = {name: "subject0" for name in manifest["operator_subjects"]}
            seal(manifest)
            report = W.evaluate(manifest, rows)
            self.assertEqual(report["declared_control_group_count"], 1)
            self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_bound_context_does_not_retain_mutable_caller_mappings(self):
        manifest, _ = fixture()
        controls = W.WanControlContext(manifest)
        before = controls.report()
        manifest["operator_subjects"]["o1"] = "subject0"
        manifest["operators"][1]["failure_domain"] = "zone0"
        manifest["control_registry"]["subjects"][1]["controller"] = "controller0"
        self.assertEqual(controls.report(), before)
        self.assertTrue(controls.repair_allowed({"o0", "o1", "o2"}, 3, 3))

    def test_alias_of_forbidden_source_is_excluded_with_three_other_groups(self):
        manifest, rows = fixture(4)
        alias(manifest, 0, 2)
        report = W.evaluate(manifest, rows)
        self.assertTrue(report["declared_operator_control_floor_met"])
        retrieval = [group for group in report["cohorts"] if group["kind"] == "cell_retrieval"]
        self.assertTrue(all(group["successful_results"] == 0 for group in retrieval))
        self.assertTrue(all(group["success_criteria_failures"] == 2 for group in retrieval))
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_two_source_ids_under_one_controller_cannot_meet_two_group_floor(self):
        manifest, rows = fixture(4)
        alias(manifest, 0, 1)
        report = W.evaluate(manifest, rows)
        self.assertTrue(report["declared_operator_control_floor_met"])
        self.assertTrue(all(group["successful_results"] == 0 for group in report["cohorts"]
                            if group["kind"] == "cell_retrieval"))
        self.assertTrue(all(group["successful_results"] == 0 for group in report["cohorts"]
                            if group["kind"] == "replica_repair"))

    def test_unknown_forbidden_origin_cannot_be_asserted_unrelated(self):
        manifest, rows = fixture(4)
        manifest["control_registry"]["subjects"][2].update(controller=None, evidence_sha256=None)
        seal(manifest)
        report = W.evaluate(manifest, rows)
        self.assertEqual(report["unknown_control_operators"], ["o2"])
        self.assertFalse(report["control_inventory_complete"])
        self.assertTrue(all(group["successful_results"] == 0 for group in report["cohorts"]
                            if group["kind"] == "cell_retrieval"))

    def test_stale_alias_is_not_an_escape_from_known_common_control(self):
        manifest, rows = fixture(4)
        alias(manifest, 0, 2, stale=True)
        controls = W.WanControlContext(manifest)
        self.assertTrue(controls.controls.related("subject0", "subject2"))
        self.assertFalse(controls.retrieval_allowed({"o0", "o1"}, ["o2"], 2))
        self.assertFalse(W.evaluate(manifest, rows)["all_cohort_arithmetic_slos_met"])

    def test_controller_evidence_expiring_midcampaign_gets_no_credit(self):
        manifest, rows = fixture(4)
        manifest["control_registry"]["evidence"][0]["valid_until_unix_ms"] = manifest["start_unix_ms"]+1000
        seal(manifest)
        report = W.evaluate(manifest, rows)
        self.assertIn("o0", report["unknown_control_operators"])
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_foreign_context_rejects_even_when_attacker_rehashes_registry(self):
        for key in ("chain_source_sha256", "hepta_source_sha256", "chain_binary_sha256",
                    "hepta_binary_sha256", "profile_sha256", "network_sha256",
                    "genesis_sha256", "parameters_sha256"):
            manifest, rows = fixture()
            manifest["control_registry"]["context"][key] = "e"*64
            seal(manifest)
            with self.subTest(key=key), self.assertRaises(ValueError):
                W.evaluate(manifest, rows)

    def test_registry_and_subject_roster_commitments_are_both_required(self):
        manifest, rows = fixture()
        manifest["control_registry"]["subjects"][0]["controller"] = "controller1"
        with self.assertRaises(ValueError):
            W.evaluate(manifest, rows)
        manifest["control_registry_sha256"] = D.canonical_sha256(manifest["control_registry"])
        with self.assertRaises(ValueError):
            W.evaluate(manifest, rows)

    def test_unknown_extra_or_missing_operator_subject_binding_rejects(self):
        for mode in ("missing", "extra", "foreign", "type"):
            manifest, rows = fixture()
            if mode == "missing":
                del manifest["operator_subjects"]["o0"]
            elif mode == "extra":
                manifest["operator_subjects"]["other"] = "subject0"
            elif mode == "foreign":
                manifest["operator_subjects"]["o0"] = "other"
            else:
                manifest["operator_subjects"]["o0"] = False
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                W.evaluate(manifest, rows)

    def test_duplicate_physical_key_under_different_subjects_is_still_common_control(self):
        manifest, rows = fixture()
        for subject in manifest["control_registry"]["subjects"]:
            subject["key_sha256"] = "f"*64
        seal(manifest)
        report = W.evaluate(manifest, rows)
        self.assertEqual(report["declared_control_group_count"], 1)
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_original_late_missing_failure_resource_denominators_remain(self):
        manifest, rows = fixture()
        rows[-1].update(outcome="timeout", result={})
        rows.pop(0)
        report = W.evaluate(manifest, rows)
        self.assertEqual((report["scheduled"], report["recorded"], report["missing"]), (48, 47, 1))
        self.assertEqual(sum(group["reported_resources"]["cpu_ns"] for group in report["cohorts"]), 47000)
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_failure_domains_are_still_a_separate_floor(self):
        manifest, rows = fixture(4)
        manifest["operators"][0]["failure_domain"] = manifest["operators"][1]["failure_domain"]
        report = W.evaluate(manifest, rows)
        self.assertEqual(report["declared_control_group_count"], 4)
        self.assertTrue(all(group["successful_results"] == 0 for group in report["cohorts"]
                            if group["kind"] == "replica_repair"))

    def test_user_supplied_acceptance_flags_and_unknown_v3_fields_reject(self):
        for key in ("independent_accepted", "production_activation", "external_independence_verified"):
            manifest, rows = fixture()
            manifest[key] = True
            with self.assertRaises(ValueError):
                W.evaluate(manifest, rows)

    def test_v2_retains_original_declaration_semantics(self):
        manifest, rows = fixture()
        alias(manifest, 0, 1)
        alias(manifest, 1, 2)
        self.assertFalse(W.evaluate(manifest, rows)["all_cohort_arithmetic_slos_met"])
        original, original_rows = fixture_v2()
        before = copy.deepcopy((original, original_rows))
        report = W.evaluate(original, original_rows)
        self.assertTrue(report["all_cohort_arithmetic_slos_met"])
        self.assertNotIn("declared_control_group_count", report)
        self.assertEqual((original, original_rows), before)

    def test_cli_emits_bound_v3_report_with_real_failure_exit(self):
        script = Path(W.__file__).resolve()
        with tempfile.TemporaryDirectory(prefix="wan-v3-synthetic-") as directory:
            manifest_path = Path(directory)/"manifest.json"
            rows_path = Path(directory)/"rows.jsonl"
            for common in (False, True):
                manifest, rows = fixture()
                if common:
                    alias(manifest, 0, 1)
                manifest_path.write_text(json.dumps(manifest))
                rows_path.write_text("\n".join(json.dumps(row) for row in rows)+"\n")
                result = subprocess.run([sys.executable, str(script), str(manifest_path), str(rows_path)],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 2 if common else 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["control_registry_sha256"], manifest["control_registry_sha256"])
                self.assertIs(report["pn5_accepted"], False)


class JointControlDomainsV4(unittest.TestCase):
    def test_three_joint_synthetic_pairs_keep_all_external_acceptance_false(self):
        manifest, rows = fixture_v4()
        before = copy.deepcopy((manifest, rows))
        report = W.evaluate(manifest, rows)
        self.assertEqual((manifest, rows), before)
        self.assertTrue(report["all_cohort_arithmetic_slos_met"])
        self.assertEqual(report["schema"], "trnm-wan-evidence-accounting-v4")
        self.assertEqual(report["operator_joint_control_failure_domain_count"], 3)
        self.assertEqual(report["operator_joint_matched_subset"], ["o0", "o1", "o2"])
        self.assertTrue(report["declared_operator_joint_floor_met"])
        self.assertEqual((report["scheduled"], report["recorded"]), (48, 48))
        self.assertEqual(len(report["repair_joint_results"]), 12)
        for result in report["repair_joint_results"]:
            self.assertEqual(result["joint_control_failure_domain_count"], 3)
            self.assertEqual(result["required_joint_count"], 3)
            self.assertTrue(result["typed_result_success"])
            self.assertEqual(result["failure_codes"], [])
        for flag in ("external_independence_verified", "independent_accepted", "pn5_accepted",
                     "public_network_ready", "production_activation", "physical_wan_duration_verified",
                     "raw_receipts_cryptographically_verified", "external_operator_attestations_verified",
                     "preregistration_independently_verified", "source_binary_identities_verified",
                     "physical_replica_independence_verified"):
            self.assertIs(report[flag], False)

    def test_five_operator_marginal_trap_is_v3_success_but_v4_failure(self):
        manifest, rows = joint_trap()
        legacy = copy.deepcopy(manifest)
        legacy["schema"] = "trnm-wan-preregistration-v3"
        old_report, report = W.evaluate(legacy, rows), W.evaluate(manifest, rows)
        self.assertTrue(old_report["all_cohort_arithmetic_slos_met"])
        self.assertNotIn("operator_joint_control_failure_domain_count", old_report)
        self.assertEqual(report["declared_control_group_count"], 3)
        self.assertEqual(report["operator_joint_control_failure_domain_count"], 2)
        self.assertFalse(report["declared_operator_joint_floor_met"])
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])
        self.assertEqual(report["operator_joint_failure_codes"],
                         ["JOINT_OPERATOR_CONTROL_FAILURE_DOMAIN_FLOOR_NOT_MET"])
        for result in report["repair_joint_results"]:
            self.assertTrue(result["original_typed_replica_criteria_met"])
            self.assertTrue(result["marginal_control_and_failure_floors_met"])
            self.assertEqual(result["joint_control_failure_domain_count"], 2)
            self.assertFalse(result["typed_result_success"])
            self.assertEqual(result["failure_codes"], ["JOINT_CONTROL_FAILURE_DOMAIN_FLOOR_NOT_MET"])
        self.assertEqual((old_report["scheduled"], old_report["recorded"], old_report["missing"]),
                         (report["scheduled"], report["recorded"], report["missing"]))
        for old, new in zip(old_report["cohorts"], report["cohorts"]):
            for key in ("scheduled", "recorded", "outcomes", "reported_resources", "resource_limits_met",
                        "operator_cohort_schedule_span_ms"):
                self.assertEqual(old[key], new[key])

    def test_registry_pass_cannot_replace_each_repair_result_matching(self):
        manifest, rows = joint_trap(6)
        report = W.evaluate(manifest, rows)
        self.assertEqual(report["operator_joint_control_failure_domain_count"], 3)
        self.assertTrue(report["declared_operator_joint_floor_met"])
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])
        self.assertTrue(all(row["joint_control_failure_domain_count"] == 2
                            for row in report["repair_joint_results"]))
        self.assertTrue(all(row["arithmetic_slo_met"] for row in report["cohorts"]
                            if row["kind"] != "replica_repair"))

    def test_global_joint_floor_applies_without_any_repair_cohort(self):
        manifest, rows = joint_trap()
        manifest["cohorts"] = [row for row in manifest["cohorts"] if row["kind"] != "replica_repair"]
        manifest["schedule"] = [row for row in manifest["schedule"] if row["cohort"] != "replica_repair"]
        rows = [row for row in rows if row["cohort"] != "replica_repair"]
        report = W.evaluate(manifest, rows)
        self.assertTrue(report["all_typed_window_arithmetic_slos_met"])
        self.assertEqual(report["repair_joint_results"], [])
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_augmenting_path_finds_matching_that_first_edge_greedy_misses(self):
        manifest, rows = fixture_v4(4)
        alias(manifest, 0, 1)
        manifest["operators"][2]["failure_domain"] = "zone0"
        for row in rows:
            if row["cohort"] == "replica_repair":
                row["result"]["complete_replica_operators"] = ["o0", "o1", "o2", "o3"]
            if row["cohort"] == "cell_retrieval":
                row["result"]["source_operators"] = ["o2", "o3"]
        for planned in manifest["schedule"]:
            if planned["cohort"] == "cell_retrieval":
                planned["expected"]["forbidden_source_operators"] = ["o0"]
        report = W.evaluate(manifest, rows)
        self.assertTrue(report["all_cohort_arithmetic_slos_met"])
        self.assertEqual(report["operator_joint_control_failure_domain_count"], 3)
        self.assertEqual(report["operator_joint_matched_subset"], ["o1", "o2", "o3"])

    def test_all_small_graphs_match_independent_exhaustive_oracle(self):
        manifest, _ = fixture_v4(9)
        for index, subject in enumerate(manifest["control_registry"]["subjects"]):
            subject["controller"] = f"controller{index // 3}"
            manifest["operators"][index]["failure_domain"] = f"zone{index % 3}"
        seal(manifest)
        controls = W.WanJointControlContext(manifest)
        for bitset in range(1 << 9):
            selected = [index for index in range(9) if bitset & (1 << index)]
            expected = 0
            for size in range(1, min(3, len(selected)) + 1):
                if any(len({i // 3 for i in subset}) == size == len({i % 3 for i in subset})
                       for subset in itertools.combinations(selected, size)):
                    expected = size
            report = controls.joint_replica_report([f"o{i}" for i in selected])
            self.assertEqual(report["joint_control_failure_domain_count"], expected, bitset)
            matched = [int(name[1:]) for name in report["matched_operator_subset"]]
            self.assertTrue(set(matched) <= set(selected), bitset)
            self.assertEqual(len({i // 3 for i in matched}), expected, bitset)
            self.assertEqual(len({i % 3 for i in matched}), expected, bitset)

    def test_input_order_does_not_change_the_matching_or_repair_diagnostics(self):
        manifest, rows = joint_trap(6)
        original = W.evaluate(manifest, rows)
        manifest["operators"].reverse()
        manifest["schedule"].reverse()
        for field in ("controllers", "subjects", "aliases", "evidence"):
            manifest["control_registry"][field].reverse()
        for row in rows:
            if row["cohort"] == "replica_repair":
                row["result"]["complete_replica_operators"].reverse()
        rows.reverse()
        seal(manifest)
        reordered = W.evaluate(manifest, rows)
        for key in ("operator_joint_control_failure_domain_count", "operator_joint_matched_subset",
                    "repair_joint_results", "cohorts", "all_cohort_arithmetic_slos_met"):
            self.assertEqual(original[key], reordered[key])

    def test_duplicate_edge_does_not_add_credit_and_duplicate_operator_rejects(self):
        manifest, rows = fixture_v4(4)
        alias(manifest, 0, 3)
        manifest["operators"][3]["failure_domain"] = "zone0"
        controls = W.WanJointControlContext(manifest)
        self.assertEqual(controls.joint_replica_report(["o0", "o1", "o2"]),
                         controls.joint_replica_report(["o0", "o1", "o2", "o3"]))
        row = next(row for row in rows if row["cohort"] == "replica_repair")
        row["result"]["complete_replica_operators"] = ["o0", "o1", "o1"]
        with self.assertRaisesRegex(ValueError, "REPLICA_OPERATORS"):
            W.evaluate(manifest, rows)

    def test_unknown_or_stale_control_never_adds_a_matching_edge(self):
        for mode in ("unknown", "stale", "revoked"):
            manifest, rows = fixture_v4(4)
            subject = manifest["control_registry"]["subjects"][0]
            evidence = manifest["control_registry"]["evidence"][0]
            if mode == "unknown":
                subject.update(controller=None, evidence_sha256=None)
            elif mode == "stale":
                evidence["valid_until_unix_ms"] = manifest["start_unix_ms"] + 1
            else:
                evidence["status"] = "revoked"
            seal(manifest)
            report = W.evaluate(manifest, rows)
            with self.subTest(mode=mode):
                self.assertEqual(report["operator_joint_control_failure_domain_count"], 3)
                self.assertNotIn("o0", report["operator_joint_matched_subset"])
                self.assertFalse(report["declared_operator_joint_floor_met"])
                self.assertFalse(report["all_cohort_arithmetic_slos_met"])
                for result in report["repair_joint_results"]:
                    self.assertEqual(result["joint_control_failure_domain_count"], 2)
                    self.assertIn("REPLICA_CONTROL_UNRESOLVED", result["failure_codes"])

    def test_unequal_marginal_floors_preserve_each_floor_and_match_their_minimum(self):
        for admin_floor, failure_floor in ((4, 3), (3, 4)):
            manifest, rows = fixture_v4(4)
            if admin_floor == 4:
                manifest["operators"][3]["failure_domain"] = "zone0"
            else:
                alias(manifest, 0, 3)
            policy = next(row for row in manifest["cohorts"] if row["kind"] == "replica_repair")
            policy["success_criteria"].update(minimum_complete_replicas=4,
                minimum_administrators=admin_floor, minimum_failure_domains=failure_floor)
            for row in rows:
                if row["cohort"] == "replica_repair":
                    row["result"]["complete_replica_operators"] = ["o0", "o1", "o2", "o3"]
            report = W.evaluate(manifest, rows)
            with self.subTest(admin=admin_floor, failure=failure_floor):
                self.assertTrue(report["all_cohort_arithmetic_slos_met"])
                self.assertTrue(all(row["required_joint_count"] == 3
                                    and row["joint_control_failure_domain_count"] == 3
                                    for row in report["repair_joint_results"]))
                changed = copy.deepcopy(rows)
                next(row for row in changed if row["cohort"] == "replica_repair")[
                    "result"]["complete_replica_operators"].remove("o3")
                rejected = W.evaluate(manifest, changed)
                self.assertFalse(rejected["all_cohort_arithmetic_slos_met"])
                self.assertTrue(any("ORIGINAL_REPAIR_CRITERIA_NOT_MET" in row["failure_codes"]
                                    for row in rejected["repair_joint_results"]))

    def test_wrong_cell_effect_and_failed_or_missing_rows_cannot_be_repaired_by_matching(self):
        manifest, rows = fixture_v4()
        repair_rows = [row for row in rows if row["cohort"] == "replica_repair"]
        repair_rows[0]["result"]["effect_sha256"] = "f" * 64
        repair_rows[1]["result"]["payload_sha256"] = "f" * 64
        repair_rows[2].update(outcome="timeout", result={})
        repair_rows[2]["resources"]["cpu_ns"] += 7000
        rows.remove(repair_rows[3])
        report = W.evaluate(manifest, rows)
        self.assertEqual((report["scheduled"], report["recorded"], report["missing"]), (48, 47, 1))
        self.assertEqual(sum(row["reported_resources"]["cpu_ns"] for row in report["cohorts"]), 54000)
        self.assertEqual(len(report["repair_joint_results"]), 10)
        rejected = [row for row in report["repair_joint_results"] if not row["typed_result_success"]]
        self.assertEqual(len(rejected), 2)
        self.assertTrue(all(row["joint_control_failure_domain_count"] == 3 for row in rejected))
        self.assertTrue(all(row["failure_codes"] == ["ORIGINAL_REPAIR_CRITERIA_NOT_MET"] for row in rejected))
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_v4_rejects_foreign_context_rebinding_and_invalid_version_or_fields(self):
        for field in ("chain_source_sha256", "hepta_source_sha256", "chain_binary_sha256",
                      "hepta_binary_sha256", "profile_sha256", "network_sha256",
                      "genesis_sha256", "parameters_sha256"):
            manifest, rows = fixture_v4()
            manifest["control_registry"]["context"][field] = "e" * 64
            seal(manifest)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "CONTEXT_BINDING"):
                W.evaluate(manifest, rows)
        for schema in ("trnm-wan-preregistration-v3", "trnm-wan-preregistration-v5", "unknown"):
            manifest, rows = fixture_v4()
            manifest["schema"] = schema
            with self.subTest(schema=schema), self.assertRaisesRegex(ValueError, "MANIFEST_SCHEMA"):
                W.evaluate_v4(manifest, rows)
        for field in ("joint_floor_override", "pn5_accepted", "physical_replica_independence_verified"):
            manifest, rows = fixture_v4()
            manifest[field] = True
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "V4_MANIFEST_FIELDS"):
                W.evaluate(manifest, rows)

    def test_cli_requires_explicit_v4_and_retains_real_arithmetic_failure_exit(self):
        with tempfile.TemporaryDirectory(prefix="wan-v4-synthetic-") as directory:
            manifest_path, rows_path = Path(directory) / "manifest.json", Path(directory) / "rows.jsonl"
            for schema, trap, expected_exit in (("v3", True, 0), ("v4", True, 2), ("v4", False, 0)):
                manifest, rows = joint_trap() if trap else fixture_v4()
                manifest["schema"] = "trnm-wan-preregistration-" + schema
                manifest_path.write_text(json.dumps(manifest))
                rows_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                result = subprocess.run([sys.executable, W.__file__, str(manifest_path), str(rows_path)],
                    capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["schema"], "trnm-wan-evidence-accounting-" + schema)
                self.assertIs(report["pn5_accepted"], False)
                self.assertEqual(report["control_registry_sha256"], manifest["control_registry_sha256"])


if __name__ == "__main__":
    unittest.main()
