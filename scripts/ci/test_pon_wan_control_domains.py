#!/usr/bin/env python3
"""Synthetic counterexamples for WAN V3; never independent WAN observations."""
from __future__ import annotations

import copy
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


if __name__ == "__main__":
    unittest.main()
