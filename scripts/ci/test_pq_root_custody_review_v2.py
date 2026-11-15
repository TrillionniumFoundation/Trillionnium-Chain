"""Declared correlations and outages; synthetic fixtures never certify custody."""
import copy
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_root_custody_review_v2 as review
import test_pq_root_custody_review_v1 as v1_tests

ROOT = Path(__file__).resolve().parents[2]


def synthetic_complete():
    custody = v1_tests.synthetic_complete()
    return {
        "schema": review.SCHEMA, "custody_v1": custody,
        "availability_domains": [
            {"key_id": key["key_id"], "network": [f"{role}-network-{index}"],
             "power": [f"{role}-power-{index}"],
             "evidence_refs": ["synthetic-custody-observation"]}
            for role in review.v1.ROLES for index, key in enumerate(custody["rosters"][role]["keys"])],
        "common_control_review": {"coverage": "declared", "groups": [],
                                  "evidence_refs": ["synthetic-custody-observation"]},
        "claims": copy.deepcopy(review.CLAIMS),
    }


def group(data, members, identity="common-controller"):
    data["common_control_review"]["groups"].append({
        "id": identity, "domains": [{"axis": axis, "domain": domain} for axis, domain in members],
        "evidence_refs": ["synthetic-custody-observation"],
    })


def install(root, data):
    v1_tests.install(root, data["custody_v1"])
    path = root / review.DEFAULT_MANIFEST
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


class CommonControlReviewTests(unittest.TestCase):
    def assert_hold(self, report):
        self.assertEqual(report["status"], "HOLD")
        self.assertIsNone(report["actual_lifetime_failure_bound"])
        for name in (*review.CLAIMS, "evidence_authenticity_verified",
                     "independent_common_restore_exclusion_proved",
                     "recovery_floor_installation_authorized", "whole_chain_pq_qualified",
                     "production_activation"):
            self.assertIs(report[name], False, name)
        v1_tests.CustodyReviewTests().assert_hold(report["custody_v1"])

    def test_checked_in_inventory_has_no_fabricated_operators_or_currentness(self):
        data = json.loads((ROOT / review.DEFAULT_MANIFEST).read_text())
        self.assertEqual(data["availability_domains"], [])
        self.assertEqual(data["common_control_review"],
                         {"coverage": "unprovided", "groups": [], "evidence_refs": []})
        report = review.inspect(ROOT)
        self.assertFalse(report["declared_inventory_complete"])
        self.assertFalse(report["declared_separation_consistent"])
        self.assertIn("common-control:coverage", report["missing_evidence"])
        self.assert_hold(report)

    def test_complete_labels_remain_only_conditional_incidence(self):
        report = review.validate_manifest(synthetic_complete())
        self.assertTrue(report["declared_inventory_complete"])
        self.assertTrue(report["declared_separation_consistent"])
        self.assertTrue(all(value == 4 for value in report["listed_factor_minimum_for_and_key_control"].values()))
        self.assertTrue(all(value == 2 for value in report["listed_factor_minimum_to_block_and_quorum"].values()))
        self.assertIn("not-a-certified-lower-bound", report["minimum_scope"])
        self.assert_hold(report)

    def test_one_network_or_power_can_block_without_granting_any_key_access(self):
        for axis in review.AVAILABILITY_AXES:
            data = synthetic_complete()
            for mapping in data["availability_domains"][:6]:
                mapping[axis] = ["shared-facility"]
            report = review.validate_manifest(data)
            self.assertEqual(report["listed_availability_axis_minimum_to_block_and_quorum"]["root"][axis], 1)
            self.assertEqual(report["listed_factor_minimum_for_and_key_control"]["root"], 4)
            self.assertFalse(report["single_listed_factor_key_control"])
            self.assertIn({"role": "root", "factor": "domain:" + axis + ":shared-facility"},
                          report["single_listed_factor_quorum_outages"])
            self.assertFalse(report["declared_separation_consistent"])
            self.assert_hold(report)

    def test_cross_axis_controller_reaches_and_quorum_while_each_axis_looks_separate(self):
        data = synthetic_complete()
        group(data, [("operator", "root-operator-0"), ("backup", "root-backup-1"),
                     ("device", "root-device-3"), ("recovery", "root-recovery-4")])
        report = review.validate_manifest(data)
        self.assertTrue(report["custody_v1"]["declared_separation_consistent"])
        self.assertEqual(report["listed_factor_minimum_for_and_key_control"]["root"], 1)
        self.assertIn({"role": "root", "factor": "group:common-controller"},
                      report["single_listed_factor_key_control"])
        self.assertFalse(report["declared_separation_consistent"])

    def test_one_family_control_can_deny_service_but_cannot_forge_both_families(self):
        data = synthetic_complete()
        group(data, [("operator", "root-operator-0"), ("backup", "root-backup-1")])
        report = review.validate_manifest(data)
        self.assertEqual(report["listed_factor_minimum_for_and_key_control"]["root"], 3)
        self.assertEqual(report["listed_factor_minimum_to_block_and_quorum"]["root"], 1)
        self.assertFalse(report["single_listed_factor_key_control"])

    def test_pure_outage_group_never_creates_key_control(self):
        data = synthetic_complete()
        group(data, [("network", "root-network-0"), ("power", "root-power-1"),
                     ("network", "root-network-3"), ("power", "root-power-4")])
        report = review.validate_manifest(data)
        self.assertEqual(report["listed_factor_minimum_for_and_key_control"]["root"], 4)
        self.assertEqual(report["listed_factor_minimum_to_block_and_quorum"]["root"], 1)

    def test_cross_role_common_group_is_visible_with_distinct_keys_and_labels(self):
        data = synthetic_complete()
        group(data, [("backup", "root-backup-0"), ("network", "anchor-network-0")])
        report = review.validate_manifest(data)
        self.assertIn({"group": "common-controller", "roles": ["anchor", "root"]},
                      report["declared_cross_role_common_groups"])
        self.assertFalse(report["declared_separation_consistent"])

    def test_cross_role_network_and_power_sharing_are_visible_without_group(self):
        for axis in review.AVAILABILITY_AXES:
            data = synthetic_complete()
            for index in (0, 12):  # root and anchor; the key identities remain different
                data["availability_domains"][index][axis] = ["common-facility"]
            report = review.validate_manifest(data)
            self.assertIn({"axis": axis, "domain": "common-facility", "roles": ["anchor", "root"]},
                          report["declared_cross_role_shared_domains"])
            self.assertFalse(report["declared_separation_consistent"])
            self.assertFalse(report["single_listed_factor_key_control"])

    def test_missing_availability_and_review_evidence_do_not_complete_inventory(self):
        data = synthetic_complete()
        data["availability_domains"].pop(0)
        data["common_control_review"]["evidence_refs"] = []
        report = review.validate_manifest(data)
        self.assertFalse(report["declared_inventory_complete"])
        self.assertIsNone(report["listed_factor_minimum_to_block_and_quorum"]["root"])
        self.assertIn("common-control:review-evidence", report["missing_evidence"])
        self.assert_hold(report)

    def test_missing_group_or_mapping_evidence_remains_missing(self):
        data = synthetic_complete()
        data["availability_domains"][0]["evidence_refs"] = []
        group(data, [("operator", "root-operator-0"), ("backup", "root-backup-1")])
        data["common_control_review"]["groups"][0]["evidence_refs"] = []
        report = review.validate_manifest(data)
        self.assertFalse(report["declared_inventory_complete"])
        self.assertIn("common-control:group-evidence:common-controller", report["missing_evidence"])

    def test_independent_exhaustive_mask_reference_for_both_security_events(self):
        rng = random.Random(4512)
        keys = synthetic_complete()["custody_v1"]["rosters"]["root"]["keys"]
        for _ in range(50):
            masks = rng.sample(range(1, 64), rng.randrange(1, 8))
            for both in (False, True):
                expected = None
                for count in range(1, len(masks) + 1):
                    for selected in itertools.combinations(masks, count):
                        reached = 0
                        for value in selected:
                            reached |= value
                        ml = sum(bool(reached & (1 << index)) for index in range(3))
                        slh = sum(bool(reached & (1 << index)) for index in range(3, 6))
                        if (ml >= 2 and slh >= 2) if both else (ml >= 2 or slh >= 2):
                            expected = count
                            break
                    if expected is not None:
                        break
                self.assertEqual(review.minimum_factors(keys, masks, both), expected)

    def test_group_membership_does_not_invent_transitive_control(self):
        data = synthetic_complete()
        group(data, [("operator", "root-operator-0"), ("operator", "root-operator-1")], "first")
        group(data, [("operator", "root-operator-1"), ("backup", "root-backup-3"),
                     ("backup", "root-backup-4")], "second")
        report = review.validate_manifest(data)
        self.assertEqual(report["listed_factor_minimum_for_and_key_control"]["root"], 2)
        self.assertFalse(report["single_listed_factor_key_control"])

    def test_unknown_duplicate_and_oversized_groups_are_refused(self):
        for fault in ("unknown-axis", "unknown-domain", "duplicate-member", "duplicate-group", "too-many"):
            data = synthetic_complete()
            group(data, [("operator", "root-operator-0"), ("backup", "root-backup-1")])
            row = data["common_control_review"]["groups"][0]
            if fault == "unknown-axis":
                row["domains"][0]["axis"] = "directory"
            elif fault == "unknown-domain":
                row["domains"][0]["domain"] = "undeclared"
            elif fault == "duplicate-member":
                row["domains"][1] = copy.deepcopy(row["domains"][0])
            elif fault == "duplicate-group":
                data["common_control_review"]["groups"].append(copy.deepcopy(row))
            else:
                data["common_control_review"]["groups"] = [row] * (review.MAX_GROUPS + 1)
            with self.assertRaises(review.CustodyReviewError, msg=fault):
                review.validate_manifest(data)

    def test_unknown_duplicate_empty_or_unbound_availability_is_refused(self):
        for fault in ("unknown", "duplicate", "empty", "missing-axis", "wrong-evidence"):
            data = synthetic_complete()
            row = data["availability_domains"][0]
            if fault == "unknown":
                row["key_id"] = "ff" * 64
            elif fault == "duplicate":
                data["availability_domains"][1] = copy.deepcopy(row)
            elif fault == "empty":
                row["power"] = []
            elif fault == "missing-axis":
                del row["network"]
            else:
                row["evidence_refs"] = ["synthetic-recovery-drill"]
            with self.assertRaises(review.CustodyReviewError, msg=fault):
                review.validate_manifest(data)

    def test_unprovided_review_cannot_carry_groups_or_evidence(self):
        for field in ("evidence_refs", "groups"):
            data = synthetic_complete()
            group(data, [("operator", "root-operator-0"), ("backup", "root-backup-1")])
            old = copy.deepcopy(data["common_control_review"][field])
            data["common_control_review"] = {"coverage": "unprovided", "groups": [], "evidence_refs": []}
            data["common_control_review"][field] = old
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)

    def test_malformed_and_promoting_declarations_are_refused(self):
        for field in review.CLAIMS:
            for value in (True, 0, None):
                data = synthetic_complete()
                data["claims"][field] = value
                with self.assertRaises(review.CustodyReviewError):
                    review.validate_manifest(data)
        for mutate in (lambda d: d.update(extra=True),
                       lambda d: d["custody_v1"]["claims"].update(production_activation=True)):
            data = synthetic_complete()
            mutate(data)
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)

    def test_verified_local_files_remain_read_only_and_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            install(root, synthetic_complete())
            before = {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            report = review.inspect(root)
            self.assertTrue(report["evidence_files_checked"])
            self.assert_hold(report)
            self.assertEqual(before, {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()})

    def test_duplicate_json_changed_missing_and_symlink_bytes_are_refused(self):
        for fault in ("duplicate-json", "changed", "missing", "symlink"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = synthetic_complete()
                install(root, data)
                path = root / review.DEFAULT_MANIFEST
                if fault == "duplicate-json":
                    path.write_text('{"schema":"a","schema":"b"}')
                else:
                    path = root / data["custody_v1"]["evidence"][0]["path"]
                    path.unlink()
                    if fault == "changed":
                        path.write_text("changed")
                    elif fault == "symlink":
                        target = root / "actual.txt"
                        target.write_text("custody-observation")
                        path.symlink_to(target)
                with self.assertRaises(review.CustodyReviewError, msg=fault):
                    review.inspect(root)

    def test_cli_zero_is_declared_consistency_and_promotions_exit_two(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = synthetic_complete()
            install(root, data)
            command = [sys.executable, str(ROOT / "scripts/ci/pq_root_custody_review_v2.py"), "--root", str(root)]
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assert_hold(json.loads(process.stdout))
            data["claims"]["availability_independence_verified"] = True
            (root / review.DEFAULT_MANIFEST).write_text(json.dumps(data))
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(json.loads(process.stderr)["status"], "REFUSE")


if __name__ == "__main__":
    unittest.main()
