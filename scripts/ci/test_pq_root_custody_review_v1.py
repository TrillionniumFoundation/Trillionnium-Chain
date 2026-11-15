"""Finite declaration checks; none of these fixtures certify real custody."""
import hashlib
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_root_custody_review_v1 as review

ROOT = Path(__file__).resolve().parents[2]


def manifest():
    return json.loads((ROOT / review.DEFAULT_MANIFEST).read_text())


def synthetic_complete():
    data = manifest()
    kinds = ["custody-observation", *review.FRESHNESS_REFS.values()]
    data["evidence"] = [{"id": "synthetic-" + kind, "kind": kind,
                         "path": "evidence/synthetic/" + kind + ".txt",
                         "sha256": hashlib.sha256(kind.encode()).hexdigest()} for kind in kinds]
    for role_index, role in enumerate(review.ROLES):
        data["rosters"][role]["keys"] = [
            {"key_id": format(role_index * 6 + index + 1, "0128x"),
             "suite": review.SUITES[index // 3],
             "domains": {axis: [f"{role}-{axis}-{index}"] for axis in review.AXES},
             "evidence_refs": ["synthetic-custody-observation"]} for index in range(6)]
    data["recovery_floor"] = {
        "source": "externally-provisioned", "enrollment_commitment": "ab" * 64,
        "head": {"version": 1, "root": "cd" * 64},
        **{field: "synthetic-" + kind for field, kind in review.FRESHNESS_REFS.items()},
    }
    return data


def install(root, data):
    for item in data["evidence"]:
        path = root / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(item["kind"])
    path = root / review.DEFAULT_MANIFEST
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


class CustodyReviewTests(unittest.TestCase):
    def assert_hold(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertIsNone(result["actual_lifetime_failure_bound"])
        for field in ("independent_custody_verified", "anchor_independence_verified",
                      "freshness_source_authenticated", "whole_chain_pq_qualified",
                      "production_activation", "evidence_authenticity_verified",
                      "enrolled_key_binding_verified",
                      "signed_ancestry_verified", "independent_common_restore_exclusion_proved",
                      "recovery_floor_installation_authorized"):
            self.assertIs(result[field], False, field)

    def test_checked_in_manifest_does_not_invent_people_or_devices(self):
        data = manifest()
        self.assertTrue(all(not row["keys"] for row in data["rosters"].values()))
        self.assertEqual(data["evidence"], [])
        report = review.inspect(ROOT)
        self.assertFalse(report["declared_inventory_complete"])
        self.assertFalse(report["declared_separation_consistent"])
        self.assertTrue(report["missing_evidence"])
        self.assert_hold(report)

    def test_complete_synthetic_labels_never_authenticate_independence(self):
        report = review.validate_manifest(synthetic_complete())
        self.assertTrue(report["declared_inventory_complete"])
        self.assertTrue(report["declared_separation_consistent"])
        self.assertTrue(all(value == 4 for row in report["minimum_declared_domains_for_and_quorum"].values()
                            for value in row.values()))
        self.assert_hold(report)

    def test_one_declared_domain_with_both_quorums_is_reported(self):
        data = synthetic_complete()
        for key in data["rosters"]["root"]["keys"]:
            key["domains"]["backup"] = ["common-backup"]
        report = review.validate_manifest(data)
        self.assertIn({"role": "root", "axis": "backup"}, report["single_declared_domain_quorums"])
        self.assertFalse(report["declared_separation_consistent"])
        self.assert_hold(report)

    def test_one_family_control_is_not_relabeled_as_both_quorums(self):
        data = synthetic_complete()
        for key in data["rosters"]["root"]["keys"][:3]:
            key["domains"]["operator"] = ["shared-ml-operator"]
        report = review.validate_manifest(data)
        self.assertEqual(report["minimum_declared_domains_for_and_quorum"]["root"]["operator"], 3)
        self.assertEqual(report["single_declared_domain_quorums"], [])

    def test_mixed_family_pairs_require_two_declared_domains(self):
        data = synthetic_complete()
        for index, key in enumerate(data["rosters"]["root"]["keys"]):
            key["domains"]["recovery"] = ["paired-operator-" + str(index % 3)]
        report = review.validate_manifest(data)
        self.assertEqual(report["minimum_declared_domains_for_and_quorum"]["root"]["recovery"], 2)

    def test_exact_incidence_calculation_matches_small_exhaustive_reference(self):
        rng = random.Random(492)
        for _ in range(30):
            keys = synthetic_complete()["rosters"]["root"]["keys"]
            names = ["domain-" + str(index) for index in range(5)]
            for key in keys:
                key["domains"]["device"] = rng.sample(names, rng.randrange(1, 6))
            expected = None
            for count in range(1, 6):
                for selected in itertools.combinations(names, count):
                    if all(sum(bool(set(key["domains"]["device"]) & set(selected))
                               for key in keys if key["suite"] == suite) >= 2 for suite in review.SUITES):
                        expected = count
                        break
                if expected is not None:
                    break
            self.assertEqual(review.minimum_declared_domains(keys, "device"), expected)

    def test_cross_role_shared_device_is_visible_even_with_distinct_keys(self):
        data = synthetic_complete()
        for role in ("root", "anchor"):
            data["rosters"][role]["keys"][0]["domains"]["device"] = ["same-machine"]
        report = review.validate_manifest(data)
        self.assertIn({"axis": "device", "domain": "same-machine", "roles": ["anchor", "root"]},
                      report["declared_cross_role_shared_domains"])
        self.assertFalse(report["declared_separation_consistent"])

    def test_cross_role_key_reuse_is_refused(self):
        data = synthetic_complete()
        data["rosters"]["anchor"]["keys"][0]["key_id"] = data["rosters"]["root"]["keys"][0]["key_id"]
        with self.assertRaises(review.CustodyReviewError):
            review.validate_manifest(data)

    def test_suite_substitution_and_family_excess_are_refused(self):
        for value in ("ML-DSA-65", "SLH-DSA-SHAKE-256s", review.SUITES[1]):
            data = synthetic_complete()
            data["rosters"]["root"]["keys"][0]["suite"] = value
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)

    def test_partial_roster_cannot_be_complete(self):
        data = synthetic_complete()
        data["rosters"]["root"]["keys"].pop()
        report = review.validate_manifest(data)
        self.assertFalse(report["declared_inventory_complete"])
        self.assertIsNone(report["minimum_declared_domains_for_and_quorum"]["root"]["device"])
        self.assert_hold(report)

    def test_missing_or_empty_custody_axis_is_refused(self):
        for remove in (True, False):
            data = synthetic_complete()
            domains = data["rosters"]["writer"]["keys"][0]["domains"]
            if remove:
                del domains["backup"]
            else:
                domains["backup"] = []
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)

    def test_promotion_flags_and_zero_probability_claim_are_refused(self):
        for name, old in review.CLAIMS.items():
            data = synthetic_complete()
            data["claims"][name] = 0 if old is None else True
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)
        data = manifest()
        data["claims"]["independent_custody_verified"] = 0
        with self.assertRaises(review.CustodyReviewError):
            review.validate_manifest(data)

    def test_wrong_or_absent_evidence_reference_is_refused(self):
        for ref in ("missing", "synthetic-recovery-drill"):
            data = synthetic_complete()
            data["rosters"]["provider"]["keys"][0]["evidence_refs"] = [ref]
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)

    def test_missing_key_evidence_is_reported_without_fabrication(self):
        data = synthetic_complete()
        data["rosters"]["provider"]["keys"][0]["evidence_refs"] = []
        self.assertFalse(review.validate_manifest(data)["declared_inventory_complete"])

    def test_locally_restored_floor_source_is_not_external_evidence(self):
        for source in ("owner-journal", "same-anchor-snapshot", "self-signed-local-file"):
            data = synthetic_complete()
            data["recovery_floor"]["source"] = source
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)

    def test_floor_counter_type_and_range_cannot_bypass_full_pin(self):
        for version in (True, -1, 129, "1", 1.0):
            data = synthetic_complete()
            data["recovery_floor"]["head"]["version"] = version
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)

    def test_unknown_fields_duplicate_keys_and_unsafe_paths_are_refused(self):
        data = synthetic_complete()
        data["independent"] = True
        with self.assertRaises(review.CustodyReviewError):
            review.validate_manifest(data)
        for path in ("../outside", "evidence/../outside", "/evidence/file", "evidence//file", "evidence/file\x00"):
            data = synthetic_complete()
            data["evidence"][0]["path"] = path
            with self.assertRaises(review.CustodyReviewError):
                review.validate_manifest(data)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / review.DEFAULT_MANIFEST
            path.parent.mkdir(parents=True)
            path.write_text('{"schema":"a","schema":"b"}')
            with self.assertRaises(review.CustodyReviewError):
                review.inspect(root)

    def test_verified_local_bytes_still_leave_custody_and_freshness_unqualified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = synthetic_complete()
            install(root, data)
            before = {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            report = review.inspect(root)
            self.assertTrue(report["evidence_files_checked"])
            self.assertEqual(len(report["evidence_files_sha256"]), 5)
            self.assert_hold(report)
            after = {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            self.assertEqual(before, after)

    def test_missing_changed_and_symlink_evidence_is_refused(self):
        for fault in ("missing", "changed", "symlink"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = synthetic_complete()
                install(root, data)
                target = root / data["evidence"][0]["path"]
                target.unlink()
                if fault == "changed":
                    target.write_text("changed")
                elif fault == "symlink":
                    source = root / "actual.txt"
                    source.write_text("custody-observation")
                    target.symlink_to(source)
                with self.assertRaises(review.CustodyReviewError):
                    review.inspect(root)

    def test_cli_reports_hold_and_nonzero_for_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = synthetic_complete()
            install(root, data)
            command = [sys.executable, str(ROOT / "scripts/ci/pq_root_custody_review_v1.py"), "--root", str(root)]
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assert_hold(json.loads(process.stdout))
            data["claims"]["production_activation"] = True
            (root / review.DEFAULT_MANIFEST).write_text(json.dumps(data))
            process = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(json.loads(process.stderr)["status"], "REFUSE")


if __name__ == "__main__":
    unittest.main()
