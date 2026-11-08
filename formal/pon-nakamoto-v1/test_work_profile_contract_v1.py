from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import work_profile_contract_v1 as contract


class WorkProfileContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = contract.loads((contract.ROOT / contract.CONTRACT_PATH).read_bytes())

    def changed(self):
        return copy.deepcopy(self.original)

    def test_full_pinned_source_and_contract_check(self):
        result = contract.check_contract(self.original)
        self.assertEqual(result["source_commit"], contract.BASELINE)
        self.assertGreater(result["verified_source_entries"], 1000)
        self.assertTrue(result["contract_and_source_consistent"])
        self.assertFalse(result["native_binary_executed"])
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertIsNone(result["qualification"]["lifetime_security_bound"])

    def test_drop_source_even_with_rehashed_inventory_rejects(self):
        obj = self.changed()
        obj["source_entries"].pop()
        obj["source_inventory_digest"] = contract.digest(obj["source_entries"])
        with self.assertRaisesRegex(ValueError, "SOURCE_ROSTER"):
            contract.check_contract(obj)

    def test_duplicate_source_even_with_rehashed_inventory_rejects(self):
        obj = self.changed()
        obj["source_entries"][1] = obj["source_entries"][0]
        obj["source_inventory_digest"] = contract.digest(obj["source_entries"])
        with self.assertRaisesRegex(ValueError, "SOURCE_ROSTER"):
            contract.check_contract(obj)

    def test_reordered_inventory_rejects(self):
        obj = self.changed()
        obj["source_entries"].reverse()
        obj["source_inventory_digest"] = contract.digest(obj["source_entries"])
        with self.assertRaisesRegex(ValueError, "SOURCE_ROSTER"):
            contract.check_contract(obj)

    def test_mutated_source_bytes_reject(self):
        original_reader = contract.bytes_at
        chosen = self.original["source_entries"][0]["path"]
        def changed_reader(root, path, mode):
            data = original_reader(root, path, mode)
            return data + b"\nmutated" if path == chosen else data
        with patch.object(contract, "bytes_at", changed_reader):
            with self.assertRaisesRegex(ValueError, "SOURCE_BYTES"):
                contract.check_contract(self.original)

    def test_wrong_git_blob_rejects_despite_sha256_relabel(self):
        obj = self.changed()
        obj["source_entries"][0]["git_blob"] = "0" * 40
        obj["source_inventory_digest"] = contract.digest(obj["source_entries"])
        with self.assertRaisesRegex(ValueError, "SOURCE_ROSTER"):
            contract.check_contract(obj)

    def test_wrong_source_sha256_rejects(self):
        obj = self.changed()
        obj["source_entries"][0]["sha256"] = "0" * 64
        obj["source_inventory_digest"] = contract.digest(obj["source_entries"])
        with self.assertRaisesRegex(ValueError, "SOURCE_BYTES"):
            contract.check_contract(obj)

    def test_bool_is_not_byte_count(self):
        obj = self.changed()
        obj["source_entries"][0]["bytes"] = True
        obj["source_inventory_digest"] = contract.digest(obj["source_entries"])
        with self.assertRaisesRegex(ValueError, "SOURCE_SIZE"):
            contract.check_contract(obj)

    def test_bool_is_not_numeric_semantics(self):
        obj = self.changed()
        obj["definition"]["numeric_semantics"]["word_bytes"] = True
        with self.assertRaisesRegex(ValueError, "DEFINITION_DRIFT"):
            contract.check_contract(obj)

    def test_missing_charge_event_rejects(self):
        for event in ("failed", "withheld", "post-winner", "cross-version-state"):
            with self.subTest(event=event):
                obj = self.changed()
                obj["definition"]["lifecycle"]["charge_events"].remove(event)
                with self.assertRaisesRegex(ValueError, "DEFINITION_DRIFT"):
                    contract.check_contract(obj)

    def test_measured_best_is_not_lower_bound(self):
        obj = self.changed()
        obj["definition"]["lifecycle"]["cost_bound_rule"] = "measured-best-is-minimum"
        with self.assertRaisesRegex(ValueError, "DEFINITION_DRIFT"):
            contract.check_contract(obj)

    def test_unknown_backend_is_not_replaced_by_an_unverified_identity(self):
        obj = self.changed()
        obj["definition"]["proof_identity"]["guest_image"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "DEFINITION_DRIFT"):
            contract.check_contract(obj)

    def test_cannot_join_a_different_source(self):
        for field in ("source_commit", "source_tree", "native_tree"):
            with self.subTest(field=field):
                obj = self.changed()
                obj[field] = "f" * 40
                with self.assertRaisesRegex(ValueError, "SOURCE_IDENTITY"):
                    contract.check_contract(obj)

    def test_every_unsupported_qualification_refuses_promotion(self):
        for field in contract.QUALIFICATION:
            with self.subTest(field=field):
                obj = self.changed()
                obj["qualification"][field] = True
                with self.assertRaisesRegex(ValueError, "CLAIM_PROMOTION"):
                    contract.check_contract(obj)

    def test_false_does_not_accept_zero_alias(self):
        obj = self.changed()
        obj["qualification"]["production_activation"] = 0
        with self.assertRaisesRegex(ValueError, "CLAIM_PROMOTION"):
            contract.check_contract(obj)

    def test_reject_unknown_top_level_keys(self):
        obj = self.changed()
        obj["acceptance"] = True
        with self.assertRaisesRegex(ValueError, "CONTRACT_KEYS"):
            contract.check_contract(obj)

    def test_strict_json_duplicate_float_and_nonfinite_reject(self):
        for data in ('{"x":1,"x":2}', '{"x":1.0}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                contract.loads(data)

    def test_canonical_limits_and_non_json_types_reject(self):
        for value in ({"x": 1 << 512}, {"x": 0.5}, {"x": (1, 2)}, {2: "x"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                contract.canonical(value)

    def test_path_escape_symlink_and_executable_drift_reject(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "file"
            path.write_bytes(b"source")
            path.chmod(0o644)
            self.assertEqual(contract.bytes_at(root, "file", "100644"), b"source")
            (root / "link").symlink_to(path)
            for value in ("../file", "/file", "a/../file", "link", "x\\file"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    contract.bytes_at(root, value, "100644")
            path.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "SOURCE_MODE"):
                contract.bytes_at(root, "file", "100644")


if __name__ == "__main__":
    unittest.main(verbosity=2)
