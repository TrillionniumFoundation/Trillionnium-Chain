#!/usr/bin/env python3
import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("profile_registry", ROOT / "scripts/ci/check_protocol_profile_registry_v1.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ProfileRegistryTests(unittest.TestCase):
    def setUp(self):
        self.data = MODULE.load()

    def test_canonical_profile_is_the_only_default(self):
        report = MODULE.validate(self.data)
        self.assertEqual(report["canonical_profile"], "bft-v0")
        self.assertEqual(report["default_build_profiles"], ["bft-v0"])
        self.assertEqual(report["default_check_profiles"], ["bft-v0"])

    def test_candidate_cannot_leak_into_default_path(self):
        mutated = copy.deepcopy(self.data)
        mutated["profiles"][1]["default_build"] = True
        with self.assertRaises(MODULE.ProfileRegistryError):
            MODULE.validate(mutated)

    def test_pcc1_reuses_v0_schema_and_errors(self):
        pcc1 = self.data["profiles"][1]
        self.assertEqual(pcc1["wire_schema_ref"], "bft-v0")
        self.assertEqual(pcc1["error_namespace_ref"], "bft-v0")
        self.assertNotIn("wire_schema", pcc1)
        self.assertNotIn("error_namespace", pcc1)


if __name__ == "__main__":
    unittest.main()
