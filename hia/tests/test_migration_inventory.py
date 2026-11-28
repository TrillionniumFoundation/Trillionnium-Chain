"""The complete HIA tree must have unique ownership, including runtime sources."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from hia.tools.check_migration import source_inventory


class CompleteSourceInventory(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="trnm-hia-inventory-")
        self.root = Path(self.directory.name)
        for name in ("hia/src/kernel.hepta", "hia/platform/fixture.hepta",
                     "hia/storage/owner.hepta", "hia/tests/test_kernel.py", "hia/tools/qualify_storage.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("source inventory fixture\n")
        self.inventory = {
            "components": [{"id": "kernel", "source": "hia/src/kernel.hepta", "tests": ["hia/tests/test_kernel.py"],
                            "node_integration_complete": False}],
            "native_foundations": [{"id": "owner", "sources": ["hia/storage/owner.hepta", "hia/platform/fixture.hepta"],
                                    "tests": ["hia/tools/qualify_storage.py"],
                                    "node_integration_complete": False, "retirement_accepted": False}],
        }

    def tearDown(self):
        self.directory.cleanup()

    def test_kernels_runtime_and_native_callers_are_all_accounted_for(self):
        self.assertEqual(source_inventory(self.inventory, self.root), (1, 1, 3))

    def test_unlisted_source_in_any_hia_subdirectory_is_refused(self):
        for name in ("hia/src/extra.hepta", "hia/storage/extra.hepta", "hia/platform/caller.hepta", "hia/tests/hidden.hepta"):
            path = self.root / name
            path.write_text("unlisted source\n")
            with self.subTest(name=name), self.assertRaises(ValueError):
                source_inventory(self.inventory, self.root)
            path.unlink()

    def test_duplicate_source_or_identity_cannot_hide_ownership(self):
        for field in ("source", "identity"):
            value = deepcopy(self.inventory)
            if field == "source":
                value["native_foundations"][0]["sources"].append("hia/src/kernel.hepta")
            else:
                value["native_foundations"][0]["id"] = "kernel"
            with self.subTest(field=field), self.assertRaises(ValueError):
                source_inventory(value, self.root)

    def test_missing_aliased_or_escaping_inputs_are_refused(self):
        missing = self.root / "hia/storage/owner.hepta"
        original = missing.read_bytes()
        missing.unlink()
        with self.assertRaises(ValueError):
            source_inventory(self.inventory, self.root)
        missing.symlink_to(self.root / "hia/src/kernel.hepta")
        with self.assertRaises(ValueError):
            source_inventory(self.inventory, self.root)
        missing.unlink(); missing.write_bytes(original)
        for bad in ("../outside.hepta", "/tmp/outside.hepta", "hia/storage/./owner.hepta", None):
            value = deepcopy(self.inventory)
            value["native_foundations"][0]["sources"][0] = bad
            with self.subTest(path=bad), self.assertRaises(ValueError):
                source_inventory(value, self.root)

    def test_finite_kernel_cannot_claim_node_integration(self):
        for claim in (True, 0, "false", None):
            value = deepcopy(self.inventory)
            value["components"][0]["node_integration_complete"] = claim
            with self.subTest(claim=claim), self.assertRaisesRegex(ValueError, "kernel node integration"):
                source_inventory(value, self.root)

    def test_each_owner_requires_a_nonempty_distinct_test_roster(self):
        for table in ("components", "native_foundations"):
            for roster in ([], "hia/tests/test_kernel.py", [None],
                           ["hia/tests/test_kernel.py"] * 2):
                value = deepcopy(self.inventory)
                value[table][0]["tests"] = roster
                with self.subTest(table=table, roster=roster), self.assertRaisesRegex(ValueError, "test roster"):
                    source_inventory(value, self.root)

    def test_hia_source_cannot_substitute_for_a_test_caller(self):
        value = deepcopy(self.inventory)
        value["components"][0]["tests"] = ["hia/storage/owner.hepta"]
        with self.assertRaisesRegex(ValueError, "test caller"):
            source_inventory(value, self.root)

    def test_distinct_owners_may_share_a_real_test_caller(self):
        value = deepcopy(self.inventory)
        value["native_foundations"][0]["tests"] = ["hia/tests/test_kernel.py"]
        self.assertEqual(source_inventory(value, self.root), (1, 1, 3))

    def test_finite_foundation_cannot_claim_node_integration_or_retirement(self):
        for field in ("node_integration_complete", "retirement_accepted"):
            for claim in (True, 0, "false"):
                value = deepcopy(self.inventory)
                value["native_foundations"][0][field] = claim
                with self.subTest(field=field, claim=claim), self.assertRaises(ValueError):
                    source_inventory(value, self.root)


if __name__ == "__main__":
    unittest.main()
