"""Independent identity vectors and semantic mutation checks for TMR1."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

import model_release_root as root


class ModelRootTests(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((Path(__file__).with_name("vectors") / "cell-model-root-v1.json").read_text())

    def test_independent_vector_reproduces(self):
        self.assertEqual(root.fixture(), self.vector)
        wire = root.encode(self.vector["closure"], self.vector["lineage"])
        self.assertEqual(wire.hex(), self.vector["wire_hex"])
        self.assertEqual(hashlib.sha256(root.DOMAIN + wire).hexdigest(), self.vector["model_root"])

    def test_every_context_pin_and_loader_policy_changes_identity(self):
        for key in self.vector["closure"]["context"]:
            value = copy.deepcopy(self.vector["closure"])
            value["context"][key] = "different-family" if key == "family" else "97" * 32
            self.assertNotEqual(root.encode(value, self.vector["lineage"]).hex(), self.vector["wire_hex"])
        for key, replacement in [("selected_generation", 8), ("loader_profile", "98" * 32)]:
            value = copy.deepcopy(self.vector["closure"])
            value[key] = replacement
            self.assertNotEqual(root.encode(value, self.vector["lineage"]).hex(), self.vector["wire_hex"])

    def test_router_presence_and_parent_roots_have_explicit_commitments(self):
        value = copy.deepcopy(self.vector["closure"])
        value["files"][2]["role"] = 6
        self.assertNotEqual(root.encode(value, self.vector["lineage"]).hex(), self.vector["wire_hex"])
        self.assertNotEqual(root.encode(self.vector["closure"], []).hex(), self.vector["wire_hex"])
        self.assertNotEqual(root.encode(self.vector["closure"], ["21" * 32, "23" * 32]).hex(), self.vector["wire_hex"])

    def test_noncanonical_or_unbounded_lineage_is_refused(self):
        for parents in [["22" * 32, "21" * 32], ["21" * 32] * 2,
                        ["00" * 32], ["01" * 32] * 17, [True]]:
            with self.subTest(parents=parents), self.assertRaises(ValueError):
                root.encode(self.vector["closure"], parents)


if __name__ == "__main__":
    unittest.main()
