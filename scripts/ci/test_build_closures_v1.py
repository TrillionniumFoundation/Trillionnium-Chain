#!/usr/bin/env python3
"""Retained feature-leakage mutants against the real Cargo manifest graph."""
from __future__ import annotations

import copy
import dataclasses
import unittest

import check_build_closures_v1 as closure

NODE = "trnm-poco-node"
CORE = "trnm-consensus-core"
SAFETY = "trnm-consensus-safety-store"
NATIVE = "trnm-native-execution-v0"
AUTHORITY = "trnm-poco-node-authority"


class FeatureClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.original_config = closure.load_toml(closure.CONFIG_PATH)
        cls.original_packages = closure.workspace_packages(
            closure.ROOT / cls.original_config["workspace_manifest"]
        )

    def setUp(self) -> None:
        self.config = copy.deepcopy(self.original_config)
        self.packages = copy.deepcopy(self.original_packages)

    def validate(self):
        return closure.validate_feature_closures(self.packages, self.config)

    def add_dependency_feature(self, owner, target, feature):
        dependency = self.packages[owner].dependencies[target]
        self.packages[owner].dependencies[target] = dataclasses.replace(
            dependency, features=(*dependency.features, feature)
        )

    def test_real_entrypoints_have_separate_feature_boundaries(self):
        reports = {row["id"]: row for row in self.validate()}
        self.assertEqual(len(reports), 5)
        self.assertIn(f"{CORE}/candidate-epoch-host-v1", reports["epoch-runtime-features"]["resolved_features"])
        self.assertIn(f"{SAFETY}/test-fixtures", reports["epoch-runtime-fixture-features"]["resolved_features"])
        self.assertNotIn(f"{NODE}/epoch-runtime-candidate", reports["node-production-features"]["resolved_features"])

    def test_dependency_feature_leak_changes_no_package_membership_but_rejects(self):
        before, _ = closure.resolve_closure(self.packages, ["trnm-poco-node-cli"], set(), True)
        self.add_dependency_feature(AUTHORITY, NODE, "epoch-runtime-candidate")
        after, _ = closure.resolve_closure(self.packages, ["trnm-poco-node-cli"], set(), True)
        self.assertEqual(before, after, "package-only checks cannot detect this authority leak")
        with self.assertRaisesRegex(closure.ClosureError, "node-production-features: forbidden"):
            self.validate()

    def test_core_candidate_feature_cannot_be_enabled_by_a_production_dependency(self):
        self.add_dependency_feature(NODE, CORE, "candidate-epoch-host-v1")
        with self.assertRaisesRegex(closure.ClosureError, "node-production-features: forbidden"):
            self.validate()

    def test_safety_candidate_default_cannot_leak_to_production(self):
        self.packages[SAFETY].features["default"].append("candidate-epoch-host-v1")
        with self.assertRaisesRegex(closure.ClosureError, "node-production-features: forbidden"):
            self.validate()

    def test_node_default_cannot_enable_epoch_candidate(self):
        self.packages[NODE].features["default"].append("epoch-runtime-candidate")
        with self.assertRaisesRegex(closure.ClosureError, "forbidden candidate features"):
            self.validate()

    def test_production_native_fixture_dependency_is_rejected(self):
        self.add_dependency_feature(NODE, NATIVE, "test-fixtures")
        with self.assertRaisesRegex(closure.ClosureError, "test features reached runtime"):
            self.validate()

    def test_any_named_test_support_feature_is_rejected_in_runtime(self):
        self.packages[CORE].features["new-path-test-support"] = []
        self.add_dependency_feature(NODE, CORE, "new-path-test-support")
        with self.assertRaisesRegex(closure.ClosureError, "new-path-test-support"):
            self.validate()

    def test_outgoing_only_authority_cannot_enable_full_epoch_runtime(self):
        self.packages[AUTHORITY].features["persistent-authority-candidate"].append(
            f"{NODE}/epoch-runtime-candidate"
        )
        with self.assertRaisesRegex(closure.ClosureError, "outgoing-authority-features: forbidden"):
            self.validate()

    def test_explicit_runtime_cannot_include_test_fixture(self):
        self.packages[NODE].features["epoch-runtime-candidate"].append(f"{NATIVE}/test-fixtures")
        with self.assertRaisesRegex(closure.ClosureError, "epoch-runtime-features: test features"):
            self.validate()

    def test_required_safety_candidate_wiring_cannot_be_removed(self):
        self.packages[NODE].features["epoch-runtime-candidate"].remove(f"{SAFETY}/candidate-epoch-host-v1")
        with self.assertRaisesRegex(closure.ClosureError, "required features absent"):
            self.validate()

    def test_transitive_core_wiring_is_semantic_not_an_exact_manifest_string(self):
        # The Safety feature forwards the same Core feature. Removing a
        # redundant direct edge preserves the actual resolved contract.
        self.packages[NODE].features["epoch-runtime-candidate"].remove(f"{CORE}/candidate-epoch-host-v1")
        self.validate()
        self.packages[SAFETY].features["candidate-epoch-host-v1"].clear()
        with self.assertRaisesRegex(closure.ClosureError, "required features absent"):
            self.validate()

    def test_real_native_fixture_wiring_cannot_be_removed(self):
        self.packages[NODE].features["epoch-runtime-test-fixtures"].remove(f"{NATIVE}/test-fixtures")
        dependency = self.packages[SAFETY].dependencies[NATIVE]
        self.packages[SAFETY].dependencies[NATIVE] = dataclasses.replace(dependency, features=())
        with self.assertRaisesRegex(closure.ClosureError, "required features absent"):
            self.validate()

    def test_feature_boundary_cannot_disappear_or_duplicate(self):
        self.config["feature_closures"].pop()
        with self.assertRaisesRegex(closure.ClosureError, "entrypoints missing or duplicated"):
            self.validate()
        self.config = copy.deepcopy(self.original_config)
        self.config["feature_closures"].append(self.config["feature_closures"][0])
        with self.assertRaisesRegex(closure.ClosureError, "entrypoints missing or duplicated"):
            self.validate()

    def test_unknown_feature_cannot_fabricate_a_successful_resolution(self):
        self.config["feature_closures"][-1]["features"] = ["nonexistent-fixture"]
        with self.assertRaisesRegex(closure.ClosureError, "unknown root feature"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
