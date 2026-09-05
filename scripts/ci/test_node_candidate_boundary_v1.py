#!/usr/bin/env python3
"""Retained default/candidate composition mutants; not implementation acceptance."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import pathlib
import shutil
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

import check_build_closures_v1 as closures
import check_node_decomposition_v1 as decomposition

ROOT = pathlib.Path(__file__).resolve().parents[2]
ADAPTER = "trnm-durable-file-adapters-v0"
FEATURE = "persistent-authority-candidate"


class CompositionMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        manifests = decomposition.workspace_packages(ROOT / "trillionnium/Cargo.toml")
        inputs = [ROOT / "trillionnium/Cargo.toml", ROOT / "config/node-decomposition-v1.toml",
                  ROOT / "config/build-closures-v1.toml", *manifests.values()]
        for package in ("trnm-poco-node-authority", "trnm-poco-node-io",
                        "trnm-poco-node-host", "trnm-poco-node-cli"):
            inputs.extend((manifests[package].parent / "src").rglob("*.rs"))
        for source in inputs:
            target = self.root / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        patcher = mock.patch.multiple(decomposition, ROOT=self.root,
                                      CONFIG=self.root / "config/node-decomposition-v1.toml")
        patcher.start()
        self.addCleanup(patcher.stop)

    def mutate(self, package: str, old: str, new: str) -> None:
        path = self.root / f"trillionnium/crates/{package}/Cargo.toml"
        text = path.read_text()
        self.assertIn(old, text, "mutant must actually change an existing input")
        path.write_text(text.replace(old, new, 1))

    def gate(self) -> dict:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(decomposition.main(), 0)
        return json.loads(output.getvalue())

    def test_positive_retains_non_activation(self) -> None:
        report = self.gate()
        self.assertTrue(report["candidate_owner_outside_composition"])
        self.assertFalse(report["production_candidate"])
        self.assertFalse(report["production_consensus_activation"])

    def test_nonoptional_adapter_rejected(self) -> None:
        self.mutate("trnm-poco-node-authority", 'optional = true', 'optional = false')
        with self.assertRaises(decomposition.DecompositionError):
            self.gate()

    def test_default_feature_cannot_select_candidate(self) -> None:
        for package in ("trnm-poco-node-host", "trnm-poco-node-authority"):
            path = self.root / f"trillionnium/crates/{package}/Cargo.toml"
            original = path.read_text()
            with self.subTest(package=package):
                self.mutate(package, 'default = []', f'default = ["{FEATURE}"]')
                with self.assertRaises(decomposition.DecompositionError):
                    self.gate()
            path.write_text(original)
            self.gate()  # positive control between independent mutants

    def test_host_feature_cannot_lose_owner_forwarding(self) -> None:
        self.mutate("trnm-poco-node-host", f'"trnm-poco-node-authority/{FEATURE}"', '"missing"')
        with self.assertRaises(decomposition.DecompositionError):
            self.gate()

    def test_fake_journal_ownership_metadata_rejected(self) -> None:
        self.mutate("trnm-poco-node-authority", 'durable_authority_journal_owner = false',
                    'durable_authority_journal_owner = true')
        with self.assertRaises(decomposition.DecompositionError):
            self.gate()

    def test_recursive_source_cannot_hide_domain_state(self) -> None:
        path = self.root / "trillionnium/crates/trnm-poco-node-authority/src/nested/owner.rs"
        path.parent.mkdir()
        for token in ("FileAuthorityCoordinatorV0", "recovered: bool", "AuthorityCommandV0",
                      "fn require_recovered", "fn validate_receipt_v0", "fs::canonicalize"):
            with self.subTest(token=token):
                path.write_text(token)
                with self.assertRaises(decomposition.DecompositionError):
                    self.gate()
        path.unlink()
        self.gate()

    def test_cli_cannot_directly_import_component_library(self) -> None:
        self.mutate("trnm-poco-node-cli", '[dependencies]',
                    '[dependencies]\ntrnm-poco-node = { path = "../trnm-poco-node" }')
        with self.assertRaises(decomposition.DecompositionError):
            self.gate()


class FeatureClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packages = closures.workspace_packages(ROOT / "trillionnium/Cargo.toml")

    def resolve(self, packages=None, root="trnm-poco-node-cli", features=(), default=True):
        return closures.resolve_closure(packages or self.packages, [root], set(features), default)[0]

    def test_default_cli_has_no_candidate_adapter(self) -> None:
        self.assertNotIn(ADAPTER, self.resolve())

    def test_no_default_cli_has_no_candidate_adapter(self) -> None:
        self.assertNotIn(ADAPTER, self.resolve(default=False))

    def test_explicit_candidate_feature_preserves_real_owner(self) -> None:
        for package in ("trnm-poco-node-host", "trnm-poco-node-authority"):
            with self.subTest(package=package):
                self.assertIn(ADAPTER, self.resolve(root=package, features=(FEATURE,), default=False))

    def test_nonoptional_dependency_is_detected_as_contamination(self) -> None:
        packages = copy.deepcopy(self.packages)
        authority = packages["trnm-poco-node-authority"]
        authority.dependencies[ADAPTER] = replace(authority.dependencies[ADAPTER], optional=False)
        reached = self.resolve(packages)
        self.assertIn(ADAPTER, reached)
        with self.assertRaises(closures.ClosureError):
            closures.validate_persistent_authority_boundary(packages, reached)

    def test_transitive_feature_forwarding_is_not_invisible(self) -> None:
        packages = copy.deepcopy(self.packages)
        cli = packages["trnm-poco-node-cli"]
        key = "trnm-poco-node-host"
        cli.dependencies[key] = replace(cli.dependencies[key], features=(FEATURE,))
        reached = self.resolve(packages)
        self.assertIn(ADAPTER, reached)
        with self.assertRaises(closures.ClosureError):
            closures.validate_persistent_authority_boundary(packages, reached)

    def test_missing_candidate_owner_is_not_success(self) -> None:
        packages = copy.deepcopy(self.packages)
        packages["trnm-poco-node-host"].features[FEATURE] = []
        with self.assertRaises(closures.ClosureError):
            closures.validate_persistent_authority_boundary(packages, self.resolve())

    def test_distinct_default_and_candidate_controls(self) -> None:
        reached = closures.validate_persistent_authority_boundary(self.packages, self.resolve())
        self.assertIn(ADAPTER, reached)
        self.assertNotIn(ADAPTER, self.resolve())


if __name__ == "__main__":
    unittest.main(verbosity=2)
