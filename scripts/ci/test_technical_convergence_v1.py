#!/usr/bin/env python3
"""Retained negative tests for the technical-convergence validator."""

from __future__ import annotations

import importlib.util
import pathlib
import shutil
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/ci/check_technical_convergence_v1.py"

spec = importlib.util.spec_from_file_location("convergence_checker", CHECKER)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load convergence checker")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class TechnicalConvergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        for relative in (
            "config/technical-convergence-v1.toml",
            "docs/protocol/poco-bft-v0/parameters.toml",
            "config/consensus-mainline.json",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        contract = checker.load_toml(ROOT, checker.CONTRACT)
        for row in contract["detailed_spec"]:
            relative = row["path"]
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def replace(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, f"fixture replacement count for {old!r}")
        path.write_text(text.replace(old, new), encoding="utf-8")

    def test_current_contract_passes(self) -> None:
        self.assertEqual(checker.validate(self.root)["result"], "PASS")

    def test_rejects_poco_leaving_shadow(self) -> None:
        self.replace(
            "docs/protocol/poco-bft-v0/parameters.toml",
            'current_phase = "shadow"',
            'current_phase = "full"',
        )
        with self.assertRaises(checker.ConvergenceError):
            checker.validate(self.root)

    def test_rejects_production_promotion(self) -> None:
        self.replace(
            "config/technical-convergence-v1.toml",
            "production_candidate = false",
            "production_candidate = true",
        )
        with self.assertRaises(checker.ConvergenceError):
            checker.validate(self.root)

    def test_rejects_duplicate_module_partition(self) -> None:
        self.replace(
            "config/technical-convergence-v1.toml",
            'non_authoritative_service = ["M14", "M16"]',
            'non_authoritative_service = ["M14", "M16", "M04"]',
        )
        with self.assertRaises(checker.ConvergenceError):
            checker.validate(self.root)

    def test_rejects_shallow_or_incomplete_spec(self) -> None:
        path = self.root / "docs/modules/M04_P2P_TECHNICAL_SPEC_V1.md"
        path.write_text("# M04 P2P / Session / Dissemination technical specification v1\n",
                        encoding="utf-8")
        with self.assertRaises(checker.ConvergenceError):
            checker.validate(self.root)

    def test_rejects_fabricated_external_gate(self) -> None:
        self.replace(
            "config/technical-convergence-v1.toml",
            'id = "EXT-REVIEW-001"\nstatus = "open-external"',
            'id = "EXT-REVIEW-001"\nstatus = "closed"',
        )
        with self.assertRaises(checker.ConvergenceError):
            checker.validate(self.root)


if __name__ == "__main__":
    unittest.main()
