#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "model.py"


class ModelTests(unittest.TestCase):
    def test_self_test(self) -> None:
        completed = subprocess.run(
            ["python3", str(MODEL), "--self-test"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        value = json.loads(completed.stdout)
        self.assertEqual(value["schema"], "trnm-g1-r4-safety-checkpoint-model-evidence-v1")
        self.assertEqual(len(value["positive_cases"]), 3)
        self.assertGreaterEqual(len(value["negative_cases"]), 15)
        self.assertTrue(value["candidate_only"])
        self.assertFalse(value["signature_producer"])
        self.assertFalse(value["production_activation"])
        self.assertFalse(value["mixed_cut_auto_repair"])


if __name__ == "__main__":
    unittest.main()
