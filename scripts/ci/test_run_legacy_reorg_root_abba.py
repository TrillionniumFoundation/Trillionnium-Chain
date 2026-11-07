#!/usr/bin/env python3
"""Current baseline binding and inherited all-attempt reader controls."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_legacy_reorg_root_abba as runner


class BindingTests(unittest.TestCase):
    def binding(self, source_commit, observer="a" * 64, store="b" * 64):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "fixture-elf"
            raw = b"\x7fELF\x02\x01" + bytes(12) + (62).to_bytes(2, "little") + b"reader-fixture"
            binary.write_bytes(raw)
            receipt = root / "build.json"
            receipt.write_text(json.dumps({"source_commit": source_commit, "build_exit": 0,
                "observer_sha256": observer, "store_sha256": store,
                "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}))
            output = root / "result"
            output.mkdir()
            with patch.object(runner, "source_digest", side_effect=lambda commit, filename:
                              "a" * 64 if filename == runner.OBSERVER else "b" * 64):
                return runner.binding("baseline", binary, receipt, "f" * 40, 62, output)

    def test_current_baseline_is_exact_and_does_not_rewrite_historical_owner(self):
        self.assertEqual(runner.BASELINE, "e70f13448aad715286fb8eb56fc802b09db643a3")
        self.assertEqual(self.binding(runner.BASELINE)["receipt"]["source_commit"], runner.BASELINE)
        with self.assertRaises(ValueError):
            self.binding(runner.retained.CONTROL)
        self.assertEqual(runner.retained.CONTROL, "852b61eeeb41c283f3bc291ce71cbe32350087a1")
        self.assertEqual(runner.retained.BASE, "0ca272d09d1522b0ffd740e441b6d3de1ed81de6")

    def test_changed_embedded_observer_or_store_is_not_a_baseline(self):
        for field in ("observer", "store"):
            with self.assertRaises(ValueError):
                self.binding(runner.BASELINE, **{field: "c" * 64})

    def test_original_denominator_budget_and_failed_attempt_retention(self):
        self.assertEqual(runner.ORDER, ("baseline", "candidate", "candidate", "baseline") * 2)
        self.assertEqual((runner.COMMAND_SECONDS, runner.GRACE_SECONDS), (300, 5))
        attempts = [{"implementation": name, "result": "HOLD",
                     "observation": {"wait4_cpu_ns": 123_456_789}}
                    for name in runner.ORDER]
        retained = copy.deepcopy(attempts)
        result = runner.comparison(attempts)
        self.assertFalse(result["complete_comparison"])
        self.assertNotIn("medians", result)
        self.assertFalse(result["failed_attempts_are_zero"])
        self.assertEqual(attempts, retained)


if __name__ == "__main__":
    unittest.main()
