#!/usr/bin/env python3
"""Synthetic runner controls; no native execution is implied by these tests."""
import unittest
import re
from pathlib import Path
from unittest.mock import patch

import run_pq_root_continuation_v4 as runner


class ContinuationRunnerControls(unittest.TestCase):
    def test_floor_roster_covers_every_native_rust_test_in_source(self):
        source = (Path(__file__).resolve().parents[2] /
                  "trillionnium/crates/trnm-pon-node/tests/recovery_floor_v4_native.rs").read_text()
        rust_tests = re.findall(r"(?m)^#\[test\]\s*\nfn ([A-Za-z_]\w*)\s*\(", source)
        self.assertTrue(rust_tests)
        self.assertEqual(len(rust_tests), len(set(rust_tests)))
        self.assertEqual(set(rust_tests), set(runner.FLOOR))


    def test_all_three_explicit_native_selectors_are_locked_and_nonempty(self):
        entries = runner.suites()
        self.assertEqual([name for name, _, _ in entries], ["recovery-floor", "provider-readback", "callback-budget"])
        self.assertEqual([argv[argv.index("--test") + 1] for _, argv, _ in entries],
                         ["recovery_floor_v4_native", "root_effect_readback_v4_native", "root_budget_v4_native"])
        for _, argv, required in entries:
            self.assertIn("--locked", argv)
            self.assertIn("pq-root-v3", argv)
            self.assertIn("--nocapture", argv)
            self.assertIn("--test-threads=1", argv)
            self.assertNotIn("--ignored", argv)
            self.assertTrue(required)

    def test_all_rosters_cover_every_native_rust_test_in_source(self):
        root = Path(__file__).resolve().parents[2]
        for name, argv, required in runner.suites():
            with self.subTest(suite=name):
                selector = argv[argv.index("--test") + 1]
                source = (root / "trillionnium/crates/trnm-pon-node/tests" /
                          (selector + ".rs")).read_text()
                rust_tests = re.findall(r"(?m)^#\[test\]\s*\nfn ([A-Za-z_]\w*)\s*\(", source)
                self.assertTrue(rust_tests)
                self.assertEqual(len(rust_tests), len(set(rust_tests)))
                self.assertEqual(set(rust_tests), set(required))

    def test_empty_or_duplicate_test_inventories_fail_before_execution(self):
        for name in ("FLOOR", "PROVIDER", "CALLBACK_BUDGET"):
            for value in ((), ("same", "same")):
                with self.subTest(name=name, value=value), patch.object(runner, name, value):
                    with self.assertRaises(ValueError):
                        runner.suites()

    def test_each_exact_native_name_and_summary_is_required(self):
        for _, _, names in runner.suites():
            raw = (f"running {len(names)} tests\n" +
                   "".join(f"test {name} ... ok\n" for name in names) +
                   f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n")
            self.assertEqual(runner.checked_result(raw, names, 0)["passed"], len(names))
            with self.assertRaises(ValueError):
                runner.checked_result(raw, names[:-1], 0)
            for changed, code in ((raw.replace(names[0], "wrong_name"), 0),
                                  (raw.replace(" ... ok", " ... ignored", 1), 0),
                                  (raw, 101), (raw, -9), (raw, 124),
                                  (raw + raw.splitlines()[-1] + "\n", 0)):
                with self.subTest(code=code), self.assertRaises(ValueError):
                    runner.checked_result(changed, names, code)


if __name__ == "__main__":
    unittest.main()
