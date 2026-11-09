#!/usr/bin/env python3
"""Synthetic parser mutations only; these are not native crypto observations."""
import unittest
from run_pq_root_native_v3 import checked_result, suites

NAMES = ("module::a", "module::b")
RAW = """running 2 tests
test module::a ... ok
test module::b ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.1s
"""


class RootNativeRunnerControls(unittest.TestCase):
    def test_exact_synthetic_result(self):
        self.assertEqual(checked_result(RAW, NAMES, 0)["passed"], 2)

    def test_failed_command_cannot_be_hidden_by_success_text(self):
        for code in (1, 101, 124, -9):
            with self.subTest(code=code), self.assertRaises(ValueError):
                checked_result(RAW, NAMES, code)

    def test_empty_inventory_is_not_a_successful_suite(self):
        with self.assertRaises(ValueError):
            checked_result(RAW, (), 0)

    def test_zero_discovery_is_refused(self):
        with self.assertRaises(ValueError):
            checked_result(RAW.replace("running 2 tests", "running 0 tests"), NAMES, 0)

    def test_duplicate_discovery_or_summary_is_refused(self):
        for changed in ("running 2 tests\n" + RAW, RAW + RAW.splitlines()[-1] + "\n"):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                checked_result(changed, NAMES, 0)

    def test_wrong_test_name_is_refused(self):
        with self.assertRaises(ValueError):
            checked_result(RAW.replace("module::b", "module::c"), NAMES, 0)

    def test_duplicate_native_names_are_refused(self):
        with self.assertRaises(ValueError):
            checked_result(RAW.replace("module::b", "module::a"), NAMES, 0)

    def test_ignored_or_failed_native_test_is_refused(self):
        for outcome in ("ignored", "FAILED"):
            with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                checked_result(RAW.replace("module::b ... ok", "module::b ... " + outcome), NAMES, 0)

    def test_changed_summary_denominators_are_refused(self):
        for old, new in (("2 passed", "1 passed"), ("0 failed", "1 failed"),
                         ("0 ignored", "1 ignored"), ("0 measured", "1 measured")):
            with self.subTest(old=old), self.assertRaises(ValueError):
                checked_result(RAW.replace(old, new), NAMES, 0)

    def test_missing_or_extra_named_results_are_refused(self):
        for changed in (RAW.replace("test module::a ... ok\n", ""),
                        RAW.replace("running 2 tests", "running 2 tests\ntest module::c ... ok")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                checked_result(changed, NAMES, 0)

    def test_native_profile_selectors_are_explicit_and_locked(self):
        entries = suites()
        self.assertEqual(len(entries), 4)
        for name, argv, required in entries:
            with self.subTest(name=name):
                self.assertIn("--locked", argv)
                self.assertIn("--test-threads=1", argv)
                self.assertNotIn("--ignored", argv)
                self.assertTrue(required)
        self.assertIn("pq-native-openssl", entries[1][1])
        self.assertIn("pq-root-v3", entries[2][1])
        self.assertIn("pq-root-v3", entries[3][1])


if __name__ == "__main__":
    unittest.main()
