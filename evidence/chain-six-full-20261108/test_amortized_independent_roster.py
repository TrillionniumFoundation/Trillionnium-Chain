#!/usr/bin/env python3
from pathlib import Path
import unittest
import verify_amortized_independent_roster as subject

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "test_amortized_cost_potential_independent.py").read_bytes()
OUT = (HERE / "amortized-independent.stdout").read_bytes()
ERR = (HERE / "amortized-independent.stderr").read_bytes()


class ExactSixControls(unittest.TestCase):
    def reject(self, err=ERR, out=OUT, code=0, source=SOURCE):
        with self.assertRaises(ValueError): subject.verify_frame(out, err, code, source)

    def test_actual_full_six_retained_results(self):
        result = subject.verify_frame(OUT, ERR, 0, SOURCE)
        self.assertEqual((result["executed_ok"], result["skipped"], len(set(result["test_ids"]))), (6, 0, 6))

    def test_missing_or_duplicate_named_entry(self):
        lines = ERR.splitlines(keepends=True)
        self.reject(b"".join(lines[2:])); self.reject(b"".join(lines[:2])+ERR)
        self.reject(ERR.replace(lines[4], lines[5]))

    def test_unknown_identity_or_class_cannot_replace_original(self):
        self.reject(ERR.replace(subject.ROSTER[2][1].encode(), b"test_other"))
        self.reject(ERR.replace(b"IndependentFiniteOracles", b"AnotherOracle", 1))

    def test_only_two_exact_original_docstring_continuations(self):
        for _, _, text in subject.ROSTER[:2]:
            self.reject(ERR.replace(text.encode()+b" ... ok\n", b" ... ok\n"))
            self.reject(ERR.replace(text.encode(), b"new exception or description"))
        self.reject(ERR.replace(b" ... ok\n", b"\nextra continuation ... ok\n", 1))

    def test_skips_failures_and_expected_failures_rejected(self):
        for replacement in (b"skipped 'no'", b"FAIL", b"ERROR", b"expected failure"):
            self.reject(ERR.replace(b"... ok", b"... "+replacement, 1))

    def test_fake_ok_changed_count_and_trailing_data_rejected(self):
        self.reject(ERR+b"OK\n"); self.reject(b"OK\n"+ERR)
        self.reject(ERR.replace(b"Ran 6 tests", b"Ran 4 tests"))
        self.reject(ERR.replace(b"OK\n", b"OK (skipped=1)\n"))

    def test_source_byte_drift_rejected(self):
        self.reject(source=SOURCE+b"\n")
        self.reject(source=SOURCE.replace(b"1600", b"1601", 1))

    def test_process_failure_extra_stdout_and_boolean_exit_rejected(self):
        for code in (1, -9, 101, False, None): self.reject(code=code)
        self.reject(out=b"OK\n")


if __name__ == "__main__": unittest.main(verbosity=2)
