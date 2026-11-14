"""Exercise the future stage reader with the actual same-source fresh six-test log."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from run_root_campaign import read_amortized_independent

HERE = Path(__file__).resolve().parent


class RootStageReaderControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        directory = Path(self.directory.name)
        self.stdout, self.stderr, self.source = [directory / name for name in ("stdout", "stderr", "source")]
        self.stdout.write_bytes(b"")
        raw = (HERE / "fresh-original-six-tests.stderr").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "c0b8e094f6d80e0324adcb5e0ec710be3146c1ddc1293b1e43795b4af4a124ac")
        self.stderr.write_bytes(raw)
        self.source.write_bytes((HERE / "test_amortized_cost_potential_independent.py").read_bytes())

    def read(self, count=6, code=0):
        row = {"stage": "amortized-independent", "exit_code": code, "passed": code == 0}
        read_amortized_independent(row, self.stdout, self.stderr, self.source, count)
        return row

    def test_actual_fresh_six_uses_the_same_fixed_named_reader(self):
        row = self.read()
        self.assertTrue(row["passed"])
        self.assertEqual(row["unittest_count"], 6)
        self.assertEqual(row["named_success_count"], 6)
        self.assertEqual(len(row["named_reader"]["test_ids"]), 6)
        self.assertNotIn("reader_error", row)

    def test_changed_actual_status_records_failure_without_raising(self):
        self.stderr.write_bytes(self.stderr.read_bytes().replace(b" ... ok", b" ... skipped 'no'", 1))
        row = self.read()
        self.assertFalse(row["passed"])
        self.assertEqual(row["reader_error"]["type"], "ValueError")

    def test_absent_source_records_reader_error_without_raising(self):
        self.source.unlink()
        row = self.read()
        self.assertFalse(row["passed"])
        self.assertEqual(row["reader_error"]["type"], "FileNotFoundError")

    def test_roster_or_process_failure_cannot_be_promoted(self):
        for count, code in [(4, 0), (True, 0), (6, 1)]:
            with self.subTest(count=count, code=code):
                row = self.read(count, code)
                self.assertFalse(row["passed"])
                self.assertIn("reader_error", row)


if __name__ == "__main__":
    unittest.main(verbosity=2)
