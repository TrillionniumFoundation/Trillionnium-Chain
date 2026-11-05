"""Adversarial controls for accepting actual process result observations."""
import json
from pathlib import Path
import tempfile
import unittest

from observations import read_single_result


class ResultLogControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "actual.stdout.log"
        self.result = {"schema": "pon-w1-risc0-research-v1", "operation": "prove",
                       "real_composite_stark_verified": True}

    def read(self):
        return read_single_result(self.path, self.result["schema"], "prove")

    def test_one_result_with_information_preserves_the_entire_raw_log(self):
        raw = "INFO actual executor diagnostic\n{}\n" + json.dumps(self.result) + "\n"
        self.path.write_text(raw)
        self.assertEqual(self.read(), self.result)
        self.assertEqual(self.path.read_text(), raw)

    def test_no_result_cannot_become_a_successful_observation(self):
        self.path.write_text("INFO execution succeeded but no proof result exists\n{}\n")
        with self.assertRaises(ValueError):
            self.read()

    def test_duplicate_identical_results_are_rejected_not_last_line_wins(self):
        self.path.write_text((json.dumps(self.result) + "\n") * 2)
        with self.assertRaises(ValueError):
            self.read()

    def test_same_schema_different_operation_is_still_ambiguous(self):
        other = dict(self.result, operation="execute")
        self.path.write_text(json.dumps(other) + "\n" + json.dumps(self.result) + "\n")
        with self.assertRaises(ValueError):
            self.read()

    def test_wrong_operation_or_truncated_result_is_not_a_proof(self):
        for raw in [json.dumps(dict(self.result, operation="execute")),
                    json.dumps(self.result)[:-1]]:
            with self.subTest(raw=raw):
                self.path.write_text(raw + "\n")
                with self.assertRaises(ValueError):
                    self.read()


if __name__ == "__main__":
    unittest.main()
