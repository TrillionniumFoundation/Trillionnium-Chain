"""Check that independently retained evaluation and payment bytes cannot be swapped."""
from pathlib import Path
import shutil
import tempfile
import unittest

import dev_circuit_evaluation as evaluation


CAPTURE = Path(__file__).resolve().parents[1] / "evidence" / "cell-circuit-funded-evaluation-20261123"


class DevelopmentEvaluationTests(unittest.TestCase):
    def test_retained_evaluation_and_fee(self):
        result = evaluation.verify(CAPTURE)
        self.assertEqual((result["development_units"], result["checked_evaluation_files"]), (2000, 12))

    def test_raw_candidate_prediction_cannot_be_replaced_by_parents(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)
            shutil.copytree(CAPTURE, path, ignore=shutil.ignore_patterns("node", "*.sqlite"), dirs_exist_ok=True)
            shutil.copyfile(path / "evaluation/parent/0000.json", path / "evaluation/candidate/0000.json")
            with self.assertRaisesRegex(ValueError, "raw evaluation bytes"):
                evaluation.verify(path)

    def test_replacing_signed_arbitration_with_delivery_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)
            shutil.copytree(CAPTURE, path, ignore=shutil.ignore_patterns("node", "*.sqlite"), dirs_exist_ok=True)
            target = path / "SIGNED_EFFECTS.json"
            payments = evaluation.read(target)
            payments["signed_arbitration"] = payments["signed_delivery"]
            target.write_bytes(evaluation.canonical(payments))
            with self.assertRaisesRegex(ValueError, "signed operation differs"):
                evaluation.verify(path)
