"""Mutation controls over the exact publicly archived inputs. Original files remain read-only."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

import compare

HERE = Path(__file__).resolve().parent
HEPTA = Path(sys.argv.pop(1)).resolve()


class ArchivedCrossReadback(unittest.TestCase):
    def test_fixed_observation_and_scopes(self):
        report = compare.compare(HEPTA)
        self.assertEqual(report, json.loads((HERE / "READOUT.json").read_bytes()))
        self.assertFalse(report["same_released_pair"])
        self.assertEqual(["scope"], [k for k,v in report["common_release_fields"].items() if v["equal"]])
        self.assertEqual(["accepted", "rejected"], [x["outcome"] for x in report["subsequent_fixture_uses"]])
        for row in report["legacy_operations"]:
            self.assertFalse(row["independent_consumer_gate"]["verified"])
            self.assertFalse(row["original_funded_mapping_observed"])
            self.assertIsNone(row["improvement_reward"]["actual_external_amount"])

    def test_positive_json_cannot_replace_original_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "CONSUMER_ENGINEERING_ORIGINALS.zip").write_text('{"paid":true,"independent":true}')
            with self.assertRaisesRegex(ValueError, "original file digest differs"):
                compare.consumer(path)

    def test_external_verifier_is_pinned_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            shutil.copyfile(HEPTA / "CONSUMER_ENGINEERING_ORIGINALS.zip", path / "CONSUMER_ENGINEERING_ORIGINALS.zip")
            (path / "verify_fixture.py").write_text("raise RuntimeError('untrusted verifier ran')")
            with self.assertRaisesRegex(ValueError, "original file digest differs"):
                compare.consumer(path)

    def test_development_payment_cannot_be_retargeted_to_b_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "candidate-job"
            shutil.copytree(compare.JOB, path)
            current = json.loads((path / "CURRENT.json").read_bytes())
            _, uses = compare.consumer(HEPTA)
            current["current_payment"]["subject"] = uses[0]["output_sha256"]
            (path / "CURRENT.json").write_text(json.dumps(current))
            with self.assertRaisesRegex(ValueError, "native development fee or scope mismatch"):
                compare.compare(HEPTA, path)

    def test_original_learning_checkpoint_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = compare.CHAIN / "evidence"
            for directory in ("hepta-real-native-adoption-20261108/chain-reader/adopt-v1",
                              "cell-learning-business-readback-20261109/bindings"):
                destination = root / "evidence" / directory
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(evidence / directory, destination)
            target = root / "evidence/hepta-real-native-adoption-20261108/chain-reader/adopt-v1/completed.bin"
            target.write_bytes(target.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, "BUSINESS_MATERIAL_PIN"):
                compare.legacy("adopt-v1", root)


if __name__ == "__main__":
    unittest.main()
