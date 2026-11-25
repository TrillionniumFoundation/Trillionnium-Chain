"""Mutation controls over the exact publicly archived inputs. Original files remain read-only."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import compare

HERE = Path(__file__).resolve().parent
HEPTA = Path(sys.argv.pop(1)).resolve()


class ArchivedCrossReadback(unittest.TestCase):
    def test_public_cli_retains_scope_without_ledger_material(self):
        result = subprocess.run([sys.executable, "-B", str(HERE / "compare.py"), str(HEPTA)],
                                capture_output=True, text=True, timeout=15, check=True)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report, dict(
            schema="trnm.archived-consumer-ledger-cross-readback-public-summary.v1",
            status="VERIFIED_ARCHIVE_READBACK", same_released_pair=False,
            release_field_equality={key: key == "scope" for key in
                ("scope", "study_sha256", "admission_sha256", "freeze_sha256", "candidate_sha256", "request_sha256")},
            legacy_operations_checked=2, subsequent_fixture_uses_checked=2, verified_evaluation_files=12,
            independently_verified_business_effect="UNVERIFIED", real_independent_consumer_use="UNVERIFIED",
            external_payer_and_settlement="UNVERIFIED", improvement_reward="UNVERIFIED",
            consensus_credit="UNVERIFIED", settlement_authorized=False))
        original = json.loads((HERE / "READOUT.json").read_bytes())
        for key in ("task", "payment_operation", "payment_subject", "development_units"):
            self.assertNotIn(str(original["checked_development_evaluation"][key]), result.stdout)

    def test_public_summary_cannot_inherit_private_nested_fields(self):
        original = json.loads((HERE / "READOUT.json").read_bytes())
        canary = "private-payment-canary-not-for-console"
        original["extra_private_field"] = canary
        original["checked_development_evaluation"].update(
            development_units=canary, payment_operation=canary, payment_subject=canary)
        original["legacy_operations"][0]["operation"] = canary
        original["subsequent_fixture_uses"][0]["operation"] = canary
        original["common_release_fields"]["scope"]["chain_evaluation"] = canary
        with mock.patch.object(compare, "compare", return_value=original) as verifier:
            result = compare.public_comparison_summary(HEPTA)
        verifier.assert_called_once_with(HEPTA)
        self.assertNotIn(canary, json.dumps(result))
        self.assertEqual(original["checked_development_evaluation"]["development_units"], canary)

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
