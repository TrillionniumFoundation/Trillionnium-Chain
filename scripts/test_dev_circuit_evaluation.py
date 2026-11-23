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

    def test_regrade_original_paid_engineering_pairs(self):
        plain = CAPTURE.parent / "cell-released-pair-funded-evaluation-20261123"
        for job, first, delta in [(CAPTURE, "candidate_only", 1), (plain, "neither", 0)]:
            with self.subTest(job=job.name):
                result = evaluation.verify(job)
                score = result["paired_performance"]
                request = evaluation.read(job / "evaluation/REQUEST.json")
                self.assertEqual(result["development_units"], 2000)
                self.assertEqual(score["candidate_sha256"], evaluation.digest(request["candidate"]))
                self.assertEqual(score["rows"], [
                    {"panel": "future", "task_sha256": evaluation.digest(request["future"][0]),
                     "outcome": first, "answers_regraded": True},
                    {"panel": "retention", "task_sha256": evaluation.digest(request["retention"][0]),
                     "outcome": "both", "answers_regraded": True},
                ])
                self.assertEqual(score["future_success_count_delta"], delta)
                self.assertTrue(score["old_parent_successes_preserved"])
                self.assertFalse(score["actual_consumer_use_verified"])
                self.assertFalse(score["learning_improvement_bonus"])

    def test_retained_no_update_preflight_has_no_paid_score(self):
        path = CAPTURE.parent / "cell-inline-source-preflight-20261123"
        observation = evaluation.read(path / "OBSERVATION.json")
        self.assertEqual(observation["source_qualification"]["outcome"], "NoUpdate")
        self.assertEqual(observation["evaluated_predictions"], 0)
        with self.assertRaises(FileNotFoundError):
            evaluation.verify(path)

    def test_counts_and_delta_must_agree_with_original_rows(self):
        result = evaluation.read(CAPTURE / "evaluation/RESULT.json")
        result["counts"]["future"].update(candidate_only=0, neither=1)
        result["future_success_count_delta"] = 0
        with self.assertRaisesRegex(ValueError, "aggregate differs"):
            evaluation.paired_performance(CAPTURE, evaluation.read(CAPTURE / "ADMISSION.json"),
                                          evaluation.read(CAPTURE / "evaluation/REQUEST.json"), result)

    def test_local_regrade_uses_answer_and_expected_structure(self):
        task = evaluation.read(CAPTURE / "evaluation/REQUEST.json")["future"][0]
        row = evaluation.read(CAPTURE / "evaluation/candidate/0000.json")
        outcome = row["outcome"]
        outcome["success"] = False
        outcome["result"] = {"reason": "structure_mismatch", "success": False}
        outcome["receipt_sha256"] = evaluation.digest({k: v for k, v in outcome.items()
                                                        if k not in ("success", "receipt_sha256")})
        with self.assertRaisesRegex(ValueError, "semantic answer replay differs"):
            evaluation.score_receipt(task, row["prediction"], outcome, {outcome["verifier_source_sha256"]})

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


class HistoricalServiceTests(unittest.TestCase):
    capture = CAPTURE.parent / "cell-historical-funded-evaluation-20261123"

    def test_historical_fee_replays_with_zero_future_users(self):
        result = evaluation.verify(self.capture)
        self.assertEqual((result["development_units"], result["checked_evaluation_files"]), (2000, 4))
        self.assertNotIn("paired_performance", result)
        observed = evaluation.read(self.capture / "evaluation/RESULT.json")
        self.assertEqual(observed["future_records"], 0)
        self.assertTrue(observed["arms"]["candidate"]["outcomes"]["historical_training_A"])

    def test_seen_task_cannot_be_relabelled_future(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)
            shutil.copytree(self.capture, path, ignore=shutil.ignore_patterns("node", "*.sqlite"), dirs_exist_ok=True)
            target = path / "evaluation/RESULT.json"
            history = evaluation.read(target)
            history["future_records"] = 1
            target.write_bytes(evaluation.canonical(history))
            with self.assertRaisesRegex(ValueError, "historical replay scope"):
                evaluation.verify(path)
