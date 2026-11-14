"""Original native completed checkpoints and adversarial continuation controls.

The two positive cases are actor fixtures, not model experiments. Encoders are
used only to attack the original bytes; missing native exports are failures.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

import capture_cell_learning_completion as capture
import cell_adoption_readback as native
import cell_learning_completion_join as completion
import cell_learning_iteration_join as iteration
from test_cell_learning_iteration_join import mutated_encoding, rehash_mutation

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "evidence/cell-learning-completion-20261108/native-readbacks"


class CompletedNativeLearningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((FIXTURES / "fixture-manifest.json").read_bytes())
        if cls.manifest["scope"] != "original-native-engineering-fixtures-not-production":
            raise AssertionError("fixture scope changed")
        if cls.manifest["pins_are_fixture_derived"] is not True:
            raise AssertionError("fixture expectations cannot establish independent custody")
        log = (FIXTURES / "native.stdout").read_bytes()
        if native.sha(log) != cls.manifest["source_log_sha256"]:
            raise AssertionError("original native stdout changed")
        for phase, record in cls.manifest["exports"].items():
            for name, digest in record["files"].items():
                if native.sha((FIXTURES / name).read_bytes()) != digest:
                    raise AssertionError("native corpus file changed: " + name)
            for kind, point in record["captures"].items():
                suffix = {"READBACK_V1": ".json", "CHECKPOINT_V2": ".selection-export.json",
                          "COMPLETION_V1": ".completed-export.json"}[kind]
                raw = (FIXTURES / (phase + suffix)).read_bytes()
                start, length = point["byte_offset"], point["byte_length"]
                if log[start:start + length] != raw or length != len(raw):
                    raise AssertionError("native export is not the retained stdout slice")

    def case(self, phase="adopted_acked"):
        suffixes = (".selection.bin", ".completed.bin", ".json", ".freeze.json", ".expected.json")
        raw = [(FIXTURES / (phase + suffix)).read_bytes() for suffix in suffixes]
        return raw[0], raw[1], raw[2], json.loads(raw[3]), json.loads(raw[4])

    def review(self, selection, completed, readback, frozen, expected):
        return completion.review_native_learning_completion(selection, completed, readback,
            expected_selection_sha256=native.sha(selection), expected_completed_sha256=native.sha(completed),
            expected_readback_sha256=native.sha(readback), frozen=frozen, expected=expected)

    def test_original_native_terminal_bytes_bind_retained_and_adopted_use(self):
        for phase in capture.ACKED:
            with self.subTest(phase=phase):
                case = self.case(phase)
                result = self.review(*case)
                completed, replay = iteration.decode_native_learning_checkpoint(case[1])
                exported = json.loads((FIXTURES / (phase + ".completed-export.json")).read_bytes())
                original_bytes, _, _ = capture.checkpoint_bytes(exported, completed=True)
                self.assertEqual(original_bytes, case[1])
                self.assertEqual(result["completed_learning_head"], replay["head"])
                self.assertEqual(result["final_observation"], completed["receipts"][-1]["observation"])
                self.assertEqual(result["no_update"], phase.startswith("retained"))
                self.assertTrue(result["native_receipt_chain_complete"])
                self.assertTrue(result["final_next_use_matches_original_actor"])
                self.assertEqual((result["authority"], result["current_permission"], result["qualification"]),
                                 ("DENY_ALL", "NOT_EXPORTED", "HOLD_NO_GO"))
                for name in ("full_learning_iteration_completed", "real_model_training_verified",
                             "learning_signatures_verified", "settlement_verified", "hepta_final_use_accepted",
                             "native_origin_authenticated", "independent_control_accepted", "production_activation"):
                    self.assertIs(result[name], False, name)

    def test_acknowledged_output_does_not_invent_model_stop_or_episode_end(self):
        for phase in capture.ACKED:
            with self.subTest(phase=phase):
                result = self.review(*self.case(phase))
                original = result["selection_use_review"]["native_readback_review"]
                self.assertTrue(result["acknowledged_use_observed"])
                self.assertFalse(original["pending_work"])
                self.assertFalse(original["pending_delivery"])
                self.assertEqual(result["model_stop_observed"], original["model_stop_observed"])
                self.assertEqual(result["terminal_episode_observed"], original["terminal_episode_observed"])

    def test_original_pending_output_is_refused_even_with_completed_checkpoint(self):
        for phase in capture.ACKED:
            with self.subTest(phase=phase):
                selection, final, _, _, _ = self.case(phase)
                pending = phase.replace("acked", "pending")
                readback = (FIXTURES / (pending + ".json")).read_bytes()
                expected = json.loads((FIXTURES / (pending + ".expected.json")).read_bytes())
                frozen = json.loads((FIXTURES / (pending + ".freeze.json")).read_bytes())
                with self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_ACK_PENDING"):
                    self.review(selection, final, readback, frozen, expected)

    def test_selection_cut_cannot_stand_in_for_final_receipt(self):
        selection, _, readback, frozen, expected = self.case()
        with self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_EXACT_RECEIPT_PREFIX"):
            self.review(selection, selection, readback, frozen, expected)

    def test_foreign_original_completed_checkpoint_is_refused(self):
        selection, _, readback, frozen, expected = self.case()
        foreign = self.case("retained_acked")[1]
        with self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_EXACT_RECEIPT_PREFIX"):
            self.review(selection, foreign, readback, frozen, expected)

    def test_changed_prior_evidence_is_refused_after_attacker_rehashes_every_receipt(self):
        selection, final, readback, frozen, expected = self.case()
        snapshot, _ = iteration.decode_native_learning_checkpoint(final)
        snapshot["receipts"][2]["evidence_digest"] = "ab" * 32
        with self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_EXACT_RECEIPT_PREFIX"):
            self.review(selection, rehash_mutation(snapshot), readback, frozen, expected)

    def test_final_journal_and_use_fields_must_match_original_actor_after_rehash(self):
        for phase in capture.ACKED:
            selection, final, readback, frozen, expected = self.case(phase)
            original, _ = iteration.decode_native_learning_checkpoint(final)
            for field in ("checkpoint_digest", "committed_step_receipt",
                          "task_owner_publication" if phase.startswith("retained") else "state_cutover_receipt"):
                with self.subTest(phase=phase, field=field):
                    snapshot = copy.deepcopy(original)
                    snapshot["receipts"][-1]["observation"][field] = "ab" * 32
                    with self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_ORIGINAL_NEXT_USE"):
                        self.review(selection, rehash_mutation(snapshot), readback, frozen, expected)

    def test_another_distinct_next_run_is_not_the_observed_original_run(self):
        selection, final, readback, frozen, expected = self.case()
        snapshot, _ = iteration.decode_native_learning_checkpoint(final)
        snapshot["receipts"][-1]["observation"]["state_partition"]["run_id"] = "unobserved-next-run"
        with self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_ORIGINAL_NEXT_USE"):
            self.review(selection, rehash_mutation(snapshot), readback, frozen, expected)

    def test_final_stage_still_requires_original_actor_predecessor_and_time(self):
        selection, final, readback, frozen, expected = self.case()
        original, _ = iteration.decode_native_learning_checkpoint(final)
        mutations = (("actor_id", "foreign-owner", "LEARNING_ACTOR"),
                     ("predecessor", "ab" * 32, "LEARNING_RECEIPT_PREDECESSOR"),
                     ("observed_unix_seconds", original["request"]["envelope"]["expiry_unix_seconds"], "LEARNING_RECEIPT_TIME"))
        for field, value, code in mutations:
            with self.subTest(field=field):
                snapshot = copy.deepcopy(original)
                snapshot["receipts"][-1][field] = value
                with self.assertRaisesRegex(native.ReadbackRefusal, code):
                    self.review(selection, mutated_encoding(snapshot), readback, frozen, expected)

    def test_completed_bytes_require_exact_pin_and_bounded_original_codec(self):
        selection, final, readback, frozen, expected = self.case()
        with self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_CHECKPOINT_PIN"):
            completion.review_native_learning_completion(selection, final, readback,
                expected_selection_sha256=native.sha(selection), expected_completed_sha256="ab" * 32,
                expected_readback_sha256=native.sha(readback), frozen=frozen, expected=expected)
        for raw in (bytearray(final), "text", b"x" * (iteration.MAX_CHECKPOINT + 1)):
            with self.subTest(kind=type(raw).__name__), self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_CHECKPOINT_LIMIT"):
                completion.review_native_learning_completion(selection, raw, readback,
                    expected_selection_sha256=native.sha(selection), expected_completed_sha256="ab" * 32,
                    expected_readback_sha256=native.sha(readback), frozen=frozen, expected=expected)
        for raw, code in ((final + b"\0", "LEARNING_CHECKPOINT_TRAILING_BYTES"),
                          (b"HEPLCP01" + final[8:], "LEARNING_CHECKPOINT_VERSION"),
                          (final[:-1], "LEARNING_CHECKPOINT_TRUNCATED")):
            with self.subTest(code=code), self.assertRaisesRegex(native.ReadbackRefusal, code):
                self.review(selection, raw, readback, frozen, expected)

    def test_extra_rehashed_next_use_cannot_complete_twice(self):
        selection, final, readback, frozen, expected = self.case("retained_acked")
        snapshot, _ = iteration.decode_native_learning_checkpoint(final)
        snapshot["receipts"].append(copy.deepcopy(snapshot["receipts"][-1]))
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_STAGE_ORDER|LEARNING_CHECKPOINT_RECEIPTS"):
            self.review(selection, rehash_mutation(snapshot), readback, frozen, expected)

    def test_cli_requires_all_five_materials_and_their_separate_pins(self):
        phase = "adopted_acked"
        cmd = [sys.executable, str(ROOT / "scripts/cell_learning_completion_join.py")]
        paths = {"selection-checkpoint": phase + ".selection.bin", "completed-checkpoint": phase + ".completed.bin",
                 "readback": phase + ".json", "freeze": phase + ".freeze.json", "expected": phase + ".expected.json"}
        for name, filename in paths.items():
            path = FIXTURES / filename
            cmd += ["--" + name, str(path), "--" + name + "-sha256", native.sha(path.read_bytes())]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.review(*self.case(phase)))
        for offset in range(2, len(cmd), 4):
            with self.subTest(argument=cmd[offset]):
                missing = cmd[:offset] + cmd[offset + 2:]
                refused = subprocess.run(missing, capture_output=True, timeout=20)
                self.assertNotEqual(refused.returncode, 0)

    def test_capture_refuses_missing_or_duplicate_native_completion(self):
        log = (FIXTURES / "native.stdout").read_bytes()
        point = self.manifest["exports"]["adopted_acked"]["captures"]["COMPLETION_V1"]
        prefix = b"HEPTA_LEARNING_COMPLETION_V1 adopted_acked "
        start, end = point["byte_offset"] - len(prefix), point["byte_offset"] + point["byte_length"]
        for changed, code in ((log[:start] + log[end + 1:], "CAPTURE_MISSING_EXPORT"),
                              (log + log[start:end] + b"\n", "CAPTURE_EXPORT_ROSTER")):
            with self.subTest(code=code), self.assertRaisesRegex(native.ReadbackRefusal, code):
                capture.capture(changed, self.manifest["native_source"])


if __name__ == "__main__":
    unittest.main()
