#!/usr/bin/env python3
"""Independent-replay controls; no Rust binary or new mining campaign is run."""
import copy
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import replay_ticket_first_w1_v1 as replay

# Actual A8018 CI x64 artifact 12872537004, gzip SHA af24dacf8909e2c3a8740ad8547b980ded5e79f58ba854d1b8a5def971dc5ed7.
# This nonce was a target miss. The complete scalar oracle must still evaluate it.
CHALLENGE = bytes.fromhex("9f82b0e33d052cb6f20b984cec632e0d02ec4bab11f350c08d42ccd9d648e78d")
TRACE = bytes.fromhex("cc74f2b77076ac5ab524e45f63f34b9b1b3d05f0ca4fddacdb70e5b8b90eedad")
FAKE = bytes.fromhex("b2ab289d5f54e1d801e75ba43cad99069cf9d65ddb65987c891904a314771351")


def state():
    return {"arithmetic_evaluations_started": 0, "arithmetic_evaluations_returned": 0,
            "inputs_verified": 0, "verified_partition": dict.fromkeys(replay.UNIQUE_PARTITION, 0),
            "inflight_input": None}


class IndependentReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, _, cls.task, cls.prefix = replay.material("continuity-maintenance-v1")
        cls.key = replay.input_key(cls.task, CHALLENGE, cls.prefix)

    def records(self, trace=TRACE):
        out = {}
        replay.retain(out, self.key, trace, "misses_before_winner", 12)
        return out

    def test_actual_recorded_native_miss_replays_full_arithmetic_without_target_precheck(self):
        target = bytes.fromhex("7f" + "ff" * 31)
        self.assertGreater(replay.work_oracle.H("ticket", CHALLENGE, TRACE), target)
        events, progress = [], state()
        replay.replay_inputs(self.records(), events.append, progress, time.monotonic() + 10)
        self.assertEqual(progress["inputs_verified"], 1)
        self.assertEqual(progress["verified_partition"]["misses_before_winner"], 1)
        self.assertTrue(events[1]["trace_matches"] and events[1]["product_matches"])

    def test_common_forged_miss_trace_is_rejected_after_full_scalar_replay(self):
        target = bytes.fromhex("7f" + "ff" * 31)
        self.assertGreater(replay.work_oracle.H("ticket", CHALLENGE, FAKE), target)
        events, progress = [], state()
        with self.assertRaisesRegex(ValueError, "TRACE_MISMATCH"):
            replay.replay_inputs(self.records(FAKE), events.append, progress, time.monotonic() + 10)
        self.assertEqual(progress["inputs_verified"], 0)
        self.assertEqual(progress["arithmetic_evaluations_returned"], 1)
        self.assertFalse(events[-1]["trace_matches"])
        self.assertEqual(events[-1]["actual_trace"], TRACE.hex())

    def test_full_prefix_in_key_prevents_reusing_success_for_changed_product(self):
        prefix = bytearray(self.prefix)
        offset = 4 + 2 * replay.work_oracle.CELLS * 4
        original = int.from_bytes(prefix[offset:offset + 4], "little")
        prefix[offset:offset + 4] = ((original + 1) % replay.work_oracle.Q).to_bytes(4, "little")
        other = replay.input_key(self.task, CHALLENGE, bytes(prefix))
        records = self.records()
        replay.retain(records, other, TRACE, "misses_before_winner", 12)
        self.assertEqual(len(records), 2)
        events, progress = [], state()
        with self.assertRaisesRegex(ValueError, "PRODUCT_MISMATCH"):
            replay.replay_inputs(records, events.append, progress, time.monotonic() + 10)
        self.assertEqual(progress["arithmetic_evaluations_returned"], 2)
        self.assertEqual(progress["inputs_verified"], 1)
        self.assertTrue(events[-1]["trace_matches"])
        self.assertFalse(events[-1]["product_matches"])

    def test_changed_challenge_cannot_reuse_a_verified_trace(self):
        records = self.records()
        other = replay.input_key(self.task, bytes(32), self.prefix)
        replay.retain(records, other, TRACE, "misses_before_winner", 12)
        progress = state()
        with self.assertRaisesRegex(ValueError, "TRACE_MISMATCH"):
            replay.replay_inputs(records, lambda _: None, progress, time.monotonic() + 10)
        self.assertEqual(progress["arithmetic_evaluations_returned"], 2)
        self.assertEqual(progress["inputs_verified"], 1)

    def test_task_and_noncanonical_prefixes_fail_before_arithmetic(self):
        invalid = [self.prefix[:-1], b"BAD!" + self.prefix[4:]]
        for offset in (4, 4 + 4096 * 4, 4 + 8192 * 4):
            value = bytearray(self.prefix)
            value[offset:offset + 4] = replay.work_oracle.Q.to_bytes(4, "little")
            invalid.append(bytes(value))
        with mock.patch.object(replay.work_oracle, "evaluate", side_effect=AssertionError("must not evaluate")):
            with self.assertRaisesRegex(ValueError, "task mismatch"):
                replay.decode_prefix(bytes(32), self.prefix)
            for prefix in invalid:
                with self.subTest(prefix_length=len(prefix)), self.assertRaises(ValueError):
                    replay.decode_prefix(self.task, prefix)

    def test_conflicting_trace_or_category_cannot_merge_with_same_exact_input(self):
        for trace, category in ((FAKE, "misses_before_winner"), (TRACE, "winning_trials")):
            with self.subTest(category=category), self.assertRaisesRegex(ValueError, "conflicting observation"):
                replay.retain(self.records(), self.key, trace, category)

    def test_complete_coverage_requires_each_miss_and_exhausted_input_and_all_repetitions(self):
        # Explicit synthetic coverage records, never treated as W1 evidence.
        records, ordinal = {}, 0
        for category, count in replay.UNIQUE_PARTITION.items():
            for _ in range(count):
                replay.retain(records, (b"task", ordinal.to_bytes(32, "little"), b"prefix"),
                              bytes(32), category, 12)
                ordinal += 1
        result = replay.coverage(records)
        self.assertEqual(result["unique_inputs"], 1367)
        self.assertEqual(result["observations"], 16404)
        exhausted = next(key for key, row in records.items() if row["category"] == "exhausted_search_trials")
        missing = copy.deepcopy(records)
        del missing[exhausted]
        with self.assertRaisesRegex(ValueError, "coverage"):
            replay.coverage(missing)
        short = copy.deepcopy(records)
        short[exhausted]["observations"] = 11
        with self.assertRaisesRegex(ValueError, "twelve"):
            replay.coverage(short)
        wrong = copy.deepcopy(records)
        wrong[exhausted]["category"] = "misses_before_winner"
        with self.assertRaisesRegex(ValueError, "coverage"):
            replay.coverage(wrong)

    def test_repeated_exact_input_shares_arithmetic_but_preserves_observation_count(self):
        records = self.records()
        replay.retain(records, self.key, TRACE, "misses_before_winner", 24)
        self.assertEqual(records[self.key]["observations"], 36)
        progress = state()
        replay.replay_inputs(records, lambda _: None, progress, time.monotonic() + 10)
        self.assertEqual(progress["arithmetic_evaluations_started"], 1)

    def test_deadline_keeps_completed_prefix_and_cannot_claim_remaining_inputs(self):
        records = self.records()
        replay.retain(records, replay.input_key(self.task, bytes(32), self.prefix),
                      TRACE, "misses_before_winner", 12)
        events, progress = [], state()
        with mock.patch.object(replay.time, "monotonic", side_effect=[1.0, 3.0]):
            with self.assertRaisesRegex(ValueError, "deadline"):
                replay.replay_inputs(records, events.append, progress, 2.0)
        self.assertEqual(progress["inputs_verified"], 1)
        self.assertEqual(progress["arithmetic_evaluations_started"], 1)
        self.assertEqual([e["kind"] for e in events], ["input-start", "input-result"])

    def test_failed_input_keeps_failed_receipt_and_existing_output_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "bad.json"
            manifest.write_text('{"schema": "wrong", "datasets": []}')
            output = root / "output"
            self.assertEqual(replay.run(manifest, output), 1)
            original = (output / "receipt.json").read_bytes()
            receipt = json.loads(original)
            self.assertEqual(receipt["status"], "failed")
            self.assertFalse(receipt["complete"])
            self.assertFalse(receipt["source_and_input_after_binding_complete"])
            self.assertFalse(receipt["boundaries"]["native_miner_cost_remeasured"])
            self.assertEqual(receipt["replay"]["arithmetic_evaluations_started"], 0)
            self.assertTrue((output / "replay.jsonl").read_bytes())
            with self.assertRaises(FileExistsError):
                replay.run(manifest, output)
            self.assertEqual((output / "receipt.json").read_bytes(), original)

    def deadline_pipeline_control(self, expire):
        """Mocked negative time-boundary control, never a successful replay."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "input.json"
            manifest.write_text("explicit synthetic deadline control\n")
            output = root / "output"
            clock, identity_calls = [0.0], [0]
            spec = {"label": "synthetic-boundary-control"}
            fingerprints = {"raw_gzip": {"sha256": "00" * 32}}
            records = self.records()

            def observed_files(_):
                identity_calls[0] += 1
                if expire == "final-hash" and identity_calls[0] == 2:
                    clock[0] = replay.DEADLINE_SECONDS + 1
                return fingerprints

            def collect(*_):
                if expire == "dataset-validation":
                    clock[0] = replay.DEADLINE_SECONDS + 1
                return records, {"observations": 12}

            def simulated_arithmetic(_records, _observe, progress, _deadline):
                # This only arranges a late failure in the surrounding wrapper.
                # The test never grants a successful arithmetic receipt.
                progress["inputs_verified"] = replay.UNIQUE_INPUTS
                progress["verified_partition"] = dict(replay.UNIQUE_PARTITION)

            with mock.patch.object(replay.time, "monotonic", side_effect=lambda: clock[0]), \
                 mock.patch.object(replay, "source_identity", return_value={"synthetic": "00" * 32}), \
                 mock.patch.object(replay, "parse_manifest", return_value=[spec]), \
                 mock.patch.object(replay, "dataset_identities", side_effect=observed_files), \
                 mock.patch.object(replay, "collect_dataset", side_effect=collect), \
                 mock.patch.object(replay, "replay_inputs", side_effect=simulated_arithmetic) as arithmetic:
                self.assertEqual(replay.run(manifest, output), 1)
            receipt = json.loads((output / "receipt.json").read_text())
            self.assertIn("deadline", receipt["error"]["message"])
            self.assertFalse(receipt["complete"])
            self.assertFalse(receipt["source_and_input_after_binding_complete"])
            self.assertEqual(arithmetic.call_count, int(expire == "final-hash"))

    def test_dataset_validation_cannot_overrun_deadline_and_start_arithmetic(self):
        self.deadline_pipeline_control("dataset-validation")

    def test_final_hash_overrun_cannot_grant_complete_receipt(self):
        self.deadline_pipeline_control("final-hash")

    def test_output_byte_limits_preserve_prefix_and_reserve_failure_terminal(self):
        stream = io.BytesIO()
        with self.assertRaisesRegex(ValueError, "line byte bound"):
            replay.journal_record(stream, {"kind": "input-result", "extra": "x" * 16384}, 0)
        self.assertEqual(stream.getvalue(), b"")
        with mock.patch.object(replay, "MAX_JOURNAL_BYTES", 2 * replay.MAX_JOURNAL_LINE_BYTES):
            used = replay.journal_record(stream, {"kind": "input-result", "extra": "x" * 8000}, 0)
            used = replay.journal_record(stream, {"kind": "input-result", "extra": "x" * 8000}, used)
            prefix = stream.getvalue()
            with self.assertRaisesRegex(ValueError, "total byte bound"):
                replay.journal_record(stream, {"kind": "input-start", "extra": "x" * 8000}, used)
            self.assertEqual(stream.getvalue(), prefix)
            final = replay.journal_record(stream, {"kind": "terminal", "status": "failed"}, used)
            self.assertEqual(final, len(stream.getvalue()))
            self.assertEqual(json.loads(stream.getvalue().splitlines()[-1])["status"], "failed")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(b"original receipt bytes\n")
            with mock.patch.object(replay, "MAX_RECEIPT_BYTES", 32):
                with self.assertRaisesRegex(ValueError, "receipt output byte bound"):
                    replay.write_json(path, {"extra": "x" * 1000})
                self.assertEqual(path.read_bytes(), b"original receipt bytes\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
