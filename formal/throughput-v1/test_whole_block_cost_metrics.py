#!/usr/bin/env python3
"""Protect the original sample census and the boundary between time and business."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import whole_block_cost_metrics as metrics


def fixture():
    rows = []
    for senders in (2, 64, 256):
        for pair in range(14):
            order = metrics.ARMS if pair % 2 == 0 else metrics.ARMS[::-1]
            for arm in order:
                reference = arm == metrics.ARMS[0]
                rows.append({
                    "schema": metrics.RAW_SCHEMA, "senders": senders, "pair": pair,
                    "transactions": 256, "workers": 4, "warmup": pair < 2,
                    "implementation": arm,
                    "wall_ns": 999_000 if pair < 2 else (200 if reference else 150),
                    "signature_verifications": 256, "speculative": 256 if reference else 1,
                    "reexecuted": 255 if reference else 0, "root": f"{senders:064x}",
                    "cpu_ns": None, "public_confirmation": False, "production_activation": False,
                })
    return rows


def stdout(rows):
    return (f"running 1 test\ntest {metrics.TEST_NAME} ... " +
            "\n".join(json.dumps(row) for row in rows) +
            "\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out; finished in 1.0s\n").encode()


def receipt(raw, stderr=b""):
    return {
        "name": "complete-block",
        "argv": ["/original/target/release/deps/trnm_mvcc_fee-test", metrics.TEST_NAME,
                 "--ignored", "--exact", "--nocapture", "--test-threads=1"],
        "cwd": "/original/checkout", "exit_code": 0, "waited_pid": 10, "wall_ns": 1_000_000_000,
        "disk_before": {"total_bytes": 100, "used_bytes": 40, "free_bytes": 60},
        "disk_after": {"total_bytes": 100, "used_bytes": 41, "free_bytes": 59},
        "extra_env": {}, "rusage": dict.fromkeys(metrics.RUSAGE_FIELDS, 0),
        "rusage_maxrss_unit": "KiB (Linux)", "stdout_sha256": hashlib.sha256(raw).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }


def check_receipt(value, raw, stderr=b""):
    encoded = json.dumps(value, sort_keys=True).encode()
    return metrics.process_receipt(encoded, hashlib.sha256(encoded).hexdigest(),
                                   stdout=raw, stderr=stderr, rows=metrics.parse_stdout(raw))


class CompleteBlockReadbackTests(unittest.TestCase):
    def project(self, rows):
        raw = stdout(rows)
        return metrics.summarize(metrics.parse_stdout(raw),
                                 original_stdout_sha256=hashlib.sha256(raw).hexdigest())

    def test_complete_census_keeps_warmups_but_not_in_wall_comparison(self):
        report = self.project(fixture())
        self.assertEqual(report["observed_records"], 84)
        self.assertEqual(report["retained_pairs"], 36)
        for cohort in report["cohorts"]:
            self.assertEqual(cohort["reference_wall_median_ns"], 200)
            self.assertEqual(cohort["candidate_wall_median_ns"], 150)
            self.assertEqual(cohort["wall_reduction_percent_from_medians"], 25)
            self.assertIsNone(cohort["cpu_reduction_percent"])
        self.assertIsNone(report["qualified_confirmed_tps"])
        self.assertIsNone(report["independently_accepted_useful_tasks_per_second"])
        self.assertIsNone(report["native_process_exit_code"])
        self.assertIsNone(report["native_process_success"])
        self.assertEqual(report["qualification"], "HOLD_NO_GO")

    def test_missing_warmup_or_measurement_is_not_a_smaller_success(self):
        for removed in (0, 6, 83):
            rows = fixture()
            del rows[removed]
            with self.assertRaises(metrics.InvalidObservation):
                self.project(rows)

    def test_duplicate_or_reordered_pair_cannot_cherry_pick(self):
        rows = fixture()
        rows[5] = copy.deepcopy(rows[4])
        with self.assertRaises(metrics.InvalidObservation):
            self.project(rows)
        rows = fixture()
        rows[4], rows[5] = rows[5], rows[4]
        with self.assertRaises(metrics.InvalidObservation):
            self.project(rows)

    def test_different_canonical_root_is_not_comparable(self):
        rows = fixture()
        rows[27]["root"] = "f" * 64
        with self.assertRaises(metrics.InvalidObservation):
            self.project(rows)

    def test_zero_missing_boolean_or_negative_time_is_not_observed_time(self):
        for value in (0, None, True, -1, "100"):
            rows = fixture()
            rows[0]["wall_ns"] = value
            with self.subTest(value=value), self.assertRaises(metrics.InvalidObservation):
                self.project(rows)

    def test_cpu_or_confirmation_claim_cannot_upgrade_v1(self):
        for key, value in (("cpu_ns", 0), ("cpu_ns", 100),
                           ("public_confirmation", True), ("production_activation", True),
                           ("public_confirmation", 0)):
            rows = fixture()
            rows[0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(metrics.InvalidObservation):
                self.project(rows)

    def test_changed_work_signature_or_warmup_is_rejected(self):
        for key, value in (("signature_verifications", 255), ("workers", 8),
                           ("transactions", 128), ("warmup", False), ("speculative", 1)):
            rows = fixture()
            rows[0][key] = value
            with self.subTest(key=key), self.assertRaises(metrics.InvalidObservation):
                self.project(rows)

    def test_failed_or_ignored_native_test_cannot_report_success(self):
        raw = stdout(fixture())
        for altered in (raw.replace(b"1 passed; 0 failed", b"0 passed; 1 failed"),
                        raw.replace(b"0 ignored", b"1 ignored"),
                        raw + b"test result: ok. 1 passed; 0 failed; 0 ignored;\n"):
            with self.assertRaises(metrics.InvalidObservation):
                metrics.parse_stdout(altered)

    def test_duplicate_json_keys_are_not_silently_overridden(self):
        raw = stdout(fixture()).replace(b'"cpu_ns": null', b'"cpu_ns": 99, "cpu_ns": null', 1)
        with self.assertRaises(metrics.InvalidObservation):
            metrics.parse_stdout(raw)

    def test_truncated_footer_or_terminal_newline_cannot_close_the_observation(self):
        raw = stdout(fixture())
        footer = raw.index(b"test result:")
        for altered in (raw[:footer] + b"test result: ok. 1 passed; 0 failed; 0 ignored;\n", raw[:-1]):
            with self.subTest(tail=altered[-80:]), self.assertRaises(metrics.InvalidObservation):
                metrics.parse_stdout(altered)

    def test_extra_process_error_or_other_test_identity_is_not_silently_discarded(self):
        raw = stdout(fixture())
        for altered in (raw + b"error: native process did not exit successfully\n",
                        raw.replace(metrics.TEST_NAME.encode(), b"another_test", 1),
                        raw.replace(b"running 1 test\n", b"running 0 tests\n", 1)):
            with self.assertRaises(metrics.InvalidObservation):
                metrics.parse_stdout(altered)

    def test_nonrecord_in_the_fixed_roster_is_not_filtered_out(self):
        raw = stdout(fixture()).replace(b"\nok\n", b"\nthread 'worker' panicked\nok\n", 1)
        with self.assertRaises(metrics.InvalidObservation):
            metrics.parse_stdout(raw)

    def test_impossible_rust_duration_and_oversized_logs_are_rejected(self):
        rows = fixture()
        rows[0]["wall_ns"] = 1 << 128
        with self.assertRaises(metrics.InvalidObservation):
            self.project(rows)
        with self.assertRaises(metrics.InvalidObservation):
            metrics.parse_stdout(b" " * (metrics.MAX_STDOUT_BYTES + 1))

    def test_exact_bytes_digest_is_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stdout.txt"
            raw = stdout(fixture())
            path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            receipt_path = Path(directory) / "command.json"
            encoded = json.dumps(receipt(raw), sort_keys=True).encode()
            receipt_path.write_bytes(encoded)
            stderr_path = Path(directory) / "stderr.txt"
            stderr_path.write_bytes(b"")
            kwargs = dict(receipt_path=receipt_path, expected_receipt_sha256=hashlib.sha256(encoded).hexdigest(),
                          stderr_path=stderr_path)
            report = metrics.read(path, digest, **kwargs)
            self.assertEqual(report["original_stdout_sha256"], digest)
            self.assertEqual(report["native_process_exit_code"], 0)
            self.assertFalse(report["native_origin_authenticated"])
            self.assertTrue(all(cohort["reference_cpu_ns"] is None for cohort in report["cohorts"]))
            path.write_bytes(raw + b"\n")
            with self.assertRaises(metrics.InvalidObservation):
                metrics.read(path, digest, **kwargs)

    def test_process_failure_or_different_command_cannot_reuse_successful_stdout(self):
        raw = stdout(fixture())
        for field, value in (("exit_code", 1), ("exit_code", False), ("name", "some-other-command"),
                             ("waited_pid", None), ("wall_ns", 1), ("extra_env", {"OTHER_PROFILE": "1"})):
            observation = receipt(raw)
            observation[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(metrics.InvalidObservation):
                check_receipt(observation, raw)
        for argv in (["/binary", metrics.TEST_NAME, "--include-ignored", "--exact", "--nocapture", "--test-threads=1"],
                     ["/binary", "another-test", "--ignored", "--exact", "--nocapture", "--test-threads=1"]):
            observation = receipt(raw)
            observation["argv"] = argv
            with self.assertRaises(metrics.InvalidObservation):
                check_receipt(observation, raw)

    def test_process_receipt_and_both_raw_streams_require_independent_byte_binding(self):
        raw = stdout(fixture())
        observation = receipt(raw)
        encoded = json.dumps(observation).encode()
        with self.assertRaisesRegex(metrics.InvalidObservation, "receipt SHA-256"):
            metrics.process_receipt(encoded, "0" * 64, stdout=raw, stderr=b"", rows=metrics.parse_stdout(raw))
        observation["stdout_sha256"] = "f" * 64
        with self.assertRaisesRegex(metrics.InvalidObservation, "byte binding"):
            check_receipt(observation, raw)
        observation = receipt(raw)
        with self.assertRaisesRegex(metrics.InvalidObservation, "byte binding"):
            check_receipt(observation, raw, b"diagnostic output\n")

    def test_stderr_error_and_nonfinite_whole_process_cpu_are_not_dropped(self):
        raw = stdout(fixture())
        stderr = b"thread worker panicked\n"
        with self.assertRaisesRegex(metrics.InvalidObservation, "empty stderr"):
            check_receipt(receipt(raw, stderr), raw, stderr)
        observation = receipt(raw)
        observation["rusage"]["ru_utime"] = float("inf")
        with self.assertRaises(metrics.InvalidObservation):
            check_receipt(observation, raw)


if __name__ == "__main__":
    unittest.main()
