#!/usr/bin/env python3
"""Synthetic reader/source/cost controls; these do not execute native Rust."""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_bound_primitive_engineering as gate

SOURCE = "a" * 40


def harness(names):
    return (f"running {len(names)} tests\n"
            + "".join(f"test {name} ... ok\n" for name in names)
            + f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.01s\n").encode()


class EngineeringControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        (self.root / "trillionnium").mkdir(parents=True)
        self.lock = self.root / "trillionnium/Cargo.lock"
        self.lock.write_bytes(b"synthetic reader fixture, never passed to Cargo\n")
        self.output = Path(self.temp.name) / "observation"
        self.identity = {"tested_commit": SOURCE, "tracked_entries": 1}

    def execute(self, *, first_raw=None, first_code=0, first_error=None,
                source_error=None, after=None, change_lock=False):
        calls = []
        def observed(argv, log, **options):
            calls.append((argv, options))
            names = (gate.NAMESPACE,) if len(calls) == 1 else gate.NOISE
            raw = first_raw if len(calls) == 1 and first_raw is not None else harness(names)
            log.write_bytes(raw)
            if len(calls) == 1 and first_error:
                raise first_error
            if len(calls) == 2 and change_lock:
                self.lock.write_bytes(b"changed lock\n")
            return {"exit_code": first_code if len(calls) == 1 else 0,
                    "executed": True, "timed_out": first_code == 124,
                    "source_verified": True}
        verification = source_error or [self.identity, after or self.identity]
        with patch.object(gate, "ROOT", self.root), \
             patch.object(gate, "verify", side_effect=verification), \
             patch.object(gate, "run_observed", side_effect=observed), \
             redirect_stdout(io.StringIO()):
            code = gate.execute(self.output, SOURCE)
        return code, json.loads((self.output / "summary.json").read_text()), calls

    def test_offline_default_profile_has_one_exact_namespace_and_three_noise_tests(self):
        suites = gate.suites()
        self.assertEqual([len(expected) for _, _, expected in suites], [1, 3])
        self.assertIn("--exact", suites[0][1])
        for _, argv, _ in suites:
            self.assertIn("--offline", argv)
            self.assertIn("--locked", argv)
            self.assertNotIn("--all-features", argv)
            self.assertNotIn("--features", argv)

    def test_named_successes_retain_source_lock_full_logs_and_nested_cost(self):
        code, report, calls = self.execute()
        self.assertEqual(code, 0)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(sum(x["observation"]["passed"] for x in report["commands"]), 4)
        self.assertEqual(report["source_before"], report["source_after"])
        self.assertEqual(report["lock_sha256_before"], report["lock_sha256_after"])
        self.assertTrue(report["command_costs_nested_in_inclusive_total"])
        self.assertFalse(report["pressure_qualified"])
        for row, (_, options) in zip(report["commands"], calls):
            raw = (self.output / row["log"]).read_bytes()
            self.assertEqual(row["log_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(options["expected_source"], SOURCE)
            self.assertEqual(options["timeout"], gate.COMMAND_SECONDS)
            self.assertGreaterEqual(row["elapsed_ns"], 0)
            self.assertTrue(all(value >= 0 for value in row["cpu"].values()))

    def test_empty_wrong_duplicate_ignored_and_non_utf8_results_never_pass(self):
        required = harness((gate.NAMESPACE,))
        cases = [harness(()), harness(("different::namespace",)),
                 harness((gate.NAMESPACE, gate.NAMESPACE)),
                 required.replace(b" ... ok", b" ... ignored"),
                 required + b"\xff"]
        for index, raw in enumerate(cases):
            with self.subTest(index=index):
                self.output = Path(self.temp.name) / f"case-{index}"
                code, report, calls = self.execute(first_raw=raw)
                self.assertEqual(code, 1)
                self.assertEqual(len(calls), 2)
                self.assertIsNotNone(report["commands"][0]["error"])
                self.assertEqual(report["commands"][1]["observation"]["passed"], 3)

    def test_nonzero_and_timeout_keep_failure_even_with_success_shaped_log(self):
        for exit_code in (101, 124):
            with self.subTest(exit_code=exit_code):
                self.output = Path(self.temp.name) / f"exit-{exit_code}"
                code, report, calls = self.execute(first_code=exit_code)
                self.assertEqual(code, 1)
                self.assertEqual(len(calls), 2)
                self.assertEqual(report["commands"][0]["execution"]["exit_code"], exit_code)
                self.assertIsNotNone(report["commands"][0]["error"])

    def test_source_drift_after_commands_cannot_pass(self):
        code, report, _ = self.execute(after={"tested_commit": "b" * 40})
        self.assertEqual(code, 1)
        self.assertNotEqual(report["source_before"], report["source_after"])

    def test_lock_drift_cannot_pass_even_if_source_receipt_were_unchanged(self):
        code, report, _ = self.execute(change_lock=True)
        self.assertEqual(code, 1)
        self.assertNotEqual(report["lock_sha256_before"], report["lock_sha256_after"])

    def test_source_refusal_executes_no_cargo_and_keeps_cost_and_failure(self):
        code, report, calls = self.execute(source_error=ValueError("SOURCE_MOVED"))
        self.assertEqual(code, 1)
        self.assertEqual(calls, [])
        self.assertEqual(report["error"]["message"], "SOURCE_MOVED")
        self.assertIn("cpu", report)

    def test_unavailable_cargo_preserves_error_and_still_observes_second_group(self):
        code, report, calls = self.execute(first_error=FileNotFoundError("cargo unavailable"))
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(report["commands"][0]["error"]["type"], "FileNotFoundError")
        self.assertEqual(report["commands"][1]["observation"]["passed"], 3)

    def test_existing_directory_cannot_relabel_a_previous_observation(self):
        self.output.mkdir()
        previous = self.output / "summary.json"
        previous.write_bytes(b"original failed observation\n")
        with patch.object(gate, "ROOT", self.root), self.assertRaises(FileExistsError):
            gate.execute(self.output, SOURCE)
        self.assertEqual(previous.read_bytes(), b"original failed observation\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
