#!/usr/bin/env python3
"""Real fixed-image receipt and signal controls; no successful verifier stand-in.

All inputs and the verifier are explicit. The test leaves every positive and
negative observation under --out. Reusing this receipt produces zero fresh proofs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import run_w1_deployment_comparison as comparison
import run_w1_receiver as receiver

OPTIONS = None


class RealReceiverControls(unittest.TestCase):
    def setUp(self):
        self.directory = OPTIONS.out / self._testMethodName
        self.directory.mkdir()

    def arguments(self, **changes):
        values = dict(verifier=OPTIONS.verifier, verifier_sha256=OPTIONS.verifier_sha256,
                      receipt=OPTIONS.receipt, header=OPTIONS.header,
                      expected_artifacts=OPTIONS.expected_artifacts, out=self.directory / "receiver",
                      wall_seconds=60., deadline_monotonic=time.monotonic() + 60,
                      deadline_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        values.update(changes)
        return argparse.Namespace(**values)

    def test_actual_fixed_image_receipt_produces_bound_ack(self):
        args = self.arguments()
        with receiver.measure.cancel_on_signals():
            result = receiver.execute(args)
        self.assertIs(result["verified"], True)
        self.assertIs(result["receiver_operation_complete"], True)
        self.assertIs(result["admission_authorized"], False)
        self.assertEqual(result["verifier_report"]["iterations"], 1)
        self.assertEqual(result["receipt_sha256"], hashlib.sha256(OPTIONS.receipt.read_bytes()).hexdigest())
        self.assertTrue((args.out / "ack.json").is_file())

    def test_actual_corrupted_receipt_cannot_create_ack(self):
        raw = bytearray(OPTIONS.receipt.read_bytes())
        self.assertGreater(len(raw), 64)
        raw[len(raw) // 2] ^= 1
        bad = self.directory / "corrupted-receipt.bin"
        bad.write_bytes(raw)
        args = self.arguments(receipt=bad)
        with receiver.measure.cancel_on_signals(), self.assertRaises(Exception):
            receiver.execute(args)
        self.assertFalse((args.out / "ack.json").exists())
        self.assertIs(comparison.read_json(args.out / "failure.json")["verified"], False)

    def test_actual_wrong_external_artifacts_cannot_create_ack(self):
        raw = bytearray(OPTIONS.expected_artifacts.read_bytes())
        raw[0] ^= 1
        bad = self.directory / "wrong-artifacts.bin"
        bad.write_bytes(raw)
        args = self.arguments(expected_artifacts=bad)
        with receiver.measure.cancel_on_signals(), self.assertRaises(Exception):
            receiver.execute(args)
        self.assertFalse((args.out / "ack.json").exists())
        self.assertIs(comparison.read_json(args.out / "failure.json")["verified"], False)

    def test_actual_post_ack_sigterm_retains_fact_and_vetoes_operation(self):
        args = self.arguments()
        original = receiver.measure.write_new
        observed = []
        def save_then_signal(path, value):
            original(path, value)
            if path == args.out / "ack.json":
                observed.append(receiver.measure.sha(path))
                os.kill(os.getpid(), signal.SIGTERM)
        with receiver.measure.cancel_on_signals(), patch.object(receiver.measure, "write_new", save_then_signal):
            with self.assertRaises(receiver.measure.Canceled) as canceled:
                receiver.execute(args)
        self.assertEqual(canceled.exception.signum, signal.SIGTERM)
        self.assertEqual(observed, [receiver.measure.sha(args.out / "ack.json")])
        self.assertIs(comparison.read_json(args.out / "ack.json")["verified"], True)
        self.assertTrue((args.out / "operation-cancellation.json").is_file())

    def test_actual_post_ack_cancel_survives_sidecar_io_error(self):
        args = self.arguments()
        original = receiver.measure.write_new
        observed = []
        def save_and_inject_real_io(path, value):
            if path == args.out / "operation-cancellation.json":
                path.mkdir()
            original(path, value)
            if path == args.out / "ack.json":
                observed.append(receiver.measure.sha(path))
                os.kill(os.getpid(), signal.SIGTERM)
        with receiver.measure.cancel_on_signals(), patch.object(receiver.measure, "write_new", save_and_inject_real_io):
            with self.assertRaises(receiver.measure.Canceled) as canceled:
                receiver.execute(args)
        self.assertEqual(canceled.exception.signum, signal.SIGTERM)
        self.assertEqual(observed, [receiver.measure.sha(args.out / "ack.json")])
        self.assertTrue((args.out / "operation-cancellation.json").is_dir())
        self.assertIsInstance(canceled.exception.__cause__, OSError)

    def test_actual_final_abba_row_cancel_cannot_publish_success(self):
        args = self.arguments(out=self.directory / "comparison")
        args.input, args.repeats = OPTIONS.input, 1
        original = comparison.measure.write_new
        def save_then_signal(path, value):
            original(path, value)
            if path == args.out / "row-0003-observation.json":
                os.kill(os.getpid(), signal.SIGTERM)
        with comparison.measure.cancel_on_signals(), patch.object(comparison.measure, "write_new", save_then_signal):
            with self.assertRaises(comparison.measure.Canceled) as canceled:
                comparison.execute(args)
        self.assertEqual(canceled.exception.signum, signal.SIGTERM)
        report = comparison.read_json(args.out / "result.json")
        self.assertEqual([r["kind"] for r in report["rows"]], ["native", "proof", "proof", "native"])
        self.assertTrue(all(r["accepted"] for r in report["rows"]))
        self.assertIs(report["operation_complete"], False)
        self.assertIsNone(report["cost_comparison"])
        self.assertEqual(report["fresh_proof_generations"], 0)
        self.assertTrue((args.out / "operation-cancellation.json").is_file())

    def test_expired_original_deadline_never_starts_verifier(self):
        args = self.arguments(deadline_monotonic=time.monotonic() - 1)
        with receiver.measure.cancel_on_signals(), self.assertRaises(TimeoutError):
            receiver.execute(args)
        report = comparison.read_json(args.out / "failure.json")
        self.assertIsNone(report["stage"]["pid"])
        self.assertIs(report["verified"], False)
        self.assertIs(report["deadline_exhausted_at_snapshot"], True)
        self.assertFalse((args.out / "ack.json").exists())


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("verifier", "receipt", "input", "header", "expected-artifacts", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--verifier-sha256", required=True)
    OPTIONS = parser.parse_args()
    for name in ("verifier", "receipt", "input", "header", "expected_artifacts"):
        setattr(OPTIONS, name, getattr(OPTIONS, name).resolve(strict=True))
    if receiver.measure.sha(OPTIONS.verifier) != OPTIONS.verifier_sha256:
        raise ValueError("qualified verifier digest mismatch before real controls")
    OPTIONS.out = OPTIONS.out.resolve()
    OPTIONS.out.mkdir(parents=True, exist_ok=False)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RealReceiverControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {"schema": "TRNM-W1-REAL-RECEIVER-CONTROLS1", "tests_run": result.testsRun,
               "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
               "actual_complete_receipt_used": True, "fresh_proof_generations": 0,
               "verifier_sha256": OPTIONS.verifier_sha256,
               "receipt_sha256": receiver.measure.sha(OPTIONS.receipt),
               "result": "PASS" if result.wasSuccessful() and result.testsRun == 7 and not result.skipped else "FAIL"}
    receiver.measure.write_new(OPTIONS.out / "summary.json", summary)
    return 0 if summary["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
