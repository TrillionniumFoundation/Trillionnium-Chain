#!/usr/bin/env python3
"""Attack retained real ABBA records; no verifier stand-in or new proof claim.

The positive inputs are the 80 original measured rows in the independently pinned
Nov07 archive. These tests re-read evidence; they perform zero cryptographic
verifications, proof generations, Node admissions, or resource settlements.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "comparison", ROOT / "scripts/run_w1_deployment_comparison.py")
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)
ARCHIVE = ROOT / "evidence/pon-w1-fresh-runtime-20261107/cost-common-rayon2/raw.tar.gz"
ARCHIVE_SHA256 = "299900afbae0e1849bc79d0122e34b065d324bb5e1119a2b49a346d9b595f6fb"


class RetainedVerifierEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ARCHIVE.open("rb") as source:
            raw = source.read((2 << 20) + 1)
        if len(raw) > 2 << 20 or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
            raise ValueError("retained real evidence archive changed")
        cls.arms = []
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            names = archive.getnames()
            if len(names) != len(set(names)):
                raise ValueError("duplicate retained archive name")
            def member(name):
                item = archive.getmember(name)
                if not item.isfile() or not 0 <= item.size <= 1 << 20:
                    raise ValueError("unbounded/nonregular retained observation")
                value = archive.extractfile(item).read(item.size + 1)
                if len(value) != item.size:
                    raise ValueError("incomplete retained observation")
                return value
            for index in (1, 2):
                base = f"common-rayon2-abba-A-01/generation-arm-{index}/"
                report = json.loads(member(base + "result.json"))
                observations = []
                for row in report["rows"]:
                    path = base + f"row-{row['index']:04d}-{row['kind']}/stdout.log"
                    observations.append((copy.deepcopy(row), member(path)))
                cls.arms.append((report, observations))
        row, raw = cls.arms[0][1][1]
        cls.stage = row["stage"]
        cls.proof = json.loads(raw)
        cls.stdout = raw
        cls.identities = cls.arms[0][0]["identities"]

    def validate(self, value=None, stage=None, kind="proof", identities=None):
        return comparison.validate_observation(
            kind, copy.deepcopy(self.stage if stage is None else stage),
            copy.deepcopy(self.proof if value is None else value),
            dict(self.identities) if identities is None else identities, None)

    def test_all_80_real_rows_bind_exact_stdout_and_remain_replays(self):
        total = 0
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stdout.log"
            for report, rows in self.arms:
                self.assertEqual(report["planned_order"], comparison.plan(10))
                self.assertEqual(len(rows), 40)
                self.assertEqual(report["fresh_proof_generations"], 0)
                identities = dict(report["identities"])
                work = None
                for row, raw in rows:
                    self.assertIs(row["accepted"], True)
                    path.write_bytes(raw)
                    value = comparison.read_verifier_report(path, row["stage"])
                    work, duration = comparison.validate_observation(
                        row["kind"], row["stage"], value, identities, work)
                    self.assertEqual(duration, row["inner_ns"])
                    total += 1
        self.assertEqual(total, 80)

    def test_rewritten_inner_timing_cannot_reuse_observer_stdout_commitment(self):
        forged = dict(self.proof, decode_and_verify_ns=[1])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stdout.log"
            path.write_text(json.dumps(forged))
            with self.assertRaisesRegex(ValueError, "differs from measured bytes"):
                comparison.read_verifier_report(path, self.stage)

    def test_missing_or_malformed_stdout_commitment_is_not_unpinned_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stdout.log"
            path.write_bytes(self.stdout)
            for digest in (None, True, 0, "", "a" * 63, "A" * 64, "g" * 64):
                with self.subTest(digest=digest), self.assertRaises(ValueError):
                    comparison.read_verifier_report(path, dict(self.stage, stdout_sha256=digest))
            stage = dict(self.stage)
            del stage["stdout_sha256"]
            with self.assertRaises(ValueError):
                comparison.read_verifier_report(path, stage)

    def test_boolean_and_float_proof_cardinality_are_rejected(self):
        for count in (True, 1.0, False, 0, 2, "1", None):
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.validate(value=dict(self.proof, independent_proof_trials=count))

    def test_boolean_and_float_exit_status_are_rejected(self):
        for status in (False, 0.0, True, "0", None):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.validate(stage=dict(self.stage, returncode=status))

    def test_unknown_row_kind_is_not_a_proof_row(self):
        for kind in ("", "transparent", "PROOF", None, 0):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(kind=kind)

    def test_rejected_receipt_and_timing_cannot_seed_journal_identity(self):
        for value in (dict(self.proof, receipt_sha256="00" * 32),
                      dict(self.proof, decode_and_verify_ns=[True]),
                      dict(self.proof, decode_and_verify_ns=[0])):
            identities = {k: v for k, v in self.identities.items() if k != "journal_sha256"}
            before = dict(identities)
            with self.assertRaises(ValueError):
                self.validate(value=value, identities=identities)
            self.assertEqual(identities, before)

    def test_invalid_wall_and_cpu_measurements_are_rejected_before_acceptance(self):
        for value in (True, False, "0.1", None, -1, float("nan"), float("inf"), 10 ** 400):
            for key in ("wall_seconds", "user_seconds", "system_seconds"):
                stage = copy.deepcopy(self.stage)
                if key == "wall_seconds":
                    stage[key] = value
                else:
                    stage["rusage"][key] = value
                with self.subTest(key=key, value=str(value)), self.assertRaises(ValueError):
                    self.validate(stage=stage)
        with self.assertRaises(ValueError):
            self.validate(stage=dict(self.stage, wall_seconds=0))

    def test_boolean_time_arguments_fail_before_dispatch_and_output_creation(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        import run_w1_receiver as receiver
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for entry in (comparison.execute, receiver.execute):
                for change in ({"wall_seconds": True}, {"wall_seconds": False},
                               {"deadline_monotonic": True}, {"deadline_monotonic": False}):
                    arguments = dict(wall_seconds=60., deadline_monotonic=None, deadline_boot_id=None,
                                     repeats=1, out=base / "not-created")
                    arguments.update(change)
                    with self.subTest(entry=entry.__module__, change=change), self.assertRaises(ValueError):
                        entry(argparse.Namespace(**arguments))
                    self.assertFalse(arguments["out"].exists())

    def test_timeout_flags_and_stage_time_types_cannot_contradict_completion(self):
        changes = [{"timed_out": True}, {"completion_observed_before_deadline": False},
                   {"started_monotonic": True}, {"effective_deadline_monotonic": True},
                   {"effective_deadline_monotonic": self.stage["started_monotonic"] + self.stage["wall_seconds"]}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(stage=dict(self.stage, **change))

    def test_regular_symlink_is_preserved_but_fifo_cannot_block_json_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            regular = base / "regular.json"
            regular.write_bytes(b'{"x":1}')
            link = base / "regular-link.json"
            link.symlink_to(regular)
            self.assertEqual(comparison.read_json(link), {"x": 1})
            fifo = base / "fifo"
            os.mkfifo(fifo)
            fifo_link = base / "fifo-link"
            fifo_link.symlink_to(fifo)
            command = ("import sys;sys.path.insert(0,sys.argv[1]);"
                       "import run_w1_deployment_comparison as m;"
                       "\ntry:m.read_json(sys.argv[2])"
                       "\nexcept ValueError:sys.exit(0)"
                       "\nelse:sys.exit(1)")
            for path in (fifo, fifo_link):
                observed = subprocess.run([sys.executable, "-c", command, str(ROOT / "scripts"), str(path)],
                                          capture_output=True, text=True, timeout=2)
                self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_utf16_duplicate_keys_and_overflow_numbers_are_rejected(self):
        invalid = [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                   b'{"x":1e400}', b'{"x":-1e400}', '{"x":1}'.encode("utf-16")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for raw in invalid:
                path.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    comparison.read_json(path)


if __name__ == "__main__":
    unittest.main()
