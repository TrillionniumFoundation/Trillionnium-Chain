#!/usr/bin/env python3
"""Adversarial controls for saved-proof observations, not new proof experiments."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import os
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("w1_transparent_compare", ROOT / "scripts/w1_transparent_compare.py")
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)
PACKET = ROOT / "evidence/pon-w1-complete-succinct-20261028"


class SavedProofComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assets = {name: compare.bounded_read(PACKET / "full-proof" / name, limit)
                      for name, limit in compare.ASSETS.items()}
        cls.identity = compare.validate_assets(cls.assets)
        with zipfile.ZipFile(PACKET / "runtime-records.zip") as archive:
            cls.native = compare.strict_json(archive.read(
                "raw/recovered-observation-and-gates/native-verifier-1000/stdout.log"))
            cls.verifier = compare.strict_json(archive.read(
                "raw/recovered-observation-and-gates/hardened-verifier-100/stdout.log"))

    def test_preserved_real_records_reconstruct_previous_failed_component_comparison(self):
        native = compare.validate_native(self.native, self.identity, historical=True)
        verifier = compare.validate_verifier(self.verifier, self.identity, historical=True)
        self.assertEqual(self.identity["work_id"],
                         "ccf544056c6df13a5ab4e6c021e587ff0008d92388270e64f72a6e2168a326cd")
        self.assertEqual(native["median_ns"], 554392.5)
        self.assertEqual(verifier["decode_and_verify"]["median_ns"], 16660953.0)
        self.assertGreater(verifier["decode_and_verify"]["median_ns"] / native["median_ns"], 30)
        self.assertEqual(len(self.assets["succinct.bin"]), 256886)

    def test_duplicate_keys_even_nested_or_escaped_are_rejected(self):
        for data in ['{"x":1,"x":1}', '{"x":{"x":1,"x":2}}', '{"x":1,"\\u0078":1}']:
            with self.subTest(data=data), self.assertRaises(compare.InvalidObservation):
                compare.strict_json(data)

    def test_nonfinite_json_and_overflow_cannot_enter_costs(self):
        for value in ["NaN", "Infinity", "-Infinity", "1e309", "-1e309"]:
            with self.subTest(value=value), self.assertRaises(compare.InvalidObservation):
                compare.strict_json('{"value":' + value + '}')

    def test_deep_json_is_controlled_rejection(self):
        with self.assertRaises(compare.InvalidObservation):
            compare.strict_json("[" * 10000 + "0" + "]" * 10000)

    def test_unbound_historical_native_report_is_not_a_live_observation(self):
        with self.assertRaises(compare.InvalidObservation):
            compare.validate_native(self.native, self.identity)

    def test_unbound_historical_verifier_is_not_a_live_observation(self):
        with self.assertRaises(compare.InvalidObservation):
            compare.validate_verifier(self.verifier, self.identity)

    def test_live_v2_schema_bindings_have_no_partial_or_unknown_profile_fallback(self):
        # Parser-only copies of historical samples; never emitted as fresh observations.
        native = copy.deepcopy(self.native)
        native.update(schema="trnm-w1-independent-native-cost-v2", work_id_hex=self.identity["work_id"],
                      header_sha256=self.identity["assets"]["header.bin"]["sha256"],
                      journal_sha256=self.identity["assets"]["expected-journal.bin"]["sha256"])
        verifier = copy.deepcopy(self.verifier)
        verifier.update(schema="TRNM-W1-HARDENED-FULL-VERIFY2", profile_id=compare.PROFILE_ID)
        compare.validate_native(native, self.identity)
        compare.validate_verifier(verifier, self.identity)
        for row, validator, key in [(native, compare.validate_native, "work_id_hex"),
                                     (native, compare.validate_native, "header_sha256"),
                                     (native, compare.validate_native, "journal_sha256"),
                                     (verifier, compare.validate_verifier, "profile_id")]:
            for value in [None, "", "0" * 64]:
                damaged = dict(row)
                damaged[key] = value
                with self.subTest(key=key), self.assertRaises(compare.InvalidObservation):
                    validator(damaged, self.identity)
            del damaged[key]
            with self.assertRaises(compare.InvalidObservation):
                validator(damaged, self.identity)

    def test_empty_zero_boolean_float_and_negative_samples_rejected(self):
        for value in [[], [0] * 1000, [True] * 1000, [1.0] * 1000, [-1] * 1000, [1 << 80] * 1000]:
            row = copy.deepcopy(self.native)
            row["native_full_verifier_ns"] = value
            with self.subTest(sample=str(value[:1])), self.assertRaises(compare.InvalidObservation):
                compare.validate_native(row, self.identity, historical=True)
        for value in [[], [0], [True], [1.0], [-1]]:
            with self.assertRaises(compare.InvalidObservation):
                compare.statistics_ns(value)

    def test_missing_unknown_and_wrong_versions_rejected(self):
        for kind in ["missing", "unknown", "schema"]:
            for original, validator in [(self.native, lambda row, identity: compare.validate_native(row, identity, historical=True)),
                                        (self.verifier, lambda row, identity: compare.validate_verifier(row, identity, historical=True))]:
                row = copy.deepcopy(original)
                if kind == "missing":
                    del row["schema"]
                elif kind == "unknown":
                    row["qualified"] = True
                else:
                    row["schema"] += "-next"
                with self.subTest(kind=kind), self.assertRaises(compare.InvalidObservation):
                    validator(row, self.identity)

    def test_input_source_and_statement_tampering_rejected(self):
        for name, offset in [("header.bin", 6), ("input.bin", 318 + 4),
                             ("expected-journal.bin", 19 + 318 + 64),
                             ("guest.bin", 1)]:
            assets = dict(self.assets)
            data = bytearray(assets[name])
            data[offset] ^= 1
            assets[name] = bytes(data)
            with self.subTest(name=name), self.assertRaises(compare.InvalidObservation):
                compare.validate_assets(assets)

    def test_complete_product_and_canonical_field_are_checked(self):
        for word in [compare.MODULUS, (1 << 32) - 1]:
            assets = dict(self.assets)
            data = bytearray(assets["input.bin"])
            data[318 + 4:318 + 8] = word.to_bytes(4, "little")
            assets["input.bin"] = bytes(data)
            with self.assertRaisesRegex(compare.InvalidObservation, "noncanonical"):
                compare.validate_assets(assets)
        assets = dict(self.assets)
        data = bytearray(assets["expected-journal.bin"])
        data[-4] ^= 1
        assets["expected-journal.bin"] = bytes(data)
        with self.assertRaisesRegex(compare.InvalidObservation, "complete product"):
            compare.validate_assets(assets)

    def test_encoding_alternatives_and_lengths_are_not_new_work(self):
        for tag in [0, 2, 3, (1 << 32) - 1]:
            assets = dict(self.assets)
            assets["succinct.bin"] = tag.to_bytes(4, "little") + assets["succinct.bin"][4:]
            with self.assertRaisesRegex(compare.InvalidObservation, "Succinct"):
                compare.validate_assets(assets)
        for name in ["header.bin", "input.bin", "expected-journal.bin"]:
            for delta in [-1, 1]:
                assets = dict(self.assets)
                assets[name] = assets[name][:-1] if delta < 0 else assets[name] + b"\0"
                with self.assertRaises(compare.InvalidObservation):
                    compare.validate_assets(assets)

    def test_zero_target_is_not_accepted(self):
        assets = dict(self.assets)
        header = bytearray(assets["header.bin"])
        header[118:150] = bytes(32)
        assets["header.bin"] = bytes(header)
        assets["input.bin"] = bytes(header) + assets["input.bin"][318:]
        offset = len(compare.DOMAIN)
        journal = bytearray(assets["expected-journal.bin"])
        journal[offset:offset + 318] = header
        assets["expected-journal.bin"] = bytes(journal)
        with self.assertRaisesRegex(compare.InvalidObservation, "ticket target"):
            compare.validate_assets(assets)

    def test_frozen_manifest_source_and_image_are_explicit(self):
        for key, value in [("source_commit", "0" * 40), ("image_id", [0] * 8),
                           ("guest_sha256", "0" * 64), ("schema", "other")]:
            assets = dict(self.assets)
            manifest = compare.strict_json(assets["manifest.json"])
            manifest[key] = value
            assets["manifest.json"] = json.dumps(manifest).encode()
            with self.subTest(key=key), self.assertRaises(compare.InvalidObservation):
                compare.validate_assets(assets)

    def test_nested_manifest_fields_and_types_are_rejected(self):
        for field, value in [("unknown", True), ("cycles", True), ("po2", 18.0),
                             ("index", 1), ("sha256", 1), ("bytes", 0)]:
            assets = dict(self.assets)
            manifest = compare.strict_json(assets["manifest.json"])
            manifest["segments"][0][field] = value
            assets["manifest.json"] = json.dumps(manifest).encode()
            with self.subTest(field=field), self.assertRaises(compare.InvalidObservation):
                compare.validate_assets(assets)

    def test_wrong_work_digest_or_reinterpreted_trial_count_rejected(self):
        for key, value in [("work_id", "0" * 64), ("receipt_sha256", "0" * 64),
                           ("header_sha256", "0" * 64), ("journal_sha256", "0" * 64),
                           ("independent_proof_trials", 100), ("proof_randomness_tickets", 1),
                           ("hash_function", "sha-256"), ("sdk", "3.0.3"),
                           ("control_id", "0" * 64), ("verifier_parameters_digest", "0" * 64),
                           ("production_tail_established", True), ("consensus_admission", True),
                           ("receipt_bytes", 1), ("seal_words", 0)]:
            row = copy.deepcopy(self.verifier)
            row[key] = value
            with self.subTest(key=key), self.assertRaises(compare.InvalidObservation):
                compare.validate_verifier(row, self.identity, historical=True)

    def test_boolean_and_float_counter_aliases_rejected(self):
        for key, value in [("independent_proof_trials", True), ("proof_randomness_tickets", False),
                           ("independent_proof_trials", 1.0), ("consensus_admission", 0)]:
            row = copy.deepcopy(self.verifier)
            row[key] = value
            with self.assertRaises(compare.InvalidObservation):
                compare.validate_verifier(row, self.identity, historical=True)

    def test_bounded_read_and_source_commit_format(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "oversized"
            path.write_bytes(b"abc")
            with self.assertRaises(compare.InvalidObservation):
                compare.bounded_read(path, 2)
            for commit in ["HEAD", "main", "-" * 40, "a" * 39]:
                with self.assertRaises(compare.InvalidObservation):
                    compare.source_identity(Path(temp), commit)

    def test_real_subprocess_nonzero_exit_preserves_stdout_and_status(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "failure"
            command = [sys.executable, "-c", "print('not a verification');raise SystemExit(7)"]
            result = compare.execute(command, directory, time.monotonic() + 5)
            self.assertEqual(result["returncode"], 7)
            self.assertEqual((directory / "stdout.log").read_text(), "not a verification\n")
            self.assertEqual(result["stdout_sha256"], compare.file_digest(directory / "stdout.log"))
            self.assertTrue((directory / "process.json").exists())

    def test_real_subprocess_timeout_is_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "timeout"
            result = compare.execute([sys.executable, "-c", "import time;time.sleep(60)"],
                                     directory, time.monotonic() + 1)
            self.assertEqual(result["termination_reason"], "TIMEOUT")
            self.assertNotEqual(result["returncode"], 0)
            self.assertLess(result["elapsed_wall_seconds"], 5)

    def test_reaped_completion_after_deadline_is_not_reported_as_on_time(self):
        real_sleep = time.sleep
        with tempfile.TemporaryDirectory() as temp, patch.object(
                compare.time, "sleep", side_effect=lambda _: real_sleep(4)):
            # The real child finishes between the deadline and our next poll.
            # We know when completion was observed, not its precise exit time.
            result = compare.execute([sys.executable, "-c", "import time;time.sleep(2.5)"],
                                     Path(temp) / "late", time.monotonic() + 2)
            self.assertEqual(result["returncode"], 0)
            self.assertEqual(result["termination_reason"],
                             "COMPLETION_NOT_OBSERVED_BEFORE_DEADLINE")
            self.assertGreaterEqual(result["elapsed_wall_seconds"], 2)

    def test_exit_zero_with_fake_accept_report_cannot_be_success(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            fake = temp / "fake-accept"
            fake.write_text("#!/bin/sh\nprintf '%s\\n' '{\"outcome\":\"ACCEPT\"}'\n")
            fake.chmod(0o755)
            pin = compare.file_digest(fake)
            env = {key: value for key, value in os.environ.items() if key not in compare.FORBIDDEN_ENV}
            source = {"commit": "a" * 40, "tree": "b" * 40, "elf_build_link": "negative control only"}
            with patch.dict(os.environ, env, clear=True), patch.object(compare, "source_identity", return_value=source), redirect_stdout(io.StringIO()):
                result = compare.main(["--proof-dir", str(PACKET / "full-proof"),
                                       "--native", str(fake), "--verifier", str(fake),
                                       "--native-sha256", pin, "--verifier-sha256", pin,
                                       "--native-source-commit", "a" * 40,
                                       "--verifier-source-commit", "a" * 40,
                                       "--out", str(temp / "run"), "--total-wall-seconds", "10"])
            self.assertEqual(result, 2)
            report = compare.strict_json((temp / "run/result.json").read_bytes())
            self.assertEqual(report["outcome"], "INCOMPLETE")
            self.assertEqual(report["stages"]["native"]["returncode"], 0)
            self.assertEqual(report["stages"]["transparent"]["returncode"], 0)
            self.assertIsNone(report["prover_cost"])
            self.assertIsNone(report["independent_confirmation_latency"])
            self.assertFalse(report["consensus_admission"])
            self.assertNotIn("selected_components_improve", report)

    def test_output_overflow_and_exhausted_deadline_are_failures(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(compare, "MAX_LOG_BYTES", 64):
            directory = Path(temp) / "overflow"
            result = compare.execute([sys.executable, "-c", "print('x'*1024)"],
                                     directory, time.monotonic() + 5)
            self.assertEqual(result["termination_reason"], "OUTPUT_LIMIT")
            result = compare.execute([sys.executable, "-c", "raise SystemExit(0)"],
                                     Path(temp) / "expired", time.monotonic() - 1)
            self.assertIsNone(result["returncode"])
            self.assertTrue(result["termination_reason"].startswith("INTERRUPTED_OR_NOT_STARTED"))

    def test_final_acceptance_deadline_keeps_successful_stage_facts(self):
        # Control-flow fixtures only. No fake report is a fresh proof observation.
        native = dict(self.native, schema="trnm-w1-independent-native-cost-v2",
                      work_id_hex=self.identity["work_id"],
                      header_sha256=self.identity["assets"]["header.bin"]["sha256"],
                      journal_sha256=self.identity["assets"]["expected-journal.bin"]["sha256"])
        verifier = dict(self.verifier, schema="TRNM-W1-HARDENED-FULL-VERIFY2",
                        profile_id=compare.PROFILE_ID)
        real_clock, real_validator = time.monotonic, compare.validate_verifier
        expired = False

        def stage(command, directory, deadline):
            directory.mkdir()
            row = native if directory.name == "native" else verifier
            (directory / "stdout.log").write_text(json.dumps(row))
            return {"returncode": 0, "termination_reason": None}

        def final_validation(row, identity):
            nonlocal expired
            result = real_validator(row, identity)
            expired = True
            return result

        with tempfile.TemporaryDirectory() as temp:
            executable = Path(sys.executable).resolve()
            pin = compare.file_digest(executable)
            env = {key: value for key, value in os.environ.items() if key not in compare.FORBIDDEN_ENV}
            with patch.dict(os.environ, env, clear=True), patch.object(compare, "source_identity", return_value={"fixture": True}), patch.object(compare, "execute", side_effect=stage), patch.object(compare, "validate_verifier", side_effect=final_validation), patch.object(compare.time, "monotonic", side_effect=lambda: real_clock() + (1000 if expired else 0)), redirect_stdout(io.StringIO()):
                result = compare.main(["--proof-dir", str(PACKET / "full-proof"),
                                       "--native", str(executable), "--verifier", str(executable),
                                       "--native-sha256", pin, "--verifier-sha256", pin,
                                       "--native-source-commit", "a" * 40,
                                       "--verifier-source-commit", "a" * 40,
                                       "--out", str(Path(temp) / "run")])
            report = compare.strict_json((Path(temp) / "run/result.json").read_bytes())
            self.assertEqual(result, 2)
            self.assertEqual(report["outcome"], "INCOMPLETE")
            self.assertIn("COMPARISON_ACCEPTANCE_NOT_OBSERVED_BEFORE_DEADLINE", report["error"])
            for row in report["stages"].values():
                self.assertEqual(row["returncode"], 0)
                self.assertIsNone(row["termination_reason"])
            self.assertEqual(report["fixed_input_native"]["n"], 1000)


if __name__ == "__main__":
    unittest.main()
