#!/usr/bin/env python3
"""Adversarial accounting tests on the actual retained proof observations."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('disposition', ROOT / 'scripts/read_w1_full_v2_disposition.py')
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class DispositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.values = reader.pinned_inputs(ROOT)
        cls.raw = reader.observation_files(cls.values[reader.PROOF + 'observation-3.tar.gz'],
                                           reader.strict_json(cls.values[reader.PROOF + 'raw-index.json']))
        cls.proof = reader.strict_json(cls.values[reader.PROOF + 'proof-result.json'])
        cls.controls = reader.strict_json(cls.values[reader.PROOF + 'controls-result.json'])
        cls.timeout = reader.strict_json(cls.values[reader.FAILED + 'summary.json'])
        cls.interrupted = reader.strict_json(cls.values[reader.INTERRUPTED])

    def evaluate(self, **changes):
        values = dict(report=self.proof, controls=self.controls, timeout=self.timeout,
                      interrupted=self.interrupted, raw=self.raw)
        values.update(changes)
        return reader.evaluate(**values)

    def test_actual_observation_is_complete_w1_but_all_product_gates_stay_closed(self):
        result = reader.analyze(ROOT)
        self.assertEqual(result['disposition'], 'HOLD_NO_GO')
        self.assertTrue(result['observed_complete_w1_v2_proof'])
        self.assertEqual(result['native_median_ns'], 954983.5)
        self.assertEqual(result['transparent_median_ns'], 28882359.5)
        self.assertEqual(result['fresh_proof_pipeline_seconds'], 6248.484106799)
        self.assertGreater(result['fresh_proof_to_original_deadline_ratio'], 1562)
        self.assertEqual(result['gates']['original_deadline_necessary_screen'], 'FAIL')
        self.assertEqual(result['gates']['same_receipt_verification_cost'], 'FAIL')
        self.assertEqual(result['gates']['local_envelope_cost'], 'FAIL')
        self.assertEqual(result['gates']['prover_p99'], 'UNKNOWN')
        self.assertFalse(result['ordinary_cell_relation_proven'])
        self.assertFalse(result['cryptographic_verification_performed_by_reader'])
        self.assertFalse(result['production_activation'])

    def test_original_timeout_and_unknown_are_kept_without_invented_complete_denominator(self):
        attempts = self.evaluate()['retained_attempts']
        self.assertEqual(attempts['complete_deadline_failure'], 1)
        self.assertEqual(attempts['interrupted_outcome'], 'UNKNOWN')
        self.assertFalse(attempts['attempt_population_complete'])
        self.assertIsNone(attempts['all_attempts_total_cost'])
        for value in ({}, dict(self.timeout, complete_proof_claim=True),
                      dict(self.timeout, total_wall_budget_seconds=7201)):
            with self.assertRaises((ValueError, KeyError)):
                self.evaluate(timeout=value)
        with self.assertRaises(ValueError):
            self.evaluate(interrupted=dict(self.interrupted, run_state_after_disconnect='SUCCESS'))

    def test_same_receipt_replays_never_become_new_independent_proofs(self):
        result = self.evaluate()
        self.assertEqual(result['same_receipt_replay_samples'], 100)
        self.assertEqual(result['independent_successful_proof_trials'], 1)
        self.assertEqual(result['new_proofs_generated'], 0)
        with self.assertRaises(ValueError):
            self.evaluate(report=dict(self.proof, independent_full_proof_trials_observed=100))

    def test_missing_or_duplicate_w1_stage_is_rejected(self):
        for stages in (self.proof['stages'][1:], self.proof['stages'][:-1],
                       self.proof['stages'][:10] + self.proof['stages'][9:]):
            with self.assertRaises(ValueError):
                self.evaluate(report=dict(self.proof, stages=stages))

    def test_segment_and_process_result_must_match_original_raw_records(self):
        value = copy.deepcopy(self.proof)
        value['manifest']['segments'].pop()
        with self.assertRaises(ValueError):
            self.evaluate(report=value)
        value = copy.deepcopy(self.proof)
        value['stages'][5]['result']['wall_seconds'] /= 2
        with self.assertRaises(ValueError):
            self.evaluate(report=value)

    def test_fastest_only_and_slow_native_baseline_substitution_rejected(self):
        for name in ('native', 'transparent'):
            value = copy.deepcopy(self.proof)
            value['benchmarks'][name]['samples_ns'] = [min(value['benchmarks'][name]['samples_ns'])]
            with self.assertRaises(ValueError):
                self.evaluate(report=value)
        value = copy.deepcopy(self.proof)
        value['benchmarks']['native']['samples_ns'] = [10**12] * 1000
        with self.assertRaises(ValueError):
            self.evaluate(report=value)

    def test_raw_public_material_or_trace_identity_substitution_rejected(self):
        for key in ('journal_sha256', 'expected_artifacts_sha256', 'receipt_sha256', 'work_id'):
            raw = dict(self.raw)
            path = 'fresh-process-strict-verification/stdout.log'
            value = reader.strict_json(raw[path])
            value[key] = '00' * 32
            raw[path] = json.dumps(value).encode()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.evaluate(raw=raw)

    def test_missing_negative_controls_and_boolean_counts_rejected(self):
        with self.assertRaises(ValueError):
            self.evaluate(controls=dict(self.controls, controls=self.controls['controls'][:-1]))
        with self.assertRaises(ValueError):
            self.evaluate(report=dict(self.proof, independent_full_proof_trials_observed=True))
        raw = dict(self.raw)
        path = 'fixed-receipt-verifier-cost/stdout.log'
        value = reader.strict_json(raw[path])
        value['decode_and_verify_ns'][0] = True
        raw[path] = json.dumps(value).encode()
        with self.assertRaises(ValueError):
            self.evaluate(raw=raw)

    def test_duplicate_json_keys_nan_and_infinity_rejected(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.assertRaises(ValueError):
                reader.strict_json(value)

    def test_altered_declaration_or_missing_failure_is_not_readback_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / reader.MANIFEST
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / reader.MANIFEST).read_bytes().replace(
                b'"original_confirmation_deadline_seconds": 4',
                b'"original_confirmation_deadline_seconds": 7200'))
            with self.assertRaises(ValueError):
                reader.pinned_inputs(root)
            target.write_bytes((ROOT / reader.MANIFEST).read_bytes())
            for relative, data in self.values.items():
                if relative == reader.FAILED + 'summary.json':
                    continue
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            with self.assertRaises(FileNotFoundError):
                reader.pinned_inputs(root)

    def test_nonregular_and_symlink_inputs_are_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                reader.read_regular(fifo, 10)
            source = root / 'source'
            source.write_bytes(b'123')
            link = root / 'link'
            link.symlink_to(source)
            with self.assertRaises(OSError):
                reader.read_regular(link, 10)
            with self.assertRaises(ValueError):
                reader.read_regular(source, 2)


if __name__ == '__main__':
    unittest.main()
