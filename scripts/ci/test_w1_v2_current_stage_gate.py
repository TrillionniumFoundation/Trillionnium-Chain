#!/usr/bin/env python3
"""Current stage-v3 contract controls. Child programs are process fixtures, not proofs."""
from __future__ import annotations

from contextlib import redirect_stdout
import copy
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import w1_v2_controls_gate as gate

CURRENT = 'TRNM-W1-STAGE-MEASUREMENT3'
HISTORICAL = 'TRNM-W1-STAGE-MEASUREMENT2'
CURRENT_FIELDS = {
    'cancellation_schema': 'TRNM-W1-CANCELLATION-HANDOFF1',
    'result_is_pre_handoff_snapshot': True,
    'canceled_signal': None, 'cancellation_event': None,
    'deadline_exhausted_at_snapshot': False,
    'prover_resource_completeness_established': False,
    'complete_proof_claim': False,
}


class CurrentStageV3ControlsGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='w1-current-stage-contract-')
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        cls.positive = gate.controls.measure(
            [sys.executable, '-c', "print('process fixture; no proof claim')"],
            root / 'positive', 120)
        cls.negative = gate.controls.measure(
            [sys.executable, '-c', "raise SystemExit(7)"], root / 'negative', 120)

    def validate(self, row, code=0, schema=CURRENT):
        return gate.validate_process_observation(row, code, schema)

    def test_current_contract_accepts_actual_clean_process_observation(self):
        self.assertEqual(self.positive['schema'], CURRENT)
        self.assertEqual(gate.CURRENT_STAGE_SCHEMA, CURRENT)
        self.assertEqual(gate.HISTORICAL_STAGE_SCHEMA, HISTORICAL)
        self.validate(self.positive)

    def test_current_contract_accepts_actual_clean_expected_rejection(self):
        self.assertEqual(self.negative['returncode'], 7)
        self.assertIs(self.negative['stage_process_complete'], False)
        self.validate(self.negative, code=7)

    def test_current_contract_refuses_legacy_and_unknown_observations(self):
        for schema in (HISTORICAL, 'TRNM-W1-STAGE-MEASUREMENT4', None, 3):
            row = copy.deepcopy(self.positive)
            row['schema'] = schema
            with self.subTest(schema=schema), self.assertRaisesRegex(
                    ValueError, 'process observation differs: schema'):
                self.validate(row)

    def test_current_contract_requires_every_new_snapshot_field(self):
        for name in CURRENT_FIELDS:
            row = copy.deepcopy(self.positive)
            del row[name]
            with self.subTest(field=name), self.assertRaisesRegex(
                    ValueError, 'current process observation differs: ' + name):
                self.validate(row)

    def test_current_contract_refuses_snapshot_cancellation(self):
        for name, value in (('canceled_signal', 15), ('cancellation_event', {})):
            row = copy.deepcopy(self.positive)
            row[name] = value
            with self.subTest(field=name), self.assertRaisesRegex(
                    ValueError, 'current process observation differs: ' + name):
                self.validate(row)

    def test_current_contract_refuses_deadline_exhaustion(self):
        row = copy.deepcopy(self.positive)
        row['deadline_exhausted_at_snapshot'] = True
        with self.assertRaisesRegex(ValueError,
                                    'current process observation differs: deadline_exhausted_at_snapshot'):
            self.validate(row)

    def test_current_contract_retains_unqualified_resource_and_proof_scope(self):
        for name in ('prover_resource_completeness_established', 'complete_proof_claim'):
            row = copy.deepcopy(self.positive)
            row[name] = True
            with self.subTest(field=name), self.assertRaisesRegex(
                    ValueError, 'current process observation differs: ' + name):
                self.validate(row)

    def test_current_snapshot_fields_cannot_coerce_types(self):
        for name, value in (('result_is_pre_handoff_snapshot', 1),
                            ('deadline_exhausted_at_snapshot', 0),
                            ('canceled_signal', False), ('cancellation_event', False)):
            row = copy.deepcopy(self.positive)
            row[name] = value
            with self.subTest(field=name), self.assertRaisesRegex(
                    ValueError, 'current process observation differs: ' + name):
                self.validate(row)

    def test_version_selector_is_explicit_and_unknown_versions_are_refused(self):
        for schema in (None, True, 'auto', 'TRNM-W1-STAGE-MEASUREMENT4'):
            with self.subTest(schema=schema), self.assertRaisesRegex(
                    ValueError, 'unsupported process observation version'):
                self.validate(self.positive, schema=schema)

    def test_current_cli_selects_current_schema_without_a_downgrade_option(self):
        # The stub isolates CLI dispatch; it is not verifier/proof evidence.
        root = Path(self.temp.name)
        binary = root / 'fixture-binary-for-hash'
        binary.write_bytes(b'not an executable proof verifier')
        with patch.object(gate, 'validate', return_value={}) as validate, redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main([str(root/'out'), str(root/'proof'), str(binary)]), 0)
        self.assertEqual(validate.call_args.kwargs['stage_schema'], CURRENT)
        self.assertEqual(validate.call_args.kwargs['verifier_sha256'], gate.controls.sha(binary))


if __name__ == '__main__':
    unittest.main(verbosity=2)
