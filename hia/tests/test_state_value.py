"""Native finite JVT1 Value constructor, grammar, ordering and serializer.

FRAME/CAPACITY are explicit local constructor/ABI results, not M06 errors.
The retained Rust bridge constructs actual Values/Maps and calls original root;
no copy of M06 validation is used as its oracle. WholeState is not tested here.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.state_value_cases import ARENA, FRAME, CAPACITY, RANGE, NONCANONICAL, value_cases

SOURCE = Path(__file__).resolve().parents[1] / "src/state/json_value.hepta"
REFERENCE_ENV = "TRNM_HIA_RUST_STATE_REFERENCE"


def arguments(case):
    return [case['input'], b'\xa5' * case['capacity'], b'\x6b' * case['scratch']]


class StateValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.module.close()

    def assert_observation(self, case, sent, actual, code, payload):
        actual.require_returned()
        self.assertEqual(actual.value, code, (case['label'], case['input'][:96], code, actual.value))
        wanted = sent[1] if payload is None else payload + sent[1][len(payload):]
        self.assertEqual(actual.arguments[0], sent[0])
        self.assertEqual(actual.arguments[1], wanted, case['label'])
        if len(sent[2]) > ARENA:
            self.assertEqual(actual.arguments[2][ARENA:], sent[2][ARENA:], case['label'])

    def test_native_model_and_bounds(self):
        cases = value_cases()
        self.assertEqual(len(cases), 471)
        for begin in range(0, len(cases), 4):
            selected = cases[begin:begin+4]
            sent = [arguments(case) for case in selected]
            observed = self.module.call_many([("f0", item) for item in sent], timeout=60)
            for case, args, actual in zip(selected, sent, observed):
                self.assert_observation(case, args, actual, case['return'], case['expected'])

    def test_original_value_and_m06_differential(self):
        reference = os.environ.get(REFERENCE_ENV)
        if not reference:
            self.skipTest("NOT_RUN: " + REFERENCE_ENV + " is not configured; original Rust has not executed")
        # The bridge has no scratch buffer. Its constructor profile, grammar and
        # original canonical output remain directly comparable for other cases.
        cases = [case for case in value_cases() if case['label'] != 'scratch-capacity']
        process = subprocess.run([str(Path(reference).resolve(strict=True))],
                                 input=''.join('tape ' + (case['input'].hex() or '-') + '\n' for case in cases),
                                 text=True, capture_output=True, timeout=60, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        rows = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(len(rows), len(cases))
        for begin in range(0, len(cases), 4):
            selected = cases[begin:begin+4]
            sent = [arguments(case) for case in selected]
            observed = self.module.call_many([("f0", item) for item in sent], timeout=60)
            for case, args, row, actual in zip(selected, sent, rows[begin:begin+4], observed):
                payload = None
                if row.get('parse') == 'TAPE':
                    self.assertIn(row.get('error'), ('FRAME', 'CAPACITY'), row)
                    code = FRAME if row['error'] == 'FRAME' else CAPACITY
                else:
                    self.assertEqual(row.get('parse'), 'OK', row)
                    self.assertIn(row.get('grammar'), ('OK', 'RANGE', 'NONCANONICAL'), row)
                    if row['grammar'] == 'RANGE':
                        code = RANGE
                    elif row['grammar'] == 'NONCANONICAL':
                        code = NONCANONICAL
                    else:
                        payload = bytes.fromhex(row['canonical'])
                        code = len(payload)
                        if code > len(args[1]):
                            code, payload = CAPACITY, None
                self.assert_observation(case, args, actual, code, payload)


if __name__ == '__main__':
    unittest.main()
