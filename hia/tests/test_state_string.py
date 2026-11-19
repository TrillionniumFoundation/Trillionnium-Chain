"""Native ASCII String codec and exact retained serde/M06 differential.

Canonical inverse is narrower than general JSON parsing: original serde must
parse a String whose original canonical serialization equals every input byte.
Missing original Rust is explicitly NOT_RUN; it is never a native pass claim.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.state_value_cases import CAPACITY, NONCANONICAL, string_cases

SOURCE = Path(__file__).resolve().parents[1] / "src/state/json_string.hepta"
REFERENCE_ENV = "TRNM_HIA_RUST_STATE_REFERENCE"


class StateStringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = NativeModule(SOURCE, byte_exports=("f0",))

    @classmethod
    def tearDownClass(cls):
        cls.module.close()

    def assert_observation(self, sent, actual, code, payload):
        actual.require_returned()
        self.assertEqual(actual.value, code, (sent[0][:96], code, actual.value))
        wanted = sent[1] if payload is None else payload + sent[1][len(payload):]
        self.assertEqual(actual.arguments[0], sent[0])
        self.assertEqual(actual.arguments[1], wanted)
        self.assertEqual(actual.arguments[2], sent[2])

    def test_native_model_and_bounds(self):
        cases, expected = string_cases()
        self.assertEqual(len(cases), 1047)
        for begin in range(0, len(cases), 100):
            selected = cases[begin:begin+100]
            observed = self.module.call_many([("f0", case) for case in selected], timeout=60)
            for sent, (code, payload), actual in zip(selected, expected[begin:begin+100], observed):
                self.assert_observation(sent, actual, code, payload)

    def test_original_serde_and_m06_differential(self):
        reference = os.environ.get(REFERENCE_ENV)
        if not reference:
            self.skipTest("NOT_RUN: " + REFERENCE_ENV + " is not configured; original Rust has not executed")
        cases, _ = string_cases()
        cases = [case for case in cases if case[0] and case[0][0] in (0, 1)]
        request = ''.join(('string ' if case[0][0] == 0 else 'json ')
                          + (case[0][1:].hex() or '-') + '\n' for case in cases)
        process = subprocess.run([str(Path(reference).resolve(strict=True))], input=request,
                                 text=True, capture_output=True, timeout=60, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)
        rows = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(len(rows), len(cases))
        for begin in range(0, len(cases), 100):
            selected = cases[begin:begin+100]
            observed = self.module.call_many([("f0", case) for case in selected], timeout=60)
            for sent, row, actual in zip(selected, rows[begin:begin+100], observed):
                payload = None
                code = NONCANONICAL
                if row.get('parse') == 'OK' and row.get('grammar') == 'OK' and row.get('string') is True:
                    encoded = bytes.fromhex(row['canonical'])
                    if sent[0][0] == 0 or encoded == sent[0][1:]:
                        payload = encoded if sent[0][0] == 0 else bytes.fromhex(row['string_bytes'])
                        code = len(payload)
                        if code > len(sent[1]):
                            code, payload = CAPACITY, None
                self.assert_observation(sent, actual, code, payload)


if __name__ == '__main__':
    unittest.main()
