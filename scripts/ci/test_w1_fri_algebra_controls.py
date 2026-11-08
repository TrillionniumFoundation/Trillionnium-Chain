"""Negative controls for claims about completed algebra tests."""
import copy
import tempfile
from pathlib import Path
import unittest

import w1_fri_algebra_controls as gate


class AlgebraCompletionTests(unittest.TestCase):
    def setUp(self):
        self.names = ['test_example.T.test_a', 'test_example.T.test_b']
        self.required = [{'module': 'test_example', 'tests': self.names[:]}]
        self.hashes = {'scripts/example.py': 'a' * 64}
        self.value = {
            'schema': gate.SCHEMA, 'roster_sha256': gate.ROSTER_SHA256,
            'source_sha256': self.hashes.copy(), 'qualification': dict(gate.QUALIFICATION),
            'suites': [{'module': 'test_example', 'registered': self.names[:],
                        'started': self.names[:], 'successful': self.names[:],
                        'tests_run': 2, 'skipped': [], 'failures': [], 'errors': [],
                        'expected_failures': [], 'unexpected_successes': [], 'exception': None}],
        }

    def test_complete_named_record_keeps_security_unknown(self):
        result = gate.validate(self.value, self.required, self.hashes)
        self.assertEqual(result['actual_successful_tests'], 2)
        self.assertIsNone(result['qualification']['unconditional_project_security_bits'])

    def test_missing_duplicate_and_boolean_completion_rejected(self):
        for field in ('registered', 'started', 'successful'):
            for bad in ([], self.names[:1], [self.names[0]] * 2):
                value = copy.deepcopy(self.value)
                value['suites'][0][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                    gate.validate(value, self.required, self.hashes)
        self.value['suites'][0]['tests_run'] = True
        with self.assertRaises(ValueError):
            gate.validate(self.value, self.required, self.hashes)

    def test_failed_skipped_or_interrupted_suite_rejected(self):
        for field in ('skipped', 'failures', 'errors', 'expected_failures', 'unexpected_successes'):
            value = copy.deepcopy(self.value)
            value['suites'][0][field] = [self.names[0]]
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.validate(value, self.required, self.hashes)
        self.value['suites'][0]['exception'] = 'SystemExit: 0'
        with self.assertRaises(ValueError):
            gate.validate(self.value, self.required, self.hashes)

    def test_stale_source_roster_and_promoted_scope_rejected(self):
        for field, bad in [('source_sha256', {'scripts/example.py': 'b' * 64}),
                           ('roster_sha256', '0' * 64)]:
            value = copy.deepcopy(self.value)
            value[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.validate(value, self.required, self.hashes)
        for field, bad in [('post_quantum_soundness_qualified', True),
                           ('production_qualified', 0),
                           ('unconditional_project_security_bits', 128)]:
            value = copy.deepcopy(self.value)
            value['qualification'][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.validate(value, self.required, self.hashes)

    def test_ambiguous_and_nonintegral_json_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'completion.json'
            for text in ('{"n":1,"n":2}', '{"n":1.0}', '{"n":NaN}', '{"n":Infinity}'):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    gate.read_json(path)


if __name__ == '__main__':
    unittest.main()
