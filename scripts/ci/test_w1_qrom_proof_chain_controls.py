"""Adversarial completion records for the separate proof-chain runner."""
import copy
import unittest

import w1_qrom_proof_chain_controls as gate


class ProofChainCompletionTests(unittest.TestCase):
    def setUp(self):
        self.required = [{'module': 'test_example', 'tests': ['test_example.T.test_a',
                                                            'test_example.T.test_b']}]
        self.hashes = {'test_example': 'a' * 64}
        self.record = {
            'schema': 'TRNM-W1-QROM-PROOF-CHAIN-CONTROLS1',
            'roster_sha256': gate.ROSTER_SHA256,
            'test_source_sha256': self.hashes,
            'qualification': dict(gate.QUALIFICATION),
            'suites': [{'module': 'test_example', 'registered': self.required[0]['tests'][:],
                        'started': self.required[0]['tests'][:],
                        'successful': self.required[0]['tests'][:], 'tests_run': 2,
                        'skipped': [], 'failures': [], 'errors': [],
                        'expected_failures': [], 'unexpected_successes': [], 'exception': None}],
        }

    def test_complete_record_keeps_security_unknown(self):
        result = gate.validate(self.record, self.required, self.hashes)
        self.assertEqual(result['actual_successful_tests'], 2)
        self.assertIsNone(result['qualification']['unconditional_project_security_bits'])

    def test_zero_exit_or_missing_names_cannot_complete(self):
        for field in ('registered', 'started', 'successful'):
            value = copy.deepcopy(self.record)
            value['suites'][0][field] = []
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.validate(value, self.required, self.hashes)

    def test_duplicate_success_cannot_replace_a_test(self):
        self.record['suites'][0]['successful'] = ['test_example.T.test_a'] * 2
        with self.assertRaises(ValueError):
            gate.validate(self.record, self.required, self.hashes)

    def test_skip_expected_failure_and_exception_are_not_passes(self):
        for field in ('skipped', 'expected_failures', 'failures', 'errors', 'unexpected_successes'):
            value = copy.deepcopy(self.record)
            value['suites'][0][field] = ['test_example.T.test_a']
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.validate(value, self.required, self.hashes)
        self.record['suites'][0]['exception'] = 'SystemExit: 0'
        with self.assertRaises(ValueError):
            gate.validate(self.record, self.required, self.hashes)

    def test_forged_qualification_source_and_boolean_count_are_refused(self):
        for key, bad in [('post_quantum_soundness_qualified', True),
                         ('post_quantum_soundness_qualified', 0),
                         ('unconditional_project_security_bits', 128)]:
            value = copy.deepcopy(self.record)
            value['qualification'][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                gate.validate(value, self.required, self.hashes)
        with self.assertRaises(ValueError):
            gate.validate(self.record, self.required, {'test_example': 'b' * 64})
        self.record['suites'][0]['tests_run'] = True
        with self.assertRaises(ValueError):
            gate.validate(self.record, self.required, self.hashes)


if __name__ == '__main__':
    unittest.main()
