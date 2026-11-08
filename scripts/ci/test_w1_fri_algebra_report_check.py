"""Prevent fixed algebra observations from becoming whole-proof certificates."""
import copy
import unittest

import w1_fri_algebra_report_check as check


class AlgebraScopeTests(unittest.TestCase):
    def setUp(self):
        flags = dict.fromkeys(check.TRUE_FLAGS, True)
        flags.update(dict.fromkeys(check.FALSE_FLAGS, False))
        flags.update(dict.fromkeys(check.NULL_FLAGS, None))
        self.report = {
            'schema': 'TRNM-W1-FRI-ALGEBRA-REPLAY1', 'profile_id': check.PROFILE,
            'receipt': {'sha256': check.RECEIPT_SHA256}, 'qualification': flags,
            'algebra': {
                'mixed_air': {'operations': 12359},
                'deep': {'query_values_checked_against_first_fri_leaf': 50},
                'fri': {'incoming_goal_equalities': 150, 'terminal_equalities': 50},
            },
        }

    def test_fixed_counts_preserve_full_proof_unknown(self):
        result = check.validate(self.report)
        self.assertEqual(result['result'], 'PASS')
        self.assertIsNone(result['qualification']['full_security_bound'])
        self.assertIs(result['qualification']['complete_receipt_verified'], False)

    def test_each_promoted_or_mistyped_qualification_rejected(self):
        for key in self.report['qualification']:
            original = self.report['qualification'][key]
            alternatives = (1, False, None) if original is True else ((0, True, None) if original is False else (0, 128, False))
            for value in alternatives:
                mutated = copy.deepcopy(self.report)
                mutated['qualification'][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    check.validate(mutated)
        for operation in ('omit', 'extra'):
            mutated = copy.deepcopy(self.report)
            if operation == 'omit':
                del mutated['qualification']['qrom_instantiated']
            else:
                mutated['qualification']['whole_chain_pq'] = True
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                check.validate(mutated)

    def test_incomplete_or_boolean_counts_rejected(self):
        for section, field in (
                ('mixed_air', 'operations'), ('deep', 'query_values_checked_against_first_fri_leaf'),
                ('fri', 'incoming_goal_equalities'), ('fri', 'terminal_equalities')):
            for value in (0, True, self.report['algebra'][section][field] - 1):
                mutated = copy.deepcopy(self.report)
                mutated['algebra'][section][field] = value
                with self.subTest(section=section, field=field, value=value), self.assertRaises(ValueError):
                    check.validate(mutated)

    def test_foreign_profile_receipt_or_schema_rejected(self):
        for key in ('profile_id', 'schema', 'receipt'):
            mutated = copy.deepcopy(self.report)
            mutated[key] = {'sha256': 'f' * 64} if key == 'receipt' else 'foreign'
            with self.subTest(key=key), self.assertRaises(ValueError):
                check.validate(mutated)


if __name__ == '__main__':
    unittest.main()
