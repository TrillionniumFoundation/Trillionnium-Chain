"""Adversarial review-comparison controls using two independently recomputed reports."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))

import w1_fri_algebra_replay as algebra
import w1_fri_algebra_report_check as check


class IndependentReviewComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Exercise live computations; a tiny synthetic success-shaped record
        # cannot establish that the comparator handles the real 50-query shape.
        cls.report = json.loads(algebra.canonical_json(algebra.build_report(ROOT)))
        path = ROOT / 'evidence/pon-w1-fri-algebra-20261108/review/recompute_register_deep.py'
        spec = importlib.util.spec_from_file_location('_register_review_controls', path)
        reviewer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reviewer)
        cls.review = json.loads(json.dumps(reviewer.build_report(ROOT)))

    def test_actual_register_expansion_matches_all_queries(self):
        result = check.compare_review(self.report, self.review)
        self.assertIs(result['register_expansion_agrees_with_combo_batching'], True)
        self.assertEqual(result['deep_goals_compared'], 50)
        self.assertEqual(result['fold_results_compared'], 150)
        self.assertEqual(result['terminal_results_compared'], 50)
        self.assertEqual(result['nonzero_divisors_compared'], 300)
        self.assertIs(result['independent_air_left_hand_side_evaluation'], False)
        # Register traversal really differs from numerical combo order.
        self.assertEqual([x['combo'] for x in self.review['denominators'][:6]],
                         [1, 0, 2, 3, 4, 'check'])

    def test_missing_duplicate_or_mistyped_denominator_identities_rejected(self):
        missing = copy.deepcopy(self.review)
        missing['denominators'].pop()
        duplicate = copy.deepcopy(self.review)
        duplicate['denominators'][-1] = copy.deepcopy(duplicate['denominators'][0])
        cases = [('missing', missing), ('duplicate', duplicate)]
        for field in ('query', 'combo'):
            for number in (0, 1):
                changed = copy.deepcopy(self.review)
                item = next(item for item in changed['denominators']
                            if type(item[field]) is int and item[field] == number)
                item[field] = bool(number)
                cases.append((f'{field}_{number}_as_bool', changed))
        for name, review in cases:
            with self.subTest(name=name), self.assertRaises(ValueError):
                check.compare_review(self.report, review)

    def test_cross_query_goals_and_denominator_hashes_rejected(self):
        changed_goal = copy.deepcopy(self.review)
        changed_goal['queries'][48]['deep_and_three_fold_goals_normal'] = copy.deepcopy(
            changed_goal['queries'][49]['deep_and_three_fold_goals_normal'])
        changed_hash = copy.deepcopy(self.review)
        changed_hash['denominators'][-1]['normal_words_le_sha256'] = (
            changed_hash['denominators'][0]['normal_words_le_sha256'])
        changed_order_hash = copy.deepcopy(self.review)
        changed_order_hash['denominators_ordered_normal_le_sha256'] = '0' * 64
        for name, review in (('late_query_goal', changed_goal),
                             ('late_denominator', changed_hash),
                             ('traversal_digest', changed_order_hash)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check.compare_review(self.report, review)
        # These are report-type controls, not accepted proofs. First make the
        # two compared integer coordinates equal, then replace only one side
        # by False. Python equality alone must not accept the bool/int alias.
        for stage in ('air', 'deep', 'terminal'):
            for side in ('main', 'review'):
                report, review = copy.deepcopy(self.report), copy.deepcopy(self.review)
                row, other = report['algebra']['fri']['queries'][0], review['queries'][0]
                if stage == 'air':
                    left = report['algebra']['mixed_air']['returned_total']
                    report['algebra']['mixed_air']['check_polynomial_times_zerofier'][0] = 0
                    right = review['air_check_side_normal_words']
                elif stage == 'deep':
                    left = row['deep_goal']
                    row['rounds'][0]['incoming_goal'][0] = 0
                    row['rounds'][0]['selected_opened_value'][0] = 0
                    right = other['deep_and_three_fold_goals_normal'][0]
                else:
                    left = row['terminal_value']
                    row['terminal_goal'][0] = 0
                    row['rounds'][2]['outgoing_goal'][0] = 0
                    right = other['deep_and_three_fold_goals_normal'][3]
                left[0] = right[0] = 0
                (left if side == 'main' else right)[0] = False
                with self.subTest(stage=stage, side=side), self.assertRaises(ValueError):
                    check.compare_review(report, review)
        for field in ('initial_index', 'terminal_index'):
            for side in ('main', 'review'):
                report, review = copy.deepcopy(self.report), copy.deepcopy(self.review)
                row, other = report['algebra']['fri']['queries'][0], review['queries'][0]
                row[field] = other[field] = 0
                (row if side == 'main' else other)[field] = False
                with self.subTest(field=field, side=side), self.assertRaises(ValueError):
                    check.compare_review(report, review)

    def test_foreign_review_receipt_and_mistyped_scope_rejected(self):
        foreign = copy.deepcopy(self.review)
        foreign['receipt']['sha256'] = 'f' * 64
        cases = [('foreign_receipt', foreign)]
        for field, value in (('qrom_instantiated', 0), ('imports_new_algebra_replay', 0),
                             ('generated_air_program_evaluated', True),
                             ('security_bits_quantum', False),
                             ('whole_chain_pq_qualified', True)):
            changed = copy.deepcopy(self.review)
            changed['scope'][field] = value
            cases.append((field, changed))
        for name, review in cases:
            with self.subTest(name=name), self.assertRaises(ValueError):
                check.compare_review(self.report, review)

    def test_missing_or_mistyped_terminal_and_fold_success_rejected(self):
        changed_air = copy.deepcopy(self.report)
        changed_air['algebra']['mixed_air']['equality_checked'] = 1
        changed_fold = copy.deepcopy(self.report)
        changed_fold['algebra']['fri']['queries'][49]['rounds'][2]['incoming_equality_checked'] = 1
        changed_terminal = copy.deepcopy(self.report)
        changed_terminal['algebra']['fri']['queries'][49]['terminal_equality_checked'] = False
        for name, report in (('air_boolean', changed_air), ('last_fold_boolean', changed_fold),
                             ('last_terminal_false', changed_terminal)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check.compare_review(report, self.review)
        changed_review = copy.deepcopy(self.review)
        changed_review['queries'][49]['terminal_equality'] = 1
        with self.assertRaises(ValueError):
            check.compare_review(self.report, changed_review)


if __name__ == '__main__':
    unittest.main()
