#!/usr/bin/env python3
"""A compiled, missing, ignored or filtered test must not qualify the native lane."""
import copy
import json
import unittest

from run_native_pq_accounts_v2 import (AUTHORITY_CAPACITY_CASES, NATIVE_CASES, PQ1_NATIVE_CASES, PHASE_SCOPE,
                                       PHASE_RESULTS, phase_result, test_result)


def log(cases, *, passed=None, ignored=0, filtered=0):
    lines = [f'test {name} ... {status}' for name, status in cases]
    count = sum(status == 'ok' for _, status in cases) if passed is None else passed
    lines.append(f'test result: ok. {count} passed; 0 failed; {ignored} ignored; 0 measured; {filtered} filtered out; finished in 1.00s')
    return '\n'.join(lines) + '\n'


class ActualCaseSetTests(unittest.TestCase):
    def test_both_actual_authority_capacity_cases_are_required(self):
        cases = [(name, 'ok') for name in sorted(AUTHORITY_CAPACITY_CASES)]
        self.assertEqual(test_result(log(cases), AUTHORITY_CAPACITY_CASES, exact=True)['passed'], 2)
        for text in [log(cases[:1]), log(cases, filtered=1),
                     log([(cases[0][0], 'ok'), (cases[1][0], 'ignored')], ignored=1),
                     log([(name, 'ok') for name in NATIVE_CASES])]:
            with self.assertRaises(ValueError):
                test_result(text, AUTHORITY_CAPACITY_CASES, exact=True)

    def test_complete_named_nine_can_be_read_without_claiming_execution(self):
        self.assertEqual(test_result(log([(n, 'ok') for n in sorted(NATIVE_CASES)]), NATIVE_CASES, exact=True)['passed'], 9)

    def test_cargo_check_or_build_only_is_not_a_test_result(self):
        with self.assertRaises(ValueError):
            test_result('Finished test profile\nExecutable tests/native_pq_v2.rs\n', NATIVE_CASES, exact=True)

    def test_zero_or_unrelated_tests_do_not_satisfy_required_cases(self):
        for text in [log([]), log([('old_component_only', 'ok')])]:
            with self.assertRaises(ValueError):
                test_result(text, NATIVE_CASES, exact=True)

    def test_summary_count_cannot_replace_missing_named_test(self):
        with self.assertRaises(ValueError):
            test_result(log([(n, 'ok') for n in sorted(NATIVE_CASES)[:-1]], passed=9), NATIVE_CASES, exact=True)

    def test_ignored_or_filtered_required_case_is_not_success(self):
        names = sorted(NATIVE_CASES)
        for text in [log([(n, 'ok') for n in names[:-1]] + [(names[-1], 'ignored')], ignored=1),
                     log([(n, 'ok') for n in names], filtered=1)]:
            with self.assertRaises(ValueError):
                test_result(text, NATIVE_CASES, exact=True)

    def test_duplicate_case_or_multiple_summaries_reject(self):
        cases = [(n, 'ok') for n in sorted(NATIVE_CASES)]
        for text in [log(cases + [cases[0]]), log(cases) + log(cases)]:
            with self.assertRaises(ValueError):
                test_result(text, NATIVE_CASES, exact=True)


class ActualPhaseReaderTests(unittest.TestCase):
    @staticmethod
    def synthetic_rows():
        rows = []
        for phase, result in PHASE_RESULTS.items():
            counts = [16] * 7 + [10] if phase == 'capacity_actual_pool_bundle' else [1]
            for count in counts:
                rows.append({'schema': 'native-pq2-phase-observation-v1', 'phase': phase,
                             'details': {'transactions': count, 'raw_bytes': count * 4263},
                             'result': result, 'wall_nanoseconds': 1, 'scope': PHASE_SCOPE})
        return rows

    @staticmethod
    def synthetic_log(rows):
        return '\n'.join(json.dumps(row, separators=(',', ':')) for row in rows)

    def test_synthetic_parser_control_is_not_runtime_evidence(self):
        result = phase_result(self.synthetic_log(self.synthetic_rows()))
        self.assertEqual(len(result['observations']), 17)
        self.assertFalse(result['cpu_measured'])
        self.assertFalse(result['worst_case_bound'])

    def test_old_six_cases_cannot_qualify_the_new_nine(self):
        with self.assertRaises(ValueError):
            test_result(log([(name, 'ok') for name in PQ1_NATIVE_CASES]), NATIVE_CASES, exact=True)

    def test_missing_invalid_signature_or_state_phase_refuses(self):
        for name in ('canonical_signature_for_wrong_message', 'actual_state_grammar_and_current_authority'):
            with self.assertRaises(ValueError):
                phase_result(self.synthetic_log([r for r in self.synthetic_rows() if r['phase'] != name]))

    def test_invalid_signature_success_cannot_be_labeled_negative_control(self):
        rows = self.synthetic_rows()
        next(r for r in rows if r['phase'] == 'canonical_signature_for_wrong_message')['result'] = 'ok'
        with self.assertRaises(ValueError):
            phase_result(self.synthetic_log(rows))

    def test_bad_wall_time_scope_or_unwind_refuses(self):
        for field, value in [('wall_nanoseconds', True), ('wall_nanoseconds', -1),
                             ('scope', 'isolated CPU'), ('result', 'unwind')]:
            rows = self.synthetic_rows()
            rows[0][field] = value
            with self.assertRaises(ValueError):
                phase_result(self.synthetic_log(rows))

    def test_partial_capacity_or_wrong_full_frame_size_refuses(self):
        original = self.synthetic_rows()
        capacity = next(i for i, row in enumerate(original) if row['phase'] == 'capacity_actual_pool_bundle')
        for mutation in ('missing', 'wrong_bytes', 'more_transactions'):
            rows = copy.deepcopy(original)
            if mutation == 'missing':
                rows.pop(capacity)
            elif mutation == 'wrong_bytes':
                rows[capacity]['details']['raw_bytes'] -= 1
            else:
                rows[capacity]['details'] = {'transactions': 17, 'raw_bytes': 17 * 4263}
            with self.assertRaises(ValueError):
                phase_result(self.synthetic_log(rows))


if __name__ == '__main__':
    unittest.main()
