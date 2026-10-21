#!/usr/bin/env python3
"""Counterexamples derived from supplied real W1 logs, not native execution.

All mutations remain in memory. The actual retained files must still have their
original bytes after the tests. No modified record is written as native evidence.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_budget_reader as reader
import pon_w1_budget_derive as derive

RAW_DIR = None


class CounterexampleInput:
    def __init__(self, raw):
        self.raw = raw

    def read_bytes(self):
        return self.raw

    def resolve(self):
        return Path('/counterexample-only/not-native-evidence.jsonl')


class ActualLogCounterexamples(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = {name: (RAW_DIR / name).read_bytes() for name in
                        ('w1-seed1.jsonl', 'w1-seed2.jsonl', 'w1-exhausted.jsonl', 'w1-receiver-budget.jsonl')}
        cls.validated = {name: reader.analyze(RAW_DIR / name) for name in cls.original}
        for name, result in cls.validated.items():
            if result['record_consistency'] != 'PASS' or result['semantic_alerts']:
                raise ValueError(name + ': supplied baseline is not internally consistent')

    @classmethod
    def tearDownClass(cls):
        for name, raw in cls.original.items():
            if hashlib.sha256((RAW_DIR / name).read_bytes()).digest() != hashlib.sha256(raw).digest():
                raise ValueError(name + ': original native input changed')

    def altered(self, filename, mutate):
        rows = [json.loads(line) for line in self.original[filename].splitlines()]
        mutate(rows)
        return CounterexampleInput(b''.join(json.dumps(row, allow_nan=False).encode() + b'\n' for row in rows))

    def reject(self, filename, mutate):
        with self.assertRaises((ValueError, KeyError, TypeError, OverflowError)):
            reader.analyze(self.altered(filename, mutate))

    def test_all_four_actual_logs_retain_original_denominators(self):
        for result in self.validated.values():
            counts = result['receiver_counts_recomputed']
            self.assertEqual(counts['requested_replays'], counts['started_replays'] + counts['start_refusals'])
            self.assertEqual(counts['started_replays'], counts['verified_work'] + counts['relation_errors'] + counts['local_cancellations'])
            self.assertIs(result['unique_confirmed_business_transactions_measured'], False)
            self.assertIs(result['native_verification_performed_by_reader'], False)

    def legal_rows(self):
        return {name: [json.loads(line) for line in self.original[name].splitlines()]
                for name in ('w1-seed1.jsonl', 'w1-seed2.jsonl')}

    def test_legal_cost_minimum_keeps_full_setup_all_attempts_and_exact_case(self):
        rows = self.legal_rows()
        costs = derive.legal_winner_costs(rows)
        original = {(name, row['case']): row for name, values in rows.items()
                    for row in values if row['kind'] == 'producer'}
        self.assertEqual({row['class'] for row in costs['samples']}, set(reader.CLASSES))
        for row in costs['samples']:
            raw = original[(row['file'], f"{row['class']}/{row['sample']}/{row['arm']}")]
            self.assertEqual(row['full_cpu_ns'], raw['total']['cpu_ns'])
            self.assertEqual(row['setup_cpu_ns'], raw['setup']['cpu_ns'])
            self.assertEqual(row['attempts'], len(raw['attempts']))
            self.assertGreaterEqual(row['full_cpu_ns'], row['setup_cpu_ns'] + row['search_cpu_ns'])
        for selected in costs['minimum_per_same_case']:
            candidates = [row for row in costs['samples']
                          if all(row[key] == selected[key] for key in ('seed', 'class', 'sample'))]
            self.assertEqual(selected['minimum_full_cpu_ns'], min(row['full_cpu_ns'] for row in candidates))
        self.assertIs(costs['fastest_adversary_lower_bound'], False)

    def test_unknown_attempt_cpu_is_retained_as_unknown_not_zero(self):
        rows = self.legal_rows()
        producer = next(row for row in rows['w1-seed1.jsonl']
                        if row['kind'] == 'producer' and row['status'] == 'target-hit-unverified'
                        and row['valid_proof_acquisition_used'])
        producer['attempts'][0]['timing']['cpu_ns'] = None
        costs = derive.legal_winner_costs(rows)
        case = next(row for row in costs['samples'] if row['file'] == 'w1-seed1.jsonl'
                    and f"{row['class']}/{row['sample']}/{row['arm']}" == producer['case'])
        self.assertEqual(case['per_attempt_cpu_ns']['unknown_count'], 1)
        self.assertEqual(case['per_attempt_cpu_ns']['known']['n'], len(producer['attempts']) - 1)
        self.assertEqual(case['full_cpu_ns'], producer['total']['cpu_ns'])

    def test_fixed_arm_cost_keeps_every_case_and_does_not_mix_hindsight_winners(self):
        rows = self.legal_rows()
        fixed = derive.fixed_legal_arm_costs(rows)
        for group in fixed['aggregates']:
            self.assertEqual(group['full_setup_plus_all_search_cpu_ns'], sum(row['full_cpu_ns'] for row in group['cases']))
            self.assertEqual(group['case_count'], len(group['cases']))
            self.assertEqual(group['attempts'], sum(row['attempts'] for row in group['cases']))
            if group['status_counts'].get('unsupported', 0):
                self.assertIs(group['eligible_for_fixed_arm_comparison'], False)
        for minimum in fixed['minimum_observed_fixed_arm_per_class']:
            actual = next(row for row in fixed['aggregates'] if row['class'] == minimum['class'] and row['arm'] == minimum['arm'])
            self.assertEqual(actual['full_setup_plus_all_search_cpu_ns'], minimum['full_setup_plus_all_search_cpu_ns'])
        self.assertIs(fixed['per_sample_hindsight_mixture_is_implemented_strategy'], False)
        producer = next(row for row in rows['w1-seed1.jsonl'] if row['kind'] == 'producer')
        rows['w1-seed1.jsonl'].remove(producer)
        with self.assertRaises(ValueError):
            derive.fixed_legal_arm_costs(rows)

    def test_fixed_arm_forced_exhaustion_retains_full_cost_and_null_per_winner(self):
        rows = {'w1-exhausted.jsonl': [json.loads(line) for line in self.original['w1-exhausted.jsonl'].splitlines()]}
        fixed = derive.fixed_legal_arm_costs(rows)
        self.assertEqual(fixed['minimum_observed_fixed_arm_per_class'], [])
        for arm in fixed['aggregates']:
            self.assertEqual(arm['winners'], 0)
            self.assertIsNone(arm['full_cpu_per_winner']['ratio_ns'])
            self.assertGreater(arm['full_setup_plus_all_search_cpu_ns'], 0)

    def test_false_trace_cannot_enter_legal_winner_minimum(self):
        rows = self.legal_rows()
        false = next(row for row in rows['w1-seed1.jsonl']
                     if row['kind'] == 'producer' and row['status'] == 'target-hit-unverified'
                     and row['case'].endswith('/from-zero-false-trace'))
        false['valid_proof_acquisition_used'] = True
        with self.assertRaises(ValueError):
            derive.legal_winner_costs(rows)

    def test_host_pair_requires_identical_source_complete_cases_and_mathematical_bytes(self):
        # In-memory reader counterexamples only; no second native execution is asserted.
        report = {'source_head': 'a' * 40, 'source_tree': 'b' * 40,
                  'strict_reader_sha256': 'c' * 64,
                  'campaigns': [{'file': name, 'campaign': rows[0]} for name, rows in self.legal_rows().items()],
                  'implemented_legal_winner_costs': derive.legal_winner_costs(self.legal_rows()),
                  'false_trace_costs': []}
        peer = copy.deepcopy(report)
        for row in peer['implemented_legal_winner_costs']['samples']:
            row['full_cpu_ns'] *= 2
            row['setup_cpu_ns'] *= 2
            row['search_cpu_ns'] *= 2
        comparison = derive.compare_hosts(report, peer, ['counterexample-left', 'counterexample-right'])
        self.assertTrue(all(row['left_cpu_over_right_cpu'] == 0.5 for row in comparison['paired_legal_costs']))
        self.assertIs(comparison['gpu_or_asic_lower_bound'], False)
        with self.assertRaises(ValueError):
            derive.compare_hosts(report, peer, ['same', 'same'])
        for field in ('source_head', 'source_tree'):
            bad = copy.deepcopy(peer)
            bad[field] = 'd' * 40
            with self.assertRaises(ValueError):
                derive.compare_hosts(report, bad, ['left', 'right'])
        for field in ('target', 'task', 'proof_digest', 'winning_challenge'):
            bad = copy.deepcopy(peer)
            bad['implemented_legal_winner_costs']['samples'][0][field] = 'd' * 64
            with self.assertRaises(ValueError):
                derive.compare_hosts(report, bad, ['left', 'right'])
        bad = copy.deepcopy(peer)
        bad['implemented_legal_winner_costs']['samples'].pop()
        with self.assertRaises(ValueError):
            derive.compare_hosts(report, bad, ['left', 'right'])
        bad = copy.deepcopy(peer)
        bad['campaigns'][0]['campaign']['attempt_budget_per_arm'] += 1
        with self.assertRaises(ValueError):
            derive.compare_hosts(report, bad, ['left', 'right'])

    def test_missing_unsupported_case_cannot_improve_completion_fraction(self):
        self.reject('w1-seed1.jsonl', lambda rows: rows.pop(next(i for i, row in enumerate(rows) if row.get('status') == 'unsupported')))

    def test_missing_failed_trial_cannot_reduce_producer_cost_denominator(self):
        def mutate(rows):
            producer = next(row for row in rows if row['kind'] == 'producer' and len(row['attempts']) > 1)
            producer['attempts'].pop(0)
            producer['attempts_executed'] -= 1
        self.reject('w1-seed1.jsonl', mutate)

    def test_zero_target_exhaustion_cannot_become_a_successful_candidate(self):
        def mutate(rows):
            row = next(row for row in rows if row.get('status') == 'exhausted')
            row['status'] = 'target-hit-unverified'
            row['candidate_proof_digest'] = '00' * 32
        self.reject('w1-exhausted.jsonl', mutate)

    def test_false_trace_success_is_retained_as_semantic_alert(self):
        def mutate(rows):
            row = next(row for row in rows if row['kind'] == 'raw-verifier-diagnostic' and row['case'].endswith('/from-zero-false-trace'))
            row['outcome'] = {'kind': 'verified-work', 'error': None}
        result = reader.analyze(self.altered('w1-seed1.jsonl', mutate))
        self.assertTrue(result['semantic_alerts'])

    def test_winning_trial_ratio_cannot_replace_full_producer_cost(self):
        def mutate(rows):
            producers = {row['case']: row for row in rows if row['kind'] == 'producer'}
            row = next(row for row in rows if row['kind'] == 'raw-verifier-diagnostic')
            last = producers[row['case']]['attempts'][-1]['timing']['cpu_ns']
            row['receiver_cpu_over_full_producer_search_cpu'] = row['timing']['cpu_ns'] / last
        self.reject('w1-seed1.jsonl', mutate)

    def test_new_receiver_epoch_cannot_refill_each_case(self):
        def mutate(rows):
            original = next(row['state'] for row in rows if row['kind'] == 'receiver-domain-start')
            second = [row for row in rows if row['kind'] == 'receiver'][1]
            second['before'] = dict(original)
        self.reject('w1-receiver-budget.jsonl', mutate)

    def test_refused_requests_cannot_disappear_from_summary(self):
        self.reject('w1-receiver-budget.jsonl', lambda rows: rows[-1].update(requested_replays=rows[-1]['started_replays']))

    def test_start_exhaustion_means_less_than_the_original_reserve(self):
        def mutate(rows):
            row = next(row for row in rows if row.get('status') == 'not-started')
            row['after']['stored_credit_ns'] = row['after']['start_reserve_ns']
        self.reject('w1-receiver-budget.jsonl', mutate)

    def test_final_flow_cannot_double_charge_the_live_interval(self):
        def mutate(rows):
            flow = rows[-1]['actual_flow']
            flow['paid_cpu_debit_ns'] += flow['live_debited_cpu_ns']
        self.reject('w1-receiver-budget.jsonl', mutate)

    def test_boolean_cannot_replace_one_real_trial(self):
        def mutate(rows):
            row = next(row for row in rows if row.get('attempts_executed') == 1)
            row['attempts_executed'] = True
        self.reject('w1-seed1.jsonl', mutate)

    def test_duplicate_keys_and_truncated_capture_are_not_complete_logs(self):
        raw = self.original['w1-seed1.jsonl']
        with self.assertRaises(ValueError):
            reader.analyze(CounterexampleInput(raw[:-1]))
        altered = raw.replace(b'"kind":"campaign"', b'"kind":"campaign","kind":"campaign"', 1)
        self.assertNotEqual(altered, raw)
        with self.assertRaises(ValueError):
            reader.analyze(CounterexampleInput(altered))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    args, remaining = parser.parse_known_args()
    RAW_DIR = args.raw_dir
    unittest.main(argv=[sys.argv[0], *remaining])
