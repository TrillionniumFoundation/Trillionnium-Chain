#!/usr/bin/env python3
"""Counterexamples derived from supplied real W1 logs, not native execution.

All mutations remain in memory. The actual retained files must still have their
original bytes after the tests. No modified record is written as native evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_w1_budget_reader as reader

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
