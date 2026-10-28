#!/usr/bin/env python3
"""Readback and injected-record controls only; never execute PoN or a node."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

import analyze


class OriginalFlowReadbackControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archive = Path(__file__).resolve().parents[3] / (
            'recovery/next-publication/ci-final-readback-r7-raw/'
            'chain-131f-native-12787328109.zip')
        # The path may differ when reproducing outside this workspace.
        archive = Path(os.environ.get('R14_ORIGINAL_ARCHIVE', str(archive)))
        with zipfile.ZipFile(archive) as zipped:
            raw = zipped.read('run-1-raw/report.json')
        if analyze.hashlib.sha256(raw).hexdigest() != analyze.REPORT_SHA[1]:
            raise AssertionError('wrong original report bytes')
        original = json.loads(raw, object_pairs_hook=analyze.unique)['phases'][1]
        cls.original = {key: original[key] for key in (
            'initial_meter', 'final_meter', 'final_actual_flow',
            'service_outcome', 'budget_samples')}

    def setUp(self):
        self.phase = deepcopy(self.original)

    def test_original_run1_transcript_interval_bound(self):
        bound, intervals = analyze.interval_bounds(self.phase)
        self.assertEqual(bound['sample_count'], 373)
        self.assertEqual(bound['lower_bound_ns'], 1_960_984_060)
        self.assertEqual(len(intervals), 374)
        self.assertEqual(bound['worst_pair']['from']['sample_index'], 51)
        self.assertEqual(bound['worst_pair']['to']['sample_index'], 52)

    def test_unknown_clock_never_becomes_known_zero(self):
        self.phase['budget_samples'][12]['meter']['Ok']['clock_failures'] = 1
        with self.assertRaisesRegex(ValueError, 'unknown sample CPU'):
            analyze.interval_bounds(self.phase)

    def test_missing_flow_is_unknown(self):
        del self.phase['budget_samples'][12]['meter']['Ok']['actual_flow']
        with self.assertRaises(KeyError):
            analyze.interval_bounds(self.phase)

    def test_failed_account_identity_is_rejected(self):
        self.phase['budget_samples'][12]['meter']['Ok']['actual_flow'][
            'remaining_paid_credit_ns'] -= 1
        with self.assertRaisesRegex(ValueError, 'paid identity'):
            analyze.interval_bounds(self.phase)

    def test_individually_balanced_nonmonotone_debit_is_rejected(self):
        flow = self.phase['budget_samples'][12]['meter']['Ok']['actual_flow']
        for key in ('paid_cpu_debit_ns', 'live_debited_cpu_ns'):
            flow[key] += 10_000_000_000
        for key in ('remaining_paid_credit_ns', 'stored_credit_ns'):
            flow[key] -= 10_000_000_000
        with self.assertRaisesRegex(ValueError, 'nonmonotone cumulative flow'):
            analyze.interval_bounds(self.phase)

    def test_unsettled_final_cpu_cannot_close_tail(self):
        self.phase['final_actual_flow']['unsettled_known_live_cpu_ns'] = 1
        with self.assertRaisesRegex(ValueError, 'unsettled final CPU'):
            analyze.interval_bounds(self.phase)

    def test_unsorted_samples_cannot_define_ledger_interval(self):
        samples = self.phase['budget_samples']
        samples[12], samples[13] = samples[13], samples[12]
        with self.assertRaisesRegex(ValueError, 'sample order'):
            analyze.interval_bounds(self.phase)

    def test_cold_constructor_cannot_substitute_full_burst_campaign(self):
        self.phase['initial_meter']['stored_credit_ns'] = 0
        with self.assertRaisesRegex(ValueError, 'constructor anchor'):
            analyze.interval_bounds(self.phase)

    def test_reservation_principal_does_not_change_paid_balance(self):
        # Synthetic accounting-identity control, not an observed native owner.
        flow = deepcopy(self.phase['final_actual_flow'])
        paid = flow['remaining_paid_credit_ns']
        flow['live_owners'] = 2
        flow['booked_reservation_ns'] = 200_000_000
        flow['stored_credit_ns'] = paid - 200_000_000
        checked = analyze.exact_flow(flow, 2_000_000_000, 100_000_000)
        self.assertEqual(checked['remaining_paid_credit_ns'], paid)
        self.assertEqual(checked['paid_cpu_debit_ns'],
                         self.phase['final_actual_flow']['paid_cpu_debit_ns'])

    def test_wrong_archive_is_rejected_before_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'wrong.zip'
            archive.write_bytes(b'not the original artifact')
            with self.assertRaisesRegex(ValueError, 'wrong original archive bytes'):
                analyze.analyze(archive)

    def test_duplicate_record_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            json.loads('{"paid_cpu_debit_ns":1,"paid_cpu_debit_ns":0}',
                       object_pairs_hook=analyze.unique)


if __name__ == '__main__':
    unittest.main()
