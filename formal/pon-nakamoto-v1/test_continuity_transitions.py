"""Independent byte-for-byte checks of actual native mandatory transitions.

Pure oracle controls can run before a native build with `... OracleControls -v`.
The full suite requires the real bridge and never skips a missing native binary.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest

from contract_wire import ROOT, canonical, unique
import continuity_transition_oracle as oracle

BINARY = Path(os.environ.get('TRNM_CONTINUITY_TRANSITIONS_BINARY',
    str(ROOT / 'trillionnium/target/debug/examples/continuity_transition_vectors')))


def compare_report(report, cases):
    if set(report) != {'schema', 'cases', 'scope', 'production_activation',
                       'independent_hardware_qualified', 'work_hardness_accepted'}:
        raise ValueError('report fields')
    if report['schema'] != 'native-continuity-transition-observations-v1':
        raise ValueError('report schema')
    if report['scope'] != 'small seeded application fixtures; not signed-command reachability or full native chain':
        raise ValueError('scope')
    if any(report[flag] is not False for flag in ('production_activation', 'independent_hardware_qualified', 'work_hardness_accepted')):
        raise ValueError('acceptance')
    if report['cases'] != [oracle.expected(case) for case in cases]:
        raise ValueError('native context/state/root/receipt/capacity mismatch')


class OracleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = oracle.fixtures()
        cls.results = [oracle.expected(case) for case in cls.cases]

    def test_six_explicit_small_fixtures_are_not_full_capacity_claims(self):
        self.assertEqual(len(self.cases), 6)
        self.assertTrue(all(len(case['state']) < 100 for case in self.cases))
        self.assertEqual(len({case['name'] for case in self.cases}), 6)

    def test_public_storage_namespace_is_fresh_and_legacy_context_stays_unchanged(self):
        legacy, legacy_network, legacy_parameters = oracle.context()
        public, public_network, public_parameters = oracle.context(oracle.PUBLIC)
        self.assertEqual(legacy['chain_label'], 'trnm-pon-continuity-devnet-12-legacy-first-two-v3')
        self.assertEqual(public['chain_label'], 'trnm-pon-continuity-devnet-12-native-public-evaluation-dev-v1-evaluation-storage2')
        self.assertNotEqual(legacy_network, public_network)
        self.assertNotEqual(legacy_parameters, public_parameters)

    def test_sixteen_then_four_refunds_preserve_funds_and_nonce(self):
        rows = self.results[0]['rows']
        self.assertEqual([len(row['receipts']) for row in rows], [16, 4, 0])
        for row in rows:
            self.assertEqual(oracle.funds(row['state']), row['state']['meta:issued'])
            self.assertEqual(row['state']['account:' + oracle.identity(1)]['nonce'], 17)
        initial = self.cases[0]['state']
        due = sorted((v['deadline'], key) for key, v in initial.items()
                     if key.startswith(('task:', 'quota:', 'release:')))
        self.assertEqual(rows[0]['receipts'], [canonical(dict(expiry=key)).hex() for _, key in due[:16]])
        self.assertEqual(rows[1]['receipts'], [canonical(dict(expiry=key)).hex() for _, key in due[16:]])
        self.assertFalse(any(key.startswith(('task:', 'quota:', 'release:')) for key in rows[2]['state']))

    def test_overlap_deduplicates_and_zero_reward_still_creates_account(self):
        initial = self.cases[0]['state']
        self.assertEqual(oracle.capacity(initial, 20)['credit_reserve'], 3)
        rows = self.results[0]['rows']
        self.assertNotIn('account:' + oracle.identity(4), rows[0]['state'])
        self.assertEqual(rows[1]['state']['account:' + oracle.identity(4)], dict(balance=0, nonce=0))
        self.assertEqual(rows[1]['capacity']['credit_reserve'], 0)

    def test_cleanup_precedes_refund_and_deadline_is_strict(self):
        first, second, _ = self.results[1]['rows']
        self.assertNotIn('quota:' + f'{30:064x}', first['state'])
        self.assertIn('task:' + f'{31:064x}', first['state'])
        self.assertEqual(first['state']['quota:' + f'{32:064x}']['remaining'], 0)
        self.assertNotIn('quota:' + f'{32:064x}', second['state'])
        self.assertNotIn('task:' + f'{31:064x}', second['state'])
        self.assertNotIn('release:' + f'{33:064x}', first['state'])
        self.assertIn('release:' + oracle.identity(0), second['state'])

    def test_archive_created_only_after_reveal_end_and_reserved_before(self):
        at_end, after_end = self.results[2]['rows']
        self.assertFalse(any(k.startswith('evaluation-archive:') for k in at_end['state']))
        self.assertEqual(at_end['capacity']['archive_reserve'], 1)
        archives = [v for k, v in after_end['state'].items() if k.startswith('evaluation-archive:')]
        self.assertEqual(len(archives), 1)
        self.assertEqual(archives[0]['public_evaluation']['closed']['status'], 'aborted')
        self.assertEqual(archives[0]['public_evaluation']['closed']['closed_height'], 48)
        self.assertEqual(after_end['capacity']['archive_reserve'], 0)

    def test_archive_256_boundary_and_orphan_record_cleanup(self):
        retained, removed = self.results[3]['rows']
        for prefix in ('evaluation-archive:', 'evaluation-record-v2:'):
            self.assertTrue(any(k.startswith(prefix) for k in retained['state']))
            self.assertFalse(any(k.startswith(prefix) for k in removed['state']))
        old_round = self.results[4]['rows'][0]['state']
        self.assertFalse(any(k.startswith(('contribution:', 'artifact:')) for k in old_round))
        self.assertTrue(any(k.startswith('evaluation-archive:') for k in old_round))
        self.assertTrue(any(k.startswith('evaluation-record-v2:') for k in old_round))

    def test_bad_queue_is_rejected_with_exact_unchanged_parent(self):
        row = self.results[5]['rows'][0]
        self.assertEqual(row['status'], 'rejected')
        self.assertEqual(row['error'], 'CONTINUITY_REWARD_QUEUE')
        self.assertEqual(row['unchanged_parent'], self.cases[5]['state'])

    def test_comparison_rejects_missing_rows_changed_receipts_roots_and_capacity(self):
        # These are checker rejection controls, not native-execution evidence.
        baseline = dict(schema='native-continuity-transition-observations-v1', cases=self.results,
            scope='small seeded application fixtures; not signed-command reachability or full native chain',
            production_activation=False, independent_hardware_qualified=False, work_hardness_accepted=False)
        for field in ('root', 'receipts', 'capacity'):
            changed = copy.deepcopy(baseline)
            changed['cases'][0]['rows'][0][field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                compare_report(changed, self.cases)
        changed = copy.deepcopy(baseline)
        changed['cases'][0]['rows'].pop()
        with self.assertRaises(ValueError):
            compare_report(changed, self.cases)


class NativeTransitions(unittest.TestCase):
    def test_real_native_context_state_root_receipt_capacity_and_rejection(self):
        if not BINARY.is_file():
            raise RuntimeError('Build actual continuity_transition_vectors; no skipped native success')
        cases = oracle.fixtures()
        request = canonical(dict(schema='continuity-transition-request-v1', cases=cases))
        self.assertLess(len(request), 262_144)
        process = subprocess.run([str(BINARY.resolve())], input=request, capture_output=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors='replace'))
        self.assertEqual(process.stderr, b'')
        self.assertLess(len(process.stdout), 2 * 1024 * 1024)
        report = json.loads(process.stdout, object_pairs_hook=unique)
        compare_report(report, cases)


if __name__ == '__main__':
    unittest.main()
