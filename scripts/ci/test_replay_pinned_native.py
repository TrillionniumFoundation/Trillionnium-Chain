#!/usr/bin/env python3
"""Small synthetic accounting/ownership controls; these are not native W1 tests."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from replay_pinned_native import producer_observations, json_load, run_child, validate_source_manifest


def fixture():
    arms = {'fixture': [['generic', 'cold-per-search'], ['structured', 'reused-one-setup']]}
    doc = dict(fastest_adversary_qualified=False, work_hardness_accepted=False,
               public_service_measured=False, production_activation=False, seed=7,
               samples_per_case_target=1, searches_per_cohort=2, attempt_budget=4,
               targets=['07'+'ff'*31, '7f'+'ff'*31], observations=[])
    for target in doc['targets']:
        for index, (strategy, mode) in enumerate(arms['fixture']):
            setup = [10, 11] if index == 0 else [12]
            outcomes = []
            for search in range(2):
                won = search == 0
                outcomes.append(dict(search_index=search, status='winner' if won else 'exhausted',
                    attempts=2 if won else 4, search_elapsed_ns=5,
                    ticket_stream_commitment='aa'*32, proof_stream_commitment='bb'*32,
                    winning_challenge='cc'*32 if won else None,
                    winner_proof_commitment='dd'*32 if won else None,
                    production_verifier_elapsed_ns=1 if won else None,
                    reference_verifier_elapsed_ns=2 if won else None,
                    reference_verifier_first=False if won else None))
            doc['observations'].append(dict(**{'class': 'fixture'}, task='11'*32,
                input_source='synthetic-test-only', rank_a=64, rank_b=64, target=target,
                sample=0, invocation_order=index, strategy=strategy, method='supported',
                mode=mode, proof_bytes=49188, setup_observations_ns=setup,
                setup_calls=len(setup), setup_elapsed_ns=sum(setup), search_elapsed_ns=10,
                total_elapsed_ns=sum(setup)+10, outcomes=outcomes))
    return doc, arms


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.doc, self.arms = fixture()

    def reject(self, code):
        with self.assertRaisesRegex(ValueError, code):
            producer_observations(self.doc, self.arms)

    def test_complete_inventory_and_retained_exhaustion(self):
        result = producer_observations(self.doc, self.arms)
        self.assertEqual((result['winner'], result['exhausted'], result['attempts']), (4, 4, 24))

    def test_zero_execution(self):
        self.doc['observations'] = []
        self.reject('ZERO_EXECUTION')

    def test_zero_search_budget(self):
        self.doc['attempt_budget'] = 0
        self.reject('ZERO_OR_INVALID_EXECUTION')

    def test_boolean_counts_are_not_integers(self):
        self.doc['samples_per_case_target'] = True
        self.reject('ZERO_OR_INVALID_EXECUTION')

    def test_unknown_cpu_or_wall_is_not_zero(self):
        self.doc['observations'][0]['total_elapsed_ns'] = None
        self.reject('COST_VALUES')

    def test_boolean_search_ordinal_is_rejected(self):
        self.doc['observations'][0]['outcomes'][0]['search_index'] = False
        self.reject('SEARCH_ORDER')

    def test_scope_cannot_be_promoted(self):
        self.doc['public_service_measured'] = True
        self.reject('SCOPE_PROMOTION')

    def test_missing_arm(self):
        self.doc['observations'].pop()
        self.reject('ARM_INVENTORY')

    def test_duplicate_arm(self):
        self.doc['observations'].append(copy.deepcopy(self.doc['observations'][0]))
        self.reject('ARM_INVENTORY')

    def test_missing_cohort(self):
        del self.doc['observations'][2:]
        self.reject('MISSING_COHORT')

    def test_missing_search(self):
        self.doc['observations'][0]['outcomes'].pop()
        self.reject('MISSING_SEARCH')

    def test_changed_stream_not_just_winner(self):
        self.doc['observations'][0]['outcomes'][1]['proof_stream_commitment'] = 'ab'*32
        self.reject('DIFFERENT_PROOF_OR_TICKET_STREAM')

    def test_changed_task_under_one_class(self):
        self.doc['observations'][0]['task'] = '22'*32
        self.reject('TASK_CONTEXT_DRIFT')

    def test_relabelled_rank(self):
        self.doc['observations'][0]['rank_a'] = 65
        self.reject('RANK_VALUES')

    def test_exhaustion_keeps_entire_budget(self):
        self.doc['observations'][0]['outcomes'][1]['attempts'] = 3
        self.reject('EXHAUSTION_COUNT')

    def test_exhaustion_has_no_winner(self):
        self.doc['observations'][0]['outcomes'][1]['winning_challenge'] = 'cc'*32
        self.reject('EXHAUSTION_WINNER')

    def test_setup_cannot_be_erased(self):
        self.doc['observations'][0]['setup_observations_ns'] = []
        self.reject('SETUP_COUNT')

    def test_cohort_sum_includes_setup(self):
        self.doc['observations'][0]['total_elapsed_ns'] = 10
        self.reject('COST_SUM')

    def test_modes_cannot_claim_free_reuse(self):
        row = self.doc['observations'][0]
        row.update(setup_calls=1, setup_observations_ns=[21])
        self.reject('SETUP_MODE')

    def test_invocation_order_is_a_permutation(self):
        self.doc['observations'][1]['invocation_order'] = 0
        self.reject('INVOCATION_ORDER')

    def test_external_plan_binds_actual_command(self):
        with self.assertRaisesRegex(ValueError, 'COMMAND_OUTPUT_MISMATCH'):
            producer_observations(self.doc, self.arms, {'seed': 8})

    def test_unsupported_still_keeps_constructor_calls_and_each_outcome(self):
        for row in self.doc['observations']:
            if row['strategy'] != 'structured':
                continue
            row.update(method='unsupported', search_elapsed_ns=0, total_elapsed_ns=12)
            for item in row['outcomes']:
                item.update(status='unsupported', attempts=0, search_elapsed_ns=0)
                for key in ('ticket_stream_commitment', 'proof_stream_commitment',
                            'winning_challenge', 'winner_proof_commitment',
                            'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns',
                            'reference_verifier_first'):
                    item[key] = None
        result = producer_observations(self.doc, self.arms)
        self.assertEqual(result['unsupported'], 4)
        self.doc['observations'][1]['outcomes'][0]['attempts'] = 1
        self.reject('UNSUPPORTED_OUTCOME')

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            json_load('{"result":false,"result":true}')

    def test_nan_rejected(self):
        with self.assertRaisesRegex(ValueError, 'NONFINITE_JSON'):
            json_load('{"cpu_ns":NaN}')


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.source={'tested_commit':'a'*40, 'tested_tree':'b'*40}
        self.identity={'commit':'a'*40,'tree':'b'*40,'tracked_worktree_verified':True}
        self.manifest={'source_before':self.identity.copy(), 'source_after':self.identity.copy()}

    def test_older_schema_uses_both_actual_identities(self):
        validate_source_manifest(self.manifest,self.source)

    def test_identity_drift_cannot_hide_behind_missing_flag(self):
        self.manifest['source_after']['tree']='c'*40
        with self.assertRaisesRegex(ValueError,'MANIFEST_SOURCE_DRIFT'):
            validate_source_manifest(self.manifest,self.source)

    def test_source_flag_and_external_binding_are_not_optional(self):
        self.manifest['source_changed']=True
        with self.assertRaisesRegex(ValueError,'MANIFEST_SOURCE_CHANGED'):
            validate_source_manifest(self.manifest,self.source)
        self.manifest['source_changed']=False
        self.source['tested_commit']='c'*40
        with self.assertRaisesRegex(ValueError,'MANIFEST_SOURCE_BINDING'):
            validate_source_manifest(self.manifest,self.source)


class ChildOwnershipTests(unittest.TestCase):
    def test_actual_cpu_success_stdout_stderr_and_no_zero_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)/'child'
            result = run_child([sys.executable, '-c',
                'import sys; print(sum(x*x for x in range(100000))); print("err",file=sys.stderr)'], folder)
            self.assertEqual(result['exit_code'], 0)
            self.assertFalse(result['timed_out'])
            self.assertGreater(result['cpu_ns'], 0)
            self.assertEqual(result['cpu_ns'], result['user_cpu_ns']+result['system_cpu_ns'])
            self.assertGreater(result['max_rss_kib'], 0)
            self.assertTrue((folder/'process.json').exists())

    def test_nonzero_status_is_retained_not_passed(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)/'child'
            result = run_child([sys.executable, '-c', 'print("before failure"); raise SystemExit(7)'], folder)
            self.assertEqual(result['exit_code'], 7)
            self.assertIn('before failure', (folder/'stdout').read_text())

    def test_timeout_is_killed_reaped_and_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)/'child'
            result = run_child([sys.executable, '-c', 'import time; print("started",flush=True); time.sleep(10)'],
                               folder, timeout=0.15)
            self.assertTrue(result['timed_out'])
            self.assertEqual(result['exit_code'], -9)
            # A timeout may kill before Python starts: empty output is retained,
            # not evidence of successful execution or a lost record.
            self.assertTrue((folder/'stdout').exists())
            self.assertTrue((folder/'process.json').exists())

    def test_old_output_is_never_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)/'child'; folder.mkdir()
            (folder/'stdout').write_text('retained old data')
            with self.assertRaises(FileExistsError):
                run_child([sys.executable, '-c', 'print("new")'], folder)
            self.assertEqual((folder/'stdout').read_text(), 'retained old data')


if __name__ == '__main__':
    # Keep the existing repository lane entry; imported controls simulate the
    # source-build driver and never claim that a Rust process ran.
    from test_run_from_zero_native import BinarySelectionTests, ExecutionBoundaryTests
    unittest.main(verbosity=2)
