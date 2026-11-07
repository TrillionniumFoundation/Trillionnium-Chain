"""Synthetic pinned-owner counterexamples; no external evaluation or native payout."""
import copy
import json
import math
import unittest
from fractions import Fraction
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from upgrade_policy import (UpgradePolicy, freeze_plan, signed_receipt, CONTROLS, MODELS,
                            COST_PARTS, FLAGS, H, canonical)


def identity(value):
    return H('upgrade-fixture-v1', str(value).encode()).hex()


def zero_costs():
    return dict.fromkeys(COST_PARTS, 0)


class UpgradePolicyTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.policy = UpgradePolicy(context=identity('context'), owner_key=public,
                                    alpha=[1, 20], bonus_cap=150)
        self.plans, self.digests = {}, {}

    def plan(self, i=0, start=0, **changes):
        parent = changes.get('parent', identity('parent'))
        p = dict(context=identity('context'), parent=parent, candidate=identity('candidate'+str(i)),
                 controls=dict(current=parent, **{m: identity(m) for m in CONTROLS[1:]}),
                 window=identity('window'+str(i)), canary_window=identity('canary-window'+str(i)),
                 data_owner=identity('data-owner'), evaluation_protocol=identity('protocol'),
                 independence_root=identity('control-registry'), producer_control=identity('producer'),
                 cost_unit=identity('frozen-budget-unit'), cost_conversion=[1, 1],
                 overhead={m: zero_costs() for m in MODELS}, utility_cap=100, cluster_cost_cap=1,
                 clusters=20, freeze_height=start, future_height=start+1, evaluate_until=start+10,
                 canary_until=start+20, margin=[0, 1], bet=[1, 2], bonus_units=100)
        p.update(changes)
        return p

    def begin(self, i=0, start=0, **changes):
        p = self.plan(i, start, **changes)
        raw, digest = freeze_plan(**p)
        attempt = self.policy.begin(raw, digest, current_parent=p['parent'], height=start)
        self.plans[attempt], self.digests[attempt] = p, digest
        return attempt

    def rows(self, attempt):
        p = self.plans[attempt]
        return [dict(cluster=identity(attempt+'cluster'+str(i)), content=identity(attempt+'bytes'+str(i)),
                     height=p['future_height'], models={m: dict(utility=100 if m == 'candidate' else 0,
                     costs=zero_costs()) for m in MODELS}) for i in range(p['clusters'])]

    def receipt(self, attempt, phase, body, height, **changes):
        p = self.plans[attempt]
        args = dict(context=p['context'], attempt=attempt, plan=self.digests[attempt], phase=phase,
                    body=body, parent=p['parent'], height=height, expires=p['canary_until'])
        if phase != 'evaluation':
            args['adoption'] = 'observed'
        args.update(changes)
        return signed_receipt(self.key, **args)

    def evaluate(self, attempt, rows=None, **conditions):
        rows = self.rows(attempt) if rows is None else rows
        p = self.plans[attempt]; height = p['evaluate_until']
        return self.policy.evaluate(attempt, rows, self.receipt(attempt, 'evaluation', rows, height, **conditions),
                                    current_parent=p['parent'], height=height)

    def canary(self, attempt, **changes):
        p = self.plans[attempt]
        observation = dict(candidate=p['candidate'], window=p['canary_window'], consumer_control=identity('consumer'),
                           operation=identity(attempt+'use'), height=p['evaluate_until']+1,
                           uses=1, net_gain=[1, 1], safety_failures=0)
        observation.update(changes)
        return observation

    def observe(self, attempt, observation=None, **conditions):
        value = self.canary(attempt) if observation is None else observation
        height = self.plans[attempt]['evaluate_until']+1
        return self.policy.observe_canary(attempt, value, self.receipt(attempt, 'canary', value, height, **conditions),
                                         current_parent=self.plans[attempt]['parent'], height=height)

    def propose(self, attempt, **conditions):
        body = self.policy.proposal_body(attempt); p = self.plans[attempt]
        height = p['evaluate_until']+2
        return self.policy.propose(attempt, self.receipt(attempt, 'proposal', body, height, **conditions),
                                   current_parent=p['parent'], height=height)

    def test_exact_evalues_and_three_stages_never_grant_native_authority(self):
        a = self.begin()
        self.assertEqual(self.evaluate(a)['status'], 'conditional-evaluation-eligible')
        measured = self.policy.observation()['events'][-1]['value']
        expected = (Fraction(1) + Fraction(50, 101))**20
        for value in measured['evalues'].values():
            self.assertEqual(Fraction(int(value[0], 16), int(value[1], 16)), expected)
        self.assertEqual(measured['per_control_alpha'], ['1', '160'])
        self.assertEqual(self.observe(a)['status'], 'conditional-canary-observed')
        result = self.propose(a)
        self.assertEqual(result['status'], 'conditional-promotion-proposal')
        self.assertEqual(result['proposed_bonus_units'], 100)
        for flag in FLAGS:
            self.assertIs(result[flag], False)
            self.assertIs(self.policy.observation()[flag], False)
        with self.assertRaisesRegex(ValueError, 'PHASE'):
            self.propose(a)

    def test_full_upfront_cost_can_reverse_apparent_accuracy_gain(self):
        overhead = {m: zero_costs() for m in MODELS}
        overhead['candidate']['compute'] = 3000
        a = self.begin(overhead=overhead)
        result = self.evaluate(a)
        self.assertEqual(result['status'], 'NoUpdate')
        self.assertEqual(result['proposed_bonus_units'], 0)
        summary = self.policy.observation()['events'][1]['value']
        self.assertEqual(summary['net_means']['current'], ['-50', '1'])

    def test_many_small_wins_do_not_establish_positive_mean_net_gain(self):
        a = self.begin(); rows = self.rows(a)
        for row in rows:
            for m in MODELS:
                row['models'][m]['utility'] = 51 if m == 'candidate' else 50
        for m in MODELS:
            rows[-1]['models'][m]['utility'] = 0 if m == 'candidate' else 100
        self.assertEqual(self.evaluate(a, rows)['status'], 'NoUpdate')
        self.assertEqual(self.policy.observation()['events'][1]['value']['net_means']['current'], ['-81', '20'])

    def test_zero_gain_and_one_stronger_control_each_block(self):
        for mode in ('all-tied', 'pooled-tied'):
            with self.subTest(mode=mode):
                self.setUp(); a = self.begin(); rows = self.rows(a)
                for row in rows:
                    for m in CONTROLS if mode == 'all-tied' else ('pooled',):
                        row['models'][m]['utility'] = 100
                self.assertEqual(self.evaluate(a, rows)['status'], 'NoUpdate')
                with self.assertRaisesRegex(ValueError, 'PHASE'):
                    self.observe(a)

    def test_failed_cancelled_attempts_spend_alpha_across_new_parents(self):
        for i, reason in enumerate(('cancelled', 'timeout', 'execution-failed')):
            a = self.begin(i, i, parent=identity('parent'+str(i)))
            self.policy.cancel(a, reason=reason, height=i)
        a = self.begin(3, 3)
        observation = self.policy.observation()
        self.assertEqual(observation['attempts'], 4)
        self.assertEqual(observation['alpha_spent'], ['1', '25'])
        self.assertEqual(observation['events'][-1]['value']['alpha'], ['1', '400'])
        self.assertEqual(observation['proposed_bonus_units'], 0)

    def test_proposal_cap_survives_new_parent_and_new_window(self):
        for i in range(2):
            a = self.begin(i, i*30, parent=identity('parent'+str(i)))
            self.assertEqual(self.evaluate(a)['status'], 'conditional-evaluation-eligible')
            self.observe(a); result = self.propose(a)
        self.assertEqual(result['status'], 'NoUpdate')
        self.assertEqual(result['reason'], 'proposal-budget-exhausted')
        self.assertEqual(self.policy.observation()['proposed_bonus_units'], 100)

    def test_missing_costs_nonfinite_values_booleans_and_alignment_refuse_atomically(self):
        a = self.begin(); pristine = self.policy.observation()
        for defect in ('missing-cost', 'unknown-cost', 'bool-cost', 'negative-cost', 'nan-utility',
                       'float-utility', 'bool-height', 'missing-control', 'excess-cost'):
            with self.subTest(defect=defect):
                rows = self.rows(a); model = rows[0]['models']['candidate']
                if defect == 'missing-cost': del model['costs']['availability']
                if defect == 'unknown-cost': model['costs']['compute'] = None
                if defect == 'bool-cost': model['costs']['compute'] = True
                if defect == 'negative-cost': model['costs']['compute'] = -1
                if defect == 'nan-utility': model['utility'] = float('nan')
                if defect == 'float-utility': model['utility'] = 100.0
                if defect == 'bool-height': rows[0]['height'] = True
                if defect == 'missing-control': del rows[0]['models']['pooled']
                if defect == 'excess-cost': model['costs']['compute'] = 2
                with self.assertRaises(ValueError):
                    self.policy.evaluate(a, rows, {}, current_parent=self.plans[a]['parent'], height=10)
                self.assertEqual(self.policy.observation(), pristine)

    def test_fixed_sample_forbids_prefix_peeking_and_second_readout(self):
        a = self.begin(); rows = self.rows(a)
        with self.assertRaisesRegex(ValueError, 'FIXED_SAMPLE'):
            self.policy.evaluate(a, rows[:-1], {}, current_parent=self.plans[a]['parent'], height=10)
        self.evaluate(a, rows)
        with self.assertRaisesRegex(ValueError, 'PHASE'):
            self.evaluate(a, rows)

    def test_same_candidate_cannot_restart_after_no_update(self):
        a = self.begin(); self.policy.cancel(a, reason='cancelled', height=0)
        with self.assertRaisesRegex(ValueError, 'CANDIDATE_REPLAY'):
            self.begin(0, 1, parent=identity('different-parent'))
        self.assertEqual(self.policy.observation()['attempts'], 1)

    def test_duplicate_and_renamed_content_holdouts_are_refused(self):
        a = self.begin(); rows = self.rows(a)
        for field in ('cluster', 'content'):
            copied = copy.deepcopy(rows); copied[1][field] = copied[0][field]
            with self.assertRaisesRegex(ValueError, 'REUSED_HOLDOUT'):
                self.evaluate(a, copied)
        self.evaluate(a, rows, independence='unknown')
        b = self.begin(1, 11); successor = self.rows(b)
        for field in ('cluster', 'content'):
            copied = copy.deepcopy(successor); copied[0][field] = rows[0][field]
            with self.assertRaisesRegex(ValueError, 'REUSED_HOLDOUT'):
                self.evaluate(b, copied)

    def test_fresh_window_is_not_just_a_new_round_label(self):
        a = self.begin(); rows = self.rows(a)
        rows[0]['height'] = 0
        with self.assertRaisesRegex(ValueError, 'FUTURE_WINDOW'):
            self.evaluate(a, rows)
        self.assertEqual(self.evaluate(a, window='unknown')['status'], 'NoUpdate')

    def test_forged_or_wrong_phase_owner_receipts_cannot_be_reused(self):
        a = self.begin(); rows = self.rows(a)
        good = self.receipt(a, 'evaluation', rows, 10)
        for field, value in (('signer', identity('other-key')), ('phase', 'canary'),
                             ('attempt', identity('another-attempt')), ('context', identity('wrong-network'))):
            bad = copy.deepcopy(good); bad['record'][field] = value
            with self.assertRaisesRegex(ValueError, 'RECEIPT_BINDING'):
                self.policy.evaluate(a, rows, bad, current_parent=self.plans[a]['parent'], height=10)
        bad = copy.deepcopy(good); bad['signature'] = '00'*64
        with self.assertRaisesRegex(ValueError, 'SIGNATURE'):
            self.policy.evaluate(a, rows, bad, current_parent=self.plans[a]['parent'], height=10)
        rows[0]['models']['candidate']['utility'] = 99
        with self.assertRaisesRegex(ValueError, 'RECEIPT_BINDING'):
            self.policy.evaluate(a, rows, good, current_parent=self.plans[a]['parent'], height=10)

    def test_signed_unknown_revoked_or_conflicted_evidence_is_no_update(self):
        for condition in ('independence', 'window', 'cost'):
            for state in ('unknown', 'revoked', 'conflict'):
                with self.subTest(condition=condition, state=state):
                    self.setUp(); a = self.begin()
                    result = self.evaluate(a, **{condition: state})
                    self.assertEqual(result['reason'], 'owner-conditions-unqualified')

    def test_receipt_expiry_future_signature_and_clock_rewind_are_refused(self):
        a = self.begin(); rows = self.rows(a)
        for issued, expiry in ((10, 9), (11, 20)):
            receipt = self.receipt(a, 'evaluation', rows, issued, expires=expiry)
            with self.assertRaisesRegex(ValueError, 'RECEIPT_TIME'):
                self.policy.evaluate(a, rows, receipt, current_parent=self.plans[a]['parent'], height=10)
        self.evaluate(a)
        with self.assertRaisesRegex(ValueError, 'HEIGHT_REWIND'):
            self.policy.cancel(a, reason='cancelled', height=9)
        self.assertEqual(self.policy.cancel(a, reason='timeout', height=21)['status'], 'NoUpdate')

    def test_stale_current_parent_blocks_evaluation_and_final_proposal(self):
        a = self.begin(); rows = self.rows(a)
        result = self.policy.evaluate(a, rows, self.receipt(a, 'evaluation', rows, 10),
                                      current_parent=identity('new-parent'), height=10)
        self.assertEqual(result['reason'], 'stale-parent')
        self.setUp(); a = self.begin(); self.evaluate(a); self.observe(a)
        body = self.policy.proposal_body(a)
        result = self.policy.propose(a, self.receipt(a, 'proposal', body, 12),
                                    current_parent=identity('new-parent'), height=12)
        self.assertEqual(result['status'], 'NoUpdate')

    def test_canary_requires_actual_declared_use_net_gain_safety_and_separate_control(self):
        for changes in ({'uses': 0}, {'net_gain': [0, 1]}, {'safety_failures': 1},
                        {'consumer_control': identity('producer')}):
            with self.subTest(changes=changes):
                self.setUp(); a = self.begin(); self.evaluate(a)
                self.assertEqual(self.observe(a, self.canary(a, **changes))['status'], 'NoUpdate')
        self.setUp(); a = self.begin(); self.evaluate(a)
        self.assertEqual(self.observe(a, adoption='unknown')['status'], 'NoUpdate')

    def test_canary_binds_candidate_window_operation_and_native_time(self):
        a = self.begin(); self.evaluate(a)
        for changes in ({'candidate': identity('other')}, {'window': self.plans[a]['window']},
                        {'uses': True}, {'height': 10}):
            with self.assertRaises(ValueError):
                self.observe(a, self.canary(a, **changes))
        self.observe(a)
        operation = self.canary(a)['operation']
        self.policy.cancel(a, reason='cancelled', height=11)
        b = self.begin(1, 12); self.evaluate(b)
        with self.assertRaisesRegex(ValueError, 'CONSUMER_REPLAY'):
            self.observe(b, self.canary(b, operation=operation))

    def test_current_revocation_after_successful_canary_still_blocks(self):
        a = self.begin(); self.evaluate(a); self.observe(a)
        result = self.propose(a, independence='revoked')
        self.assertEqual(result['status'], 'NoUpdate')
        self.assertEqual(self.policy.observation()['proposed_bonus_units'], 0)

    def test_owner_cannot_sign_future_evaluation_canary_or_proposal_events(self):
        a = self.begin(); rows = self.rows(a); rows[-1]['height'] = 8
        early = self.receipt(a, 'evaluation', rows, 7)
        before = self.policy.observation()
        with self.assertRaisesRegex(ValueError, 'RECEIPT_TIME'):
            self.policy.evaluate(a, rows, early, current_parent=self.plans[a]['parent'], height=10)
        self.assertEqual(self.policy.observation(), before)
        self.evaluate(a, rows)
        canary = self.canary(a); early = self.receipt(a, 'canary', canary, 10)
        before = self.policy.observation()
        with self.assertRaisesRegex(ValueError, 'RECEIPT_TIME'):
            self.policy.observe_canary(a, canary, early, current_parent=self.plans[a]['parent'], height=11)
        self.assertEqual(self.policy.observation(), before)
        # The use occurred at 11, but this owner records it at 12. A proposal
        # signed at 11 cannot claim to follow the retained canary observation.
        self.policy.observe_canary(a, canary, self.receipt(a, 'canary', canary, 11),
                                   current_parent=self.plans[a]['parent'], height=12)
        body = self.policy.proposal_body(a); early = self.receipt(a, 'proposal', body, 11)
        before = self.policy.observation()
        with self.assertRaisesRegex(ValueError, 'RECEIPT_TIME'):
            self.policy.propose(a, early, current_parent=self.plans[a]['parent'], height=13)
        self.assertEqual(self.policy.observation(), before)
        self.assertEqual(self.policy.propose(a, self.receipt(a, 'proposal', body, 12),
                         current_parent=self.plans[a]['parent'], height=13)['status'],
                         'conditional-promotion-proposal')

    def test_plan_is_strict_canonical_and_bound_to_external_pin(self):
        p = self.plan(); raw, expected = freeze_plan(**p)
        modified = json.loads(raw); modified['bonus_units'] = 1
        with self.assertRaisesRegex(ValueError, 'PLAN_BINDING'):
            self.policy.begin(canonical(modified), expected, current_parent=p['parent'], height=0)
        for change in ({'cost_conversion': None}, {'clusters': True}, {'bet': [2, 2]},
                       {'margin': [float('nan'), 1]}, {'future_height': 0}, {'unknown': 1}):
            with self.assertRaises(ValueError):
                freeze_plan(**dict(p, **change))
        for parent in (identity('wrong-parent'),):
            with self.assertRaisesRegex(ValueError, 'CONTEXT_OR_PARENT'):
                self.policy.begin(raw, expected, current_parent=parent, height=0)

    def test_mutable_snapshots_do_not_rewrite_alpha_or_proposal_budget(self):
        a = self.begin(); observed = self.policy.observation()
        observed['events'][0]['value']['alpha'] = ['1', '1']
        observed['results'][0]['status'] = 'conditional-promotion-proposal'
        observed['proposal_budget'] = 10**12
        self.assertEqual(self.policy.observation()['events'][0]['value']['alpha'], ['1', '40'])
        self.assertEqual(self.policy.observation()['proposal_budget'], 150)

    def test_large_exact_rationals_use_bounded_hex_encoding(self):
        a = self.begin(clusters=512, cost_conversion=[999999937, 999999929],
                       margin=[1, 999999893], bet=[999999797, 999999883])
        self.assertEqual(self.evaluate(a)['status'], 'conditional-evaluation-eligible')
        summary = self.policy.observation()['events'][1]['value']
        self.assertEqual(summary['evalue_encoding'], 'hex-rational-pair')
        self.assertGreater(len(summary['evalues']['current'][0]), 4300)
        self.assertGreater(len(canonical(self.policy.observation())), 0)

    def test_exact_fair_null_distribution_respects_the_first_attempt_error_budget(self):
        expectation, false_proposal_gate = Fraction(0), Fraction(0)
        # Enumerate all 21 sufficient-statistic outcomes of 2**20 fair paired
        # samples. This is a synthetic null, not a claim about external data.
        for wins in range(21):
            self.setUp(); a = self.begin(); rows = self.rows(a)
            for i in range(wins, 20):
                for m in MODELS:
                    rows[i]['models'][m]['utility'] = 0 if m == 'candidate' else 100
            result = self.evaluate(a, rows)
            measured = self.policy.observation()['events'][1]['value']['evalues']['current']
            observed = Fraction(int(measured[0], 16), int(measured[1], 16))
            expected = Fraction(151, 101)**wins * Fraction(51, 101)**(20-wins)
            self.assertEqual(observed, expected)
            probability = Fraction(math.comb(20, wins), 1 << 20)
            expectation += probability*observed
            if result['status'] == 'conditional-evaluation-eligible':
                false_proposal_gate += probability
        self.assertEqual(expectation, 1)
        self.assertLessEqual(false_proposal_gate, Fraction(1, 160))


if __name__ == '__main__':
    unittest.main()
