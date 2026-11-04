"""Five-lane conservation, split-claim and external-effect fork counterexamples."""
import copy
import unittest

from contract_wire import H
from reward_budget_oracle import LANES, RewardBudgetPlanner, mining_reward_limit


def key(label):
    return H('reward-budget-test-v1', label.encode()).hex()


def capacity(lane, amount=100):
    return dict.fromkeys(LANES[lane], amount)


class RewardBudgets(unittest.TestCase):
    def setUp(self):
        self.root = key('contribution-root')
        self.book = RewardBudgetPlanner(context=key('genesis-and-owner-policy'),
            contribution_root_caps={self.root: 50}, max_records=32)

    def budget(self, lane, *, label=None, cap=100):
        label = label or lane
        source = key('funding-' + label)
        kwargs = {'fees': 7} if lane == 'mining' else {}
        amount = mining_reward_limit(1, 7) if lane == 'mining' else 200
        self.book.register_funding(source=source, lane=lane, amount=amount,
                                  height=1, **kwargs)
        budget = key('budget-' + label)
        self.book.open_budget(budget=budget, source=source, lane=lane, cap=cap,
                              maturity=21, deadline=40, resource_cap=capacity(lane))
        return budget, source

    def reserve(self, lane, budget, *, label=None, amount=20, resource_amount=30,
                beneficiary=None):
        label = label or lane
        claim = key('claim-' + label)
        self.book.reserve(claim=claim, budget=budget, subject=key('subject-' + label),
            beneficiary=beneficiary if beneficiary is not None else key('beneficiary-' + label), amount=amount,
            resource_reservation=capacity(lane, resource_amount), height=2,
            contribution_root=self.root if lane == 'contribution' else None)
        return claim

    def test_all_five_lanes_conserve_funding_and_report_distinct_resources(self):
        for lane in LANES:
            budget, source = self.budget(lane)
            claim = self.reserve(lane, budget)
            self.book.resolve(claim=claim, height=21, paid=15,
                              consumed=capacity(lane, 23), outcome='positive')
            self.book.close(budget=budget, height=40)
            self.assertEqual(self.book.resource_used(budget), capacity(lane, 23))
            self.assertEqual(self.book.branch.funding[source].available,
                             self.book.branch.funding[source].total - 15)
        report = self.book.summary()
        self.assertEqual(report['lanes'], {lane: {'cap': 100, 'paid': 15,
                         'refunded': 85, 'available': 0, 'reserved': 0} for lane in LANES})
        self.assertFalse(report['native_funding_verified'])
        self.assertFalse(report['public_reward_eligible'])
        self.assertEqual(report['additional_chainwork'], 0)

    def test_funding_identity_cannot_be_registered_twice_or_cross_fund_lanes(self):
        budget, source = self.budget('serving')
        before = copy.deepcopy(self.book.branch)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_SOURCE'):
            self.book.register_funding(source=source, lane='evaluation', amount=200, height=1)
        with self.assertRaisesRegex(ValueError, 'LANE_TRANSFER'):
            self.book.open_budget(budget=key('second'), source=source, lane='storage',
                cap=20, maturity=21, deadline=40, resource_cap=capacity('storage'))
        self.assertEqual(self.book.branch, before)

    def test_existing_mining_schedule_and_maturity_are_not_new_issuance(self):
        self.assertEqual(mining_reward_limit(0, 7), 1007)
        self.assertEqual(mining_reward_limit(100000, 7), 507)
        self.assertEqual(mining_reward_limit(6400000, 7), 7)
        with self.assertRaisesRegex(ValueError, 'MINING_SOURCE'):
            self.book.register_funding(source=key('overissue'), lane='mining',
                amount=1008, height=1, fees=7)
        budget, _ = self.budget('mining')
        claim = self.reserve('mining', budget)
        with self.assertRaisesRegex(ValueError, 'UNQUALIFIED_PAYMENT'):
            self.book.resolve(claim=claim, height=20, paid=20,
                              consumed=capacity('mining', 1), outcome='positive')
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('mining', 1), outcome='positive')
        with self.assertRaisesRegex(ValueError, 'NONMINING_ISSUANCE'):
            self.book.register_funding(source=key('fake-eval-emission'), lane='evaluation',
                                      amount=10, height=1, fees=7)

    def test_tokens_do_not_substitute_storage_or_serving_capacity(self):
        budget, _ = self.budget('storage')
        before = copy.deepcopy(self.book.branch)
        with self.assertRaisesRegex(ValueError, 'RESOURCE_KIND'):
            self.book.reserve(claim=key('wrong-unit'), budget=budget, subject=key('s'),
                beneficiary=key('b'), amount=1, resource_reservation=capacity('serving'), height=2)
        with self.assertRaisesRegex(ValueError, 'RESOURCES'):
            self.reserve('storage', budget, resource_amount=101)
        self.assertEqual(self.book.branch, before)

    def test_root_splitting_across_cells_accounts_and_budgets_does_not_raise_cap(self):
        first, _ = self.budget('contribution', label='first')
        second, _ = self.budget('contribution', label='second')
        self.reserve('contribution', first, label='cell-a', amount=30)
        before = copy.deepcopy(self.book.branch)
        with self.assertRaisesRegex(ValueError, 'ROOT_CAP'):
            self.reserve('contribution', second, label='cell-b', amount=21)
        self.assertEqual(self.book.branch, before)
        self.reserve('contribution', second, label='cell-b', amount=20)
        self.assertEqual(self.book.summary()['lanes']['contribution']['reserved'], 50)

    def test_zero_gain_unknown_and_invalid_cost_resources_but_pay_zero(self):
        for outcome in ('no-gain', 'unknown', 'invalid', 'cancelled'):
            budget, _ = self.budget('contribution', label=outcome)
            claim = self.reserve('contribution', budget, label=outcome)
            with self.assertRaisesRegex(ValueError, 'UNQUALIFIED_PAYMENT'):
                self.book.resolve(claim=claim, height=21, paid=1,
                    consumed=capacity('contribution', 20), outcome=outcome)
            self.book.resolve(claim=claim, height=21, paid=0,
                consumed=capacity('contribution', 20), outcome=outcome)
            self.assertEqual(self.book.available(budget), 100)
            self.assertEqual(self.book.resource_used(budget),
                             capacity('contribution', 20))

    def test_replayed_or_renamed_subject_cannot_claim_twice(self):
        budget, _ = self.budget('evaluation')
        claim = self.reserve('evaluation', budget)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('evaluation', 15), outcome='positive')
        with self.assertRaisesRegex(ValueError, 'ALREADY_RESOLVED'):
            self.book.resolve(claim=claim, height=21, paid=20,
                              consumed=capacity('evaluation', 15), outcome='positive')
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_CLAIM'):
            self.book.reserve(claim=key('renamed'), budget=budget,
                subject=key('subject-evaluation'), beneficiary=key('another-account'),
                amount=1, resource_reservation=capacity('evaluation', 1), height=21)

    def test_failure_and_expiry_cannot_erase_consumed_resource_cost(self):
        budget, _ = self.budget('serving')
        claim = self.reserve('serving', budget, resource_amount=70)
        self.book.resolve(claim=claim, height=21, paid=0,
                          consumed=capacity('serving', 60), outcome='invalid')
        with self.assertRaisesRegex(ValueError, 'RESOURCES'):
            self.reserve('serving', budget, label='too-much-after-failure', resource_amount=41)
        self.reserve('serving', budget, label='unknown-on-expiry', resource_amount=40)
        self.book.close(budget=budget, height=40)
        self.assertEqual(self.book.resource_used(budget), capacity('serving', 100))
        self.assertEqual(self.book.summary()['lanes']['serving']['refunded'], 100)
        with self.assertRaisesRegex(ValueError, 'CLOSED'):
            self.reserve('serving', budget, label='after-expiry')

    def test_reorg_retains_pending_and_completed_external_effect_facts(self):
        budget, _ = self.budget('serving')
        checkpoint = self.book.checkpoint()
        claim = self.reserve('serving', budget)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 20), outcome='positive')
        operation, effect = key('stable-operation'), key('exact-effect')
        self.assertEqual(self.book.prepare_external(claim=claim, operation=operation, effect=effect), 'new')
        self.book.reorg(checkpoint)
        self.assertNotIn(claim, self.book.branch.claims)
        claim = self.reserve('serving', budget)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 20), outcome='positive')
        self.assertEqual(self.book.prepare_external(claim=claim, operation=operation, effect=effect), 'pending')
        with self.assertRaisesRegex(ValueError, 'REPLAY_MISMATCH'):
            self.book.prepare_external(claim=claim, operation=key('new-operation'), effect=effect)
        self.book.finish_external(lane='serving', subject=key('subject-serving'),
                                  operation=operation, receipt=key('target-receipt'))
        self.book.reorg(checkpoint)
        claim = self.reserve('serving', budget)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 20), outcome='positive')
        self.assertEqual(self.book.prepare_external(claim=claim, operation=operation, effect=effect), 'done')
        self.assertEqual(self.book.summary()['external_intents'], 1)

    def test_unpaid_or_overrun_claim_never_opens_external_dispatch_intent(self):
        budget, _ = self.budget('storage')
        claim = self.reserve('storage', budget)
        before = copy.deepcopy(self.book.branch)
        with self.assertRaisesRegex(ValueError, 'OVERRUN'):
            self.book.resolve(claim=claim, height=21, paid=21,
                              consumed=capacity('storage', 1), outcome='positive')
        self.assertEqual(self.book.branch, before)
        with self.assertRaisesRegex(ValueError, 'NOT_SETTLED'):
            self.book.prepare_external(claim=claim, operation=key('o'), effect=key('e'))

    def test_numeric_aliases_and_oversized_record_sets_refuse(self):
        for amount in (-1, True, 1 << 64):
            with self.assertRaisesRegex(ValueError, 'UNITS'):
                self.book.register_funding(source=key('bad-number'), lane='evaluation',
                                          amount=amount, height=1)
        tiny = RewardBudgetPlanner(context=key('tiny'), contribution_root_caps={}, max_records=1)
        tiny.register_funding(source=key('one'), lane='evaluation', amount=1, height=1)
        with self.assertRaisesRegex(ValueError, 'RECORD_LIMIT'):
            tiny.register_funding(source=key('two'), lane='evaluation', amount=1, height=1)

    def test_source_overallocation_and_early_refund_are_atomic(self):
        budget, source = self.budget('evaluation')
        before = copy.deepcopy(self.book.branch)
        with self.assertRaisesRegex(ValueError, 'FUNDING_OR_WINDOW'):
            self.book.open_budget(budget=key('overallocated'), source=source,
                lane='evaluation', cap=101, maturity=21, deadline=40,
                resource_cap=capacity('evaluation'))
        with self.assertRaisesRegex(ValueError, 'NOT_DUE'):
            self.book.close(budget=budget, height=39)
        self.assertEqual(self.book.branch, before)

    def test_expired_claim_and_resource_overrun_cannot_settle(self):
        budget, _ = self.budget('serving')
        claim = self.reserve('serving', budget)
        before = copy.deepcopy(self.book.branch)
        with self.assertRaisesRegex(ValueError, 'OVERRUN'):
            self.book.resolve(claim=claim, height=21, paid=1,
                              consumed=capacity('serving', 31), outcome='positive')
        with self.assertRaisesRegex(ValueError, 'UNQUALIFIED_PAYMENT'):
            self.book.resolve(claim=claim, height=40, paid=1,
                              consumed=capacity('serving', 1), outcome='positive')
        self.assertEqual(self.book.branch, before)

    def test_existing_source_round_limit_and_global_numeric_limit(self):
        with self.assertRaisesRegex(ValueError, 'SOURCE_ROUND_CAP'):
            RewardBudgetPlanner(context=key('bad-policy'),
                contribution_root_caps={self.root: 100001}, max_records=1)
        self.book.register_funding(source=key('maximum'), lane='storage',
                                  amount=(1 << 64) - 1, height=1)
        with self.assertRaisesRegex(ValueError, 'UNITS'):
            self.book.register_funding(source=key('overflow'), lane='serving', amount=1, height=1)

    def test_changed_external_receipt_is_not_an_exact_replay(self):
        budget, _ = self.budget('serving')
        claim = self.reserve('serving', budget)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 1), outcome='positive')
        operation, effect = key('operation'), key('effect')
        self.book.prepare_external(claim=claim, operation=operation, effect=effect)
        self.book.finish_external(lane='serving', subject=key('subject-serving'),
                                  operation=operation, receipt=key('receipt'))
        with self.assertRaisesRegex(ValueError, 'RECEIPT_MISMATCH'):
            self.book.finish_external(lane='serving', subject=key('subject-serving'),
                operation=operation, receipt=key('different-receipt'))

    def test_reorg_cannot_reset_pending_or_consumed_physical_capacity(self):
        budget, _ = self.budget('serving')
        checkpoint = self.book.checkpoint()
        claim = self.reserve('serving', budget, resource_amount=70)
        self.book.reorg(checkpoint)
        self.assertEqual(self.book.summary()['orphaned_resource_jobs'], 1)
        with self.assertRaisesRegex(ValueError, 'RESOURCES'):
            self.reserve('serving', budget, label='parallel', resource_amount=31)
        self.book.reserve(claim=claim, budget=budget, subject=key('subject-serving'),
            beneficiary=key('beneficiary-serving'), amount=20,
            resource_reservation=capacity('serving', 70), height=2)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 60), outcome='positive')
        self.book.reorg(checkpoint)
        status = self.book.reserve(claim=claim, budget=budget, subject=key('subject-serving'),
            beneficiary=key('beneficiary-serving'), amount=20,
            resource_reservation=capacity('serving', 70), height=2)
        self.assertEqual(status, 'done')
        with self.assertRaisesRegex(ValueError, 'RESOURCE_REPLAY_MISMATCH'):
            self.book.resolve(claim=claim, height=21, paid=20,
                              consumed=capacity('serving', 1), outcome='positive')
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 60), outcome='positive')
        with self.assertRaisesRegex(ValueError, 'RESOURCES'):
            self.reserve('serving', budget, label='parallel', resource_amount=41)
        self.reserve('serving', budget, label='parallel', resource_amount=40)
        self.assertEqual(self.book.summary()['resource_liabilities'][budget],
                         {'used': capacity('serving', 60), 'reserved': capacity('serving', 40),
                          'cap': capacity('serving', 100)})

    def test_orphan_pending_work_keeps_cost_at_expiry_and_renamed_retry_refuses(self):
        budget, _ = self.budget('storage')
        checkpoint = self.book.checkpoint()
        self.reserve('storage', budget, resource_amount=70)
        self.book.reorg(checkpoint)
        with self.assertRaisesRegex(ValueError, 'RESOURCE_SUBJECT_REPLAY'):
            self.book.reserve(claim=key('renamed'), budget=budget, subject=key('subject-storage'),
                beneficiary=key('beneficiary-storage'), amount=20,
                resource_reservation=capacity('storage', 70), height=2)
        self.book.close(budget=budget, height=40)
        self.assertEqual(self.book.resource_used(budget), capacity('storage', 70))
        self.assertEqual(self.book.summary()['lanes']['storage']['refunded'], 100)

    def test_budget_policy_identity_survives_rollback(self):
        checkpoint = self.book.checkpoint()
        budget, source = self.budget('storage')
        self.book.reorg(checkpoint)
        with self.assertRaisesRegex(ValueError, 'SOURCE_REPLAY_MISMATCH'):
            self.book.register_funding(source=source, lane='storage', amount=201, height=1)
        self.book.register_funding(source=source, lane='storage', amount=200, height=1)
        with self.assertRaisesRegex(ValueError, 'POLICY_REPLAY_MISMATCH'):
            self.book.open_budget(budget=budget, source=source, lane='storage', cap=100,
                maturity=21, deadline=40, resource_cap=capacity('storage', 101))

    def test_global_operation_cannot_open_second_subject_or_lane_intent(self):
        budget, _ = self.budget('serving')
        claim = self.reserve('serving', budget)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 1), outcome='positive')
        operation, effect = key('one-global-operation'), key('identical-effect')
        self.assertEqual(self.book.prepare_external(claim=claim, operation=operation, effect=effect), 'new')
        self.assertEqual(self.book.prepare_external(claim=claim, operation=operation, effect=effect), 'pending')
        others = []
        for lane in ('serving', 'storage'):
            other_budget = budget if lane == 'serving' else self.budget(lane)[0]
            other = self.reserve(lane, other_budget, label='second-' + lane,
                                 beneficiary=key('beneficiary-serving'))
            self.book.resolve(claim=other, height=21, paid=20,
                              consumed=capacity(lane, 1), outcome='positive')
            before = copy.deepcopy(self.book.__dict__)
            with self.assertRaisesRegex(ValueError, 'OPERATION_REPLAY_MISMATCH'):
                self.book.prepare_external(claim=other, operation=operation, effect=effect)
            self.assertEqual(self.book.__dict__, before)
            others.append(other)
        self.book.finish_external(lane='serving', subject=key('subject-serving'),
                                  operation=operation, receipt=key('receipt'))
        self.assertEqual(self.book.prepare_external(claim=claim, operation=operation, effect=effect), 'done')
        for other in others:
            before = copy.deepcopy(self.book.__dict__)
            with self.assertRaisesRegex(ValueError, 'OPERATION_REPLAY_MISMATCH'):
                self.book.prepare_external(claim=other, operation=operation, effect=effect)
            self.assertEqual(self.book.__dict__, before)
        self.assertEqual(len(self.book._effects), 1)
        self.assertEqual(len(self.book._operations), 1)

    def test_finish_uses_global_operation_binding_and_refusal_is_atomic(self):
        budget, _ = self.budget('serving')
        for label in ('one', 'two'):
            claim = self.reserve('serving', budget, label=label)
            self.book.resolve(claim=claim, height=21, paid=20,
                              consumed=capacity('serving', 1), outcome='positive')
            self.book.prepare_external(claim=claim, operation=key('operation-' + label),
                                       effect=key('effect-' + label))
        for lane, subject, operation in (
            ('serving', key('subject-two'), key('operation-one')),
            ('storage', key('subject-one'), key('operation-one')),
            ('serving', key('subject-one'), key('unknown-operation')),
        ):
            before = copy.deepcopy(self.book.__dict__)
            with self.assertRaisesRegex(ValueError, 'RECEIPT_MISMATCH'):
                self.book.finish_external(lane=lane, subject=subject,
                                          operation=operation, receipt=key('receipt'))
            self.assertEqual(self.book.__dict__, before)
        self.book.finish_external(lane='serving', subject=key('subject-one'),
                                  operation=key('operation-one'), receipt=key('receipt'))

    def test_global_operation_binding_survives_pending_and_done_reorganizations(self):
        budget, _ = self.budget('serving')
        checkpoint = self.book.checkpoint()
        claim = self.reserve('serving', budget)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 1), outcome='positive')
        operation, effect = key('stable-operation'), key('effect')
        self.book.prepare_external(claim=claim, operation=operation, effect=effect)
        for label, expected in (('pending', 'pending'), ('done', 'done')):
            self.book.reorg(checkpoint)
            other = self.reserve('serving', budget, label=label,
                                 beneficiary=key('beneficiary-serving'))
            self.book.resolve(claim=other, height=21, paid=20,
                              consumed=capacity('serving', 1), outcome='positive')
            before = copy.deepcopy(self.book.__dict__)
            with self.assertRaisesRegex(ValueError, 'OPERATION_REPLAY_MISMATCH'):
                self.book.prepare_external(claim=other, operation=operation, effect=effect)
            self.assertEqual(self.book.__dict__, before)
            self.reserve('serving', budget)
            self.book.resolve(claim=claim, height=21, paid=20,
                              consumed=capacity('serving', 1), outcome='positive')
            self.assertEqual(self.book.prepare_external(claim=claim, operation=operation, effect=effect), expected)
            with self.assertRaisesRegex(ValueError, 'OPERATION_REPLAY_MISMATCH'):
                self.book.prepare_external(claim=claim, operation=operation, effect=key('changed-effect'))
            if expected == 'pending':
                self.book.finish_external(lane='serving', subject=key('subject-serving'),
                                          operation=operation, receipt=key('receipt'))

    def test_monotonic_operation_index_is_bounded_and_exact_retry_needs_no_slot(self):
        self.book = RewardBudgetPlanner(context=key('tiny'), contribution_root_caps={}, max_records=2)
        budget, _ = self.budget('serving')
        for label in ('one', 'two'):
            claim = self.reserve('serving', budget, label=label)
            self.book.resolve(claim=claim, height=21, paid=20,
                              consumed=capacity('serving', 1), outcome='positive')
            self.book.prepare_external(claim=claim, operation=key('operation-' + label),
                                       effect=key('effect-' + label))
        self.assertEqual(len(self.book._effects), 2)
        self.assertEqual(len(self.book._operations), 2)
        before = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'RECORD_LIMIT'):
            self.reserve('serving', budget, label='over-capacity')
        self.assertEqual(self.book.__dict__, before)
        self.assertEqual(self.book.prepare_external(claim=claim, operation=key('operation-two'),
                                                   effect=key('effect-two')), 'pending')

    def test_same_operation_cannot_rebind_changed_fork_settlement_amount(self):
        budget, _ = self.budget('serving')
        checkpoint = self.book.checkpoint()
        claim = self.reserve('serving', budget)
        self.book.resolve(claim=claim, height=21, paid=20,
                          consumed=capacity('serving', 1), outcome='positive')
        operation, effect = key('operation'), key('effect')
        self.book.prepare_external(claim=claim, operation=operation, effect=effect)
        self.book.reorg(checkpoint)
        self.reserve('serving', budget)
        self.book.resolve(claim=claim, height=21, paid=15,
                          consumed=capacity('serving', 1), outcome='positive')
        before = copy.deepcopy(self.book.__dict__)
        with self.assertRaisesRegex(ValueError, 'OPERATION_REPLAY_MISMATCH'):
            self.book.prepare_external(claim=claim, operation=operation, effect=effect)
        self.assertEqual(self.book.__dict__, before)


if __name__ == '__main__':
    unittest.main()
