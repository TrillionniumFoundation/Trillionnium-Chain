"""Run with Python; covers mathematical examples, not real neural work/security."""
import unittest
from copy import deepcopy
from reference import Branch, ChainState, LocalEffects, ReorgExample, allocate, claim, preferred, retarget, timestamp_state, work


class WorkExamples(unittest.TestCase):
    def test_exact_work_formula(self):
        self.assertEqual(work(3, 8), 64)
        self.assertEqual(work(255, 8), 1)
        self.assertEqual(work(1), 1 << 255)
    def test_target_bounds(self):
        for value in [0, -1, 256, True, 1.0]:
            with self.assertRaises(ValueError): work(value, 8)
    def test_shorter_heavier_wins(self):
        low = Branch('long-low', (9999,) * 10)
        high = Branch('short-high', (99,) * 2)
        self.assertIs(preferred(low, [high]), high)
    def test_equal_work_keeps_current(self):
        first = Branch('first', (999, 999))
        self.assertIs(preferred(first, [Branch('later', (999, 999))]), first)
    def test_invalid_heavy_does_not_win(self):
        first = Branch('valid', (9999,))
        self.assertIs(preferred(first, [Branch('bad', (1,), False)]), first)
    def test_unavailable_heavy_is_not_applied(self):
        first = Branch('valid', (9999,))
        self.assertIs(preferred(first, [Branch('header-only', (1,), True, False)]), first)
    def test_lucky_digest_not_an_input(self):
        self.assertEqual(work(12345), work(12345))
        self.assertNotIn('digest', work.__code__.co_varnames[:work.__code__.co_argcount])
    def test_initial_tip_requires_valid_candidate(self):
        self.assertIsNone(preferred(None, [Branch('invalid', (1,), False)]))
    def test_no_quality_or_stake_input(self):
        self.assertEqual(set(Branch.__dataclass_fields__), {'name','targets','abstract_valid','abstract_available'})


class DifficultyExamples(unittest.TestCase):
    def test_interval_uses_n_minus_one(self):
        self.assertEqual(retarget(1000, 0, 150, 16, 10, 10000), 1000)
    def test_fast_clamp_rounding(self):
        self.assertEqual(retarget(1000, 0, 1, 16, 10, 10000), 253)
    def test_slow_clamp(self):
        self.assertEqual(retarget(1000, 0, 100000, 16, 10, 10000), 4000)
    def test_pow_limit_and_floor(self):
        self.assertEqual(retarget(1000, 0, 100000, 16, 10, 2000), 2000)
        self.assertEqual(retarget(1, 0, 1, 16, 10, 2000), 1)
    def test_time_regression_uses_lower_clamp(self):
        self.assertEqual(retarget(1000, 100, 1, 16, 10, 10000), 253)
    def test_invalid_parameters(self):
        with self.assertRaises(ValueError): retarget(1000, 0, 1, 15, 10, 10000)
    def test_median_equal_rejects(self):
        self.assertEqual(timestamp_state(6, list(range(1,12)), 100, 10), 'invalid-median')
    def test_future_is_deferred_then_admitted(self):
        self.assertEqual(timestamp_state(200, [1,2,3], 100, 10), 'deferred-future')
        self.assertEqual(timestamp_state(200, [1,2,3], 195, 10), 'admissible')


class EconomicRecoveryExamples(unittest.TestCase):
    def test_no_gain_no_payout(self): self.assertEqual(allocate(100, [9,1], False), ([0,0],100))
    def test_zero_scores(self): self.assertEqual(allocate(100, [0,0], True), ([0,0],100))
    def test_dust_retained(self): self.assertEqual(allocate(10, [1,1,1], True), ([3,3,3],1))
    def test_conservation(self):
        for pool in range(101):
            payouts,dust=allocate(pool,[2,3,5],True);self.assertEqual(sum(payouts)+dust,pool)
    def test_bad_score(self):
        with self.assertRaises(ValueError): allocate(10,[1,-1],True)
    def test_split_root_cannot_claim_twice(self):
        state=ChainState();remaining=claim(state,'root:component','one',30,100)
        with self.assertRaises(ValueError): claim(state,'root:component','alias',30,remaining)
        self.assertEqual(state.balances,{'one':30})
    def test_unfunded_claim_has_no_mutation(self):
        state=ChainState()
        with self.assertRaises(ValueError): claim(state,'component','one',101,100)
        self.assertEqual(state,ChainState())
    def test_reorg_does_not_erase_real_effect_or_revoke(self):
        state=ChainState({'a':30},{'a':1},'expert',{'reward'})
        local=LocalEffects();local.enter('task');local.revoked.add('grant')
        reorg=ReorgExample(state);reorg.stage(ChainState({'a':0},{'a':0},'base',set()));reorg.recover()
        self.assertEqual(reorg.visible.release,'base');self.assertEqual(reorg.visible.claims,set())
        self.assertEqual(local.entered,{'task'});self.assertEqual(local.revoked,{'grant'})
        with self.assertRaises(ValueError): local.enter('task')
    def test_reorg_staging_not_visible_until_publish(self):
        r=ReorgExample(ChainState(release='old'));r.stage(ChainState(release='new'))
        self.assertEqual(r.visible.release,'old');r.recover();self.assertEqual(r.visible.release,'new')
    def test_recovery_is_idempotent(self):
        r=ReorgExample(ChainState());r.stage(ChainState(release='new'));r.recover();r.recover()
        self.assertEqual(r.generation,1)
    def test_second_reorg_owner_rejected(self):
        r=ReorgExample(ChainState());r.stage(ChainState())
        with self.assertRaises(ValueError): r.stage(ChainState())

if __name__ == '__main__': unittest.main(verbosity=2)
