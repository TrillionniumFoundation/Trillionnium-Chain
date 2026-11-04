"""Run with Python; covers mathematical examples, not real neural work/security."""
import unittest
from copy import deepcopy
import json
from pathlib import Path
from reference import Branch, ChainState, LocalEffects, ReorgExample, allocate, claim, preferred, retarget, timestamp_state, work


def native_consensus_arithmetic_vectors():
    """Python integer expectations consumed by the actual native core tests.

    Unlike the native restoring-division comparison, this oracle does not share
    a fixed-width subtraction, carry, or shift implementation. These are local
    arithmetic checks, not work-hardness or production qualification.
    """
    maximum = (1 << 512) - 1
    target_maximum = (1 << 256) - 1
    rows = []

    def result(operation, value, **inputs):
        row = dict(operation=operation, **inputs)
        if value < 0:
            row['error'] = 'CHAINWORK_UNDERFLOW'
        elif value > maximum:
            row['error'] = 'CHAINWORK_OVERFLOW'
        else:
            row['expected'] = f'{value:0128x}'
        rows.append(row)

    for bit in (1, 63, 64, 127, 128, 191, 192, 255, 256, 319, 383, 447, 511):
        numerator = maximum - (1 << bit) + 1
        denominator = (1 << bit) + 1
        result('divide', numerator // denominator,
               left=f'{numerator:0128x}', right=f'{denominator:0128x}')
    rows.append(dict(operation='divide', left=f'{maximum:0128x}',
                     right='00' * 64, error='DIVISION_BY_ZERO'))
    for bit in range(63, 512, 64):
        left, right = (1 << (bit + 1)) - 1, 1
        result('add', left + right, left=f'{left:0128x}', right=f'{right:0128x}')
        left = 1 << bit
        result('subtract', left - right, left=f'{left:0128x}', right=f'{right:0128x}')
        result('multiply', left * ((1 << 64) - 1),
               left=f'{left:0128x}', factor=(1 << 64) - 1)
    result('subtract', -1, left='00' * 64, right=f'{1:0128x}')
    for target in (1, 2, (1 << 64) - 1, 1 << 64, (1 << 128) + 1,
                   (1 << 192) - 1, (1 << 255) - 2, (1 << 255) - 1,
                   1 << 255, target_maximum):
        result('required_work', work(target), target=f'{target:064x}')
    rows.append(dict(operation='required_work', target='00' * 32, error='TARGET'))
    for target in (1, (1 << 128) + 1, (1 << 255) - 1, target_maximum):
        for first, last in ((100, 0), (0, 38), (0, 149), (0, 150), (0, 151), (0, 601)):
            result('retarget', retarget(target, first, last, 16, 10, target_maximum),
                   target=f'{target:064x}', first=first, last=last, interval=16,
                   spacing=10, pow_limit=f'{target_maximum:064x}')
    # A 320-bit intermediate and the largest valid 4*desired time bound.
    spacing = ((1 << 64) - 1) // 60
    result('retarget', retarget(target_maximum, 0, (1 << 64) - 1, 16, spacing, target_maximum),
           target=f'{target_maximum:064x}', first=0, last=(1 << 64) - 1,
           interval=16, spacing=spacing, pow_limit=f'{target_maximum:064x}')
    return dict(schema='pon-native-consensus-integer-vectors-v1', rows=rows)


class NativeArithmeticExamples(unittest.TestCase):
    def test_native_vectors_match_independent_python_integer_arithmetic(self):
        path = Path(__file__).parent / 'vectors' / 'consensus-arithmetic-v1.json'
        self.assertEqual(json.loads(path.read_text()), native_consensus_arithmetic_vectors())


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
