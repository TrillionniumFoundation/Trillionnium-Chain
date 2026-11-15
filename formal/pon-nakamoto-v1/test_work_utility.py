"""Duplicate A/B, branch replay, adoption and complete reported-cost accounting."""
from __future__ import annotations
from fractions import Fraction
import unittest
from work_utility import UniqueUsefulOutputAccounting, measured_cost, STAGES
from contract_wire import H


def identity(value):
    return H('utility-test', value.encode()).hex()


class UsefulOutputTests(unittest.TestCase):
    def setUp(self):
        self.branch = identity('branch')
        self.observer = UniqueUsefulOutputAccounting(context=identity('task-contract'), current_branch=self.branch)

    def attempt(self, name='a', *, branch=None, task='same-task', output='same-output', partition='evaluation_a', costs=True, gain=Fraction(1,2), accepted=True):
        attempt = identity(name)
        key = self.observer.begin_attempt(attempt=attempt, branch=self.branch if branch is None else branch,
            task_content=identity(task), output_content=identity(output), function_fingerprint=identity('adapter'+name),
            source=identity('source'+name), partition=partition)
        if costs:
            for stage in STAGES:
                self.observer.record_cost(attempt, stage, observer='controlled-process-clock',
                    cost=measured_cost(cpu_ns=10, wall_ns=20, operations=30, gpu_ns=None))
        self.observer.finish_verification(attempt, accepted=accepted, quality_gain=gain, outcome='observed')
        return attempt, key

    def adopt(self, attempt, operation='consume', output='same-output'):
        return self.observer.adopt_output(attempt, consumer_operation=identity(operation),
            consumer=identity('ordinary-consumer'), observed_output=identity(output))

    def test_verification_alone_is_not_actual_downstream_adoption(self):
        self.attempt()
        result = self.observer.snapshot()
        self.assertEqual(result['verified_useful_unique_outputs'], 1)
        self.assertEqual(result['unique_useful_outputs_actually_adopted'], 0)
        self.assertEqual(result['accepted_but_unadopted_unique_outputs'], 1)

    def test_duplicate_AB_wrapper_new_signer_nonce_and_function_do_not_add_useful_output(self):
        first, key = self.attempt('a', partition='evaluation_a')
        second, other = self.attempt('b', partition='evaluation_b')
        self.assertEqual(key, other)
        self.adopt(first, 'operation-a'); self.adopt(second, 'operation-b')
        result = self.observer.snapshot()
        self.assertEqual(result['unique_useful_outputs_actually_adopted'], 1)
        self.assertEqual(result['downstream_adoption_events'], 2)
        self.assertEqual(result['repeated_output_attempts'], 1)
        self.assertEqual(result['cost_records'], 8)
        self.assertEqual(result['cost_totals']['cpu_ns'], 80)

    def test_stale_verified_attempt_cannot_be_adopted_but_all_costs_remain(self):
        attempt, _ = self.attempt(branch=identity('stale'))
        with self.assertRaisesRegex(ValueError, 'UTILITY_STALE_BRANCH'): self.adopt(attempt)
        result = self.observer.snapshot()
        self.assertEqual(result['stale_attempts'], 1)
        self.assertEqual(result['unique_useful_outputs_actually_adopted'], 0)
        self.assertEqual(result['cost_totals']['operations'], 120)

    def test_reorg_does_not_erase_prior_adoption_or_cost_history(self):
        attempt, _ = self.attempt(); self.adopt(attempt)
        old_events = self.observer.events
        self.observer.reorganize(new_branch=identity('new-branch'), active_branches=[identity('new-branch')])
        result = self.observer.snapshot()
        self.assertEqual(result['unique_useful_outputs_actually_adopted'], 1)
        self.assertEqual(result['currently_valid_unique_useful_outputs'], 0)
        self.assertEqual(result['cost_totals']['cpu_ns'], 40)
        self.assertEqual(self.observer.events[:len(old_events)], old_events)
        with self.assertRaisesRegex(ValueError, 'UTILITY_STALE_BRANCH'): self.adopt(attempt, 'new-operation')

    def test_same_output_reexecution_on_new_branch_cannot_double_historical_credit(self):
        first, _ = self.attempt(); self.adopt(first)
        new = identity('new')
        self.observer.reorganize(new_branch=new, active_branches=[new])
        retried, _ = self.attempt('retry', branch=new, partition='evaluation_b'); self.adopt(retried, 'retry-use')
        result = self.observer.snapshot()
        self.assertEqual(result['unique_useful_outputs_actually_adopted'], 1)
        self.assertEqual(result['currently_valid_unique_useful_outputs'], 1)
        self.assertEqual(result['attempts'], 2)
        self.assertEqual(result['cost_totals']['cpu_ns'], 80)

    def test_zero_and_negative_gain_cannot_be_relabelled_useful(self):
        for name, gain in [('zero', Fraction()), ('negative', Fraction(-1,2))]:
            attempt, _ = self.attempt(name, gain=gain)
            with self.assertRaisesRegex(ValueError, 'UTILITY_NOT_USEFUL'): self.adopt(attempt, name)
        self.assertEqual(self.observer.snapshot()['unique_useful_outputs_actually_adopted'], 0)

    def test_rejected_attempt_costs_are_not_dropped(self):
        attempt, _ = self.attempt(accepted=False)
        with self.assertRaisesRegex(ValueError, 'UTILITY_NOT_USEFUL'): self.adopt(attempt)
        self.assertEqual(self.observer.snapshot()['rejected_attempts'], 1)
        self.assertEqual(self.observer.snapshot()['cost_totals']['cpu_ns'], 40)

    def test_missing_cost_stage_blocks_adoption_and_unknown_gpu_is_not_zero(self):
        attempt, _ = self.attempt(costs=False)
        self.observer.record_cost(attempt, 'quality', observer='clock', cost=measured_cost(cpu_ns=2, wall_ns=3, operations=4))
        with self.assertRaisesRegex(ValueError, 'UTILITY_INCOMPLETE_COSTS'): self.adopt(attempt)
        result = self.observer.snapshot()
        self.assertIsNone(result['cost_totals']['gpu_ns'])
        self.assertEqual(result['cost_records_with_unknown_gpu'], 1)
        self.assertEqual(result['attempts_with_incomplete_required_costs'], 1)

    def test_changed_output_or_reused_consumer_operation_reject(self):
        attempt, _ = self.attempt()
        with self.assertRaisesRegex(ValueError, 'UTILITY_OUTPUT_BINDING'): self.adopt(attempt, output='forged')
        self.adopt(attempt)
        with self.assertRaisesRegex(ValueError, 'UTILITY_CONSUMER_REPLAY'): self.adopt(attempt)

    def test_attempt_and_verification_replay_cannot_reset_costs(self):
        attempt, _ = self.attempt()
        with self.assertRaisesRegex(ValueError, 'UTILITY_ATTEMPT_REPLAY'): self.attempt()
        with self.assertRaisesRegex(ValueError, 'UTILITY_VERIFICATION_REPLAY'):
            self.observer.finish_verification(attempt, accepted=True, quality_gain=Fraction(1), outcome='retry')
        self.assertEqual(self.observer.snapshot()['cost_records'], 4)

    def test_cost_retry_stages_charge_every_invocation(self):
        attempt, _ = self.attempt()
        self.observer.record_cost(attempt, 'proof', observer='clock', cost=measured_cost(cpu_ns=9, wall_ns=10, operations=11, gpu_ns=0))
        result = self.observer.snapshot()
        self.assertEqual(result['cost_totals']['cpu_ns'], 49)
        self.assertEqual(result['cost_stages']['proof'], 2)
        self.assertIsNone(result['cost_totals']['gpu_ns'])

    def test_unknown_numeric_aliases_and_unbounded_histories_reject(self):
        for bad in [True, -1, 1.5, 1 << 63]:
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'UTILITY_COST'):
                measured_cost(cpu_ns=bad, wall_ns=0, operations=0)
        with self.assertRaisesRegex(ValueError, 'UTILITY_GAIN'): self.attempt(gain=1.0)
        bounded = UniqueUsefulOutputAccounting(context=identity('context'), current_branch=self.branch, max_attempts=1)
        kwargs = dict(branch=self.branch, task_content=identity('t'), output_content=identity('o'),
                      function_fingerprint=identity('f'), source=identity('s'), partition='evaluation')
        bounded.begin_attempt(attempt=identity('one'), **kwargs)
        with self.assertRaisesRegex(ValueError, 'UTILITY_ATTEMPT_LIMIT'): bounded.begin_attempt(attempt=identity('two'), **kwargs)

    def test_returned_events_cannot_mutate_retained_adoption_history(self):
        attempt, _ = self.attempt(); self.adopt(attempt)
        before = self.observer.snapshot(); exposed = self.observer.events; exposed.clear()
        self.assertEqual(self.observer.snapshot(), before)

    def test_invalid_reorg_leaves_accepted_history_intact(self):
        self.attempt(); before = self.observer.snapshot()
        with self.assertRaisesRegex(ValueError, 'UTILITY_BRANCHES'):
            self.observer.reorganize(new_branch=identity('new'), active_branches=[self.branch])
        self.assertEqual(self.observer.snapshot(), before)

    def test_total_cost_overflow_rejects_without_losing_existing_history(self):
        attempt, _ = self.attempt(costs=False)
        cost = measured_cost(cpu_ns=(1<<63)-1, wall_ns=0, operations=0)
        self.observer.record_cost(attempt, 'proof', observer='bounded-meter', cost=cost)
        self.observer.record_cost(attempt, 'proof', observer='bounded-meter', cost=cost)
        before = self.observer.events
        with self.assertRaisesRegex(ValueError, 'UTILITY_TOTAL_COST_LIMIT'):
            self.observer.record_cost(attempt, 'proof', observer='bounded-meter', cost=cost)
        self.assertEqual(self.observer.events, before)


if __name__ == '__main__':
    unittest.main()
