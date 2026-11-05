"""Complete arithmetic checks and failure-denominator controls, not native evidence."""
import unittest

from contract_wire import canonical
from experiments import grouped_cell_operator_v0 as relation
from experiments import grouped_delivery_cost_v1 as delivery
from experiments.shared_cell_operator_v1 import prepare_numpy
from test_grouped_cell_operator_v0 import fixture


class DeliveryCostTests(unittest.TestCase):
    def test_both_producers_equal_independent_scalar_all_states_and_shapes(self):
        for size in (1, 4, 16, 64):
            model, rows, _ = fixture(size)
            expected = relation.scalar_product(model, rows)
            for arm in delivery.ARMS:
                with self.subTest(size=size, arm=arm):
                    self.assertEqual(delivery.produce(prepare_numpy(model, rows), arm), expected)

    def test_full_delivery_rejects_rehashed_wrong_output(self):
        model, rows, provenance = fixture(4)
        init, commands = relation.make_commands(model, rows, provenance, [4], 1, 0)
        command = commands[0]
        model_hash = relation.model_commitment(init)
        input_hash = relation.input_commitment(model_hash, command)
        for key in ('router_outputs', 'logits', 'routes', 'groups', 'predictions'):
            product = delivery.produce(prepare_numpy(model, rows), 'packed_grouped')
            if key in ('router_outputs', 'logits'):
                product[key][0][0] += 1
            elif key == 'groups':
                product[key][0].reverse()
            else:
                product[key][0] = (product[key][0] + 1) % 3
            raw = canonical(dict(model=model_hash, input=input_hash, product=product,
                statement=relation.statement_commitment(model_hash, input_hash, command['context'], product)))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'COMPLETE_RELATION'):
                delivery.verify_delivery(raw, init, command, model, rows)

    def test_plan_counterbalances_without_minting_request_demand(self):
        cases = delivery.plan([1, 4], 2)
        self.assertEqual([c['arm'] for c in cases], list(delivery.ARMS) * 2 + list(delivery.ARMS[::-1]) * 2)
        result = delivery.summarize(cases, [])
        self.assertEqual(result['planned_cases'], 8)
        self.assertEqual(result['planned_request_occurrences'], 20)
        self.assertEqual(result['distinct_retrospective_input_rows'], 4)
        self.assertEqual(result['missing_indices'], list(range(8)))

    @staticmethod
    def observation(case, *, late=False, failed=False):
        return dict(case, wall_ns=40 if late else 10, cpu_ns=6,
                    original_budget_ns=30,
                    quality_exact=not failed, deadline_met=not (late or failed),
                    input_identity='a' * 64, product_sha256='b' * 64)

    def test_failure_lateness_and_missing_case_remain_in_denominator(self):
        cases = delivery.plan([4], 2)
        rows = [self.observation(cases[0]), self.observation(cases[1], late=True),
                self.observation(cases[2], failed=True)]
        result = delivery.summarize(cases, rows)
        self.assertEqual(result['planned_request_occurrences'], 16)
        self.assertEqual(result['observed_cases'], 3)
        self.assertEqual(result['missing_indices'], [3])
        group = result['by_batch_size'][0]
        self.assertIsNone(group['packed_over_direct_total_cpu_median'])
        self.assertEqual(group['arms']['packed_grouped']['cpu_ns_all_observed'], 12)

    def test_paired_quality_or_input_change_forbids_ratio(self):
        cases = delivery.plan([4], 1)
        for field in ('input_identity', 'product_sha256'):
            rows = [self.observation(c) for c in cases]
            rows[1][field] = 'c' * 64
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'PAIRED_INPUT_OR_QUALITY_CHANGED'):
                delivery.summarize(cases, rows)

    def test_duplicate_or_reassigned_observation_refuses(self):
        cases = delivery.plan([1], 1)
        row = self.observation(cases[0])
        with self.assertRaisesRegex(ValueError, 'OBSERVATION_IDENTITY'):
            delivery.summarize(cases, [row, row])
        row['arm'] = 'packed_grouped'
        with self.assertRaisesRegex(ValueError, 'OBSERVATION_PLAN_BINDING'):
            delivery.summarize(cases, [row])

    def test_complete_pair_reports_only_whole_local_cost(self):
        cases = delivery.plan([1], 1)
        rows = [self.observation(c) for c in cases]
        rows[1]['cpu_ns'] = 9
        report = delivery.summarize(cases, rows)['by_batch_size'][0]
        self.assertEqual(report['packed_over_direct_total_cpu_median'], 1.5)
        self.assertTrue(report['paired_complete_quality_and_local_deadline'])

    def test_deadline_cannot_be_claimed_or_changed_for_one_arm(self):
        cases = delivery.plan([1], 1)
        rows = [self.observation(c) for c in cases]
        rows[0]['wall_ns'] = 30
        with self.assertRaisesRegex(ValueError, 'DEADLINE_READBACK'):
            delivery.summarize(cases, rows)
        rows = [self.observation(c) for c in cases]
        rows[1]['original_budget_ns'] = 31
        with self.assertRaisesRegex(ValueError, 'PAIRED_INPUT_OR_QUALITY_CHANGED'):
            delivery.summarize(cases, rows)

    def test_bad_plan_and_unknown_arm_refuse(self):
        for sizes, repetitions in (([], 1), ([True], 1), ([65], 1), ([4, 1], 1), ([1], 0)):
            with self.assertRaises(ValueError):
                delivery.plan(sizes, repetitions)
        with self.assertRaisesRegex(ValueError, 'ARM'):
            delivery.produce(None, 'silently-optimized')


if __name__ == '__main__':
    unittest.main()
