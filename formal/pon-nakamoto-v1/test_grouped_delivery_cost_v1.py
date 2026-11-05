"""Complete arithmetic checks and failure-denominator controls, not native evidence."""
import copy
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

import numpy as np

from contract_wire import canonical
from experiments import grouped_cell_operator_v0 as relation
from experiments import grouped_delivery_cost_v1 as delivery
from test_grouped_cell_operator_v0 import fixture


class DeliveryCostTests(unittest.TestCase):
    def test_both_producers_equal_independent_scalar_all_states_and_shapes(self):
        for size in (1, 4, 16, 64):
            model, rows, _ = fixture(size)
            expected = relation.scalar_product(model, rows)
            for arm in delivery.ARMS:
                with self.subTest(size=size, arm=arm):
                    self.assertEqual(delivery.produce(delivery.prepare_material(model, rows), arm), expected)

    def test_full_delivery_rejects_rehashed_wrong_output(self):
        model, rows, provenance = fixture(4)
        init, commands = relation.make_commands(model, rows, provenance, [4], 1, 0)
        command = commands[0]
        model_hash = relation.model_commitment(init)
        input_hash = relation.input_commitment(model_hash, command)
        for key in ('router_outputs', 'logits', 'routes', 'groups', 'predictions'):
            product = delivery.produce(delivery.prepare_material(model, rows), 'packed_grouped')
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

    @staticmethod
    def wire(init, command, product):
        model_hash = relation.model_commitment(init)
        input_hash = relation.input_commitment(model_hash, command)
        return canonical(dict(model=model_hash, input=input_hash, product=product,
            statement=relation.statement_commitment(model_hash, input_hash, command['context'], product)))

    def test_scalar_cannot_use_another_model_than_the_committed_envelope(self):
        model, rows, provenance = fixture(4)
        init, commands = relation.make_commands(model, rows, provenance, [4], 1, 0)
        command = commands[0]
        original = relation.scalar_product(model, rows)
        for matrix in ('base', 'router', 'deltas'):
            other = copy.deepcopy(model)
            if matrix == 'deltas':
                other[matrix][0][0][256] += 1
            else:
                other[matrix][0][256] += 1
            product = relation.scalar_product(other, rows)
            self.assertNotEqual(product, original)
            raw = self.wire(init, command, product)
            with self.subTest(matrix=matrix), self.assertRaisesRegex(ValueError, 'MODEL_ENVELOPE_BINDING'):
                delivery.verify_delivery(raw, init, command, other, rows)

    def test_rehashed_envelope_cannot_change_matrices_but_keep_model_artifact(self):
        model, rows, provenance = fixture(4)
        init, commands = relation.make_commands(model, rows, provenance, [4], 1, 0)
        changed = copy.deepcopy(init)
        changed['base'][0][256] += 1
        product = relation.scalar_product(changed, rows)
        raw = self.wire(changed, commands[0], product)
        with self.assertRaisesRegex(ValueError, 'MODEL_ENVELOPE_BINDING'):
            delivery.verify_delivery(raw, changed, commands[0], model, rows)
        changed = copy.deepcopy(init)
        changed['model_version'] = '0' * 64
        product = relation.scalar_product(model, rows)
        with self.assertRaisesRegex(ValueError, 'MODEL_ENVELOPE_BINDING'):
            delivery.verify_delivery(self.wire(changed, commands[0], product), changed, commands[0], model, rows)

    def test_scalar_cannot_use_another_order_id_or_feature_than_the_command(self):
        model, rows, provenance = fixture(4)
        init, commands = relation.make_commands(model, rows, provenance, [4], 1, 0)
        for mutation in ('feature', 'id', 'order', 'count'):
            other = copy.deepcopy(rows)
            if mutation == 'feature':
                other[0]['x'][3] = 1
            elif mutation == 'id':
                other[0]['id'] = '0' * 64
            elif mutation == 'order':
                other.reverse()
            else:
                other.pop()
            raw = self.wire(init, commands[0], relation.scalar_product(model, other))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'INPUT_ENVELOPE_BINDING'):
                delivery.verify_delivery(raw, init, commands[0], model, other)

    def test_context_scope_and_request_time_stay_in_the_input_commitment(self):
        model, rows, provenance = fixture(4)
        init, commands = relation.make_commands(model, rows, provenance, [4], 1, 0)
        product = relation.scalar_product(model, rows)
        raw = self.wire(init, commands[0], product)
        for key in ('context', 'scope', 'arrival_ns', 'deadline_ns'):
            command = copy.deepcopy(commands[0])
            if key == 'context':
                command['context']['challenge'] = '0' * 64
            elif key == 'scope':
                command['requests'][0][key] = '0' * 64
            elif key == 'arrival_ns':
                command['requests'][0][key] = 1
            else:
                command['requests'][0][key] -= 1
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'DELIVERY_IDENTITY'):
                delivery.verify_delivery(raw, init, command, model, rows)

    def test_source_booleans_and_coerced_prepared_arrays_are_rejected(self):
        model, rows, _ = fixture(4)
        changed = copy.deepcopy(model)
        changed['base'][0][0] = True
        with self.assertRaisesRegex(ValueError, 'NUMERIC'):
            delivery.prepare_material(changed, rows)
        changed_rows = copy.deepcopy(rows)
        changed_rows[0]['x'][3] = False
        with self.assertRaisesRegex(ValueError, 'INPUT_RANGE'):
            delivery.prepare_material(model, changed_rows)
        for position in range(3):
            for dtype in (np.bool_, np.float64, object):
                prepared = list(delivery.prepare_material(model, rows))
                prepared[position] = prepared[position].astype(dtype)
                for arm in delivery.ARMS:
                    with self.subTest(position=position, dtype=dtype, arm=arm), self.assertRaisesRegex(
                            ValueError, 'MATERIAL_INTEGER_TYPE'):
                        delivery.produce(tuple(prepared), arm)

    def test_plan_counterbalances_without_minting_request_demand(self):
        cases = delivery.plan([1, 4], 2)
        self.assertEqual([c['arm'] for c in cases], list(delivery.ARMS) * 2 + list(delivery.ARMS[::-1]) * 2)
        result = delivery.summarize(cases, [], budget_ns=30)
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
        result = delivery.summarize(cases, rows, budget_ns=30)
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
                delivery.summarize(cases, rows, budget_ns=30)

    def test_duplicate_or_reassigned_observation_refuses(self):
        cases = delivery.plan([1], 1)
        row = self.observation(cases[0])
        with self.assertRaisesRegex(ValueError, 'OBSERVATION_IDENTITY'):
            delivery.summarize(cases, [row, row], budget_ns=30)
        row['arm'] = 'packed_grouped'
        with self.assertRaisesRegex(ValueError, 'OBSERVATION_PLAN_BINDING'):
            delivery.summarize(cases, [row], budget_ns=30)

    def test_complete_pair_reports_only_whole_local_cost(self):
        cases = delivery.plan([1], 1)
        rows = [self.observation(c) for c in cases]
        rows[1]['cpu_ns'] = 9
        report = delivery.summarize(cases, rows, budget_ns=30)['by_batch_size'][0]
        self.assertEqual(report['packed_over_direct_total_cpu_median'], 1.5)
        self.assertTrue(report['paired_complete_quality_and_local_deadline'])

    def test_deadline_cannot_be_claimed_or_changed_for_one_arm(self):
        cases = delivery.plan([1], 1)
        rows = [self.observation(c) for c in cases]
        rows[0]['wall_ns'] = 30
        with self.assertRaisesRegex(ValueError, 'DEADLINE_READBACK'):
            delivery.summarize(cases, rows, budget_ns=30)
        rows = [self.observation(c) for c in cases]
        rows[1]['original_budget_ns'] = 31
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_BUDGET'):
            delivery.summarize(cases, rows, budget_ns=30)

    def test_both_arms_cannot_extend_the_frozen_budget(self):
        cases = delivery.plan([1], 1)
        rows = [self.observation(c) for c in cases]
        for row in rows:
            row.update(wall_ns=40, original_budget_ns=60, deadline_met=True)
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_BUDGET'):
            delivery.summarize(cases, rows, budget_ns=30)
        with self.assertRaises(TypeError):
            delivery.summarize(cases, rows)
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_BUDGET'):
            delivery.summarize(cases, rows, budget_ns=True)

    def test_success_requires_exact_input_and_product_digests(self):
        cases = delivery.plan([1], 1)
        for field in ('input_identity', 'product_sha256'):
            for invalid in (None, True, 'A' * 64, 'a' * 63):
                rows = [self.observation(c) for c in cases]
                for row in rows:
                    row[field] = invalid
                with self.subTest(field=field, invalid=invalid), self.assertRaisesRegex(ValueError, 'SUCCESS_IDENTITY'):
                    delivery.summarize(cases, rows, budget_ns=30)

    def test_boolean_case_binding_and_truncated_plan_refuse(self):
        cases = delivery.plan([1], 1)
        rows = [self.observation(c) for c in cases]
        rows[0]['repeat'] = False
        with self.assertRaisesRegex(ValueError, 'OBSERVATION_PLAN_BINDING'):
            delivery.summarize(cases, rows, budget_ns=30)
        with self.assertRaisesRegex(ValueError, 'PLAN_LAYOUT'):
            delivery.summarize(cases[:1], rows[:1], budget_ns=30)

    def test_zero_cpu_keeps_all_cases_without_crashing_or_selecting_ratios(self):
        for zeroes in ((0,), (1,), (0, 1, 2, 3)):
            cases = delivery.plan([1], 2)
            rows = [self.observation(c) for c in cases]
            for index in zeroes:
                rows[index]['cpu_ns'] = 0
            summary = delivery.summarize(cases, rows, budget_ns=30)
            self.assertEqual(summary['observed_cases'], 4)
            group = summary['by_batch_size'][0]
            self.assertTrue(group['paired_complete_quality_and_local_deadline'])
            self.assertFalse(group['paired_cpu_comparison_complete'])
            self.assertEqual(len(group['paired_cpu_ratio_records']), 2)
            for field in ('packed_over_direct_total_cpu_median', 'paired_total_cpu_ratio_range',
                          'aggregate_packed_over_direct_cpu'):
                self.assertIsNone(group[field])

    def test_sources_include_actual_transitive_modules_and_loaded_configuration(self):
        source = delivery.source_snapshot()
        for name in delivery.REQUIRED_MODULES:
            path = str(delivery.FORMAL_ROOT.joinpath(*name.split('.')).with_suffix('.py'))
            self.assertEqual(source['module_paths'][name], path)
            self.assertIn(path, source['files_sha256'])
        for name in ('ledger-v1.json', 'work-profile-v1.json', 'model-family-v1.json', 'devnet-v1.json'):
            self.assertIn(str(delivery.REPOSITORY_ROOT / 'config/pon' / name), source['files_sha256'])
        self.assertEqual(delivery.verify_source_snapshot(source), source)

    def test_wrong_module_path_and_changed_dependency_or_configuration_refuse(self):
        before = delivery.source_snapshot()
        with patch.object(relation, '__file__', str(Path(relation.__file__).with_name('different.py'))):
            with self.assertRaisesRegex(ValueError, 'SOURCE_MODULE_PATH'):
                delivery.verify_source_snapshot(before)
        read = Path.read_bytes
        for target in (delivery.FORMAL_ROOT / 'experiments/shared_cell_operator_v1.py',
                       delivery.REPOSITORY_ROOT / 'config/pon/model-family-v1.json'):
            def changed(path):
                return read(path) + (b'\nchanged' if path == target else b'')
            with patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(ValueError, 'SOURCE_DRIFT'):
                    delivery.verify_source_snapshot(before)
        added = ModuleType('unexpected_delivery_dependency')
        added.__file__ = str(delivery.FORMAL_ROOT / 'work_oracle.py')
        with patch.dict(sys.modules, {added.__name__: added}):
            with self.assertRaisesRegex(ValueError, 'SOURCE_DRIFT'):
                delivery.verify_source_snapshot(before)

    def test_bad_plan_and_unknown_arm_refuse(self):
        for sizes, repetitions in (([], 1), ([True], 1), ([65], 1), ([4, 1], 1), ([1], 0)):
            with self.assertRaises(ValueError):
                delivery.plan(sizes, repetitions)
        with self.assertRaisesRegex(ValueError, 'ARM'):
            delivery.produce(None, 'silently-optimized')


if __name__ == '__main__':
    unittest.main()
