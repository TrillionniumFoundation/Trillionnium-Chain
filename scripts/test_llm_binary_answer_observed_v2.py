"""Fabricated contract/trace controls; no model execution or gain evidence."""
import copy
import math
from pathlib import Path
import time
import unittest
from unittest.mock import patch

import llm_binary_answer_observed_v2 as binary
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_pilot as runtime
import test_llm_runtime_parent_step_v2 as original_tests


class BinaryObservedV2Tests(unittest.TestCase):
    def setUp(self):
        self.original = original_tests.ParentStepV2Tests()
        self.original.setUp()
        self.addCleanup(self.original.doCleanups)
        self.value = copy.deepcopy(self.original.value)
        self.value.update(schema=binary.SCHEMA, source=v2.sources(binary.PROFILE))
        self.value['initial_setup']['profile'] = binary.PROFILE
        self.path = self.original.root / 'binary-plan-v2.json'
        self.plan = binary.plan_record(self.value)
        self.freeze(self.plan)

    def freeze(self, plan):
        runtime.save(self.path, plan)
        self.value['initial_setup']['binary_plan'] = dict(path=str(self.path), sha256=runtime.file_sha(self.path))

    def arguments(self):
        args = self.original.arguments(self.value)
        args.initial_setup_profile = binary.PROFILE
        args.binary_plan = str(self.path)
        args.binary_plan_sha256 = runtime.file_sha(self.path)
        return args

    def test_new_plan_preserves_original_material_budget_and_ten_independent_rows(self):
        self.assertEqual(step.preflight(self.value)[4], self.original.original)
        self.assertEqual(self.plan['base_model_plan']['identity'], self.value['experiment'])
        self.assertEqual(self.plan['training_budget'], self.original.base.plan['training_budget'])
        self.assertEqual(self.plan['independent_source_rows'], 10)
        self.assertEqual(self.plan['actual_row_exposures'], 100)
        self.assertEqual(self.plan['source_ledger_records'], 20)
        self.assertEqual(self.plan['recipe']['optimizer_steps'], 10)
        self.assertFalse(self.plan['same_work_as_legacy_ten_single_rows'])
        self.assertTrue(all(value is False for value in self.plan['flags'].values()))
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_old_namespaces_profiles_and_arguments_never_select_new_training(self):
        for schema in (step.SCHEMA, v2.SCHEMA, 'llm-runtime-parent-step-observed-input-v1'):
            with self.assertRaises(ValueError):
                step.preflight(dict(self.value, schema=schema))
        for profile in (None, v2.PROFILE, v2.NEW_TASK_PROFILE, 'canonical-parent-original-task-observed-execution-v1'):
            args = self.arguments()
            args.initial_setup_profile = profile
            with patch.object(runtime, 'supervise') as supervisor:
                with self.assertRaises(ValueError):
                    step.run(args)
                supervisor.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_source_train_only_closed_fields_and_numeric_relabelling_refuse(self):
        changes = [lambda value: value.update(extra=True),
            lambda value: value.update(operation='evaluate'),
            lambda value: value.update(operation='readback'),
            lambda value: value['source'].update(binary_answer_observed='f' * 64),
            lambda value: value['initial_setup'].update(profile=v2.PROFILE),
            lambda value: value['initial_setup']['recipe'].update(initialization_seed=7.0),
            lambda value: value['flags'].update(installation_accepted=0)]
        with patch.object(runtime, 'runtime_import') as imports:
            for change in changes:
                value = copy.deepcopy(self.value)
                change(value)
                with self.assertRaises(ValueError):
                    step.preflight(value)
            imports.assert_not_called()

    def test_recipe_ledger_rows_counts_observer_and_budget_are_exact_frozen_inputs(self):
        changes = [lambda record: record['recipe'].update(learning_rate='0.004'),
            lambda record: record['recipe'].update(optimizer_steps=100),
            lambda record: record.update(independent_source_rows=100),
            lambda record: record.update(actual_row_exposures=10),
            lambda record: record['training_rows'].reverse(),
            lambda record: record['training_budget'].update(wall_seconds=1801),
            lambda record: record['observer'].update(extra=True),
            lambda record: record['flags'].update(installation_accepted=True)]
        for change in changes:
            record = copy.deepcopy(self.plan)
            change(record)
            self.freeze(record)
            with self.assertRaisesRegex(ValueError, 'EXACT_EXECUTION_PLAN'):
                step.preflight(self.value)
        self.freeze(self.plan)
        self.path.write_bytes(self.path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'PLAN_PIN'):
            step.preflight(self.value)

    def trace_fixture(self, directory):
        # Complete fabricated trace, deliberately tiny input IDs. It only
        # exercises parsing/counting; it is never a real tokenizer/model proof.
        selected = binary.rows(self.original.base.plan)
        records = [dict(event='start', profile=binary.PROFILE, input=runtime.identity(self.value),
            recipe=runtime.identity(binary.RECIPE), plan_sha256=self.value['initial_setup']['binary_plan']['sha256'],
            source=runtime.file_sha(binary.__file__), source_rows=[runtime.identity(row) for row in selected],
            pid=1, start_monotonic_ns=1)]
        for update in range(10):
            for ordinal, row in enumerate(selected):
                records.append(dict(event='microstep', optimizer_step=update, row_ordinal=ordinal,
                    source_row_sha256=runtime.identity(row), input_ids=[ordinal + 1, 33],
                    answer_token_ids=[10407, 4607], target_index=binary.RECIPE['answer_order'].index(row['expected_output']),
                    answer_logits=['0', '0'], loss=format(math.log(2), '.17g'), backward_completed=True,
                    completed_monotonic_ns=len(records) + 1, completed_process_cpu_ns=len(records) + 1))
            records.append(dict(event='optimizer-step', optimizer_step=update, microsteps=10,
                gradient_l2_squared='1', optimizer_completed=True,
                completed_monotonic_ns=len(records) + 1, completed_process_cpu_ns=len(records) + 1))
        records.append(dict(event='complete', optimizer_steps=10, microsteps=100, tokens=200,
            supervised_tokens=100, completed_monotonic_ns=len(records) + 1))
        training = dict(steps=10, loss=[format(math.log(2), '.17g')] * 10,
            tokens=200, supervised_tokens=100, supported_profile_flops=0,
            flop_scope='profiler-supported-operators-only-not-total-work')
        self.save_trace(directory, records, training)
        return records, training

    def save_trace(self, directory, records, training):
        path = directory / binary.TRACE
        path.write_bytes(b''.join(runtime.canonical(record) + b'\n' for record in records))
        pin = dict(path=str(path), sha256=runtime.file_sha(path), bytes=path.stat().st_size)
        training['objective'] = binary.objective_record(self.value, pin, training['tokens'])

    def fixture_completion(self):
        directory, report = self.original.completed_fixture(changed=True)
        records, training = self.trace_fixture(directory)
        report.update(schema=v2.named(self.value, 'llm-runtime-parent-step-actual'),
            source=self.value['source'], input=runtime.identity(self.value), attempt_binding=v2.binding(self.value),
            binary_observed_execution=binary.context(self.value), training=training)
        runtime.save(directory / (v2.named(self.value, 'parent-candidate') + '.json'),
            v2.candidate_record(self.value, report['setup'], report['candidate'], True))
        runtime.save(directory / 'actual-receipt.json', report)
        return directory, report, records

    def test_complete_trace_counts_and_new_receipts_preserve_material_lineage(self):
        directory, report, records = self.fixture_completion()
        self.assertEqual(len(records), 112)
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))
        self.assertEqual(report['training']['supervised_tokens'], 100)
        self.assertTrue(all(report[name] is False for name in step.FALSES))
        for field, replacement in [('schema', v2.ACTUAL), ('binary_observed_execution', {}),
                ('installation_accepted', True)]:
            changed = copy.deepcopy(report)
            changed[field] = replacement
            runtime.save(directory / 'actual-receipt.json', changed)
            with self.assertRaises(ValueError):
                step.verify_completion(self.value)

    def test_missing_reordered_relabelled_nonfinite_or_fake_backward_trace_refuses(self):
        directory, report, records = self.fixture_completion()
        changes = [lambda values: values.pop(1),
            lambda values: values[1].update(row_ordinal=1),
            lambda values: values[1].update(optimizer_step=True),
            lambda values: values[1].update(target_index=1 - values[1]['target_index']),
            lambda values: values[1].update(answer_token_ids=[4607, 10407]),
            lambda values: values[1].update(backward_completed=False),
            lambda values: values[1].update(answer_logits=['nan', '0']),
            lambda values: values[1].update(loss='0'),
            lambda values: values[12].update(input_ids=[999, 33]),
            lambda values: values[11].update(gradient_l2_squared='0'),
            lambda values: values[11].update(optimizer_completed=False),
            lambda values: values[-1].update(microsteps=10),
            lambda values: values[-1].update(completed_monotonic_ns=0)]
        for change in changes:
            changed = copy.deepcopy(records)
            change(changed)
            training = copy.deepcopy(report['training'])
            self.save_trace(directory, changed, training)
            with self.assertRaises(ValueError):
                binary.verify_training(self.value, self.original.base.plan, training)

    def test_legacy_counts_and_more_work_cannot_be_relabelled(self):
        directory, report, records = self.fixture_completion()
        for change in [dict(steps=100), dict(tokens=526), dict(supervised_tokens=40),
                dict(supported_profile_flops=True)]:
            training = dict(report['training'], **change)
            with self.assertRaises(ValueError):
                binary.verify_training(self.value, self.original.base.plan, training)
        report['training']['objective']['independent_source_rows'] = 100
        with self.assertRaises(ValueError):
            binary.verify_training(self.value, self.original.base.plan, report['training'])
        self.assertEqual(len(records), 112)

    def test_original_owned_reap_failure_stays_failed_and_has_new_namespace(self):
        terminal = dict(outcome='success', exit_code=0, stop_reason=None,
            budget=self.original.base.plan['training_budget'], waited_child_reaped=False,
            owned_child_reap_resolved=False, owned_child_echild_observed=False,
            waited_child_observation_error=None)
        args = self.arguments()
        with patch.object(runtime, 'supervise', return_value=terminal) as supervisor:
            with self.assertRaisesRegex(ValueError, 'CHILD_FAILED'):
                step.run(args)
        root = Path(args.output)
        self.assertEqual(step.read_object(root / 'parent-step-input-binary-observed-v2.json'), self.value)
        self.assertEqual(supervisor.call_args.kwargs['exit_observation'], self.plan['observer'])
        result = step.read_object(root / 'parent-step-result-binary-observed-v2.json')
        self.assertEqual(result['outcome'], 'failed')
        self.assertFalse(result['completion_verified'])
        self.assertFalse((root / 'parent-step-result-v2.json').exists())

    def test_exact_original_terminal_observer_and_budget_required(self):
        result = dict(exit_observation_profile=self.plan['observer'],
            terminal_reconciliation_profile='explicit-' + binary.OBSERVER,
            budget=self.original.base.plan['training_budget'])
        binary.verify_supervisor(self.value, result)
        for change in [dict(exit_observation_profile=None), dict(terminal_reconciliation_profile='strict-v1'),
                dict(budget=dict(wall_seconds=1801, rss_bytes=16 * 1024 ** 3))]:
            with self.assertRaisesRegex(ValueError, 'SUPERVISOR_BINDING'):
                binary.verify_supervisor(self.value, dict(result, **change))

    def test_live_finalization_preserves_original_exception_when_receipt_cannot_save(self):
        directory = self.original.root / 'blocked-finalization'
        directory.mkdir()
        # Actual filesystem failure: a directory cannot be overwritten by save.
        (directory / 'live-release-binary-observed-v2.json').mkdir()
        observer = type('Observer', (), {'stage': staticmethod(lambda name, function: function())})()
        report = dict(outcome='failed', error_type='LookupError', error='primary')
        primary = LookupError('primary')
        try:
            raise primary
        except LookupError as pending:
            binary.finalize_live_child(self.value, directory, observer, report, time.monotonic_ns(), pending)
        self.assertEqual(str(primary), 'primary')
        self.assertTrue(any('IsADirectoryError' in note for note in primary.__notes__))
        self.assertEqual(step.read_object(directory / 'actual-receipt.json')['error_type'], 'LookupError')
        with self.assertRaises(IsADirectoryError):
            binary.finalize_live_child(self.value, directory, observer, dict(outcome='success'), time.monotonic_ns(), None)


if __name__ == '__main__':
    unittest.main(verbosity=2)
