"""Finite fabricated material/trace/dispatch controls; never model qualification.

The fixed public token arrays are real frozen inputs. Logits, clocks, gradients,
model materials and successful owner receipts below are explicit test fixtures.
No Torch/model import, optimizer, future task or resource-owner run is executed.
"""
import argparse
import ast
from collections import Counter
import copy
import inspect
import math
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import llm_binary_answer_observed_v2 as binary
import llm_binary_diverse60_observed_v3 as diverse
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_pilot as runtime
import test_llm_runtime_parent_step_v2 as original_tests


class BinaryDiverse60V3Tests(unittest.TestCase):
    def setUp(self):
        self.original = original_tests.ParentStepV2Tests()
        self.original.setUp()
        self.addCleanup(self.original.doCleanups)
        self.value = copy.deepcopy(self.original.value)
        self.value.update(schema=diverse.SCHEMA, source=v2.sources(diverse.PROFILE))
        self.value['initial_setup']['profile'] = diverse.PROFILE
        self.data_path = self.original.root / 'offered-training-data.json'
        self.data_path.write_bytes((runtime.REPOSITORY / diverse.DATA_RELATIVE_PATH).read_bytes())
        self.value['initial_setup']['training_data'] = dict(path=str(self.data_path), sha256=diverse.DATA_SHA256)
        self.data = diverse.load_training_data(self.value['initial_setup']['training_data'])
        self.path = self.original.root / 'diverse-execution-plan.json'
        self.plan = diverse.plan_record(self.value)
        self.freeze(self.plan)

    def freeze(self, plan):
        runtime.save(self.path, plan)
        self.value['initial_setup']['diverse_plan'] = dict(path=str(self.path), sha256=runtime.file_sha(self.path))

    def arguments(self):
        args = self.original.arguments(self.value)
        args.initial_setup_profile = diverse.PROFILE
        args.diverse_plan, args.diverse_plan_sha256 = str(self.path), runtime.file_sha(self.path)
        args.diverse_training_data, args.diverse_training_data_sha256 = str(self.data_path), diverse.DATA_SHA256
        return args

    def trace_fixture(self, directory):
        records = [dict(event='start', profile=diverse.PROFILE, input=runtime.identity(self.value),
            recipe=runtime.identity(diverse.RECIPE), plan_sha256=self.value['initial_setup']['diverse_plan']['sha256'],
            source=runtime.file_sha(diverse.__file__), source_rows=self.data['ordered_training_row_sha256'],
            training_data_sha256=diverse.DATA_SHA256, update_schedule_sha256=runtime.identity(self.data['update_schedule']),
            pid=1, start_monotonic_ns=1)]
        tokens = 0
        for update, indices in enumerate(self.data['update_schedule']):
            for ordinal, index in enumerate(indices):
                row = self.data['training_rows'][index]
                ids = self.data['training_token_ids'][index]
                tokens += len(ids)
                records.append(dict(event='microstep', optimizer_step=update, row_ordinal=ordinal,
                    source_row_index=index, source_row_sha256=runtime.identity(row), input_ids=ids,
                    answer_token_ids=[10407, 4607], target_index=diverse.RECIPE['answer_order'].index(row['expected_output']),
                    answer_logits=['0', '0'], loss=format(math.log(2), '.17g'), backward_completed=True,
                    completed_monotonic_ns=len(records) + 1, completed_process_cpu_ns=len(records) + 1))
            records.append(dict(event='optimizer-step', optimizer_step=update, microsteps=10,
                gradient_l2_squared='1', optimizer_completed=True,
                completed_monotonic_ns=len(records) + 1, completed_process_cpu_ns=len(records) + 1))
        records.append(dict(event='complete', optimizer_steps=30, microsteps=300, tokens=tokens,
            supervised_tokens=300, completed_monotonic_ns=len(records) + 1))
        training = dict(steps=30, loss=[format(math.log(2), '.17g')] * 30, tokens=tokens,
            supervised_tokens=300, supported_profile_flops=0, flop_scope='profiler-supported-operators-only-not-total-work')
        self.save_trace(directory, records, training)
        return records, training

    def save_trace(self, directory, records, training):
        path = directory / diverse.TRACE
        path.write_bytes(b''.join(runtime.canonical(row) + b'\n' for row in records))
        pin = dict(path=str(path), bytes=path.stat().st_size, sha256=runtime.file_sha(path))
        training['objective'] = diverse.objective_record(self.value, pin, training['tokens'])

    def fixture_completion(self, changed=True):
        directory, report = self.original.completed_fixture(changed=changed)
        records, training = self.trace_fixture(directory)
        report.update(schema=v2.named(self.value, 'llm-runtime-parent-step-actual'), source=self.value['source'],
            input=runtime.identity(self.value), attempt_binding=v2.binding(self.value),
            binary_diverse60_observed_execution=diverse.context(self.value), training=training)
        runtime.save(directory / (v2.named(self.value, 'parent-candidate') + '.json'),
            v2.candidate_record(self.value, report['setup'], report['candidate'], changed))
        runtime.save(directory / 'actual-receipt.json', report)
        return directory, report, records

    def terminal_fixture(self):
        return dict(outcome='success', exit_code=0, stop_reason=None, budget=self.plan['training_budget'],
            exit_observation_profile=self.plan['observer'], terminal_reconciliation_profile='explicit-' + diverse.OBSERVER,
            child_spawned=True, owned_child_exit_observed=True, waited_child_reaped=True,
            owned_child_reap_resolved=True, owned_child_echild_observed=False,
            waited_child_observation_error=None, cleanup_method='wait4', sample_interval_ms=50,
            observed_wall_ns=1, child_cpu_ns=1, observer_cpu_ns=1, sampled_peak_rss_bytes=1,
            waited_child_peak_rss_bytes=1)

    def test_explicit_plan_keeps_parent_material_and_current_owner_with_exact_new_work(self):
        with patch.object(runtime, 'runtime_import') as imports:
            self.assertEqual(step.preflight(self.value)[4], self.original.original)
            imports.assert_not_called()
        self.assertEqual(self.plan['base_model_plan']['identity'], self.value['experiment'])
        self.assertEqual(self.original.base.plan['training_steps'], 10)
        self.assertEqual(self.plan['recipe']['optimizer_steps'], 30)
        self.assertEqual(self.plan['expected_source_ledger_records'], 120)
        self.assertEqual(self.plan['expected_input_tokens'], 15600)
        self.assertEqual(self.plan['observer']['observer_source_sha256'], diverse.OBSERVER_SOURCE_SHA256)
        self.assertEqual(self.value['source']['binary_diverse60_observed'], runtime.file_sha(diverse.__file__))
        self.assertEqual(self.value['source']['binary_diverse60_training_data'], diverse.DATA_SHA256)
        self.assertEqual(Counter(index for batch in self.plan['update_schedule'] for index in batch),
                         Counter({index: 5 for index in range(60)}))
        self.assertFalse(Path(self.value['output']).parent.exists())
        self.assertTrue(all(item is False for item in self.plan['flags'].values()))

    def test_data_byte_pin_refuses_substitution_and_symlink_without_default_fallback(self):
        original = self.data_path.read_bytes()
        for change in [lambda d: d['training_rows'].reverse(),
                       lambda d: d['update_schedule'][0].reverse(),
                       lambda d: d['training_token_ids'][0].append(33),
                       lambda d: d.update(expected_input_tokens=4860),
                       lambda d: d.update(extra=True)]:
            with self.subTest(change=change):
                data = copy.deepcopy(self.data)
                change(data)
                runtime.save(self.data_path, data)
                self.value['initial_setup']['training_data']['sha256'] = runtime.file_sha(self.data_path)
                with self.assertRaisesRegex(ValueError, 'FIXED_DATA_IDENTITY'):
                    step.preflight(self.value)
        self.data_path.write_bytes(original)
        self.value['initial_setup']['training_data']['sha256'] = diverse.DATA_SHA256
        link = self.original.root / 'data-link.json'
        link.symlink_to(self.data_path)
        with self.assertRaises((ValueError, OSError)):
            diverse.load_training_data(dict(path=str(link), sha256=diverse.DATA_SHA256))
        self.data_path.unlink()
        with self.assertRaises((ValueError, OSError)):
            step.preflight(self.value)

    def test_old_profile_schema_and_partial_new_cli_pairs_refuse_before_effect(self):
        changes = [(name, None) for name in ('diverse_plan', 'diverse_plan_sha256',
                                           'diverse_training_data', 'diverse_training_data_sha256')]
        changes += [('initial_setup_profile', profile) for profile in (None, v2.PROFILE, binary.PROFILE)]
        for name, replacement in changes:
            args = self.arguments()
            setattr(args, name, replacement)
            with self.subTest(argument=name, replacement=replacement), patch.object(runtime, 'supervise') as owner:
                with self.assertRaises(ValueError):
                    step.run(args)
                owner.assert_not_called()
        for schema in (step.SCHEMA, v2.SCHEMA, binary.SCHEMA):
            with self.assertRaises(ValueError):
                step.preflight(dict(self.value, schema=schema))
        parser = argparse.ArgumentParser()
        v2.add_arguments(parser)
        parsed = parser.parse_args(['--initial-setup-profile', diverse.PROFILE,
            '--diverse-plan', str(self.path), '--diverse-plan-sha256', runtime.file_sha(self.path),
            '--diverse-training-data', str(self.data_path), '--diverse-training-data-sha256', diverse.DATA_SHA256])
        self.assertEqual(parsed.diverse_training_data_sha256, diverse.DATA_SHA256)
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_plan_counts_schedule_source_observer_and_budgets_cannot_be_relabelled(self):
        changes = [lambda p: p['recipe'].update(optimizer_steps=10),
            lambda p: p.update(distinct_source_rows=10), lambda p: p.update(actual_row_exposures=100),
            lambda p: p.update(expected_source_ledger_records=20), lambda p: p.update(physical_microbatch=10),
            lambda p: p['update_schedule'][0].reverse(), lambda p: p.update(expected_input_tokens=4860),
            lambda p: p['source'].update(binary_diverse60_observed='f' * 64),
            lambda p: p['source'].update(binary_diverse60_training_data='f' * 64),
            lambda p: p['observer'].update(observer_source_sha256='aef' + '0' * 61),
            lambda p: p['training_budget'].update(wall_seconds=1801),
            lambda p: p['inference_budget'].update(rss_bytes=16 * 1024**3)]
        for change in changes:
            with self.subTest(change=change):
                record = copy.deepcopy(self.plan)
                change(record)
                self.freeze(record)
                with self.assertRaisesRegex(ValueError, 'EXACT_EXECUTION_PLAN'):
                    step.preflight(self.value)
        self.freeze(self.plan)
        self.path.write_bytes(self.path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'PLAN_PIN'):
            step.preflight(self.value)

    def test_input_closed_fields_changed_source_and_real_parent_byte_corruption_refuse(self):
        for change in [lambda v: v.update(extra=True), lambda v: v.update(operation='evaluate'),
                lambda v: v.update(operation='readback'), lambda v: v['initial_setup'].update(profile=binary.PROFILE),
                lambda v: v['source'].update(binary_diverse60_observed='f' * 64),
                lambda v: v['source'].update(binary_diverse60_training_data='f' * 64),
                lambda v: v['flags'].update(installation_accepted=0),
                lambda v: v['initial_setup']['recipe'].update(initialization_seed=7.0)]:
            value = copy.deepcopy(self.value)
            change(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                step.preflight(value)
        path = Path(self.value['files']['parent_artifact'])
        original = path.read_bytes()
        path.write_bytes(original[:-1] + b'\1')
        with self.assertRaises(ValueError):
            step.preflight(self.value)
        path.write_bytes(original)
        self.assertEqual(step.preflight(self.value)[4], self.original.original)

    def test_complete_fabricated_trace_recounts_332_records_and_15600_real_input_tokens(self):
        directory, report, records = self.fixture_completion()
        self.assertEqual(len(records), 332)
        self.assertEqual(report['training']['tokens'], 15600)
        self.assertEqual(report['training']['supervised_tokens'], 300)
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))
        counts = Counter(row['source_row_index'] for row in records if row['event'] == 'microstep')
        self.assertEqual(counts, Counter({index: 5 for index in range(60)}))
        self.assertEqual(sum(row['event'] == 'optimizer-step' for row in records), 30)
        with self.assertRaises(ValueError):
            binary.verify_training(self.value, self.original.base.plan, report['training'])

    def test_missing_reordered_wrong_token_fake_backward_and_old_count_traces_refuse(self):
        directory, report, records = self.fixture_completion()
        changes = [lambda r: r.pop(1), lambda r: r.__setitem__(slice(1, 3), [r[2], r[1]]),
            lambda r: r[1].update(source_row_index=True), lambda r: r[1].update(source_row_index=59),
            lambda r: r[1].update(source_row_sha256='f' * 64), lambda r: r[1].update(input_ids=[1, 33]),
            lambda r: r[1].update(answer_token_ids=[4607, 10407]),
            lambda r: r[1].update(target_index=1 - r[1]['target_index']),
            lambda r: r[1].update(answer_logits=['nan', '0']), lambda r: r[1].update(loss='0'),
            lambda r: r[1].update(backward_completed=False), lambda r: r[1].update(extra=True),
            lambda r: r[1].update(completed_process_cpu_ns=-1),
            lambda r: r[11].update(optimizer_completed=False), lambda r: r[11].update(gradient_l2_squared='0'),
            lambda r: r[0].update(training_data_sha256='f' * 64),
            lambda r: r[0].update(update_schedule_sha256='f' * 64),
            lambda r: r[-1].update(optimizer_steps=10, microsteps=100, tokens=4860, supervised_tokens=100)]
        for change in changes:
            with self.subTest(change=change):
                mutated = copy.deepcopy(records)
                change(mutated)
                training = copy.deepcopy(report['training'])
                self.save_trace(directory, mutated, training)
                with self.assertRaises(ValueError):
                    diverse.verify_training(self.value, self.original.base.plan, training)

    def test_receipt_context_false_authority_and_scalar_work_relabelling_refuse(self):
        directory, report, records = self.fixture_completion()
        for fields in [dict(steps=10), dict(tokens=4860), dict(supervised_tokens=100),
                       dict(supported_profile_flops=True)]:
            with self.assertRaises(ValueError):
                diverse.verify_training(self.value, self.original.base.plan, dict(report['training'], **fields))
        for name, replacement in [('schema', v2.ACTUAL), ('binary_diverse60_observed_execution', {}),
                                   ('installation_accepted', True)]:
            mutated = copy.deepcopy(report)
            mutated[name] = replacement
            runtime.save(directory / 'actual-receipt.json', mutated)
            with self.assertRaises(ValueError):
                step.verify_completion(self.value)
        with self.assertRaisesRegex(ValueError, 'TRAINING_PLAN'):
            diverse.verify_training(self.value, dict(self.original.base.plan, training_steps=30), report['training'])

    def test_setup_only_unchanged_candidate_never_completes_new_training(self):
        self.fixture_completion(changed=False)
        with self.assertRaisesRegex(ValueError, 'ACTUAL_TRAINING_CHANGE'):
            step.verify_completion(self.value)

    def test_full_owner_policy_costs_and_original_terminal_deadline_refuse_bad_receipts(self):
        good = self.terminal_fixture()
        diverse.verify_supervisor(self.value, good)
        changes = [dict(owned_child_exit_observed=False), dict(waited_child_reaped=False), dict(child_cpu_ns=-1),
            dict(sampled_peak_rss_bytes=16 * 1024**3 + 1), dict(waited_child_peak_rss_bytes=16 * 1024**3 + 1),
            dict(observed_wall_ns=1800 * 1000000000 + 1), dict(exit_observation_profile=None),
            dict(terminal_reconciliation_profile='strict-v1'), dict(sample_interval_ms=100),
            dict(sample_interval_ms=50.0),
            dict(budget=dict(wall_seconds=1801, rss_bytes=16 * 1024**3)),
            dict(budget=dict(wall_seconds=1800.0, rss_bytes=16 * 1024**3)),
            dict(exit_cleanup_observation=dict(outcome='terminal-wait4', completed_ns=100000002,
                missing_sample_ns=1, retirement_closed_by='exact-owned-child-terminal-wait4'))]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                diverse.verify_supervisor(self.value, dict(good, **change))
        for field in ('stop_reason', 'waited_child_observation_error'):
            incomplete = dict(good)
            incomplete.pop(field)
            with self.assertRaisesRegex(ValueError, 'REQUIRED_OWNER_FIELDS'):
                diverse.verify_supervisor(self.value, incomplete)
        for elapsed in (0, 100000000):
            diverse.verify_supervisor(self.value, dict(good, exit_cleanup_observation=dict(outcome='terminal-wait4',
                completed_ns=1 + elapsed, missing_sample_ns=1,
                retirement_closed_by='exact-owned-child-terminal-wait4')))
        self.assertNotIn('exit_cleanup_observation', good)

    def test_failed_owned_reap_persists_only_new_failed_completion(self):
        terminal = dict(self.terminal_fixture(), waited_child_reaped=False, owned_child_reap_resolved=False)
        with patch.object(runtime, 'supervise', return_value=terminal) as owner:
            with self.assertRaisesRegex(ValueError, 'CHILD_FAILED'):
                step.run(self.arguments())
        root = Path(self.value['output']).parent
        self.assertEqual(step.read_object(root / 'parent-step-input-binary-diverse60-observed-v3.json'), self.value)
        result = step.read_object(root / 'parent-step-result-binary-diverse60-observed-v3.json')
        self.assertEqual(result['outcome'], 'failed')
        self.assertFalse(result['completion_verified'])
        self.assertFalse((root / 'parent-step-result-binary-observed-v2.json').exists())
        self.assertEqual(owner.call_args.kwargs['exit_observation'], self.plan['observer'])

    def test_fabricated_run_wiring_calls_full_new_completion_reader_and_preserves_owner_directory(self):
        def owner_fixture(command, output, budget, exit_observation):
            self.assertEqual(command[1], str(Path(runtime.__file__).resolve()))
            self.assertEqual(output, self.value['output'])
            self.assertFalse(Path(output).exists())
            self.assertEqual(budget, self.plan['training_budget'])
            self.assertEqual(exit_observation, self.plan['observer'])
            self.fixture_completion()
            return self.terminal_fixture()
        with patch.object(runtime, 'supervise', side_effect=owner_fixture), patch.object(runtime, 'runtime_import') as imports:
            step.run(self.arguments())
            imports.assert_not_called()
        result = step.read_object(Path(self.value['output']).parent / 'parent-step-result-binary-diverse60-observed-v3.json')
        self.assertEqual(result['outcome'], 'success')
        self.assertTrue(result['completion_verified'])
        self.assertEqual(result['actual_receipt_sha256'], runtime.file_sha(Path(self.value['output']) / 'actual-receipt.json'))
        self.assertEqual(result['binary_diverse60_observed_execution'], diverse.context(self.value))
        self.assertTrue(all(item is False for item in result['flags'].values()))

    def test_actual_child_discriminant_preserves_pre_model_failure_in_new_namespace(self):
        directory = Path(self.value['output'])
        directory.mkdir(parents=True)
        input_path = directory.parent / 'explicit-child-input.json'
        runtime.save(input_path, self.value)
        args = argparse.Namespace(parent_step_input=str(input_path), expected_parent_step_input=runtime.identity(self.value),
            materials=self.value['files']['materials'], plan=self.value['files']['plan'], output=str(directory), role='candidate')
        with (patch.object(runtime, 'runtime_import', side_effect=LookupError('fixture-before-model')) as imports,
              patch.object(diverse, 'train') as train):
            with self.assertRaisesRegex(LookupError, 'fixture-before-model'):
                step.child(args)
            imports.assert_called_once()
            train.assert_not_called()
        report = step.read_object(directory / 'actual-receipt.json')
        self.assertEqual(report['schema'], 'llm-runtime-parent-step-actual-binary-diverse60-observed-v3')
        self.assertEqual(report['error_type'], 'LookupError')
        self.assertEqual(report['outcome'], 'failed')
        self.assertNotIn('training', report)
        self.assertNotIn('torch', sys.modules)

    def test_scalar_math_and_per_update_profiler_are_original_without_batch_or_teardown_changes(self):
        old, new = ast.parse(inspect.getsource(binary.train)), ast.parse(inspect.getsource(diverse.train))
        def calls(tree, name):
            return [ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                if isinstance(node, ast.Call) and ((isinstance(node.func, ast.Name) and node.func.id == name) or
                (isinstance(node.func, ast.Attribute) and node.func.attr == name))]
        for name in ('model', 'AdamW', 'cross_entropy', 'backward', 'step', 'zero_grad', 'profile'):
            self.assertEqual(calls(old, name), calls(new, name), name)
        source = inspect.getsource(diverse.train)
        self.assertLess(source.index('for update in range(UPDATES)'), source.index('with torch.profiler.profile'))
        self.assertLess(source.index('with torch.profiler.profile'), source.index('for ordinal, source_row_index'))
        self.assertEqual(diverse.RECIPE['physical_microbatch'], 1)
        self.assertEqual(diverse.RECIPE['threads'], 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
