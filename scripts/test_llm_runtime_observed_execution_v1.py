"""Synthetic byte/dispatch controls, plus a small real child supervisor probe.

These are not pretrained-model training, installation, or quality evidence.
"""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import llm_runtime_observed_execution_v1 as observed
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_pilot as runtime
import test_llm_runtime_parent_step_v2 as original_tests


class ObservedExecutionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = original_tests.ParentStepV2Tests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.value = copy.deepcopy(self.fixture.value)
        self.value.update(schema=observed.SCHEMA, source=v2.sources(observed.PROFILE))
        self.value['initial_setup']['profile'] = observed.PROFILE
        self.path = self.fixture.root / 'observation-plan.json'
        runtime.save(self.path, observed.plan_record(self.value))
        self.value['initial_setup']['observation_plan'] = dict(
            path=str(self.path), sha256=runtime.file_sha(self.path))

    def args(self):
        args = self.fixture.arguments(self.value)
        args.initial_setup_profile = observed.PROFILE
        args.observation_plan = str(self.path)
        args.observation_plan_sha256 = runtime.file_sha(self.path)
        return args

    def completion(self):
        directory, report = self.fixture.completed_fixture(changed=True)
        report.update(schema=v2.named(self.value, 'llm-runtime-parent-step-actual'),
            attempt_binding=v2.binding(self.value), input=runtime.identity(self.value),
            source=self.value['source'], observation_execution=observed.context(self.value))
        runtime.save(directory / 'actual-receipt.json', report)
        (directory / 'parent-candidate-v2.json').unlink()
        runtime.save(directory / 'parent-candidate-observed-v1.json',
            v2.candidate_record(self.value, report['setup'], report['candidate'], True))
        return directory, report

    def supervisor(self):
        return dict(outcome='success', exit_code=0, stop_reason=None,
            budget=self.fixture.base.plan['training_budget'], waited_child_reaped=True,
            owned_child_reap_resolved=True, owned_child_echild_observed=False,
            waited_child_observation_error=None,
            exit_observation_profile=runtime.exit_observation_profile(observed.OBSERVER),
            terminal_reconciliation_profile='explicit-' + observed.OBSERVER)

    def test_original_full_byte_preflight_and_target_are_reused(self):
        original = v2.preflight(self.fixture.value)
        with patch.object(runtime, 'runtime_import', side_effect=AssertionError('no model imports')):
            checked = step.preflight(self.value)
        self.assertEqual(checked, original)
        self.assertEqual(runtime.plan_exit_profile(checked[0]), 'strict-v1')
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_fresh_hash_cannot_authorize_changed_policy_parent_source_or_budgets(self):
        record = runtime.read_json(self.path)
        for mutate in (
            lambda r: r['training_budget'].update(wall_seconds=1801),
            lambda r: r['inference_budget'].update(rss_bytes=1),
            lambda r: r['observer'].update(maximum_drain_ns=200000000),
            lambda r: r['parent'].update(contract='f' * 64),
            lambda r: r['source'].update(parent_step='f' * 64),
            lambda r: r.update(installation=True),
            lambda r: r.update(extra='unbound'),
        ):
            changed = copy.deepcopy(record); mutate(changed)
            runtime.save(self.path, changed)
            self.value['initial_setup']['observation_plan']['sha256'] = runtime.file_sha(self.path)
            with self.assertRaisesRegex(ValueError, 'OBSERVED_EXACT_PLAN'):
                step.preflight(self.value)
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_plan_tamper_and_legacy_relabelling_reject_before_any_child(self):
        self.path.write_bytes(self.path.read_bytes() + b' ')
        with patch.object(runtime, 'supervise') as supervise:
            with self.assertRaisesRegex(ValueError, 'OBSERVED_PLAN_PIN'):
                step.preflight(self.value)
            for schema in (step.SCHEMA, v2.SCHEMA):
                with self.assertRaises(ValueError):
                    step.preflight(dict(self.value, schema=schema))
            supervise.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_old_v1_and_v2_arguments_refuse_observation_without_opt_in(self):
        with patch.object(runtime, 'supervise') as supervise:
            for profile in (None, v2.PROFILE):
                args = self.args(); args.initial_setup_profile = profile
                if profile is None:
                    args.parent_material = args.parent_material_sha256 = None
                with self.assertRaisesRegex(ValueError, 'ARGUMENTS'):
                    step.run(args)
            supervise.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_new_receipts_require_new_context_and_original_factor_verifier(self):
        directory, report = self.completion()
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))
        for change in (
            dict(schema=v2.ACTUAL),
            dict(observation_execution=dict(report['observation_execution'], observer='f' * 64)),
            dict(training_changed_from_setup=False),
        ):
            runtime.save(directory / 'actual-receipt.json', dict(report, **change))
            with self.assertRaises(ValueError): step.verify_completion(self.value)
        runtime.save(directory / 'actual-receipt.json', report)
        path = directory / 'artifact.safetensors'
        raw = path.read_bytes(); path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(ValueError): step.verify_completion(self.value)

    def test_same_owner_dispatch_selects_profile_without_changing_model_plan_or_budget(self):
        args = self.args()
        result = self.supervisor()
        with patch.object(runtime, 'supervise', return_value=result) as supervise, \
                patch.object(v2, 'verify_completion', return_value='1' * 64) as verify:
            step.run(args)
        verify.assert_called_once()
        command, output, budget = supervise.call_args.args
        self.assertEqual(command[1], str(Path(runtime.__file__).resolve()))
        self.assertIn('parent-step', command)
        self.assertEqual(budget, self.fixture.base.plan['training_budget'])
        self.assertEqual(output, self.value['output'])
        self.assertEqual(supervise.call_args.kwargs['exit_observation'],
                         runtime.exit_observation_profile(observed.OBSERVER))
        frozen = runtime.read_json(Path(args.output) / 'parent-step-input-observed-v1.json')
        self.assertEqual(frozen, self.value)
        result = runtime.read_json(Path(args.output) / 'parent-step-result-observed-v1.json')
        self.assertTrue(result['completion_verified'])
        self.assertEqual(result['observation_execution'], observed.context(self.value))
        self.assertTrue(all(flag is False for flag in result['flags'].values()))
        self.assertEqual(runtime.read_json(frozen['files']['plan']), self.fixture.base.plan)

    def test_exact_reap_and_observer_binding_required_before_completion(self):
        for change in (dict(waited_child_reaped=False), dict(owned_child_echild_observed=True),
                       dict(exit_observation_profile=None), dict(terminal_reconciliation_profile='strict-v1')):
            with self.subTest(change=change):
                args = self.args()
                args.output += '-' + str(len(list(self.fixture.root.glob('output-*'))))
                with patch.object(runtime, 'supervise', return_value=dict(self.supervisor(), **change)), \
                        patch.object(v2, 'verify_completion') as verify:
                    with self.assertRaises(ValueError): step.run(args)
                verify.assert_not_called()
                result = runtime.read_json(Path(args.output) / 'parent-step-result-observed-v1.json')
                self.assertFalse(result['completion_verified'])

    def test_actual_small_child_has_explicit_profile_and_exact_owned_wait(self):
        directory = self.fixture.root / 'real-small-child'
        result = runtime.supervise([sys.executable, '-I', '-B', '-c', 'sum(range(1000))'],
            directory, dict(wall_seconds=5, rss_bytes=128 * 1024**2),
            exit_observation=runtime.exit_observation_profile(observed.OBSERVER))
        self.assertEqual(result['outcome'], 'success')
        self.assertEqual(result['exit_observation_profile'], runtime.exit_observation_profile(observed.OBSERVER))
        self.assertEqual(result['terminal_reconciliation_profile'], 'explicit-' + observed.OBSERVER)
        self.assertTrue(result['waited_child_reaped'] and result['owned_child_reap_resolved'])
        self.assertFalse(result['owned_child_echild_observed'])
        self.assertIsNone(result['waited_child_observation_error'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
