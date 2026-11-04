"""Synthetic contract/dispatch controls; these fixtures are not model evidence."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

import llm_answer_eos_research_v3 as research
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_pilot as runtime
import test_llm_runtime_parent_step_v2 as original_tests


class ResearchV3Tests(unittest.TestCase):
    def setUp(self):
        self.original = original_tests.ParentStepV2Tests()
        self.original.setUp()
        self.addCleanup(self.original.doCleanups)
        self.value = copy.deepcopy(self.original.value)
        self.value.update(schema=research.SCHEMA, source=v2.sources(research.PROFILE))
        self.value['initial_setup']['profile'] = research.PROFILE
        self.path = self.original.root / 'research-plan-v3.json'
        self.plan = research.plan_record(self.value)
        self.freeze(self.plan)

    def freeze(self, plan):
        runtime.save(self.path, plan)
        self.value['initial_setup']['research_plan'] = dict(path=str(self.path), sha256=runtime.file_sha(self.path))

    def arguments(self):
        args = self.original.arguments(self.value)
        args.initial_setup_profile = research.PROFILE
        args.research_plan = str(self.path)
        args.research_plan_sha256 = runtime.file_sha(self.path)
        return args

    def test_exact_source_plan_parent_and_old_material_contract(self):
        self.assertEqual(step.preflight(self.value)[4], self.original.original)
        self.assertEqual(self.plan['schedule']['supervised_tokens'], 40)
        self.assertFalse(self.plan['material_and_control_plan']['legacy_candidate_recipe_is_used'])
        self.assertTrue(all(v is False for v in self.plan['flags'].values()))
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_unknown_scope_source_profile_and_numeric_relabelling_refuse(self):
        mutations = [lambda v: v.update(schema='llm-runtime-parent-step-input-v4'),
            lambda v: v.update(extra=True), lambda v: v['source'].update(research_objective='f' * 64),
            lambda v: v['initial_setup'].update(profile=v2.PROFILE),
            lambda v: v['initial_setup']['recipe'].update(initialization_seed=7.0)]
        for mutate in mutations:
            value = copy.deepcopy(self.value); mutate(value)
            with self.assertRaises(ValueError): step.preflight(value)

    def test_frozen_recipe_tasks_counts_and_all_qualification_flags_cannot_drift(self):
        mutations = [lambda p: p['recipe'].update(learning_rate='0.002'),
            lambda p: p['recipe'].update(answer_weight=[1, 1], each_eos_weight=[0, 1]),
            lambda p: p['schedule'].update(supervised_tokens=20),
            lambda p: p.update(evaluation_tasks='f' * 64),
            lambda p: p['flags'].update(installation_accepted=True),
            lambda p: p['flags'].update(installation_accepted=0),
            lambda p: p['participants'].remove('actual-current-incumbent')]
        for mutate in mutations:
            plan = copy.deepcopy(self.plan); mutate(plan); self.freeze(plan)
            with self.assertRaisesRegex(ValueError, 'RESEARCH_V3_EXACT_PLAN'): step.preflight(self.value)
        self.freeze(self.plan)
        self.path.write_bytes(self.path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'RESEARCH_V3_PLAN_PIN'): step.preflight(self.value)

    def test_old_namespaces_and_arguments_cannot_silently_select_research(self):
        for schema in (step.SCHEMA, v2.SCHEMA):
            with self.assertRaises(ValueError): step.preflight(dict(self.value, schema=schema))
        for profile in (None, v2.PROFILE, v2.NEW_TASK_PROFILE):
            args = self.arguments(); args.initial_setup_profile = profile
            with patch.object(runtime, 'supervise') as supervisor:
                with self.assertRaises(ValueError): step.run(args)
                supervisor.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_only_train_is_implemented_and_plan_must_exist_before_effects(self):
        with patch.object(runtime, 'runtime_import') as imports, patch.object(runtime, 'supervise') as supervisor:
            for operation in ('evaluate', 'readback'):
                with self.assertRaisesRegex(ValueError, 'TRAIN_ONLY'):
                    step.preflight(dict(self.value, operation=operation))
            self.path.unlink()
            with self.assertRaises(OSError): step.preflight(self.value)
            imports.assert_not_called(); supervisor.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def fixture_completion(self):
        # Reuse the explicitly fabricated complete-byte fixture, never a receipt
        # emitted by a real model or supplied to an installation owner.
        directory, report = self.original.completed_fixture(changed=True)
        report.update(schema='llm-runtime-parent-step-actual-v3', source=self.value['source'],
            input=runtime.identity(self.value), attempt_binding=v2.binding(self.value), research=research.context(self.value))
        report['training'].update(tokens=526, supervised_tokens=40, objective=research.objective_record())
        runtime.save(directory / 'parent-candidate-v3.json', v2.candidate_record(self.value,
            report['setup'], report['candidate'], True))
        runtime.save(directory / 'actual-receipt.json', report)
        return directory, report

    def test_new_receipt_and_material_binding_do_not_accept_old_or_changed_objective(self):
        directory, report = self.fixture_completion()
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))
        mutations = [lambda r: r.update(schema=v2.ACTUAL),
            lambda r: r['research'].update(plan_sha256='f' * 64),
            lambda r: r['training'].update(supervised_tokens=20),
            lambda r: r['training']['objective'].update(nonzero_weight_tokens=10),
            lambda r: r.update(installation_accepted=True)]
        for mutate in mutations:
            changed = copy.deepcopy(report); mutate(changed)
            runtime.save(directory / 'actual-receipt.json', changed)
            with self.assertRaises(ValueError): step.verify_completion(self.value)

    def test_original_reap_failure_stays_failed_in_new_namespace(self):
        args = self.arguments()
        terminal = dict(outcome='success', exit_code=0, stop_reason=None,
            budget=self.original.base.plan['training_budget'], waited_child_reaped=False,
            owned_child_reap_resolved=False, owned_child_echild_observed=False,
            waited_child_observation_error=None)
        with patch.object(runtime, 'supervise', return_value=terminal) as supervisor:
            with self.assertRaisesRegex(ValueError, 'CHILD_FAILED'): step.run(args)
        root = Path(args.output)
        frozen = step.read_object(root / 'parent-step-input-v3.json')
        self.assertEqual(frozen, self.value)
        self.assertIn(str(root / 'parent-step-input-v3.json'), supervisor.call_args.args[0])
        result = step.read_object(root / 'parent-step-result-v3.json')
        self.assertEqual(result['schema'], 'llm-runtime-parent-step-result-v3')
        self.assertEqual(result['outcome'], 'failed')
        self.assertFalse(result['completion_verified'])
        self.assertIsNone(result['actual_receipt_sha256'])
        self.assertFalse((root / 'parent-step-result-v2.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
