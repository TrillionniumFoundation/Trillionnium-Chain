"""Byte-level cross-task negatives, with explicit synthetic parent fixtures."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import llm_answer_eos_research_v3 as objective
import llm_answer_eos_task_research_v4 as research
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_parent_step_task_v2 as task
import llm_runtime_candidate_observation_v1 as observation
import llm_runtime_pilot as runtime
import test_llm_runtime_parent_step_task_v2 as prior


class TaskResearchV4Tests(unittest.TestCase):
    def setUp(self):
        self.prior = prior.NewTaskProfileTests()
        self.prior.setUp()
        self.addCleanup(self.prior.doCleanups)
        self.value = copy.deepcopy(self.prior.value)
        self.value.update(schema=research.SCHEMA, source=v2.sources(research.PROFILE))
        self.value['initial_setup']['profile'] = research.PROFILE
        self.path = self.prior.base.root / 'research-plan-v4.json'
        self.plan = research.plan_record(self.value)
        self.freeze(self.plan)

    def freeze(self, plan):
        runtime.save(self.path, plan)
        self.value['initial_setup']['research_plan'] = dict(path=str(self.path), sha256=runtime.file_sha(self.path))

    def arguments(self):
        args = self.prior.base.arguments(self.value)
        args.initial_setup_profile = research.PROFILE
        args.research_plan = str(self.path)
        args.research_plan_sha256 = runtime.file_sha(self.path)
        return args

    def test_exact_old_parent_with_explicit_different_task_is_verified(self):
        checked = step.preflight(self.value)
        self.assertEqual(checked[2], self.prior.parent)
        self.assertEqual(self.plan['recipe'], objective.RECIPE)
        self.assertEqual(self.plan['source'], v2.sources(research.PROFILE))
        self.assertNotEqual(self.value['parent']['contract'], self.plan['task_link']['derived_contract'])
        self.assertTrue(all(v is False for v in self.plan['flags'].values()))
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_old_v3_cannot_silently_gain_cross_task_permission(self):
        value = copy.deepcopy(self.value)
        value.update(schema=objective.SCHEMA, source=v2.sources(objective.PROFILE))
        value['initial_setup'].update(profile=objective.PROFILE)
        value['initial_setup'].pop('task_link')
        runtime.save(self.path, objective.plan_record(value))
        value['initial_setup']['research_plan']['sha256'] = runtime.file_sha(self.path)
        with self.assertRaisesRegex(ValueError, 'PARENT_STEP_CURRENT_CONTRACT'):
            step.preflight(value)

    def test_missing_changed_or_unpinned_task_identity_refuses_before_effects(self):
        mutations = [lambda v: v['initial_setup'].pop('task_link'),
            lambda v: v['initial_setup']['task_link'].update(parent_admission='f' * 64),
            lambda v: v['initial_setup']['task_link'].update(training_plan='f' * 64),
            lambda v: v['initial_setup']['task_link'].update(derived_contract=v['parent']['contract']),
            lambda v: v['source'].pop('research_task'),
            lambda v: v['source'].pop('task_link'),
            lambda v: v['initial_setup'].update(profile=objective.PROFILE),
            lambda v: v.update(schema=objective.SCHEMA)]
        with patch.object(runtime, 'supervise') as supervisor, patch.object(runtime, 'runtime_import') as imports:
            for mutate in mutations:
                value = copy.deepcopy(self.value); mutate(value)
                with self.assertRaises((ValueError, KeyError)):
                    step.preflight(value)
            imports.assert_not_called(); supervisor.assert_not_called()
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_exact_frozen_objective_scope_and_participants_cannot_drift(self):
        for mutate in [lambda p: p.update(schema=objective.PLAN),
                lambda p: p['recipe'].update(learning_rate='0.002'),
                lambda p: p['task_link'].update(derived_contract='f' * 64),
                lambda p: p['flags'].update(installation_accepted=True),
                lambda p: p['participants'].remove('actual-source-parent')]:
            plan = copy.deepcopy(self.plan); mutate(plan); self.freeze(plan)
            with self.assertRaisesRegex(ValueError, 'RESEARCH_V4_EXACT_PLAN'):
                step.preflight(self.value)

    def test_loaded_model_other_contract_fields_are_still_refused(self):
        # The original exact verifier, also called on actual child-loaded bytes.
        self.prior.test_every_other_field_and_extra_registration_field_refuse()
        self.prior.test_actual_loaded_raw_and_identity_are_independently_checked()
        self.assertEqual(self.prior.base.base.fixture.contract_path.read_bytes(),
                         runtime.contract_module().freeze_target_contract(self.prior.parent)[0])

    def completion(self):
        self.prior.base.value = self.value
        directory, report = self.prior.base.completed_fixture(changed=True)
        report.update(schema='llm-runtime-parent-step-actual-v4', source=self.value['source'],
            research=research.context(self.value), task_link=self.value['initial_setup']['task_link'])
        report['training'].update(tokens=526, supervised_tokens=40, objective=objective.objective_record())
        runtime.save(directory / 'parent-candidate-v4.json', v2.candidate_record(
            self.value, report['setup'], report['candidate'], True))
        runtime.save(directory / 'actual-receipt.json', report)
        return directory, report

    def test_receipt_cannot_relabel_old_schema_omit_actual_task_or_claim_installation(self):
        directory, report = self.completion()
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))
        for mutate in [lambda r: r.update(schema='llm-runtime-parent-step-actual-v3'),
                lambda r: r.pop('task_link'),
                lambda r: r['task_link'].update(derived_contract=r['parent']['contract']),
                lambda r: r['research'].update(task_link='f' * 64),
                lambda r: r.update(installation_accepted=True),
                lambda r: r['training']['objective'].update(nonzero_weight_tokens=10)]:
            changed = copy.deepcopy(report); mutate(changed)
            runtime.save(directory / 'actual-receipt.json', changed)
            with self.assertRaises(ValueError):
                step.verify_completion(self.value)

    def test_unreaped_child_stays_failed_with_original_caps_and_new_namespace(self):
        args = self.arguments()
        terminal = dict(outcome='success', exit_code=0, stop_reason=None,
            budget=self.prior.plan['training_budget'], waited_child_reaped=False,
            owned_child_reap_resolved=False, owned_child_echild_observed=False,
            waited_child_observation_error=None)
        with patch.object(runtime, 'supervise', return_value=terminal) as supervisor:
            with self.assertRaisesRegex(ValueError, 'CHILD_FAILED'): step.run(args)
        root = Path(args.output)
        self.assertEqual(runtime.read_json(root / 'parent-step-input-v4.json'), self.value)
        result = runtime.read_json(root / 'parent-step-result-v4.json')
        self.assertFalse(result['completion_verified'])
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(supervisor.call_args.args[2], self.prior.plan['training_budget'])
        self.assertFalse((root / 'parent-step-result-v3.json').exists())

    def test_evaluation_and_readback_remain_unimplemented(self):
        for operation in ('evaluate', 'readback'):
            with self.assertRaisesRegex(ValueError, 'RESEARCH_V4_TRAIN_ONLY'):
                step.preflight(dict(self.value, operation=operation))

    def observation_fixture(self):
        execution, actual = self.completion()
        directory = execution.parent
        terminal = dict(outcome='success', exit_code=0, stop_reason=None,
            budget=self.prior.plan['training_budget'], waited_child_reaped=True,
            owned_child_reap_resolved=True, owned_child_echild_observed=False,
            waited_child_observation_error=None)
        runtime.save(execution / 'supervisor.json', terminal)
        runtime.save(directory / 'parent-step-input-v4.json', self.value)
        result = dict(schema='llm-runtime-parent-step-result-v4', scope=step.SCOPE,
            input=runtime.identity(self.value), attempt_binding=v2.binding(self.value),
            supervisor=terminal, outcome='success', completion_verified=True,
            actual_receipt_sha256=runtime.file_sha(execution / 'actual-receipt.json'), flags=step.FALSES)
        runtime.save(directory / 'parent-step-result-v4.json', result)
        request = dict(schema=observation.INPUT_V4, scope=observation.SCOPE, operation='evaluate',
            attempt_id=runtime.identity('explicit-V4-observer'), source=observation._sources(research.PROFILE),
            training_directory=str(directory), training_input_digest=runtime.identity(self.value),
            training_result_sha256=runtime.file_sha(directory / 'parent-step-result-v4.json'),
            candidate_record_sha256=runtime.file_sha(execution / 'parent-candidate-v4.json'),
            actual_training_receipt_sha256=result['actual_receipt_sha256'], parent=self.value['parent'],
            candidate=actual['candidate'], plan_digest=self.value['experiment'],
            output=str(directory.parent / 'observation/execution'), flags=step.FALSES)
        return directory, request, result

    def test_explicit_v4_observer_validates_lineage_and_old_schema_cannot_borrow_it(self):
        directory, request, result = self.observation_fixture()
        self.assertEqual(observation._preflight(request)[0], self.value)
        # Even putting a V4 frame at old filenames cannot select the new path.
        runtime.save(directory / 'parent-step-input-v2.json', self.value)
        runtime.save(directory / 'parent-step-result-v2.json', result)
        with self.assertRaisesRegex(ValueError, 'OBSERVATION_SOURCE'):
            observation._preflight(dict(request, schema=observation.INPUT))
        runtime.save(directory / 'parent-step-result-v4.json', dict(result,
            schema='llm-runtime-parent-step-result-v3'))
        changed = dict(request, training_result_sha256=runtime.file_sha(directory / 'parent-step-result-v4.json'))
        with self.assertRaisesRegex(ValueError, 'TRAINING_CONTEXT'):
            observation._preflight(changed)

    def test_new_observer_cannot_turn_exit_zero_without_reap_into_evaluation(self):
        directory, request, _ = self.observation_fixture()
        args = SimpleNamespace(producer_version='v4', training_directory=str(directory),
            expected_training_result_sha256=request['training_result_sha256'],
            expected_candidate_record_sha256=request['candidate_record_sha256'],
            expected_contract=request['parent']['contract'], expected_parent_adapter=request['parent']['adapter'],
            expected_parent_file_sha256=request['parent']['file_sha256'],
            expected_candidate_adapter=request['candidate']['adapter'],
            expected_candidate_file_sha256=request['candidate']['file_sha256'],
            output=str(Path(request['output']).parent), attempt_id=request['attempt_id'])
        terminal = dict(outcome='success', exit_code=0, stop_reason=None,
            budget=self.prior.plan['inference_budget'], waited_child_reaped=False,
            owned_child_reap_resolved=False, owned_child_echild_observed=False,
            waited_child_observation_error=None)
        with patch.object(runtime, 'supervise', return_value=terminal), \
                patch.object(observation, '_verify_observation') as verify:
            with self.assertRaisesRegex(ValueError, 'OBSERVATION_TERMINAL'): observation._run(args)
            verify.assert_not_called()
        failed = runtime.read_json(Path(args.output) / 'candidate-observation-result.json')
        self.assertEqual(failed['schema'], observation.RESULT_V4)
        self.assertEqual(failed['outcome'], 'failed')
        self.assertFalse(failed['completion_verified'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
