"""Synthetic contract/lineage controls; no model execution or admission proof."""
import ast
import copy
import inspect
from pathlib import Path
import unittest

import llm_initial_trainable_setup_v2 as setup
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_parent_step_task_v2 as task
import llm_runtime_pilot as runtime
import test_llm_runtime_parent_step_v2 as prior


class NewTaskProfileTests(unittest.TestCase):
    def setUp(self):
        self.base = prior.ParentStepV2Tests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.parent = copy.deepcopy(self.base.contract)
        self.parent['registration']['target_admission'] = runtime.identity(dict(prior='registered-task'))
        c = runtime.contract_module()
        raw, cid = c.freeze_target_contract(self.parent)
        wrapped, aid = c.freeze_wrapped_adapter(setup._wrapped(self.parent, cid, self.base.original), self.parent, cid)
        f = self.base.base.fixture
        f.contract_path.write_bytes(raw); f.adapter_path.write_bytes(wrapped)
        self.value = copy.deepcopy(self.base.value)
        self.value['parent'].update(contract=cid, adapter=aid)
        origin = dict(self.base.origin, **self.value['parent'])
        runtime.save(self.base.origin_path, origin)
        self.value['initial_setup'].update(profile=v2.NEW_TASK_PROFILE,
            parent_material=dict(path=str(self.base.origin_path), sha256=runtime.file_sha(self.base.origin_path)))
        self.value['source'] = v2.sources(v2.NEW_TASK_PROFILE)
        self.value['initial_setup']['task_link'] = task.request_link(self.value)
        self.plan = self.base.base.plan
        self.current, self.current_raw, self.current_id = task.derive(self.value, self.parent, self.plan,
            self.base.base.manifest, self.base.base.config)
        self.base.value, self.base.contract, self.base.base.cid = self.value, self.parent, cid

    def verify(self, current=None, value=None):
        current = self.current if current is None else current
        raw, cid = runtime.contract_module().freeze_target_contract(current)
        return task.verify_link(value or self.value, self.parent, current, raw, cid, self.plan)

    def completed(self):
        directory, actual = self.base.completed_fixture()
        actual['source'] = self.value['source']
        actual['task_link'] = self.verify()
        runtime.save(directory / 'actual-receipt.json', actual)
        return directory, actual

    def test_only_explicit_new_task_profile_accepts_single_admission_difference(self):
        self.assertEqual(step.preflight(self.value)[2], self.parent)
        observed = self.verify()
        self.assertNotEqual(self.value['parent']['contract'], observed['derived_contract'])
        self.assertEqual(observed['training_plan'], runtime.identity(self.plan))
        strict = copy.deepcopy(self.value)
        strict['initial_setup'].pop('task_link')
        strict['initial_setup']['profile'] = v2.PROFILE
        strict['source'] = v2.sources()
        with self.assertRaisesRegex(ValueError, 'PARENT_STEP_CURRENT_CONTRACT'): step.preflight(strict)

    def test_every_other_field_and_extra_registration_field_refuse(self):
        before = self.base.base.fixture.contract_path.read_bytes()
        changes = [('numeric', 'operator_contract'), ('tokenizer', 'behavior_contract'),
                   ('registration', 'owner_record'), ('backbone', 'owner_reference')]
        for section, field in changes:
            current = copy.deepcopy(self.current)
            old = current[section][field]
            current[section][field] = ('0' if old[0] != '0' else '1') + old[1:]
            raw, cid = runtime.contract_module().freeze_target_contract(current)
            with self.subTest(field=(section, field)), self.assertRaisesRegex(ValueError, 'CONTRACT_DIFFERENCE'):
                task.verify_link(self.value, self.parent, current, raw, cid, self.plan)
        for mutate in [lambda c: c['registration'].update(extra='x'),
                       lambda c: c['registration'].update(independent_accepted=True),
                       lambda c: c['ports'].update(input_tokens_max=127),
                       lambda c: c['targets'][0].update(alpha=[9, 1])]:
            current = copy.deepcopy(self.current); mutate(current)
            with self.assertRaises(ValueError): self.verify(current)
        self.assertEqual(self.base.base.fixture.contract_path.read_bytes(), before)

    def test_same_admission_cannot_silently_select_new_profile(self):
        value = copy.deepcopy(self.value)
        value['parent']['contract'] = self.current_id
        value['initial_setup']['task_link']['parent_admission'] = runtime.identity(self.plan)
        with self.assertRaisesRegex(ValueError, 'CONTRACT_DIFFERENCE'):
            task.verify_link(value, self.current, self.current, self.current_raw, self.current_id, self.plan)

    def test_closed_link_source_and_wrong_expected_domains_refuse_before_effect(self):
        for mutate in [lambda v: v['initial_setup']['task_link'].update(extra=1),
                lambda v: v['initial_setup']['task_link'].update(parent_admission='f' * 64),
                lambda v: v['initial_setup']['task_link'].update(training_plan='f' * 64),
                lambda v: v['initial_setup']['task_link'].update(derived_contract=v['parent']['contract']),
                lambda v: v['source'].pop('task_link'),
                lambda v: v.update(operation='evaluate')]:
            value = copy.deepcopy(self.value); mutate(value)
            with self.assertRaises(ValueError): step.preflight(value)
        self.assertFalse(Path(self.value['output']).parent.exists())

    def test_actual_loaded_raw_and_identity_are_independently_checked(self):
        for raw, cid in [(self.current_raw + b' ', self.current_id), (self.current_raw, 'f' * 64)]:
            with self.assertRaisesRegex(ValueError, 'CONTRACT_DIFFERENCE'):
                task.verify_link(self.value, self.parent, self.current, raw, cid, self.plan)

    def test_candidate_keeps_old_parent_contract_and_binds_actual_new_domain(self):
        directory, actual = self.completed()
        self.assertEqual(step.verify_completion(self.value), runtime.file_sha(directory / 'actual-receipt.json'))
        wrapper = runtime.read_json(directory / 'setup-wrapped-adapter.json')
        self.assertEqual(wrapper['contract'], self.value['parent']['contract'])
        self.assertNotEqual(wrapper['contract'], actual['task_link']['derived_contract'])
        self.assertTrue(all(actual[n] is False for n in step.FALSES))
        actual['task_link']['derived_contract'] = wrapper['contract']
        runtime.save(directory / 'actual-receipt.json', actual)
        with self.assertRaisesRegex(ValueError, 'TASK_LINK_REPORT'): step.verify_completion(self.value)

    def test_child_checks_real_derived_contract_before_copy_and_keeps_one_model(self):
        source = inspect.getsource(v2.child)
        self.assertLess(source.index('verify_link(value'), source.index('capture_seeded_a'))
        self.assertLess(source.index("cid = value['parent']['contract']"), source.index('prepare_working_copy'))
        calls = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        self.assertEqual(sum(n.func.attr == 'make_contract' for n in calls), 1)
        self.assertEqual(sum(n.func.attr == 'insert_lora' for n in calls), 1)
        self.assertNotIn('supervise(', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
