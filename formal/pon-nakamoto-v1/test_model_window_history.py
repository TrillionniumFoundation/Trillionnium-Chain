"""Synthetic multi-window records; no model execution or independent custody."""
import copy
import unittest
from unittest.mock import patch

import model_window_history as window
from contract_wire import H, canonical
from llm_adapter_contract import freeze, validate_run_plan, evaluate_run_record, CONTROL_IDS
from model_acceptance import freeze_preregistration
from test_model_acceptance import fixture
from test_llm_adapter_contract import fixture_record, identity


def rebuild(data, *, gain=True):
    prereg, plan, receipt = data['prereg'], data['plan'], data['receipt']
    plan['tasks'].sort(key=lambda task: task['id'])
    _, pid = freeze(plan, validate_run_plan, 'target-decoder-evaluation-run-plan-v1')
    prereg['run_plan'] = pid
    prereg['future_groups'] = sorted({t['source_group'] for t in plan['tasks']
                                     if t['partition'] == 'evaluation'})
    record = fixture_record(plan, pid)
    if gain:
        for participant in record['participants'][1:]:
            for run in participant['runs']:
                run['outputs'] = {task: identity('incorrect-control') for task in run['outputs']}
    raw, aid = freeze_preregistration(prereg, plan, pid)
    receipt['preregistration'] = aid
    receipt['run_record'] = evaluate_run_record(plan, record, pid)['record']
    task = next(t for t in plan['tasks'] if t['partition'] == 'evaluation')
    receipt['consumers'][0].update(task=task['id'], candidate=plan['candidate'],
                                    output=task['target_output_sha256'])
    data.update(raw=raw, aid=aid, pid=pid, record=record)


def model_fixture(number):
    prereg, _, _, plan, _, _, receipt, material = fixture()
    for task in plan['tasks']:
        for field in ('id', 'prompt_sha256', 'source_group'):
            task[field] = identity(str(number) + ':' + task[field])
    prereg['training_groups'] = [identity('training:' + str(number))]
    for probe in prereg['probes']:
        probe['prompt'] = identity(str(number) + ':' + probe['prompt'])
    receipt['probes'] = [dict(id=p['id'], outputs={name: p['target']
                         for name in ('candidate', *CONTROL_IDS)}) for p in prereg['probes']]
    offset = (number - 1) * 50
    for field in ('registered_at', 'release_after', 'closes_at', 'retention_until'):
        prereg[field] += offset
    for field in ('observed_at', 'task_released_at'):
        receipt[field] += offset
    for use in receipt['consumers']:
        use['used_at'] += offset
    for row in receipt['retention']:
        for field in ('starts_at', 'ends_at', 'retrieved_at'):
            row[field] += offset
    data = dict(prereg=prereg, plan=plan, receipt=receipt, material=material)
    rebuild(data)
    return data


def initial_history(data):
    return window.empty_history(identity('external-series'), data['prereg']['owner'],
                                data['prereg']['governance'])


def bind(data, history):
    history_raw, hid = window.freeze_history(history)
    declaration = dict(schema='pon-model-window-preregistration-v1', scope=window.SCOPE,
        context=H(window.CONTEXT_DOMAIN, canonical(history['context'])).hex(),
        ordinal=len(history['entries']) + 1, previous=history['head'],
        preregistration=data['aid'], run_plan=data['pid'])
    raw, wid = window.freeze_window(declaration, history_raw, hid, data['raw'],
                                     data['aid'], data['plan'], data['pid'])
    return dict(window_raw=raw, expected_window=wid, history_raw=history_raw,
                expected_history=hid, preregistration_raw=data['raw'],
                expected_preregistration=data['aid'], plan=data['plan'],
                expected_plan=data['pid'], record=data['record'], receipt=data['receipt'],
                material=data['material'])


def complete(data, history):
    return window.verify_window(**bind(data, history))


class ModelWindowHistoryTests(unittest.TestCase):
    def setUp(self):
        self.first = model_fixture(1)
        self.genesis = initial_history(self.first)
        self.one = complete(self.first, self.genesis)
        self.history = self.one['history']
        self.second = model_fixture(2)

    def evaluation(self, data):
        return next(t for t in data['plan']['tasks'] if t['partition'] == 'evaluation')

    def calibration(self, data):
        return next(t for t in data['plan']['tasks'] if t['partition'] == 'calibration')

    def test_three_windows_link_all_entries_and_keep_external_flags_false(self):
        original = copy.deepcopy(self.history)
        two = complete(self.second, self.history)
        three = complete(model_fixture(3), two['history'])
        self.assertEqual(original, self.history)
        self.assertEqual(len(three['history']['entries']), 3)
        self.assertEqual(two['previous_history'], self.one['next_history'])
        self.assertEqual(three['previous_history'], two['next_history'])
        self.assertEqual(window.freeze_history(three['history'])[1], three['next_history'])
        for result in (self.one, two, three):
            self.assertTrue(result['window_consumed'])
            self.assertTrue(result['assessment']['reported_gates_passed'])
            for field in ('historical_execution_verified', 'hidden_windows_excluded',
                          'physical_custody_verified', 'prospective_accepted',
                          'independent_accepted', 'public_reward_eligible', 'production_activation'):
                self.assertIs(result[field], False)

    def test_old_evaluation_id_rejects_with_new_prompt_and_group(self):
        self.evaluation(self.second)['id'] = self.evaluation(self.first)['id']
        rebuild(self.second)
        with self.assertRaisesRegex(ValueError, 'WINDOW_REUSED_TASK'):
            bind(self.second, self.history)

    def test_old_evaluation_prompt_rejects_after_id_and_group_relabel(self):
        self.evaluation(self.second)['prompt_sha256'] = self.evaluation(self.first)['prompt_sha256']
        rebuild(self.second)
        with self.assertRaisesRegex(ValueError, 'WINDOW_REUSED_PROMPT'):
            bind(self.second, self.history)

    def test_old_calibration_prompt_is_not_fresh_evaluation(self):
        self.evaluation(self.second)['prompt_sha256'] = self.calibration(self.first)['prompt_sha256']
        rebuild(self.second)
        with self.assertRaisesRegex(ValueError, 'WINDOW_REUSED_PROMPT'):
            bind(self.second, self.history)

    def test_old_probe_prompt_is_not_fresh_evaluation(self):
        self.evaluation(self.second)['prompt_sha256'] = self.first['prereg']['probes'][0]['prompt']
        rebuild(self.second)
        with self.assertRaisesRegex(ValueError, 'WINDOW_REUSED_PROMPT'):
            bind(self.second, self.history)

    def test_old_training_calibration_and_evaluation_groups_reject(self):
        groups = [self.first['prereg']['training_groups'][0],
                  self.calibration(self.first)['source_group'],
                  self.evaluation(self.first)['source_group']]
        for group in groups:
            data = model_fixture(2)
            self.evaluation(data)['source_group'] = group
            rebuild(data)
            with self.subTest(group=group), self.assertRaisesRegex(ValueError, 'WINDOW_REUSED_GROUP'):
                bind(data, self.history)

    def test_old_tasks_can_train_and_calibrate_when_future_evaluation_is_new(self):
        source = self.calibration(self.first)
        target = self.calibration(self.second)
        for field in ('id', 'prompt_sha256', 'source_group'):
            target[field] = source[field]
        self.second['prereg']['training_groups'] = [self.evaluation(self.first)['source_group']]
        self.second['prereg']['probes'] = copy.deepcopy(self.first['prereg']['probes'])
        rebuild(self.second)
        self.assertTrue(complete(self.second, self.history)['window_consumed'])

    def test_common_target_outputs_are_not_a_global_exclusion_set(self):
        self.assertEqual({t['target_output_sha256'] for t in self.first['plan']['tasks']},
                         {t['target_output_sha256'] for t in self.second['plan']['tasks']})
        self.assertTrue(complete(self.second, self.history)['window_consumed'])

    def test_candidate_may_change_within_fixed_owner_governance_context(self):
        self.second['plan']['candidate'] = identity('different-candidate')
        rebuild(self.second)
        self.assertTrue(complete(self.second, self.history)['window_consumed'])

    def test_zero_gain_consumes_window_and_cannot_retry_same_future_prompts(self):
        rebuild(self.second, gain=False)
        result = complete(self.second, self.history)
        self.assertFalse(result['assessment']['reported_gates']['reported_gain'])
        self.assertFalse(result['history']['entries'][-1]['reported_gates_passed'])
        third = model_fixture(3)
        self.evaluation(third)['prompt_sha256'] = self.evaluation(self.second)['prompt_sha256']
        rebuild(third)
        with self.assertRaisesRegex(ValueError, 'WINDOW_REUSED_PROMPT'):
            bind(third, result['history'])

    def test_malformed_current_record_does_not_advance_or_mutate_history(self):
        args = bind(self.second, self.history)
        saved = canonical(self.history)
        args['material'] = dict(args['material'])
        args['material'].pop(next(iter(args['material'])))
        with self.assertRaisesRegex(ValueError, 'MATERIAL_SET'):
            window.verify_window(**args)
        self.assertEqual(canonical(self.history), saved)
        self.assertEqual(window.freeze_history(self.history)[1], self.one['next_history'])

    def test_declared_over_budget_run_is_not_consumed_as_successful_evidence(self):
        args = bind(self.second, self.history)
        saved = canonical(self.history)
        args['record'] = copy.deepcopy(args['record'])
        args['record']['participants'][0]['runs'][0]['costs'][0]['cpu_ns'] = (1 << 63) - 1
        with self.assertRaisesRegex(ValueError, 'LLM_REPORTED_BUDGET_EXCEEDED'):
            window.verify_window(**args)
        self.assertEqual(canonical(self.history), saved)

    def test_external_history_and_window_identities_cannot_be_self_selected(self):
        for field in ('expected_history', 'expected_window'):
            args = bind(self.second, self.history)
            args[field] = identity('untrusted-replacement')
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'MANIFEST_IDENTITY'):
                window.verify_window(**args)

    def test_rewind_to_empty_history_fails_against_pinned_latest_identity(self):
        args = bind(self.second, self.history)
        args['history_raw'] = window.freeze_history(self.genesis)[0]
        with self.assertRaisesRegex(ValueError, 'MANIFEST_IDENTITY'):
            window.verify_window(**args)

    def test_omitted_entry_cannot_retain_its_chain_head(self):
        changed = copy.deepcopy(self.history)
        changed['entries'].clear()
        with self.assertRaisesRegex(ValueError, 'WINDOW_HISTORY_HEAD'):
            window.freeze_history(changed)

    def test_reordered_duplicate_and_modified_prior_entries_reject(self):
        history = complete(self.second, self.history)['history']
        variants = []
        changed = copy.deepcopy(history); changed['entries'].reverse(); variants.append(changed)
        changed = copy.deepcopy(history); changed['entries'][1] = copy.deepcopy(changed['entries'][0]); variants.append(changed)
        changed = copy.deepcopy(history); changed['entries'][0]['receipt'] = identity('substitute'); variants.append(changed)
        for changed in variants:
            with self.subTest(entries=changed['entries']), self.assertRaisesRegex(ValueError, 'WINDOW_HISTORY_LINK'):
                window.freeze_history(changed)

    def test_old_declared_identity_sets_are_rebuilt_not_supplied_as_authority(self):
        changed = copy.deepcopy(self.history)
        changed['exposed_prompts'] = []
        with self.assertRaisesRegex(ValueError, 'WINDOW_HISTORY_FIELDS'):
            window.freeze_history(changed)

    def test_owner_governance_or_series_change_requires_a_fresh_external_context(self):
        for field in ('owner', 'governance'):
            data = model_fixture(2)
            data['prereg'][field] = identity('changed-' + field)
            rebuild(data)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'WINDOW_OWNER_GOVERNANCE'):
                bind(data, self.history)
        args = bind(self.second, self.history)
        alternate = window.empty_history(identity('alternate-series'), self.second['prereg']['owner'],
                                         self.second['prereg']['governance'])
        args['history_raw'], args['expected_history'] = window.freeze_history(alternate)
        with self.assertRaisesRegex(ValueError, 'WINDOW_PREREGISTRATION_BINDING'):
            window.verify_window(**args)

    def test_later_window_registration_must_follow_prior_observed_record(self):
        self.second['prereg']['registered_at'] = self.first['receipt']['observed_at']
        rebuild(self.second)
        with self.assertRaisesRegex(ValueError, 'WINDOW_CHRONOLOGY'):
            bind(self.second, self.history)

    def test_history_gate_boolean_ordinal_and_unknown_field_boundaries(self):
        for value in (0, 1, None, 'true'):
            changed = copy.deepcopy(self.history)
            changed['entries'][0]['reported_gates_passed'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'WINDOW_GATE_TYPE'):
                window.freeze_history(changed)
        changed = copy.deepcopy(self.history)
        changed['entries'][0]['window']['ordinal'] = True
        with self.assertRaisesRegex(ValueError, 'WINDOW_ORDINAL'):
            window.freeze_history(changed)
        changed = copy.deepcopy(self.history)
        changed['entries'][0]['production_activation'] = True
        with self.assertRaisesRegex(ValueError, 'WINDOW_ENTRY_FIELDS'):
            window.freeze_history(changed)

    def test_history_count_byte_and_cumulative_item_limits(self):
        with patch.object(window, 'MAX_WINDOWS', 1):
            with self.assertRaisesRegex(ValueError, 'WINDOW_HISTORY_FULL'):
                bind(self.second, self.history)
        raw, _ = window.freeze_history(self.history)
        with patch.object(window, 'MAX_HISTORY_BYTES', len(raw) - 1):
            with self.assertRaisesRegex(ValueError, 'WINDOW_HISTORY_BYTE_BOUND'):
                window.freeze_history(self.history)
        existing = sum(len(self.history['entries'][0][name])
                       for name in ('tasks', 'probe_prompts', 'training_groups'))
        with patch.object(window, 'MAX_ITEMS', existing):
            with self.assertRaisesRegex(ValueError, 'WINDOW_HISTORY_ITEM_BOUND'):
                bind(self.second, self.history)

    def test_preregistration_reserves_bytes_for_the_completed_window(self):
        result = complete(self.second, self.history)
        actual_bytes = len(window.freeze_history(result['history'])[0])
        # The current history fits. Its next result cannot fit, so do not admit
        # that evaluation window before its reported outcome can be retained.
        self.assertLess(len(window.freeze_history(self.history)[0]), actual_bytes - 1)
        with patch.object(window, 'MAX_HISTORY_BYTES', actual_bytes - 1):
            with self.assertRaisesRegex(ValueError, 'WINDOW_HISTORY_BYTE_BOUND'):
                bind(self.second, self.history)

    def test_exact_reserved_bytes_can_retain_a_late_false_gate_outcome(self):
        rebuild(self.second, gain=False)
        self.second['receipt']['observed_at'] = self.second['prereg']['closes_at']
        result = complete(self.second, self.history)
        exact_bytes = len(window.freeze_history(result['history'])[0])
        with patch.object(window, 'MAX_HISTORY_BYTES', exact_bytes):
            retained = complete(self.second, self.history)
            self.assertFalse(retained['history']['entries'][-1]['reported_gates_passed'])
            self.assertEqual(len(window.freeze_history(retained['history'])[0]), exact_bytes)

    def test_history_task_prompts_and_partition_coverage_match_v1_shape(self):
        changed = copy.deepcopy(self.history)
        tasks = changed['entries'][0]['tasks']
        tasks[1]['prompt'] = tasks[0]['prompt']
        with self.assertRaisesRegex(ValueError, 'WINDOW_TASK_PROMPT_ALIAS'):
            window.freeze_history(changed)
        changed = copy.deepcopy(self.history)
        changed['entries'][0]['tasks'] = [t for t in changed['entries'][0]['tasks']
                                          if t['partition'] == 'evaluation']
        with self.assertRaisesRegex(ValueError, 'WINDOW_PARTITION_COVERAGE'):
            window.freeze_history(changed)

    def test_noncanonical_and_duplicate_json_cannot_create_a_history_anchor(self):
        args = bind(self.second, self.history)
        args['history_raw'] += b'\n'
        args['expected_history'] = H(window.HISTORY_DOMAIN, args['history_raw']).hex()
        with self.assertRaisesRegex(ValueError, 'MANIFEST_CANONICAL'):
            window.verify_window(**args)
        args = bind(self.second, self.history)
        args['history_raw'] = b'{"schema":0,"schema":1}'
        args['expected_history'] = H(window.HISTORY_DOMAIN, args['history_raw']).hex()
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            window.verify_window(**args)


if __name__ == '__main__':
    unittest.main(verbosity=2)
