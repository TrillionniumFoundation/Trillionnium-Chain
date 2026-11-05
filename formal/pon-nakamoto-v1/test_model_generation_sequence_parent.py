"""Signed synthetic parent-control negatives; no physical evolution acceptance."""
import copy
import itertools
import unittest

import test_model_generation_sequence_context as fixtures
from llm_adapter_contract import freeze, validate_run_plan
from model_generation_sequence import (
    PLAN_DOMAIN, verify_parent_bound_generation_sequence,
)


class ParentBoundGenerationSequenceTests(unittest.TestCase):
    def setUp(self):
        self.owner = fixtures.ContextBoundGenerationSequenceTests()

    def repin(self, case):
        for plan, generation, row in zip(
                case['plans'], case['generations'], case['history']['entries']):
            _, pin = freeze(plan, validate_run_plan, PLAN_DOMAIN)
            generation['run_plan'] = pin
            row['window']['run_plan'] = pin
        self.owner.relink(case)
        self.owner.sign_receipts(case)
        self.owner.sign_contexts(case)

    def case(self, decisions=('adopted', 'adopted', 'adopted')):
        case = self.owner.case(decisions)
        for plan, generation in zip(case['plans'], case['generations']):
            plan['controls'][0]['artifact'] = generation['predecessor_model']
        self.repin(case)
        return case

    def verify(self, case):
        return verify_parent_bound_generation_sequence(
            *self.owner.args(case), case['plans'], case['initial'], case['contexts'])

    def test_complete_signatures_parent_bindings_and_false_authority(self):
        case = self.case()
        before = copy.deepcopy(case)
        legacy = self.owner.verify(case)
        result = self.verify(case)
        self.assertEqual(case, before)
        self.assertEqual(result, self.verify(case))
        self.assertEqual(result['verified_context_sequence'], legacy['id'])
        self.assertNotEqual(result['id'], legacy['id'])
        self.assertTrue(result['supplied_parent_control_identities_verified'])
        self.assertEqual(len(result['parent_control_bindings']), 3)
        for binding, generation in zip(result['parent_control_bindings'], case['generations']):
            self.assertEqual(binding['evaluated_parent_control'], generation['predecessor_model'])
        for name in ('hidden_windows_excluded', 'actual_model_installation_verified',
                     'independent_controller_verified', 'new_consumer_benefit_verified',
                     'prospective_accepted', 'independent_accepted', 'public_reward_eligible',
                     'production_activation', 'ordinary_hepta_generation_verified',
                     'physical_custody_verified'):
            self.assertIs(result[name], False)
            self.assertIs(result[name], legacy[name])

    def test_resigned_unrelated_parent_passes_v2_but_not_v3(self):
        for index in range(3):
            case = self.case()
            case['plans'][index]['controls'][0]['artifact'] = fixtures.identity(f'unrelated:{index}')
            self.repin(case)
            before = copy.deepcopy(case)
            self.assertTrue(self.owner.verify(case)['supplied_plan_exposure_verified'])
            with self.subTest(index=index), self.assertRaisesRegex(
                    ValueError, 'GENERATION_SEQUENCE_PARENT_CONTROL_BINDING'):
                self.verify(case)
            self.assertEqual(case, before)

    def test_predecessor_in_wrong_control_slot_does_not_satisfy_parent(self):
        for index in range(3):
            for other in range(1, 4):
                case = self.case()
                controls = case['plans'][index]['controls']
                controls[0]['artifact'], controls[other]['artifact'] = (
                    controls[other]['artifact'], controls[0]['artifact'])
                self.repin(case)
                self.assertTrue(self.owner.verify(case)['context_signatures_verified'])
                with self.subTest(index=index, other=other), self.assertRaisesRegex(
                        ValueError, 'GENERATION_SEQUENCE_PARENT_CONTROL_BINDING'):
                    self.verify(case)

    def test_stale_bootstrap_cannot_replace_a_later_adopted_parent(self):
        for index in (1, 2):
            case = self.case()
            case['plans'][index]['controls'][0]['artifact'] = case['initial']
            self.repin(case)
            self.assertTrue(self.owner.verify(case)['supplied_run_plans_verified'])
            with self.subTest(index=index), self.assertRaisesRegex(
                    ValueError, 'GENERATION_SEQUENCE_PARENT_CONTROL_BINDING'):
                self.verify(case)

    def test_all_adoption_and_no_update_paths_use_the_actual_selected_parent(self):
        for decisions in itertools.product(('adopted', 'no_update'), repeat=3):
            case = self.case(decisions)
            with self.subTest(decisions=decisions):
                result = self.verify(case)
                expected = case['initial']
                for binding, generation in zip(result['parent_control_bindings'], case['generations']):
                    self.assertEqual(binding['evaluated_parent_control'], expected)
                    expected = generation['adopted_model']
                self.assertEqual(result['terminal_model'], expected)

    def test_no_gain_and_every_owner_hold_remain_non_authorizing(self):
        for reason in ('no_gain', 'safety_hold', 'consent_withdrawn',
                       'resource_unavailable', 'selection_fenced'):
            case = self.case(('adopted', 'no_update', 'adopted'))
            case['receipts'][1]['decision_reason'] = reason
            if reason == 'no_gain':
                case['receipts'][1]['candidate_score'] = 100
                case['history']['entries'][1]['reported_gates_passed'] = False
            self.repin(case)
            with self.subTest(reason=reason):
                result = self.verify(case)
                self.assertEqual(result['parent_control_bindings'][2]['predecessor_model'],
                                 case['generations'][0]['adopted_model'])
                self.assertFalse(result['production_activation'])

    def test_changed_plan_cannot_reuse_old_context_signatures(self):
        case = self.case()
        case['plans'][0]['controls'][0]['artifact'] = fixtures.identity('new-parent')
        _, pin = freeze(case['plans'][0], validate_run_plan, PLAN_DOMAIN)
        case['generations'][0]['run_plan'] = pin
        case['history']['entries'][0]['window']['run_plan'] = pin
        self.owner.relink(case)
        with self.assertRaisesRegex(ValueError, 'CONSUMER_CONTEXT_BINDING'):
            self.verify(case)

    def test_original_initial_pin_and_use_chronology_still_gate_v3(self):
        case = self.case()
        case['initial'] = fixtures.identity('unrelated-initial')
        with self.assertRaisesRegex(ValueError, 'GENERATION_SEQUENCE_INITIAL_MODEL'):
            self.verify(case)
        for index in (0, 1):
            case = self.case()
            case['receipts'][index]['used_at'] = case['history']['entries'][index + 1]['registered_at']
            self.repin(case)
            with self.subTest(index=index), self.assertRaisesRegex(
                    ValueError, 'GENERATION_SEQUENCE_PREDECESSOR_USE'):
                self.verify(case)

    def test_every_receipt_and_context_role_signature_still_runs(self):
        for lane, prefix in (('attestations', 'CONSUMER_BENEFIT'), ('contexts', 'CONSUMER_CONTEXT')):
            for index in range(3):
                for role in ('consumer', 'controller'):
                    case = self.case()
                    case[lane][index][role + '_signature'] = '00' * 64
                    with self.subTest(lane=lane, index=index, role=role), self.assertRaisesRegex(
                            ValueError, prefix + '_' + role.upper() + '_SIGNATURE'):
                        self.verify(case)

    def test_no_fallback_on_missing_plan_context_or_misreported_exposure(self):
        for plans in (None, [], [{}] * 2, [{}] * 4):
            case = self.case()
            case['plans'] = plans
            with self.assertRaisesRegex(ValueError, 'GENERATION_SEQUENCE_PLAN_COUNT'):
                self.verify(case)
        case = self.case()
        case['contexts'] = []
        with self.assertRaisesRegex(ValueError, 'CONSUMER_CONTEXT_COUNT'):
            self.verify(case)
        case = self.case()
        case['history']['entries'][1]['tasks'][0]['prompt'] = fixtures.identity('misreported-prompt')
        self.owner.relink(case)
        self.owner.sign_contexts(case)
        with self.assertRaisesRegex(ValueError, 'GENERATION_SEQUENCE_EXPOSURE_BINDING'):
            self.verify(case)


if __name__ == '__main__':
    unittest.main()
