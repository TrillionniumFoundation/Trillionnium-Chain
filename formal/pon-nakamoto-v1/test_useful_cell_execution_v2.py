"""Independent arithmetic and rejection controls for the bounded V2 executor.

Fixtures here are small synthetic arithmetic examples, not authenticated source
tasks or new production/model-quality evidence.  Real SHA256 vectors cover the
sampler.  The two explicitly labelled injected-digest tests exercise otherwise
astronomically rare rejection branches; they do not certify real sample draws.
"""
from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from contract_wire import H, canonical
from ledger import FAMILY
from model_contract import CLASSES, DIM, SCALE
import useful_cell_execution_v2 as execution


def matrix(value=0):
    return [[value] * DIM for _ in range(3)]


def model_fixture():
    return {'schema': 'hepta-source-owner-linear-256-v1', 'family': FAMILY.hex(),
            'scale': SCALE, 'source': '12' * 20, 'feature': 'signed-token-hash-256-clipped8-plus-bias-v1',
            'classes': list(CLASSES), 'base': matrix(), 'router': matrix(),
            'deltas': [matrix() for _ in range(3)]}


def rows_fixture(count=1, *, feature=2, label=1):
    result = []
    for index in range(count):
        features = [0] * DIM
        features[0], features[-1] = feature, 8
        result.append({'id': format(index + 1, '064x'), 'file': 'source/' + str(index) + '.rs',
                       'source_content_sha256': format(index + 1000, '064x'),
                       'split': 'consumer', 'label': label, 'x': features})
    return result


def training_fixture(*, enabled=True):
    return {'learning_rate_num': 1, 'learning_rate_den': 10,
            'momentum_num': 0, 'momentum_den': 1, 'clip_abs': 100,
            'trainable_mask': {'base': matrix(enabled), 'deltas': [matrix(enabled) for _ in range(3)]}}


class UsefulCellExecutionTests(unittest.TestCase):
    def setUp(self):
        self.model = model_fixture()
        self.rows = rows_fixture()
        self.policy = execution.default_policy(1)
        self.before = self.state()

    def state(self, *, model=None, steps=10):
        return execution.initial_state(self.model if model is None else model,
                                       cell_id='11' * 32, generation=7, scope='research/cell-a',
                                       rng_seed='22' * 32, remaining_steps=steps)

    def run_cell(self, *, model=None, rows=None, before=None, policy=None, products=None):
        return execution.execute(self.model if model is None else model,
                                 self.rows if rows is None else rows,
                                 self.before if before is None else before,
                                 self.policy if policy is None else policy,
                                 verified_products=products)

    @staticmethod
    def stage(result, name):
        return next(row for row in result['trace'] if row['stage'] == name)

    def test_zero_model_has_hand_computable_outputs_and_real_transition(self):
        value = self.run_cell()
        output = value['output']
        self.assertEqual(output['logits'], [[0, 0, 0]])
        self.assertEqual(output['routes'], [0])
        self.assertEqual(output['predictions'], [0])
        self.assertEqual(output['actions'], ['emit'])
        self.assertEqual(output['delivery_content'], [
            {'kind': 'classification', 'source_id': self.rows[0]['id'], 'label': 'M00'}])
        self.assertEqual(value['after_state']['sequence'], 1)
        self.assertEqual(value['after_state']['remaining_steps'], 9)
        self.assertEqual(value['after_state']['memory'], [0, 0, 0])
        self.assertEqual(value['after_model'], self.model)
        self.assertEqual(json.loads(canonical(value)), value)

    def test_preprocessor_really_zeros_features_and_preserves_source_metadata(self):
        self.policy['feature_mask'][0] = False
        self.model['base'][0][0] = 9
        self.before = self.state()
        prepared = execution.prepare_rows(self.rows, self.policy)
        self.assertEqual(prepared[0]['x'][0], 0)
        self.assertEqual(prepared[0]['x'][-1], 8)
        self.assertEqual(self.rows[0]['x'][0], 2)
        self.assertEqual(prepared[0]['id'], self.rows[0]['id'])
        value = self.run_cell()
        self.assertEqual(value['output']['logits'], [[0, 0, 0]])
        self.assertEqual(self.stage(value, 'preprocess')['outputs']['rows'], prepared)

    def test_bias_feature_cannot_be_masked(self):
        self.policy['feature_mask'][-1] = False
        with self.assertRaisesRegex(ValueError, 'BIAS_MASK'):
            self.run_cell()

    def test_router_ties_use_lowest_legal_expert_and_selected_delta(self):
        for expert in range(3):
            self.model['router'][expert][0] = 5
        self.model['deltas'][1][2][0] = 3
        self.policy['expert_mask'] = [[False, True, True]]
        self.before = self.state()
        value = self.run_cell()
        self.assertEqual(value['output']['routes'], [1])
        self.assertEqual(value['output']['logits'], [[0, 0, 6]])
        self.assertEqual(value['output']['predictions'], [2])

    def test_all_false_expert_mask_and_non_boolean_masks_fail_closed(self):
        for mask in ([False, False, False], [1, True, False], [True, False], [True] * 4):
            with self.subTest(mask=mask):
                self.policy['expert_mask'] = [mask]
                with self.assertRaisesRegex(ValueError, 'EXPERT_MASK'):
                    self.run_cell()
        self.policy = execution.default_policy(1)
        self.policy['feature_mask'][0] = 1
        with self.assertRaisesRegex(ValueError, 'FEATURE_MASK'):
            self.run_cell()

    def test_every_operator_product_is_recomputed_including_unselected_experts(self):
        self.model['base'][0][0] = 3
        self.model['deltas'][2][1][-1] = -2
        self.before = self.state()
        products = [[0] for _ in range(15)]
        products[0][0], products[13][0] = 6, -16
        result = self.run_cell(products=products)
        self.assertEqual(result['output']['logits'], [[6, 0, 0]])
        products[13][0] += 1
        with self.assertRaisesRegex(ValueError, 'VERIFIED_PRODUCTS_MISMATCH'):
            self.run_cell(products=products)

    def test_unmasked_products_cannot_replace_actual_masked_products(self):
        self.model['base'][0][0] = 3
        self.before = self.state()
        products = [[0] for _ in range(15)]
        products[0][0] = 6
        self.policy['feature_mask'][0] = False
        with self.assertRaisesRegex(ValueError, 'VERIFIED_PRODUCTS_MISMATCH'):
            self.run_cell(products=products)

    def test_product_shape_types_and_field_encoding_are_not_accepted_as_signed_values(self):
        cases = [[[0] for _ in range(14)], [[0, 0] for _ in range(15)],
                 [[False] for _ in range(15)], [[1.0] for _ in range(15)],
                 [[execution.PRODUCT_BOUND + 1] for _ in range(15)]]
        for products in cases:
            with self.subTest(products=products[0]), self.assertRaisesRegex(ValueError, 'VERIFIED_PRODUCTS'):
                self.run_cell(products=products)

    def test_recurrent_state_changes_the_next_row_and_uses_floor_for_negative_values(self):
        self.model['base'][0][0] = 1
        self.model['base'][1][0] = -1
        self.before = self.state()
        value = self.run_cell(rows=rows_fixture(2, feature=1), policy=execution.default_policy(2))
        self.assertEqual(value['output']['logits'], [[1, -1, 0], [2049, -2049, 0]])
        self.assertEqual(value['after_state']['memory'], [3584, -3584, 0])
        self.assertEqual(value['after_state']['sequence'], 1)
        self.assertEqual(value['after_state']['remaining_steps'], 8)
        # A separate zero-model row makes the negative floor rule observable.
        self.model = model_fixture()
        self.before = self.state()
        self.before['memory'] = [-1, 0, 0]
        value = self.run_cell()
        self.assertEqual(value['after_state']['memory'][0], -2049)

    def test_stop_rows_do_not_consume_memory_rng_or_step_budget(self):
        self.before = self.state(steps=0)
        self.before['memory'] = [17, -9, 1]
        self.before['rng_counter'] = execution.U64_MAX
        self.policy['sampler'] = 'sha256-positive-shift-v1'
        value = self.run_cell()
        self.assertEqual(value['output']['actions'], ['stop'])
        for field in ('routes', 'logits', 'predictions', 'tool_proposals', 'delivery_content'):
            self.assertEqual(value['output'][field], [None])
        for field in ('memory', 'rng_counter', 'remaining_steps'):
            self.assertEqual(value['after_state'][field], self.before[field])
        self.assertEqual(value['after_state']['sequence'], self.before['sequence'] + 1)

    def test_partial_batch_exhausts_then_stops_without_silent_extra_work(self):
        self.before = self.state(steps=1)
        value = self.run_cell(rows=rows_fixture(3), policy=execution.default_policy(3))
        self.assertEqual(value['output']['actions'], ['emit', 'stop', 'stop'])
        self.assertEqual(value['output']['logits'], [[0, 0, 0], None, None])
        self.assertEqual(value['after_state']['remaining_steps'], 0)

    def test_abstention_threshold_is_strict_and_does_not_draw_rng(self):
        self.model['base'][0][0] = 5
        self.before = self.state()
        self.before['rng_counter'] = execution.U64_MAX
        self.rows = rows_fixture(feature=1)
        self.policy['abstain_margin'] = 5
        self.assertEqual(self.run_cell()['output']['actions'], ['emit'])
        self.policy['abstain_margin'] = 6
        self.policy['sampler'] = 'sha256-positive-shift-v1'
        value = self.run_cell()
        self.assertEqual(value['output']['actions'], ['abstain'])
        self.assertEqual(value['output']['predictions'], [None])
        self.assertEqual(value['after_state']['rng_counter'], execution.U64_MAX)
        self.assertEqual(value['after_state']['memory'], [2048, 0, 0])
        self.assertEqual(value['after_state']['remaining_steps'], 9)

    def test_disallowed_emit_stop_abstention_and_tool_proposals_are_refused(self):
        variants = [('emit', 10, 0, [None, None, None]),
                    ('stop', 0, 0, [None, None, None]),
                    ('abstain', 10, 1, [None, None, None]),
                    ('propose_tool', 10, 0, ['research/tool', None, None])]
        for action, steps, margin, names in variants:
            with self.subTest(action=action):
                policy = execution.default_policy(1)
                policy['allowed_actions'] = [name for name in execution.ACTIONS if name != action]
                policy.update(abstain_margin=margin, tool_names=names)
                with self.assertRaisesRegex(ValueError, 'ACTION_NOT_ALLOWED'):
                    self.run_cell(before=self.state(steps=steps), policy=policy)

    def test_tool_output_is_only_computed_proposal_content(self):
        self.policy['tool_names'][0] = 'research/classify'
        value = self.run_cell()
        self.assertEqual(value['output']['actions'], ['propose_tool'])
        self.assertEqual(value['output']['tool_proposals'], [
            {'name': 'research/classify', 'arguments':
             {'source_id': self.rows[0]['id'], 'label': 'M00', 'logits': [0, 0, 0]}}])
        self.assertEqual(value['output']['delivery_content'], [None])
        self.assertNotIn('authorization', value['output'])

    def test_real_sha256_sampling_matches_independent_positive_shift_roulette(self):
        self.policy['sampler'] = 'sha256-positive-shift-v1'
        self.before['memory'] = [-7, 2, 11]
        self.before['rng_counter'] = 13
        masses = [1, 10, 19]
        counter = 13
        threshold = (1 << 256) - ((1 << 256) % 30)
        while True:
            raw = (b'pon-useful-cell-execution-v2/positive-shift\x00' + bytes.fromhex('22' * 32)
                   + counter.to_bytes(8, 'little'))
            number = int.from_bytes(hashlib.sha256(raw).digest(), 'big')
            counter += 1
            if number < threshold:
                break
        ticket = number % 30
        wanted = 0 if ticket < masses[0] else 1 if ticket < sum(masses[:2]) else 2
        value = self.run_cell()
        self.assertEqual(value['output']['predictions'], [wanted])
        self.assertEqual(value['after_state']['rng_counter'], counter)
        sample = self.stage(value, 'decision/0')['outputs']['sampling']
        self.assertEqual(sample['masses'], masses)
        self.assertEqual(sample['limit_hex'], format(threshold, '065x'))
        self.assertEqual(len(sample['limit_hex']), 65)
        self.assertEqual(json.loads(canonical(value)), value)

    def test_sampler_exact_power_of_two_threshold_remains_canonical(self):
        self.before['memory'] = [0, 0, 1]
        self.policy['sampler'] = 'sha256-positive-shift-v1'
        value = self.run_cell()
        sample = self.stage(value, 'decision/0')['outputs']['sampling']
        self.assertEqual(sample['masses'], [1, 1, 2])
        self.assertEqual(sample['limit_hex'], '1' + '0' * 64)
        self.assertEqual(json.loads(canonical(value)), value)

    def test_sampler_counter_overflow_never_wraps(self):
        self.policy['sampler'] = 'sha256-positive-shift-v1'
        self.before['rng_counter'] = execution.U64_MAX
        with self.assertRaisesRegex(ValueError, 'RNG_COUNTER_OVERFLOW'):
            self.run_cell()
        self.assertEqual(self.before['rng_counter'], execution.U64_MAX)

    def test_injected_rejection_branch_counts_every_draw_without_modulo_bias(self):
        class Digest:
            def __init__(self, raw):
                self.raw = raw

            def digest(self):
                return self.raw

        # Branch coverage only: FF...FF is the single rejected 256-bit value
        # for total=3.  It must consume counter 7 before zero accepts counter 8.
        with patch.object(execution.hashlib, 'sha256', side_effect=[Digest(b'\xff' * 32), Digest(b'\x00' * 32)]) as sha:
            prediction, counter, sample = execution._sample([0, 0, 0], '22' * 32, 7)
        self.assertEqual((prediction, counter), (0, 9))
        self.assertEqual([row['accepted'] for row in sample['draws']], [False, True])
        self.assertEqual([row['counter'] for row in sample['draws']], [7, 8])
        self.assertEqual([int.from_bytes(call.args[0][-8:], 'little') for call in sha.call_args_list], [7, 8])

    def test_injected_all_rejected_draws_stop_at_hard_cap(self):
        class Digest:
            @staticmethod
            def digest():
                return b'\xff' * 32

        with patch.object(execution.hashlib, 'sha256', return_value=Digest()) as sha:
            with self.assertRaisesRegex(ValueError, 'RNG_REJECTION_LIMIT'):
                execution._sample([0, 0, 0], '22' * 32, 0)
        self.assertEqual(sha.call_count, 64)

    def test_loss_backward_clipping_and_sgd_have_hand_computed_exact_values(self):
        self.policy['training'] = training_fixture()
        value = self.run_cell()
        self.assertEqual(value['output']['training']['loss'], 8192 ** 2)
        self.assertEqual(value['output']['training']['active_rows'], 1)
        backward = self.stage(value, 'training-backward')['outputs']
        self.assertEqual(backward['gradients']['base'][1][0], -32768)
        self.assertEqual(backward['gradients']['base'][1][-1], -131072)
        self.assertEqual(backward['gradients']['deltas'][0][1][0], -32768)
        self.assertEqual(backward['gradients']['deltas'][1], matrix())
        self.assertEqual(backward['router_gradients'], matrix())
        update = self.stage(value, 'training-update')['outputs']
        self.assertEqual(update['clipped_gradients']['base'][1][0], -100)
        self.assertEqual(update['updates']['base'][1][0], -10)
        self.assertEqual(value['after_model']['base'][1][0], 10)
        self.assertEqual(value['after_model']['base'][1][-1], 10)
        self.assertEqual(value['after_model']['deltas'][0][1][0], 10)
        self.assertEqual(value['after_model']['router'], self.model['router'])
        self.assertEqual(value['after_state']['optimizer']['step'], 1)
        self.assertEqual(value['after_state']['model_artifact'], H('artifact', canonical(value['after_model'])).hex())
        self.assertNotEqual(value['after_state']['model_artifact'], self.before['model_artifact'])

    def test_returned_updated_model_is_actually_used_by_a_following_execution(self):
        self.policy['training'] = training_fixture()
        learned = self.run_cell()
        next_value = self.run_cell(model=learned['after_model'], before=learned['after_state'],
                                   policy=execution.default_policy(1))
        self.assertEqual(next_value['output']['logits'], [[0, 200, 0]])
        self.assertEqual(next_value['output']['predictions'], [1])
        self.assertEqual(next_value['after_state']['optimizer'], learned['after_state']['optimizer'])

    def test_frozen_parameters_and_nonzero_moments_both_stay_exactly_unchanged(self):
        training = training_fixture(enabled=False)
        training.update(learning_rate_den=2, momentum_num=1, momentum_den=2, clip_abs=1)
        training['trainable_mask']['base'][1][-1] = True
        self.policy['training'] = training
        self.before['optimizer'] = {'schema': execution.OPTIMIZER_SCHEMA, 'step': 9,
                                    'base': matrix(), 'deltas': [matrix() for _ in range(3)]}
        self.before['optimizer']['base'][0][0] = 12345
        self.before['optimizer']['deltas'][0][1][-1] = -77
        self.before['optimizer']['base'][1][-1] = -5
        value = self.run_cell()
        self.assertEqual(value['after_state']['optimizer']['base'][0][0], 12345)
        self.assertEqual(value['after_state']['optimizer']['deltas'][0][1][-1], -77)
        self.assertEqual(value['after_model']['base'][0][0], 0)
        self.assertEqual(value['after_model']['deltas'][0][1][-1], 0)
        # trunc0(-5/2) + clip(-131072, 1) = -2 - 1 = -3;
        # update=trunc0(-3/2)=-1, hence the weight becomes +1.
        self.assertEqual(value['after_state']['optimizer']['base'][1][-1], -3)
        self.assertEqual(value['after_model']['base'][1][-1], 1)
        self.assertEqual(value['after_state']['optimizer']['step'], 10)

    def test_feature_mask_is_applied_to_backward_not_only_forward(self):
        self.policy['feature_mask'][0] = False
        self.policy['training'] = training_fixture()
        value = self.run_cell()
        gradients = self.stage(value, 'training-backward')['outputs']['gradients']
        self.assertEqual(gradients['base'][1][0], 0)
        self.assertEqual(gradients['base'][1][-1], -131072)
        self.assertEqual(value['after_model']['base'][1][0], 0)

    def test_gradient_is_aggregated_then_clipped_and_uses_frozen_model_for_the_batch(self):
        self.policy = execution.default_policy(2)
        self.policy['training'] = training_fixture()
        value = self.run_cell(rows=rows_fixture(2))
        self.assertEqual(value['output']['logits'], [[0, 0, 0], [0, 0, 0]])
        self.assertEqual(value['output']['training']['loss'], 2 * 8192 ** 2)
        backward = self.stage(value, 'training-backward')['outputs']['gradients']
        self.assertEqual(backward['base'][1][0], -65536)
        self.assertEqual(value['after_model']['base'][1][0], 10)
        self.assertEqual(value['after_state']['optimizer']['step'], 1)

    def test_abstain_is_trained_but_stopped_rows_are_not(self):
        self.policy = execution.default_policy(3)
        self.policy.update(abstain_margin=1, training=training_fixture())
        value = self.run_cell(rows=rows_fixture(3), before=self.state(steps=1))
        self.assertEqual(value['output']['actions'], ['abstain', 'stop', 'stop'])
        self.assertEqual(value['output']['training']['active_rows'], 1)
        self.assertEqual(value['output']['training']['loss'], 8192 ** 2)

    def test_all_stop_training_preserves_uninitialized_or_existing_optimizer(self):
        self.policy['training'] = training_fixture()
        self.before = self.state(steps=0)
        value = self.run_cell()
        self.assertEqual(value['output']['training']['loss'], 0)
        self.assertEqual(value['output']['training']['active_rows'], 0)
        self.assertIsNone(value['after_state']['optimizer'])
        self.before['optimizer'] = {'schema': execution.OPTIMIZER_SCHEMA, 'step': execution.U64_MAX,
                                    'base': matrix(7), 'deltas': [matrix(-3) for _ in range(3)]}
        value = self.run_cell()
        self.assertEqual(value['after_state']['optimizer'], self.before['optimizer'])

    def test_zero_learning_rate_retains_parameters_but_reports_real_optimizer_step(self):
        self.policy['training'] = training_fixture()
        self.policy['training']['learning_rate_num'] = 0
        value = self.run_cell()
        self.assertEqual(value['after_model'], self.model)
        self.assertIs(value['output']['training']['parameters_changed'], False)
        self.assertEqual(value['after_state']['optimizer']['base'][1][0], -100)
        self.assertEqual(value['after_state']['optimizer']['step'], 1)

    def test_optimizer_and_sequence_overflow_and_weight_overflow_fail_closed(self):
        self.policy['training'] = training_fixture()
        self.before['optimizer'] = {'schema': execution.OPTIMIZER_SCHEMA, 'step': execution.U64_MAX,
                                    'base': matrix(), 'deltas': [matrix() for _ in range(3)]}
        with self.assertRaisesRegex(ValueError, 'OPTIMIZER_STEP_OVERFLOW'):
            self.run_cell()
        self.before = self.state(steps=0)
        self.before['sequence'] = execution.U64_MAX
        with self.assertRaisesRegex(ValueError, 'STATE_SEQUENCE_OVERFLOW'):
            self.run_cell()
        self.before = self.state()
        self.policy['training'].update(learning_rate_num=1 << 20, learning_rate_den=1)
        snapshot = copy.deepcopy((self.model, self.before))
        with self.assertRaisesRegex(ValueError, 'TRAINED_WEIGHT_RANGE'):
            self.run_cell()
        self.assertEqual((self.model, self.before), snapshot)

    def test_closed_policy_training_state_and_optimizer_fields(self):
        for key in self.policy:
            with self.subTest(missing_policy=key):
                policy = copy.deepcopy(self.policy)
                del policy[key]
                with self.assertRaises(ValueError):
                    self.run_cell(policy=policy)
        for key in self.before:
            with self.subTest(missing_state=key):
                before = copy.deepcopy(self.before)
                del before[key]
                with self.assertRaises(ValueError):
                    self.run_cell(before=before)
        training = training_fixture()
        for key in training:
            with self.subTest(missing_training=key):
                policy = copy.deepcopy(self.policy)
                policy['training'] = copy.deepcopy(training)
                del policy['training'][key]
                with self.assertRaises(ValueError):
                    self.run_cell(policy=policy)
        for value, function in ((dict(self.policy, trusted=True), execution.validate_policy),
                                (dict(self.before, authorized=True), execution.validate_state)):
            with self.assertRaises(ValueError):
                function(value, 1) if function is execution.validate_policy else function(value)

    def test_integer_fields_refuse_bool_float_negative_and_out_of_range_values(self):
        for name in ('generation', 'rng_counter', 'remaining_steps', 'sequence'):
            for wrong in (True, 1.0, -1, 1 << 64):
                with self.subTest(field=name, value=wrong):
                    before = copy.deepcopy(self.before)
                    before[name] = wrong
                    with self.assertRaises(ValueError):
                        self.run_cell(before=before)
        for name in ('learning_rate_num', 'learning_rate_den', 'momentum_num', 'momentum_den', 'clip_abs'):
            for wrong in (True, 0.5, -1, 1 << 64):
                with self.subTest(field=name, value=wrong):
                    policy = copy.deepcopy(self.policy)
                    policy['training'] = training_fixture()
                    policy['training'][name] = wrong
                    with self.assertRaises(ValueError):
                        self.run_cell(policy=policy)

    def test_training_mask_cannot_unfreeze_router_or_use_integer_boolean_aliases(self):
        policy = copy.deepcopy(self.policy)
        policy['training'] = training_fixture()
        policy['training']['trainable_mask']['router'] = matrix(True)
        with self.assertRaisesRegex(ValueError, 'TRAINABLE_MASK_FIELDS'):
            self.run_cell(policy=policy)
        del policy['training']['trainable_mask']['router']
        policy['training']['trainable_mask']['base'][0][0] = 1
        with self.assertRaisesRegex(ValueError, 'TRAINABLE_BASE_BOOLEAN'):
            self.run_cell(policy=policy)

    def test_invalid_rows_models_state_artifacts_and_actions_are_refused(self):
        for name, wrong in (('label', True), ('id', 'bad'), ('file', '../escape'), ('split', 'training')):
            with self.subTest(row_field=name):
                rows = copy.deepcopy(self.rows)
                rows[0][name] = wrong
                with self.assertRaises(ValueError):
                    self.run_cell(rows=rows)
        rows = [copy.deepcopy(self.rows[0]), copy.deepcopy(self.rows[0])]
        with self.assertRaisesRegex(ValueError, 'EXECUTION_DUPLICATE_ROW'):
            self.run_cell(rows=rows, policy=execution.default_policy(2))
        before = copy.deepcopy(self.before)
        before['model_artifact'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'STATE_MODEL_ARTIFACT_MISMATCH'):
            self.run_cell(before=before)
        for wrong in (True, 32768, -32768, 1.0):
            with self.subTest(weight=wrong):
                model = copy.deepcopy(self.model)
                model['base'][0][0] = wrong
                with self.assertRaises(ValueError):
                    self.run_cell(model=model)
        for actions in ([], ['emit', 'emit'], ['execute_tool'], [True]):
            policy = copy.deepcopy(self.policy)
            policy['allowed_actions'] = actions
            with self.assertRaises(ValueError):
                self.run_cell(policy=policy)

    def test_no_caller_owned_inputs_are_mutated_and_validators_return_copies(self):
        self.policy['training'] = training_fixture()
        snapshot = copy.deepcopy((self.model, self.rows, self.before, self.policy))
        value = self.run_cell()
        self.assertEqual((self.model, self.rows, self.before, self.policy), snapshot)
        validated = execution.validate_state(self.before)
        validated['memory'][0] = 10
        validated_policy = execution.validate_policy(self.policy, 1)
        validated_policy['training']['trainable_mask']['base'][0][0] = False
        value['after_model']['base'][0][0] = 500
        self.assertEqual((self.model, self.rows, self.before, self.policy), snapshot)

    def test_maximal_valid_numeric_trace_remains_canonical(self):
        model = model_fixture()
        model['base'] = matrix(32767)
        model['deltas'] = [matrix(32767) for _ in range(3)]
        rows = rows_fixture(64)
        for row in rows:
            row['x'] = [8] * DIM
        policy = execution.default_policy(64)
        policy.update(sampler='sha256-positive-shift-v1', training=training_fixture())
        policy['training']['learning_rate_num'] = 0
        before = self.state(model=model, steps=64)
        before['memory'] = [8192] * 3
        value = self.run_cell(model=model, rows=rows, before=before, policy=policy)
        self.assertEqual(value['output']['training']['active_rows'], 64)
        self.assertLess(value['output']['training']['loss'], 1 << 64)
        self.assertEqual(json.loads(canonical(value)), value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
