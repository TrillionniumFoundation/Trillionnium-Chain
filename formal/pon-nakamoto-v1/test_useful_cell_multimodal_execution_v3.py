"""Hand-calculated arithmetic and raw-codec controls, not model-quality data."""
from __future__ import annotations

import copy
import hashlib
import struct
import unittest
from unittest.mock import patch

from contract_wire import canonical
import useful_cell_multimodal_execution_v3 as execution


def model_fixture():
    return {'schema': execution.MODEL_SCHEMA, 'classes': ['alpha', 'beta', 'gamma'],
            'parameters': execution.zero_parameters()}


def source(raw, name):
    return {'origin': 'arithmetic-fixture', 'object_id': name, 'sha256': hashlib.sha256(raw).hexdigest()}


def text_part(raw=b'A', mask=None):
    normalized = raw.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n').encode('utf-8')
    return {'modality': 'text-utf8', 'source': source(raw, 'text'), 'payload_hex': raw.hex(),
            'mask': [True] * len(normalized) if mask is None else mask}


def image_part(raw=bytes([255, 128, 0]), width=1, height=1, mask=None):
    return {'modality': 'image-rgb8', 'source': source(raw, 'image'), 'payload_hex': raw.hex(),
            'width': width, 'height': height, 'mask': [True] * 16 if mask is None else mask}


def audio_part(samples=(32767, 0, 0, 0), rate=8000, mask=None):
    raw = struct.pack('<' + 'h' * len(samples), *samples)
    valid = (len(samples) // (2 if rate == 16000 else 1) + 3) // 4
    return {'modality': 'audio-pcm16le', 'source': source(raw, 'audio'), 'payload_hex': raw.hex(),
            'sample_rate_hz': rate,
            'mask': [index < valid for index in range(16)] if mask is None else mask}


def inputs_fixture(*parts, label=1, identity=1):
    return [{'id': format(identity, '064x'), 'label': label, 'parts': list(parts) or [text_part()]}]


def state_fixture(model, steps=10):
    return execution.initial_state(model, cell_id='11' * 32, generation=7, scope='research/multimodal',
                                   rng_seed='22' * 32, remaining_steps=steps)


def training_fixture(*names, numerator=1, denominator=256, clip=1024):
    mask = execution.zero_parameters(False)
    for name in names:
        mask[name] = [True] * len(mask[name])
    return {'learning_rate_num': numerator, 'learning_rate_den': denominator,
            'momentum_num': 0, 'momentum_den': 1, 'clip_abs': clip, 'trainable_mask': mask}


def multimodal_model():
    model = model_fixture()
    parameters = model['parameters']
    parameters['text_embedding'][ord('A') * 8] = 12
    parameters['text_embedding'][ord('B') * 8] = -12
    parameters['image_projection'][0] = 8
    parameters['audio_projection'][0] = 8
    parameters['head'][0] = 2
    parameters['head'][8] = -1
    return model


class MultimodalExecutionTests(unittest.TestCase):
    def setUp(self):
        self.model = model_fixture()
        self.model['parameters']['text_embedding'][ord('A') * 8] = 8
        self.inputs = inputs_fixture()
        self.policy = execution.default_policy(1)

    def run_cell(self, *, inputs=None, model=None, before=None, policy=None):
        model = self.model if model is None else model
        return execution.execute(model, self.inputs if inputs is None else inputs,
                                 state_fixture(model) if before is None else before,
                                 self.policy if policy is None else policy)

    @staticmethod
    def stage(result, name):
        return next(row for row in result['trace'] if row['stage'] == name)

    @staticmethod
    def gradient(result, name):
        return MultimodalExecutionTests.stage(result, 'training-backward')['outputs']['gradients'][name]

    def test_learned_byte_embedding_changes_real_head_and_state(self):
        self.model['parameters']['head'][0] = 2
        result = self.run_cell()
        self.assertEqual(result['output']['logits'], [[16, 0, 0]])
        self.assertEqual(result['output']['actions'], ['emit'])
        self.assertEqual(result['after_state']['memory'], [16, 0, 0])
        self.assertEqual(result['after_state']['remaining_steps'], 9)
        self.assertEqual(result['after_state']['sequence'], 1)
        self.assertEqual(result['output']['delivery_content'][0]['label'], 'alpha')
        self.model['parameters']['text_embedding'][ord('A') * 8] = 7
        self.assertEqual(self.run_cell()['output']['logits'], [[14, 0, 0]])

    def test_utf8_is_decoded_normalized_and_retokenized_as_exact_bytes(self):
        raw = b'A\r\nB\r\xc3\xa9'
        prepared = execution.prepare_inputs(inputs_fixture(text_part(raw)))
        part = prepared[0]['parts'][0]
        self.assertEqual(part['decoded'], 'A\r\nB\r\u00e9')
        self.assertEqual(part['normalized'], 'A\nB\n\u00e9')
        self.assertEqual(part['tokens'], [65, 10, 66, 10, 195, 169])
        self.assertEqual(len(part['mask']), 6)

    def test_invalid_utf8_and_raw_length_are_rejected(self):
        for raw, error in ((b'\xc0\xaf', 'MM3_UTF8'), (b'A' * 65, 'MM3_TEXT_LIMIT')):
            part = text_part()
            part.update(payload_hex=raw.hex(), source=source(raw, 'bad'))
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, error):
                execution.prepare_inputs(inputs_fixture(part))

    def test_source_digest_is_checked_against_original_not_normalized_bytes(self):
        part = text_part(b'A\r\n')
        part['source']['sha256'] = hashlib.sha256(b'A\n').hexdigest()
        with self.assertRaisesRegex(ValueError, 'MM3_SOURCE_CONTENT_MISMATCH'):
            execution.prepare_inputs(inputs_fixture(part))

    def test_text_masks_apply_after_normalization_and_before_pooling(self):
        self.model['parameters']['text_embedding'][ord('B') * 8] = -8
        self.model['parameters']['head'][0] = 1
        result = self.run_cell(inputs=inputs_fixture(text_part(b'AB', [False, True])))
        self.assertEqual(result['output']['logits'], [[-8, 0, 0]])
        with self.assertRaisesRegex(ValueError, 'MM3_INPUT_MASK'):
            execution.prepare_inputs(inputs_fixture(text_part(b'A\r\n', [True] * 3)))

    def test_rgb_shape_resize_patch_order_and_quantization_have_known_values(self):
        part = image_part(bytes([0, 128, 255, 255, 128, 0]), width=2,
                          mask=[True] + [False] * 15)
        prepared = execution.prepare_inputs(inputs_fixture(part))[0]['parts'][0]
        self.assertEqual(prepared['resized_rgb8'][:15], [0, 128, 255] * 4 + [255, 128, 0])
        self.assertEqual(prepared['raw_features'][0], [-8, 0, 7] * 4)
        self.assertEqual(prepared['raw_features'][2], [7, 0, -8] * 4)
        self.model['parameters']['image_projection'][0] = 8
        self.model['parameters']['head'][0] = 1
        self.assertEqual(self.run_cell(inputs=inputs_fixture(part))['output']['logits'], [[-8, 0, 0]])

    def test_rgb_dimension_channel_count_and_integer_type_are_strict(self):
        for field, value, error in (('width', True, 'MM3_IMAGE_WIDTH'), ('height', 17, 'MM3_IMAGE_HEIGHT'),
                                    ('width', 2, 'MM3_IMAGE_BYTE_SHAPE'), ('channels', 4, 'MM3_PART_FIELDS')):
            part = image_part()
            part[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                execution.prepare_inputs(inputs_fixture(part))

    def test_pcm_little_endian_pair_mean_resample_quantize_and_padding(self):
        part = audio_part((-32768, -32768, 32767, 32767, -1, 0, 4095, 4096), rate=16000)
        prepared = execution.prepare_inputs(inputs_fixture(part))[0]['parts'][0]
        self.assertEqual(prepared['resampled_8khz'], [-32768, 32767, 0, 4095])
        self.assertEqual(prepared['quantized_audio'], [-8, 7, 0, 0])
        self.assertEqual(prepared['raw_features'][0], [-8, 7, 0, 0])
        self.assertEqual(prepared['raw_features'][1:], [[0] * 4 for _ in range(15)])
        self.model['parameters']['audio_projection'][0] = 8
        self.model['parameters']['head'][0] = 1
        self.assertEqual(self.run_cell(inputs=inputs_fixture(part))['output']['logits'], [[-8, 0, 0]])

    def test_pcm_rate_pair_byte_and_sample_boundaries_fail_closed(self):
        cases = []
        part = audio_part()
        part['sample_rate_hz'] = 44100
        cases.append((part, 'MM3_AUDIO_RATE'))
        cases.append((audio_part((1, 2, 3), rate=16000), 'MM3_AUDIO_PAIR_SHAPE'))
        cases.append((audio_part(tuple(range(65))), 'MM3_AUDIO_SAMPLE_LIMIT'))
        part = audio_part()
        part.update(payload_hex='00', source=source(b'\x00', 'odd'))
        cases.append((part, 'MM3_AUDIO_BYTE_SHAPE'))
        for part, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                execution.prepare_inputs(inputs_fixture(part))

    def test_audio_padding_cannot_be_unmasked(self):
        part = audio_part((1,))
        part['mask'][1] = True
        with self.assertRaisesRegex(ValueError, 'MM3_AUDIO_PADDING_MASK'):
            execution.prepare_inputs(inputs_fixture(part))

    def test_masks_are_boolean_and_all_masked_encoder_outputs_are_zero(self):
        self.model['parameters']['image_bias'][0] = 31
        self.model['parameters']['head'][0] = 1
        part = image_part(mask=[False] * 16)
        self.assertEqual(self.run_cell(inputs=inputs_fixture(part))['output']['logits'], [[0, 0, 0]])
        part['mask'][0] = 0
        with self.assertRaisesRegex(ValueError, 'MM3_INPUT_MASK'):
            self.run_cell(inputs=inputs_fixture(part))

    def test_three_modalities_are_actually_fused_before_feature_mask(self):
        model = multimodal_model()
        inputs = inputs_fixture(text_part(), image_part(), audio_part())
        result = self.run_cell(model=model, inputs=inputs)
        fusion = self.stage(result, 'fusion-mask')
        self.assertEqual([component[0] for component in fusion['inputs']['components'][0]], [12, 7, 7])
        self.assertEqual(fusion['outputs']['masked']['values'], [8, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(result['output']['logits'], [[16, -8, 0]])
        self.assertEqual(len(result['operations']), 12)
        self.policy['feature_mask'][0] = False
        self.assertEqual(self.run_cell(model=model, inputs=inputs)['output']['logits'], [[0, 0, 0]])

    def test_duplicate_unsorted_empty_modalities_and_duplicate_rows_are_rejected(self):
        for inputs, error in ((inputs_fixture(text_part(), text_part()), 'MM3_MODALITY_ORDER_OR_DUPLICATE'),
                              (inputs_fixture(image_part(), text_part()), 'MM3_MODALITY_ORDER_OR_DUPLICATE'),
                              ([{'id': '01' * 32, 'label': 0, 'parts': []}], 'MM3_PART_COUNT'),
                              (self.inputs + copy.deepcopy(self.inputs), 'MM3_DUPLICATE_INPUT')):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                execution.prepare_inputs(inputs)

    def test_residual_mlp_lora_composition_and_lowest_legal_tie_are_hand_computable(self):
        parameters = self.model['parameters']
        parameters['base_up'][0], parameters['base_up_bias'][0] = 2, 1
        parameters['base_down'][0], parameters['base_down_bias'][0] = 8, 2
        parameters['router'][0], parameters['router'][8], parameters['router'][16] = 1, 1, -1
        parameters['adapter_1_down'][0], parameters['adapter_1_up'][0] = 4, 6
        parameters['head'][0], parameters['head'][8], parameters['head_bias'][0] = 2, -1, 3
        self.policy['expert_mask'] = [[False, True, True]]
        result = self.run_cell()
        self.assertEqual(result['output']['routes'], [1])
        self.assertEqual(self.stage(result, 'base-up-activation')['outputs']['relu']['values'][0], 3)
        self.assertEqual(self.stage(result, 'base-residual')['outputs']['clamped']['values'][0], 13)
        self.assertEqual(self.stage(result, 'selected-adapter-residual')['outputs']['head_input']['values'][0], 16)
        self.assertEqual(result['output']['logits'], [[35, -16, 0]])
        self.assertEqual(result['after_state']['memory'], [16, -16, 0])
        self.assertEqual(len(result['operations']), 10)

    def test_full_bundle_includes_unselected_adapter_computation(self):
        self.model['parameters']['adapter_2_down'][0] = 4
        result = self.run_cell()
        operation = next(item for item in result['operations'] if item['id'] == 'adapter_2_down')
        self.assertEqual(operation['output']['values'], [32, 0])
        self.assertEqual(result['output']['routes'], [0])

    def test_sequence_recurrence_uses_previous_row_and_floor_for_negative_memory(self):
        self.model['parameters']['head'][0] = -1
        inputs = self.inputs + inputs_fixture(text_part(), identity=2)
        before = state_fixture(self.model)
        before['memory'][0] = -1
        result = self.run_cell(inputs=inputs, before=before, policy=execution.default_policy(2))
        self.assertEqual(result['output']['logits'], [[-9, 0, 0], [-25, 0, 0]])
        self.assertEqual(result['after_state']['memory'][0], -29)

    def test_stop_does_not_consume_rng_memory_or_optimizer_but_advances_sequence(self):
        self.policy['training'] = training_fixture('head')
        before = state_fixture(self.model, steps=0)
        before['memory'], before['rng_counter'] = [3, -5, 7], 9
        result = self.run_cell(before=before)
        self.assertEqual(result['output']['actions'], ['stop'])
        self.assertIsNone(result['output']['logits'][0])
        self.assertEqual(result['after_state'], dict(before, sequence=1))
        self.assertEqual(result['after_model'], self.model)
        self.assertEqual(result['output']['training']['active_rows'], 0)

    def test_abstain_updates_memory_and_training_without_sampling(self):
        self.model['parameters']['head'][0] = 1
        self.policy['sampler'], self.policy['abstain_margin'] = 'sha256-positive-shift-v3', 9
        self.policy['training'] = training_fixture(denominator=1)
        result = self.run_cell()
        self.assertEqual(result['output']['actions'], ['abstain'])
        self.assertEqual(result['after_state']['memory'], [16, 0, 0])
        self.assertEqual(result['after_state']['rng_counter'], 0)
        self.assertEqual(result['output']['training']['active_rows'], 1)

    def test_tool_proposal_and_legal_action_set_are_enforced(self):
        self.policy['tool_names'][0] = 'classification.review'
        result = self.run_cell()
        self.assertEqual(result['output']['actions'], ['propose_tool'])
        self.assertEqual(result['output']['tool_proposals'][0]['name'], 'classification.review')
        self.assertIsNone(result['output']['delivery_content'][0])
        self.policy['allowed_actions'] = ['emit']
        with self.assertRaisesRegex(ValueError, 'MM3_ACTION_NOT_ALLOWED'):
            self.run_cell()

    def test_real_sampler_vector_consumes_exact_counter_and_positive_shift_mass(self):
        self.model['parameters']['head'][0] = 2
        self.policy['sampler'] = 'sha256-positive-shift-v3'
        before = state_fixture(self.model)
        before['rng_counter'] = 17
        raw = hashlib.sha256(b'pon-useful-cell-multimodal-execution-v3/positive-shift\x00' +
                             bytes.fromhex('22' * 32) + (17).to_bytes(8, 'little')).digest()
        ticket = int.from_bytes(raw, 'big') % 19
        expected = 0 if ticket < 17 else 1 if ticket == 17 else 2
        result = self.run_cell(before=before)
        sampling = self.stage(result, 'decision/0')['outputs']['sampling']
        self.assertEqual(sampling['masses'], [17, 1, 1])
        self.assertEqual(sampling['draws'][0]['sha256'], raw.hex())
        self.assertEqual(result['output']['predictions'], [expected])
        self.assertEqual(result['after_state']['rng_counter'], 18)

    def test_injected_digest_rejection_control_consumes_rejected_draw_and_is_bounded(self):
        # Deliberately injected arithmetic branch control, not real SHA/W1 evidence.
        class Digest:
            def __init__(self, value):
                self.value = value

            def digest(self):
                return self.value

        draws = iter([b'\xff' * 32, bytes(32)])
        with patch.object(execution.hashlib, 'sha256', side_effect=lambda _: Digest(next(draws))):
            prediction, counter, report = execution._sample([0, 0, 0], '22' * 32, 4)
        self.assertEqual((prediction, counter), (0, 6))
        self.assertEqual([draw['accepted'] for draw in report['draws']], [False, True])
        with patch.object(execution.hashlib, 'sha256', return_value=Digest(b'\xff' * 32)):
            with self.assertRaisesRegex(ValueError, 'MM3_RNG_REJECTION_LIMIT'):
                execution._sample([0, 0, 0], '22' * 32, 0)

    def test_head_loss_gradient_clip_and_update_match_hand_calculation(self):
        self.model['parameters']['head'][0] = 2
        self.policy['training'] = training_fixture('head', denominator=256, clip=512)
        result = self.run_cell()
        self.assertEqual(result['output']['training']['loss'], 16 * 16 + 64 * 64)
        gradient = self.gradient(result, 'head')
        self.assertEqual((gradient[0], gradient[8]), (256, -1024))
        self.assertEqual((result['after_model']['parameters']['head'][0],
                          result['after_model']['parameters']['head'][8]), (1, 2))
        self.assertEqual((result['after_state']['optimizer']['moments']['head'][0],
                          result['after_state']['optimizer']['moments']['head'][8]), (256, -512))
        self.assertEqual(result['after_state']['optimizer']['step'], 1)

    def test_backward_reaches_learned_text_encoder_and_frozen_heads_stay_fixed(self):
        self.model['parameters']['head'][0] = 2
        self.policy['training'] = training_fixture('text_embedding', denominator=64)
        result = self.run_cell()
        self.assertEqual(self.gradient(result, 'text_embedding')[ord('A') * 8], 64)
        self.assertEqual(result['after_model']['parameters']['text_embedding'][ord('A') * 8], 7)
        self.assertEqual(result['after_model']['parameters']['head'], self.model['parameters']['head'])
        self.assertEqual(self.gradient(result, 'router'), [0] * 24)

    def test_backward_through_residual_mlp_and_selected_lora_has_hand_computed_adjoints(self):
        parameters = self.model['parameters']
        parameters['base_up'][0], parameters['base_up_bias'][0] = 2, 1
        parameters['base_down'][0], parameters['base_down_bias'][0] = 8, 2
        parameters['router'][8] = 1
        parameters['adapter_1_down'][0], parameters['adapter_1_up'][0] = 4, 6
        parameters['head'][0], parameters['head'][8], parameters['head_bias'][0] = 2, -1, 3
        self.policy['training'] = training_fixture()
        result = self.run_cell()
        # logits=(35,-16,0), d_logits=(70,-160,0), dz=300.
        # Quantized adjoints are trunc0(300/8)=37 and trunc0(222/8)=27.
        expected = {'head': 1120, 'head_bias': 70, 'adapter_1_up': 148,
                    'adapter_1_down': 216, 'base_down': 111,
                    'base_down_bias': 300, 'base_up': 296, 'base_up_bias': 296}
        for name, value in expected.items():
            self.assertEqual(self.gradient(result, name)[0], value, name)
        self.assertEqual(self.gradient(result, 'text_embedding')[65 * 8], 108 + 300 + 74)
        self.assertEqual(self.gradient(result, 'adapter_0_down'), [0] * 16)
        self.assertEqual(self.gradient(result, 'adapter_2_up'), [0] * 16)

    def test_backward_reaches_image_and_audio_projections_with_exact_quantized_adjoints(self):
        parts = (image_part(bytes([0, 128, 255]), mask=[True] + [False] * 15),
                 audio_part((-32768, 32767, 0, 0)))
        for key, part in zip(('image', 'audio'), parts):
            model = model_fixture()
            model['parameters'][key + '_projection'][0] = 8
            model['parameters']['head'][0] = 2
            policy = execution.default_policy(1)
            policy['training'] = training_fixture(key + '_projection', key + '_bias', denominator=64)
            result = self.run_cell(model=model, inputs=inputs_fixture(part), policy=policy)
            self.assertEqual(self.gradient(result, key + '_projection')[0], 64)
            self.assertEqual(self.gradient(result, key + '_bias')[0], -64)
            self.assertEqual(result['after_model']['parameters'][key + '_projection'][0], 7)
            self.assertEqual(result['after_model']['parameters'][key + '_bias'][0], 1)

    def test_surrogate_clamp_boundary_blocks_encoder_gradient_and_mask_blocks_it(self):
        self.model['parameters']['text_embedding'][ord('A') * 8] = 64
        self.model['parameters']['head'][0] = 1
        self.policy['training'] = training_fixture(denominator=1)
        result = self.run_cell()
        self.assertEqual(self.gradient(result, 'text_embedding')[ord('A') * 8], 0)
        self.model['parameters']['text_embedding'][ord('A') * 8] = 8
        self.policy['feature_mask'][0] = False
        result = self.run_cell()
        self.assertEqual(self.gradient(result, 'text_embedding')[ord('A') * 8], 0)

    def test_router_is_explicitly_frozen_not_silently_ignored_by_training_mask(self):
        self.policy['training'] = training_fixture('router')
        with self.assertRaisesRegex(ValueError, 'MM3_ROUTER_FROZEN'):
            self.run_cell()

    def test_frozen_weight_and_nonzero_moment_are_retained_and_momentum_truncates_to_zero(self):
        before = state_fixture(self.model)
        moments = execution.zero_parameters()
        moments['head'][0], moments['head_bias'][0] = -3, 97
        before['optimizer'] = {'schema': execution.OPTIMIZER_SCHEMA, 'step': 3, 'moments': moments}
        self.policy['training'] = training_fixture(denominator=1)
        self.policy['training']['trainable_mask']['head'][0] = True
        self.policy['training'].update(momentum_num=1, momentum_den=2)
        result = self.run_cell(before=before)
        self.assertEqual(result['after_state']['optimizer']['moments']['head'][0], -1)
        self.assertEqual(result['after_model']['parameters']['head'][0], 1)
        self.assertEqual(result['after_state']['optimizer']['moments']['head_bias'][0], 97)
        self.assertEqual(result['after_model']['parameters']['head_bias'][0], 0)

    def test_training_update_rejects_weight_overflow_instead_of_saturating(self):
        self.policy['training'] = training_fixture('head', denominator=1)
        with self.assertRaisesRegex(ValueError, 'MM3_TRAINED_WEIGHT_RANGE'):
            self.run_cell()

    def test_updated_encoder_is_used_on_next_distinct_input_and_old_model_rejected(self):
        self.model['parameters']['head'][0] = 2
        self.policy['training'] = training_fixture('text_embedding', denominator=64)
        first = self.run_cell()
        next_inputs = inputs_fixture(text_part(b'AA'), identity=2)
        second = self.run_cell(model=first['after_model'], before=first['after_state'], inputs=next_inputs,
                               policy=execution.default_policy(1))
        self.assertEqual(second['output']['logits'], [[30, 0, 0]])
        self.assertEqual(second['after_state']['sequence'], 2)
        with self.assertRaisesRegex(ValueError, 'MM3_STATE_MODEL_MISMATCH'):
            self.run_cell(before=first['after_state'], inputs=next_inputs)

    def test_all_stop_and_active_prefix_have_explicit_budget_behavior(self):
        inputs = self.inputs + inputs_fixture(identity=2) + inputs_fixture(identity=3)
        result = self.run_cell(inputs=inputs, before=state_fixture(self.model, steps=1),
                               policy=execution.default_policy(3))
        self.assertEqual(result['output']['actions'], ['emit', 'stop', 'stop'])
        self.assertEqual(result['after_state']['remaining_steps'], 0)

    def test_state_sequence_rng_and_optimizer_counters_never_wrap(self):
        for field in ('sequence', 'rng_counter'):
            before = state_fixture(self.model)
            before[field] = execution.U64_MAX
            self.policy['sampler'] = 'sha256-positive-shift-v3'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'OVERFLOW'):
                self.run_cell(before=before)
        before = state_fixture(self.model)
        before['optimizer'] = {'schema': execution.OPTIMIZER_SCHEMA, 'step': execution.U64_MAX,
                               'moments': execution.zero_parameters()}
        self.policy['training'] = training_fixture()
        with self.assertRaisesRegex(ValueError, 'MM3_OPTIMIZER_STEP_OVERFLOW'):
            self.run_cell(before=before)

    def test_shape_dtype_unknown_fields_and_batch_bounds_are_rejected(self):
        for value in (True, 1.0, 9):
            model = copy.deepcopy(self.model)
            model['parameters']['head'][0] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'MM3_PARAMETER_RANGE'):
                self.run_cell(model=model)
        model = copy.deepcopy(self.model)
        model['parameters']['head'].append(0)
        with self.assertRaisesRegex(ValueError, 'MM3_PARAMETER_SHAPE'):
            self.run_cell(model=model)
        model = copy.deepcopy(self.model)
        model['accepted'] = True
        with self.assertRaisesRegex(ValueError, 'MM3_MODEL_FIELDS'):
            self.run_cell(model=model)
        with self.assertRaisesRegex(ValueError, 'MM3_BATCH'):
            execution.prepare_inputs([inputs_fixture(identity=index)[0] for index in range(5)])

    def test_call_does_not_mutate_owner_model_inputs_state_or_policy(self):
        before = state_fixture(self.model)
        self.policy['training'] = training_fixture('text_embedding', denominator=64)
        objects = [self.model, self.inputs, before, self.policy]
        original = canonical(objects)
        self.run_cell(before=before)
        self.assertEqual(canonical(objects), original)


if __name__ == '__main__':
    unittest.main()
