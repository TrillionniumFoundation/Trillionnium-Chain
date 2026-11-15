"""Real full-W1 and cross-task/tensor attacks for the finite multimodal graph.

All examples are explicit arithmetic fixtures.  They measure no production
quality, external delivery or work hardness.  W1 is never mocked in this file.
"""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import unittest
from unittest.mock import patch

from contract_wire import H, canonical
import useful_cell_multimodal_execution_v3 as execution
import useful_cell_multimodal_relation_v3 as relation
import work_oracle as work
from test_useful_cell_multimodal_execution_v3 import (
    audio_part, image_part, inputs_fixture, multimodal_model, source, state_fixture,
    text_part, training_fixture,
)


PARENT = {'network': '31' * 32, 'parent_id': '32' * 32, 'parent_state_root': '33' * 32,
          'block_height': 41, 'consensus_time_ms': 1500}


def admit(model, inputs, before, policy, *, request_id='44' * 32):
    # This is the independent fixture owner, before any downloaded proof exists.
    # Its expected record is assembled from its own bytes/state/admission values,
    # never by parsing a producer's contract or witness.
    program = relation.current_identity()
    raw = relation.freeze_contract(model, inputs, before, policy=policy, consumer='fixture/owner',
                                   allowed_use='research/classify', request_id=request_id,
                                   issued_at_ms=1000, deadline_ms=2000, parent_context=PARENT,
                                   target='ff' * 32)
    expected = {'contract_id': relation.contract_id(raw), 'program_sha256': program['program_sha256'],
                'parameters_sha256': program['parameters_sha256'], 'before_state': copy.deepcopy(before),
                'consumer': 'fixture/owner', 'allowed_use': 'research/classify', 'request_id': request_id,
                'candidate_artifact': execution.artifact(model),
                'inputs_sha256': hashlib.sha256(canonical(inputs)).hexdigest(), 'parent_context': copy.deepcopy(PARENT)}
    return raw, expected


def rehash_segments(witness, cid):
    """Adversary can recompute every hash; actual dataflow still must match."""
    prior = H(relation.RELATION_ID + '/segment-start', bytes.fromhex(cid)).hex()
    for index, segment in enumerate(witness['segments']):
        segment.update(contract_id=cid, ordinal=index, predecessor=prior)
        segment.pop('segment_id', None)
        prior = H(relation.RELATION_ID + '/segment', canonical(segment)).hex()
        segment['segment_id'] = prior
    return prior


class MultimodalRelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = multimodal_model()
        cls.inputs = inputs_fixture(text_part(), image_part(), audio_part())
        cls.before = state_fixture(cls.model)
        cls.policy = execution.default_policy(1)
        cls.raw, cls.expected = admit(cls.model, cls.inputs, cls.before, cls.policy)
        cls.proof = relation.prove_reference(cls.raw, cls.model, cls.inputs, cls.before, max_attempts=1)
        cls.witness = json.loads(cls.proof['witness'])
        cls.other_raw, cls.other_expected = admit(cls.model, cls.inputs, cls.before, cls.policy, request_id='45' * 32)
        cls.other_proof = relation.prove_reference(cls.other_raw, cls.model, cls.inputs, cls.before, max_attempts=1)

    def verify(self, *, raw=None, expected=None, before=None, output=None, after=None, witness=None):
        return relation.verify_historical_relation(
            self.raw if raw is None else raw, self.before if before is None else before,
            self.proof['output'] if output is None else output,
            self.proof['after_state'] if after is None else after,
            self.proof['witness'] if witness is None else canonical(witness),
            expected=self.expected if expected is None else expected)

    def test_every_forward_dense_has_real_complete_w1_and_qualification_flags_stay_false(self):
        report = self.verify()
        self.assertEqual(report['complete_w1_transcripts_verified'], 12)
        self.assertTrue(report['all_forward_dense_products_verified'])
        self.assertTrue(report['learned_encoder_replayed'])
        self.assertEqual(report['nonlinear_and_backward_verification'], 'full-scalar-replay')
        for name in ('source_origin_authenticated', 'backward_w1_proven', 'owner_authorization_verified',
                     'request_consumed', 'checkpoint_committed', 'final_use_granted',
                     'actual_production_model_use_verified', 'arbitrary_encoder_or_graph',
                     'ordinary_hepta_product', 'native_node_admission', 'tools_executed',
                     'external_delivery_verified', 'succinct_proof', 'work_security_qualified',
                     'model_quality_qualified', 'production_qualified', 'public_reward_eligible'):
            self.assertIs(report[name], False, name)
        self.assertEqual(self.proof['work_attempts'], [1] * 12)

    def test_pure_verifier_accepts_same_proof_again_without_consuming_operation(self):
        first = self.verify()
        second = self.verify()
        self.assertEqual(first, second)
        self.assertFalse(second['request_consumed'])

    def test_replay_and_w1_challenges_use_one_stable_owner_state_snapshot(self):
        before = copy.deepcopy(self.before)
        original = copy.deepcopy(before)
        changed = []

        def change_caller_state_at_replay(frame, event, argument):
            # Deterministic scheduling control, not replacement verifier code.
            # The owner still must recheck current state at its real commit.
            if event == 'call' and frame.f_code is execution.execute.__code__ and not changed:
                before['generation'] += 1
                before['memory'][0] += 1
                changed.append(True)

        previous = sys.getprofile()
        try:
            sys.setprofile(change_caller_state_at_replay)
            report = self.verify(before=before)
        finally:
            sys.setprofile(previous)
        self.assertEqual(changed, [True])
        self.assertNotEqual(before, original)
        self.assertEqual(report['before_state_sha256'], execution.digest(original))
        self.assertFalse(report['owner_authorization_verified'])

    def test_historical_time_never_reads_current_clock_and_live_time_rejects_expiry(self):
        with patch.object(relation.time, 'time_ns', side_effect=AssertionError('historical clock read')):
            report = self.verify()
        self.assertEqual(report['consensus_time_ms'], 1500)
        with self.assertRaisesRegex(ValueError, 'MM3_LIVE_START_WINDOW'):
            relation.verify_live_relation(self.raw, self.before, self.proof['output'], self.proof['after_state'],
                                          self.proof['witness'], expected=self.expected, clock_ms=lambda: 2001)

    def test_live_verification_checks_end_deadline_and_clock_rollback(self):
        for times in ((1500, 2001), (1500, 1499)):
            iterator = iter(times)
            with self.subTest(times=times), self.assertRaisesRegex(ValueError, 'MM3_LIVE_COMPLETION_WINDOW'):
                relation.verify_live_relation(self.raw, self.before, self.proof['output'], self.proof['after_state'],
                                              self.proof['witness'], expected=self.expected,
                                              clock_ms=lambda: next(iterator))

    def test_each_independent_expected_field_is_required_and_matched(self):
        changes = {'contract_id': '99' * 32, 'program_sha256': '99' * 32, 'parameters_sha256': '99' * 32,
                   'consumer': 'different/owner', 'allowed_use': 'different/use', 'request_id': '99' * 32,
                   'candidate_artifact': '99' * 32, 'inputs_sha256': '99' * 32}
        for name, replacement in changes.items():
            expected = copy.deepcopy(self.expected)
            expected[name] = replacement
            with self.subTest(field=name), self.assertRaisesRegex(ValueError, 'MM3_EXPECTED'):
                self.verify(expected=expected)
        expected = copy.deepcopy(self.expected)
        expected['before_state']['generation'] += 1
        with self.assertRaisesRegex(ValueError, 'MM3_EXPECTED_STATE'):
            self.verify(expected=expected)
        for field in PARENT:
            expected = copy.deepcopy(self.expected)
            expected['parent_context'][field] = '99' * 32 if type(PARENT[field]) is str else PARENT[field] + 1
            with self.subTest(parent=field), self.assertRaisesRegex(ValueError, 'MM3_EXPECTED_PARENT'):
                self.verify(expected=expected)
        expected = copy.deepcopy(self.expected)
        expected.pop('inputs_sha256')
        with self.assertRaisesRegex(ValueError, 'MM3_EXPECTED_FIELDS'):
            self.verify(expected=expected)

    def test_internally_valid_other_task_is_rejected_by_original_owner_context(self):
        with self.assertRaisesRegex(ValueError, 'MM3_EXPECTED_CONTRACT'):
            self.verify(raw=self.other_raw, output=self.other_proof['output'], after=self.other_proof['after_state'],
                        witness=json.loads(self.other_proof['witness']))

    def test_same_tensor_proof_from_other_task_cannot_be_spliced(self):
        witness = copy.deepcopy(self.witness)
        other = json.loads(self.other_proof['witness'])
        # Material is identical, but the actual W1 transcript has a different
        # admitted-task challenge.  Rewriting segment ids cannot repair it.
        self.assertEqual(witness['dense_proofs'][0]['proof_hex'][8:8 + 16 * work.CELLS],
                         other['dense_proofs'][0]['proof_hex'][8:8 + 16 * work.CELLS])
        witness['dense_proofs'][0] = other['dense_proofs'][0]
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            self.verify(witness=witness)

    def test_altered_raw_bytes_even_with_new_content_digest_cannot_keep_owner_contract(self):
        witness = copy.deepcopy(self.witness)
        part = witness['inputs'][0]['parts'][0]
        part.update(payload_hex=b'B'.hex(), source=source(b'B', 'text'))
        with self.assertRaisesRegex(ValueError, 'MM3_EXECUTED_CONTRACT_MISMATCH'):
            self.verify(witness=witness)

    def test_altered_modality_mask_or_pcm_rate_cannot_keep_owner_contract(self):
        for index, field, value in ((0, 'mask', [False]), (1, 'width', 2), (2, 'sample_rate_hz', 16000)):
            witness = copy.deepcopy(self.witness)
            witness['inputs'][0]['parts'][index][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(witness=witness)

    def test_unselected_adapter_and_unused_modality_weights_are_in_complete_bundle(self):
        for name in ('adapter_2_up', 'text_embedding'):
            witness = copy.deepcopy(self.witness)
            witness['model']['parameters'][name][0] = 1
            with self.subTest(parameter=name), self.assertRaisesRegex(ValueError, 'MM3_STATE_MODEL_MISMATCH'):
                self.verify(witness=witness)

    def test_hash_consistent_changed_intermediate_tensor_is_replayed_and_rejected(self):
        witness = copy.deepcopy(self.witness)
        segment = next(row for row in witness['segments'] if row['stage'] == 'selected-adapter-residual')
        segment['outputs']['head_input']['values'][0] += 1
        output = copy.deepcopy(self.proof['output'])
        output['segment_root'] = rehash_segments(witness, self.expected['contract_id'])
        with self.assertRaisesRegex(ValueError, 'MM3_SEGMENT_DATAFLOW_RELATION'):
            self.verify(witness=witness, output=output)

    def test_hash_consistent_dense_input_dtype_shape_or_values_splice_is_rejected(self):
        for field, replacement in (('dtype', 'u64'), ('shape', [8, 1]), ('values', [9] + [0] * 7)):
            witness = copy.deepcopy(self.witness)
            segment = next(row for row in witness['segments'] if row['stage'] == 'dense/head')
            segment['inputs']['input'][field] = replacement
            output = copy.deepcopy(self.proof['output'])
            output['segment_root'] = rehash_segments(witness, self.expected['contract_id'])
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'MM3_SEGMENT_DATAFLOW_RELATION'):
                self.verify(witness=witness, output=output)

    def test_every_w1_material_and_full_product_is_checked(self):
        witness = copy.deepcopy(self.witness)
        raw = bytearray.fromhex(witness['dense_proofs'][0]['proof_hex'])
        raw[4] ^= 1
        witness['dense_proofs'][0]['proof_hex'] = raw.hex()
        with self.assertRaisesRegex(ValueError, 'MM3_DENSE_MATERIAL'):
            self.verify(witness=witness)
        witness = copy.deepcopy(self.witness)
        raw = bytearray.fromhex(witness['dense_proofs'][0]['proof_hex'])
        raw[4 + 8 * work.CELLS] ^= 1
        witness['dense_proofs'][0]['proof_hex'] = raw.hex()
        with self.assertRaisesRegex(ValueError, 'PRODUCT'):
            self.verify(witness=witness)

    def test_fabricated_transcript_can_pass_cheap_precheck_but_never_relation(self):
        witness = copy.deepcopy(self.witness)
        entry = witness['dense_proofs'][0]
        raw = bytes.fromhex(entry['proof_hex'])[:-32] + bytes(32)
        result = execution.execute(self.model, self.inputs, self.before, self.policy)
        tile = relation._tile(result['operations'][0])
        challenge = relation._challenge(self.expected['contract_id'], self.before, 0, tile, entry['nonce'])
        work.precheck(challenge, tile['task'], b'\xff' * 32, raw)
        entry['proof_hex'] = raw.hex()
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            self.verify(witness=witness)

    def test_nonce_order_omission_duplicates_and_extra_proofs_are_rejected(self):
        witness = copy.deepcopy(self.witness)
        witness['dense_proofs'][0]['nonce'] += 1
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            self.verify(witness=witness)
        for proofs in (self.witness['dense_proofs'][:-1], self.witness['dense_proofs'] + [self.witness['dense_proofs'][0]]):
            witness = copy.deepcopy(self.witness)
            witness['dense_proofs'] = proofs
            with self.assertRaisesRegex(ValueError, 'MM3_DENSE_PROOF_COUNT'):
                self.verify(witness=witness)
        witness = copy.deepcopy(self.witness)
        witness['dense_proofs'][0], witness['dense_proofs'][1] = witness['dense_proofs'][1], witness['dense_proofs'][0]
        with self.assertRaisesRegex(ValueError, 'MM3_DENSE_PROOF_ORDER'):
            self.verify(witness=witness)
        witness = copy.deepcopy(self.witness)
        witness['dense_proofs'][1] = witness['dense_proofs'][0]
        with self.assertRaisesRegex(ValueError, 'MM3_DENSE_PROOF_ORDER'):
            self.verify(witness=witness)

    def test_scalar_decode_rejects_wrong_field_sign_range_and_padding(self):
        operation = {'id': 'hand', 'weight': {'dtype': 'i64', 'shape': [1, 1], 'values': [-2]},
                     'input': {'dtype': 'i64', 'shape': [1, 1], 'values': [3]},
                     'output': {'dtype': 'i64', 'shape': [1, 1], 'values': [-6]}}
        tile = relation._tile(operation)
        product = [0] * work.CELLS
        product[0] = work.Q - 6
        relation._check_product(operation, tile, product)
        product[1] = 1
        with self.assertRaisesRegex(ValueError, 'MM3_DENSE_PRODUCT_PADDING'):
            relation._check_product(operation, tile, product)
        product[1], product[0] = 0, work.Q - 7
        with self.assertRaisesRegex(ValueError, 'MM3_DENSE_PRODUCT_RANGE'):
            relation._check_product(operation, tile, product)
        product[0] = 6
        with self.assertRaisesRegex(ValueError, 'MM3_DENSE_PRODUCT_MISMATCH'):
            relation._check_product(operation, tile, product)
        product[0] = work.Q
        with self.assertRaisesRegex(ValueError, 'MM3_DENSE_PRODUCT_FIELD'):
            relation._check_product(operation, tile, product)

    def test_after_state_output_model_and_extra_scope_claims_are_not_accepted(self):
        after = copy.deepcopy(self.proof['after_state'])
        after['memory'][0] += 1
        with self.assertRaisesRegex(ValueError, 'MM3_AFTER_STATE_RELATION'):
            self.verify(after=after)
        witness = copy.deepcopy(self.witness)
        witness['after_model']['parameters']['head'][0] += 1
        with self.assertRaisesRegex(ValueError, 'MM3_AFTER_MODEL_RELATION'):
            self.verify(witness=witness)
        output = copy.deepcopy(self.proof['output'])
        output['external_delivery_verified'] = True
        with self.assertRaisesRegex(ValueError, 'MM3_OUTPUT_RELATION'):
            self.verify(output=output)

    def test_missing_expected_and_wrong_namespace_are_rejected(self):
        with self.assertRaises(TypeError):
            relation.verify_historical_relation(self.raw, self.before, self.proof['output'],
                                                self.proof['after_state'], self.proof['witness'])
        raw = json.loads(self.raw)
        raw['schema'] = 'pon-useful-cell-stateful-int257-v2'
        raw = canonical(raw)
        expected = copy.deepcopy(self.expected)
        expected['contract_id'] = relation.contract_id(raw)
        with self.assertRaisesRegex(ValueError, 'MM3_RELATION_VERSION'):
            self.verify(raw=raw, expected=expected)

    def test_canonical_parser_rejects_duplicate_float_noncanonical_and_oversize_inputs(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{ "x":1}', b'{"x":true}\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                relation.strict_json(raw, 100, 'TEST')
        with self.assertRaisesRegex(ValueError, 'TEST_LIMIT'):
            relation.strict_json(b'{}', 1, 'TEST')


class MultimodalTrainingRelationTests(unittest.TestCase):
    def test_real_training_proof_and_successor_model_use_on_independent_next_bytes(self):
        model = multimodal_model()
        inputs = inputs_fixture(text_part())
        before = state_fixture(model)
        policy = execution.default_policy(1)
        policy['training'] = training_fixture('text_embedding', denominator=64)
        raw, expected = admit(model, inputs, before, policy, request_id='51' * 32)
        first = relation.prove_reference(raw, model, inputs, before, max_attempts=1)
        report = relation.verify_historical_relation(raw, before, first['output'], first['after_state'],
                                                     first['witness'], expected=expected)
        self.assertTrue(report['training_step_verified'])
        self.assertNotEqual(first['after_model'], model)
        next_inputs = inputs_fixture(text_part(b'AA'), identity=2)
        next_policy = execution.default_policy(1)
        next_raw, next_expected = admit(first['after_model'], next_inputs, first['after_state'], next_policy,
                                        request_id='52' * 32)
        second = relation.prove_reference(next_raw, first['after_model'], next_inputs,
                                          first['after_state'], max_attempts=1)
        next_report = relation.verify_historical_relation(next_raw, first['after_state'], second['output'],
                                                          second['after_state'], second['witness'], expected=next_expected)
        self.assertEqual(next_report['before_model_artifact'], report['after_model_artifact'])
        self.assertEqual(second['after_state']['sequence'], 2)
        self.assertFalse(next_report['checkpoint_committed'])
        self.assertFalse(next_report['actual_production_model_use_verified'])
        witness = json.loads(first['witness'])
        segment = next(row for row in witness['segments'] if row['stage'] == 'training-backward')
        segment['outputs']['gradients']['text_embedding'][65 * 8] += 1
        output = copy.deepcopy(first['output'])
        output['segment_root'] = rehash_segments(witness, expected['contract_id'])
        with self.assertRaisesRegex(ValueError, 'MM3_SEGMENT_DATAFLOW_RELATION'):
            relation.verify_historical_relation(raw, before, output, first['after_state'], canonical(witness),
                                                 expected=expected)


class MultimodalLoadedSourceTests(unittest.TestCase):
    def test_foreign_execute_rebinding_cannot_keep_source_identity(self):
        with patch.object(execution, 'execute', lambda *args, **kwargs: {'relation_valid': True}):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()

    def test_foreign_preprocessor_rebinding_cannot_keep_source_identity(self):
        with patch.object(execution, 'prepare_inputs', lambda *args: []):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()

    def test_code_constants_and_parameter_shapes_are_source_checked(self):
        with patch.object(execution, 'QUANT_DIVISOR', 4):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_CONSTANT_MISMATCH'):
                relation.current_identity()
        shapes = copy.deepcopy(execution.PARAMETER_SHAPES)
        shapes['head'] = [8, 3]
        with patch.object(execution, 'PARAMETER_SHAPES', shapes):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_CONSTANT_MISMATCH'):
                relation.current_identity()

    def test_changed_prover_defaults_and_imported_work_implementation_are_rejected(self):
        defaults = relation.prove_reference.__kwdefaults__
        try:
            relation.prove_reference.__kwdefaults__ = {'max_attempts': 1}
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_DEFAULT_MISMATCH'):
                relation.current_identity()
        finally:
            relation.prove_reference.__kwdefaults__ = defaults
        with patch.object(work, 'verify', lambda *args: (bytes(32), [0] * work.CELLS)):
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_BINDING_MISMATCH'):
                relation.current_identity()


if __name__ == '__main__':
    unittest.main()
