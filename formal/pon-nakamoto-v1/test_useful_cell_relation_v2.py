"""Actual source/W1/state/training replay controls; no successful verifier mock."""
from __future__ import annotations

import copy
import json
import struct
import unittest

from contract_wire import canonical
from evaluation_bundle import artifact_id
from experiments import shared_cell_operator_v1 as cell
import useful_cell_execution_v2 as execution
import useful_cell_relation_v1 as v1
import useful_cell_relation_v2 as relation
import work_oracle as work


class StatefulCellRelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, cls.rows, _ = cell.load_inputs(
            cell.DEFAULT_MATERIAL / 'model.json', cell.DEFAULT_MATERIAL / 'consumer.json',
            cell.DEFAULT_MATERIAL / 'evaluation-bundle.json', cell.DEFAULT_BUNDLE,
            'consumer', 0, 2)
        cls.before = execution.initial_state(
            cls.model, cell_id='11' * 32, generation=7, scope='source-router/test-owner',
            rng_seed='22' * 32, remaining_steps=2)
        cls.before['memory'] = [17, -31, 9]
        cls.policy = execution.default_policy(len(cls.rows))
        cls.policy['feature_mask'][0] = False
        cls.policy['expert_mask'] = [[False, True, True], [True, False, True]]
        cls.policy['sampler'] = 'sha256-positive-shift-v1'
        mask = {'base': [[False] * 257 for _ in range(3)],
                'deltas': [[[False] * 257 for _ in range(3)] for _ in range(3)]}
        mask['base'][0][-1] = True
        cls.policy['training'] = {
            'learning_rate_num': 1, 'learning_rate_den': 1,
            'momentum_num': 0, 'momentum_den': 1,
            'clip_abs': 1, 'trainable_mask': mask}
        cls.options = {
            'policy': cls.policy, 'consumer': 'independent-consumer',
            'allowed_use': 'research-stateful-computation', 'request_id': '33' * 32,
            'issued_at_ms': 1000, 'deadline_ms': 2000,
            'parent_context': {'network': '44' * 32, 'parent_id': '55' * 32,
                               'parent_state_root': '66' * 32, 'block_height': 12,
                               'consensus_time_ms': 1500}, 'target': 'ff' * 32}
        # These task, source and state inputs belong to the consumer fixture.
        # No producer proposal or returned verification report supplies expected.
        identity = relation.current_identity()
        cls.raw = relation.freeze_contract(cls.model, cls.rows, cls.before, **cls.options)
        cls.expected = {
            'contract_id': relation.contract_id(cls.raw),
            'program_sha256': identity['program_sha256'],
            'parameters_sha256': identity['parameters_sha256'],
            'before_state': copy.deepcopy(cls.before),
            'consumer': cls.options['consumer'], 'allowed_use': cls.options['allowed_use'],
            'candidate_artifact': artifact_id(cls.model),
            'parent_context': copy.deepcopy(cls.options['parent_context'])}
        cls.proved = relation.prove_reference(cls.raw, cls.model, cls.rows, cls.before,
                                             max_attempts=1)

    def verify(self, *, raw=None, before=None, output=None, after=None,
               witness=None, expected=None):
        return relation.verify_historical_relation(
            self.raw if raw is None else raw, self.before if before is None else before,
            self.proved['output'] if output is None else output,
            self.proved['after_state'] if after is None else after,
            self.proved['witness'] if witness is None else witness,
            expected=self.expected if expected is None else expected)

    def test_complete_masked_stateful_training_relation(self):
        report = self.verify()
        self.assertTrue(report['relation_valid'])
        self.assertEqual(report['complete_w1_transcripts_verified'], 5)
        self.assertTrue(report['training_step_verified'])
        self.assertEqual(report['time_semantics'], 'historical-parent-protocol-time')
        self.assertEqual(report['consensus_time_ms'], 1500)
        self.assertEqual(self.proved['work_attempts'], [1] * 5)
        self.assertEqual(self.proved['after_state']['rng_counter'], 2)
        self.assertEqual(self.proved['after_state']['sequence'], 1)
        self.assertEqual(self.proved['after_state']['remaining_steps'], 0)
        self.assertNotEqual(self.proved['after_state']['memory'], self.before['memory'])
        self.assertEqual(self.proved['after_state']['optimizer']['step'], 1)
        self.assertNotEqual(self.proved['after_model'], self.model)
        self.assertEqual(self.proved['after_model']['router'], self.model['router'])
        self.assertEqual(self.proved['after_model']['deltas'], self.model['deltas'])
        for field in ('owner_authorization_verified', 'request_consumed', 'checkpoint_committed',
                      'final_use_granted', 'actual_model_use_verified', 'native_node_admission',
                      'ordinary_hepta_encoder_verified', 'tools_executed',
                      'external_delivery_verified', 'production_qualified',
                      'public_reward_eligible', 'work_security_qualified', 'model_quality_qualified'):
            self.assertIs(report[field], False, field)

    def test_every_state_component_is_recomputed(self):
        for name in ('generation', 'sequence', 'remaining_steps', 'rng_counter'):
            with self.subTest(name=name):
                after = copy.deepcopy(self.proved['after_state'])
                after[name] += 1
                with self.assertRaisesRegex(ValueError, 'AFTER_STATE_RELATION'):
                    self.verify(after=after)
        after = copy.deepcopy(self.proved['after_state'])
        after['memory'][0] += 1
        with self.assertRaisesRegex(ValueError, 'AFTER_STATE_RELATION'):
            self.verify(after=after)
        after = copy.deepcopy(self.proved['after_state'])
        after['optimizer']['base'][0][-1] += 1
        with self.assertRaisesRegex(ValueError, 'AFTER_STATE_RELATION'):
            self.verify(after=after)

    def test_updated_model_cannot_change_a_frozen_parameter(self):
        witness = json.loads(self.proved['witness'])
        witness['after_model']['router'][0][0] += 1
        with self.assertRaisesRegex(ValueError, 'AFTER_MODEL_RELATION'):
            self.verify(witness=canonical(witness))

    def test_forward_backward_loss_and_clipping_trace_are_replayed(self):
        original = json.loads(self.proved['witness'])
        for name, mutate in (
                ('training-loss', lambda s: s['outputs'].__setitem__('loss', s['outputs']['loss'] + 1)),
                ('training-backward', lambda s: s['outputs']['gradients']['base'][0].__setitem__(0, 1)),
                ('training-update', lambda s: s['outputs']['clipped_gradients']['base'][0].__setitem__(0, 1))):
            with self.subTest(name=name):
                witness = copy.deepcopy(original)
                stage = next(s for s in witness['segments'] if s['stage'] == name)
                mutate(stage)
                with self.assertRaisesRegex(ValueError, 'SEGMENT_DATAFLOW_RELATION'):
                    self.verify(witness=canonical(witness))

    def test_issued_deadline_and_parent_are_independently_bound(self):
        for field in ('parent_id', 'parent_state_root', 'network', 'block_height', 'consensus_time_ms'):
            with self.subTest(field=field):
                expected = copy.deepcopy(self.expected)
                value = expected['parent_context'][field]
                expected['parent_context'][field] = value + 1 if type(value) is int else 'ab' * 32
                with self.assertRaisesRegex(ValueError, 'EXPECTED_PARENT_CONTEXT'):
                    self.verify(expected=expected)

    def test_live_completion_and_clock_regression(self):
        args = (self.raw, self.before, self.proved['output'], self.proved['after_state'],
                self.proved['witness'])
        report = relation.verify_live_relation(*args, expected=self.expected, clock_ms=lambda: 1500)
        self.assertEqual(report['time_semantics'], 'live-consumer-clock')
        for observations, error in (((999,), 'LIVE_START_WINDOW'),
                                    ((2001,), 'LIVE_START_WINDOW'),
                                    ((1999, 2001), 'LIVE_COMPLETION_WINDOW'),
                                    ((1500, 1499), 'LIVE_COMPLETION_WINDOW')):
            with self.subTest(observations=observations):
                clock = iter(observations)
                with self.assertRaisesRegex(ValueError, error):
                    relation.verify_live_relation(*args, expected=self.expected,
                                                  clock_ms=lambda: next(clock))

    def test_valid_v1_challenge_transcript_is_not_a_v2_proof(self):
        witness = json.loads(self.proved['witness'])
        tile, _ = cell.build_tiles(self.model, execution.prepare_rows(self.rows, self.policy))
        tile = tile[0]
        words = list(struct.unpack('<' + 'I' * (2 * work.CELLS), tile['material']))
        # A genuine accepted old-domain transcript, not malformed random bytes.
        challenge = v1.H(v1.CHALLENGE_DOMAIN, b'old-context')
        proof = work.prove(challenge, words[:work.CELLS], words[work.CELLS:])
        work.verify(challenge, bytes.fromhex(tile['task']), bytes.fromhex('ff' * 32), proof)
        witness['tiles'][0]['proof_hex'] = proof.hex()
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            self.verify(witness=canonical(witness))

    def test_preprocessing_cannot_be_self_certified_by_rehashing_features(self):
        witness = json.loads(self.proved['witness'])
        witness['rows'][0]['x'][1] = 7 if witness['rows'][0]['x'][1] != 7 else 6
        with self.assertRaisesRegex(ValueError, 'SOURCE_FEATURE_BINDING'):
            relation.freeze_contract(self.model, witness['rows'], self.before, **self.options)

    def test_witness_and_output_closed_schemas(self):
        for field in ('trusted', 'native_verified', 'final_use'):
            witness = json.loads(self.proved['witness'])
            witness[field] = True
            with self.assertRaisesRegex(ValueError, 'V2_WITNESS_FIELDS'):
                self.verify(witness=canonical(witness))
        output = copy.deepcopy(self.proved['output'])
        output['tools_executed'] = True
        with self.assertRaisesRegex(ValueError, 'OUTPUT_RELATION'):
            self.verify(output=output)

    def test_malformed_deep_and_cyclic_objects_fail_closed(self):
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaisesRegex(ValueError, 'V2_OUTPUT'):
            self.verify(output=cyclic)
        witness = json.loads(self.proved['witness'])
        witness['model'] = None
        with self.assertRaisesRegex(ValueError, 'MODEL_OBJECT'):
            self.verify(witness=canonical(witness))

    def test_new_execution_loaded_code_is_guarded(self):
        original = execution.execute.__code__

        def substituted(model, rows, before, policy, *, verified_products=None):
            return {}

        try:
            execution.execute.__code__ = substituted.__code__
            with self.assertRaisesRegex(ValueError, 'V2_LOADED_CODE_MISMATCH'):
                self.verify()
        finally:
            execution.execute.__code__ = original
        self.assertEqual(relation.current_identity()['program_sha256'],
                         self.expected['program_sha256'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
