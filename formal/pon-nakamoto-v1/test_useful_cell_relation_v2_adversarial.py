"""Independent task-splicing and historical/live boundary counterexamples.

Every donor has real source replay and five accepted W1 certificates.  Forged
stage chains are rehashed by the attacker below, without using the verifier's
segment builder.  These checks exercise computation binding; they do not stand
in for the real owner's authorization, FinalUse or persistent operation journal.
"""
from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from contract_wire import H, canonical
from experiments import shared_cell_operator_v1 as cell
import useful_cell_execution_v2 as execution
import useful_cell_relation_v2 as relation
import work_oracle as work


class StatefulCellSpliceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, cls.rows, _ = cell.load_inputs(
            cell.DEFAULT_MATERIAL / 'model.json',
            cell.DEFAULT_MATERIAL / 'consumer.json',
            cell.DEFAULT_MATERIAL / 'evaluation-bundle.json',
            cell.DEFAULT_BUNDLE, 'consumer', 0, 2)
        cls.before = execution.initial_state(
            cls.model, cell_id='a1' * 32, generation=19,
            scope='independent-owner/source-routing', rng_seed='b2' * 32,
            remaining_steps=len(cls.rows))
        cls.before['memory'] = [11, -7, 3]
        cls.policy = execution.default_policy(len(cls.rows))
        cls.policy['sampler'] = 'sha256-positive-shift-v1'
        cls.policy['tool_names'] = ['review-public-source'] * 3
        cls.options = {
            'consumer': 'owner-a', 'allowed_use': 'research-routing-proposal',
            'request_id': 'c3' * 32, 'issued_at_ms': 1000, 'deadline_ms': 2000,
            'parent_context': {'network': 'd4' * 32, 'parent_id': 'e5' * 32,
                               'parent_state_root': 'f6' * 32, 'block_height': 31,
                               'consensus_time_ms': 1500},
            'target': 'ff' * 32}
        # The admitting owner supplies each task/state and pins local code before
        # any producer result exists.  Nothing is copied out of a submitted
        # contract's claimed authority or a verifier's report.
        identity = relation.current_identity()
        cls.primary = cls.admit(cls.policy, cls.options, identity)
        foreign_options = dict(cls.options, consumer='owner-b', request_id='17' * 32)
        cls.foreign = cls.admit(cls.policy, foreign_options, identity)
        masked_policy = copy.deepcopy(cls.policy)
        masked_policy['feature_mask'] = [False] * 256 + [True]
        cls.masked = cls.admit(masked_policy, dict(cls.options, request_id='28' * 32), identity)

    @classmethod
    def admit(cls, policy, options, identity):
        raw = relation.freeze_contract(cls.model, cls.rows, cls.before,
                                       policy=policy, **options)
        expected = {
            'contract_id': relation.contract_id(raw),
            'program_sha256': identity['program_sha256'],
            'parameters_sha256': identity['parameters_sha256'],
            'before_state': copy.deepcopy(cls.before),
            'consumer': options['consumer'], 'allowed_use': options['allowed_use'],
            'candidate_artifact': H('artifact', canonical(cls.model)).hex(),
            'parent_context': copy.deepcopy(options['parent_context'])}
        proved = relation.prove_reference(raw, cls.model, cls.rows, cls.before,
                                          max_attempts=1)
        return {'raw': raw, 'expected': expected, 'proved': proved}

    def verify(self, package=None, *, witness=None, output=None, expected=None):
        package = self.primary if package is None else package
        proved = package['proved']
        return relation.verify_historical_relation(
            package['raw'], self.before,
            proved['output'] if output is None else output,
            proved['after_state'], proved['witness'] if witness is None else witness,
            expected=package['expected'] if expected is None else expected)

    @staticmethod
    def segment(package, name):
        return next(item for item in json.loads(package['proved']['witness'])['segments']
                    if item['stage'] == name)

    def rehash_forgery(self, witness):
        """Give the attacker every public hash, ordinal and predecessor repair."""
        cid = self.primary['expected']['contract_id']
        prior = H('useful-cell-stateful-int257-v2/segment-start', bytes.fromhex(cid)).hex()
        linked = []
        for ordinal, entry in enumerate(witness['segments']):
            item = {key: copy.deepcopy(value) for key, value in entry.items()
                    if key != 'segment_id'}
            item.update(contract_id=cid, ordinal=ordinal, predecessor=prior)
            prior = H('useful-cell-stateful-int257-v2/segment', canonical(item)).hex()
            linked.append(dict(item, segment_id=prior))
        witness['segments'] = linked
        output = copy.deepcopy(self.primary['proved']['output'])
        output['segment_root'] = prior
        return canonical(witness), output

    def assert_rehashed_forgery_refused(self, witness):
        encoded, output = self.rehash_forgery(witness)
        with self.assertRaisesRegex(ValueError, 'SEGMENT_DATAFLOW_RELATION'):
            self.verify(witness=encoded, output=output)

    def test_donor_proofs_are_valid_with_equal_and_different_actual_tensors(self):
        for package in (self.primary, self.foreign, self.masked):
            with self.subTest(contract=package['expected']['contract_id']):
                report = self.verify(package)
                self.assertTrue(report['relation_valid'])
                self.assertEqual(report['complete_w1_transcripts_verified'], 5)
                self.assertEqual(package['proved']['work_attempts'], [1] * 5)
        self.assertNotEqual(self.primary['raw'], self.foreign['raw'])
        self.assertEqual(self.segment(self.primary, 'five-w1-products')['outputs'],
                         self.segment(self.foreign, 'five-w1-products')['outputs'])
        self.assertEqual(self.primary['proved']['output']['execution'],
                         self.foreign['proved']['output']['execution'])
        self.assertNotEqual(self.segment(self.primary, 'five-w1-products')['outputs'],
                            self.segment(self.masked, 'five-w1-products')['outputs'])

    def test_same_tensor_segment_from_another_valid_task_is_refused(self):
        for stage in ('source-replay', 'feature-mask', 'five-w1-products',
                      'decision/0', 'checkpoint'):
            with self.subTest(stage=stage):
                current = self.segment(self.primary, stage)
                foreign = self.segment(self.foreign, stage)
                self.assertEqual(current['inputs'], foreign['inputs'])
                self.assertEqual(current['outputs'], foreign['outputs'])
                self.assertNotEqual(current['segment_id'], foreign['segment_id'])
                witness = json.loads(self.primary['proved']['witness'])
                index = next(i for i, entry in enumerate(witness['segments'])
                             if entry['stage'] == stage)
                witness['segments'][index] = foreign
                with self.assertRaisesRegex(ValueError, 'SEGMENT_DATAFLOW_RELATION'):
                    self.verify(witness=canonical(witness))

    def test_real_foreign_tensor_values_fail_even_after_all_chain_hashes_are_repaired(self):
        for stage in ('feature-mask', 'five-w1-products', 'operator-products', 'decision/0'):
            with self.subTest(stage=stage):
                donor = self.segment(self.masked, stage)
                witness = json.loads(self.primary['proved']['witness'])
                recipient = next(item for item in witness['segments'] if item['stage'] == stage)
                self.assertNotEqual(recipient['outputs'], donor['outputs'])
                recipient['outputs'] = copy.deepcopy(donor['outputs'])
                self.assert_rehashed_forgery_refused(witness)

    def test_shape_and_dtype_are_executed_despite_self_consistent_segment_hashes(self):
        for field, value in (('shape', [len(self.rows), 15]), ('dtype', 'float32')):
            with self.subTest(field=field):
                witness = json.loads(self.primary['proved']['witness'])
                stage = next(item for item in witness['segments'] if item['stage'] == 'five-w1-products')
                self.assertNotEqual(stage['outputs'][field], value)
                stage['outputs'][field] = value
                self.assert_rehashed_forgery_refused(witness)

    def test_reordering_omission_and_duplication_fail_after_renumbering_and_rehashing(self):
        for mutation in ('swap', 'omit', 'duplicate'):
            with self.subTest(mutation=mutation):
                witness = json.loads(self.primary['proved']['witness'])
                stages = witness['segments']
                if mutation == 'swap':
                    stages[0], stages[1] = stages[1], stages[0]
                elif mutation == 'omit':
                    del stages[1]
                else:
                    stages.insert(1, copy.deepcopy(stages[1]))
                self.assert_rehashed_forgery_refused(witness)

    def test_foreign_checkpoint_is_not_adopted_by_rehashing_its_task_identity(self):
        witness = json.loads(self.primary['proved']['witness'])
        donor = self.segment(self.masked, 'checkpoint')
        self.assertNotEqual(witness['segments'][-1]['inputs'], donor['inputs'])
        witness['segments'][-1] = donor
        self.assert_rehashed_forgery_refused(witness)

    def test_valid_w1_from_another_task_fails_even_when_both_matrices_are_identical(self):
        witness = json.loads(self.primary['proved']['witness'])
        foreign = json.loads(self.foreign['proved']['witness'])
        original_bytes = bytes.fromhex(witness['tiles'][0]['proof_hex'])
        foreign_bytes = bytes.fromhex(foreign['tiles'][0]['proof_hex'])
        material_end = 4 + 2 * work.CELLS * 4
        self.assertEqual(original_bytes[4:material_end], foreign_bytes[4:material_end])
        self.assertNotEqual(original_bytes[-32:], foreign_bytes[-32:])
        witness['tiles'][0] = foreign['tiles'][0]
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            self.verify(witness=canonical(witness))

    def test_a_fully_self_consistent_producer_task_cannot_replace_owner_admission(self):
        self.assertTrue(self.verify(self.foreign)['relation_valid'])
        with self.assertRaisesRegex(ValueError, 'EXPECTED_CONTRACT'):
            self.verify(self.foreign, expected=self.primary['expected'])
        # Even accepting a new contract hash cannot silently change the consumer
        # retained in the owner's independent task record.
        rebound = copy.deepcopy(self.primary['expected'])
        rebound['contract_id'] = self.foreign['expected']['contract_id']
        with self.assertRaisesRegex(ValueError, 'EXPECTED_CONSUMER'):
            self.verify(self.foreign, expected=rebound)

    def test_historical_result_ignores_wall_clock_and_survives_current_expiry(self):
        baseline = self.verify()
        proved = self.primary['proved']
        with self.assertRaisesRegex(ValueError, 'LIVE_START_WINDOW'):
            relation.verify_live_relation(
                self.primary['raw'], self.before, proved['output'], proved['after_state'],
                proved['witness'], expected=self.primary['expected'], clock_ms=lambda: 2001)
        # A successful source/work verifier is never patched.  This trap proves
        # that historical verification cannot consult the host's current time.
        with patch.object(relation.time, 'time_ns', side_effect=AssertionError('wall-clock read')):
            after_expiry = self.verify()
        self.assertEqual(after_expiry, baseline)
        self.assertEqual(after_expiry['consensus_time_ms'], 1500)
        self.assertFalse(after_expiry['owner_authorization_verified'])

    def test_today_revocation_or_clock_cannot_enter_the_historical_api(self):
        proved = self.primary['proved']
        args = (self.primary['raw'], self.before, proved['output'], proved['after_state'],
                proved['witness'])
        for name, value in (('clock_ms', lambda: 2001), ('current_revocations', ['revoked']),
                            ('current_generation', 20)):
            with self.subTest(keyword=name), self.assertRaises(TypeError):
                relation.verify_historical_relation(*args, expected=self.primary['expected'],
                                                     **{name: value})
        expected = dict(self.primary['expected'], current_revocations=['revoked'])
        with self.assertRaisesRegex(ValueError, 'V2_EXPECTED_FIELDS'):
            self.verify(expected=expected)

    def test_repeated_live_verification_neither_consumes_nor_commits_nor_grants_authority(self):
        proved = self.primary['proved']
        before = copy.deepcopy(self.before)
        output = copy.deepcopy(proved['output'])
        after = copy.deepcopy(proved['after_state'])
        expected = copy.deepcopy(self.primary['expected'])
        snapshot = copy.deepcopy((before, output, after, expected))
        reports = [relation.verify_live_relation(
            self.primary['raw'], before, output, after, proved['witness'],
            expected=expected, clock_ms=lambda: 1500) for _ in range(2)]
        self.assertEqual(reports[0], reports[1])
        self.assertEqual((before, output, after, expected), snapshot)
        self.assertEqual(output['execution']['actions'], ['propose_tool'] * len(self.rows))
        self.assertEqual(after['sequence'], before['sequence'] + 1)
        self.assertEqual(after['rng_counter'], before['rng_counter'] + len(self.rows))
        for field in ('owner_authorization_verified', 'request_consumed', 'checkpoint_committed',
                      'final_use_granted', 'actual_model_use_verified', 'tools_executed',
                      'external_delivery_verified', 'ordinary_hepta_encoder_verified',
                      'native_node_admission', 'production_qualified', 'public_reward_eligible'):
            self.assertIs(reports[0][field], False, field)


if __name__ == '__main__':
    unittest.main(verbosity=2)
