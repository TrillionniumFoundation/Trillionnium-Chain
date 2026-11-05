"""Adversarial controls for the complete, research-only integer Cell relation.

The positive fixture replays frozen public source and constructs actual W1
certificates with the independent reference implementation. These tests do not
qualify native execution, proof-system soundness, work hardness, model benefit,
or production admission. No successful source or verifier is mocked.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from contract_wire import H, canonical
from experiments import shared_cell_operator_v1 as cell
from model_contract import infer
import useful_cell_relation_v1 as relation
from useful_cell_attempt_journal_v1 import (AttemptJournal, bind_delivered_witness,
                                          inspect_acknowledged_journal, inspect_journal)
import work_oracle as work


class UsefulCellRelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model, cls.rows, _ = cell.load_inputs(
            cell.DEFAULT_MATERIAL / 'model.json',
            cell.DEFAULT_MATERIAL / 'consumer.json',
            cell.DEFAULT_MATERIAL / 'evaluation-bundle.json',
            cell.DEFAULT_BUNDLE, 'consumer', 0, 2)
        cls.artifact = H('artifact', canonical(cls.model)).hex()
        cls.before = {'cell_id': '11' * 32, 'generation': 7,
                      'state_root': '22' * 32,
                      'model_artifact': cls.artifact}
        cls.options = {'consumer': '33' * 32,
                       'allowed_use': 'research-inference-only',
                       'candidate_artifact': cls.artifact,
                       'deadline_ms': 2000, 'request_id': '44' * 32,
                       'target': 'ff' * 32}
        # The verifier's expected policy comes from its own state and source,
        # not from a producer's witness or a returned verification report.
        identity = relation.current_identity()
        cls.raw = relation.freeze_contract(
            cls.model, cls.rows, cls.before, **cls.options)
        cls.contract = json.loads(cls.raw)
        cls.expected = {
            'contract_id': relation.contract_id(cls.raw),
            'program_sha256': identity['program_sha256'],
            'parameters_sha256': identity['parameters_sha256'],
            'before_state': copy.deepcopy(cls.before),
            'consumer': cls.options['consumer'],
            'allowed_use': cls.options['allowed_use'],
            'candidate_artifact': cls.artifact,
        }
        cls.proved = relation.prove_reference(
            cls.raw, cls.model, cls.rows, cls.before, max_attempts=1)

    def verify(self, *, raw=None, before=None, output=None, after=None,
               witness=None, expected=None, clock=None):
        return relation.verify_relation(
            self.raw if raw is None else raw,
            self.before if before is None else before,
            self.proved['output'] if output is None else output,
            self.proved['after_state'] if after is None else after,
            self.proved['witness'] if witness is None else witness,
            expected=self.expected if expected is None else expected,
            clock_ms=(lambda: 1000) if clock is None else clock)

    def rehashed_expected(self, raw):
        value = copy.deepcopy(self.expected)
        value['contract_id'] = relation.contract_id(raw)
        return value

    def assert_contract_refused(self, value, *, rehash=True):
        raw = canonical(value)
        with self.assertRaises(ValueError):
            expected = self.rehashed_expected(raw) if rehash else self.expected
            self.verify(raw=raw, expected=expected)

    @staticmethod
    def different(value):
        """Change one fixed semantic value without using its implementation."""
        if type(value) is bool:
            return not value
        if type(value) is int:
            return value + 1
        if type(value) is str:
            return value + '-unsupported'
        if type(value) is list:
            return value + ['unsupported']
        if type(value) is dict:
            return dict(value, unsupported=True)
        return 'unsupported'

    def test_complete_public_source_relation_matches_separate_scalar_inference(self):
        report = self.verify()
        self.assertIsInstance(report, dict)
        self.assertTrue(report['relation_valid'])
        self.assertTrue(report['upstream_verified'])
        self.assertTrue(report['integer_decision_verified'])
        self.assertTrue(report['read_only_state_verified'])
        self.assertTrue(report['external_context_matched'])
        self.assertEqual(report['complete_w1_transcripts_verified'], 5)
        for field in ('ordinary_hepta_encoder_verified',
                      'owner_authorization_verified', 'calibration_qualified',
                      'ood_qualified', 'old_task_retention_qualified',
                      'succinct_proof', 'work_security_qualified',
                      'production_qualified', 'public_reward_eligible'):
            self.assertIs(report[field], False, field)
        self.assertIsNone(report['model_behavior_preserved'])
        self.assertIsNone(report['bf16_equivalence'])
        self.assertEqual(relation.RELATION_ID, 'pon-useful-cell-int257-v1')
        self.assertEqual(self.raw, canonical(self.contract))
        self.assertEqual(set(self.contract), {'schema', 'model', 'state',
                         'inputs', 'numeric', 'decision', 'output',
                         'proof', 'scope'})
        self.assertEqual(self.proved['after_state'], self.before)
        self.assertEqual(self.proved['output']['predictions'],
                         infer(self.model, [row['x'] for row in self.rows]))

    def test_valid_witness_does_not_mutate_caller_owned_state(self):
        before = copy.deepcopy(self.before)
        after = copy.deepcopy(self.proved['after_state'])
        output = copy.deepcopy(self.proved['output'])
        expected = copy.deepcopy(self.expected)
        snapshot = copy.deepcopy((before, after, output, expected))
        self.verify(before=before, after=after, output=output, expected=expected)
        self.assertEqual((before, after, output, expected), snapshot)

    def test_durable_attempt_journal_replays_every_tile_and_preserves_relation_bytes(self):
        tiles, _ = cell.build_tiles(self.model, self.rows)
        expected_plan = relation.reference_search_plan(self.raw, self.before, tiles, len(self.rows), 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'search.jsonl'
            with AttemptJournal(path) as journal:
                result = relation.prove_reference(self.raw, self.model, self.rows, self.before,
                                                  max_attempts=1, attempt_sink=journal.append)
                retained_endpoint = journal.head
            observed = inspect_journal(path.read_bytes(), expected_plan=expected_plan,
                                       materials={tile['index']: tile['material'] for tile in tiles},
                                       expected_final_sha256=retained_endpoint)
        self.assertEqual(result, self.proved)
        self.assertEqual(observed['mathematical_attempts_replayed'], 5)
        self.assertEqual(observed['counts']['started_attempts'], 5)
        self.assertEqual(observed['counts']['hits'], 5)
        self.assertEqual(observed['counts']['misses'], 0)
        self.assertTrue(self.verify(witness=result['witness'])['relation_valid'])

    def test_sink_failure_aborts_before_an_attempt_and_does_not_emit_success(self):
        events = []

        def reject_start(event):
            if event['kind'] == 'attempt-start':
                raise OSError('evidence device unavailable')
            events.append(event)

        with self.assertRaisesRegex(OSError, 'evidence device unavailable'):
            relation.prove_reference(self.raw, self.model, self.rows, self.before,
                                     max_attempts=1, attempt_sink=reject_start)
        self.assertEqual([event['kind'] for event in events], ['plan'])

    def test_sink_receives_copies_and_cannot_modify_the_search_or_output(self):
        def mutate(event):
            if event['kind'] == 'plan':
                event['tiles'].clear()
            event.clear()

        result = relation.prove_reference(self.raw, self.model, self.rows, self.before,
                                          max_attempts=1, attempt_sink=mutate)
        self.assertEqual(result, self.proved)

    def test_another_genuine_valid_nonce_cannot_replace_the_measured_first_hit(self):
        from experiments import useful_cell_relation_v1 as driver

        tiles, _ = cell.build_tiles(self.model, self.rows)
        events = []
        proved = relation.prove_reference(self.raw, self.model, self.rows, self.before,
                                          max_attempts=1, attempt_sink=events.append)
        witness = json.loads(proved['witness'])
        tile = tiles[0]
        words = list(struct.unpack('<' + 'I' * (2 * work.CELLS), tile['material']))
        challenge = relation._challenge(self.raw, self.before, tile, 1)
        alternate = work.prove(challenge, words[:work.CELLS], words[work.CELLS:])
        witness['tiles'][0] = {'index': 0, 'nonce': 1, 'proof_hex': alternate.hex()}
        different_witness = canonical(witness)
        # This is a genuinely valid W1/Cell witness. Rejecting it is specifically
        # the accounting/delivery binding, not a changed W1 acceptance rule.
        self.assertTrue(self.verify(witness=different_witness)['relation_valid'])
        events[-1]['witness_sha256'] = hashlib.sha256(different_witness).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            with AttemptJournal(out / 'proof-search.jsonl') as journal:
                for event in events:
                    journal.append(event)
                acknowledgement = journal.acknowledgement()
            report = inspect_acknowledged_journal(
                (out / 'proof-search.jsonl').read_bytes(), expected_plan=events[0],
                acknowledgement=acknowledgement,
                materials={item['index']: item['material'] for item in tiles})
            self.assertEqual(report['status'], 'complete')
            self.assertEqual(report['winning_attempts'][0]['nonce'], 0)
            with self.assertRaisesRegex(ValueError, 'SEARCH_DELIVERED_FIRST_HIT'):
                bind_delivered_witness(report, different_witness)
            for name, value in (
                    ('contract.json', self.raw), ('before-state.json', self.before),
                    ('proof-search-input.json', {'model': self.model, 'rows': self.rows}),
                    ('expected.json', self.expected), ('plan.json', events[0]),
                    ('acknowledgement.json', acknowledgement), ('witness.json', different_witness),
                    ('output.json', proved['output']), ('after-state.json', proved['after_state'])):
                driver.save(out / name, value)
            with self.assertRaisesRegex(ValueError, 'SEARCH_DELIVERED_FIRST_HIT'):
                driver.inspect_search_directory(out, out / 'expected.json', out / 'plan.json',
                                                out / 'acknowledgement.json')

    def test_final_fsync_failure_does_not_make_readable_end_a_completed_producer(self):
        tiles, _ = cell.build_tiles(self.model, self.rows)
        plan = relation.reference_search_plan(self.raw, self.before, tiles, len(self.rows), 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'search.jsonl'
            with AttemptJournal(path) as journal:
                def sink(event):
                    if event['kind'] == 'end':
                        with patch('useful_cell_attempt_journal_v1.os.fsync',
                                   side_effect=OSError('final fsync failed')):
                            journal.append(event)
                    else:
                        journal.append(event)

                with self.assertRaisesRegex(OSError, 'final fsync failed'):
                    relation.prove_reference(self.raw, self.model, self.rows, self.before,
                                             max_attempts=1, attempt_sink=sink)
                acknowledgement = journal.acknowledgement()
            raw = path.read_bytes()
            # Reading a complete last line is not proof that its fsync returned.
            self.assertEqual(inspect_journal(raw, expected_plan=plan)['status'], 'complete')
            report = inspect_acknowledged_journal(raw, expected_plan=plan,
                                                  acknowledgement=acknowledgement)
            self.assertEqual(report['status'], 'incomplete')
            self.assertEqual(report['completed_producer_batches'], 0)
            self.assertEqual(report['producer_reported_complete_outputs'], 0)
            self.assertEqual(report['counts']['completed_attempts'], 5)
            self.assertGreater(report['unacknowledged_suffix_bytes'], 0)

    def test_external_expected_policy_is_closed_and_mandatory(self):
        for key in self.expected:
            with self.subTest(missing=key):
                expected = copy.deepcopy(self.expected)
                del expected[key]
                with self.assertRaises(ValueError):
                    self.verify(expected=expected)
        for extra in ('trusted', 'source_verified', 'production_activation'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.verify(expected=dict(self.expected, **{extra: True}))

    def test_external_contract_program_and_parameters_cannot_be_rebound(self):
        for key in ('contract_id', 'program_sha256', 'parameters_sha256'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(expected=dict(self.expected, **{key: '00' * 32}))

    def test_external_consumer_use_and_candidate_are_checked(self):
        for key, value in [('consumer', '55' * 32),
                           ('allowed_use', 'production-model-installation'),
                           ('candidate_artifact', '66' * 32)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(expected=dict(self.expected, **{key: value}))

    def test_wrong_current_cell_generation_root_and_artifact_are_refused(self):
        for key, value in [('cell_id', '55' * 32), ('generation', 8),
                           ('state_root', '66' * 32),
                           ('model_artifact', '77' * 32)]:
            with self.subTest(key=key):
                before = dict(self.before, **{key: value})
                with self.assertRaises(ValueError):
                    self.verify(before=before)
                expected = dict(self.expected, before_state=before)
                with self.assertRaises(ValueError):
                    self.verify(expected=expected)
                # An attacker cannot replace both local arguments while the
                # independently frozen task still names the old generation.
                with self.assertRaises(ValueError):
                    self.verify(before=before, expected=expected)

    def test_read_only_transition_rejects_any_state_change(self):
        for key, value in [('cell_id', '55' * 32), ('generation', 8),
                           ('state_root', '66' * 32),
                           ('model_artifact', '77' * 32)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(after=dict(self.before, **{key: value}))
        with self.assertRaises(ValueError):
            self.verify(after=dict(self.before, next_generation=8))

    def test_deadline_is_checked_before_verification(self):
        with self.assertRaises(ValueError):
            self.verify(clock=lambda: self.options['deadline_ms'] + 1)

    def test_deadline_is_checked_after_full_verification(self):
        calls = []

        def clock():
            calls.append(1)
            return 1000 if len(calls) == 1 else 2001

        with self.assertRaises(ValueError):
            self.verify(clock=clock)
        self.assertGreaterEqual(len(calls), 2)

    def test_clock_must_return_exact_bounded_integers(self):
        for value in (True, False, 1000.0, -1, 1 << 64, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.verify(clock=lambda value=value: value)

    def test_contract_unknown_top_level_and_nested_fields_are_refused(self):
        self.assert_contract_refused(dict(self.contract, trusted=True))
        for name in ('model', 'state', 'inputs', 'numeric', 'decision',
                     'output', 'proof'):
            with self.subTest(section=name):
                value = copy.deepcopy(self.contract)
                value[name]['trusted'] = True
                self.assert_contract_refused(value)

    def test_contract_missing_sections_are_refused(self):
        for key in self.contract:
            with self.subTest(key=key):
                value = copy.deepcopy(self.contract)
                del value[key]
                self.assert_contract_refused(value)

    def test_numeric_semantics_are_executed_not_arbitrary_committed_labels(self):
        for key, original in self.contract['numeric'].items():
            with self.subTest(key=key):
                value = copy.deepcopy(self.contract)
                value['numeric'][key] = self.different(original)
                self.assert_contract_refused(value)
                with self.assertRaises(ValueError):
                    relation.prove_reference(canonical(value), self.model,
                                             self.rows, self.before,
                                             max_attempts=1)

    def test_decision_ties_stop_abstention_and_randomness_are_fixed(self):
        for key, original in self.contract['decision'].items():
            with self.subTest(key=key):
                value = copy.deepcopy(self.contract)
                value['decision'][key] = self.different(original)
                self.assert_contract_refused(value)
                with self.assertRaises(ValueError):
                    relation.prove_reference(canonical(value), self.model,
                                             self.rows, self.before,
                                             max_attempts=1)

    def test_contract_bytes_must_be_canonical_and_duplicate_free(self):
        duplicate = self.raw[:-1] + b',"schema":' + canonical(self.contract['schema']) + b'}'
        for raw in (b' ' + self.raw, self.raw + b'\n',
                    json.dumps(self.contract, indent=1).encode(), duplicate):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                self.verify(raw=raw, expected=self.rehashed_expected(raw))

    def test_nonfinite_json_and_non_object_contracts_are_refused(self):
        for raw in (b'NaN', b'Infinity', b'-Infinity', b'null', b'[]',
                    b'{"schema":NaN}', b'{"schema":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.verify(raw=raw, expected=self.rehashed_expected(raw))

    def test_bools_cannot_alias_state_counters_or_deadlines(self):
        for value in (True, False, 7.0, -1, 1 << 64):
            with self.subTest(generation=value), self.assertRaises(ValueError):
                relation.freeze_contract(self.model, self.rows,
                                         dict(self.before, generation=value),
                                         **self.options)
        for value in (True, False, 2000.0, -1, 1 << 64):
            with self.subTest(deadline=value), self.assertRaises(ValueError):
                relation.freeze_contract(self.model, self.rows, self.before,
                                         **dict(self.options, deadline_ms=value))

    def test_zero_noncanonical_and_malformed_targets_are_refused(self):
        for value in ('00' * 32, 'FF' * 32, 'ff' * 31, 'gg' * 32,
                      True, 1, None):
            with self.subTest(target=value), self.assertRaises(ValueError):
                relation.freeze_contract(self.model, self.rows, self.before,
                                         **dict(self.options, target=value))

    def test_source_features_cannot_be_asserted_by_the_producer(self):
        rows = copy.deepcopy(self.rows)
        rows[0]['x'][0] = 7 if rows[0]['x'][0] != 7 else 6
        with self.assertRaises(ValueError):
            relation.freeze_contract(self.model, rows, self.before, **self.options)
        with self.assertRaises(ValueError):
            relation.prove_reference(self.raw, self.model, rows, self.before,
                                     max_attempts=1)

    def test_source_identity_content_and_path_cannot_be_asserted(self):
        for key, value in [('id', '55' * 32),
                           ('source_content_sha256', '66' * 32),
                           ('file', '../outside.rs')]:
            with self.subTest(key=key):
                rows = copy.deepcopy(self.rows)
                rows[0][key] = value
                with self.assertRaises(ValueError):
                    relation.freeze_contract(self.model, rows, self.before,
                                             **self.options)

    def test_duplicate_missing_and_reordered_members_cannot_replay_one_batch(self):
        for rows in ([self.rows[0], self.rows[0]], self.rows[:1],
                     list(reversed(self.rows))):
            with self.subTest(ids=[row['id'] for row in rows]), self.assertRaises(ValueError):
                relation.prove_reference(self.raw, self.model, rows, self.before,
                                         max_attempts=1)

    def test_out_of_range_features_and_boolean_aliases_are_refused(self):
        for value in (9, -9, True, 0.0):
            with self.subTest(value=value):
                rows = copy.deepcopy(self.rows)
                rows[0]['x'][0] = value
                with self.assertRaises(ValueError):
                    relation.freeze_contract(self.model, rows, self.before,
                                             **self.options)

    def test_changed_model_cannot_reuse_the_original_artifact_or_contract(self):
        model = copy.deepcopy(self.model)
        model['base'][0][0] += 1 if model['base'][0][0] < 32767 else -1
        with self.assertRaises(ValueError):
            relation.freeze_contract(model, self.rows, self.before, **self.options)
        with self.assertRaises(ValueError):
            relation.prove_reference(self.raw, model, self.rows, self.before,
                                     max_attempts=1)

    def test_model_numeric_profile_and_range_are_closed(self):
        for key, value in [('scale', 512), ('feature', 'other-encoder'),
                           ('schema', 'bf16-hepta-model')]:
            with self.subTest(key=key):
                model = copy.deepcopy(self.model)
                model[key] = value
                with self.assertRaises(ValueError):
                    relation.freeze_contract(model, self.rows, self.before,
                                             **self.options)
        for value in (32768, -32768, True, 0.0):
            with self.subTest(weight=value):
                model = copy.deepcopy(self.model)
                model['router'][0][0] = value
                with self.assertRaises(ValueError):
                    relation.freeze_contract(model, self.rows, self.before,
                                             **self.options)

    def test_changed_prediction_is_refused(self):
        output = copy.deepcopy(self.proved['output'])
        output['predictions'][0] = (output['predictions'][0] + 1) % 3
        with self.assertRaises(ValueError):
            self.verify(output=output)

    def test_unknown_output_fields_are_not_consumer_authority(self):
        with self.assertRaises(ValueError):
            self.verify(output=dict(self.proved['output'], trusted=True))

    def test_entire_correct_rehashed_package_cannot_replace_external_admission(self):
        before = dict(self.before, generation=self.before['generation'] + 1,
                      state_root='88' * 32)
        options = dict(self.options, consumer='99' * 32, request_id='aa' * 32)
        raw = relation.freeze_contract(self.model, self.rows, before, **options)
        changed = relation.prove_reference(raw, self.model, self.rows, before,
                                           max_attempts=1)
        self.assertNotEqual(relation.contract_id(raw), self.expected['contract_id'])
        # Every byte in the second package is internally correct, including
        # genuine proofs generated for that package's own challenge domain.
        with self.assertRaisesRegex(ValueError, 'EXPECTED_CONTRACT'):
            self.verify(raw=raw, before=before, output=changed['output'],
                        after=changed['after_state'], witness=changed['witness'])
        expected = self.rehashed_expected(raw)
        with self.assertRaisesRegex(ValueError, 'EXPECTED_STATE'):
            self.verify(raw=raw, before=before, output=changed['output'],
                        after=changed['after_state'], witness=changed['witness'],
                        expected=expected)
        expected['before_state'] = before
        with self.assertRaisesRegex(ValueError, 'EXPECTED_CONSUMER'):
            self.verify(raw=raw, before=before, output=changed['output'],
                        after=changed['after_state'], witness=changed['witness'],
                        expected=expected)

    def test_contract_mutation_reaches_executed_semantics_after_rehash(self):
        cases = [('numeric', 'reduction_order', 'arbitrary-parallel-float'),
                 ('numeric', 'overflow', 'wrap-mod-field'),
                 ('decision', 'router_ties', 'highest-index'),
                 ('decision', 'stop', 'enabled'),
                 ('decision', 'abstention', 'enabled'),
                 ('decision', 'randomness', 'seed-from-producer'),
                 ('inputs', 'upstream', 'trusted-producer-boolean')]
        for section, key, replacement in cases:
            with self.subTest(section=section, key=key):
                value = copy.deepcopy(self.contract)
                value[section][key] = replacement
                raw = canonical(value)
                # A refreshed outer contract ID cannot legitimize unsupported
                # semantics. This must reach the relation's reconstruction,
                # rather than merely failing the unchanged outer digest.
                with self.assertRaisesRegex(ValueError, 'EXECUTED_CONTRACT_MISMATCH'):
                    self.verify(raw=raw, expected=self.rehashed_expected(raw))

    def test_witness_schema_closed_fields_and_native_status_spoof_are_refused(self):
        original = json.loads(self.proved['witness'])
        cases = [dict(original, schema='pon-matmul-transcript-64-v1'),
                 dict(original, schema='pon-shared-cell-operator-v1'),
                 dict(original, source_verified=True),
                 dict(original, verification={'native': {'outcome': 'Accepted'}})]
        for key in original:
            value = copy.deepcopy(original)
            del value[key]
            cases.append(value)
        for index, value in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                self.verify(witness=canonical(value))

    def test_witness_must_be_canonical_bounded_and_duplicate_free(self):
        raw = self.proved['witness']
        value = json.loads(raw)
        duplicate = raw[:-1] + b',"schema":' + canonical(value['schema']) + b'}'
        cases = [b'', raw[:-1], raw + b'\n', b' ' + raw, duplicate,
                 b'NaN', b'null', b'[]', b'{"schema":NaN}',
                 b' ' * (relation.WITNESS_LIMIT + 1)]
        for index, changed in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                self.verify(witness=changed)

    def test_witness_model_and_features_are_rechecked(self):
        original = json.loads(self.proved['witness'])
        changed = copy.deepcopy(original)
        weight = changed['model']['base'][0][0]
        changed['model']['base'][0][0] = weight + 1 if weight < 32767 else weight - 1
        with self.assertRaises(ValueError):
            self.verify(witness=canonical(changed))
        changed = copy.deepcopy(original)
        value = changed['rows'][0]['x'][0]
        changed['rows'][0]['x'][0] = value + 1 if value < 8 else value - 1
        with self.assertRaises(ValueError):
            self.verify(witness=canonical(changed))

    def test_missing_duplicate_extra_and_reordered_witness_tiles_are_refused(self):
        original = json.loads(self.proved['witness'])
        tiles = original['tiles']
        for replacement in (tiles[:-1], tiles + tiles[:1],
                            [tiles[0]] * 5, list(reversed(tiles))):
            with self.subTest(indices=[entry['index'] for entry in replacement]), self.assertRaises(ValueError):
                self.verify(witness=canonical(dict(original, tiles=replacement)))

    def test_tile_indices_nonces_and_fields_are_strict(self):
        original = json.loads(self.proved['witness'])
        for key, replacement in [('index', True), ('index', 1),
                                 ('nonce', True), ('nonce', -1),
                                 ('nonce', 1 << 64), ('nonce', 1)]:
            with self.subTest(key=key, replacement=replacement):
                value = copy.deepcopy(original)
                value['tiles'][0][key] = replacement
                with self.assertRaises(ValueError):
                    self.verify(witness=canonical(value))
        value = copy.deepcopy(original)
        value['tiles'][0]['verified'] = True
        with self.assertRaises(ValueError):
            self.verify(witness=canonical(value))

    def test_proof_magic_material_product_trace_and_field_are_verified(self):
        original = json.loads(self.proved['witness'])
        original_proof = bytes.fromhex(original['tiles'][0]['proof_hex'])
        material_end = 4 + 2 * work.CELLS * 4
        changes = {}
        changed = bytearray(original_proof)
        changed[0] ^= 1
        changes['magic'] = bytes(changed)
        changed = bytearray(original_proof)
        changed[4] ^= 1
        changes['A-material'] = bytes(changed)
        changed = bytearray(original_proof)
        changed[4 + work.CELLS * 4] ^= 1
        changes['B-material'] = bytes(changed)
        changed = bytearray(original_proof)
        product = struct.unpack_from('<I', changed, material_end)[0]
        struct.pack_into('<I', changed, material_end, (product + 1) % work.Q)
        changes['product'] = bytes(changed)
        changed = bytearray(original_proof)
        changed[-1] ^= 1
        changes['trace'] = bytes(changed)
        changed = bytearray(original_proof)
        struct.pack_into('<I', changed, material_end, work.Q)
        changes['noncanonical-field'] = bytes(changed)
        changes['truncated'] = original_proof[:-1]
        changes['extended'] = original_proof + b'\x00'
        for kind, proof in changes.items():
            with self.subTest(kind=kind):
                value = copy.deepcopy(original)
                value['tiles'][0]['proof_hex'] = proof.hex()
                with self.assertRaises(ValueError):
                    self.verify(witness=canonical(value))

    def test_correct_old_w1_challenge_proof_cannot_cross_into_the_new_relation(self):
        value = json.loads(self.proved['witness'])
        original = bytes.fromhex(value['tiles'][0]['proof_hex'])
        words = list(struct.unpack('<' + 'I' * (2 * work.CELLS),
                                   original[4:4 + 2 * work.CELLS * 4]))
        a, b = words[:work.CELLS], words[work.CELLS:]
        task = work.task_id(a, b)
        target = bytes.fromhex(self.options['target'])
        old_challenge = H('pon-shared-material-challenge-v1', task, target,
                          bytes.fromhex('12' * 32), struct.pack('<Q', 0),
                          struct.pack('<Q', 0))
        old_proof = work.prove(old_challenge, a, b)
        # Establish the adversary has a genuinely valid old-context proof;
        # a malformed random byte string would not test domain separation.
        work.verify(old_challenge, task, target, old_proof)
        value['tiles'][0]['proof_hex'] = old_proof.hex()
        with self.assertRaisesRegex(ValueError, 'TRANSCRIPT'):
            self.verify(witness=canonical(value))

    def test_output_routes_logits_ties_stop_and_abstention_are_not_self_reported(self):
        for key in ('routes', 'predictions'):
            with self.subTest(key=key):
                output = copy.deepcopy(self.proved['output'])
                output[key][0] = (output[key][0] + 1) % 3
                with self.assertRaisesRegex(ValueError, 'OUTPUT_RELATION'):
                    self.verify(output=output)
        output = copy.deepcopy(self.proved['output'])
        output['logits'][0][0] += 1
        with self.assertRaisesRegex(ValueError, 'OUTPUT_RELATION'):
            self.verify(output=output)
        for key in ('stop', 'abstain'):
            for replacement in (True, 0):
                with self.subTest(key=key, replacement=replacement):
                    output = copy.deepcopy(self.proved['output'])
                    output[key][0] = replacement
                    with self.assertRaisesRegex(ValueError, 'OUTPUT_(RELATION|DECISIONS)'):
                        self.verify(output=output)

    def test_output_consumer_request_candidate_and_contract_are_bound(self):
        for key in ('consumer', 'request_id', 'candidate_artifact', 'contract_id'):
            with self.subTest(key=key):
                output = copy.deepcopy(self.proved['output'])
                output[key] = 'ff' * 32
                with self.assertRaisesRegex(ValueError, 'OUTPUT_RELATION'):
                    self.verify(output=output)

    def test_clock_cannot_rewind_during_verification(self):
        observations = iter((1000, 999))
        with self.assertRaisesRegex(ValueError, 'COMPLETION_DEADLINE'):
            self.verify(clock=lambda: next(observations))

    def test_self_consistent_feature_recommitment_still_requires_real_source(self):
        witness = json.loads(self.proved['witness'])
        rows = witness['rows']
        rows[0]['x'][0] = 7 if rows[0]['x'][0] != 7 else 6
        contract = copy.deepcopy(self.contract)
        contract['inputs']['rows_sha256'] = hashlib.sha256(canonical(rows)).hexdigest()
        contract['inputs']['batch_members'][0]['features_sha256'] = hashlib.sha256(
            canonical(rows[0]['x'])).hexdigest()
        raw = canonical(contract)
        # All supplied feature hashes and the outer admitted hash now agree.
        # Rejection must come from actual source reconstruction, before proof
        # material or the old output can provide an incidental rejection.
        with self.assertRaisesRegex(ValueError, 'SOURCE_FEATURE_BINDING'):
            self.verify(raw=raw, witness=canonical(witness),
                        expected=self.rehashed_expected(raw))

    def test_rehashing_cannot_promote_reference_scope_or_change_state_policy(self):
        for key, value in self.contract['scope'].items():
            with self.subTest(scope=key):
                contract = copy.deepcopy(self.contract)
                contract['scope'][key] = self.different(value)
                raw = canonical(contract)
                with self.assertRaisesRegex(ValueError, 'EXECUTED_CONTRACT_MISMATCH'):
                    self.verify(raw=raw, expected=self.rehashed_expected(raw))

    def test_replacing_loaded_code_is_rejected_and_restoration_recovers_identity(self):
        original = relation._components.__code__

        def changed_components(model, identity):
            return {}

        try:
            # A negative control only: even with unchanged disk source, this
            # process no longer executes the code named by its pinned digest.
            relation._components.__code__ = changed_components.__code__
            with self.assertRaisesRegex(ValueError, 'PROGRAM_LOADED_CODE_MISMATCH'):
                relation.current_identity()
            with self.assertRaisesRegex(ValueError, 'PROGRAM_LOADED_CODE_MISMATCH'):
                self.verify()
        finally:
            relation._components.__code__ = original
        self.assertEqual(relation.current_identity()['program_sha256'],
                         self.expected['program_sha256'])

    def test_malformed_models_raise_closed_rejection_not_type_errors(self):
        original = json.loads(self.proved['witness'])
        for model in (None, 7, True, [{}]):
            with self.subTest(model=model):
                with self.assertRaisesRegex(ValueError, 'MODEL_OBJECT'):
                    relation.freeze_contract(model, self.rows, self.before,
                                             **self.options)
                with self.assertRaisesRegex(ValueError, 'MODEL_OBJECT'):
                    relation.prove_reference(self.raw, model, self.rows,
                                             self.before, max_attempts=1)
                with self.assertRaisesRegex(ValueError, 'MODEL_OBJECT'):
                    self.verify(witness=canonical(dict(original, model=model)))

    def test_deep_or_cyclic_output_is_rejected_before_recursive_serialization(self):
        nested = 0
        for _ in range(1500):
            nested = [nested]
        output = copy.deepcopy(self.proved['output'])
        output['logits'][0][0] = nested
        with self.assertRaisesRegex(ValueError, 'OUTPUT_LOGITS'):
            self.verify(output=output)
        with self.assertRaisesRegex(ValueError, 'OUTPUT_FIELDS'):
            self.verify(output=nested)
        cyclic = []
        cyclic.append(cyclic)
        output['logits'][0][0] = cyclic
        with self.assertRaisesRegex(ValueError, 'OUTPUT_LOGITS'):
            self.verify(output=output)

    def stale_source_subprocess(self, case, expected_error):
        """Mutate only an isolated source copy, never the active repository."""
        code = r'''
import json
from pathlib import Path
import sys

case, expected_error = sys.argv[1:]
path = Path('formal/pon-nakamoto-v1/useful_cell_numeric_v1.py')
if case == 'after-relation-import':
    import useful_cell_relation_v1 as relation
else:
    import useful_cell_numeric_v1
raw = path.read_text()
if case == 'stale-constant':
    old = 'WEIGHT_ABS_MAX = 32767'
    new = 'WEIGHT_ABS_MAX = 32766'
elif case == 'stale-profile-leaf':
    old = '"inference_rounding": "none"'
    new = '"inference_rounding": "free"'
elif case == 'stale-profile-expression':
    old = '"coefficient_scale": SCALE,'
    new = '"coefficient_scale": SCALE * 2,'
else:
    old = 'def evaluate_exact(model, rows):\n'
    new = old + '    raise RuntimeError("NEW_DISK_CODE_MUST_NOT_BE_OLD_LOADED_CODE")\n'
if raw.count(old) != 1:
    raise RuntimeError('STALE_SOURCE_TEST_ANCHOR')
path.write_text(raw.replace(old, new, 1))
if case != 'after-relation-import':
    import useful_cell_relation_v1 as relation
try:
    relation.current_identity()
except ValueError as error:
    if str(error) != expected_error:
        raise
    print(json.dumps({'case': case, 'rejected': str(error)}))
else:
    raise RuntimeError('STALE_SOURCE_WRONGLY_ACCEPTED')
'''
        with tempfile.TemporaryDirectory(prefix='useful-cell-stale-source-') as directory:
            isolated = Path(directory)
            for relative in relation.SOURCE_FILES:
                destination = isolated / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(relation.ROOT / relative, destination)
            env = dict(os.environ)
            env['PYTHONPATH'] = str(isolated / 'formal/pon-nakamoto-v1')
            env['PYTHONDONTWRITEBYTECODE'] = '1'
            completed = subprocess.run(
                [sys.executable, '-B', '-c', code, case, expected_error],
                cwd=isolated, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30, check=False)
            self.assertEqual(completed.returncode, 0,
                             completed.stderr.decode(errors='replace'))
            self.assertEqual(json.loads(completed.stdout),
                             {'case': case, 'rejected': expected_error})

    def test_source_changed_after_relation_import_requires_restart(self):
        self.stale_source_subprocess('after-relation-import',
                                     'PROGRAM_SOURCE_CHANGED_RESTART_REQUIRED')

    def test_dependency_loaded_before_source_change_cannot_claim_new_program(self):
        self.stale_source_subprocess('before-relation-import',
                                     'PROGRAM_LOADED_CODE_MISMATCH')

    def test_same_line_constant_change_cannot_hide_behind_identical_function_code(self):
        self.stale_source_subprocess('stale-constant',
                                     'PROGRAM_LOADED_CONSTANT_MISMATCH')

    def test_literal_profile_leaf_in_computed_dictionary_is_not_skipped(self):
        for case in ('stale-profile-leaf', 'stale-profile-expression'):
            with self.subTest(case=case):
                self.stale_source_subprocess(case,
                                             'PROGRAM_LOADED_CONSTANT_MISMATCH')


if __name__ == '__main__':
    unittest.main(verbosity=2)
