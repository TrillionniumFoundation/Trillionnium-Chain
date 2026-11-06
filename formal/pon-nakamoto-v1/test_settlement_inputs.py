"""Frozen settlement inputs and model-contraction binding, not efficacy evidence.

These controlled fixtures use no new training, external monetary rewards or real demand.
The scalar W1 oracle constructs complete legal proofs; the settlement boundary must
still reject a proof for any other admitted model, consumer input or challenge.
"""
from __future__ import annotations

import copy
from argparse import Namespace
from contextlib import contextmanager, redirect_stdout
from dataclasses import FrozenInstanceError
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from contract_wire import H, canonical
from evaluation import CONTROL_ORDER
from evaluation_bundle import artifact_id, evaluate_bundle, freeze_bundle, predict_rows, verify_bundle
from experiments import settle_model as settle
from test_evaluation_bundle import model, rows
import work_oracle as oracle


TARGET = bytes([255]) * 32
PARTITIONS = ('train', 'calibration', 'evaluation_a', 'evaluation_b', 'consumer')


def candidate_model():
    candidate = model(0)
    candidate['base'][0][1] = -1
    candidate['base'][1][2] = 2
    candidate['deltas'][0][1][0] = 32
    candidate['deltas'][0][1][2] = -1
    candidate['deltas'][0][2][63] = -4
    # Distinct unused coefficients keep the three real contribution artifacts
    # distinct without changing the expert-0 routing or any fixture prediction.
    candidate['deltas'][1][2][200] = 1
    candidate['deltas'][2][2][200] = 2
    return candidate


def input_partitions():
    partitions = {name: rows(name, count=65 if name == 'consumer' else 24)
                  for name in PARTITIONS}
    for partition in partitions.values():
        for index, row in enumerate(partition):
            for column, value in ((0, 1 + index % 3), (1, -2), (2, 3), (63, 4), (64, 5)):
                row['x'][column] = value
    return partitions


def generator_work(files):
    """Reference the existing model_loop generator, independently of settle_model.

    A pads the first 64 consumer feature prefixes to a 64 by 64 matrix. B pads
    the transpose of (base + expert 0)'s first 64 features to three output columns.
    The challenge binds the entire raw model artifact and all canonical consumers.
    """
    candidate = json.loads(files['model.json'])
    consumer = json.loads(files['consumer.json'])
    prefixes = [row['x'][:64] for row in consumer[:64]]
    prefixes.extend([[0] * 64 for _ in range(64 - len(prefixes))])
    weights = [[candidate['base'][output][feature] + candidate['deltas'][0][output][feature]
                for output in range(3)] + [0] * 61 for feature in range(64)]
    a = [value % oracle.Q for row in prefixes for value in row]
    b = [value % oracle.Q for row in weights for value in row]
    context = H('real-model-work', H('artifact', files['model.json']),
                H('tasks', canonical(consumer)))
    return a, b, context


def frozen_files(*, candidate=None, partitions=None, parent_release='00' * 32, round_number=1):
    current = model(0)
    candidate = candidate_model() if candidate is None else candidate
    partitions = input_partitions() if partitions is None else partitions
    raw, digest = freeze_bundle(source_commit='ab' * 20, round_number=round_number,
        parent_release=parent_release, current=current, candidate=candidate,
        controls={name: copy.deepcopy(current) for name in CONTROL_ORDER},
        partitions=partitions)
    bundle = verify_bundle(raw, digest)
    files = {'evaluation-bundle.json': raw, 'model.json': canonical(candidate)}
    files.update({name + '.json': canonical(data) for name, data in partitions.items()})
    results = {}
    for name in ('evaluation_a', 'evaluation_b', 'consumer'):
        result = evaluate_bundle(raw, digest, partitions[name], name,
                                 calibration_rows=partitions['calibration'])
        results[name] = dict(schema='controlled-source-evaluation-v3',
            task_commitment=H('tasks', canonical(partitions[name])).hex(),
            evaluation_bundle=digest, evaluation_partition=name,
            model_artifact=bundle['candidate_artifact'], predictions=result['predictions'],
            value_claim=result['value_claim'],
            whole_gain=dict(result['primary'], score=result['primary']['exploratory_score']),
            marginal=[dict(value, score=value['exploratory_score']) for value in result['marginal']],
            strong_reference=bundle['selected'], strong_reference_artifact=result['reference_artifact'])
        files[name + '-result.json'] = canonical(results[name])
    a, b, context = generator_work(files)
    report = dict(schema='controlled-model-loop-report-v1', source='ab' * 20,
        models=dict(artifact_hash=artifact_id(candidate), bytes=len(files['model.json'])),
        evaluation_bundle=digest, results=results,
        useful_work=dict(proof_file='model-work.bin', task_commitment=oracle.task_id(a, b).hex(),
                         challenge=context.hex(), proof_bytes=oracle.PROOF_BYTES,
                         exact_integer_contraction=True))
    files['report.json'] = canonical(report)
    return files, digest


class SettlementInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files, cls.digest = frozen_files()
        report = json.loads(cls.files['report.json'])
        for name in ('evaluation_a', 'evaluation_b'):
            if (report['results'][name]['whole_gain']['score'] <= 0 or
                    report['results'][name]['marginal'][0]['score'] <= 0):
                raise AssertionError('Fixture must reach the work gate before opening a ledger')
        cls.a, cls.b, cls.context = generator_work(cls.files)
        cls.proof = oracle.prove(cls.context, cls.a, cls.b)
        cls.other_context = H('settlement-input-test-other-context', cls.context)
        cls.other_context_proof = oracle.prove(cls.other_context, cls.a, cls.b)
        cls.other_a = [int(i == j) for i in range(64) for j in range(64)]
        cls.other_b = list(cls.other_a)
        cls.other_matrix_proof = oracle.prove(cls.context, cls.other_a, cls.other_b)
        corrupt = bytearray(cls.proof)
        corrupt[-1] ^= 1
        cls.corrupt_trace = bytes(corrupt)
        cls.files['model-work.bin'] = cls.proof

    @contextmanager
    def observation(self, files=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'input'
            directory.mkdir()
            for name, raw in (self.files if files is None else files).items():
                (directory / name).write_bytes(raw)
            yield directory

    def snapshot(self, files=None, digest=None):
        with self.observation(files) as directory:
            return settle._read_observation(directory, self.digest if digest is None else digest)

    def test_complete_bound_proof_matches_generator_mapping(self):
        inputs = self.snapshot()
        a, b = settle._verify_model_work(inputs, self.proof)
        self.assertEqual((a, b), (self.a, self.b))
        self.assertEqual(a[:3], [1, oracle.Q - 2, 3])
        self.assertEqual(b[1], 32)
        self.assertEqual(b[64], oracle.Q - 1)
        self.assertEqual(b[2 * 64 + 1], 1)
        self.assertEqual(b[63 * 64 + 2], oracle.Q - 4)
        self.assertTrue(all(b[row * 64 + col] == 0 for row in range(64) for col in range(3, 64)))
        _, product = oracle.verify(self.context, oracle.task_id(a, b), TARGET, self.proof)
        self.assertEqual(product[:4], [2, 35, oracle.Q - 16, 0])

    def test_short_consumer_batch_retains_generator_zero_padding(self):
        partitions = input_partitions()
        partitions['consumer'] = partitions['consumer'][:7]
        files, digest = frozen_files(partitions=partitions)
        a, b, context = generator_work(files)
        proof = oracle.prove(context, a, b)
        self.assertEqual(settle._verify_model_work(self.snapshot(files, digest), proof), (a, b))
        self.assertEqual(a[7 * 64:], [0] * (57 * 64))

    def test_same_matrix_product_at_another_challenge_cannot_authorize_this_observation(self):
        task = oracle.task_id(self.a, self.b)
        _, first = oracle.verify(self.context, task, TARGET, self.proof)
        _, other = oracle.verify(self.other_context, task, TARGET, self.other_context_proof)
        self.assertEqual(first, other)
        self.assertNotEqual(self.proof[-32:], self.other_context_proof[-32:])
        with self.assertRaises(ValueError):
            settle._verify_model_work(self.snapshot(), self.other_context_proof)

    def test_another_legal_matrix_proof_is_not_the_model_contraction(self):
        oracle.verify(self.context, oracle.task_id(self.other_a, self.other_b), TARGET,
                      self.other_matrix_proof)
        with self.assertRaises(ValueError):
            settle._verify_model_work(self.snapshot(), self.other_matrix_proof)

    def test_model_change_outside_selected_expert_still_changes_context(self):
        candidate = candidate_model()
        candidate['deltas'][2][2][256] = 1
        files, digest = frozen_files(candidate=candidate)
        a, b, context = generator_work(files)
        self.assertEqual((a, b), (self.a, self.b))
        self.assertNotEqual(context, self.context)
        with self.assertRaises(ValueError):
            settle._verify_model_work(self.snapshot(files, digest), self.proof)

    def test_full_consumer_context_includes_unselected_rows_and_features(self):
        for row, column in ((64, 0), (0, 64)):
            with self.subTest(row=row, column=column):
                partitions = input_partitions()
                partitions['consumer'][row]['x'][column] += 1
                files, digest = frozen_files(partitions=partitions)
                a, b, context = generator_work(files)
                self.assertEqual((a, b), (self.a, self.b))
                self.assertNotEqual(context, self.context)
                with self.assertRaises(ValueError):
                    settle._verify_model_work(self.snapshot(files, digest), self.proof)

    def test_changed_selected_consumer_features_cannot_reuse_original_matrix(self):
        partitions = input_partitions()
        partitions['consumer'][0]['x'][0] += 1
        files, digest = frozen_files(partitions=partitions)
        a, b, _ = generator_work(files)
        self.assertNotEqual(a, self.a)
        self.assertEqual(b, self.b)
        with self.assertRaises(ValueError):
            settle._verify_model_work(self.snapshot(files, digest), self.proof)

    def test_complete_transcript_check_is_required_after_successful_precheck(self):
        oracle.precheck(self.context, oracle.task_id(self.a, self.b), TARGET, self.corrupt_trace)
        with self.assertRaises(ValueError):
            settle._verify_model_work(self.snapshot(), self.corrupt_trace)

    def test_legal_field_work_cannot_bypass_generator_merged_coefficient_bound(self):
        candidate = candidate_model()
        candidate['base'][1][0] = 20000
        candidate['deltas'][0][1][0] = 20000
        files, digest = frozen_files(candidate=candidate)
        a, b, context = generator_work(files)
        proof = oracle.prove(context, a, b)
        oracle.verify(context, oracle.task_id(a, b), TARGET, proof)
        with self.assertRaisesRegex(ValueError, 'MODEL_BOUND'):
            settle._verify_model_work(self.snapshot(files, digest), proof)

    def test_snapshot_survives_original_file_changes(self):
        with self.observation() as directory:
            inputs = settle._read_observation(directory, self.digest)
            original = tuple(inputs.files)
            self.assertIsInstance(inputs.files, tuple)
            for name, raw in original:
                self.assertIsInstance(raw, bytes)
                (directory / name).write_bytes(b'changed after verification')
            self.assertEqual(inputs.files, original)
            for name, raw in original:
                self.assertEqual(inputs.raw(name), raw)
            self.assertEqual(settle._verify_model_work(inputs, self.proof), (self.a, self.b))
            with self.assertRaises(FrozenInstanceError):
                inputs.files = ()

    def test_parsed_values_cannot_mutate_retained_snapshot(self):
        inputs = self.snapshot()
        exposed_model = inputs.parsed('model.json')
        exposed_consumer = inputs.parsed('consumer.json')
        exposed_model['deltas'][0][1][0] = 0
        exposed_consumer[0]['x'][0] = 0
        self.assertEqual(inputs.raw('model.json'), self.files['model.json'])
        self.assertEqual(inputs.parsed('consumer.json'), json.loads(self.files['consumer.json']))
        self.assertEqual(settle._verify_model_work(inputs, self.proof), (self.a, self.b))

    def assert_unsupported_settlement_context(self, parent_release, round_number):
        # All bytes and scores are genuinely recomputed under the supplied
        # bundle digest. The consumer must reject the unsupported context,
        # rather than relying on an invalid hash, missing proof or losing score.
        files, digest = frozen_files(parent_release=parent_release, round_number=round_number)
        files['model-work.bin'] = self.proof
        bundle = verify_bundle(files['evaluation-bundle.json'], digest)
        self.assertEqual(bundle['parent_release'], parent_release)
        self.assertEqual(bundle['round'], round_number)
        self.assertEqual(generator_work(files), (self.a, self.b, self.context))
        report = json.loads(files['report.json'])
        for partition in ('evaluation_a', 'evaluation_b'):
            self.assertGreater(report['results'][partition]['whole_gain']['score'], 0)
            self.assertGreater(report['results'][partition]['marginal'][0]['score'], 0)
        with self.observation(files) as directory:
            output = directory.parent / 'settlement'
            with patch.object(settle, 'evaluate_bundle', side_effect=AssertionError('evaluation started')) as replay, \
                    patch.object(settle, 'Ledger', side_effect=AssertionError('ledger opened')) as ledger:
                with self.assertRaisesRegex(ValueError, '^SETTLEMENT_CONTEXT$'):
                    settle.run(directory, output, digest)
                replay.assert_not_called()
                ledger.assert_not_called()
            self.assertFalse((output / 'chain').exists())
            self.assertFalse((output / 'report.json').exists())

    def test_initial_settlement_rejects_nonzero_parent_before_evaluation_or_ledger(self):
        self.assert_unsupported_settlement_context('a1' * 32, 1)

    def test_initial_settlement_rejects_later_evaluation_round_before_evaluation_or_ledger(self):
        self.assert_unsupported_settlement_context('00' * 32, 2)

    def test_initial_settlement_rejects_foreign_parent_and_round_before_evaluation_or_ledger(self):
        self.assert_unsupported_settlement_context('a1' * 32, 7)

    def test_bad_work_is_rejected_before_ledger_opens(self):
        bad_proofs = {'other legal matrices': self.other_matrix_proof,
                      'other legal challenge': self.other_context_proof,
                      'fabricated trace passing precheck': self.corrupt_trace,
                      'truncated proof': self.proof[:-1]}
        for name, proof in bad_proofs.items():
            with self.subTest(proof=name), self.observation() as directory:
                (directory / 'model-work.bin').write_bytes(proof)
                output = directory.parent / 'settlement'
                with patch.object(settle, 'Ledger', side_effect=AssertionError('ledger opened before work check')) as ledger:
                    with self.assertRaises(ValueError):
                        settle.run(directory, output, self.digest)
                    ledger.assert_not_called()
                self.assertFalse((output / 'chain').exists())

    def test_valid_frozen_inputs_reach_ledger_only_after_work_check(self):
        with self.observation() as directory:
            output = directory.parent / 'settlement'
            with patch.object(settle, 'Ledger', side_effect=RuntimeError('validated ledger boundary')) as ledger:
                with self.assertRaisesRegex(RuntimeError, 'validated ledger boundary'):
                    settle.run(directory, output, self.digest)
                ledger.assert_called_once_with(output / 'chain')

    def test_inference_binds_the_bytes_actually_loaded_before_path_replacement(self):
        from experiments import model_loop
        candidate = json.loads(self.files['model.json'])
        consumer = json.loads(self.files['consumer.json'])
        replacement = copy.deepcopy(candidate)
        replacement['base'][0][200] = 11
        original_raw, replacement_raw = canonical(candidate), canonical(replacement)
        expected = predict_rows(candidate, consumer)
        self.assertEqual(predict_rows(replacement, consumer), expected)
        self.assertNotEqual(original_raw, replacement_raw)
        with self.observation() as directory:
            actual_predict = model_loop.predict

            def predict_then_replace(*args, **kwargs):
                predicted = actual_predict(*args, **kwargs)
                (directory / 'model.json').write_bytes(replacement_raw)
                return predicted

            output = directory.parent / 'inference.json'
            with patch.object(model_loop, 'predict', side_effect=predict_then_replace) as predict:
                model_loop.worker(Namespace(mode='infer', tasks=str(directory / 'consumer.json'),
                                            model=str(directory / 'model.json'), out=str(output)))
                predict.assert_called_once()
            observed = json.loads(output.read_bytes())
            self.assertEqual(observed['predictions'], expected)
            self.assertEqual(observed['model_artifact'], H('artifact', original_raw).hex())
            self.assertEqual((directory / 'model.json').read_bytes(), replacement_raw)

    def test_real_settlement_uses_snapshot_after_original_inputs_are_replaced(self):
        """One actual ledger/work/disk/inference path; no successful ledger mock."""
        bundle = verify_bundle(self.files['evaluation-bundle.json'], self.digest)
        self.assertEqual(bundle['parent_release'], '00' * 32)
        self.assertEqual(bundle['round'], 1)
        with self.observation() as directory:
            output = directory.parent / 'settlement'
            persisted = []
            renamed = []
            actual_persist, actual_rename = settle._persist_inputs, Path.rename
            replacement = b'original input replaced after the verified snapshot\n'

            def persist_then_replace(inputs, out):
                digest = actual_persist(inputs, out)
                persisted.append(inputs)
                for name, _ in inputs.files:
                    (directory / name).write_bytes(replacement)
                return digest

            def record_real_rename(source, destination):
                renamed.append((source, Path(destination)))
                return actual_rename(source, destination)

            with patch.object(settle, '_persist_inputs', side_effect=persist_then_replace), \
                    patch.object(Path, 'rename', new=record_real_rename), \
                    redirect_stdout(io.StringIO()):
                settle.run(directory, output, self.digest)
            self.assertEqual(len(persisted), 1)
            for name, raw in persisted[0].files:
                self.assertEqual((output / 'verified-inputs' / name).read_bytes(), raw)
                self.assertEqual((directory / name).read_bytes(), replacement)
            self.assertTrue(renamed, 'The real local author-copy withdrawal must execute')
            self.assertTrue(all(directory not in (source.parent, destination.parent)
                                for source, destination in renamed))
            self.assertFalse((directory / 'model.author-offline').exists())
            report = json.loads((output / 'report.json').read_bytes())
            original_artifact = H('artifact', self.files['model.json']).hex()
            self.assertEqual(report['outcome'], 'experimental_release_claim_and_free_service_completed')
            self.assertEqual(report['adopted_model'], original_artifact)
            self.assertEqual(report['rewarded_experts'], [0])
            self.assertTrue(report['model_work_binding_replayed'])
            self.assertEqual(report['author_withdrawal_scope'], 'frozen-local-author-copy')
            self.assertGreater(report['block_count'], 0)
            service = json.loads((output / 'consumer-service.json').read_bytes())
            self.assertEqual(service['model_artifact'], original_artifact)
            self.assertEqual(service['predictions'], predict_rows(
                json.loads(self.files['model.json']), json.loads(self.files['consumer.json'])))


if __name__ == '__main__':
    unittest.main()
