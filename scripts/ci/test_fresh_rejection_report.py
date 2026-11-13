#!/usr/bin/env python3
"""Synthetic clock/metadata fixtures exercise the reader, never native benchmarks.

Inputs and false-ticket searches are real. The positive reader test uses the
unchanged independent scalar W1 implementation for every selected transcript.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_fresh_rejection_report as cost


def row_fixture(class_name, target, sample):
    _, _, prefix, task = cost.material(class_name)
    challenge = cost.challenge_for(class_name, target, sample)
    attempts = []
    for nonce in range(cost.LIMIT):
        trace = cost.trace_for(challenge, nonce)
        ticket = cost.h(b'ticket', challenge, trace)
        selected = ticket.hex() <= target
        attempts.append({'nonce': nonce, 'trace': trace.hex(), 'ticket': ticket.hex(),
                         'selected': selected, 'trace_ns': 3, 'ticket_ns': 5})
        if selected:
            break
    assert selected, 'deterministic fixed fixture must actually find a fake ticket'
    count = len(attempts)
    search_ns = 8 * count + 11
    return {'class': class_name, 'sample': sample, 'target': target, 'task': task,
            'challenge': challenge.hex(), 'prefix_sha256': cost.digest(prefix),
            'setup': {'material_ns': 11, 'task_ns': 13, 'challenge_ns': 17, 'prefix_ns': 19,
                      'wall_ns': 65, 'overhead_ns': 5},
            'search': {'outcome': 'ticket-found', 'attempt_limit': cost.LIMIT,
                       'wall_ns': search_ns, 'trace_ns': 3 * count, 'ticket_ns': 5 * count,
                       'overhead_ns': 11, 'attempts': attempts},
            'proof': {'bytes': cost.PROOF_BYTES, 'sha256': cost.digest(prefix + trace), 'encoding_ns': 7},
            'acquisition': {'wall_ns': 65 + search_ns + 7 + 4,
                            'accounted_ns': 65 + search_ns + 7, 'overhead_ns': 4},
            'precheck': {'actual_result': 'FilterPassed', 'elapsed_ns': 29},
            'measurements': [{'position': position, 'kernel': cost.KERNELS[(position + sample) % 2],
                              'elapsed_ns': 500 if (position + sample) % 2 == 0 else 1500,
                              'actual_result': 'Transcript',
                              'probe': cost.expected_progress(challenge)} for position in range(2)]}


@lru_cache(maxsize=1)
def template():
    return {'schema': cost.SCHEMA, 'profile': cost.PROFILE,
            'construction': 'public-inputs-zero-product-claim-fake-trace',
            'valid_proof_preacquired': False, 'attempt_limit': cost.LIMIT,
            'samples_per_group': cost.SAMPLES, 'kernels': list(cost.KERNELS),
            'metadata': {'arch': 'x86_64', 'os': 'linux', 'pointer_bits': 64, 'process_id': 1234,
                         'debug_assertions': False, 'clock': 'std::time::Instant-wall-nanoseconds',
                         'identity_scope': 'external-source-binary-resource-receipt-required'},
            'samples': [row_fixture(c, t, s) for c in cost.CLASSES for t in cost.TARGETS for s in range(cost.SAMPLES)],
            **{flag: False for flag in cost.FLAGS}}


def fixture():
    return copy.deepcopy(template())


class FreshRejectionReaderTests(unittest.TestCase):
    def test_real_fifo_cli_refuses_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.fifo'
            os.mkfifo(path)
            completed = subprocess.run(
                [sys.executable, '-B', str(Path(cost.__file__)), str(path),
                 '--raw-sha256', '00' * 32],
                capture_output=True, text=True, timeout=3)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, '')
            self.assertIn('nonregular', completed.stderr)

    def test_raw_ancestor_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / 'actual'
            actual.mkdir()
            data = b'{}'
            (actual / 'raw.json').write_bytes(data)
            alias = root / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                cost.load_raw(alias / 'raw.json', cost.digest(data))

    def test_raw_descriptor_limit_and_regular_file_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'raw.json'
            data = b'{}' + b' ' * 6
            path.write_bytes(data)
            with patch.object(cost, 'RAW_LIMIT', 8):
                self.assertEqual(cost.load_raw(path, cost.digest(data)), {})
                path.write_bytes(data + b' ')
                with self.assertRaisesRegex(ValueError, 'oversize'):
                    cost.load_raw(path, cost.digest(data + b' '))
                with self.assertRaisesRegex(ValueError, 'nonregular'):
                    cost.load_raw(Path(directory), cost.digest(data))

    def reject(self, mutation):
        value = fixture()
        mutation(value)
        with self.assertRaises(ValueError):
            cost.summarize(value)

    def test_complete_real_relation_replay_with_explicitly_synthetic_clocks(self):
        result = cost.summarize(fixture())
        self.assertEqual(result['samples'], 64)
        self.assertEqual(result['independent_relation_replays'], 64)
        self.assertTrue(result['complete_campaign'])
        self.assertGreater(result['all_search_attempts'], 64)
        self.assertFalse(result['native_source_binary_resource_authenticated'])
        self.assertIsNone(result['all_legal_strategy_cost_bound'])
        for group in result['groups']:
            self.assertEqual(group['constructed'], 8)
            self.assertEqual(group['exhausted'], 0)
            self.assertEqual(group['receiver_wall_ns']['production-full-limb'], 4000)
            self.assertEqual(group['receiver_wall_ns']['scalar-reference'], 12000)
            self.assertEqual(group['all_acquisition_wall_ns'], 8 * 87 + 8 * group['all_search_attempts'])
            self.assertEqual(group['receiver_to_all_acquisition_ratio']['production-full-limb'],
                             cost.ratio(4000, group['all_acquisition_wall_ns']))

    def test_no_honest_product_or_proof_acquisition_flag(self):
        self.reject(lambda r: r.update(valid_proof_preacquired=True))
        self.reject(lambda r: r.update(construction='prepared-task-full-transcript'))

    def test_old_diagnostic_cannot_be_relabelled(self):
        self.reject(lambda r: r.update(schema='pon-work-rejection-cost-v2'))

    def test_true_or_numeric_qualification_flags_refused(self):
        for flag in cost.FLAGS:
            for invalid in (True, 0, None, 'false'):
                with self.subTest(flag=flag, invalid=invalid):
                    self.reject(lambda r: r.update({flag: invalid}))

    def test_fixed_sample_denominator_and_order(self):
        self.reject(lambda r: r['samples'].pop())
        self.reject(lambda r: r['samples'].reverse())
        self.reject(lambda r: r.update(samples_per_group=1))

    def test_unknown_fields_do_not_supply_authority(self):
        self.reject(lambda r: r.update(proven=True))
        self.reject(lambda r: r['samples'][0].update(acquisition_waived=True))

    def test_class_target_task_and_challenge_are_bound(self):
        for name, value in [('class', 'zero'), ('target', 'ff' * 32), ('task', '00' * 32), ('challenge', '00' * 32)]:
            with self.subTest(name=name):
                self.reject(lambda r: r['samples'][0].update({name: value}))

    def test_nonzero_or_computed_product_claim_is_refused(self):
        def mutate(raw):
            row = raw['samples'][0]
            prefix = bytearray(cost.material(row['class'])[2])
            prefix[-4:] = (1).to_bytes(4, 'little')
            row['prefix_sha256'] = cost.digest(prefix)
            row['proof']['sha256'] = cost.digest(prefix + bytes.fromhex(row['search']['attempts'][-1]['trace']))
        self.reject(mutate)

    def test_deleted_failed_trials_cannot_be_omitted_or_reindexed(self):
        def mutate(raw):
            row = next(r for r in raw['samples'] if len(r['search']['attempts']) > 1)
            row['search']['attempts'].pop(0)
        self.reject(mutate)
        def reindex(raw):
            mutate(raw)
            row = next(r for r in raw['samples'] if r['search']['attempts'][0]['nonce'] != 0)
            for i, attempt in enumerate(row['search']['attempts']):
                attempt['nonce'] = i
        self.reject(reindex)

    def test_post_success_search_and_false_selection_are_refused(self):
        self.reject(lambda r: r['samples'][0]['search']['attempts'].append(copy.deepcopy(r['samples'][0]['search']['attempts'][-1])))
        self.reject(lambda r: r['samples'][0]['search']['attempts'][-1].update(selected=False))
        self.reject(lambda r: r['samples'][0]['search']['attempts'][-1].update(selected=1))

    def test_hash_trial_and_proof_identity_are_recomputed(self):
        self.reject(lambda r: r['samples'][0]['search']['attempts'][0].update(trace='00' * 32))
        self.reject(lambda r: r['samples'][0]['search']['attempts'][0].update(ticket='00' * 32))
        self.reject(lambda r: r['samples'][0]['proof'].update(sha256='00' * 32))
        self.reject(lambda r: r['samples'][0]['proof'].update(bytes=cost.PROOF_BYTES - 1))

    def test_setup_search_encoding_and_overhead_cannot_be_subtracted(self):
        self.reject(lambda r: r['samples'][0]['setup'].pop('material_ns'))
        self.reject(lambda r: r['samples'][0]['search'].update(trace_ns=0))
        self.reject(lambda r: r['samples'][0]['acquisition'].update(accounted_ns=7))
        self.reject(lambda r: r['samples'][0]['acquisition'].update(overhead_ns=-1))
        self.reject(lambda r: r['samples'][0]['proof'].update(encoding_ns=0))

    def test_numeric_aliases_and_zero_denominator_are_refused(self):
        for field, invalid in [('wall_ns', 0), ('wall_ns', True), ('wall_ns', 1.0), ('wall_ns', '1')]:
            with self.subTest(invalid=invalid):
                self.reject(lambda r: r['samples'][0]['acquisition'].update({field: invalid}))
        self.reject(lambda r: r['samples'][0].update(sample=False))
        self.reject(lambda r: r['samples'][0]['measurements'][0].update(elapsed_ns=0))

    def test_target_product_acceptance_and_generic_errors_are_not_transcript_rejection(self):
        for invalid in ('Target', 'Product', 'Accepted', 'Error', True):
            with self.subTest(invalid=invalid):
                self.reject(lambda r: r['samples'][0]['measurements'][0].update(actual_result=invalid))
        self.reject(lambda r: r['samples'][0]['precheck'].update(actual_result='Target'))

    def test_both_kernels_and_balanced_receiver_order_are_required(self):
        self.reject(lambda r: r['samples'][0]['measurements'].pop())
        self.reject(lambda r: r['samples'][0]['measurements'].reverse())
        self.reject(lambda r: r['samples'][0]['measurements'][0].update(kernel='scalar-reference'))

    def test_complete_progress_sequence_and_no_product_or_capability(self):
        for field, value in [('transcript_tiles', 511), ('before_product', 1),
                             ('before_verified_work', 1), ('timed', True),
                             ('sequence_sha256', '00' * 32), ('before_replay', True)]:
            with self.subTest(field=field):
                self.reject(lambda r: r['samples'][0]['measurements'][0]['probe'].update({field: value}))

    def test_matching_actual_transcript_cannot_be_assumed_invalid(self):
        raw = fixture()
        trace = bytes.fromhex(raw['samples'][0]['search']['attempts'][-1]['trace'])
        with patch.object(cost, 'independent_trace', return_value=trace):
            with self.assertRaisesRegex(ValueError, 'independently establish Transcript'):
                cost.summarize(raw)

    def test_early_exhaustion_and_fabricated_receiver_results_are_refused(self):
        self.reject(lambda r: r['samples'][0]['search'].update(outcome='search-exhausted'))
        self.reject(lambda r: r['samples'][0]['search']['attempts'].clear())
        self.reject(lambda r: r['samples'][0]['search'].update(attempt_limit=1))

    def test_full_exhaustion_preserves_entire_acquisition_cost(self):
        row = row_fixture('dense', cost.TARGETS[0], 0)
        challenge = bytes.fromhex(row['challenge'])
        # Explicit synthetic branch control: all 4096 scheduled guesses are this
        # actual nonwinning ticket. This is not a native/campaign observation.
        nonce = 0
        while True:
            trace = cost.h(b'synthetic-exhaustion-fixture', nonce.to_bytes(8, 'little'))
            ticket = cost.h(b'ticket', challenge, trace)
            if ticket.hex() > row['target']:
                break
            nonce += 1
        row['search'].update(outcome='search-exhausted', trace_ns=3 * cost.LIMIT,
                             ticket_ns=5 * cost.LIMIT, wall_ns=8 * cost.LIMIT + 11,
                             attempts=[{'nonce': i, 'trace': trace.hex(), 'ticket': ticket.hex(),
                                        'selected': False, 'trace_ns': 3, 'ticket_ns': 5} for i in range(cost.LIMIT)])
        row['proof'] = row['precheck'] = None; row['measurements'] = []
        row['acquisition'].update(accounted_ns=65 + row['search']['wall_ns'],
                                  wall_ns=69 + row['search']['wall_ns'])
        with patch.object(cost, 'trace_for', return_value=trace):
            self.assertFalse(cost.validate_row(row, 'dense', cost.TARGETS[0], 0))
            row['search']['attempts'].pop()
            with self.assertRaises(ValueError):
                cost.validate_row(row, 'dense', cost.TARGETS[0], 0)

    def test_debug_costs_and_self_attested_execution_identity_are_refused(self):
        self.reject(lambda r: r['metadata'].update(debug_assertions=True))
        self.reject(lambda r: r['metadata'].update(identity_scope='verified'))
        self.reject(lambda r: r['metadata'].update(source_commit=cost.REFERENCE_COMMIT))

    def test_missing_or_changed_reference_bytes_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cost, 'ROOT', Path(directory)):
                with self.assertRaisesRegex(ValueError, 'independent reference'):
                    cost.summarize(fixture())

    def test_strict_json_digest_duplicates_nonfinite_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'raw.json'
            for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    cost.load_raw(path, cost.digest(data))
            path.write_bytes(b'{}')
            with self.assertRaises(ValueError):
                cost.load_raw(path, '00' * 32)
            alias = Path(directory) / 'alias.json'; alias.symlink_to(path)
            with self.assertRaises(ValueError):
                cost.load_raw(alias, cost.digest(path.read_bytes()))

    def test_cli_replays_caller_pinned_bytes_without_granting_execution_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic-clock-fixture.json'
            data = json.dumps(fixture()).encode(); path.write_bytes(data)
            result = subprocess.run([sys.executable, '-B', str(Path(cost.__file__)), str(path),
                                     '--raw-sha256', cost.digest(data)], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['raw_sha256'], cost.digest(data))
            self.assertFalse(report['native_source_binary_resource_authenticated'])


if __name__ == '__main__':
    unittest.main()
