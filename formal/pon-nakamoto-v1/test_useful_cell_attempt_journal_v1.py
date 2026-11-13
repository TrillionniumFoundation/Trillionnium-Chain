"""Negative controls for retained attempts; genuine W1 math, synthetic test clocks.

These controls do not mock a successful verifier. Their tiny chosen matrices
and caller-retained plan are diagnostic fixtures, not a trained Hepta run.
"""
from __future__ import annotations

import copy
from argparse import Namespace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from contract_wire import H, canonical, u64
from useful_cell_attempt_journal_v1 import AttemptJournal, inspect_acknowledged_journal, inspect_journal
import work_oracle as work


class AttemptJournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.materials, cls.operands = {}, {}
        cls.plan = {'schema': 'useful-cell-reference-search-plan-v1',
                    'kind': 'plan', 'relation': 'pon-useful-cell-int257-v1',
                    'contract_id': '11' * 32, 'before_state_sha256': '22' * 32,
                    'target': 'ff' * 32, 'batch_size': 2, 'max_attempts_per_tile': 8,
                    'tiles': []}
        for index in range(5):
            a, b = [0] * work.CELLS, [0] * work.CELLS
            a[index], b[index * work.N] = 1 + index, 3 - index
            b = [v % work.Q for v in b]
            material = work.field_bytes(a) + work.field_bytes(b)
            cls.materials[index], cls.operands[index] = material, (a, b)
            cls.plan['tiles'].append({'index': index, 'task': work.task_id(a, b).hex(),
                                      'material_sha256': hashlib.sha256(material).hexdigest()})
        cls.events = [cls.plan]
        for index in range(5):
            challenge = cls.challenge(cls.plan, index, 0)
            proof = work.prove(challenge, *cls.operands[index])
            context = {'tile': index, 'nonce': 0, 'challenge': challenge.hex()}
            cls.events.extend([
                {'kind': 'attempt-start', **context},
                {'kind': 'attempt-complete', **context, 'trace': proof[-32:].hex(),
                 'proof_sha256': hashlib.sha256(proof).hexdigest(),
                 'ticket': H('ticket', challenge, proof[-32:]).hex(), 'hit': True,
                 'wall_ns': 17, 'process_cpu_ns': 11},
            ])
        cls.events.append({'kind': 'end', 'status': 'complete',
                           'witness_sha256': '33' * 32, 'output_sha256': '44' * 32,
                           'after_state_sha256': cls.plan['before_state_sha256']})

    @staticmethod
    def challenge(plan, index, nonce):
        return H('useful-cell-int257-v1/challenge', bytes.fromhex(plan['contract_id']),
                 bytes.fromhex(plan['before_state_sha256']), bytes.fromhex(plan['tiles'][index]['task']),
                 u64(index), u64(nonce))

    @staticmethod
    def encode(events):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'search.jsonl'
            with AttemptJournal(path) as journal:
                for event in events:
                    journal.append(event)
            return path.read_bytes()

    def inspect(self, events=None, *, raw=None, plan=None, replay=False, endpoint=None):
        return inspect_journal(self.encode(self.events if events is None else events) if raw is None else raw,
                               expected_plan=self.plan if plan is None else plan,
                               materials=self.materials if replay else None,
                               expected_final_sha256=endpoint)

    def test_every_real_completed_attempt_replays_without_claiming_cell_acceptance(self):
        report = self.inspect(replay=True)
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['planned_tiles'], 5)
        self.assertEqual(report['planned_application_requests'], 2)
        self.assertEqual(report['counts']['started_attempts'], 5)
        self.assertEqual(report['counts']['completed_attempts'], 5)
        self.assertEqual(report['mathematical_attempts_replayed'], 5)
        self.assertEqual(report['verified_complete_cell_outputs'], 0)
        self.assertFalse(report['complete_cell_relation_verified'])
        self.assertFalse(report['invalid_input_rejection_measured'])
        self.assertFalse(report['production_qualified'])

    def test_structural_check_cannot_claim_arithmetic_replay(self):
        report = self.inspect()
        self.assertFalse(report['full_arithmetic_replay'])
        self.assertEqual(report['mathematical_attempts_replayed'], 0)

    def test_real_exhaustion_retains_miss_and_four_not_run_tiles(self):
        events = copy.deepcopy(self.events[:3])
        ticket = int(events[2]['ticket'], 16)
        self.assertGreater(ticket, 1)
        events[0]['target'] = (ticket - 1).to_bytes(32, 'big').hex()
        events[0]['max_attempts_per_tile'] = 1
        events[2]['hit'] = False
        events.append({'kind': 'end', 'status': 'failed',
                       'error_type': 'ValueError', 'error': 'SEARCH_EXHAUSTED'})
        report = self.inspect(events, plan=events[0], replay=True)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['counts']['misses'], 1)
        self.assertEqual(report['tiles'][0]['status'], 'search-exhausted')
        self.assertEqual(report['not_run_tiles'], 4)
        self.assertEqual(report['producer_reported_complete_outputs'], 0)
        self.assertEqual(report['mathematical_attempts_replayed'], 1)

    def test_attempt_error_keeps_spent_time_and_denominator(self):
        events = copy.deepcopy(self.events[:2])
        events.append(dict(self.events[1], kind='attempt-error', wall_ns=101,
                           process_cpu_ns=61, error_type='ArithmeticError', error='failed'))
        events.append({'kind': 'end', 'status': 'failed', 'error_type': 'ArithmeticError', 'error': 'failed'})
        report = self.inspect(events)
        self.assertEqual(report['counts']['failed_attempts'], 1)
        self.assertEqual(report['counts']['recorded_process_cpu_ns'], 61)
        self.assertEqual(report['counts']['completed_attempts'], 0)
        self.assertEqual(report['not_run_tiles'], 4)

    def test_crash_after_durable_start_is_unknown_not_unspent(self):
        report = self.inspect(self.events[:2])
        self.assertEqual(report['status'], 'incomplete')
        self.assertEqual(report['counts']['unknown_attempts'], 1)
        self.assertEqual(report['tiles'][0]['status'], 'outcome-unknown')
        self.assertEqual(report['not_run_tiles'], 4)
        self.assertTrue(report['unrecorded_partial_work_possible'])

    def test_absent_search_still_preserves_the_full_planned_denominator(self):
        report = self.inspect(raw=b'')
        self.assertEqual(report['status'], 'not-started')
        self.assertEqual(report['planned_tiles'], 5)
        self.assertEqual(report['not_run_tiles'], 5)
        self.assertEqual(report['planned_application_requests'], 2)

    def test_truncated_tail_is_visible_and_never_complete(self):
        raw = self.encode(self.events)
        for value in (raw[:-1], raw[:-37], raw + b'{"sequence":12'):
            with self.subTest(tail=value[-40:]):
                report = self.inspect(raw=value)
                self.assertNotEqual(report['status'], 'complete')
                self.assertGreater(report['truncated_tail_bytes'], 0)
                self.assertEqual(report['producer_reported_complete_outputs'], 0)

    def test_external_endpoint_refuses_a_truncated_or_rewritten_suffix(self):
        raw = self.encode(self.events)
        endpoint = self.inspect(raw=raw)['last_entry_sha256']
        self.assertEqual(self.inspect(raw=raw, endpoint=endpoint)['status'], 'complete')
        with self.assertRaisesRegex(ValueError, 'RETAINED_ENDPOINT'):
            self.inspect(raw=self.encode(self.events[:-1]), endpoint=endpoint)

    def test_delete_duplicate_or_reorder_records_cannot_keep_success(self):
        for events in (self.events[:1] + self.events[2:], self.events[:-2] + self.events[-1:],
                       self.events[:3] + self.events[1:3] + self.events[3:],
                       self.events[:1] + [self.events[2], self.events[1]] + self.events[3:]):
            with self.subTest(events=len(events)), self.assertRaises(ValueError):
                self.inspect(events)

    def test_same_nonce_after_first_hit_and_skipped_nonces_are_refused(self):
        events = copy.deepcopy(self.events)
        events[3]['tile'] = 0
        with self.assertRaises(ValueError):
            self.inspect(events)
        events = copy.deepcopy(self.events)
        events[1]['nonce'] = 1
        with self.assertRaises(ValueError):
            self.inspect(events)

    def test_false_trace_with_a_matching_ticket_still_requires_full_arithmetic(self):
        events = copy.deepcopy(self.events)
        events[2]['trace'] = 'ab' * 32
        events[2]['ticket'] = H('ticket', bytes.fromhex(events[2]['challenge']),
                                bytes.fromhex(events[2]['trace'])).hex()
        self.assertEqual(self.inspect(events)['status'], 'complete')
        with self.assertRaisesRegex(ValueError, 'FULL_ARITHMETIC_REPLAY'):
            self.inspect(events, replay=True)

    def test_wrong_material_or_external_context_cannot_relabel_math(self):
        events = copy.deepcopy(self.events)
        events[0]['contract_id'] = 'cc' * 32
        with self.assertRaisesRegex(ValueError, 'EXPECTED_PLAN'):
            self.inspect(events)
        materials = dict(self.materials, **{})
        materials[0] = self.materials[1]
        with self.assertRaisesRegex(ValueError, 'MATERIAL_BYTES'):
            inspect_journal(self.encode(self.events), expected_plan=self.plan, materials=materials)

    def test_plan_cannot_shrink_tiles_or_use_boolean_numbers(self):
        for mutate in (lambda x: x['tiles'].pop(), lambda x: x.update(batch_size=True),
                       lambda x: x.update(max_attempts_per_tile=0)):
            plan = copy.deepcopy(self.plan)
            mutate(plan)
            with self.assertRaises(ValueError):
                self.inspect(plan=plan)

    def test_unknown_fields_boolean_clocks_and_false_endings_are_refused(self):
        for field, value in (('process_cpu_ns', True), ('wall_ns', -1),
                             ('wall_ns', '17'), ('trusted', True)):
            events = copy.deepcopy(self.events)
            events[2][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.inspect(events)
        with self.assertRaisesRegex(ValueError, 'INCOMPLETE_SUCCESS'):
            self.inspect(self.events[:3] + [self.events[-1]])

    def test_append_fsync_failure_poisoning_propagates_and_forbids_more_records(self):
        with tempfile.TemporaryDirectory() as directory:
            with AttemptJournal(Path(directory) / 'journal.jsonl') as journal:
                with patch('useful_cell_attempt_journal_v1.os.fsync', side_effect=OSError('disk unavailable')):
                    with self.assertRaisesRegex(OSError, 'disk unavailable'):
                        journal.append(self.plan)
                self.assertTrue(journal.poisoned)
                with self.assertRaisesRegex(ValueError, 'SINK_UNAVAILABLE'):
                    journal.append(self.events[1])

    def test_existing_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'journal.jsonl'
            path.write_bytes(b'failed original')
            with self.assertRaises(FileExistsError):
                AttemptJournal(path)
            self.assertEqual(path.read_bytes(), b'failed original')

    def test_driver_loading_failure_keeps_original_requested_batch_and_tiles(self):
        from experiments import useful_cell_relation_v1 as driver

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            output = path / 'observation'
            args = Namespace(out=str(output), deadline_ms=None, target='7f' + 'ff' * 31,
                             max_attempts=64, batch_size=64, offset=0,
                             model_dir=str(path / 'unavailable-model'), bundle_hash='00' * 32)
            with self.assertRaises(FileNotFoundError):
                driver.run(args)
            failed = json.loads((output / 'failure.json').read_bytes())
            self.assertEqual(failed['planned_tiles'], 5)
            self.assertEqual(failed['not_run_tiles'], 5)
            self.assertEqual(failed['requested_batch_size'], 64)
            self.assertEqual(failed['fully_completed_trial_outputs'], 0)
            self.assertEqual(failed['search_status'], 'not-started')
            self.assertTrue((output / 'attempt.json').is_file())

    def test_driver_final_fsync_failure_has_no_nested_completed_outputs(self):
        from experiments import useful_cell_relation_v1 as driver

        original_append = AttemptJournal.append

        def fail_final(journal, event):
            if event['kind'] == 'end':
                with patch('useful_cell_attempt_journal_v1.os.fsync', side_effect=OSError('final fsync failure')):
                    original_append(journal, event)
            else:
                original_append(journal, event)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'observation'
            args = Namespace(out=str(output), deadline_ms=None, target='ff' * 32,
                             max_attempts=1, batch_size=2, offset=0,
                             model_dir=str(driver.cell.DEFAULT_MATERIAL), bundle_hash=driver.cell.DEFAULT_BUNDLE,
                             cell_id='11' * 32, generation=0, state_root='22' * 32,
                             consumer='research/fsync-failure-control', request_id='44' * 32)
            with patch.object(AttemptJournal, 'append', fail_final):
                with self.assertRaisesRegex(OSError, 'final fsync failure'):
                    driver.run(args)
            failed = json.loads((output / 'failure.json').read_bytes())
            self.assertEqual(failed['fully_completed_trial_outputs'], 0)
            self.assertEqual(failed['search']['completed_producer_batches'], 0)
            self.assertEqual(failed['search']['producer_reported_complete_outputs'], 0)
            self.assertGreater(failed['search']['unacknowledged_suffix_bytes'], 0)
            self.assertFalse((output / 'witness.json').exists())
            self.assertTrue(failed['search_acknowledgement']['sink_failed'])

    def test_acknowledgement_cannot_claim_unwritten_or_partial_prefix(self):
        raw = self.encode(self.events)
        for size, count, head in ((len(raw) + 1, len(self.events), '11' * 32),
                                  (len(raw) - 1, len(self.events), '11' * 32),
                                  (0, 1, '00' * 32)):
            acknowledgement = {'schema': 'useful-cell-reference-search-journal-v1/acknowledgement',
                               'bytes': size, 'entries': count, 'head': head, 'sink_failed': False}
            with self.subTest(size=size), self.assertRaises(ValueError):
                inspect_acknowledged_journal(raw, expected_plan=self.plan, acknowledgement=acknowledgement)

    def test_loaded_diagnostics_cannot_be_relabelled_after_disk_source_changes(self):
        from experiments import useful_cell_relation_v1 as driver

        for relative in ('formal/pon-nakamoto-v1/experiments/useful_cell_relation_v1.py',
                         'formal/pon-nakamoto-v1/useful_cell_attempt_journal_v1.py'):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as directory:
                isolated = Path(directory)
                paths = set(driver.relation.SOURCE_FILES) | {
                    str(path.relative_to(driver.ROOT)) for path in driver.DIAGNOSTIC_PATHS}
                for name in paths:
                    destination = isolated / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(driver.ROOT / name, destination)
                env = dict(os.environ, PYTHONPATH=str(isolated / 'formal/pon-nakamoto-v1'),
                           PYTHONDONTWRITEBYTECODE='1')
                code = '''from pathlib import Path
import sys
from experiments import useful_cell_relation_v1 as driver
before = driver.diagnostic_identity()
path = Path(sys.argv[1])
path.write_bytes(path.read_bytes() + b"\\n")
try:
    driver.diagnostic_identity()
except ValueError as error:
    assert str(error) == "DIAGNOSTIC_SOURCE_CHANGED_RESTART_REQUIRED", str(error)
else:
    raise AssertionError("changed measurement source was silently relabelled")
'''
                result = subprocess.run([sys.executable, '-B', '-c', code, relative],
                                        cwd=isolated, env=env, capture_output=True, timeout=30, check=False)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
