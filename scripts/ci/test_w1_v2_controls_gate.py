#!/usr/bin/env python3
"""Replay real saved observations and mutate their evidence; never run a prover."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import w1_v2_controls_gate as gate
import w1_stage_measure as stage


ROOT = Path(__file__).resolve().parents[2]
PROOF = ROOT / 'evidence/pon-w1-full-v2-20261105'
RECORDED_OUT = Path('/workspace/shared/w1-run/controls-3-repaired')
RECORDED_VERIFIER = Path('/workspace/shared/w1-run/pinned-bin/w1-verify-v2')
VERIFIER_SHA256 = '9c3e3f321a24e1acb66638058fd77f67906824593422692f9e296e70a688fe65'
ARCHIVE_SHA256 = '0bdc390cd790f9e6493690db22658f12f40f4eb086c0499ba490623e8c16b1b1'
CURRENT_ARCHIVE = ROOT / 'evidence/seven-gates-followup-20261108/research-ci-fix/transparent-bb-controls.tar.xz'
CURRENT_ARCHIVE_SHA256 = 'e5f2e58908889961a0198a273ea2c5aab0a70c679ea46c5b06d92a0012fab028'


class V2ControlsGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.seed.cleanup)
        raw = (PROOF / 'controls-3-repaired.tar.xz').read_bytes()
        if hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
            raise ValueError('the original saved observation fixture changed')
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
            archive.extractall(cls.seed.name, filter='data')
        cls.original = Path(cls.seed.name) / 'controls-3-repaired'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / 'observations'
        shutil.copytree(self.original, self.out)
        self.report = gate.read_json(self.out / 'result.json')

    def write_json(self, path, value):
        path.write_text(json.dumps(value))

    def save(self, index=None, *, process=True):
        self.write_json(self.out / 'result.json', self.report)
        if index is not None:
            row = self.report['controls'][index]
            directory = self.out / row['case_directory']
            self.write_json(directory / 'result.json', row)
            if process:
                self.write_json(directory / 'process/result.json', row['process'])

    def validate(self):
        # These explicit original paths and the retained hash replay evidence
        # consistency. No historical executable is invoked or authenticated.
        return gate.validate(self.out, PROOF, verifier_path=RECORDED_VERIFIER,
                             verifier_sha256=VERIFIER_SHA256, recorded_out=RECORDED_OUT)

    def test_real_saved_controls_pass(self):
        self.assertEqual(self.report, gate.read_json(PROOF / 'controls-result.json'))
        result = self.validate()
        self.assertEqual((result['positive_controls_passed'], result['negative_controls_passed']), (1, 57))

    def test_negative_process_acceptance_is_rejected(self):
        self.report['controls'][1]['process']['returncode'] = 0
        self.save(1)
        with self.assertRaisesRegex(ValueError, 'process observation differs: returncode'):
            self.validate()

    def test_positive_process_rejection_is_rejected(self):
        self.report['controls'][0]['process']['returncode'] = 1
        self.save(0)
        with self.assertRaisesRegex(ValueError, 'process observation differs: returncode'):
            self.validate()

    def test_nested_timeout_is_rejected(self):
        self.report['controls'][0]['process']['timed_out'] = True
        self.save(0)
        with self.assertRaisesRegex(ValueError, 'process observation differs: timed_out'):
            self.validate()

    def test_truncated_output_scans_are_rejected(self):
        for key in ('stdout_scan_truncated', 'stderr_scan_truncated'):
            with self.subTest(key=key):
                self.report['controls'][1][key] = True
                self.save(1)
                with self.assertRaisesRegex(ValueError, f'control observation differs: {key}'):
                    self.validate()
                self.report['controls'][1][key] = False

    def test_incomplete_session_observation_is_rejected(self):
        self.report['controls'][0]['process']['owned_session_observation_complete'] = False
        self.save(0)
        with self.assertRaisesRegex(ValueError, 'process observation differs: owned_session_observation_complete'):
            self.validate()

    def test_process_scan_errors_are_rejected(self):
        self.report['controls'][0]['process']['proc_scan_errors'] = [{'error': 'fixture'}]
        self.save(0)
        with self.assertRaisesRegex(ValueError, 'process observation differs: proc_scan_errors'):
            self.validate()

    def test_unsettled_owned_groups_are_rejected(self):
        self.report['controls'][0]['process']['final_known_group_probes'][0]['state'] = 'PRESENT'
        self.save(0)
        with self.assertRaisesRegex(ValueError, 'owned process groups were not all observed absent'):
            self.validate()

    def test_process_pid_must_belong_to_observed_groups(self):
        original = copy.deepcopy(self.report)
        for pid in (False, 0, -1, None, 1000000):
            with self.subTest(pid=pid):
                self.report = copy.deepcopy(original)
                self.report['controls'][0]['process']['pid'] = pid
                self.save(0)
                with self.assertRaisesRegex(ValueError, 'owned process groups were not all observed absent'):
                    self.validate()
        self.report = copy.deepcopy(original)
        self.report['controls'][0]['process'].update(
            pid=1, known_owned_groups=[1], final_known_group_probes=[{'group': True, 'state': 'ABSENT'}])
        self.save(0)
        with self.assertRaisesRegex(ValueError, 'owned process groups were not all observed absent'):
            self.validate()

    def test_case_command_must_use_pinned_verifier(self):
        self.report['controls'][1]['process']['command'][0] = '/tmp/unrelated-verifier'
        self.save(1)
        with self.assertRaisesRegex(ValueError, 'case command differs from pinned verifier and inputs'):
            self.validate()

    def test_case_command_must_use_planned_inputs(self):
        self.report['controls'][1]['process']['command'][1] = str(RECORDED_OUT / 'original/receipt.bin')
        self.save(1)
        with self.assertRaisesRegex(ValueError, 'case command differs from pinned verifier and inputs'):
            self.validate()

    def test_mutation_identity_must_match_planned_bytes(self):
        path = self.out / self.report['controls'][1]['case_directory'] / 'mutation.json'
        mutation = gate.read_json(path)
        mutation['assets']['receipt']['sha256'] = '0' * 64
        self.write_json(path, mutation)
        with self.assertRaisesRegex(ValueError, 'case mutation identity differs from planned inputs'):
            self.validate()

    def test_saved_inputs_must_match_planned_bytes(self):
        path = self.out / self.report['controls'][1]['case_directory'] / 'receipt.bin'
        path.write_bytes((PROOF / 'succinct.bin').read_bytes())
        with self.assertRaisesRegex(ValueError, 'case input differs from planned mutation'):
            self.validate()

    def test_retained_process_must_match_summary(self):
        self.report['controls'][0]['process']['finished_unix_ns'] += 1
        self.save(0, process=False)
        with self.assertRaisesRegex(ValueError, 'retained process result differs from aggregate observation'):
            self.validate()

    def test_case_result_must_match_summary(self):
        self.report['controls'][0]['process']['finished_unix_ns'] += 1
        self.save()
        with self.assertRaisesRegex(ValueError, 'case result differs from aggregate observation'):
            self.validate()

    def test_output_hashes_must_match_saved_logs(self):
        path = self.out / self.report['controls'][1]['case_directory'] / 'process/stderr.log'
        path.write_bytes(path.read_bytes() + b'unrecorded output\n')
        with self.assertRaisesRegex(ValueError, 'process output identity differs: stderr_sha256'):
            self.validate()

    def test_rejection_layer_must_match_saved_stderr(self):
        row = self.report['controls'][57]
        path = self.out / row['case_directory'] / 'process/stderr.log'
        data = path.read_bytes().replace(b'W1_V2_CRYPTO_REJECT', b'W1_V2_PUBLIC_REJECT')
        path.write_bytes(data)
        row['process']['stderr_sha256'] = gate.controls.digest(data)
        row['observed_rejection_layers'] = ['public']
        self.save(57)
        with self.assertRaisesRegex(ValueError, 'wrong rejection layer'):
            self.validate()

    def test_required_rejection_text_must_be_present(self):
        index, row = next((index, row) for index, row in enumerate(self.report['controls'])
                          if row.get('required_error_text'))
        path = self.out / row['case_directory'] / 'process/stderr.log'
        data = path.read_bytes().replace(row['required_error_text'].encode(), b'changed error text')
        path.write_bytes(data)
        row['process']['stderr_sha256'] = gate.controls.digest(data)
        self.save(index)
        with self.assertRaisesRegex(ValueError, 'required rejection text is absent'):
            self.validate()

    def test_positive_stdout_must_match_summary(self):
        self.report['positive_report']['decode_and_verify_ns'][0] += 1
        self.save()
        with self.assertRaisesRegex(ValueError, 'positive stdout differs from aggregate report'):
            self.validate()

    def test_original_control_order_and_count_are_required(self):
        original = copy.deepcopy(self.report)
        self.report['controls'].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, 'all 58 original controls are required'):
            self.validate()
        self.report = original
        self.report['controls'][1], self.report['controls'][2] = self.report['controls'][2], self.report['controls'][1]
        self.save()
        with self.assertRaisesRegex(ValueError, 'original ordered control or expectation'):
            self.validate()

    def test_verifier_hash_must_match_pinned_identity(self):
        with self.assertRaisesRegex(ValueError, 'v2 controls summary differs: verifier_sha256'):
            gate.validate(self.out, PROOF, verifier_path=RECORDED_VERIFIER,
                          verifier_sha256='0' * 64, recorded_out=RECORDED_OUT)

    def test_integer_exit_codes_cannot_be_booleans(self):
        self.report['controls'][1]['process']['returncode'] = True
        self.save(1)
        with self.assertRaisesRegex(ValueError, 'process observation differs: returncode'):
            self.validate()

    def test_budget_and_qualification_cannot_be_widened(self):
        for key, value in (('total_wall_budget_seconds', 121), ('quantum_security_qualified', True)):
            with self.subTest(key=key):
                original = self.report[key]
                self.report[key] = value
                self.save()
                with self.assertRaisesRegex(ValueError, f'v2 controls summary differs: {key}'):
                    self.validate()
                self.report[key] = original


    def current_process(self, exit_code=0):
        # This is an actual small process lifecycle control, not proof evidence.
        out = Path(self.temp.name) / f'current-process-{exit_code}'
        return stage.measure([sys.executable, '-I', '-S', '-c',
                              f'raise SystemExit({exit_code})'], out, 120)

    def test_current_stage_measurements_pass_without_proof_claim(self):
        for code in (0, 7):
            with self.subTest(code=code):
                process = self.current_process(code)
                self.assertEqual(process['schema'], gate.CURRENT_STAGE_SCHEMA)
                self.assertFalse(process['complete_proof_claim'])
                self.assertFalse(process['prover_resource_completeness_established'])
                gate.validate_process_observation(process, code)

    def test_current_gate_rejects_legacy_without_explicit_replay(self):
        # Current admission explicitly selects v3; the existing default remains
        # the historical read-only API. Relocated v2 evidence needs its actual
        # recorded paths to match retained command and mutation identities.
        with self.assertRaisesRegex(ValueError, 'process observation differs: schema'):
            gate.validate(self.out, PROOF, verifier_path=RECORDED_VERIFIER,
                          verifier_sha256=VERIFIER_SHA256, recorded_out=RECORDED_OUT,
                          stage_schema=gate.CURRENT_STAGE_SCHEMA)
        with self.assertRaisesRegex(ValueError, 'case mutation identity differs from planned inputs'):
            gate.validate(self.out, PROOF, verifier_path=RECORDED_VERIFIER,
                          verifier_sha256=VERIFIER_SHA256,
                          stage_schema=gate.HISTORICAL_STAGE_SCHEMA)
        self.validate()

    def test_current_gate_rejects_unknown_process_schema(self):
        process = self.current_process()
        for value in (None, '', 'TRNM-W1-STAGE-MEASUREMENT4'):
            with self.subTest(schema=value):
                with self.assertRaisesRegex(ValueError, 'unsupported process observation version'):
                    gate.validate_process_observation(process, 0, stage_schema=value)
                with self.assertRaisesRegex(ValueError, 'process observation differs: schema'):
                    gate.validate_process_observation(dict(process, schema=value), 0)

    def test_current_stage_cancellation_fields_are_mandatory_and_exact(self):
        process = self.current_process()
        changes = {
            'cancellation_schema': 'unknown', 'result_is_pre_handoff_snapshot': False,
            'canceled_signal': 15, 'cancellation_event': {},
            'deadline_exhausted_at_snapshot': True,
        }
        for name, value in changes.items():
            for missing in (False, True):
                with self.subTest(field=name, missing=missing):
                    altered = dict(process)
                    if missing:
                        del altered[name]
                    else:
                        altered[name] = value
                    with self.assertRaisesRegex(ValueError, 'current process observation differs: ' + name):
                        gate.validate_process_observation(altered, 0)

    def test_current_stage_clock_cannot_extend_original_budget(self):
        process = self.current_process()
        for name in ('started_monotonic', 'wall_seconds', 'effective_deadline_monotonic',
                     'effective_remaining_seconds'):
            for value in (True, 0, -1, None, float('inf'), float('nan')):
                with self.subTest(field=name, value=value):
                    with self.assertRaisesRegex(ValueError, 'current process clock differs: ' + name):
                        gate.validate_process_observation(dict(process, **{name: value}), 0)
        for changes in (
                {'wall_seconds': process['effective_remaining_seconds']},
                {'effective_remaining_seconds': 121},
                {'effective_deadline_monotonic': process['effective_deadline_monotonic'] + 1},
                {'wall_limit_seconds': 121}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    gate.validate_process_observation(dict(process, **changes), 0)

    def test_current_stage_cannot_skip_common_settlement_controls(self):
        process = self.current_process()
        for changes in (
                {'returncode': True}, {'owned_session_observation_complete': False},
                {'proc_scan_errors': [{}]}, {'group_probe_errors': [{}]},
                {'cleanup_errors': [{}]}, {'members_after_child_exit': [{}]},
                {'final_owned_session_members': [{}]}, {'known_owned_groups': []},
                {'process_group_remaining_after_child_exit': True},
                {'final_known_group_probes': []}, {'complete_proof_claim': True}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    gate.validate_process_observation(dict(process, **changes), 0)

    def test_current_hosted_controls_bind_common_clock_and_summary_completion(self):
        # Replay the exact failed bb026697 hosted run; do not call it a new
        # verification or silently replace its original failed gate outcome.
        raw = CURRENT_ARCHIVE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), CURRENT_ARCHIVE_SHA256)
        current = Path(self.temp.name) / 'hosted'
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
            archive.extractall(current, filter='data')
        self.out = current / 'v2-controls'
        self.report = gate.read_json(self.out / 'result.json')
        original = copy.deepcopy(self.report)
        command = original['controls'][0]['process']['command']

        def validate_current():
            return gate.validate(self.out, PROOF, verifier_path=Path(command[0]),
                                 verifier_sha256=original['verifier_sha256'],
                                 recorded_out=Path(command[1]).parents[1],
                                 stage_schema=gate.CURRENT_STAGE_SCHEMA)

        self.assertEqual(validate_current()['completed_controls'], 58)
        for name in ('started_monotonic', 'deadline_monotonic'):
            for value in (None, True, 0, -1, float('inf'), float('nan')):
                with self.subTest(field=name, value=value):
                    self.report = copy.deepcopy(original)
                    self.report[name] = value
                    self.save()
                    with self.assertRaises(ValueError):
                        validate_current()
        for changes in (
                {'deadline_monotonic': original['deadline_monotonic'] + 1},
                {'started_monotonic': original['started_monotonic'] - 1},
                {'elapsed_wall_seconds': 0.000001}):
            with self.subTest(changes=changes):
                self.report = dict(copy.deepcopy(original), **changes)
                self.save()
                with self.assertRaises(ValueError):
                    validate_current()
        for changes in (
                {'schema': gate.HISTORICAL_STAGE_SCHEMA},
                {'canceled_signal': 15}, {'cancellation_event': {}},
                {'deadline_exhausted_at_snapshot': True}):
            with self.subTest(process_changes=changes):
                self.report = copy.deepcopy(original)
                self.report['controls'][0]['process'].update(changes)
                self.save(0)
                with self.assertRaises(ValueError):
                    validate_current()

    def test_cancellation_after_stage_snapshot_cannot_complete_the_controls(self):
        # /usr/bin/true supplies only a real exited process. It cannot verify
        # the receipt; cancellation must prevent even the positive parser from
        # running and must leave the whole control attempt incomplete.
        verifier = Path(shutil.which('true')).resolve(strict=True)
        out = Path(self.temp.name) / 'late-cancellation'
        original_write = stage.write_new
        sent = []

        def saved_then_cancel(path, value):
            original_write(path, value)
            if path.name == 'result.json' and path.parent.name == 'process':
                sent.append(path)
                os.kill(os.getpid(), signal.SIGTERM)

        with patch.object(stage, 'write_new', side_effect=saved_then_cancel), \
                contextlib.redirect_stdout(io.StringIO()):
            code = gate.controls.main([
                '--verifier', str(verifier), '--receipt', str(PROOF / 'succinct.bin'),
                '--header', str(PROOF / 'header.bin'), '--expected-artifacts',
                str(PROOF / 'expected-artifacts.bin'), '--out', str(out)])
        self.assertEqual(code, 1)
        self.assertEqual(len(sent), 1)
        snapshot = gate.read_json(sent[0])
        self.assertEqual(snapshot['returncode'], 0)
        self.assertTrue(snapshot['stage_process_complete'])
        self.assertTrue(snapshot['result_is_pre_handoff_snapshot'])
        self.assertFalse(snapshot['complete_proof_claim'])
        result = gate.read_json(out / 'result.json')
        self.assertFalse(result['all_controls_passed'])
        self.assertEqual(result['completed_controls'], 0)
        self.assertIsNone(result['positive_report'])
        self.assertIn('Canceled', result['error'])
        self.assertEqual(result['uncompleted_controls'][0]['status'],
                         'ATTEMPT_WITHOUT_FINAL_CONTROL_RESULT')
        with self.assertRaisesRegex(ValueError, 'all 58 original controls are required'):
            gate.validate(out, PROOF, verifier_path=verifier,
                          verifier_sha256=gate.controls.sha(verifier))


if __name__ == '__main__':
    unittest.main()
