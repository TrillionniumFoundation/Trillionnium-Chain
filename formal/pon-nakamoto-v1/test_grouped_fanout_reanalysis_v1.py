"""Adversarial replay-reader controls; all constructed campaigns here are synthetic."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from experiments import reanalyze_grouped_fanout_v1 as replay
from test_grouped_fresh_deployment_cost_v0 import synthetic_worker


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def synthetic_campaign():
    topologies = []
    for size in (1, 2, 4):
        workers = [synthetic_worker(index) for index in range(size)]
        for worker in workers:
            worker['raw_readback_passed'] = True
        topologies.append({
            'planned_receivers': size, 'workers': workers,
            'accounting': {'status': 'PASS', 'issues': [], 'planned_receivers': 999,
                           'verified_receptions': 1_000_000, 'receiver_wait4_cpu_seconds': 0},
            'orchestration_failures': [], 'unstarted_clients': [],
            'whole_topology': {'wall_ns': size, 'thread_cpu_ns': 1},
        })
    return {
        'schema': replay.INPUT_SCHEMA, 'status': 'PASS', 'topologies': topologies,
        'failures': [], 'not_started_topologies': [],
        'expected_source_sha': 'a' * 40, 'runner_sha256': 'b' * 64,
        'source_before': {'commit': 'a' * 40, 'synthetic_fixture': True},
        'source_after': {'commit': 'a' * 40, 'synthetic_fixture': True},
        'measurement_mode': 'synthetic-test-not-a-measurement',
        'cost_scope': ['Synthetic worker numbers; no real process was measured.'],
        'all_receptions_are_not_independent_tickets': True,
        'output_storage_before': {'filesystem_type': 'synthetic', 'power_loss_durability_tested': False},
        'output_storage_after': {'filesystem_type': 'synthetic', 'power_loss_durability_tested': False},
        **replay.QUALIFICATION_BOUNDARIES,
    }


class FanoutReanalysisTests(unittest.TestCase):
    def recheck(self, value):
        raw = encode(value)
        return replay.reanalyze(raw, expected_sha256=sha(raw))

    def test_raw_workers_recompute_counts_and_preserve_original_source_metadata(self):
        value = synthetic_campaign()
        before = copy.deepcopy(value)
        raw = encode(value)
        result = replay.reanalyze(raw, expected_sha256=sha(raw))
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['topology_denominator'], [1, 2, 4])
        self.assertEqual(result['planned_receiver_slots'], 7)
        self.assertEqual(result['planned_transport_attempts'], 42)
        self.assertEqual(result['input_sha256'], sha(raw))
        for size, row in zip((1, 2, 4), result['topologies']):
            self.assertEqual(row['new_accounting']['planned_receivers'], size)
            self.assertEqual(row['new_accounting']['verified_receptions'], size * 3)
            self.assertEqual(row['new_accounting']['receiver_wait4_cpu_seconds'], size * 3.0)
            self.assertEqual(row['old_accounting']['verified_receptions'], 1_000_000)
            self.assertEqual(row['new_status'], 'PASS')
        self.assertEqual(result['original_metadata'], {k: v for k, v in before.items() if k != 'topologies'})
        self.assertEqual(value, before)
        self.assertFalse(result['originals_modified'])
        self.assertFalse(result['new_experiment_executed'])
        self.assertFalse(result['source_and_binary_checks_reexecuted'])
        self.assertFalse(result['original_transport_files_reread'])
        self.assertEqual(result['qualification_status'], 'HOLD')
        self.assertEqual(result['checker']['source_sha256'],
                         sha(Path(replay.accounting.__file__).read_bytes()))
        self.assertEqual(result['checker']['reanalysis_source_sha256'], sha(Path(replay.__file__).read_bytes()))

    def test_external_pin_is_mandatory_and_tampered_input_is_refused(self):
        raw = encode(synthetic_campaign())
        for pin in (None, '', 'x' * 64, 'a' * 63, 'A' * 64, False):
            with self.subTest(pin=pin):
                with self.assertRaisesRegex(ValueError, 'EXPECTED_SHA256_REQUIRED'):
                    replay.reanalyze(raw, expected_sha256=pin)
        with self.assertRaisesRegex(ValueError, 'INPUT_SHA256_MISMATCH'):
            replay.reanalyze(raw + b' ', expected_sha256=sha(raw))

    def test_duplicate_json_keys_are_rejected_even_with_matching_input_pin(self):
        value = synthetic_campaign()
        raw = encode(value).replace(b'"status":"PASS"', b'"status":"PASS","status":"FAIL"', 1)
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            replay.reanalyze(raw, expected_sha256=sha(raw))
        raw = b'{"schema":"wrong","schema":"' + replay.INPUT_SCHEMA.encode() + b'"}'
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            replay.reanalyze(raw, expected_sha256=sha(raw))

    def test_nonfinite_literals_and_overflowing_float_exponents_are_rejected(self):
        value = synthetic_campaign()
        value['otherwise_unused_metadata'] = 'NONFINITE_SENTINEL'
        for number in (b'NaN', b'Infinity', b'-Infinity', b'1e9999', b'-1e9999'):
            with self.subTest(number=number):
                raw = encode(value).replace(b'"NONFINITE_SENTINEL"', number)
                with self.assertRaisesRegex(ValueError, 'NONFINITE_JSON_NUMBER'):
                    replay.reanalyze(raw, expected_sha256=sha(raw))

    def test_input_size_limit_has_an_explicit_inclusive_boundary(self):
        raw = encode(synthetic_campaign())
        at_limit = raw + b' ' * (replay.MAX_INPUT_BYTES - len(raw))
        self.assertEqual(replay.reanalyze(at_limit, expected_sha256=sha(at_limit))['input_bytes'],
                         replay.MAX_INPUT_BYTES)
        oversized = at_limit + b' '
        with self.assertRaisesRegex(ValueError, 'INPUT_SIZE_OR_TYPE'):
            replay.reanalyze(oversized, expected_sha256=sha(oversized))

    def test_duplicate_missing_reordered_extra_and_alias_topologies_are_refused(self):
        for sizes in ((1, 1, 4), (1, 2), (4, 2, 1), (1, 2, 4, 4), (True, 2, 4), (1.0, 2, 4)):
            with self.subTest(sizes=sizes):
                value = synthetic_campaign()
                original = value['topologies']
                value['topologies'] = [dict(copy.deepcopy(original[min(index, 2)]), planned_receivers=size)
                                       for index, size in enumerate(sizes)]
                with self.assertRaisesRegex(ValueError, 'TOPOLOGY_DENOMINATOR_EXPECTED_1_2_4'):
                    self.recheck(value)

    def test_old_pass_and_forged_summary_cannot_hide_missing_raw_work_identity(self):
        value = synthetic_campaign()
        del value['topologies'][0]['workers'][0]['worker_report']['transport_records'][0]['verification']['work_id']
        result = self.recheck(value)
        self.assertEqual(result['old_status'], 'PASS')
        self.assertEqual(result['new_status'], 'FAIL')
        self.assertTrue(result['status_changed'])
        self.assertEqual(len(result['new_failures']), 1)
        first = result['topologies'][0]
        self.assertEqual(first['old_status'], 'PASS')
        self.assertEqual(first['new_status'], 'FAIL')
        self.assertEqual(first['new_accounting']['verified_receptions'], 3)
        self.assertIsNone(first['new_accounting']['distinct_verified_work_ids'])
        self.assertTrue(any('WORK_ID_UNKNOWN' in item for item in result['new_failures'][0]['accounting_issues']))
        self.assertEqual([r['new_status'] for r in result['topologies'][1:]], ['PASS', 'PASS'])

    def test_old_pass_cannot_hide_unobserved_transport_cost(self):
        for replacement in (None, -1, False, []):
            with self.subTest(counter=replacement):
                value = synthetic_campaign()
                value['topologies'][1]['workers'][0]['worker_report']['transport_records'][0]['received_frame_bytes'] = replacement
                result = self.recheck(value)
                self.assertEqual(result['status'], 'FAIL')
                self.assertEqual(result['new_failures'][0]['planned_receivers'], 2)
                checked = result['topologies'][1]['new_accounting']
                self.assertEqual(checked['planned_transport_attempts'], 12)
                self.assertEqual(checked['completed_transport_attempts'], 12)
                self.assertIsNone(checked['tcp_application_received_by_receivers_bytes'])

    def test_missing_worker_stays_in_fixed_plan_denominator(self):
        value = synthetic_campaign()
        value['topologies'][2]['workers'].pop()
        result = self.recheck(value)
        checked = result['topologies'][2]['new_accounting']
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(checked['planned_receivers'], 4)
        self.assertEqual(checked['observed_receiver_slots'], 3)
        self.assertEqual(checked['planned_transport_attempts'], 24)
        self.assertEqual(checked['completed_transport_attempts'], 18)
        self.assertIsNone(checked['receiver_wait4_cpu_seconds'])
        self.assertEqual(checked['observed_wait4_cpu_seconds_partial'], 9.0)

    def test_original_failure_is_retained_without_automatic_upgrade(self):
        value = synthetic_campaign()
        value['status'] = 'FAIL'
        value['failures'] = [{'stage': 'external', 'reason': 'UNKNOWN_OWNER_RESULT'}]
        value['topologies'][0]['accounting'].update(status='FAIL', issues=['ORIGINAL_GATE'])
        result = self.recheck(value)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['topologies'][0]['new_accounting']['status'], 'PASS')
        self.assertEqual(result['topologies'][0]['new_status'], 'FAIL')
        self.assertEqual(result['original_metadata']['failures'], value['failures'])
        self.assertIn('ORIGINAL_FAILURES_RETAINED', result['issues'])

    def test_original_readback_failure_is_not_cleared_by_arithmetic_recheck(self):
        value = synthetic_campaign()
        value['topologies'][0]['workers'][0]['raw_readback_passed'] = False
        result = self.recheck(value)
        row = result['topologies'][0]
        self.assertEqual(row['new_accounting']['status'], 'PASS')
        self.assertEqual(row['new_status'], 'FAIL')
        self.assertIn('ORIGINAL_RECEIVER_0_READBACK_NOT_PASS', row['retained_gate_issues'])
        self.assertFalse(result['original_transport_files_reread'])

    def test_orchestration_failure_cannot_be_suppressed_by_old_pass(self):
        value = synthetic_campaign()
        value['topologies'][0]['orchestration_failures'] = [{'reason': 'FAILED_REAP'}]
        result = self.recheck(value)
        self.assertEqual(result['topologies'][0]['new_status'], 'FAIL')
        self.assertIn('ORIGINAL_ORCHESTRATION_FAILURES_RETAINED',
                      result['topologies'][0]['retained_gate_issues'])

    def test_qualification_promotions_and_integer_boolean_aliases_are_rejected(self):
        for field, value in (('production_activation', True), ('external_demand_authenticated', True),
                             ('global_verification_cap_enforced', True), ('actual_consumer_uses_observed', 1),
                             ('chainwork_awarded', False), ('independent_operators', 0)):
            with self.subTest(field=field, value=value):
                original = synthetic_campaign()
                original[field] = value
                result = self.recheck(original)
                self.assertEqual(result['status'], 'FAIL')
                self.assertEqual(result['original_metadata'][field], value)
                self.assertEqual(result[field], replay.QUALIFICATION_BOUNDARIES[field])
                self.assertIn('ORIGINAL_QUALIFICATION_BOUNDARY_' + field.upper(), result['issues'])

    def test_checker_change_during_reanalysis_is_refused(self):
        raw = encode(synthetic_campaign())
        first = replay._checker_identity()
        changed = dict(first, source_sha256='f' * 64)
        with mock.patch.object(replay, '_checker_identity', side_effect=[first, changed]):
            with self.assertRaisesRegex(ValueError, 'CHECKER_SOURCE_CHANGED_DURING_REANALYSIS'):
                replay.reanalyze(raw, expected_sha256=sha(raw))

    def test_cli_stdout_is_complete_and_never_writes_originals(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'original.json'
            raw = encode(synthetic_campaign())
            source.write_bytes(raw)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = replay.main(['--input', str(source), '--expected-sha256', sha(raw)])
            self.assertEqual(code, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result['input_sha256'], sha(raw))
            self.assertTrue(result['input_unchanged_after_reanalysis'])
            self.assertFalse(result['originals_modified'])
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(list(Path(directory).iterdir()), [source])

    def test_cli_output_is_create_only_and_mismatched_pin_creates_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'original.json', Path(directory) / 'reanalysis.json'
            raw = encode(synthetic_campaign())
            source.write_bytes(raw)
            args = ['--input', str(source), '--expected-sha256', sha(raw), '--out', str(output)]
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(replay.main(args), 0)
                first = output.read_bytes()
                self.assertEqual(replay.main(args), 2)
            self.assertEqual(output.read_bytes(), first)
            self.assertEqual(source.read_bytes(), raw)
            untouched = Path(directory) / 'should-not-exist.json'
            args = ['--input', str(source), '--expected-sha256', '0' * 64, '--out', str(untouched)]
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(replay.main(args), 2)
            self.assertFalse(untouched.exists())

    def test_cli_new_failure_is_retained_with_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'original.json', Path(directory) / 'reanalysis.json'
            value = synthetic_campaign()
            value['topologies'][0]['workers'][0]['worker_report']['transport_records'][0]['status'] = 'unknown'
            raw = encode(value)
            source.write_bytes(raw)
            args = ['--input', str(source), '--expected-sha256', sha(raw), '--out', str(output)]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(replay.main(args), 1)
            result = json.loads(output.read_bytes())
            self.assertEqual(result['old_status'], 'PASS')
            self.assertEqual(result['new_status'], 'FAIL')
            self.assertEqual(result['topologies'][0]['new_accounting']['completed_transport_attempts'], 5)
            self.assertEqual(source.read_bytes(), raw)

    def test_cli_refuses_source_change_before_any_output_creation(self):
        raw = encode(synthetic_campaign())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created.json'
            args = ['--input', 'controlled-test-input', '--expected-sha256', sha(raw), '--out', str(output)]
            with mock.patch.object(replay, '_read_bounded', side_effect=[raw, raw + b' ']):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(replay.main(args), 2)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
