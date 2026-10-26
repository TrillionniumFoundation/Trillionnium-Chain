#!/usr/bin/env python3
"""Plan/analysis rejection controls; synthetic rows are never native evidence."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import run_w1_compact_miner_research as runner
from analyze_w1_compact_miner_research import analyze, compare, main as analyze_main
from read_w1_compact_miner_research import cpu_observer_reconciliation


class PlanControls(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((ROOT / 'formal/pon-nakamoto-v1/experiments/w1_compact_miner_plan_v1.json').read_text())

    def test_exact_frozen_grid(self):
        self.assertEqual(len(runner.validate_plan(self.plan)), 13)

    def test_seed_selection_rejected(self):
        self.plan['jobs'][0]['args'][7] = '7104'
        with self.assertRaisesRegex(ValueError, 'EXACT_PREREGISTERED'):
            runner.validate_plan(self.plan)

    def test_omitted_failure_control_rejected(self):
        self.plan['jobs'].pop()
        with self.assertRaisesRegex(ValueError, 'EXACT_PREREGISTERED'):
            runner.validate_plan(self.plan)

    def test_adaptive_order_rejected(self):
        self.plan['jobs'][0], self.plan['jobs'][1] = self.plan['jobs'][1], self.plan['jobs'][0]
        with self.assertRaisesRegex(ValueError, 'EXACT_PREREGISTERED'):
            runner.validate_plan(self.plan)

    def test_duplicate_flag_rejected(self):
        self.plan['jobs'][1]['args'] += ['--seed', '7101']
        with self.assertRaisesRegex(ValueError, 'PLAN_OPTIONS'):
            runner.validate_plan(self.plan)

    def test_original_budget_cannot_change(self):
        self.plan['jobs'][0]['args'][3] = '256000000'
        with self.assertRaisesRegex(ValueError, 'EXACT_PREREGISTERED'):
            runner.validate_plan(self.plan)

    def test_boolean_allowance_rejected(self):
        self.plan['waited_cpu_endpoint_allowance_ns'] = True
        with self.assertRaisesRegex(ValueError, 'REGISTERED_OBSERVER'):
            runner.validate_plan(self.plan)

    def test_activation_flag_rejected(self):
        self.plan['production_activation'] = True
        with self.assertRaisesRegex(ValueError, 'PLAN_AUTHORITY'):
            runner.validate_plan(self.plan)

    def test_analyzer_changed_registered_options_rejected(self):
        jobs = []
        for registered in runner.registered_jobs():
            if registered['binary'] == 'pon_w1_compact_miner_research':
                from w1_compact_miner_reader import options_from_args
            else:
                from w1_late_assembly_reader import options_from_args
            jobs.append(dict(job=registered['name'], binary=registered['binary'],
                             options=options_from_args(registered['args'])))
        jobs[0]['options']['miner_budget_ns'] += 1
        value = dict(schema='pon-w1-compact-miner-research-derived-v1',
            external_identity_pins_checked=True,
            all_retained_full_proof_records_independently_replayed=True,
            compact_all_deterministic_attempts_independently_recomputed=True, jobs=jobs)
        with self.assertRaisesRegex(ValueError, 'REGISTERED_OPTIONS_BINDING'):
            analyze(value)

    def test_wrong_external_readback_hash_rejected_before_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic-input.json'
            output = Path(directory) / 'must-not-exist.json'
            path.write_text('{}')
            argv = ['analyzer', '--readback', str(path), '--out', str(output),
                    '--expected-readback-sha256', '0' * 64]
            with patch.object(sys, 'argv', argv):
                with self.assertRaisesRegex(ValueError, 'READBACK_EXTERNAL_PIN_MISMATCH'):
                    analyze_main()
            self.assertFalse(output.exists())


class ComparisonControls(unittest.TestCase):
    def setUp(self):
        self.compact = dict(job='synthetic-compact', attempts=2,
            options=dict(seed=7101, miner_budget_ns=128000000, setup_budget_ns=1000000000, max_attempts=4096),
            setup_statement=dict(header_hex='synthetic', proof_sha256='synthetic'),
            opportunity_identities=['a', 'b'], hit_sequence=[True, False],
            setup_complete=True, censored_by_attempt_cap=False,
            full_winners_available_by_B=1, phase_cpu_ns=dict(setup=5, miner=10), raw_bytes=100)
        self.late = copy.deepcopy(self.compact)
        self.late['options']['mode'] = 'deferred'
        self.late['job'] = 'synthetic-late'

    def test_matched_observation(self):
        result = compare(self.compact, self.late)
        self.assertTrue(result['matched'])
        self.assertEqual(result['winning_ticket_ratio']['decimal'], 1)

    def test_unmatched_stream_stays_null(self):
        self.compact['opportunity_identities'][1] = 'different'
        result = compare(self.compact, self.late)
        self.assertIsNone(result['winning_ticket_ratio'])
        self.assertIn('different-opportunity-prefix', result['null_reasons'])

    def test_changed_setup_stays_null(self):
        self.compact['setup_statement']['header_hex'] = 'different'
        self.assertIsNone(compare(self.compact, self.late)['winning_ticket_ratio'])

    def test_wrong_comparator_mode_stays_null(self):
        self.late['options']['mode'] = 'eager'
        self.assertIsNone(compare(self.compact, self.late)['winning_ticket_ratio'])

    def test_boolean_resource_identity_is_not_an_integer(self):
        self.compact['options']['seed'] = True
        self.late['options']['seed'] = 1
        self.assertIsNone(compare(self.compact, self.late)['winning_ticket_ratio'])

    def test_cap_censoring_not_a_budget_gain(self):
        self.compact['censored_by_attempt_cap'] = True
        self.assertIsNone(compare(self.compact, self.late)['winning_ticket_ratio'])

    def test_zero_denominator_is_not_infinite_advantage(self):
        self.late['full_winners_available_by_B'] = 0
        self.assertIsNone(compare(self.compact, self.late)['winning_ticket_ratio'])

    def test_regression_preserved(self):
        self.late['full_winners_available_by_B'] = 2
        self.assertEqual(compare(self.compact, self.late)['winning_ticket_ratio']['decimal'], 0.5)

    def test_signed_observer_residual_not_clamped(self):
        step = dict(whole_waited_child_resources=dict(user_cpu_ns=1000, system_cpu_ns=0),
                    command_usage=dict(user_seconds_decimal='0.00', system_seconds_decimal='0.00'))
        result = cpu_observer_reconciliation(dict(total_process_cpu_ns=1500), step)
        self.assertEqual(result['signed_residual_cpu_ns'], -500)
        self.assertFalse(result['residual_clamped'])

    def test_observer_scope_disagreement_rejected(self):
        step = dict(whole_waited_child_resources=dict(user_cpu_ns=1000, system_cpu_ns=0),
                    command_usage=dict(user_seconds_decimal='0.00', system_seconds_decimal='0.00'))
        with self.assertRaisesRegex(ValueError, 'NATIVE_CPU_EXCEEDS'):
            cpu_observer_reconciliation(dict(total_process_cpu_ns=4000), step)


if __name__ == '__main__':
    unittest.main()
