#!/usr/bin/env python3
"""Negative accounting controls; every timing fixture here is synthetic."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('latency', ROOT / 'scripts/pon_proof_latency.py')
latency = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(latency)


def encode(value):
    return json.dumps(value, sort_keys=True).encode()


def fixture(count=2, endpoint='winner-to-receiver-validated'):
    policy = {
        'schema': latency.POLICY_SCHEMA, 'campaign_id': 'synthetic-negative-controls',
        'source_commit': 'a' * 40, 'profile_id': 'full-w1-v2-control-only',
        'endpoint': endpoint, 'competitor_rate_per_second': .1,
        'max_competition_probability': .01, 'timeout_after_winner_ns': 4_000_000_000,
        'original_confirmation_budget_ns': 4_000_000_000,
        'trials': [{'trial_id': 'trial-' + str(i), 'header_sha256': format(i + 1, '064x'),
                    'expected_artifacts_sha256': 'b' * 64} for i in range(count)],
    }
    raw = encode(policy)
    pin = hashlib.sha256(raw).hexdigest()
    observations = {key: policy[key] for key in ('campaign_id', 'source_commit', 'profile_id', 'endpoint')}
    observations.update(schema=latency.OBSERVATION_SCHEMA, policy_sha256=pin, trials=[])
    for i, trial in enumerate(policy['trials']):
        start = 1_000_000_000 + i * 10_000_000_000
        clock = 'one-controller-clock-' + str(i)
        names = latency.PHASES[endpoint]
        phases = [{'phase': name, 'clock_domain': clock,
                   'start_ns': start + j * 10_000_000,
                   'end_ns': start + (j + 1) * 10_000_000}
                  for j, name in enumerate(names)]
        observations['trials'].append(dict(trial, outcome='success', clock_domain=clock,
            winner_observed_ns=start, terminal_observed_ns=phases[-1]['end_ns'],
            deadline_ns=start + policy['timeout_after_winner_ns'], stages=phases,
            missing_timing_reason=None))
    return policy, observations, pin


class PublicationLatencyTests(unittest.TestCase):
    def read(self, policy, observations, pin):
        return latency.evaluate(encode(policy), encode(observations), pin)

    def reject_observation(self, mutate):
        policy, observations, pin = fixture()
        mutate(observations)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.read(policy, observations, pin)

    def test_poisson_example_and_inverted_budget(self):
        report = latency.model(.1, .01, [.1, 1, 10, 6248.484106799])
        self.assertAlmostEqual(report['latency_budget_seconds'], .10050335853501442)
        for row, expected in zip(report['rows'][:3], [.9900498337491681, .9048374180359595, .36787944117144233]):
            self.assertAlmostEqual(row['no_competitor_probability'], expected)
        self.assertFalse(report['rows'][-1]['within_model_budget'])
        self.assertIsNone(report['stale_block_probability'])
        self.assertFalse(report['consensus_admission'])

    def test_invalid_model_values_do_not_become_safe_probabilities(self):
        for value in (True, False, -1, 0, float('inf'), float('nan')):
            with self.subTest(rate=value), self.assertRaises(ValueError):
                latency.model(value, .01, [1])
        for value in (True, 0, -1, 1, 2, float('nan')):
            with self.subTest(epsilon=value), self.assertRaises(ValueError):
                latency.model(.1, value, [1])
        for value in (True, -1, float('nan'), float('inf')):
            with self.subTest(duration=value), self.assertRaises(ValueError):
                latency.model(.1, .01, [value])
        with self.assertRaises(ValueError):
            latency.model(1e308, .01, [1e308])

    def test_complete_finite_screen_never_promotes_population_or_runtime(self):
        report = self.read(*fixture())
        self.assertEqual(report['planned_trials'], 2)
        self.assertEqual(report['finite_poisson_latency_screen'], 'FINITE_SCREEN_PASS')
        self.assertEqual(report['finite_nearest_rank_quantiles_seconds'], {'p50': .09, 'p95': .09, 'p99': .09})
        self.assertAlmostEqual(report['empirical_mean_no_competitor_probability'], math.exp(-.009))
        for key in ('population_prover_p99_seconds', 'stale_block_probability'):
            self.assertIsNone(report[key])
        self.assertEqual(report['disposition'], 'HOLD_NO_GO')
        self.assertFalse(report['consensus_admission'])
        self.assertFalse(report['production_activation'])
        self.assertFalse(report['measurement_authentication_performed'])

    def test_risk_budget_does_not_replace_original_four_second_constraint(self):
        policy, observations, pin = fixture(1)
        row = observations['trials'][0]
        # Fully retained 0.29 s is below four seconds but fails the 1% model screen.
        row['stages'][-1]['end_ns'] += 200_000_000
        row['terminal_observed_ns'] += 200_000_000
        result = self.read(policy, observations, pin)['trials'][0]
        self.assertEqual(result['poisson_latency_screen'], 'FAIL')
        self.assertEqual(result['original_confirmation_necessary_screen'], 'FINITE_NECESSARY_SCREEN_PASS')

    def test_changed_external_policy_cannot_pick_a_more_permissive_threshold(self):
        policy, observations, pin = fixture()
        for name, value in [('max_competition_probability', .99), ('competitor_rate_per_second', .00001),
                            ('timeout_after_winner_ns', 9000000000), ('source_commit', 'f' * 40)]:
            changed = copy.deepcopy(policy)
            changed[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.read(changed, observations, pin)
        with self.assertRaises(ValueError):
            self.read(policy, observations, '0' * 64)

    def test_externally_repinned_original_confirmation_change_is_still_rejected(self):
        policy, observations, _ = fixture()
        policy['original_confirmation_budget_ns'] = 10000000000
        pin = hashlib.sha256(encode(policy)).hexdigest()
        observations['policy_sha256'] = pin
        with self.assertRaises(ValueError):
            self.read(policy, observations, pin)

    def test_context_and_external_statement_substitution_refused(self):
        for key in ('source_commit', 'profile_id', 'campaign_id', 'endpoint', 'policy_sha256'):
            with self.subTest(key=key):
                self.reject_observation(lambda o: o.__setitem__(key, 'substituted'))
        for key in ('header_sha256', 'expected_artifacts_sha256'):
            with self.subTest(key=key):
                self.reject_observation(lambda o: o['trials'][0].__setitem__(key, 'c' * 64))

    def test_all_outcomes_retained_and_failure_not_hidden_from_tail(self):
        policy, observations, pin = fixture(5)
        for row, outcome in zip(observations['trials'], latency.OUTCOMES):
            row['outcome'] = outcome
            if outcome != 'success':
                for key in ('clock_domain', 'winner_observed_ns', 'terminal_observed_ns', 'deadline_ns', 'stages'):
                    row[key] = None
                row['missing_timing_reason'] = 'timing unavailable; original outcome retained'
        report = self.read(policy, observations, pin)
        self.assertEqual(report['retained_outcomes'], dict.fromkeys(latency.OUTCOMES, 1))
        self.assertEqual(report['finite_poisson_latency_screen'], 'FAIL')
        self.assertIsNone(report['finite_nearest_rank_quantiles_seconds'])
        self.assertIsNone(report['empirical_mean_no_competitor_probability'])
        self.assertFalse(report['all_planned_trials_reached_endpoint_with_observed_winner_clock'])

    def test_observed_proof_success_with_unknown_winner_time_stays_unknown(self):
        policy, observations, pin = fixture(1)
        row = observations['trials'][0]
        for key in ('clock_domain', 'winner_observed_ns', 'terminal_observed_ns', 'deadline_ns', 'stages'):
            row[key] = None
        row['missing_timing_reason'] = 'fresh pipeline observed; winner event not recorded'
        report = self.read(policy, observations, pin)
        self.assertEqual(report['retained_outcomes']['success'], 1)
        self.assertEqual(report['finite_poisson_latency_screen'], 'UNKNOWN')
        self.assertIsNone(report['trials'][0]['latency_seconds'])
        self.assertIsNone(report['finite_nearest_rank_quantiles_seconds'])
        row['fresh_proof_pipeline_seconds'] = 6248.484106799
        with self.assertRaises(ValueError):
            self.read(policy, observations, pin)

    def test_missing_duplicate_and_extra_trial_cannot_reduce_denominator(self):
        self.reject_observation(lambda o: o['trials'].pop())
        self.reject_observation(lambda o: o['trials'].append(copy.deepcopy(o['trials'][0])))
        self.reject_observation(lambda o: o['trials'].__setitem__(1, copy.deepcopy(o['trials'][0])))
        self.reject_observation(lambda o: o['trials'][0].__setitem__('trial_id', 'unplanned'))

    def test_missing_or_reordered_phase_and_fake_endpoint_are_refused(self):
        self.reject_observation(lambda o: o['trials'][0]['stages'].pop())
        self.reject_observation(lambda o: o['trials'][0]['stages'][0].__setitem__('phase', 'prove'))
        self.reject_observation(lambda o: o['trials'][0]['stages'][3].__setitem__('phase', 'prove'))

    def test_gaps_overlap_and_nonmonotone_clocks_refused(self):
        self.reject_observation(lambda o: o['trials'][0]['stages'][2].__setitem__('start_ns', 0))
        self.reject_observation(lambda o: o['trials'][0]['stages'][2].__setitem__('start_ns', 1020000001))
        self.reject_observation(lambda o: o['trials'][0]['stages'][2].__setitem__('end_ns', 0))
        self.reject_observation(lambda o: o['trials'][0].__setitem__('terminal_observed_ns', 0))
        self.reject_observation(lambda o: o['trials'][0].__setitem__('terminal_observed_ns', 1090000001))

    def test_receiver_clock_and_restarted_deadline_refused(self):
        self.reject_observation(lambda o: o['trials'][0]['stages'][-1].__setitem__('clock_domain', 'remote-host-clock'))
        self.reject_observation(lambda o: o['trials'][0].__setitem__('deadline_ns', 6000000000))

    def test_boolean_float_negative_and_huge_timestamps_refused(self):
        for value in (True, 1.0, -1, 2**63, float('nan')):
            with self.subTest(value=value):
                self.reject_observation(lambda o: o['trials'][0].__setitem__('winner_observed_ns', value))

    def test_late_success_keeps_actual_time_but_fails(self):
        policy, observations, pin = fixture(1)
        row = observations['trials'][0]
        row['stages'][-1]['end_ns'] = row['deadline_ns'] + 1
        row['terminal_observed_ns'] = row['deadline_ns'] + 1
        report = self.read(policy, observations, pin)
        self.assertEqual(report['retained_outcomes']['success'], 1)
        self.assertEqual(report['finite_poisson_latency_screen'], 'FAIL')
        self.assertEqual(report['finite_nearest_rank_quantiles_seconds']['p99'], 4.000000001)
        self.assertTrue(report['all_planned_trials_reached_endpoint_with_observed_winner_clock'])
        self.assertFalse(report['all_planned_trials_completed_within_original_timeout'])

    def test_unknown_short_terminal_does_not_invent_a_confirmation_failure(self):
        policy, observations, pin = fixture(1)
        row = observations['trials'][0]
        row['outcome'] = 'unknown'
        row['stages'] = row['stages'][:2]
        row['terminal_observed_ns'] = row['stages'][-1]['end_ns']
        report = self.read(policy, observations, pin)
        self.assertEqual(report['finite_poisson_latency_screen'], 'UNKNOWN')
        self.assertEqual(report['trials'][0]['original_confirmation_necessary_screen'], 'UNKNOWN')
        self.assertIsNone(report['finite_nearest_rank_quantiles_seconds'])

    def test_deep_json_uses_standard_cli_refusal_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b'[' * 10000 + b'0' + b']' * 10000
            (root / 'policy.json').write_bytes(raw)
            (root / 'observations.json').write_bytes(b'{}')
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/pon_proof_latency.py'),
                'evaluate', '--policy', str(root / 'policy.json'), '--observations',
                str(root / 'observations.json'), '--expected-policy-sha256',
                hashlib.sha256(raw).hexdigest()], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('proof latency input rejected:', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_slow_competitor_assumption_cannot_mask_original_confirmation_veto(self):
        policy, observations, _ = fixture(1)
        policy['competitor_rate_per_second'] = .0001
        policy['timeout_after_winner_ns'] = 10_000_000_000
        pin = hashlib.sha256(encode(policy)).hexdigest()
        observations['policy_sha256'] = pin
        row = observations['trials'][0]
        row['deadline_ns'] = row['winner_observed_ns'] + 10_000_000_000
        row['terminal_observed_ns'] = row['winner_observed_ns'] + 5_000_000_000
        row['stages'][-1]['end_ns'] = row['terminal_observed_ns']
        report = self.read(policy, observations, pin)
        self.assertEqual(report['finite_poisson_latency_screen'], 'FINITE_SCREEN_PASS')
        self.assertEqual(report['finite_original_confirmation_necessary_screen'], 'FAIL')
        self.assertEqual(report['disposition'], 'HOLD_NO_GO')

    def test_timeout_at_deadline_is_not_a_completed_endpoint(self):
        policy, observations, pin = fixture(1)
        row = observations['trials'][0]
        row['outcome'] = 'timeout'
        row['terminal_observed_ns'] = row['deadline_ns']
        row['stages'][-1]['end_ns'] = row['deadline_ns']
        report = self.read(policy, observations, pin)
        self.assertTrue(report['trials'][0]['terminal_at_or_before_original_deadline'])
        self.assertFalse(report['trials'][0]['endpoint_completed_within_original_timeout'])
        self.assertFalse(report['all_planned_trials_completed_within_original_timeout'])
        self.assertEqual(report['finite_poisson_latency_screen'], 'FAIL')

    def test_identical_observations_do_not_establish_independent_proofs(self):
        policy, observations, _ = fixture(2)
        policy['trials'][1].update(header_sha256=policy['trials'][0]['header_sha256'])
        observations['trials'][1] = dict(copy.deepcopy(observations['trials'][0]), trial_id='trial-1')
        pin = hashlib.sha256(encode(policy)).hexdigest()
        observations['policy_sha256'] = pin
        report = self.read(policy, observations, pin)
        self.assertEqual(report['planned_trials'], 2)
        self.assertFalse(report['independent_proof_trials_established'])
        self.assertIsNone(report['population_prover_p99_seconds'])
        self.assertEqual(report['disposition'], 'HOLD_NO_GO')

    def test_partial_failure_clock_is_allowed_but_not_success_clock(self):
        policy, observations, pin = fixture(1)
        row = observations['trials'][0]
        row['outcome'] = 'canceled'
        row['stages'] = row['stages'][:2]
        row['terminal_observed_ns'] = row['stages'][-1]['end_ns']
        result = self.read(policy, observations, pin)
        self.assertEqual(result['finite_poisson_latency_screen'], 'FAIL')
        self.assertEqual(result['trials'][0]['latency_seconds'], .02)
        row['outcome'] = 'success'
        with self.assertRaises(ValueError):
            self.read(policy, observations, pin)

    def test_timeout_cannot_be_relabelled_early(self):
        policy, observations, pin = fixture(1)
        observations['trials'][0]['outcome'] = 'timeout'
        with self.assertRaises(ValueError):
            self.read(policy, observations, pin)

    def test_mean_probability_is_not_probability_at_mean_latency(self):
        policy, observations, _ = fixture(2)
        policy['timeout_after_winner_ns'] = 20_000_000_000
        pin = hashlib.sha256(encode(policy)).hexdigest()
        observations['policy_sha256'] = pin
        for row, duration in zip(observations['trials'], [1, 10]):
            row['deadline_ns'] = row['winner_observed_ns'] + policy['timeout_after_winner_ns']
            row['terminal_observed_ns'] = row['winner_observed_ns'] + duration * 1000000000
            row['stages'][-1]['end_ns'] = row['terminal_observed_ns']
        report = self.read(policy, observations, pin)
        empirical = report['empirical_mean_no_competitor_probability']
        self.assertAlmostEqual(empirical, (math.exp(-.1) + math.exp(-1)) / 2)
        self.assertGreater(empirical, math.exp(-.55))

    def test_unsupported_schema_or_extra_claim_field_is_not_ignored(self):
        self.reject_observation(lambda o: o.__setitem__('production_activation', True))
        self.reject_observation(lambda o: o.__setitem__('schema', 'future-version'))
        self.reject_observation(lambda o: o['trials'][0].__setitem__('outcome', 'successful'))

    def test_duplicate_json_keys_and_nonfinite_literals_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                latency.strict_json(raw)

    def test_nonregular_symlink_and_oversized_inputs_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source'
            source.write_bytes(b'123')
            with self.assertRaises(ValueError):
                latency.read_regular(source, 2)
            link = root / 'link'
            link.symlink_to(source)
            with self.assertRaises(OSError):
                latency.read_regular(link, 100)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                latency.read_regular(fifo, 100)

    def test_real_cli_model_and_declaration_rejection(self):
        script = str(ROOT / 'scripts/pon_proof_latency.py')
        run = subprocess.run([sys.executable, script, 'model', '--competitor-rate-per-second', '.1',
                              '--max-competition-probability', '.01', '--latency-seconds', '.1', '1', '10'],
                             text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(json.loads(run.stdout)['rows']), 3)
        with tempfile.TemporaryDirectory() as folder:
            policy, observations, pin = fixture()
            p, o = Path(folder) / 'policy.json', Path(folder) / 'observations.json'
            p.write_bytes(encode(policy))
            o.write_bytes(encode(observations))
            args = [sys.executable, script, 'evaluate', '--policy', str(p), '--observations', str(o),
                    '--expected-policy-sha256', pin]
            valid = subprocess.run(args, text=True, capture_output=True)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            p.write_bytes(encode(dict(policy, max_competition_probability=.999)))
            bad = subprocess.run(args, text=True, capture_output=True)
            self.assertEqual(bad.returncode, 2)
            self.assertIn('independently retained', bad.stderr)


if __name__ == '__main__':
    unittest.main()
