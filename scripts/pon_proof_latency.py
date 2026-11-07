#!/usr/bin/env python3
"""Screen a predeclared finite proof-publication campaign; never grant admission.

`model` evaluates an explicitly hypothetical homogeneous-Poisson scenario.
`evaluate` requires an independently retained SHA256 of the policy bytes. The
policy fixes the source, full statement identities, endpoint, all planned trials,
original timeout, and risk budget before the observations are interpreted. The
records are bookkeeping inputs: this program authenticates neither clocks nor
proofs. Passing a finite screen is not a stale-rate, p99, WAN or security claim.

All phase boundaries must be observed in ONE monotonic observer clock domain.
For a remote endpoint, timestamp its acknowledgement at that observer; do not
subtract clocks from different hosts. Phases partition the critical-path wall
interval; overlapping CPU work belongs in a separate resource ledger.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

POLICY_SCHEMA = 'trnm-pon-proof-publication-policy-v1'
OBSERVATION_SCHEMA = 'trnm-pon-proof-publication-observations-v1'
REPORT_SCHEMA = 'trnm-pon-proof-publication-screen-v1'
OUTCOMES = ('success', 'failure', 'timeout', 'canceled', 'unknown')
PHASES = {
    'winner-to-publish-ready': ('queue', 'witness', 'prove', 'compress',
                                'local_verify', 'package'),
    'winner-to-receiver-validated': ('queue', 'witness', 'prove', 'compress',
                                   'local_verify', 'package', 'propagate',
                                   'receiver_queue', 'receiver_verify'),
}
MAX_NS = 2**63 - 1
MAX_TRIALS = 10000
ORIGINAL_CONFIRMATION_NS = 4_000_000_000


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names),
            label + ': missing or unknown fields')


def text(value, label):
    require(type(value) is str and 0 < len(value) <= 512 and
            not any(ord(x) < 32 for x in value), label + ': invalid text')
    return value


def digest(value, size, label):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value),
            label + ': invalid digest')
    return value


def ns(value, label, positive=False):
    require(type(value) is int and (0 < value if positive else 0 <= value) and
            value <= MAX_NS, label + ': expected bounded integer nanoseconds')
    return value


def number(value, label, positive=False):
    require(type(value) in (int, float) and math.isfinite(value) and
            (value > 0 if positive else value >= 0), label + ': invalid finite number')
    return float(value)


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON key: ' + key)
            out[key] = value
        return out

    def reject(value):
        raise ValueError('nonfinite JSON number: ' + value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                'input is not a bounded regular file')
        raw = source.read(limit + 1)
        after = os.fstat(source.fileno())
        require(len(raw) == before.st_size and len(raw) <= limit and
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'input changed while reading')
        return raw


def model(competing_rate, max_competition_probability, durations):
    rate = number(competing_rate, 'competitor rate', positive=True)
    epsilon = number(max_competition_probability, 'risk budget', positive=True)
    require(epsilon < 1, 'risk budget must be below one')
    budget = -math.log1p(-epsilon) / rate
    require(math.isfinite(budget) and budget > 0, 'model budget outside numeric range')
    require(type(durations) in (list, tuple) and len(durations) <= MAX_TRIALS,
            'bounded duration list required')
    rows = []
    for duration in durations:
        seconds = number(duration, 'duration')
        exposure = rate * seconds
        require(math.isfinite(exposure), 'Poisson exposure outside numeric range')
        rows.append({'latency_seconds': seconds,
                     'log_no_competitor_probability': -exposure,
                     'no_competitor_probability': math.exp(-exposure),
                     'at_least_one_competitor_probability': -math.expm1(-exposure),
                     'within_model_budget': seconds <= budget})
    return {
        'schema': 'trnm-pon-proof-publication-poisson-model-v1',
        'scope': 'conditional homogeneous-Poisson illustration; not a fork model',
        'competitor_rate_per_second': rate,
        'max_competition_probability': epsilon,
        'latency_budget_seconds': budget,
        'assumptions': ['competitor arrivals are homogeneous Poisson',
                        'latency is independent of competitor arrivals',
                        'rate describes competing complete eligible work, not an asserted DAA interval'],
        'rows': rows,
        'stale_block_probability': None,
        'production_activation': False,
        'consensus_admission': False,
    }


def validate_policy(policy):
    fields(policy, ('schema', 'campaign_id', 'source_commit', 'profile_id',
                    'endpoint', 'competitor_rate_per_second',
                    'max_competition_probability', 'timeout_after_winner_ns',
                    'original_confirmation_budget_ns', 'trials'), 'policy')
    require(policy['schema'] == POLICY_SCHEMA, 'unknown policy schema')
    text(policy['campaign_id'], 'campaign')
    digest(policy['source_commit'], 40, 'source commit')
    text(policy['profile_id'], 'profile')
    require(policy['endpoint'] in PHASES, 'unknown measured endpoint')
    model(policy['competitor_rate_per_second'], policy['max_competition_probability'], [])
    ns(policy['timeout_after_winner_ns'], 'declared timeout', positive=True)
    confirmation = policy['original_confirmation_budget_ns']
    require(confirmation is None or type(confirmation) is int and
            confirmation == ORIGINAL_CONFIRMATION_NS,
            'original four-second confirmation screen changed')
    planned = policy['trials']
    require(type(planned) is list and 0 < len(planned) <= MAX_TRIALS,
            'nonempty bounded predeclared trial list required')
    identities = {}
    for trial in planned:
        fields(trial, ('trial_id', 'header_sha256', 'expected_artifacts_sha256'), 'planned trial')
        key = text(trial['trial_id'], 'trial ID')
        require(key not in identities, 'duplicate planned trial')
        digest(trial['header_sha256'], 64, 'header digest')
        digest(trial['expected_artifacts_sha256'], 64, 'expected material digest')
        identities[key] = trial
    return identities


def evaluate(policy_raw, observations_raw, expected_policy_sha256):
    """Interpret exact JSON bytes; caller must retain the expected policy hash."""
    digest(expected_policy_sha256, 64, 'externally expected policy hash')
    require(hashlib.sha256(policy_raw).hexdigest() == expected_policy_sha256,
            'policy differs from independently retained expected bytes')
    policy = strict_json(policy_raw)
    identities = validate_policy(policy)
    observed = strict_json(observations_raw)
    fields(observed, ('schema', 'campaign_id', 'policy_sha256', 'source_commit',
                      'profile_id', 'endpoint', 'trials'), 'observations')
    require(observed['schema'] == OBSERVATION_SCHEMA, 'unknown observation schema')
    require(observed['policy_sha256'] == expected_policy_sha256, 'observation policy mismatch')
    for key in ('campaign_id', 'source_commit', 'profile_id', 'endpoint'):
        require(observed[key] == policy[key], 'observation context mismatch: ' + key)
    trials = observed['trials']
    require(type(trials) is list and len(trials) == len(identities),
            'missing or extra planned outcome')
    counts = {key: 0 for key in OUTCOMES}
    latencies = []
    results = []
    seen = set()
    scenario = model(policy['competitor_rate_per_second'], policy['max_competition_probability'], [])
    for row in trials:
        fields(row, ('trial_id', 'header_sha256', 'expected_artifacts_sha256',
                     'outcome', 'clock_domain', 'winner_observed_ns',
                     'terminal_observed_ns', 'deadline_ns', 'stages',
                     'missing_timing_reason'), 'trial observation')
        key = text(row['trial_id'], 'trial ID')
        require(key in identities and key not in seen, 'unknown or duplicate observed trial')
        seen.add(key)
        for name in ('header_sha256', 'expected_artifacts_sha256'):
            require(row[name] == identities[key][name], 'trial statement mismatch: ' + name)
        outcome = row['outcome']
        require(type(outcome) is str and outcome in OUTCOMES, 'unknown trial outcome')
        counts[outcome] += 1
        measured = row['winner_observed_ns'] is not None
        result = {'trial_id': key, 'outcome': outcome, 'latency_seconds': None,
                  'poisson_latency_screen': 'UNKNOWN', 'original_confirmation_necessary_screen': 'UNKNOWN'}
        if not measured:
            require(all(row[name] is None for name in
                        ('clock_domain', 'terminal_observed_ns', 'deadline_ns', 'stages')),
                    'partial or substituted clock is not a winner latency')
            text(row['missing_timing_reason'], 'missing timing reason')
        else:
            require(row['missing_timing_reason'] is None, 'measured clock has missing-timing reason')
            clock = text(row['clock_domain'], 'observer monotonic clock domain')
            start = ns(row['winner_observed_ns'], 'winner time')
            end = ns(row['terminal_observed_ns'], 'terminal time')
            deadline = ns(row['deadline_ns'], 'absolute deadline')
            require(start <= end, 'terminal precedes winner')
            require(start + policy['timeout_after_winner_ns'] <= MAX_NS and
                    deadline == start + policy['timeout_after_winner_ns'],
                    'original absolute deadline changed')
            stages = row['stages']
            require(type(stages) is list and 0 < len(stages) <= len(PHASES[policy['endpoint']]),
                    'bounded critical-path stages required')
            expected_phases = PHASES[policy['endpoint']]
            previous = start
            for i, stage in enumerate(stages):
                fields(stage, ('phase', 'clock_domain', 'start_ns', 'end_ns'), 'stage')
                require(stage['phase'] == expected_phases[i], 'phase omitted, reordered or duplicated')
                require(stage['clock_domain'] == clock, 'cross-clock subtraction is forbidden')
                a = ns(stage['start_ns'], 'phase start')
                b = ns(stage['end_ns'], 'phase end')
                require(a == previous and a <= b <= end, 'phase gap, overlap or negative duration')
                previous = b
            require(previous == end, 'unaccounted critical-path wall time')
            if outcome == 'success':
                require(len(stages) == len(expected_phases), 'success lacks the declared endpoint')
            if outcome == 'timeout':
                require(end >= deadline, 'timeout declared before original deadline')
            elapsed = (end - start) / 1e9
            complete_success = outcome == 'success' and end <= deadline
            within_model = elapsed <= scenario['latency_budget_seconds']
            result.update(latency_seconds=elapsed,
                          poisson_latency_screen=('FINITE_SCREEN_PASS' if complete_success and within_model else
                                          'UNKNOWN' if outcome == 'unknown' and within_model and end <= deadline
                                          else 'FAIL'),
                          elapsed_interval_kind='winner-to-declared-endpoint' if outcome == 'success'
                          else 'winner-to-failed-or-interrupted-terminal',
                          terminal_at_or_before_original_deadline=end <= deadline,
                          endpoint_completed_within_original_timeout=complete_success)
            if policy['original_confirmation_budget_ns'] is not None:
                result['original_confirmation_necessary_screen'] = (
                    'FINITE_NECESSARY_SCREEN_PASS' if complete_success and
                    end - start <= policy['original_confirmation_budget_ns'] else
                    'UNKNOWN' if outcome == 'unknown' and end <= deadline and
                    end - start <= policy['original_confirmation_budget_ns'] else 'FAIL')
            # A late successful endpoint is a real (slow) observation. Keep it
            # in the complete finite distribution; it still fails its deadline.
            if outcome == 'success':
                latencies.append(elapsed)
        if outcome not in ('success', 'unknown'):
            result['poisson_latency_screen'] = 'FAIL'
            if policy['original_confirmation_budget_ns'] is not None:
                result['original_confirmation_necessary_screen'] = 'FAIL'
        results.append(result)
    require(seen == set(identities), 'planned outcome omitted')
    # No conditional-on-success tail statistic: every predeclared trial must
    # actually reach the endpoint with an observed winner clock. Late successes
    # remain in this denominator; timeout/canceled/unknown endpoints do not.
    complete = len(latencies) == len(identities)
    quantiles = None
    empirical = None
    if complete:
        values = sorted(latencies)
        quantiles = {name: values[math.ceil(q * len(values)) - 1]
                     for name, q in [('p50', .50), ('p95', .95), ('p99', .99)]}
        probabilities = [math.exp(-policy['competitor_rate_per_second'] * value)
                         for value in latencies]
        empirical = math.fsum(probabilities) / len(probabilities)
    screens = [row['poisson_latency_screen'] for row in results]
    screen = ('FAIL' if 'FAIL' in screens else
              'FINITE_SCREEN_PASS' if complete else 'UNKNOWN')
    confirmation_screens = [row['original_confirmation_necessary_screen'] for row in results]
    confirmation_screen = (
        'NOT_APPLIED' if policy['original_confirmation_budget_ns'] is None else
        'FAIL' if 'FAIL' in confirmation_screens else
        'FINITE_NECESSARY_SCREEN_PASS' if all(value == 'FINITE_NECESSARY_SCREEN_PASS'
                                             for value in confirmation_screens) else 'UNKNOWN')
    return {
        'schema': REPORT_SCHEMA,
        'campaign_id': policy['campaign_id'],
        'source_commit': policy['source_commit'],
        'profile_id': policy['profile_id'],
        'endpoint': policy['endpoint'],
        'policy_sha256': expected_policy_sha256,
        'observations_sha256': hashlib.sha256(observations_raw).hexdigest(),
        'scope': 'declaration-bound finite accounting; not authenticated timing or proof verification',
        'planned_trials': len(identities),
        'retained_outcomes': counts,
        'all_planned_trials_reached_endpoint_with_observed_winner_clock': complete,
        'all_planned_trials_completed_within_original_timeout': complete and
            all(row.get('endpoint_completed_within_original_timeout') is True for row in results),
        'finite_poisson_latency_screen': screen,
        'finite_original_confirmation_necessary_screen': confirmation_screen,
        'poisson_model': scenario,
        'trials': results,
        'finite_nearest_rank_quantiles_seconds': quantiles,
        'empirical_mean_no_competitor_probability': empirical,
        'empirical_probability_scope': 'mean(exp(-lambda*L_i)) only if every declared trial completes; not exp(-lambda*mean(L))',
        'population_prover_p99_seconds': None,
        'stale_block_probability': None,
        'independent_proof_trials_established': False,
        'measurement_authentication_performed': False,
        'cryptographic_verification_performed': False,
        'production_activation': False,
        'consensus_admission': False,
        'disposition': 'HOLD_NO_GO',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    arithmetic = sub.add_parser('model', help='explicitly hypothetical Poisson illustration')
    arithmetic.add_argument('--competitor-rate-per-second', type=float, required=True)
    arithmetic.add_argument('--max-competition-probability', type=float, required=True)
    arithmetic.add_argument('--latency-seconds', type=float, nargs='*', default=[])
    read = sub.add_parser('evaluate', help='read a separately pinned planned campaign')
    read.add_argument('--policy', type=Path, required=True)
    read.add_argument('--observations', type=Path, required=True)
    read.add_argument('--expected-policy-sha256', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'model':
            report = model(args.competitor_rate_per_second, args.max_competition_probability,
                           args.latency_seconds)
        else:
            report = evaluate(read_regular(args.policy, 4 * 1024 * 1024),
                              read_regular(args.observations, 32 * 1024 * 1024),
                              args.expected_policy_sha256)
        print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError) as error:
        print('proof latency input rejected: ' + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
