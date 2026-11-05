#!/usr/bin/env python3
"""Post-hoc W1 zero-v2 paired cost accounting, not proof or hardware qualification.

Run the existing native/schema/artifact checks first. This independent observer
binds the supplied raw bytes, checks the complete pairing and computes exact
ratios. It never changes the native report, selects a production implementation,
sets a performance gate, or replaces check_zero_locality_cost.py.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import sys

STRATEGIES = ('prepared-generic', 'structured-zero-reference', 'blocked-zero',
              'paired-product', 'blocked-zero-integer-paired')
MODES = ('cold-per-search', 'reused-one-setup')
TARGETS = tuple(prefix + 'ff' * 31 for prefix in ('7f', '07'))
FALSE_FLAGS = ('fastest_adversary_qualified', 'work_hardness_accepted',
               'public_service_measured', 'input_provenance_verified', 'production_activation')
CLOCKS = frozenset(('setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns',
                   'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns'))
WINNER_FIELDS = ('winning_challenge', 'winner_proof_commitment',
                 'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns',
                 'reference_verifier_first')
TIMING_SCOPE = {
    'actual_setup_per_mode': True,
    'all_attempts_including_target_misses': True,
    'challenge_ticket_and_full_proof_stream_hashing_in_search': True,
    'material_generation_rank_checks_and_cross_strategy_comparison_timed': False,
    'verifier_timing_after_generation': True,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError('paired zero cost: ' + message)


def natural(value, message: str, *, positive: bool = False) -> int:
    require(type(value) is int and value >= int(positive), message)
    return value


def ratio(numerator: int, denominator: int) -> dict | None:
    """Keep the actual integer totals; a zero denominator is unknown, not zero."""
    natural(numerator, 'ratio numerator')
    natural(denominator, 'ratio denominator')
    return {'numerator': numerator, 'denominator': denominator} if denominator else None


def projection(value):
    """Only clocks may differ, including between architectures; retain all else."""
    if isinstance(value, dict):
        return {key: (len(item) if key == 'setup_observations_ns' else projection(item))
                for key, item in value.items() if key not in CLOCKS}
    if isinstance(value, list):
        return [projection(item) for item in value]
    return value


def canonical_digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def summarize_report(data: dict) -> dict:
    """Account for a complete v2 grid. This does not replay W1 cryptography."""
    require(type(data) is dict and data.get('schema') == 'pon-w1-zero-locality-v2',
            'explicit v2 only; historical schemas must not be relabelled')
    samples = natural(data['samples_per_case_target'], 'positive samples', positive=True)
    searches = natural(data['searches_per_cohort'], 'positive searches', positive=True)
    budget = natural(data['attempt_budget'], 'positive attempt budget', positive=True)
    natural(data['seed'], 'seed')
    require(data.get('zero_structure_only') is True and data.get('targets') == list(TARGETS),
            'retain zero-only structure and separate targets')
    require(data.get('timing') == 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting'
            and data.get('timing_scope') == TIMING_SCOPE
            and all(type(v) is bool for v in data['timing_scope'].values()), 'retain timing scope')
    require(all(data.get(key) is False for key in FALSE_FLAGS), 'no promoted acceptance flag')
    rows = data['observations']
    require(type(rows) is list and len(rows) == 20 * samples, 'complete two-target ten-arm grid')
    groups = defaultdict(dict)
    identities = set()
    for position, row in enumerate(rows):
        require(type(row) is dict, 'cohort object')
        sample = natural(row['sample'], 'sample')
        order = natural(row['invocation_order'], 'invocation order')
        require(row['target'] == TARGETS[position // (10 * samples)]
                and sample == (position // 10) % samples and order == position % 10,
                'retain target/sample/actual invocation order')
        invocation = (sample // 2 + (order if sample % 2 == 0 else 9 - order)) % 10
        require(row['strategy'] == STRATEGIES[invocation // 2]
                and row['mode'] == MODES[invocation % 2], 'complete balanced native arm order')
        require(row['class'] == 'zero' and row['input_source'] == 'synthetic-fixture'
                and natural(row['rank_a'], 'rank A') == 0
                and natural(row['rank_b'], 'rank B') == 0
                and natural(row['proof_bytes'], 'proof length') == 49188, 'unchanged zero relation scope')
        require(type(row['task']) is str and re.fullmatch('[0-9a-f]{64}', row['task']) is not None,
                'task digest shape')
        identities.add(row['task'])
        setups = row['setup_observations_ns']
        expected = searches if row['mode'] == 'cold-per-search' else 1
        require(type(setups) is list and len(setups) == expected
                and natural(row['setup_calls'], 'setup calls') == expected, 'retain all cold/reused setup calls')
        for elapsed in setups:
            natural(elapsed, 'setup clock')
        for field in ('setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns'):
            natural(row[field], field)
        require(row['setup_elapsed_ns'] == sum(setups), 'setup cost total')
        outcomes = row['outcomes']
        require(type(outcomes) is list and len(outcomes) == searches, 'retain every repeated search')
        for index, outcome in enumerate(outcomes):
            require(natural(outcome['search_index'], 'search index') == index, 'ordered search indices')
            require(outcome['status'] in ('winner', 'exhausted'), 'failed/unsupported is not an eligible arm')
            attempts = natural(outcome['attempts'], 'nonempty search', positive=True)
            require(attempts <= budget, 'attempt budget')
            natural(outcome['search_elapsed_ns'], 'search clock')
            for field in ('ticket_stream_commitment', 'proof_stream_commitment'):
                require(type(outcome[field]) is str and re.fullmatch('[0-9a-f]{64}', outcome[field])
                        is not None, 'complete attempted proof/ticket stream digest')
            if outcome['status'] == 'exhausted':
                require(attempts == budget and all(outcome[field] is None for field in WINNER_FIELDS),
                        'exhaustion consumes its budget and invents no winner')
            else:
                for field in ('winning_challenge', 'winner_proof_commitment'):
                    require(type(outcome[field]) is str and re.fullmatch('[0-9a-f]{64}', outcome[field])
                            is not None, 'winner digest shape')
                for field in ('production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns'):
                    natural(outcome[field], field)
                require(type(outcome['reference_verifier_first']) is bool
                        and outcome['reference_verifier_first'] == ((sample + index) % 2 == 0),
                        'actual verifier order')
        require(row['search_elapsed_ns'] == sum(o['search_elapsed_ns'] for o in outcomes)
                and row['total_elapsed_ns'] == row['setup_elapsed_ns'] + row['search_elapsed_ns'],
                'retain setup, every miss and every exhausted search in generation cost')
        group = groups[(row['target'], row['mode'])]
        key = row['strategy'], sample
        require(key not in group, 'no duplicate cohort')
        group[key] = row
    require(len(identities) == 1, 'one task across every target and arm')
    # Compare modes too: reuse must not change the challenge/proof/ticket stream.
    for target in TARGETS:
        for sample in range(samples):
            baseline = projection(groups[(target, MODES[0])][(STRATEGIES[0], sample)]['outcomes'])
            for mode in MODES:
                for strategy in STRATEGIES:
                    require(projection(groups[(target, mode)][(strategy, sample)]['outcomes']) == baseline,
                            'same complete outcomes and streams across all paired arms and modes')
    result = []
    for target in TARGETS:
        for mode in MODES:
            group = groups[(target, mode)]
            arms = []
            for strategy in STRATEGIES:
                cohorts = [group[(strategy, sample)] for sample in range(samples)]
                outcomes = [outcome for row in cohorts for outcome in row['outcomes']]
                setup = sum(row['setup_elapsed_ns'] for row in cohorts)
                search = sum(row['search_elapsed_ns'] for row in cohorts)
                total = setup + search
                attempts = sum(o['attempts'] for o in outcomes)
                winners = sum(o['status'] == 'winner' for o in outcomes)
                verifier = sum(o['production_verifier_elapsed_ns'] or 0 for o in outcomes)
                reference = sum(o['reference_verifier_elapsed_ns'] or 0 for o in outcomes)
                arms.append({'strategy': strategy, 'samples': samples, 'searches': len(outcomes),
                    'attempts': attempts, 'winners': winners, 'exhausted': len(outcomes) - winners,
                    'target_misses': attempts - winners, 'setup_elapsed_ns': setup,
                    'search_elapsed_ns': search, 'generation_elapsed_ns': total,
                    'production_verifier_elapsed_ns': verifier, 'reference_verifier_elapsed_ns': reference,
                    'generation_ns_per_attempt': ratio(total, attempts),
                    'generation_ns_per_winner': ratio(total, winners),
                    'production_verifier_ns_per_winner': ratio(verifier, winners),
                    'observed_generation_to_production_verifier_ratio': ratio(total, verifier),
                    'cohorts': [{'sample': row['sample'], 'invocation_order': row['invocation_order'],
                        'setup_calls': row['setup_calls'], 'generation_elapsed_ns': row['total_elapsed_ns'],
                        'attempts': sum(o['attempts'] for o in row['outcomes']),
                        'winners': sum(o['status'] == 'winner' for o in row['outcomes']),
                        'exhausted': sum(o['status'] == 'exhausted' for o in row['outcomes']),
                        'generation_ns_per_winner': ratio(row['total_elapsed_ns'],
                            sum(o['status'] == 'winner' for o in row['outcomes']))} for row in cohorts],
                    'comparisons': [{'reference_strategy': baseline,
                        'aggregate_cost_ratio': ratio(total, sum(group[(baseline, s)]['total_elapsed_ns']
                                                                 for s in range(samples))),
                        'paired_samples': [{'sample': s,
                            'candidate_invocation_order': group[(strategy, s)]['invocation_order'],
                            'reference_invocation_order': group[(baseline, s)]['invocation_order'],
                            'cost_ratio': ratio(group[(strategy, s)]['total_elapsed_ns'],
                                                group[(baseline, s)]['total_elapsed_ns'])}
                            for s in range(samples)]}
                        for baseline in ('prepared-generic', 'blocked-zero')]})
            # No hindsight switching between samples; each candidate is one fixed arm.
            # A zero clock total does not establish infinite speed or a fastest arm.
            best = None
            if all(arm['generation_elapsed_ns'] > 0 for arm in arms):
                lowest = min(Fraction(arm['generation_elapsed_ns'], arm['attempts']) for arm in arms)
                best = [arm['strategy'] for arm in arms
                        if Fraction(arm['generation_elapsed_ns'], arm['attempts']) == lowest]
            result.append({'target': target, 'mode': mode, 'arms': arms,
                           'lowest_observed_fixed_arms': best})
    return {'schema': 'pon-w1-zero-paired-cost-accounting-v1', 'native_schema': data['schema'],
        'seed': data['seed'], 'samples_per_case_target': samples, 'searches_per_cohort': searches,
        'attempt_budget': budget, 'task': next(iter(identities)), 'timing': data['timing'],
        'timing_scope': data['timing_scope'], 'groups': result,
        'stream_projection_sha256': canonical_digest(projection(data)),
        'scope': 'post-hoc-arithmetic-and-pairing-only', 'proof_correctness_replayed': False,
        'native_artifact_authenticity_established': False, 'speed_threshold_applied': False,
        'independent_hardware_qualified': False, 'confidence_interval_established': False,
        **{key: False for key in FALSE_FLAGS}}


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field ' + key)
        result[key] = value
    return result


def read_bound_report(path: Path, expected_sha256: str) -> tuple[dict, str]:
    require(type(expected_sha256) is str and re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None,
            'explicit expected SHA-256')
    require(path.is_file() and not path.is_symlink(), 'regular non-symlink report')
    with path.open('rb') as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    require(len(raw) <= 16 * 1024 * 1024, 'report size bound')
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == expected_sha256, 'raw report differs from the selected retained bytes')
    def invalid_constant(value):
        raise ValueError('paired zero cost: non-finite JSON ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant), digest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--x64', type=Path, required=True)
    parser.add_argument('--x64-sha256', required=True)
    parser.add_argument('--arm64', type=Path, required=True)
    parser.add_argument('--arm64-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        loaded = {arch: read_bound_report(getattr(args, arch), getattr(args, arch + '_sha256'))
                  for arch in ('x64', 'arm64')}
        summaries = {arch: summarize_report(data) for arch, (data, _) in loaded.items()}
        require(projection(loaded['x64'][0]) == projection(loaded['arm64'][0]),
                'same complete non-clock observations across architectures')
        result = {'schema': 'pon-w1-zero-paired-cross-arch-accounting-v1',
            'architecture_labels': 'caller-supplied; validate native manifests separately',
            'observer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'input_sha256': {arch: digest for arch, (_, digest) in loaded.items()},
            'architectures': summaries}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + '\n')
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
