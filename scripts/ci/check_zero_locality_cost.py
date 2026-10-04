#!/usr/bin/env python3
"""Strict zero-only native cost schema; no general workload or speed acceptance."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib

from check_cross_arch_cost import (FALSE_FLAGS, MATERIALS, MODES, TARGETS, TIMING_SCOPE,
                                   deterministic_projection, hash_text, natural,
                                   projection_digest, require)

STRATEGIES = ['prepared-generic', 'structured-zero-reference', 'blocked-zero']
METHODS = {'prepared-generic': 'generic-product-and-transcript',
           'structured-zero-reference': 'zero-reassociated-transcript',
           'blocked-zero': 'blocked-zero-full-prefix-transcript'}


def winning_challenge(task: str, seed: int, sample: int, search_index: int,
                      target: str, nonce: int) -> str:
    # This fresh domain cannot be substituted with the older reused-cost-v1 stream.
    tag = b'zero-locality-cost-v1'
    value = hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag)
    for part in [bytes.fromhex(task), seed.to_bytes(8, 'little'), sample.to_bytes(8, 'little'),
                 search_index.to_bytes(8, 'little'), bytes.fromhex(target), nonce.to_bytes(8, 'little')]:
        value.update(len(part).to_bytes(4, 'little') + part)
    return value.hexdigest()


def validate_zero_report(data: dict, campaign: dict) -> dict:
    require(type(data) is dict and set(data) == {
        'schema', 'zero_structure_only', 'timing', 'timing_scope', 'targets', 'seed',
        'samples_per_case_target', 'searches_per_cohort', 'attempt_budget',
        'observations', *FALSE_FLAGS}, 'exact zero-locality native report fields')
    require(data['schema'] == 'pon-w1-zero-locality-v1' and data['zero_structure_only'] is True,
            'zero-only scope cannot be relabelled as a general workload')
    require(data['timing'] == 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting',
            'zero-locality clock scope')
    require(data['targets'] == TARGETS, 'same two explicit finite targets')
    require(data['timing_scope'] == TIMING_SCOPE and
            all(type(v) is bool for v in data['timing_scope'].values()),
            'zero-locality setup, misses and full-proof hashing scope')
    for field, argument in [('seed', 'seed'), ('samples_per_case_target', 'samples'),
                            ('searches_per_cohort', 'searches'), ('attempt_budget', 'attempt_budget')]:
        require(type(data[field]) is int and data[field] == campaign[argument],
                'exact zero-locality argument echo ' + field)
    require(all(data[field] is False for field in FALSE_FLAGS),
            'zero-only observations cannot promote work, hardware or service acceptance')
    rows = data['observations']
    require(isinstance(rows, list) and len(rows) == 2 * campaign['samples'] * 6,
            'complete zero-only two-target/three-strategy/two-mode grid')
    statuses = Counter()
    groups = defaultdict(list)
    for position, row in enumerate(rows):
        require(type(row) is dict and set(row) == {
            'class', 'input_source', 'task', 'rank_a', 'rank_b', 'target', 'sample',
            'invocation_order', 'strategy', 'method', 'mode', 'proof_bytes',
            'setup_observations_ns', 'setup_calls', 'setup_elapsed_ns', 'search_elapsed_ns',
            'total_elapsed_ns', 'outcomes'}, 'exact zero-locality cohort fields')
        require(row['class'] == 'zero' and row['input_source'] == 'synthetic-fixture' and
                row['task'] == MATERIALS['zero'][2], 'fixed zero material and task identity')
        require(natural(row['rank_a'], 'zero matrix rank') == 0 and
                natural(row['rank_b'], 'zero matrix rank') == 0, 'exact zero ranks')
        require(type(row['sample']) is int and type(row['invocation_order']) is int and
                row['target'] == TARGETS[position // (campaign['samples'] * 6)] and
                row['sample'] == (position // 6) % campaign['samples'] and
                row['invocation_order'] == position % 6,
                'all target/sample/rotation positions retain their actual native order')
        invocation = (row['sample'] + row['invocation_order']) % 6
        require(row['strategy'] == STRATEGIES[invocation // 2] and
                row['mode'] == MODES[invocation % 2], 'six rotating native invocation orders')
        require(row['method'] == METHODS[row['strategy']], 'exact selected zero producer method')
        require(type(row['proof_bytes']) is int and row['proof_bytes'] == 49188,
                'complete canonical W1 proof length')
        setups = row['setup_observations_ns']
        expected_setups = campaign['searches'] if row['mode'] == 'cold-per-search' else 1
        require(isinstance(setups, list) and len(setups) == expected_setups and
                natural(row['setup_calls'], 'actual zero setup calls') == expected_setups and
                all(type(v) is int and v >= 0 for v in setups),
                'all three producers perform actual cold or reused construction')
        for field in ['setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns']:
            natural(row[field], 'zero-locality cohort clock ' + field)
        require(row['setup_elapsed_ns'] == sum(setups), 'all actual setup cost retained')
        outcomes = row['outcomes']
        require(isinstance(outcomes, list) and len(outcomes) == campaign['searches'],
                'every zero-locality repeated search retained')
        for index, outcome in enumerate(outcomes):
            require(type(outcome) is dict and set(outcome) == {
                'search_index', 'status', 'attempts', 'search_elapsed_ns',
                'ticket_stream_commitment', 'proof_stream_commitment', 'winning_challenge',
                'winner_proof_commitment', 'production_verifier_elapsed_ns',
                'reference_verifier_elapsed_ns', 'reference_verifier_first'},
                'exact zero-locality outcome fields')
            require(type(outcome['search_index']) is int and outcome['search_index'] == index,
                    'ordered zero-locality searches')
            require(outcome['status'] in {'winner', 'exhausted'},
                    'unsupported constructor or failure cannot be a successful zero observation')
            statuses[outcome['status']] += 1
            attempts = natural(outcome['attempts'], 'actual zero candidates attempted')
            require(0 < attempts <= campaign['attempt_budget'], 'finite nonempty zero search')
            natural(outcome['search_elapsed_ns'], 'actual zero search clock')
            for field in ['ticket_stream_commitment', 'proof_stream_commitment']:
                hash_text(outcome[field], 'every attempted zero ticket and full-proof stream')
            if outcome['status'] == 'exhausted':
                require(attempts == campaign['attempt_budget'], 'zero exhaustion consumes its full budget')
                require(all(outcome[field] is None for field in [
                    'winning_challenge', 'winner_proof_commitment',
                    'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns',
                    'reference_verifier_first']), 'no invented winner or verifier on exhaustion')
            else:
                require(outcome['winning_challenge'] == winning_challenge(
                    row['task'], campaign['seed'], row['sample'], index, row['target'], attempts - 1),
                    'zero winner binds its fresh domain and complete challenge stream')
                hash_text(outcome['winner_proof_commitment'], 'complete zero winner proof commitment')
                natural(outcome['production_verifier_elapsed_ns'], 'actual zero production verification')
                natural(outcome['reference_verifier_elapsed_ns'], 'actual zero reference verification')
                require(type(outcome['reference_verifier_first']) is bool and
                        outcome['reference_verifier_first'] == ((row['sample'] + index) % 2 == 0),
                        'zero verifier runs alternate actual order')
        require(row['search_elapsed_ns'] == sum(value['search_elapsed_ns'] for value in outcomes),
                'zero search cost includes all winning and exhausted outcomes')
        require(row['total_elapsed_ns'] == row['setup_elapsed_ns'] + row['search_elapsed_ns'],
                'zero setup amortization does not hide search or construction cost')
        groups[(row['target'], row['sample'])].append(row)
    require(len(groups) == 2 * campaign['samples'], 'complete zero target/sample groups')
    for group in groups.values():
        require(len(group) == 6 and {(row['strategy'], row['mode']) for row in group} ==
                {(strategy, mode) for strategy in STRATEGIES for mode in MODES},
                'every zero strategy and reuse mode actually executes')
        baseline = next(row for row in group if row['strategy'] == 'prepared-generic' and
                        row['mode'] == 'cold-per-search')
        expected = deterministic_projection(baseline['outcomes'])
        for row in group:
            require(deterministic_projection(row['outcomes']) == expected,
                    'all zero producers and modes retain the same full proof and ticket streams')
    return {'rows': len(rows), 'outcomes': sum(statuses.values()), 'statuses': dict(statuses),
            'deterministic_projection_sha256': projection_digest(data)}
