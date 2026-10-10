#!/usr/bin/env python3
"""Strict one-zero/rank-one native costs; no general workload or speed acceptance."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib

from check_cross_arch_cost import (FALSE_FLAGS, MODES, TARGETS, TIMING_SCOPE,
                                   deterministic_projection, hash_text, natural,
                                   projection_digest, require)

MATERIALS = {
    'left-zero-rank-one': (0, 1, 'fde0e480d2cdc414c17eeb58909b0c349ac6a0af1572ceead65fa5227b64f027'),
    'right-zero-rank-one': (1, 0, 'a311ab05c13b5472c437485ee693c7f98fbb69fe3b18869bf1f3706c3867cca9'),
}
STRATEGIES = ['prepared-generic', 'structured-zero-product-reference', 'blocked-one-zero-rank-one']
METHODS = {'prepared-generic': 'generic-product-and-transcript',
           'structured-zero-product-reference': 'zero-product-full-transcript',
           'blocked-one-zero-rank-one': 'blocked-one-zero-rank-one-full-prefix-transcript'}


def winning_challenge(task: str, seed: int, sample: int, search_index: int,
                      target: str, nonce: int) -> str:
    # This fresh domain cannot be substituted with the older reused-cost-v1 stream.
    tag = b'one-zero-locality-cost-v1'
    value = hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag)
    for part in [bytes.fromhex(task), seed.to_bytes(8, 'little'), sample.to_bytes(8, 'little'),
                 search_index.to_bytes(8, 'little'), bytes.fromhex(target), nonce.to_bytes(8, 'little')]:
        value.update(len(part).to_bytes(4, 'little') + part)
    return value.hexdigest()


def validate_one_zero_report(data: dict, campaign: dict) -> dict:
    require(type(data) is dict and set(data) == {
        'schema', 'one_zero_rank_one_structure_only', 'timing', 'timing_scope', 'targets', 'seed',
        'samples_per_case_target', 'searches_per_cohort', 'attempt_budget',
        'observations', *FALSE_FLAGS}, 'exact one-zero-locality native report fields')
    require(data['schema'] == 'pon-w1-one-zero-locality-v1' and data['one_zero_rank_one_structure_only'] is True,
            'one-zero/rank-one-only scope cannot be relabelled as a general workload')
    require(data['timing'] == 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting',
            'one-zero-locality clock scope')
    require(data['targets'] == TARGETS, 'same two explicit finite targets')
    require(data['timing_scope'] == TIMING_SCOPE and
            all(type(v) is bool for v in data['timing_scope'].values()),
            'one-zero-locality setup, misses and full-proof hashing scope')
    for field, argument in [('seed', 'seed'), ('samples_per_case_target', 'samples'),
                            ('searches_per_cohort', 'searches'), ('attempt_budget', 'attempt_budget')]:
        require(type(data[field]) is int and data[field] == campaign[argument],
                'exact one-zero-locality argument echo ' + field)
    require(all(data[field] is False for field in FALSE_FLAGS),
            'one-zero/rank-one-only observations cannot promote work, hardware or service acceptance')
    rows = data['observations']
    require(isinstance(rows, list) and len(rows) == 2 * 2 * campaign['samples'] * 6,
            'complete two-material/two-target/three-strategy/two-mode grid')
    statuses = Counter()
    groups = defaultdict(list)
    material_order = list(MATERIALS)
    for position, row in enumerate(rows):
        require(type(row) is dict and set(row) == {
            'class', 'input_source', 'task', 'rank_a', 'rank_b', 'target', 'sample',
            'invocation_order', 'strategy', 'method', 'mode', 'proof_bytes',
            'setup_observations_ns', 'setup_calls', 'setup_elapsed_ns', 'search_elapsed_ns',
            'total_elapsed_ns', 'outcomes'}, 'exact one-zero-locality cohort fields')
        require(row['class'] in MATERIALS and row['input_source'] == 'synthetic-fixture',
                'two exact synthetic one-zero/rank-one materials')
        ranks = (natural(row['rank_a'], 'left matrix rank'), natural(row['rank_b'], 'right matrix rank'))
        require((*ranks, row['task']) == MATERIALS[row['class']],
                'exact asymmetric rank and task identity')
        require(type(row['sample']) is int and type(row['invocation_order']) is int and
                row['class'] == material_order[position // (2 * campaign['samples'] * 6)] and
                row['target'] == TARGETS[(position // (campaign['samples'] * 6)) % 2] and
                row['sample'] == (position // 6) % campaign['samples'] and
                row['invocation_order'] == position % 6,
                'all target/sample/rotation positions retain their actual native order')
        invocation = (row['sample'] + row['invocation_order']) % 6
        require(row['strategy'] == STRATEGIES[invocation // 2] and
                row['mode'] == MODES[invocation % 2], 'six rotating native invocation orders within each material')
        require(row['method'] == METHODS[row['strategy']], 'exact selected one-zero/rank-one producer method')
        require(type(row['proof_bytes']) is int and row['proof_bytes'] == 49188,
                'complete canonical W1 proof length')
        setups = row['setup_observations_ns']
        expected_setups = campaign['searches'] if row['mode'] == 'cold-per-search' else 1
        require(isinstance(setups, list) and len(setups) == expected_setups and
                natural(row['setup_calls'], 'actual one-zero/rank-one setup calls') == expected_setups and
                all(type(v) is int and v >= 0 for v in setups),
                'all three producers perform actual cold or reused construction')
        for field in ['setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns']:
            natural(row[field], 'one-zero-locality cohort clock ' + field)
        require(row['setup_elapsed_ns'] == sum(setups), 'all actual setup cost retained')
        outcomes = row['outcomes']
        require(isinstance(outcomes, list) and len(outcomes) == campaign['searches'],
                'every one-zero-locality repeated search retained')
        for index, outcome in enumerate(outcomes):
            require(type(outcome) is dict and set(outcome) == {
                'search_index', 'status', 'attempts', 'search_elapsed_ns',
                'ticket_stream_commitment', 'proof_stream_commitment', 'winning_challenge',
                'winner_proof_commitment', 'production_verifier_elapsed_ns',
                'reference_verifier_elapsed_ns', 'reference_verifier_first'},
                'exact one-zero-locality outcome fields')
            require(type(outcome['search_index']) is int and outcome['search_index'] == index,
                    'ordered one-zero-locality searches')
            require(outcome['status'] in {'winner', 'exhausted'},
                    'unsupported constructor or failure cannot be a successful one-zero/rank-one observation')
            statuses[outcome['status']] += 1
            attempts = natural(outcome['attempts'], 'actual one-zero/rank-one candidates attempted')
            require(0 < attempts <= campaign['attempt_budget'], 'finite nonempty one-zero/rank-one search')
            natural(outcome['search_elapsed_ns'], 'actual one-zero/rank-one search clock')
            for field in ['ticket_stream_commitment', 'proof_stream_commitment']:
                hash_text(outcome[field], 'every attempted one-zero/rank-one ticket and full-proof stream')
            if outcome['status'] == 'exhausted':
                require(attempts == campaign['attempt_budget'], 'one-zero/rank-one exhaustion consumes its full budget')
                require(all(outcome[field] is None for field in [
                    'winning_challenge', 'winner_proof_commitment',
                    'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns',
                    'reference_verifier_first']), 'no invented winner or verifier on exhaustion')
            else:
                require(outcome['winning_challenge'] == winning_challenge(
                    row['task'], campaign['seed'], row['sample'], index, row['target'], attempts - 1),
                    'one-zero/rank-one winner binds its fresh domain and complete challenge stream')
                hash_text(outcome['winner_proof_commitment'], 'complete one-zero/rank-one winner proof commitment')
                natural(outcome['production_verifier_elapsed_ns'], 'actual one-zero/rank-one production verification')
                natural(outcome['reference_verifier_elapsed_ns'], 'actual one-zero/rank-one reference verification')
                require(type(outcome['reference_verifier_first']) is bool and
                        outcome['reference_verifier_first'] == ((row['sample'] + index) % 2 == 0),
                        'one-zero/rank-one verifier runs alternate actual order')
        require(row['search_elapsed_ns'] == sum(value['search_elapsed_ns'] for value in outcomes),
                'one-zero/rank-one search cost includes all winning and exhausted outcomes')
        require(row['total_elapsed_ns'] == row['setup_elapsed_ns'] + row['search_elapsed_ns'],
                'one-zero/rank-one setup amortization does not hide search or construction cost')
        groups[(row['class'], row['target'], row['sample'])].append(row)
    require(len(groups) == 2 * 2 * campaign['samples'], 'complete one-zero material/target/sample groups')
    for group in groups.values():
        require(len(group) == 6 and {(row['strategy'], row['mode']) for row in group} ==
                {(strategy, mode) for strategy in STRATEGIES for mode in MODES},
                'every one-zero/rank-one strategy and reuse mode actually executes')
        baseline = next(row for row in group if row['strategy'] == 'prepared-generic' and
                        row['mode'] == 'cold-per-search')
        expected = deterministic_projection(baseline['outcomes'])
        for row in group:
            require(deterministic_projection(row['outcomes']) == expected,
                    'all one-zero/rank-one producers and modes retain the same full proof and ticket streams')
    return {'rows': len(rows), 'outcomes': sum(statuses.values()), 'statuses': dict(statuses),
            'deterministic_projection_sha256': projection_digest(data)}
