#!/usr/bin/env python3
"""Validate the fixed genesis-maintenance experiment without granting work qualification."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib

from check_cross_arch_cost import (FALSE_FLAGS, MODES, TARGETS, TIMING_SCOPE,
                                   deterministic_projection, hash_text, natural,
                                   projection_digest, require)

MATERIAL_CLASS = 'continuity-maintenance-v1'
MATERIAL_SOURCE = 'genesis-policy-public-deterministic-fixture'
MATERIAL_TASK = 'c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496'
TASK_PROFILE = 'consensus-maintenance-continuity-dev-v1'
V1_SCHEMA = 'pon-w1-maintenance-paired-v1'
V2_SCHEMA = 'pon-w1-maintenance-preprocessing-v2'
V3_SCHEMA = 'pon-w1-maintenance-prefix-v3'
V1_STRATEGIES = ['prepared-generic', 'tiled-classical', 'tiled-strassen-one-level', 'paired-product']
V2_STRATEGIES = V1_STRATEGIES + ['maintenance-periodic-setup']
STRATEGIES = V2_STRATEGIES + ['maintenance-integer-paired', 'maintenance-periodic-prefix']
METHODS = {'prepared-generic': 'generic-product-and-transcript',
           'tiled-classical': 'tiled-classical-full-transcript',
           'tiled-strassen-one-level': 'tiled-strassen-one-level-full-transcript',
           'paired-product': 'paired-field-products-full-prefix-transcript',
           'maintenance-periodic-setup': 'maintenance-periodic-setup-full-transcript',
           'maintenance-integer-paired': 'maintenance-integer-paired-full-transcript',
           'maintenance-periodic-prefix': 'maintenance-periodic-prefix-integer-paired-full-transcript'}


def winning_challenge(task: str, seed: int, sample: int, search_index: int,
                      target: str, nonce: int) -> str:
    tag = b'maintenance-paired-cost-v1'
    value = hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag)
    for part in [bytes.fromhex(task), seed.to_bytes(8, 'little'), sample.to_bytes(8, 'little'),
                 search_index.to_bytes(8, 'little'), bytes.fromhex(target), nonce.to_bytes(8, 'little')]:
        value.update(len(part).to_bytes(4, 'little') + part)
    return value.hexdigest()


def validate_maintenance_report(data: dict, campaign: dict, *, version: int | None = None) -> dict:
    require(type(data) is dict and set(data) == {
        'schema', 'genesis_maintenance_material_only', 'task_profile', 'timing', 'timing_scope',
        'targets', 'seed', 'samples_per_case_target', 'searches_per_cohort', 'attempt_budget',
        'observations', *FALSE_FLAGS}, 'exact fixed-maintenance native fields')
    schemas = {1: V1_SCHEMA, 2: V2_SCHEMA, 3: V3_SCHEMA}
    require(version is None or type(version) is int and version in schemas,
            'explicit historical or current maintenance version')
    require(data['schema'] in schemas.values() and
            (version is None or data['schema'] == schemas[version]) and
            data['genesis_maintenance_material_only'] is True and data['task_profile'] == TASK_PROFILE,
            'fixed genesis policy material and profile cannot become general work qualification')
    strategies = {V1_SCHEMA: V1_STRATEGIES, V2_SCHEMA: V2_STRATEGIES, V3_SCHEMA: STRATEGIES}[data['schema']]
    arms = len(strategies) * len(MODES)
    require(data['timing'] == 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting',
            'maintenance experiment clock scope')
    require(data['targets'] == TARGETS, 'the same two finite maintenance targets')
    require(data['timing_scope'] == TIMING_SCOPE and
            all(type(value) is bool for value in data['timing_scope'].values()),
            'maintenance setup, misses, full-proof hashing and post-verifier scope')
    for field, argument in [('seed', 'seed'), ('samples_per_case_target', 'samples'),
                            ('searches_per_cohort', 'searches'), ('attempt_budget', 'attempt_budget')]:
        require(type(data[field]) is int and data[field] == campaign[argument],
                'exact maintenance argument echo ' + field)
    require(all(data[field] is False for field in FALSE_FLAGS),
            'maintenance experiment cannot promote hardness, fairness, provenance or service acceptance')
    rows = data['observations']
    require(type(rows) is list and len(rows) == 2 * campaign['samples'] * arms,
            'complete fixed-material/two-target/versioned-strategy/two-mode grid')
    statuses = Counter()
    groups = defaultdict(list)
    for position, row in enumerate(rows):
        require(type(row) is dict and set(row) == {
            'class', 'input_source', 'task', 'rank_a', 'rank_b', 'target', 'sample',
            'invocation_order', 'strategy', 'method', 'mode', 'proof_bytes',
            'setup_observations_ns', 'setup_calls', 'setup_elapsed_ns', 'search_elapsed_ns',
            'total_elapsed_ns', 'outcomes'}, 'exact maintenance cohort fields')
        require(row['class'] == MATERIAL_CLASS and row['input_source'] == MATERIAL_SOURCE and
                row['task'] == MATERIAL_TASK, 'fixed genesis-maintenance material bytes and source')
        require(natural(row['rank_a'], 'maintenance left rank') == 56 and
                natural(row['rank_b'], 'maintenance right rank') == 32,
                'fixed maintenance ranks cannot be replaced with a structural zero task')
        require(type(row['sample']) is int and type(row['invocation_order']) is int and
                row['target'] == TARGETS[position // (campaign['samples'] * arms)] and
                row['sample'] == (position // arms) % campaign['samples'] and
                row['invocation_order'] == position % arms,
                'native maintenance target/sample/invocation order remains complete')
        direction_offset = row['invocation_order'] if row['sample'] % 2 == 0 else arms - 1 - row['invocation_order']
        invocation = (row['sample'] // 2 + direction_offset) % arms
        require(row['strategy'] == strategies[invocation // 2] and row['mode'] == MODES[invocation % 2],
                'each paired maintenance sample reverses its shared rotation across the exact versioned positions')
        require(row['method'] == METHODS[row['strategy']], 'actual selected maintenance producer method')
        require(type(row['proof_bytes']) is int and row['proof_bytes'] == 49188,
                'maintenance still emits the complete canonical W1 certificate')
        setups = row['setup_observations_ns']
        expected_setups = campaign['searches'] if row['mode'] == MODES[0] else 1
        require(type(setups) is list and len(setups) == expected_setups and
                natural(row['setup_calls'], 'maintenance constructor calls') == expected_setups and
                all(type(value) is int and value >= 0 for value in setups),
                'every producer retains actual cold/reused construction calls')
        for field in ['setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns']:
            natural(row[field], 'maintenance cohort clock ' + field)
        require(row['setup_elapsed_ns'] == sum(setups), 'maintenance setup time cannot disappear')
        outcomes = row['outcomes']
        require(type(outcomes) is list and len(outcomes) == campaign['searches'],
                'every bounded maintenance search remains in its original position')
        for index, outcome in enumerate(outcomes):
            require(type(outcome) is dict and set(outcome) == {
                'search_index', 'status', 'attempts', 'search_elapsed_ns', 'ticket_stream_commitment',
                'proof_stream_commitment', 'winning_challenge', 'winner_proof_commitment',
                'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns', 'reference_verifier_first'},
                'exact maintenance search outcome fields')
            require(type(outcome['search_index']) is int and outcome['search_index'] == index,
                    'ordered maintenance repeated searches')
            require(outcome['status'] in {'winner', 'exhausted'},
                    'unsupported or failed required maintenance producer cannot be accepted')
            statuses[outcome['status']] += 1
            attempts = natural(outcome['attempts'], 'maintenance attempted candidates')
            require(0 < attempts <= campaign['attempt_budget'], 'finite nonempty maintenance search')
            natural(outcome['search_elapsed_ns'], 'maintenance actual search clock')
            for field in ['ticket_stream_commitment', 'proof_stream_commitment']:
                hash_text(outcome[field], 'every maintenance attempted ticket and complete proof stream')
            if outcome['status'] == 'exhausted':
                require(attempts == campaign['attempt_budget'], 'maintenance exhaustion consumes the exact budget')
                require(all(outcome[field] is None for field in [
                    'winning_challenge', 'winner_proof_commitment', 'production_verifier_elapsed_ns',
                    'reference_verifier_elapsed_ns', 'reference_verifier_first']),
                    'exhausted maintenance searches cannot invent a winner or verifier')
            else:
                require(outcome['winning_challenge'] == winning_challenge(
                    row['task'], campaign['seed'], row['sample'], index, row['target'], attempts - 1),
                    'maintenance winner binds the fresh challenge domain and full deterministic search')
                hash_text(outcome['winner_proof_commitment'], 'maintenance complete winning proof')
                natural(outcome['production_verifier_elapsed_ns'], 'maintenance production verifier clock')
                natural(outcome['reference_verifier_elapsed_ns'], 'maintenance reference verifier clock')
                require(type(outcome['reference_verifier_first']) is bool and
                        outcome['reference_verifier_first'] == ((row['sample'] + index) % 2 == 0),
                        'maintenance verification order alternates between actual full validators')
        require(row['search_elapsed_ns'] == sum(value['search_elapsed_ns'] for value in outcomes),
                'all winning and exhausted maintenance search costs are retained')
        require(row['total_elapsed_ns'] == row['setup_elapsed_ns'] + row['search_elapsed_ns'],
                'maintenance total includes every construction and search cost')
        groups[(row['target'], row['sample'])].append(row)
    require(len(groups) == 2 * campaign['samples'], 'complete maintenance target/sample groups')
    for group in groups.values():
        require(len(group) == arms and {(row['strategy'], row['mode']) for row in group} ==
                {(strategy, mode) for strategy in strategies for mode in MODES},
                'every maintenance producer and reuse mode actually executes')
        baseline = next(row for row in group if row['strategy'] == 'prepared-generic' and row['mode'] == MODES[0])
        expected = deterministic_projection(baseline['outcomes'])
        require(all(deterministic_projection(row['outcomes']) == expected for row in group),
                'every maintenance producer/mode must preserve full proof and ticket streams')
    return {'rows': len(rows), 'outcomes': sum(statuses.values()), 'statuses': dict(statuses),
            'deterministic_projection_sha256': projection_digest(data)}


def validate_maintenance_v1_report(data: dict, campaign: dict) -> dict:
    """Historical four-strategy meaning; never accepts a relabelled v2 grid."""
    return validate_maintenance_report(data, campaign, version=1)


def validate_maintenance_v2_report(data: dict, campaign: dict) -> dict:
    """Historical five-strategy execution retains its exact grid and source set."""
    return validate_maintenance_report(data, campaign, version=2)


def validate_maintenance_v3_report(data: dict, campaign: dict) -> dict:
    """Current seven-strategy prefix experiment cannot substitute a v1/v2 grid."""
    return validate_maintenance_report(data, campaign, version=3)
