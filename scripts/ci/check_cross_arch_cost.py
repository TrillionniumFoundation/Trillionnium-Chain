#!/usr/bin/env python3
"""Check retained native cost correctness and stream equality, never a speed target."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

from ci_observation import digest, source

ARCHITECTURES = {
    'x64': {'runner': 'ubuntu-24.04', 'runner_arch': 'X64', 'machine': 'x86_64',
            'target': 'x86_64-unknown-linux-gnu', 'elf_machine': 62},
    'arm64': {'runner': 'ubuntu-24.04-arm', 'runner_arch': 'ARM64', 'machine': 'aarch64',
              'target': 'aarch64-unknown-linux-gnu', 'elf_machine': 183},
}
CAMPAIGNS = [
    {'samples': 4, 'searches': 4, 'attempt_budget': 64, 'seed': 0},
    {'samples': 2, 'searches': 4, 'attempt_budget': 8, 'seed': 1},
]
STRATEGIES = ['scalar-original', 'prepared-generic', 'prepared-structured',
              'tiled-classical', 'tiled-strassen-one-level']
MODES = ['cold-per-search', 'reused-one-setup']
TARGETS = [prefix + 'ff' * 31 for prefix in ['7f', '07']]
# Fixed diagnostic materials, independently encoded/rank-checked over F_(2^32-5).
# This inventory binds the native stream; it is not workload provenance evidence.
MATERIALS = {
    'periodic-dense-fixture': (31, 37, '56dac087e1241f23d72e47421fee9b439d9c8e4ad7eab89598ed46f8c6e61f34'),
    'full-rank-field': (64, 64, '4c0a5e314f94185b12939f955f610b351c8164ffddc98448f2b888dd472391fe'),
    'zero': (0, 0, '6618f8a794517852f621993ccb6ac311c684e1db2b9d1d47166fa00a744c4c29'),
    'identity': (64, 64, 'e9e9e2bb493cf1e6f65ae53117bb69a3bc590ae47f98f3e574586d7ab834f038'),
    'rank-one': (1, 1, '3928df2604028b7376234282da5e32d8da27e069781f80a0d2b5e1a837bb72b6'),
    'sparse-diagonal': (64, 64, '91edd11278a79eef833bde27bc7645265c11cf0b902602019d23bb55e2a0d4d1'),
    'continuity-maintenance-v1': (56, 32, 'c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496'),
}
METHODS = {'scalar-original': 'scalar-full-generation', 'prepared-generic': 'generic-product-and-transcript',
           'tiled-classical': 'tiled-classical-full-transcript',
           'tiled-strassen-one-level': 'tiled-strassen-one-level-full-transcript'}
STRUCTURED_METHODS = {'zero': 'zero-reassociated-transcript', 'identity': 'left-identity-full-transcript',
                      'rank-one': 'rank-one-product-full-transcript',
                      'sparse-diagonal': 'diagonal-product-full-transcript'}
TIMING_SCOPE = {'actual_setup_per_mode': True, 'all_attempts_including_target_misses': True,
                'challenge_ticket_and_full_proof_stream_hashing_in_search': True,
                'material_generation_rank_checks_and_cross_strategy_comparison_timed': False,
                'verifier_timing_after_generation': True}
FALSE_FLAGS = ['fastest_adversary_qualified', 'work_hardness_accepted',
               'public_service_measured', 'input_provenance_verified', 'production_activation']
TIMINGS = {'setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns',
           'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns'}
SUITES = ('reused', 'zero-locality', 'one-zero-locality', 'maintenance-paired')
# These are command limits, not measured execution time or a completion promise.
# Every capture has a five-second TERM grace before KILL, including identity and
# build commands; retain that budget for all four independently captured suites.
COST_IDENTITY_TIMEOUT_SECONDS = 30
COST_BUILD_TIMEOUT_SECONDS = 900
COST_CAMPAIGN_TIMEOUT_SECONDS = 300
COST_TERMINATION_GRACE_SECONDS = 5
COST_JOB_OVERHEAD_SECONDS = 27 * 60
COST_JOB_TIMEOUT_MINUTES = 135


def cost_job_budget_seconds() -> int:
    captures = 3 + 1 + len(CAMPAIGNS)
    return len(SUITES) * (3 * COST_IDENTITY_TIMEOUT_SECONDS + COST_BUILD_TIMEOUT_SECONDS +
                         len(CAMPAIGNS) * COST_CAMPAIGN_TIMEOUT_SECONDS +
                         captures * COST_TERMINATION_GRACE_SECONDS) + COST_JOB_OVERHEAD_SECONDS


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError('cross-architecture cost: ' + message)


def natural(value, message: str) -> int:
    require(type(value) is int and value >= 0, message)
    return value


def hash_text(value, message: str) -> str:
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None, message)
    return value


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field ' + key)
        result[key] = value
    return result


def read_json(path: Path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024 * 1024,
            'missing, linked or oversized JSON observation')
    return json.loads(path.read_text(), object_pairs_hook=unique)


def elf_machine(path: Path) -> int:
    with path.open('rb') as stream:
        header = stream.read(20)
    require(len(header) == 20 and header[:6] == b'\x7fELF\x02\x01',
            'expected a native ELF64 little-endian executable')
    return int.from_bytes(header[18:20], 'little')


def validate_files(base: Path, files: dict) -> None:
    actual_files = {p.relative_to(base).as_posix() for p in base.rglob('*')
                    if p.is_file() and p.relative_to(base).as_posix() != 'manifest.json'}
    require(set(files) == actual_files, 'all original native outputs must remain inventoried')
    for name, value in files.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and not (base / relative).is_symlink(),
                'artifact path cannot escape or substitute a symlink')
        require((base / relative).resolve().is_relative_to(base.resolve()), 'artifact path containment')
        require(digest(base / relative) == hash_text(value, 'artifact digest'),
                'retained output bytes changed: ' + name)


def benchmark_arguments(campaign: dict) -> list[str]:
    return ['--samples', str(campaign['samples']), '--searches', str(campaign['searches']),
            '--attempt-budget', str(campaign['attempt_budget']), '--seed', str(campaign['seed'])]


def winning_challenge(task: str, seed: int, sample: int, search_index: int, target: str, nonce: int) -> str:
    tag = b'reused-cost-v1'
    value = hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag)
    for part in [bytes.fromhex(task), seed.to_bytes(8, 'little'), sample.to_bytes(8, 'little'),
                 search_index.to_bytes(8, 'little'), bytes.fromhex(target), nonce.to_bytes(8, 'little')]:
        value.update(len(part).to_bytes(4, 'little') + part)
    return value.hexdigest()


def deterministic_projection(value):
    """Drop only measured clock values; setup count and all stream bytes remain."""
    if isinstance(value, dict):
        return {key: (len(item) if key == 'setup_observations_ns' else deterministic_projection(item))
                for key, item in value.items() if key not in TIMINGS}
    if isinstance(value, list):
        return [deterministic_projection(item) for item in value]
    return value


def projection_digest(value) -> str:
    return hashlib.sha256(json.dumps(deterministic_projection(value), sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def validate_raw_report(data: dict, campaign: dict) -> dict:
    require(set(data) == {'schema', 'timing', 'timing_scope', 'targets', 'seed', 'samples_per_case_target',
                         'searches_per_cohort', 'attempt_budget', 'observations', *FALSE_FLAGS},
            'exact native report fields')
    require(data['schema'] == 'pon-w1-reused-search-v1', 'native schema')
    require(data['timing'] == 'monotonic-wall-elapsed-nanoseconds-not-cpu-accounting', 'clock scope')
    require(data['targets'] == TARGETS, 'same two explicit finite targets')
    require(data['timing_scope'] == TIMING_SCOPE and all(type(v) is bool for v in data['timing_scope'].values()),
            'setup, misses, hashing and verifier timing scope cannot be relabelled')
    for key, argument in [('seed', 'seed'), ('samples_per_case_target', 'samples'),
                          ('searches_per_cohort', 'searches'), ('attempt_budget', 'attempt_budget')]:
        require(data[key] == campaign[argument] and type(data[key]) is int, 'native argument echo ' + key)
    require(all(data[key] is False for key in FALSE_FLAGS), 'finite observations cannot promote acceptance')
    rows = data['observations']
    require(isinstance(rows, list) and len(rows) == 7 * 2 * campaign['samples'] * 10,
            'complete seven-material/two-target/five-strategy/two-mode grid')
    groups = defaultdict(list)
    material_identity = {}
    statuses = Counter()
    # The native program emits its seven fixed materials, then targets, samples,
    # and each sequential invocation. Retain that observed order as well as the
    # complete set: a rearranged JSON array is not the original native output.
    material_order = list(MATERIALS)
    for position, row in enumerate(rows):
        require(set(row) == {'class', 'input_source', 'task', 'rank_a', 'rank_b', 'target', 'sample',
                            'invocation_order', 'strategy', 'method', 'mode', 'proof_bytes',
                            'setup_observations_ns', 'setup_calls', 'setup_elapsed_ns', 'search_elapsed_ns',
                            'total_elapsed_ns', 'outcomes'}, 'exact native cohort fields')
        key = (row['class'], row['target'], row['sample'])
        require(row['target'] in TARGETS and type(row['sample']) is int and
                0 <= row['sample'] < campaign['samples'], 'case target/sample bounds')
        require(row['class'] == material_order[position // (2 * campaign['samples'] * 10)] and
                row['target'] == TARGETS[(position // (campaign['samples'] * 10)) % 2] and
                row['sample'] == (position // 10) % campaign['samples'] and
                row['invocation_order'] == position % 10,
                'material, target, sample and invocation rows retain their native emitted order')
        hash_text(row['task'], 'task commitment')
        for rank in ['rank_a', 'rank_b']:
            require(natural(row[rank], 'finite field rank') <= 64, 'matrix rank upper bound')
        identity = (row['task'], row['rank_a'], row['rank_b'], row['input_source'])
        require(row['class'] in MATERIALS and
                (row['rank_a'], row['rank_b'], row['task']) == MATERIALS[row['class']],
                'fixed material/rank/task identity')
        require(row['input_source'] == ('hash-generated-rank-checked' if row['class'] == 'full-rank-field'
                                       else 'synthetic-fixture'), 'material provenance scope')
        require(row['class'] not in material_identity or material_identity[row['class']] == identity,
                'one material identity across targets, samples and strategies')
        material_identity[row['class']] = identity
        require(row['strategy'] in STRATEGIES and row['mode'] in MODES, 'explicit strategy and mode')
        expected_method = (STRUCTURED_METHODS.get(row['class'], 'unsupported')
                           if row['strategy'] == 'prepared-structured' else METHODS[row['strategy']])
        require(row['method'] == expected_method, 'actual selected producer method')
        require(row['proof_bytes'] == 49188, 'unchanged canonical W1 proof length')
        require(type(row['invocation_order']) is int and 0 <= row['invocation_order'] < 10,
                'paired execution order')
        invocation = (row['sample'] + row['invocation_order']) % 10
        require(row['strategy'] == STRATEGIES[invocation // 2] and row['mode'] == MODES[invocation % 2],
                'sample rotates both strategy and reuse-mode order')
        setups = row['setup_observations_ns']
        expected_setups = 0 if row['strategy'] == 'scalar-original' else (
            campaign['searches'] if row['mode'] == 'cold-per-search' else 1)
        require(isinstance(setups, list) and len(setups) == expected_setups and
                natural(row['setup_calls'], 'construction count') == expected_setups,
                'actual cold/reused construction count')
        require(all(type(v) is int and v >= 0 for v in setups), 'setup clock observations')
        for field in ['setup_elapsed_ns', 'search_elapsed_ns', 'total_elapsed_ns']:
            natural(row[field], 'cohort clock ' + field)
        require(row['setup_elapsed_ns'] == sum(setups), 'all setup costs retained')
        outcomes = row['outcomes']
        require(isinstance(outcomes, list) and len(outcomes) == campaign['searches'],
                'every requested repeated search retained')
        for index, outcome in enumerate(outcomes):
            require(set(outcome) == {'search_index', 'status', 'attempts', 'search_elapsed_ns',
                                    'ticket_stream_commitment', 'proof_stream_commitment', 'winning_challenge',
                                    'winner_proof_commitment', 'production_verifier_elapsed_ns',
                                    'reference_verifier_elapsed_ns', 'reference_verifier_first'},
                    'exact retained search outcome fields')
            require(type(outcome['search_index']) is int and outcome['search_index'] == index,
                    'ordered repeated searches')
            require(outcome['status'] in {'winner', 'exhausted', 'unsupported'}, 'explicit search outcome')
            require((outcome['status'] == 'unsupported') == (row['method'] == 'unsupported'),
                    'unsupported method cannot fabricate a supported search')
            statuses[outcome['status']] += 1
            attempts = natural(outcome['attempts'], 'actual attempted candidates')
            elapsed = natural(outcome['search_elapsed_ns'], 'search clock')
            require(attempts <= campaign['attempt_budget'], 'bounded finite search')
            if outcome['status'] == 'unsupported':
                require(row['strategy'] == 'prepared-structured' and row['method'] == 'unsupported',
                        'unsupported producer must be explicit')
                require(attempts == 0 and elapsed == 0, 'unsupported search cannot claim execution')
                require(all(outcome[k] is None for k in ['ticket_stream_commitment', 'proof_stream_commitment',
                            'winning_challenge', 'winner_proof_commitment',
                            'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns']),
                        'unsupported search cannot fabricate proof or verification')
            else:
                require(attempts > 0, 'supported search must actually attempt work')
                for field in ['ticket_stream_commitment', 'proof_stream_commitment']:
                    hash_text(outcome[field], 'complete attempted ticket/proof stream')
                if outcome['status'] == 'exhausted':
                    require(attempts == campaign['attempt_budget'], 'exhaustion must consume the exact finite budget')
                    require(all(outcome[k] is None for k in ['winning_challenge', 'winner_proof_commitment',
                                'production_verifier_elapsed_ns', 'reference_verifier_elapsed_ns']),
                            'exhaustion must not invent a winner or verifier execution')
                else:
                    hash_text(outcome['winning_challenge'], 'actual winning challenge')
                    require(outcome['winning_challenge'] == winning_challenge(
                        row['task'], campaign['seed'], row['sample'], index, row['target'], attempts - 1),
                        'winner must bind the complete deterministic challenge stream')
                    hash_text(outcome['winner_proof_commitment'], 'actual winning proof bytes')
                    natural(outcome['production_verifier_elapsed_ns'], 'production verification clock')
                    natural(outcome['reference_verifier_elapsed_ns'], 'reference verification clock')
            if outcome['status'] == 'winner':
                require(type(outcome['reference_verifier_first']) is bool and
                        outcome['reference_verifier_first'] == ((row['sample'] + index) % 2 == 0),
                        'both real verifier runs alternate order')
            else:
                require(outcome['reference_verifier_first'] is None, 'no fabricated verifier order without a winner')
        require(row['search_elapsed_ns'] == sum(v['search_elapsed_ns'] for v in outcomes),
                'all search costs including misses retained')
        require(row['total_elapsed_ns'] == row['setup_elapsed_ns'] + row['search_elapsed_ns'],
                'explicit setup amortization without hidden setup cost')
        groups[key].append(row)
    require(len(material_identity) == 7 and len(groups) == 7 * 2 * campaign['samples'], 'complete material grid')
    for group in groups.values():
        require(len(group) == 10 and {(r['strategy'], r['mode']) for r in group} ==
                {(strategy, mode) for strategy in STRATEGIES for mode in MODES},
                'each strategy/mode executes once per paired cohort')
        require({r['invocation_order'] for r in group} == set(range(10)), 'complete execution order')
        baseline = next(r for r in group if r['strategy'] == 'scalar-original' and r['mode'] == 'cold-per-search')
        expected = deterministic_projection(baseline['outcomes'])
        for row in group:
            if row['method'] != 'unsupported':
                require(deterministic_projection(row['outcomes']) == expected,
                        'all supported producers and reuse modes must retain identical attempt/proof/ticket streams')
    return {'rows': len(rows), 'outcomes': sum(statuses.values()), 'statuses': dict(statuses),
            'deterministic_projection_sha256': projection_digest(data)}


def suite_contract(suite: str = 'reused', *, maintenance_version: int = 4) -> dict:
    """Separate raw schemas and artifact namespaces; no normalization between them."""
    require(suite in SUITES, 'explicit native cost suite')
    common_inputs = ['rust-toolchain.toml', 'trillionnium/Cargo.lock',
                     'scripts/ci/run_cross_arch_cost.py', 'scripts/ci/check_cross_arch_cost.py']
    if suite == 'maintenance-paired':
        from check_maintenance_cost import (validate_maintenance_v1_report, validate_maintenance_v2_report,
                                            validate_maintenance_v3_report, validate_maintenance_v4_report)
        require(type(maintenance_version) is int and maintenance_version in (1, 2, 3, 4),
                'explicit historical/current maintenance artifact schema')
        additional_inputs = [] if maintenance_version == 1 else [
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_periodic.rs',
            'trillionnium/crates/trnm-crypto-primitives/examples/pon_paired_io.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/continuity_v1.rs',
            'trillionnium/crates/trnm-pon-node/tests/maintenance_paired_conformance.rs',
            'formal/pon-nakamoto-v1/work_oracle.py',
            'formal/pon-nakamoto-v1/contract_wire.py',
            'formal/pon-nakamoto-v1/test_paired_work.py',
        ]
        if maintenance_version >= 3:
            additional_inputs += [
                'trillionnium/crates/trnm-crypto-primitives/src/pon_work/integer_paired.rs',
                'trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_prefix.rs',
            ]
        if maintenance_version >= 4:
            additional_inputs += [
                'trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_limb.rs',
            ]
        return {'directory': 'cross-arch-maintenance-cost', 'example': 'pon_maintenance_cost',
                'execution_schema': f'trnm-cross-arch-maintenance-cost-execution-v{maintenance_version}',
                'comparison_schema': f'trnm-cross-arch-maintenance-cost-comparison-v{maintenance_version}',
                'validate_raw_report': {1: validate_maintenance_v1_report,
                                       2: validate_maintenance_v2_report,
                                       3: validate_maintenance_v3_report,
                                       4: validate_maintenance_v4_report}[maintenance_version],
                'inputs': common_inputs + [
                    'trillionnium/crates/trnm-crypto-primitives/examples/pon_maintenance_cost.rs',
                    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
                    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/paired_product.rs',
                    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/structured.rs',
                    'scripts/ci/check_maintenance_cost.py'] + additional_inputs}
    if suite == 'reused':
        return {'directory': 'cross-arch-cost', 'example': 'pon_reused_cost',
                'execution_schema': 'trnm-cross-arch-cost-execution-v1',
                'comparison_schema': 'trnm-cross-arch-cost-comparison-v1',
                'validate_raw_report': validate_raw_report,
                'inputs': common_inputs + [
                    'trillionnium/crates/trnm-crypto-primitives/examples/pon_reused_cost.rs',
                    'trillionnium/crates/trnm-crypto-primitives/examples/support/w1_material.rs']}
    if suite == 'one-zero-locality':
        from check_one_zero_locality_cost import validate_one_zero_report
        return {'directory': 'cross-arch-one-zero-locality-cost', 'example': 'pon_one_zero_locality_cost',
                'execution_schema': 'trnm-cross-arch-one-zero-locality-cost-execution-v1',
                'comparison_schema': 'trnm-cross-arch-one-zero-locality-cost-comparison-v1',
                'validate_raw_report': validate_one_zero_report,
                'inputs': common_inputs + [
                    'trillionnium/crates/trnm-crypto-primitives/examples/pon_one_zero_locality_cost.rs',
                    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
                    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/structured.rs',
                    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_one_zero.rs',
                    'scripts/ci/check_one_zero_locality_cost.py']}
    from check_zero_locality_cost import validate_zero_report
    return {'directory': 'cross-arch-zero-locality-cost', 'example': 'pon_zero_locality_cost',
            'execution_schema': 'trnm-cross-arch-zero-locality-cost-execution-v1',
            'comparison_schema': 'trnm-cross-arch-zero-locality-cost-comparison-v1',
            'validate_raw_report': validate_zero_report,
            'inputs': common_inputs + [
                'trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_locality_cost.rs',
                'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
                'trillionnium/crates/trnm-crypto-primitives/src/pon_work/structured.rs',
                'trillionnium/crates/trnm-crypto-primitives/src/pon_work/blocked_zero.rs',
                'scripts/ci/check_zero_locality_cost.py']}


def validate_artifact(directory: Path, expected_source: str, *, suite: str = 'reused',
                      maintenance_version: int = 4) -> tuple[dict, list[dict]]:
    contract = suite_contract(suite, maintenance_version=maintenance_version)
    example = contract['example']
    validate_raw = contract['validate_raw_report']
    require(directory.is_dir() and not directory.is_symlink(), 'artifact directory cannot be substituted')
    require(not any(p.is_symlink() for p in directory.rglob('*')), 'retained artifact cannot contain symlinks')
    report = read_json(directory / contract['directory'] / 'manifest.json')
    require(report['schema'] == contract['execution_schema'] and report['result'] == 'PASS',
            'actual successful native execution required for each architecture')
    # capture() only adds error/launch_error on a failed path. A null, empty or
    # nonempty failure field is equally inconsistent with its success shape;
    # never erase one while accepting an otherwise matching PASS label.
    require(set(report) == {'schema', 'result', 'execution_context', 'architecture',
            'runner_label', 'observations', 'campaigns', 'build_profile', 'compiler_channel',
            'target', 'public_network_ready', 'independent_hardware_qualified',
            'resource_fairness_qualified', 'work_profile_qualified', 'production_activation',
            'runner_context', 'uname', 'source_before', 'source_after', 'source_changed',
            'build_environment_overrides', 'binary_elf_machine', 'binary_sha256_before',
            'binary_sha256_after', 'input_sha256', 'artifact_sha256'},
            'exact successful execution manifest cannot retain a hidden error')
    require(report['execution_context'] == 'github-hosted', 'local preflight cannot replace hosted execution')
    arch = report['architecture']
    require(arch in ARCHITECTURES, 'native architecture inventory')
    spec = ARCHITECTURES[arch]
    require(report['runner_label'] == spec['runner'] and report['target'] == spec['target'], 'runner/target match')
    require(report['uname']['system'] == 'Linux' and report['uname']['machine'] == spec['machine'] and
            report['runner_context']['RUNNER_ARCH'] == spec['runner_arch'], 'actual native host architecture')
    require(all(isinstance(report['runner_context'][key], str) and report['runner_context'][key].isdigit()
                for key in ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']), 'actual hosted run/attempt identity')
    require(report['compiler_channel'] == '1.95.0' and report['build_profile'] == 'release' and
            report['build_environment_overrides'] == {}, 'fixed native release compiler settings')
    before, after = report['source_before'], report['source_after']
    require(before == after and report['source_changed'] is False, 'source unchanged around actual execution')
    require(before['commit'] == expected_source and before['source_state'] == 'committed-clean' and
            before['tracked_worktree_verified'] is True, 'actual tracked source bound to the expected candidate')
    require(natural(before['tracked_entries'], 'tracked source entries') > 0 and
            natural(before['tracked_bytes'], 'tracked source bytes') > 0, 'nonempty tracked-byte verification')
    require(set(report['input_sha256']) == set(contract['inputs']),
            'compiler lock, native example/materials and evidence owners must be hashed')
    for value in report['input_sha256'].values():
        hash_text(value, 'source input digest')
    receipt = read_json(directory / 'source.json')
    require(receipt['tested_commit'] == before['commit'] and receipt['tested_tree'] == before['tree'] and
            receipt['tracked_worktree_verified'] is True, 'workflow and native source receipts agree')
    for flag in ['public_network_ready', 'independent_hardware_qualified', 'resource_fairness_qualified',
                 'work_profile_qualified', 'production_activation']:
        require(report[flag] is False, 'hosted VM observations cannot qualify ' + flag)
    base = directory / contract['directory']
    files = report['artifact_sha256']
    validate_files(base, files)
    require(report['binary_elf_machine'] == spec['elf_machine'] and
            elf_machine(base / example) == spec['elf_machine'], 'retained executable native architecture')
    require(report['binary_sha256_before'] == report['binary_sha256_after'] == files[example],
            'same measured executable before and after all campaigns')
    compiler = (base / 'rustc.stdout').read_text()
    require('\nrelease: 1.95.0\n' in compiler and '\nhost: ' + spec['target'] + '\n' in compiler,
            'actual compiler release and native host retained')
    require((base / 'cpuinfo.txt').stat().st_size > 0 and spec['machine'] in (base / 'uname.stdout').read_text(),
            'actual CPU and uname output retained')
    observations = report['observations']
    require(isinstance(observations, list) and all(type(o) is dict and set(o) == {
            'command', 'cwd', 'exit_code', 'timed_out', 'timeout_seconds', 'stdout',
            'stderr', 'elapsed_ns'} and type(o['exit_code']) is int and o['exit_code'] == 0
            and o['timed_out'] is False for o in observations),
            'exact actual command success cannot conceal launch errors or boolean aliases')
    for observed in observations:
        natural(observed['elapsed_ns'], 'command elapsed time')
    require(len(observations) == 6 and all(o['exit_code'] == 0 and not o['timed_out'] for o in observations),
            'actual identity, build and both campaign command statuses')
    commands = [['uname', '-a'], ['rustc', '+1.95.0', '-vV'], ['cargo', '+1.95.0', '--version'],
                ['cargo', '+1.95.0', 'build', '--locked', '--release', '--manifest-path',
                 'trillionnium/Cargo.toml', '--target', spec['target'], '-p',
                 'trnm-crypto-primitives', '--example', example]]
    for observed, command, stem in zip(observations, commands, ['uname', 'rustc', 'cargo', 'build']):
        require(observed['command'] == command and observed['stdout'] == stem + '.stdout' and
                observed['stderr'] == stem + '.stderr' and
                observed['timeout_seconds'] == (COST_BUILD_TIMEOUT_SECONDS if stem == 'build' else
                                                COST_IDENTITY_TIMEOUT_SECONDS),
                'actual identity/build commands and full stdout/stderr')
    require(all(o['stdout'] in files and o['stderr'] in files for o in observations),
            'stdout and stderr must be retained even when empty')
    require(len(report['campaigns']) == len(CAMPAIGNS), 'both fixed finite campaigns must execute')
    data = []
    for index, (row, configuration) in enumerate(zip(report['campaigns'], CAMPAIGNS)):
        require(type(row) is dict and set(row) == {
                'configuration', 'observation', 'result', 'validated'},
                'exact successful campaign cannot retain a hidden failure')
        require(row['configuration'] == configuration and row['result'] == 'PASS', 'same fixed campaign configuration')
        observed = row['observation']
        require(observed == observations[index + 4] and
                observed['timeout_seconds'] == COST_CAMPAIGN_TIMEOUT_SECONDS and
                observed['stdout'] == f'campaign-{index}.stdout' and
                observed['stderr'] == f'campaign-{index}.stderr', 'actual bounded campaign stdout/stderr')
        require(isinstance(observed['command'], list) and len(observed['command']) == 9 and
                Path(observed['command'][0]).name == example and
                observed['command'][1:] == benchmark_arguments(configuration), 'actual native benchmark CLI')
        raw = read_json(base / observed['stdout'])
        require(row['validated'] == validate_raw(raw, configuration), 'native correctness summary replays')
        data.append(raw)
    return report, data


def compare_artifacts(root: Path, expected_source: str, *, suite: str = 'reused',
                      maintenance_version: int = 4) -> dict:
    contract = suite_contract(suite, maintenance_version=maintenance_version)
    directories = sorted(p for p in root.iterdir() if p.is_dir())
    require(len(directories) == 2, 'exactly two current-run architecture artifacts required')
    loaded = [(validate_artifact(path, expected_source) if suite == 'reused' else
               validate_artifact(path, expected_source, suite=suite,
                                 maintenance_version=maintenance_version)) for path in directories]
    require({r['architecture'] for r, _ in loaded} == set(ARCHITECTURES), 'both architectures must actually execute')
    left, right = loaded
    for key in ['source_before', 'source_after', 'input_sha256']:
        require(left[0][key] == right[0][key], 'same source and measured implementation inputs: ' + key)
    for key in ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']:
        require(left[0]['runner_context'][key] and left[0]['runner_context'][key] == right[0]['runner_context'][key],
                'same actual hosted run and attempt')
    for index in range(len(CAMPAIGNS)):
        require(deterministic_projection(left[1][index]) == deterministic_projection(right[1][index]),
                'same material/target/sample/search/proof streams across architectures')
    return {'schema': contract['comparison_schema'], 'result': 'PASS', 'source': expected_source,
            'tree': left[0]['source_before']['tree'], 'architectures': sorted(ARCHITECTURES),
            'campaigns': [contract['validate_raw_report'](raw, configuration)
                          for raw, configuration in zip(left[1], CAMPAIGNS)],
            'manifest_sha256': {path.name: digest(path / contract['directory'] / 'manifest.json') for path in directories},
            'speed_threshold_applied': False, 'independent_hardware_qualified': False,
            'resource_fairness_qualified': False, 'work_hardness_accepted': False, 'production_activation': False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--suite', choices=SUITES, default='reused')
    parser.add_argument('--maintenance-version', type=int, choices=(1, 2, 3, 4), default=4,
                        help='explicit historical v1/v2/v3 or current v4 maintenance artifact parsing')
    args = parser.parse_args()
    result = {'schema': suite_contract(args.suite, maintenance_version=args.maintenance_version)['comparison_schema'], 'result': 'FAIL',
              'source': args.expected_source, 'speed_threshold_applied': False}
    try:
        current = source()
        require(current['commit'] == args.expected_source and current['source_state'] == 'committed-clean',
                'comparison code must be the exact clean candidate')
        result = compare_artifacts(args.artifacts, args.expected_source, suite=args.suite,
                                   maintenance_version=args.maintenance_version)
        require(result['tree'] == current['tree'], 'observation tree equals the comparison code tree')
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result['result'] = 'FAIL'
        result['error'] = str(error)
        print(str(error), file=sys.stderr)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))
    return 0 if result['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
