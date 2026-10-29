#!/usr/bin/env python3
"""Read actual same-source retained PQ gates and the new anchored NPQ5 lane."""
from __future__ import annotations

import ast
import gzip
import hashlib
import json
from pathlib import Path

from ci_observation import ROOT, digest
import run_native_pq_tasks_v5 as retained

PROFILE = 'pon-native-pq-tasks-v5-anchored-migration-v1'
SCOPE = ('actual ordinary W1/reference/admit/SQL on shared host; external prior PQ '
         'registry and source finality remain premises')
CASES = {
    'actual_anchored_claim_pq5_task_native_work_reorg_and_cold_readback',
    'full_9432_byte_claims_preserve_the_original_55_accept_56_reject_capacity',
    'wrong_anchor_current_context_prior_key_and_legacy_profiles_never_grant_claim_authority',
}
BASE_RUNNER = 'scripts/ci/run_native_pq_tasks_v5.py'
BASE_RUNNER_BLOB = '0bc5700a7b577d60a96d71fd47f9f2f5ee1a5204'
BASE_TESTS = (
    ('m00', 'trnm-protocol', ('--lib',), None),
    ('m06', 'trnm-mvcc-fee', ('--lib',), None),
    ('task-renewal', 'trnm-mvcc-fee', ('--test', 'pq5_task_renewal'), retained.TASK_CASES),
    ('native-task', 'trnm-pon-node', ('--test', 'native_pq_v5'), retained.NATIVE_TASK_CASES),
    ('retained-task-authority', 'trnm-mvcc-fee', ('--test', 'pq4_task_authority'), retained.V4_TASK_CASES),
    ('retained-native-task', 'trnm-pon-node', ('--test', 'native_pq_v4'), retained.V4_NATIVE_TASK_CASES),
    ('retained-quota-authority', 'trnm-mvcc-fee', ('--test', 'pq3_quota_authority'), retained.QUOTA_CASES),
    ('retained-authority-capacity', 'trnm-mvcc-fee', ('--test', 'pq2_authority_capacity'), retained.AUTHORITY_CAPACITY_CASES),
    ('retained-native-quota', 'trnm-pon-node', ('--test', 'native_pq_v3'), retained.NATIVE_QUOTA_CASES),
    ('retained-pq2', 'trnm-pon-node', ('--test', 'native_pq_v2'), retained.NATIVE_CASES),
    ('retained-pq1', 'trnm-pon-node', ('--test', 'native_pq_v1'), retained.PQ1_NATIVE_CASES),
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def canonical_hash(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in '0123456789abcdef' for c in value)


def artifact(directory: Path, name: str) -> Path:
    require(isinstance(name, str) and bool(name), 'artifact name')
    relative = Path(name)
    require(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name, 'artifact path')
    path = directory / relative
    require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(directory.resolve()), 'actual artifact file')
    return path


def baseline_commands() -> list[tuple[str, list[str]]]:
    manifest = ['--manifest-path', 'trillionnium/Cargo.toml']
    cargo = ['cargo', '+1.95.0']
    commands = [
        ('rustc.log', ['rustc', '+1.95.0', '-vV']),
        ('preflight.log', ['bash', 'scripts/project-preflight.sh', '--audit']),
        ('source-negatives.log', ['python3', 'scripts/ci/test_ci_source_integrity.py']),
        ('inventory.log', ['python3', 'scripts/refresh_distributed_source_inventory.py', '--check']),
        ('cargo-graph.log', cargo + ['metadata', '--locked', '--format-version', '1'] + manifest),
        ('fmt.log', cargo + ['fmt'] + manifest + ['--all', '--', '--check']),
    ]
    commands.extend((name + '.log', cargo + ['test', '--locked'] + manifest + ['-p', package] + list(target)
                     + ['--', '--show-output', '--test-threads=1'])
                    for name, package, target, _ in BASE_TESTS)
    commands.append(('clippy.log', cargo + ['clippy', '--locked'] + manifest
                     + ['-p', 'trnm-protocol', '-p', 'trnm-mvcc-fee', '-p', 'trnm-pon-node',
                        '--all-targets', '--all-features', '--', '-D', 'warnings']))
    return commands


def baseline_inputs(root: Path) -> set[str]:
    raw = (root / BASE_RUNNER).read_bytes()
    observed = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    require(observed == BASE_RUNNER_BLOB, 'original 205 runner bytes changed')
    calls = [node for node in ast.walk(ast.parse(raw)) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == 'finish']
    require(len(calls) == 1 and len(calls[0].args) == 3, 'original input roster')
    values = ast.literal_eval(calls[0].args[2])
    require(isinstance(values, list) and len(set(values)) == len(values), 'original input duplicates')
    return set(values)


def baseline_result(directory: Path, expected_head: str, expected_tree: str, root: Path = ROOT) -> dict:
    require(canonical_hash(expected_head, 40) and canonical_hash(expected_tree, 40), 'exact source identity')
    report_path = artifact(directory, 'manifest.json')
    report = json.loads(report_path.read_text())
    source = report.get('source', {})
    require(report.get('schema') == 'native-pq-tasks-v5-research-ci-v1' and report.get('result') == 'PASS'
            and report.get('source_expected') == expected_head and report.get('source_consistent') is True
            and source.get('commit') == expected_head and source.get('tree') == expected_tree
            and source.get('source_state') == 'committed-clean' and source.get('tracked_worktree_verified') is True
            and type(source.get('tracked_entries')) is int and source['tracked_entries'] > 0
            and type(source.get('tracked_bytes')) is int and source['tracked_bytes'] > 0,
            'same-source complete retained gate required')
    require(report.get('total_command_budget_seconds') == 2400 and report.get('renewal_19_22_qualified') is True
            and report.get('supported_new_commands') == [18, 19, 20, 21, 22]
            and report.get('production_activation') is False and report.get('whole_chain_post_quantum') is False,
            'retained qualification scope')
    pins = report.get('input_sha256')
    require(isinstance(pins, dict) and set(pins) == baseline_inputs(root), 'complete original input pins')
    for name, sha in pins.items():
        require(canonical_hash(sha) and digest(root / name) == sha, 'retained input differs: ' + name)
    hashes = report.get('artifact_sha256')
    require(isinstance(hashes, dict) and bool(hashes), 'retained actual artifacts required')
    for name, sha in hashes.items():
        require(canonical_hash(sha) and digest(artifact(directory, name)) == sha, 'retained artifact differs: ' + name)
    commands = baseline_commands()
    observations = report.get('observations')
    require(isinstance(observations, list) and len(observations) == len(commands) == 18, 'all retained commands required')
    elapsed = 0
    for observation, (log, command) in zip(observations, commands, strict=True):
        require(observation.get('command') == command and observation.get('log') == log and log in hashes
                and observation.get('cwd') == str(root) and observation.get('exit_code') == 0
                and observation.get('process_exit_code') == 0 and observation.get('executed') is True
                and observation.get('timed_out') is False and observation.get('expected_source') == expected_head
                and observation.get('source_before_verified') is True and observation.get('source_after_verified') is True
                and observation.get('source_verified') is True and not observation.get('source_error')
                and type(observation.get('elapsed_ns')) is int and observation['elapsed_ns'] > 0,
                'retained command did not execute under source guards: ' + log)
        elapsed += observation['elapsed_ns']
    require(elapsed <= 2400 * 1_000_000_000, 'original retained time budget')
    require('\nrelease: 1.95.0\n' in '\n' + artifact(directory, 'rustc.log').read_text(), 'original compiler')
    parsed = {}
    for name, _, _, required in BASE_TESTS:
        text = artifact(directory, name + '.log').read_text()
        parsed[name] = retained.unit_result(text, name) if required is None else retained.test_result(text, required, exact=True)
    require(report.get('tests') == parsed, 'retained report/raw test mismatch')
    require(sum(row['passed'] for row in parsed.values()) == 205
            and sum(row['ignored'] for row in parsed.values()) == 8
            and sum(parsed[name]['passed'] for name, _, _, required in BASE_TESTS if required is not None) == 68,
            'original 205/68/eight-ignore contract')
    phase_files = {
        'native-task-phases.json': retained.task_phases(artifact(directory, 'native-task.log').read_text()),
        'retained-task-phases.json': retained.v4_task_phases(artifact(directory, 'retained-native-task.log').read_text()),
        'retained-quota-phases.json': retained.quota_phases(artifact(directory, 'retained-native-quota.log').read_text()),
        'retained-pq2-phases.json': retained.phase_result(artifact(directory, 'retained-pq2.log').read_text()),
    }
    for name, value in phase_files.items():
        require(name in hashes and json.loads(artifact(directory, name).read_text()) == value, 'retained phase/raw mismatch')
    require(report.get('native_task_phase_count') == 37, 'all retained native phases')
    binary = report.get('native_binary', {})
    require(binary.get('retained_gzip') == 'native-task-test.bin.gz'
            and type(binary.get('bytes')) is int and 0 < binary['bytes'] <= 64 * 1024 * 1024
            and binary.get('gzip_sha256') == hashes.get('native-task-test.bin.gz')
            and canonical_hash(binary.get('sha256')), 'actual retained native executable')
    with gzip.open(artifact(directory, binary['retained_gzip']), 'rb') as stream:
        raw = stream.read(binary['bytes'] + 1)
    require(len(raw) == binary['bytes'] and raw.startswith(b'\x7fELF')
            and hashlib.sha256(raw).hexdigest() == binary['sha256'], 'retained executable bytes')
    return {'source_commit': expected_head, 'source_tree': expected_tree, 'passed': 205,
            'integration_passed': 68, 'original_ignored': 8, 'executed_commands': 18,
            'native_task_phases': 37, 'manifest_sha256': digest(report_path),
            'native_binary_sha256': binary['sha256'],
            'historical_report_flags_rewritten': False}


EXPECTED_PHASES = {
    'unified': ['source-checkpoint', 'claims', 'lease', 'registration', 'material',
                'fork-1', 'fork-2', 'fork-3', 'fork-4', 'fork-5', 'replayed-claims',
                'fresh-lease', 'fresh-registration', 'fresh-material'],
    'capacity': ['source-checkpoint', 'claims-capacity'],
    'refusal': ['source-checkpoint', 'other-source-checkpoint', 'valid-claim-after-refusals'],
}


def native_result(text: str) -> dict:
    tests = retained.test_result(text, CASES, exact=True)
    rows, completions, fresh = [], [], []
    for line in text.splitlines():
        if '"schema":"native-pq5-migration-actual-phase-v1"' in line:
            rows.append(json.loads(line))
        elif '"schema":"native-pq5-migration-completion-v1"' in line:
            completions.append(json.loads(line))
        elif '"schema":"native-pq5-fresh-namespace-observation-v1"' in line:
            fresh.append(json.loads(line))
    require(len(rows) == 19 and len(completions) == 3 and len(fresh) == 1, 'complete actual anchored observations')
    lookup = {}
    fields = {'schema', 'case', 'phase', 'profile', 'block', 'parent', 'state_root', 'transactions',
              'raw_bytes', 'proof_bytes', 'packet_bytes', 'activated', 'wall_nanoseconds', 'scope'}
    for row in rows:
        key = (row.get('case'), row.get('phase'))
        require(set(row) == fields and key not in lookup and row.get('scope') == SCOPE, 'phase shape or duplicate')
        require(key[0] in EXPECTED_PHASES and key[1] in EXPECTED_PHASES[key[0]], 'unknown actual phase')
        source = key[1] in ('source-checkpoint', 'other-source-checkpoint')
        require(row['profile'] == ('source-legacy' if source else PROFILE), 'actual configured profile')
        require(all(canonical_hash(row[field]) for field in ('block', 'parent', 'state_root'))
                and all(type(row[field]) is int and row[field] >= 0
                        for field in ('transactions', 'raw_bytes', 'proof_bytes', 'packet_bytes', 'wall_nanoseconds'))
                and row['proof_bytes'] == 49188 and row['wall_nanoseconds'] > 0
                and row['transactions'] <= 256 and row['raw_bytes'] <= 524288
                and row['packet_bytes'] == (0 if source else 8) + 318 + 2 + 2 * row['transactions'] + row['raw_bytes'] + row['proof_bytes']
                and row['packet_bytes'] <= 1048576 and type(row['activated']) is bool,
                'actual full-W1/packet observation')
        require(row['activated'] is (not key[1].startswith('fork-')), 'actual activation stage')
        expected_count = (57 if key == ('capacity', 'source-checkpoint') else 1) if source else {
            'claims': 2, 'lease': 1, 'registration': 1, 'replayed-claims': 2,
            'fresh-lease': 1, 'fresh-registration': 1, 'claims-capacity': 55,
            'valid-claim-after-refusals': 1,
        }.get(key[1], 0)
        if key[1] == 'other-source-checkpoint':
            expected_count = 0
        require(row['transactions'] == expected_count, 'actual transaction count')
        if not source:
            expected_bytes = {'claims': 18864, 'lease': 4053, 'registration': 7894,
                              'replayed-claims': 18864, 'fresh-lease': 4053, 'fresh-registration': 7894,
                              'claims-capacity': 518760, 'valid-claim-after-refusals': 9432}.get(key[1], 0)
            require(row['raw_bytes'] == expected_bytes, 'complete actual PQ frames')
        lookup[key] = row
    require(set(lookup) == {(case, phase) for case, phases in EXPECTED_PHASES.items() for phase in phases}, 'actual phase roster')
    completion = {}
    for row in completions:
        case = row.get('case')
        common = {'schema', 'case', 'source_checkpoint', 'cold_tip', 'cold_state_root',
                  'prior_pq_registry_external', 'source_retirement_finality_proved'}
        extra = {
            'unified': {'genesis', 'reorg_claims_and_nonce_restored', 'task_authority_restored',
                        'local_pool_ordinal_preserved', 'new_branch_signed_records'},
            'capacity': {'claim_bytes', 'accepted_claims', 'accepted_raw_bytes', 'refused_claims',
                         'refused_raw_bytes', 'transaction_bytes_limit', 'packet_bytes_limit', 'source_accounts'},
            'refusal': {'wrong_checkpoint_refused', 'wrong_context_refused', 'wrong_anchor_refused',
                        'wrong_prior_key_refused', 'old_pq2_refused', 'old_ed25519_refused', 'wrong_cold_context_refused'},
        }
        require(case in extra and set(row) == common | extra[case], 'actual completion shape')
        require(case in EXPECTED_PHASES and case not in completion and row.get('prior_pq_registry_external') is True
                and row.get('source_retirement_finality_proved') is False
                and row.get('source_checkpoint') == lookup[(case, 'source-checkpoint')]['block'], 'actual completion source binding')
        last = lookup[(case, EXPECTED_PHASES[case][-1])]
        require(row.get('cold_tip') == last['block'] and row.get('cold_state_root') == last['state_root'], 'actual cold readback binding')
        completion[case] = row
    unified = completion['unified']
    require(unified.get('reorg_claims_and_nonce_restored') is True and unified.get('task_authority_restored') is True
            and unified.get('local_pool_ordinal_preserved') is True and unified.get('new_branch_signed_records') == 2
            and type(unified.get('new_branch_signed_records')) is int
            and canonical_hash(unified.get('genesis')), 'actual shared claim/task reorg')
    for chain in (['claims', 'lease', 'registration', 'material'],
                  ['fork-1', 'fork-2', 'fork-3', 'fork-4', 'fork-5', 'replayed-claims', 'fresh-lease', 'fresh-registration', 'fresh-material']):
        parent = unified['genesis']
        for phase in chain:
            row = lookup[('unified', phase)]
            require(row['parent'] == parent, 'actual unified parent chain')
            parent = row['block']
    capacity = completion['capacity']
    require(all(type(capacity.get(key)) is int and capacity.get(key) == value for key, value in {'claim_bytes': 9432, 'accepted_claims': 55,
            'accepted_raw_bytes': 518760, 'refused_claims': 56, 'refused_raw_bytes': 528192,
            'transaction_bytes_limit': 524288, 'packet_bytes_limit': 1048576, 'source_accounts': 60}.items()), 'original claim capacity')
    refusal = completion['refusal']
    require(all(refusal.get(key) is True for key in ('wrong_checkpoint_refused', 'wrong_context_refused', 'wrong_anchor_refused',
            'wrong_prior_key_refused', 'old_pq2_refused', 'old_ed25519_refused', 'wrong_cold_context_refused')), 'actual refusal controls')
    require(lookup[('refusal', 'other-source-checkpoint')]['parent'] == lookup[('refusal', 'source-checkpoint')]['block'], 'second actual source checkpoint')
    require(set(fresh[0]) == {'schema', 'network', 'parameters', 'genesis', 'state_root', 'state_json_sha256', 'anchored_constructor_used'}
            and fresh[0]['anchored_constructor_used'] is False
            and all(canonical_hash(fresh[0][key]) for key in ('network', 'parameters', 'genesis', 'state_root', 'state_json_sha256'))
            and fresh[0]['genesis'] != unified['genesis'], 'separate original fresh namespace observation')
    return {'tests': tests, 'phases': rows, 'completions': completion, 'fresh_namespace': fresh[0],
            'scope': SCOPE, 'synthetic_fixture_is_native_evidence': False}
